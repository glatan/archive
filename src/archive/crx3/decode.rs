//! CRX container decoding (versions 2 and 3).
//!
//! CRX3 layout reference: `components/crx_file/crx3.proto` (snapshot in
//! `docs/spec/sources/crx3.proto`). The file is `Cr24` magic, a
//! little-endian version (3), a little-endian header length N, an
//! N-octet protobuf `CrxFileHeader`, then a ZIP archive.
//!
//! CRX2 layout reference: Chromium `components/crx_file/crx_file.h`
//! `CrxFileHeader`. The file is `Cr24` magic, a little-endian version
//! (2), a little-endian public-key length, a little-endian signature
//! length, the public key, the signature, then a ZIP archive — a fixed
//! layout with no protobuf header.

use alloc::string::String;
use alloc::vec::Vec;

use crate::archive::zip;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"Cr24";
const VERSION: u32 = 3;
/// CRX2 wire version: fixed-layout header, no protobuf.
const VERSION_CRX2: u32 = 2;
/// Upper bound on the protobuf header length; the spec tells clients
/// to reject an N too large to safely hold in memory.
const MAX_HEADER_LEN: usize = 16 * 1024 * 1024;
/// Upper bound on a CRX2 public key or signature; Chromium's
/// `crx_verifier.cc` accepts at most 64 KiB each.
const MAX_CRX2_PROOF_LEN: usize = 64 * 1024;

// CrxFileHeader field numbers.
const F_RSA_PROOF: u32 = 2;
const F_ECDSA_PROOF: u32 = 3;
const F_VERIFIED_CONTENTS: u32 = 4;
const F_SIGNED_HEADER_DATA: u32 = 10000;

// AsymmetricKeyProof / SignedData field numbers.
const F_PUBLIC_KEY: u32 = 1;
const F_SIGNATURE: u32 = 2;
const F_CRX_ID: u32 = 1;

/// Signing algorithm of an `AsymmetricKeyProof`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAlgorithm {
    /// `sha256_with_rsa` — RSA-PSS, X.509 SubjectPublicKeyInfo key.
    Sha256WithRsa,
    /// `sha256_with_ecdsa` — NIST P-256, named-curve public key.
    Sha256WithEcdsa,
    /// CRX2 header proof — RSA PKCS#1 signature. The CRX2 wire format
    /// carries no algorithm id; Chromium's verifier accepts the
    /// SHA-1 / SHA-256 RSA PKCS#1 v1.5 variants.
    RsaPkcs1,
}

/// A parsed `AsymmetricKeyProof` message — also used to carry the
/// raw public key + signature pair of a CRX2 fixed header. The
/// signature is **not** verified by this decoder.
#[derive(Debug, Clone)]
pub struct Crx3Proof {
    /// Signing algorithm the proof claims.
    pub algorithm: ProofAlgorithm,
    /// Signer's public key (X.509 SPKI for RSA, named-curve for ECDSA).
    pub public_key: Vec<u8>,
    /// Signature over `"CRX3 SignedData\x00" + size + signed_header_data
    /// + archive`.
    pub signature: Vec<u8>,
}

/// A decoded CRX3 entry (one member of the embedded ZIP archive).
#[derive(Debug, Clone)]
pub struct Crx3Entry {
    /// Member name.
    pub name: String,
    /// Member contents.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for Crx3Entry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decoded CRX file (container version 2 or 3).
#[derive(Debug)]
pub struct Crx3Image {
    /// Container version from the wire header (2 or 3).
    pub version: u32,
    /// 16-byte extension id from `SignedData.crx_id`, if present.
    /// Version 2 files carry no `SignedData` on the wire, so the id is
    /// derived as `SHA-256(public_key)[..16]` — the same derivation
    /// Chromium's `crx_verifier.cc` `GetCrxIdFromPublicKey` uses for
    /// both versions.
    pub crx_id: Option<[u8; 16]>,
    /// Signing proofs carried by the header (unverified).
    pub proofs: Vec<Crx3Proof>,
    /// GZIP-compressed verified-contents JSON, if present.
    pub verified_contents: Option<Vec<u8>>,
    /// Entries decoded from the embedded ZIP archive.
    pub entries: Vec<Crx3Entry>,
}

impl Crx3Image {
    /// Check `SignedData.crx_id` against the RSA public keys carried
    /// by the `sha256_with_rsa` proofs. Per crx3.proto, the first
    /// 128 bits of the SHA-256 hash of the public key must equal the
    /// `crx_id`.
    ///
    /// Returns `Some(true)` when an RSA proof key matches,
    /// `Some(false)` when RSA public keys are present but none
    /// matches, and `None` when the check cannot be performed —
    /// the header carries no `crx_id` or no RSA public key. The
    /// archive is decoded either way; this only reports the consistency
    /// result to the caller. For CRX2 the `crx_id` is derived from the
    /// public key itself (see `Crx3Image::crx_id`), so this always
    /// returns `None`: v2 proofs are `RsaPkcs1`, not `Sha256WithRsa`.
    pub fn verify_crx_id(&self) -> Option<bool> {
        let crx_id = self.crx_id?;
        let mut saw_rsa_key = false;
        for proof in &self.proofs {
            if proof.algorithm != ProofAlgorithm::Sha256WithRsa || proof.public_key.is_empty() {
                continue;
            }
            saw_rsa_key = true;
            let digest = crate::util::sha256::sha256(&proof.public_key);
            if digest[..16] == crx_id[..] {
                return Some(true);
            }
        }
        if saw_rsa_key { Some(false) } else { None }
    }
}

// ---- minimal protobuf wire parser (varint + length-delimited only) ----

fn read_varint(b: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*pos).ok_or(Error::UnexpectedEof)?;
        *pos += 1;
        v |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::InvalidData("crx3 varint overflow"));
        }
    }
}

/// Iterate the length-delimited fields of a protobuf message.
/// `f(field_no, bytes)` is called per LEN field; other wire types are
/// skipped when well-formed, and malformed data returns an error.
fn for_each_len_field(
    b: &[u8],
    mut f: impl FnMut(u32, &[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut pos = 0usize;
    while pos < b.len() {
        let key = read_varint(b, &mut pos)?;
        let field = key >> 3;
        if field == 0 || field > 0x1FFF_FFFF {
            return Err(Error::InvalidData("crx3 bad field number"));
        }
        match key & 0x7 {
            2 => {
                let len = read_varint(b, &mut pos)? as usize;
                let end = pos.checked_add(len).ok_or(Error::UnexpectedEof)?;
                let val = b.get(pos..end).ok_or(Error::UnexpectedEof)?;
                f(field as u32, val)?;
                pos = end;
            }
            0 => {
                read_varint(b, &mut pos)?;
            }
            1 => {
                if b.len() - pos < 8 {
                    return Err(Error::UnexpectedEof);
                }
                pos += 8;
            }
            5 => {
                if b.len() - pos < 4 {
                    return Err(Error::UnexpectedEof);
                }
                pos += 4;
            }
            _ => return Err(Error::InvalidData("crx3 unsupported wire type")),
        }
    }
    Ok(())
}

fn parse_proof(algo: ProofAlgorithm, b: &[u8]) -> Result<Crx3Proof, Error> {
    let mut public_key = Vec::new();
    let mut signature = Vec::new();
    for_each_len_field(b, |field, val| {
        match field {
            F_PUBLIC_KEY => public_key = val.to_vec(),
            F_SIGNATURE => signature = val.to_vec(),
            _ => {}
        }
        Ok(())
    })?;
    if public_key.is_empty() && signature.is_empty() {
        return Err(Error::InvalidData("crx3 empty proof"));
    }
    Ok(Crx3Proof {
        algorithm: algo,
        public_key,
        signature,
    })
}

fn parse_signed_data(b: &[u8]) -> Result<Option<[u8; 16]>, Error> {
    let mut id = None;
    for_each_len_field(b, |field, val| {
        if field == F_CRX_ID && val.len() == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(val);
            id = Some(a);
        }
        Ok(())
    })?;
    Ok(id)
}

fn zip_entries(archive: &[u8]) -> Result<Vec<Crx3Entry>, Error> {
    Ok(zip::decode::decode(archive)?
        .into_iter()
        .map(|e| Crx3Entry {
            name: e.name,
            data: e.data,
        })
        .collect())
}

/// Decode the fixed-layout CRX2 header (`crx_file.h` `CrxFileHeader`):
/// u32 public-key length, u32 signature length, public key, signature,
/// then the ZIP archive. The RSA PKCS#1 signature is exposed, not
/// verified.
fn decode_crx2(input: &[u8]) -> Result<Crx3Image, Error> {
    let fixed = input.get(..16).ok_or(Error::UnexpectedEof)?;
    let key_len = u32::from_le_bytes(fixed[8..12].try_into().unwrap()) as usize;
    let sig_len = u32::from_le_bytes(fixed[12..16].try_into().unwrap()) as usize;
    if key_len > MAX_CRX2_PROOF_LEN || sig_len > MAX_CRX2_PROOF_LEN {
        return Err(Error::InvalidData("crx2 proof field too large"));
    }
    let key_end = 16usize.checked_add(key_len).ok_or(Error::UnexpectedEof)?;
    let sig_end = key_end.checked_add(sig_len).ok_or(Error::UnexpectedEof)?;
    let public_key = input.get(16..key_end).ok_or(Error::UnexpectedEof)?;
    let signature = input.get(key_end..sig_end).ok_or(Error::UnexpectedEof)?;
    if public_key.is_empty() && signature.is_empty() {
        return Err(Error::InvalidData("crx2 empty proof"));
    }
    // CRX2 carries no SignedData on the wire; per crx3.proto the
    // crx_id is the first 128 bits of SHA-256(public_key), the same
    // derivation Chromium uses for both versions
    // (crx_verifier.cc GetCrxIdFromPublicKey).
    let crx_id = if public_key.is_empty() {
        None
    } else {
        let digest = crate::util::sha256::sha256(public_key);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Some(id)
    };
    let archive = input.get(sig_end..).ok_or(Error::UnexpectedEof)?;
    Ok(Crx3Image {
        version: VERSION_CRX2,
        crx_id,
        proofs: alloc::vec![Crx3Proof {
            algorithm: ProofAlgorithm::RsaPkcs1,
            public_key: public_key.to_vec(),
            signature: signature.to_vec(),
        }],
        verified_contents: None,
        entries: zip_entries(archive)?,
    })
}

/// Decode a CRX file (version 2 or 3) into header metadata + ZIP
/// member entries.
pub fn decode(input: &[u8]) -> Result<Crx3Image, Error> {
    if input.len() < 12 || &input[..4] != MAGIC {
        return Err(Error::InvalidData("not a crx3 file"));
    }
    let version = u32::from_le_bytes(input[4..8].try_into().unwrap());
    if version == VERSION_CRX2 {
        return decode_crx2(input);
    }
    if version != VERSION {
        return Err(Error::InvalidData("crx3 unsupported version"));
    }
    let n = u32::from_le_bytes(input[8..12].try_into().unwrap()) as usize;
    if n > MAX_HEADER_LEN {
        return Err(Error::InvalidData("crx3 header too large"));
    }
    let header_end = 12usize.checked_add(n).ok_or(Error::UnexpectedEof)?;
    let header = input.get(12..header_end).ok_or(Error::UnexpectedEof)?;
    let archive = input.get(header_end..).ok_or(Error::UnexpectedEof)?;

    let mut proofs = Vec::new();
    let mut verified_contents = None;
    let mut signed_header_data: Option<Vec<u8>> = None;
    for_each_len_field(header, |field, val| {
        match field {
            F_RSA_PROOF => proofs.push(parse_proof(ProofAlgorithm::Sha256WithRsa, val)?),
            F_ECDSA_PROOF => proofs.push(parse_proof(ProofAlgorithm::Sha256WithEcdsa, val)?),
            F_VERIFIED_CONTENTS => verified_contents = Some(val.to_vec()),
            F_SIGNED_HEADER_DATA => signed_header_data = Some(val.to_vec()),
            _ => {}
        }
        Ok(())
    })?;
    let crx_id = match &signed_header_data {
        Some(d) => parse_signed_data(d)?,
        None => None,
    };

    let entries = zip_entries(archive)?;
    Ok(Crx3Image {
        version: VERSION,
        crx_id,
        proofs,
        verified_contents,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::zip::encode::ZipEncoder;

    // ---- protobuf writer for tests ----
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn len_field(field: u64, data: &[u8], out: &mut Vec<u8>) {
        varint(field << 3 | 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn proof_msg(key: &[u8], sig: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(F_PUBLIC_KEY as u64, key, &mut m);
        len_field(F_SIGNATURE as u64, sig, &mut m);
        m
    }

    fn signed_data_msg(id: &[u8; 16]) -> Vec<u8> {
        let mut m = Vec::new();
        len_field(F_CRX_ID as u64, id, &mut m);
        m
    }

    fn build(header: &[u8], zip: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&VERSION.to_le_bytes());
        f.extend_from_slice(&(header.len() as u32).to_le_bytes());
        f.extend_from_slice(header);
        f.extend_from_slice(zip);
        f
    }

    fn zip_bytes() -> Vec<u8> {
        let mut e = ZipEncoder::new();
        e.add_file("manifest.json", b"{}");
        e.add_file("content.js", b"console.log(1)");
        e.finish().unwrap()
    }

    fn build_crx2(key: &[u8], sig: &[u8], zip: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&VERSION_CRX2.to_le_bytes());
        f.extend_from_slice(&(key.len() as u32).to_le_bytes());
        f.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        f.extend_from_slice(key);
        f.extend_from_slice(sig);
        f.extend_from_slice(zip);
        f
    }

    #[test]
    fn decodes_crx2() {
        let img = decode(&build_crx2(b"RSAPUB2", b"RSASIG2", &zip_bytes())).unwrap();
        assert_eq!(img.version, 2);
        let digest = crate::util::sha256::sha256(b"RSAPUB2");
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        assert_eq!(img.crx_id, Some(id));
        assert_eq!(img.verified_contents, None);
        assert_eq!(img.proofs.len(), 1);
        assert_eq!(img.proofs[0].algorithm, ProofAlgorithm::RsaPkcs1);
        assert_eq!(img.proofs[0].public_key, b"RSAPUB2");
        assert_eq!(img.proofs[0].signature, b"RSASIG2");
        assert_eq!(img.entries.len(), 2);
        assert_eq!(img.entries[0].name, "manifest.json");
        assert_eq!(img.entries[0].data, b"{}");
        assert_eq!(img.entries[1].data, b"console.log(1)");
    }

    #[test]
    fn crx2_crx_id_derived_from_pubkey() {
        // CRX2 carries no SignedData; crx_id is derived as
        // SHA-256(public_key)[..16] like Chromium's
        // GetCrxIdFromPublicKey.
        let pubkey = b"fake-der-spki-v2";
        let digest = crate::util::sha256::sha256(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        let img = decode(&build_crx2(pubkey, b"RSASIG", &zip_bytes())).unwrap();
        assert_eq!(img.version, 2);
        assert_eq!(img.crx_id, Some(id));
    }

    #[test]
    fn rejects_truncated_crx2_header() {
        let z = zip_bytes();
        // fixed header shorter than the 16-byte CrxFileHeader
        let mut f = Vec::new();
        f.extend_from_slice(MAGIC);
        f.extend_from_slice(&VERSION_CRX2.to_le_bytes());
        f.extend_from_slice(&[0u8; 3]);
        assert!(decode(&f).is_err());
        // public key length past end of input
        let mut f = build_crx2(b"K", b"S", &z);
        f[8..12].copy_from_slice(&99999u32.to_le_bytes());
        assert!(decode(&f).is_err());
        // signature length past end of input
        let mut f = build_crx2(b"K", b"S", &z);
        f[12..16].copy_from_slice(&99999u32.to_le_bytes());
        assert!(decode(&f).is_err());
        // proof fields parse but the ZIP tail is cut short
        let mut f = build_crx2(b"K", b"S", &z);
        f.truncate(f.len() - 2);
        assert!(decode(&f).is_err());
    }

    #[test]
    fn decodes_header_and_zip() {
        let id = [7u8; 16];
        let mut hdr = Vec::new();
        len_field(
            F_RSA_PROOF as u64,
            &proof_msg(b"RSAPUB", b"RSASIG"),
            &mut hdr,
        );
        len_field(
            F_ECDSA_PROOF as u64,
            &proof_msg(b"ECPUB", b"ECSIG"),
            &mut hdr,
        );
        len_field(F_VERIFIED_CONTENTS as u64, b"VC", &mut hdr);
        len_field(F_SIGNED_HEADER_DATA as u64, &signed_data_msg(&id), &mut hdr);
        let img = decode(&build(&hdr, &zip_bytes())).unwrap();
        assert_eq!(img.crx_id, Some(id));
        assert_eq!(img.proofs.len(), 2);
        assert_eq!(img.proofs[0].algorithm, ProofAlgorithm::Sha256WithRsa);
        assert_eq!(img.proofs[0].public_key, b"RSAPUB");
        assert_eq!(img.proofs[0].signature, b"RSASIG");
        assert_eq!(img.proofs[1].algorithm, ProofAlgorithm::Sha256WithEcdsa);
        assert_eq!(img.verified_contents.as_deref(), Some(&b"VC"[..]));
        assert_eq!(img.entries.len(), 2);
        assert_eq!(img.entries[0].name, "manifest.json");
        assert_eq!(img.entries[0].data, b"{}");
        assert_eq!(img.entries[1].data, b"console.log(1)");
    }

    #[test]
    fn decodes_headerless_crx() {
        // A minimal CRX3 with an empty header still decodes the ZIP.
        let img = decode(&build(&[], &zip_bytes())).unwrap();
        assert_eq!(img.crx_id, None);
        assert!(img.proofs.is_empty());
        assert_eq!(img.entries.len(), 2);
    }

    #[test]
    fn rejects_bad_inputs() {
        let z = zip_bytes();
        // bad magic
        let mut f = build(&[], &z);
        f[0] = b'X';
        assert!(decode(&f).is_err());
        // bad version
        let mut f = build(&[], &z);
        f[4] = 2;
        assert!(decode(&f).is_err());
        // header length beyond input
        let mut f = build(&[], &z);
        f[8..12].copy_from_slice(&99999u32.to_le_bytes());
        assert!(decode(&f).is_err());
        // truncated protobuf (varint without terminator)
        let hdr = alloc::vec![0xFF, 0xFF];
        assert!(decode(&build(&hdr, &z)).is_err());
    }

    #[test]
    fn crx_id_matches_rsa_pubkey() {
        // crx_id == SHA-256(proof public_key)[..16] verifies as true.
        let pubkey = b"fake-der-spki";
        let digest = crate::util::sha256::sha256(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        let mut hdr = Vec::new();
        len_field(F_RSA_PROOF as u64, &proof_msg(pubkey, b"SIG"), &mut hdr);
        len_field(F_SIGNED_HEADER_DATA as u64, &signed_data_msg(&id), &mut hdr);
        let img = decode(&build(&hdr, &zip_bytes())).unwrap();
        assert_eq!(img.verify_crx_id(), Some(true));
    }

    #[test]
    fn crx_id_mismatch_reported() {
        // A crx_id derived from a different key reports Some(false)
        // without rejecting the archive.
        let digest = crate::util::sha256::sha256(b"other-key");
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        let mut hdr = Vec::new();
        len_field(
            F_RSA_PROOF as u64,
            &proof_msg(b"proof-key", b"SIG"),
            &mut hdr,
        );
        len_field(F_SIGNED_HEADER_DATA as u64, &signed_data_msg(&id), &mut hdr);
        let img = decode(&build(&hdr, &zip_bytes())).unwrap();
        assert_eq!(img.verify_crx_id(), Some(false));
    }

    #[test]
    fn crx_id_none_when_no_signed_data() {
        // No signed_header_data at all: the check is not applicable.
        let mut hdr = Vec::new();
        len_field(F_RSA_PROOF as u64, &proof_msg(b"K", b"S"), &mut hdr);
        let img = decode(&build(&hdr, &zip_bytes())).unwrap();
        assert_eq!(img.verify_crx_id(), None);

        // crx_id present but only an ECDSA proof: no RSA key to check.
        let mut hdr = Vec::new();
        len_field(F_ECDSA_PROOF as u64, &proof_msg(b"EC", b"S"), &mut hdr);
        len_field(
            F_SIGNED_HEADER_DATA as u64,
            &signed_data_msg(&[9u8; 16]),
            &mut hdr,
        );
        let img = decode(&build(&hdr, &zip_bytes())).unwrap();
        assert_eq!(img.verify_crx_id(), None);
    }
}
