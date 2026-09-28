//! CRX3 container decoding.
//!
//! Layout reference: `components/crx_file/crx3.proto` (snapshot in
//! `docs/spec/sources/crx3.proto`). The file is `Cr24` magic, a
//! little-endian version (3), a little-endian header length N, an
//! N-octet protobuf `CrxFileHeader`, then a ZIP archive.

use alloc::string::String;
use alloc::vec::Vec;

use crate::archive::zip;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"Cr24";
const VERSION: u32 = 3;
/// Upper bound on the protobuf header length; the spec tells clients
/// to reject an N too large to safely hold in memory.
const MAX_HEADER_LEN: usize = 16 * 1024 * 1024;

// CrxFileHeader field numbers.
const F_RSA_PROOF: u32 = 2;
const F_ECDSA_PROOF: u32 = 3;
const F_VERIFIED_CONTENTS: u32 = 4;
const F_SIGNED_HEADER_DATA: u32 = 10000;

// AsymmetricKeyProof / SignedData field numbers.
const F_PUBLIC_KEY: u32 = 1;
const F_SIGNATURE: u32 = 2;
const F_CRX_ID: u32 = 1;

/// Signing algorithm of an [`AsymmetricKeyProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofAlgorithm {
    /// `sha256_with_rsa` — RSA-PSS, X.509 SubjectPublicKeyInfo key.
    Sha256WithRsa,
    /// `sha256_with_ecdsa` — NIST P-256, named-curve public key.
    Sha256WithEcdsa,
}

/// A parsed `AsymmetricKeyProof` message. The signature is **not**
/// verified by this decoder.
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

/// Decoded CRX3 file.
#[derive(Debug)]
pub struct Crx3Image {
    /// 16-byte extension id from `SignedData.crx_id`, if present.
    pub crx_id: Option<[u8; 16]>,
    /// Signing proofs carried by the header (unverified).
    pub proofs: Vec<Crx3Proof>,
    /// GZIP-compressed verified-contents JSON, if present.
    pub verified_contents: Option<Vec<u8>>,
    /// Entries decoded from the embedded ZIP archive.
    pub entries: Vec<Crx3Entry>,
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

/// Decode a CRX3 file into header metadata + ZIP member entries.
pub fn decode(input: &[u8]) -> Result<Crx3Image, Error> {
    if input.len() < 12 || &input[..4] != MAGIC {
        return Err(Error::InvalidData("not a crx3 file"));
    }
    let version = u32::from_le_bytes(input[4..8].try_into().unwrap());
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

    let entries = zip::decode::decode(archive)?
        .into_iter()
        .map(|e| Crx3Entry {
            name: e.name,
            data: e.data,
        })
        .collect();
    Ok(Crx3Image {
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
}
