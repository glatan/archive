//! PEA 1.x archive decoding.
//!
//! Layout reference: PeaZip `pea_utils.pas`
//! (`pea_archive_hdr`/`pea_stream_hdr`/`trigger_eoa`,
//! `pea_parse_archive_header`/`pea_parse_stream_header`) and
//! `pea.pas` (object write/read loops, `compress_file`,
//! `nocompress_file`), snapshots in `docs/spec/sources/`.
//! All multi-byte integer fields are little-endian.

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::zlib;
use crate::error::Error;
use crate::util;
use crate::util::aes256::{Aes128, Aes256};

pub(crate) const MAGIC: u8 = 0xEA;
pub(crate) const VER: u8 = 1;
pub(crate) const REV: u8 = 6;
/// Compression block buffer in the reference implementation.
pub(crate) const WBUFSIZE: usize = 1048576;
pub(crate) const FA_DIRECTORY: u32 = 0x10;

/// Control/integrity algorithm of a PEA stream, object, or volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeaAlgo {
    /// No control tag.
    None,
    /// Adler-32 tag.
    Adler32,
    /// CRC-32 tag.
    Crc32,
    /// CRC-64 tag.
    Crc64,
    /// MD5 tag.
    Md5,
    /// RIPEMD-160 tag (parsed, not verified).
    Ripemd160,
    /// SHA-1 tag.
    Sha1,
    /// SHA-256 tag.
    Sha256,
    /// SHA-512 tag (parsed, not verified).
    Sha512,
    /// Whirlpool tag (parsed, not verified).
    Whirlpool,
    /// SHA3-256 tag (parsed, not verified).
    Sha3_256,
    /// SHA3-512 tag (parsed, not verified).
    Sha3_512,
    /// BLAKE2s tag (parsed, not verified).
    Blake2s,
    /// BLAKE2b tag (parsed, not verified).
    Blake2b,
    /// Authenticated-encryption stream control; 48/49/65 are AES
    /// algorithms decoded with a password, the rest unsupported.
    Encrypted(u8),
}

impl PeaAlgo {
    fn from_code(code: u8) -> Result<PeaAlgo, Error> {
        Ok(match code {
            0 => PeaAlgo::None,
            1 => PeaAlgo::Adler32,
            2 => PeaAlgo::Crc32,
            3 => PeaAlgo::Crc64,
            16 => PeaAlgo::Md5,
            17 => PeaAlgo::Ripemd160,
            18 => PeaAlgo::Sha1,
            19 => PeaAlgo::Sha256,
            20 => PeaAlgo::Sha512,
            21 => PeaAlgo::Whirlpool,
            22 => PeaAlgo::Sha3_256,
            23 => PeaAlgo::Sha3_512,
            24 => PeaAlgo::Blake2s,
            25 => PeaAlgo::Blake2b,
            c if matches!(c, 48..=51 | 65..=76) => PeaAlgo::Encrypted(c),
            _ => return Err(Error::InvalidData("pea unknown control algorithm")),
        })
    }

    /// Control-algorithm code byte (inverse of `from_code`).
    pub(crate) fn code(self) -> u8 {
        match self {
            PeaAlgo::None => 0,
            PeaAlgo::Adler32 => 1,
            PeaAlgo::Crc32 => 2,
            PeaAlgo::Crc64 => 3,
            PeaAlgo::Md5 => 16,
            PeaAlgo::Ripemd160 => 17,
            PeaAlgo::Sha1 => 18,
            PeaAlgo::Sha256 => 19,
            PeaAlgo::Sha512 => 20,
            PeaAlgo::Whirlpool => 21,
            PeaAlgo::Sha3_256 => 22,
            PeaAlgo::Sha3_512 => 23,
            PeaAlgo::Blake2s => 24,
            PeaAlgo::Blake2b => 25,
            PeaAlgo::Encrypted(c) => c,
        }
    }

    /// Tag size in bytes.
    pub(crate) fn tag_size(self) -> usize {
        match self {
            PeaAlgo::None => 0,
            PeaAlgo::Adler32 | PeaAlgo::Crc32 => 4,
            PeaAlgo::Crc64 => 8,
            PeaAlgo::Md5 => 16,
            PeaAlgo::Ripemd160 | PeaAlgo::Sha1 => 20,
            PeaAlgo::Sha256 | PeaAlgo::Sha3_256 | PeaAlgo::Blake2s => 32,
            PeaAlgo::Sha512 | PeaAlgo::Whirlpool | PeaAlgo::Sha3_512 | PeaAlgo::Blake2b => 64,
            PeaAlgo::Encrypted(_) => 16,
        }
    }

    /// Compute the tag over `data` when this crate implements the
    /// algorithm; `None` for algorithms we parse but cannot verify.
    pub(crate) fn compute(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            PeaAlgo::Adler32 => Some(util::adler32::adler32(data).to_le_bytes().to_vec()),
            PeaAlgo::Crc32 => Some(util::crc32::crc32(data).to_le_bytes().to_vec()),
            PeaAlgo::Crc64 => Some(util::crc64::crc64(data).to_le_bytes().to_vec()),
            PeaAlgo::Md5 => Some(util::md5::md5(data).to_vec()),
            PeaAlgo::Sha1 => Some(util::sha1::sha1(data).to_vec()),
            PeaAlgo::Sha256 => Some(util::sha256::sha256(data).to_vec()),
            _ => None,
        }
    }
}

/// A decoded PEA object (file or directory).
#[derive(Debug, Clone)]
pub struct PeaEntry {
    /// Qualified object name as stored (ANSI bytes, lossy-decoded).
    pub name: String,
    /// True for directory objects.
    pub is_dir: bool,
    /// DOS-format last-modification timestamp as stored.
    pub mtime: u32,
    /// Platform attribute word as stored.
    pub attributes: u32,
    /// File contents; empty for directories.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for PeaEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decoded PEA archive.
#[derive(Debug)]
pub struct PeaImage {
    /// Format version/revision from the archive header.
    pub version: (u8, u8),
    /// Entries across all streams, in storage order.
    pub entries: Vec<PeaEntry>,
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::UnexpectedEof)?;
        let s = self.input.get(self.pos..end).ok_or(Error::UnexpectedEof)?;
        self.pos = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn verify_tag(algo: PeaAlgo, tag: &[u8], covered: &[u8]) -> Result<(), Error> {
    if let Some(expected) = algo.compute(covered)
        && expected.as_slice() != tag
    {
        return Err(Error::InvalidData("pea integrity tag mismatch"));
    }
    Ok(())
}

/// Decode one compressed file-data area (PCOMPRESS1-3):
/// blocks of `[u32 compsize][compsize bytes]`; `compsize` equal to
/// the expected output size means a stored (uncompressed) block;
/// a final u32 gives the uncompressed size of the last block.
fn decode_compressed(
    r: &mut Reader,
    file_size: u64,
    obj_bytes: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    let mut remaining = file_size;
    let mut out = Vec::with_capacity(remaining.min(1 << 24) as usize);
    let mut last_out = 0usize;
    while remaining > 0 {
        let compsize = r.u32()? as usize;
        let block = r.take(compsize)?;
        obj_bytes.extend_from_slice(&(compsize as u32).to_le_bytes());
        let expected = remaining.min(WBUFSIZE as u64) as usize;
        let chunk = if compsize == expected {
            block.to_vec()
        } else {
            let d = zlib::decode::decode(block)
                .map_err(|_| Error::InvalidData("pea bad compressed block"))?;
            if d.len() != expected {
                return Err(Error::InvalidData("pea bad uncompressed block size"));
            }
            d
        };
        obj_bytes.extend_from_slice(&chunk);
        remaining -= chunk.len() as u64;
        last_out = chunk.len();
        out.extend_from_slice(&chunk);
    }
    let declared = r.u32()?;
    obj_bytes.extend_from_slice(&declared.to_le_bytes());
    if declared as usize != last_out {
        return Err(Error::InvalidData("pea last block size mismatch"));
    }
    Ok(out)
}

struct StreamProps {
    compression: u8,
    stream_algo: PeaAlgo,
    obj_algo: PeaAlgo,
}

fn parse_stream_header(r: &mut Reader, password: bool) -> Result<StreamProps, Error> {
    let h = r.take(10)?;
    if h[0] != 0 || h[1] != 0 || &h[2..5] != b"POD" || h[5] != 0 {
        return Err(Error::InvalidData("pea bad stream header"));
    }
    if h[6] > 3 {
        return Err(Error::InvalidData("pea unknown compression scheme"));
    }
    let stream_algo = match h[8] {
        c @ (48 | 49 | 65) => {
            if !password {
                return Err(Error::InvalidData(
                    "pea encrypted stream requires a password",
                ));
            }
            PeaAlgo::Encrypted(c)
        }
        // Twofish/Serpent EAX and the cascade modes are not supported
        50 | 51 | 66..=76 => {
            return Err(Error::Unsupported("pea encrypted control algorithm"));
        }
        c => PeaAlgo::from_code(c)?,
    };
    let obj_algo = PeaAlgo::from_code(h[9])?;
    if let PeaAlgo::Encrypted(_) = obj_algo {
        return Err(Error::Unsupported("pea encrypted object control algorithm"));
    }
    Ok(StreamProps {
        compression: h[6],
        stream_algo,
        obj_algo,
    })
}

/// Decode a PEA 1.x archive.
pub fn decode(input: &[u8]) -> Result<PeaImage, Error> {
    decode_impl(input, true, None)
}

/// Decode a PEA 1.x archive using a password for streams protected
/// with the AES-128 HMAC (48), AES-128 EAX (49), or AES-256 EAX (65)
/// authenticated-encryption control algorithms.
pub fn decode_with_password(input: &[u8], password: &str) -> Result<PeaImage, Error> {
    decode_impl(input, true, Some(password.as_bytes()))
}

/// [`decode_with_password`] taking the password as raw bytes.
pub fn decode_with_password_bytes(input: &[u8], password: &[u8]) -> Result<PeaImage, Error> {
    decode_impl(input, true, Some(password))
}

/// Verify and strip the trailing volume control tag of one volume
/// (`volume_authsize` bytes; the volume control algorithm resets
/// per volume, so the tag covers that volume's own bytes only).
/// Returns the volume body without the tag.
fn strip_volume_tag(algo: PeaAlgo, part: &[u8]) -> Result<&[u8], Error> {
    let n = algo.tag_size();
    let body_len = part.len().checked_sub(n).ok_or(Error::UnexpectedEof)?;
    let (body, tag) = part.split_at(body_len);
    verify_tag(algo, tag, body)?;
    Ok(body)
}

/// Decode a split (multi-volume) PEA archive — fixed-size `.pea`
/// volumes concatenated in volume order — into memory. Each volume
/// ends with a `volume_authsize`-byte control tag over that
/// volume's own bytes; the tags are verified (when the algorithm
/// is implemented) and stripped, then the bodies are decoded as
/// one archive.
///
/// Empty parts are rejected; a single part is decoded as [`decode`].
pub fn decode_parts(parts: &[&[u8]]) -> Result<PeaImage, Error> {
    decode_parts_impl(parts, None)
}

/// [`decode_parts`] with a password for encrypted streams.
pub fn decode_parts_with_password_bytes(
    parts: &[&[u8]],
    password: &[u8],
) -> Result<PeaImage, Error> {
    decode_parts_impl(parts, Some(password))
}

fn decode_parts_impl(parts: &[&[u8]], password: Option<&[u8]>) -> Result<PeaImage, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidData("pea empty archive part"));
    }
    if parts.len() == 1 {
        return decode_impl(parts[0], true, password);
    }
    let first = parts[0];
    if first.len() < 4 || first[0] != MAGIC {
        return Err(Error::InvalidData("not a pea archive"));
    }
    let volume_algo = PeaAlgo::from_code(first[3])?;
    if let PeaAlgo::Encrypted(_) = volume_algo {
        return Err(Error::Unsupported("pea encrypted volume control algorithm"));
    }
    let mut input = Vec::new();
    for p in parts {
        input.extend_from_slice(strip_volume_tag(volume_algo, p)?);
    }
    decode_impl(&input, false, password)
}

fn decode_impl(input: &[u8], volume_tag: bool, password: Option<&[u8]>) -> Result<PeaImage, Error> {
    if input.len() < 10 || input[0] != MAGIC {
        return Err(Error::InvalidData("not a pea archive"));
    }
    let (ver, rev) = (input[1], input[2]);
    if ver > VER || (ver == VER && rev > REV) {
        return Err(Error::InvalidData("pea revision not supported"));
    }
    let volume_algo = PeaAlgo::from_code(input[3])?;
    if let PeaAlgo::Encrypted(_) = volume_algo {
        return Err(Error::Unsupported("pea encrypted volume control algorithm"));
    }

    let mut r = Reader { input, pos: 10 };
    let mut entries = Vec::new();
    let mut streams = 0u32;

    loop {
        streams += 1;
        if streams > 1024 {
            return Err(Error::InvalidData("pea too many streams"));
        }
        let hdr_pos = r.pos;
        let props = parse_stream_header(&mut r, password.is_some())?;
        let stream_hdr = &input[hdr_pos..r.pos];

        let next_stream = match props.stream_algo {
            PeaAlgo::Encrypted(code) => {
                // 16-byte FCA crypto subheader: two zeroed signature
                // bytes, the 96-bit KDF salt, the LE pw verifier
                let sub = r.take(16)?;
                let crypto = init_stream_crypto(
                    code,
                    password.unwrap_or_default(),
                    &input[..10],
                    stream_hdr,
                    sub,
                )?;
                let ct_start = r.pos;
                // the CTR keystream is position independent: decrypt
                // the remaining input, then the plaintext object
                // parser locates the end of the authenticated
                // ciphertext (EOA trigger) and the 16-byte tag
                let plain = crypto.decrypt(&input[ct_start..]);
                let mut pr = Reader {
                    input: plain.as_slice(),
                    pos: 0,
                };
                let next = read_objects(&mut pr, &props, &mut entries)?;
                let ct_end = ct_start.checked_add(pr.pos).ok_or(Error::UnexpectedEof)?;
                let tag_end = ct_end.checked_add(16).ok_or(Error::UnexpectedEof)?;
                let stag = input.get(ct_end..tag_end).ok_or(Error::UnexpectedEof)?;
                crypto.verify(&input[ct_start..ct_end], stag)?;
                r.pos = tag_end;
                next
            }
            _ => {
                let next = read_objects(&mut r, &props, &mut entries)?;
                if !next {
                    // stream-level control tag covers every byte from
                    // the start of the file through the EOA trigger
                    let stag = r.take(props.stream_algo.tag_size())?;
                    verify_tag(props.stream_algo, stag, &input[..r.pos - stag.len()])?;
                }
                next
            }
        };
        if !next_stream {
            break;
        }
    }

    if volume_tag {
        // trailing volume control tag covers all preceding bytes
        let vtag = r.take(volume_algo.tag_size())?;
        verify_tag(volume_algo, vtag, &input[..r.pos - vtag.len()])?;
    }
    if r.pos != input.len() {
        return Err(Error::InvalidData("pea trailing garbage"));
    }

    Ok(PeaImage {
        version: (ver, rev),
        entries,
    })
}

/// Stream cipher state for the AES authenticated-encryption control
/// algorithms (Ehrhardt fcrypta.pas / fcaes256.pas). PBKDF2 derives
/// the cipher key, the HMAC key or EAX nonce, and a 16-bit password
/// verifier from the crypto subheader salt.
enum PeaCrypto {
    /// Algorithm 48: AES-128 CTR + truncated HMAC-SHA1.
    Hmac128 { cipher: Aes128, mac_key: [u8; 16] },
    /// Algorithm 49: AES-128 EAX with a 16-byte nonce.
    Eax128 { cipher: Aes128, nonce: [u8; 16] },
    /// Algorithm 65: AES-256 EAX with a 32-byte nonce.
    Eax256 { cipher: Aes256, nonce: [u8; 32] },
}

impl PeaCrypto {
    /// Decrypt a ciphertext tail; trailing bytes past the end of the
    /// authenticated region decrypt to garbage and are ignored.
    fn decrypt(&self, tail: &[u8]) -> Vec<u8> {
        match self {
            // FCA HMAC mode runs AES-CTR from an all-zero counter
            PeaCrypto::Hmac128 { cipher, .. } => util::eax::ctr_apply(cipher, &[0; 16], tail),
            PeaCrypto::Eax128 { cipher, nonce } => {
                util::eax::ctr_apply(cipher, &util::eax::eax_nonce_tag(cipher, nonce), tail)
            }
            PeaCrypto::Eax256 { cipher, nonce } => {
                util::eax::ctr_apply(cipher, &util::eax::eax_nonce_tag(cipher, nonce), tail)
            }
        }
    }

    /// Verify the 16-byte stream authentication tag over the
    /// ciphertext region.
    fn verify(&self, ciphertext: &[u8], tag: &[u8]) -> Result<(), Error> {
        match self {
            // FCA HMAC tag is the first 16 bytes of HMAC-SHA1 over
            // the ciphertext
            PeaCrypto::Hmac128 { mac_key, .. } => {
                let mac = util::pbkdf2::hmac(util::sha1::sha1, mac_key, ciphertext);
                if mac[..16] != *tag {
                    return Err(Error::InvalidData("pea stream authentication failed"));
                }
                Ok(())
            }
            PeaCrypto::Eax128 { cipher, nonce } => util::eax::eax_verify_tag(
                cipher,
                nonce,
                &[],
                ciphertext,
                tag.try_into().map_err(|_| Error::UnexpectedEof)?,
            ),
            PeaCrypto::Eax256 { cipher, nonce } => util::eax::eax_verify_tag(
                cipher,
                nonce,
                &[],
                ciphertext,
                tag.try_into().map_err(|_| Error::UnexpectedEof)?,
            ),
        }
    }
}

/// Derive the FCA extended key for an AES encrypted stream and check
/// the password verifier stored in the crypto subheader. The KDF
/// password is the user password followed by the archive header, the
/// stream header, and the two zeroed signature bytes of the crypto
/// subheader (pea.pas init_AE*_control_algo).
fn init_stream_crypto(
    code: u8,
    password: &[u8],
    archive_hdr: &[u8],
    stream_hdr: &[u8],
    sub: &[u8],
) -> Result<PeaCrypto, Error> {
    let mut pw = Vec::with_capacity(password.len() + 22);
    pw.extend_from_slice(password);
    pw.extend_from_slice(archive_hdr);
    pw.extend_from_slice(stream_hdr);
    pw.extend_from_slice(&sub[..2]);
    let salt = &sub[2..14];
    let stored_ver = u16::from_le_bytes(sub[14..16].try_into().unwrap());
    match code {
        // TXKey: AES-128 key || HMAC key or EAX nonce || verifier
        48 | 49 => {
            let dk = util::pbkdf2::pbkdf2(util::sha1::sha1, &pw, salt, 1000, 34);
            if u16::from_le_bytes(dk[32..34].try_into().unwrap()) != stored_ver {
                return Err(Error::InvalidData("pea wrong password"));
            }
            let cipher = Aes128::new(dk[..16].try_into().unwrap());
            let hk: [u8; 16] = dk[16..32].try_into().unwrap();
            Ok(if code == 48 {
                PeaCrypto::Hmac128 {
                    cipher,
                    mac_key: hk,
                }
            } else {
                PeaCrypto::Eax128 { cipher, nonce: hk }
            })
        }
        // TX256Key: AES-256 key || 32-byte EAX nonce || verifier,
        // derived with PBKDF2-HMAC-Whirlpool
        65 => {
            let dk = util::pbkdf2::pbkdf2(util::whirlpool::whirlpool, &pw, salt, 1000, 66);
            if u16::from_le_bytes(dk[64..66].try_into().unwrap()) != stored_ver {
                return Err(Error::InvalidData("pea wrong password"));
            }
            Ok(PeaCrypto::Eax256 {
                cipher: Aes256::new(dk[..32].try_into().unwrap()),
                nonce: dk[32..64].try_into().unwrap(),
            })
        }
        _ => Err(Error::Unsupported("pea encrypted control algorithm")),
    }
}

/// Object records of one stream up to its trigger object; returns
/// true when a POD trigger indicates a further stream follows.
fn read_objects(
    r: &mut Reader<'_>,
    props: &StreamProps,
    entries: &mut Vec<PeaEntry>,
) -> Result<bool, Error> {
    loop {
        let name_len = r.u16()? as usize;
        if name_len == 0 {
            // trigger object: 4-byte message + NUL
            let t = r.take(4)?;
            match t {
                b"POD\0" => {
                    // another stream header follows immediately
                    return Ok(true);
                }
                b"EOS\0" | b"EOA\0" => return Ok(false),
                _ => return Err(Error::InvalidData("pea unknown trigger")),
            }
        }
        let name = String::from_utf8_lossy(r.take(name_len)?).into_owned();
        let mtime = r.u32()?;
        let attributes = r.u32()?;
        // object-control coverage: header fields (+ file size),
        // then object data as fed by the reference writer
        let mut covered = Vec::with_capacity(name_len + 18);
        covered.extend_from_slice(&(name_len as u16).to_le_bytes());
        covered.extend_from_slice(name.as_bytes());
        covered.extend_from_slice(&mtime.to_le_bytes());
        covered.extend_from_slice(&attributes.to_le_bytes());

        let (is_dir, data) = if attributes & FA_DIRECTORY != 0 {
            (true, Vec::new())
        } else {
            let file_size = r.u64()?;
            covered.extend_from_slice(&file_size.to_le_bytes());
            let data = if file_size == 0 {
                Vec::new()
            } else if props.compression == 0 {
                let d = r.take(file_size as usize)?.to_vec();
                covered.extend_from_slice(&d);
                d
            } else {
                decode_compressed(r, file_size, &mut covered)?
            };
            (false, data)
        };

        let tag = r.take(props.obj_algo.tag_size())?;
        verify_tag(props.obj_algo, tag, &covered)?;
        entries.push(PeaEntry {
            name,
            is_dir,
            mtime,
            attributes,
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // minimal PEA writer mirroring the reference layout
    fn w16(v: u16, o: &mut Vec<u8>) {
        o.extend_from_slice(&v.to_le_bytes());
    }
    fn w32(v: u32, o: &mut Vec<u8>) {
        o.extend_from_slice(&v.to_le_bytes());
    }
    fn w64(v: u64, o: &mut Vec<u8>) {
        o.extend_from_slice(&v.to_le_bytes());
    }

    fn tag(algo: PeaAlgo, covered: &[u8]) -> Vec<u8> {
        // unverifiable algorithms get a nonzero garbage tag, proving
        // the decoder skips tag bytes instead of checking them
        algo.compute(covered)
            .unwrap_or_else(|| alloc::vec![0xA5u8; algo.tag_size()])
    }

    // stream body: object records + object tags + EOA trigger
    fn objects_blob(
        entries: &[(&str, bool, &[u8])],
        obj_algo: PeaAlgo,
        compression: u8,
    ) -> Vec<u8> {
        let mut f = Vec::new();
        for (name, is_dir, data) in entries {
            w16(name.len() as u16, &mut f);
            f.extend_from_slice(name.as_bytes());
            w32(0x5432, &mut f);
            w32(if *is_dir { FA_DIRECTORY } else { 0 }, &mut f);
            let mut covered = Vec::new();
            covered.extend_from_slice(&(name.len() as u16).to_le_bytes());
            covered.extend_from_slice(name.as_bytes());
            covered.extend_from_slice(&0x5432u32.to_le_bytes());
            covered.extend_from_slice(&(if *is_dir { FA_DIRECTORY } else { 0 }).to_le_bytes());
            if !is_dir {
                w64(data.len() as u64, &mut f);
                covered.extend_from_slice(&(data.len() as u64).to_le_bytes());
                if compression == 0 {
                    f.extend_from_slice(data);
                    covered.extend_from_slice(data);
                } else {
                    let comp = zlib::encode::encode(data);
                    w32(comp.len() as u32, &mut f);
                    f.extend_from_slice(&comp);
                    covered.extend_from_slice(&(comp.len() as u32).to_le_bytes());
                    covered.extend_from_slice(data);
                    w32(data.len() as u32, &mut f);
                    covered.extend_from_slice(&(data.len() as u32).to_le_bytes());
                }
            }
            f.extend_from_slice(&tag(obj_algo, &covered));
        }
        f.extend_from_slice(&[0, 0, b'E', b'O', b'A', 0]);
        f
    }

    fn build(entries: &[(&str, bool, &[u8])], obj_algo: PeaAlgo, compression: u8) -> Vec<u8> {
        // archive header
        let mut f = alloc::vec![
            MAGIC, VER, REV, 2, /* volume algo: CRC32 */
            0, 1, 1, 1, 0, 0
        ];
        // stream header
        f.extend_from_slice(&[0, 0, b'P', b'O', b'D', 0]);
        f.push(compression);
        f.push(0);
        f.push(2); // stream algo: CRC32
        f.push(obj_algo.code());
        f.extend_from_slice(&objects_blob(entries, obj_algo, compression));
        // stream tag: CRC32 over everything so far
        w32(util::crc32::crc32(&f), &mut f);
        // volume tag: CRC32 over everything so far
        w32(util::crc32::crc32(&f), &mut f);
        f
    }

    // encrypted-stream writer mirroring the reference layout:
    // [00 00][96-bit salt][LE pw verifier] || CTR/EAX ciphertext ||
    // 16-byte stream authentication tag
    fn build_encrypted(
        entries: &[(&str, bool, &[u8])],
        obj_algo: PeaAlgo,
        compression: u8,
        code: u8,
        password: &[u8],
        salt: &[u8; 12],
    ) -> Vec<u8> {
        let mut f = alloc::vec![
            MAGIC, VER, REV, 2, /* volume algo: CRC32 */
            0, 1, 1, 1, 0, 0
        ];
        let archive_hdr = f.clone();
        f.extend_from_slice(&[0, 0, b'P', b'O', b'D', 0]);
        f.push(compression);
        f.push(0);
        f.push(code);
        f.push(obj_algo.code());
        let stream_hdr = f[10..20].to_vec();
        let plain = objects_blob(entries, obj_algo, compression);
        // KDF password: pw || archive header || stream header || the
        // two zeroed signature bytes of the crypto subheader
        let mut pw = password.to_vec();
        pw.extend_from_slice(&archive_hdr);
        pw.extend_from_slice(&stream_hdr);
        pw.extend_from_slice(&[0, 0]);
        let (ct, tag, ver) = match code {
            48 => {
                let dk = util::pbkdf2::pbkdf2(util::sha1::sha1, &pw, salt, 1000, 34);
                let cipher = Aes128::new(dk[..16].try_into().unwrap());
                let ct = util::eax::ctr_apply(&cipher, &[0; 16], &plain);
                let mac = util::pbkdf2::hmac(util::sha1::sha1, &dk[16..32], &ct);
                (ct, mac[..16].to_vec(), dk[32..34].to_vec())
            }
            49 => {
                let dk = util::pbkdf2::pbkdf2(util::sha1::sha1, &pw, salt, 1000, 34);
                let cipher = Aes128::new(dk[..16].try_into().unwrap());
                let (ct, tag) = util::eax::eax_encrypt(&cipher, &dk[16..32], &[], &plain);
                (ct, tag.to_vec(), dk[32..34].to_vec())
            }
            _ => {
                let dk = util::pbkdf2::pbkdf2(util::whirlpool::whirlpool, &pw, salt, 1000, 66);
                let cipher = Aes256::new(dk[..32].try_into().unwrap());
                let (ct, tag) = util::eax::eax_encrypt(&cipher, &dk[32..64], &[], &plain);
                (ct, tag.to_vec(), dk[64..66].to_vec())
            }
        };
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(salt);
        f.extend_from_slice(&ver);
        f.extend_from_slice(&ct);
        f.extend_from_slice(&tag);
        // volume tag: CRC32 over everything so far
        w32(util::crc32::crc32(&f), &mut f);
        f
    }

    #[test]
    fn decodes_stored_archive() {
        let f = build(
            &[
                ("dir", true, &[]),
                ("dir/file.txt", false, b"hello pea"),
                ("empty.bin", false, &[]),
            ],
            PeaAlgo::Crc32,
            0,
        );
        let img = decode(&f).unwrap();
        assert_eq!(img.version, (1, 6));
        assert_eq!(img.entries.len(), 3);
        assert!(img.entries[0].is_dir);
        assert_eq!(img.entries[1].name, "dir/file.txt");
        assert_eq!(img.entries[1].data, b"hello pea");
        assert_eq!(img.entries[2].data.len(), 0);
    }

    #[test]
    fn decodes_compressed_archive() {
        let data = b"compress me compress me compress me";
        let f = build(&[("f.bin", false, data)], PeaAlgo::None, 2);
        let img = decode(&f).unwrap();
        assert_eq!(img.entries[0].data, data);
    }

    #[test]
    fn rejects_bad_magic_version_trigger() {
        let mut f = build(&[("a", false, b"x")], PeaAlgo::None, 0);
        f[0] = 0;
        assert!(decode(&f).is_err());
        let mut f2 = build(&[("a", false, b"x")], PeaAlgo::None, 0);
        f2[2] = 99; // revision > 6
        assert!(decode(&f2).is_err());
        let mut f3 = build(&[("a", false, b"x")], PeaAlgo::None, 0);
        f3[8] = 99; // stream algo byte -> crypto unknown? actually stream header byte; corrupt POD
        f3[12] = b'X';
        assert!(decode(&f3).is_err());
    }

    #[test]
    fn rejects_tampered_tag() {
        let mut f = build(&[("a.txt", false, b"data")], PeaAlgo::Crc32, 0);
        // corrupt one byte inside the covered object region
        f[25] ^= 0xFF;
        assert!(decode(&f).is_err());
    }

    #[test]
    fn skips_unverified_object_tags() {
        // Algorithms we parse but cannot verify (codes 17, 20-25):
        // the tag is filled with garbage bytes by `build` and must be
        // skipped at exactly tag_size() length, not checked.
        for algo in [
            PeaAlgo::Ripemd160,
            PeaAlgo::Sha512,
            PeaAlgo::Whirlpool,
            PeaAlgo::Sha3_256,
            PeaAlgo::Sha3_512,
            PeaAlgo::Blake2s,
            PeaAlgo::Blake2b,
        ] {
            let f = build(
                &[("dir", true, &[]), ("f.bin", false, b"tagged data")],
                algo,
                0,
            );
            let img = decode(&f).unwrap();
            assert_eq!(img.entries.len(), 2);
            assert!(img.entries[0].is_dir);
            assert_eq!(img.entries[1].name, "f.bin");
            assert_eq!(img.entries[1].data, b"tagged data");
        }
    }

    #[test]
    fn skips_unverified_object_tags_compressed() {
        // Same skip behaviour with compressed object data.
        let data = b"compress and tag me compress and tag me";
        for algo in [PeaAlgo::Sha512, PeaAlgo::Blake2b] {
            let f = build(&[("f.bin", false, data)], algo, 2);
            let img = decode(&f).unwrap();
            assert_eq!(img.entries[0].data, data);
        }
    }

    #[test]
    fn rejects_truncated_object_tag() {
        // 64-byte SHA-512 object tag: hdr(10) + stream hdr(10) +
        // name_len(2) + name(5) + mtime(4) + attr(4) + fsize(8) + data(4)
        let f = build(&[("f.bin", false, b"data")], PeaAlgo::Sha512, 0);
        let tag_off = 10 + 10 + 2 + 5 + 4 + 4 + 8 + 4;
        let mut short = f.clone();
        short.drain(tag_off..tag_off + 32);
        assert!(decode(&short).is_err());
    }

    // split a logical stream into volume bodies at `cuts`, each
    // followed by its CRC32 volume tag (matching `build`'s header)
    fn volumes(stream: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut prev = 0;
        for &c in cuts.iter().chain(&[stream.len()]) {
            let body = &stream[prev..c];
            let mut v = body.to_vec();
            v.extend_from_slice(&util::crc32::crc32(body).to_le_bytes());
            out.push(v);
            prev = c;
        }
        out
    }

    #[test]
    fn decodes_multi_volume() {
        let f = build(
            &[("dir", true, &[]), ("dir/a.txt", false, b"volume data")],
            PeaAlgo::Crc32,
            0,
        );
        // drop the single-volume tag to get the logical stream
        let stream = &f[..f.len() - 4];
        for cuts in [&[12usize, 30][..], &[stream.len() / 2][..]] {
            let vs = volumes(stream, cuts);
            let parts: Vec<&[u8]> = vs.iter().map(Vec::as_slice).collect();
            let img = decode_parts(&parts).unwrap();
            assert_eq!(img.version, (1, 6));
            assert_eq!(img.entries.len(), 2);
            assert!(img.entries[0].is_dir);
            assert_eq!(img.entries[1].name, "dir/a.txt");
            assert_eq!(img.entries[1].data, b"volume data");
        }
        // a single part decodes like decode()
        let one = decode_parts(&[&f]).unwrap();
        assert_eq!(one.entries.len(), decode(&f).unwrap().entries.len());
    }

    #[test]
    fn rejects_bad_volume_tag() {
        let f = build(&[("a.txt", false, b"data")], PeaAlgo::Crc32, 0);
        let stream = &f[..f.len() - 4];
        let mut vs = volumes(stream, &[stream.len() / 2]);
        // corrupt the second volume's trailing tag
        let n = vs[1].len();
        vs[1][n - 1] ^= 0xFF;
        let parts: Vec<&[u8]> = vs.iter().map(Vec::as_slice).collect();
        assert!(matches!(decode_parts(&parts), Err(Error::InvalidData(_))));
        // corrupt a covered body byte in the first volume
        let mut vs = volumes(stream, &[stream.len() / 2]);
        vs[0][5] ^= 0xFF;
        let parts: Vec<&[u8]> = vs.iter().map(Vec::as_slice).collect();
        assert!(matches!(decode_parts(&parts), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_empty_volume_list() {
        let f = build(&[("a", false, b"x")], PeaAlgo::Crc32, 0);
        assert!(matches!(decode_parts(&[]), Err(Error::InvalidData(_))));
        assert!(matches!(
            decode_parts(&[&f[..20], &[]]),
            Err(Error::InvalidData(_))
        ));
        // first part too short to carry the archive header
        assert!(matches!(
            decode_parts(&[&f[..2], &f[2..]]),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn decodes_aes_hmac_stream() {
        let f = build_encrypted(
            &[("dir", true, &[]), ("dir/secret.txt", false, b"hidden pea")],
            PeaAlgo::Crc32,
            0,
            48,
            b"passphrase",
            &[0xA7; 12],
        );
        let img = decode_with_password(&f, "passphrase").unwrap();
        assert_eq!(img.entries.len(), 2);
        assert!(img.entries[0].is_dir);
        assert_eq!(img.entries[1].name, "dir/secret.txt");
        assert_eq!(img.entries[1].data, b"hidden pea");
    }

    #[test]
    fn decodes_aes_eax_stream() {
        let f = build_encrypted(
            &[("note.txt", false, b"eax payload")],
            PeaAlgo::Sha256,
            0,
            49,
            b"passphrase",
            &[0x31; 12],
        );
        let img = decode_with_password_bytes(&f, b"passphrase").unwrap();
        assert_eq!(img.entries.len(), 1);
        assert_eq!(img.entries[0].data, b"eax payload");
    }

    #[test]
    fn decodes_aes256_eax_stream() {
        let f = build_encrypted(
            &[("big.bin", false, b"eax256 payload")],
            PeaAlgo::Crc32,
            0,
            65,
            b"hunter2",
            &[0x55; 12],
        );
        let img = decode_with_password(&f, "hunter2").unwrap();
        assert_eq!(img.entries[0].data, b"eax256 payload");
    }

    #[test]
    fn decodes_encrypted_compressed_stream() {
        let data = b"repeat me repeat me repeat me repeat me";
        let f = build_encrypted(
            &[("c.bin", false, data)],
            PeaAlgo::Crc32,
            2,
            49,
            b"pw",
            &[0x13; 12],
        );
        let img = decode_with_password(&f, "pw").unwrap();
        assert_eq!(img.entries[0].data, data);
    }

    #[test]
    fn rejects_bad_auth_tag() {
        for code in [48u8, 49, 65] {
            // tamper the first ciphertext byte
            let mut f = build_encrypted(
                &[("a.txt", false, b"data")],
                PeaAlgo::None,
                0,
                code,
                b"pw",
                &[9; 12],
            );
            f[36] ^= 0xFF;
            assert!(decode_with_password(&f, "pw").is_err());
            // tamper the stream tag (last 16 bytes before the volume tag)
            let mut f = build_encrypted(
                &[("a.txt", false, b"data")],
                PeaAlgo::None,
                0,
                code,
                b"pw",
                &[9; 12],
            );
            let n = f.len();
            f[n - 20] ^= 0xFF;
            assert!(decode_with_password(&f, "pw").is_err());
        }
    }

    #[test]
    fn rejects_wrong_password() {
        for code in [48u8, 49, 65] {
            let f = build_encrypted(
                &[("a.txt", false, b"data")],
                PeaAlgo::None,
                0,
                code,
                b"right",
                &[9; 12],
            );
            assert!(matches!(
                decode_with_password(&f, "wrong"),
                Err(Error::InvalidData(_))
            ));
        }
    }

    #[test]
    fn encrypted_stream_requires_password() {
        let f = build_encrypted(
            &[("a.txt", false, b"data")],
            PeaAlgo::None,
            0,
            49,
            b"pw",
            &[9; 12],
        );
        assert!(decode(&f).is_err());
        assert!(decode_parts(&[&f]).is_err());
    }

    #[test]
    fn rejects_unsupported_encrypted_stream() {
        // Twofish EAX (50), Serpent EAX (51) and the cascades
        // (66..=76) parse but are intentionally unsupported
        for code in [50u8, 51, 66, 76] {
            let mut f = build_encrypted(
                &[("a.txt", false, b"data")],
                PeaAlgo::None,
                0,
                49,
                b"pw",
                &[9; 12],
            );
            f[18] = code;
            assert!(matches!(
                decode_with_password(&f, "pw"),
                Err(Error::Unsupported(_))
            ));
        }
    }

    #[test]
    fn rejects_all_truncations() {
        // PEA terminates with a stream tag then a volume tag, so no
        // proper prefix of an archive is valid: every cut must fail,
        // either at EOF or at tag verification.
        let f = build(
            &[("d", true, b""), ("d/f.bin", false, b"payload-data")],
            PeaAlgo::Crc32,
            0,
        );
        for cut in 0..f.len() {
            assert!(decode(&f[..cut]).is_err(), "cut={cut} unexpectedly decoded");
        }
    }
}
