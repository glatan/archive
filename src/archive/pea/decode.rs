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

const MAGIC: u8 = 0xEA;
const VER: u8 = 1;
const REV: u8 = 6;
/// Compression block buffer in the reference implementation.
const WBUFSIZE: usize = 1048576;
const FA_DIRECTORY: u32 = 0x10;

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
    /// Authenticated-encryption stream control (unsupported).
    Encrypted(u8),
}

impl PeaAlgo {
    fn from_code(code: u8, encrypted_ok: bool) -> Result<PeaAlgo, Error> {
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
            c if encrypted_ok && matches!(c, 48..=51 | 65..=76) => PeaAlgo::Encrypted(c),
            _ => return Err(Error::InvalidData("pea unknown control algorithm")),
        })
    }

    /// Tag size in bytes.
    fn tag_size(self) -> usize {
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
    fn compute(self, data: &[u8]) -> Option<Vec<u8>> {
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

fn parse_stream_header(r: &mut Reader) -> Result<StreamProps, Error> {
    let h = r.take(10)?;
    if h[0] != 0 || h[1] != 0 || &h[2..5] != b"POD" || h[5] != 0 {
        return Err(Error::InvalidData("pea bad stream header"));
    }
    if h[6] > 3 {
        return Err(Error::InvalidData("pea unknown compression scheme"));
    }
    let stream_algo = PeaAlgo::from_code(h[8], true)?;
    if let PeaAlgo::Encrypted(_) = stream_algo {
        return Err(Error::InvalidData("pea encrypted stream unsupported"));
    }
    let obj_algo = PeaAlgo::from_code(h[9], false)?;
    Ok(StreamProps {
        compression: h[6],
        stream_algo,
        obj_algo,
    })
}

/// Decode a PEA 1.x archive.
pub fn decode(input: &[u8]) -> Result<PeaImage, Error> {
    if input.len() < 10 || input[0] != MAGIC {
        return Err(Error::InvalidData("not a pea archive"));
    }
    let (ver, rev) = (input[1], input[2]);
    if ver > VER || (ver == VER && rev > REV) {
        return Err(Error::InvalidData("pea revision not supported"));
    }
    let volume_algo = PeaAlgo::from_code(input[3], false)?;

    let mut r = Reader { input, pos: 10 };
    let mut entries = Vec::new();
    let mut streams = 0u32;

    'streams: loop {
        streams += 1;
        if streams > 1024 {
            return Err(Error::InvalidData("pea too many streams"));
        }
        let props = parse_stream_header(&mut r)?;

        'objects: loop {
            let name_len = r.u16()? as usize;
            if name_len == 0 {
                // trigger object: 4-byte message + NUL
                let t = r.take(4)?;
                match t {
                    b"POD\0" => {
                        // another stream header follows immediately
                        continue 'streams;
                    }
                    b"EOS\0" | b"EOA\0" => break 'objects,
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
                    decode_compressed(&mut r, file_size, &mut covered)?
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

        // stream-level control tag covers every byte from the start
        // of the file through the EOA trigger
        let stag = r.take(props.stream_algo.tag_size())?;
        verify_tag(props.stream_algo, stag, &input[..r.pos - stag.len()])?;
        break;
    }

    // trailing volume control tag covers all preceding bytes
    let vtag = r.take(volume_algo.tag_size())?;
    verify_tag(volume_algo, vtag, &input[..r.pos - vtag.len()])?;
    if r.pos != input.len() {
        return Err(Error::InvalidData("pea trailing garbage"));
    }

    Ok(PeaImage {
        version: (ver, rev),
        entries,
    })
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
        algo.compute(covered)
            .unwrap_or_else(|| alloc::vec![0u8; algo.tag_size()])
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
        f.push(match obj_algo {
            PeaAlgo::None => 0,
            PeaAlgo::Crc32 => 2,
            PeaAlgo::Sha256 => 19,
            _ => 0,
        });
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
        // stream tag: CRC32 over everything so far
        w32(util::crc32::crc32(&f), &mut f);
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
}
