//! ARJ archive read and store-method write support.
//!
//! Reference: ARJ technical note ("arj tekninen" / ARJ file format
//! description published with ARJ 2.x). Supported scope:
//!
//! - reading: ARJ 2.x basic headers, method 0 (`stored`) and
//!   file-type 3 (directory) / 4 (volume label) entries. Compressed
//!   methods 1-4 and entries flagged as garbled (password-protected,
//!   flag bit 0x01) are rejected with [`Error::Unsupported`];
//! - writing: method-0 binary file entries only.
//!
//! Layout: each header starts with the two-byte signature `0x60 0xEA`
//! followed by a `u16le` header size (0 = end of archive). The basic
//! header is a fixed 30-byte block, then a NUL-terminated filename,
//! a NUL-terminated comment, and a `u32le` CRC-32 of the header bytes
//! starting at `first_hdr_size`. File data follows the header CRC (and
//! any extended header block, which is skipped). The main (first)
//! header describes the archive itself and carries no data.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

pub(crate) const SIG: [u8; 2] = [0x60, 0xEA];
pub(crate) const BASIC_HDR_SIZE: usize = 30;

/// One decoded ARJ entry. The archive-level main header is not
/// returned as an entry.
#[derive(Debug, Clone)]
pub struct ArjEntry {
    /// File or directory name.
    pub name: String,
    /// Compression method byte (always 0 for accepted entries).
    pub method: u8,
    /// ARJ file type: 0 = binary, 1 = text, 3 = directory, 4 = label.
    pub file_type: u8,
    /// `true` for directory entries (file type 3).
    pub is_dir: bool,
    /// DOS-format timestamp as stored in the header.
    pub mtime: u32,
    /// CRC-32 of the uncompressed file data.
    pub crc32: u32,
    /// Entry payload (empty for directories and labels).
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ArjEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn read_cstr(b: &[u8]) -> Result<(&str, usize), Error> {
    match b.iter().position(|&c| c == 0) {
        Some(end) => Ok((
            core::str::from_utf8(&b[..end])
                .map_err(|_| Error::InvalidData("arj: name is not UTF-8"))?,
            end + 1,
        )),
        None => Err(Error::InvalidData("arj: unterminated string")),
    }
}

/// Parse one ARJ header block starting at `pos` (which must point at
/// the 0x60 0xEA signature). Returns `(header_end, fixed_fields,
/// name, comment)` where `header_end` is the offset just past the
/// header CRC (and optional extended header), and `fixed_fields` is
/// the 30-byte basic header.
fn parse_header(
    input: &[u8],
    pos: usize,
) -> Result<(usize, [u8; BASIC_HDR_SIZE], String, String), Error> {
    if pos + 4 > input.len() || input[pos..pos + 2] != SIG {
        return Err(Error::InvalidData("arj: bad signature"));
    }
    let hsize = u16le(&input[pos + 2..]) as usize;
    if hsize == 0 {
        return Err(Error::InvalidData("arj: empty header"));
    }
    // hsize counts bytes from first_hdr_size through the comment NUL.
    if pos + 4 + hsize > input.len() || hsize < BASIC_HDR_SIZE {
        return Err(Error::InvalidData("arj: truncated header"));
    }
    let body = &input[pos + 4..pos + 4 + hsize];
    let first = body[0] as usize;
    if first > hsize || first < BASIC_HDR_SIZE {
        return Err(Error::InvalidData("arj: bad first header size"));
    }
    let mut fixed = [0u8; BASIC_HDR_SIZE];
    // body[0] is first_hdr_size, field 1 of the fixed header; fields
    // are counted from byte 0 of the header body.
    fixed[..first.min(BASIC_HDR_SIZE)].copy_from_slice(&body[..first.min(BASIC_HDR_SIZE)]);
    let (name, nlen) = read_cstr(&body[first..])?;
    let (comment, clen) = read_cstr(&body[first + nlen..])?;
    if first + nlen + clen > hsize {
        return Err(Error::InvalidData("arj: strings exceed header"));
    }
    // The 4-byte header CRC is stored after the hsize bytes.
    let crc_off = pos + 4 + hsize;
    if crc_off + 4 > input.len() {
        return Err(Error::InvalidData("arj: truncated header crc"));
    }
    let stored_crc = u32le(&input[crc_off..]);
    let actual = crate::util::crc32::crc32(&input[pos + 4..pos + 4 + hsize]);
    if stored_crc != actual {
        return Err(Error::InvalidData("arj: header CRC-32 mismatch"));
    }
    // The u16 extended-header size always follows the header CRC;
    // 0 means no extended header, otherwise  bytes plus a u32 CRC.
    let mut end = crc_off + 4;
    if end + 2 > input.len() {
        return Err(Error::InvalidData("arj: truncated ext size"));
    }
    let ext = u16le(&input[end..]) as usize;
    if ext > 0 {
        if end + 2 + ext + 4 > input.len() {
            return Err(Error::InvalidData("arj: truncated ext header"));
        }
        end += 2 + ext + 4;
    } else {
        end += 2;
    }
    Ok((end, fixed, name.into(), comment.into()))
}

/// Decode an ARJ archive into entries.
pub fn decode(input: &[u8]) -> Result<Vec<ArjEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    let mut pos = 0usize;
    let mut first = true;
    loop {
        if pos + 4 > input.len() {
            return Err(Error::InvalidData("arj: truncated signature"));
        }
        if input[pos..pos + 2] != SIG {
            return Err(Error::InvalidData("arj: bad signature"));
        }
        let hsize = u16le(&input[pos + 2..]) as usize;
        if hsize == 0 {
            return Ok(entries); // end of archive
        }
        let (end, fixed, name, _comment) = parse_header(input, pos)?;
        // fixed[0] = first_hdr_size, [1] version, [2] min ver,
        // [3] host os, [4] arj flags, [5] method, [6] file type,
        // [7] reserved, [8..12] dos time, [12..16] crc32,
        // [16..20] compressed size, [20..24] original size,
        // [24..28] original filename offset, [28..30] host data.
        let flags = fixed[4];
        let method = fixed[5];
        let file_type = fixed[6];
        let mtime = u32le(&fixed[8..]);
        let crc = u32le(&fixed[12..]);
        let packed = u32le(&fixed[16..]) as usize;
        let orig = u32le(&fixed[20..]) as usize;
        if first {
            // Main header: file_type != 0 binary data; no payload follows.
            first = false;
            pos = end;
            continue;
        }
        if flags & 0x01 != 0 {
            return Err(Error::Unsupported("arj: unsupported method")); // garbled/encrypted
        }
        if method != 0 {
            return Err(Error::Unsupported("arj: unsupported method"));
        }
        let is_dir = file_type == 3;
        let take = if is_dir || file_type == 4 { 0 } else { packed };
        if end + take > input.len() {
            return Err(Error::InvalidData("arj: truncated entry data"));
        }
        let data = input[end..end + take].to_vec();
        if !is_dir && file_type != 4 {
            if data.len() != orig {
                return Err(Error::InvalidData("arj: size mismatch"));
            }
            if crate::util::crc32::crc32(&data) != crc {
                return Err(Error::InvalidData("arj: data CRC-32 mismatch"));
            }
        }
        entries.push(ArjEntry {
            name,
            method,
            file_type,
            is_dir,
            mtime,
            crc32: crc,
            data,
        });
        pos = end + take;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = crate::archive::arj::encode::encode(&[
            ("hello.txt", b"hi arj"),
            ("d/f.bin", &[9, 8, 7]),
        ])
        .unwrap();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "hello.txt");
        assert_eq!(e[0].data, b"hi arj");
        assert_eq!(e[1].name, "d/f.bin");
        assert_eq!(e[0].method, 0);
    }

    #[test]
    fn dir_entry() {
        let mut enc = crate::archive::arj::encode::ArjEncoder::new();
        enc.add_dir("sub", 0).unwrap();
        enc.add_file("sub/a", b"q", 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert!(e[0].is_dir);
        assert_eq!(e[0].file_type, 3);
    }

    /// Offset of the second (first file) header in .
    fn second_header_off(a: &[u8]) -> usize {
        // main header: SIG(2) + hsize(2) + body(hsize) + crc(4) + ext u16(2)
        let h1 = u16le(&a[2..]) as usize;
        4 + h1 + 4 + 2
    }

    #[test]
    fn rejects_compressed() {
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        let second = second_header_off(&a);
        a[second + 4 + 5] = 1; // method=1
        // fix header crc
        let bsize = u16le(&a[second + 2..]) as usize;
        let crc = crate::util::crc32::crc32(&a[second + 4..second + 4 + bsize]);
        a[second + 4 + bsize..second + 8 + bsize].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_bad_header_crc() {
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        let second = second_header_off(&a);
        let bsize = u16le(&a[second + 2..]) as usize;
        a[second + 4 + bsize] ^= 0xff; // corrupt stored header CRC
        assert!(decode(&a).is_err());
    }
}
