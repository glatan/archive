//! LHA / LZH archive read and store-method write support.
//!
//! Reference: lha header documentation ("apphead"/lzh_note) as used by
//! the original LHA and GNU `lha`. Supported scope:
//!
//! - header levels 0, 1, and 2 for reading;
//! - methods `-lh0-` (stored) and `-lhd-` (directory marker, no data);
//!   every other method (`-lh1-`, `-lh5-`, `-lh6-`, `-lh7-`, `-lzs-`,
//!   `-lz4-`, `-pm0-`, `-pm2-`, ...) is rejected with
//!   [`Error::Unsupported`];
//! - writing emits header level 0 `-lh0-` entries only (file names must
//!   fit in one byte, i.e. at most 255 bytes, and be non-empty).
//!
//! Layout (level 0):
//! `[hdr_size u8][checksum u8][method 5B][packed u32le][orig u32le]
//!  [dos time u32le][attr u8][level u8][name_len u8][name][crc16 u16le]
//!  [data]`. `hdr_size` counts bytes from `method` through `crc16`;
//! `checksum` is the byte sum of that range. Level 1 replaces the
//! trailing fields with `crc16 u16le + OS id + extended headers`;
//! level 2 uses a `u16` size field, no checksum, `crc16 + OS id +
//! extended headers` (filename in extension block 0x01). The archive is
//! terminated by a zero header-size field.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// One decoded LHA entry.
#[derive(Debug, Clone)]
pub struct LhaEntry {
    /// File or directory name (directories end with `/` when built from
    /// level-2 directory extension blocks or `-lhd-` entries).
    pub name: String,
    /// Header level (0, 1, or 2) this entry was read with.
    pub level: u8,
    /// `true` for `-lhd-` directory entries.
    pub is_dir: bool,
    /// Original-file CRC-16 (IBM polynomial) when present in the header.
    pub crc16: Option<u16>,
    /// DOS-format timestamp as stored (level 0/1) or Unix seconds
    /// (level 2); `None` if the level does not define one.
    pub mtime: u32,
    /// Entry payload (empty for directories and unsupported methods).
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for LhaEntry {
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

fn method_of(h: &[u8]) -> &[u8] {
    &h[0..5]
}

/// (filename extension, directory extension) pair.
type ExtNameDir = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Walk a level-1/2 extended-header chain and return (filename,
/// directory-path components). `blocks` starts at the first `u16`
/// extension size; each block is `u16 size` (counting the size field
/// itself) + `u8 type` + payload.
fn walk_ext_headers(mut blocks: &[u8]) -> Result<ExtNameDir, Error> {
    let mut name = None;
    let mut dir = None;
    while blocks.len() >= 2 {
        let size = u16le(blocks) as usize;
        if size == 0 {
            break;
        }
        if size < 3 || size > blocks.len() {
            return Err(Error::InvalidData("lha: bad extended header"));
        }
        let ty = blocks[2];
        let payload = &blocks[3..size.min(blocks.len())];
        match ty {
            0x01 => name = Some(payload.to_vec()),
            0x02 => dir = Some(payload.to_vec()),
            _ => {}
        }
        blocks = &blocks[size..];
    }
    Ok((name, dir))
}

fn sanitize_name(raw: &[u8]) -> Result<String, Error> {
    let s =
        core::str::from_utf8(raw).map_err(|_| Error::InvalidData("lha: filename is not UTF-8"))?;
    // Level-2 directory blocks separate components with 0xff.
    let cleaned: String = s
        .chars()
        .map(|c| if c == '\u{ff}' { '/' } else { c })
        .collect();
    if cleaned.contains('\0') {
        return Err(Error::InvalidData("lha: NUL in filename"));
    }
    Ok(cleaned)
}

/// Decode an LHA/LZH archive into entries. Stops at the terminating
/// zero-size header field; trailing bytes after it are ignored.
pub fn decode(input: &[u8]) -> Result<Vec<LhaEntry>, Error> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos >= input.len() {
            // Spec files end with a zero byte; tolerate a clean EOF too.
            return Ok(entries);
        }
        if input[pos] == 0 {
            return Ok(entries);
        }
        // All supported levels put the level byte at offset 20 and the
        // "-lX-" method marker at offset 2. Distinguish by level byte:
        // level 2 uses a u16 size field, levels 0/1 use a u8 size.
        if pos + 21 > input.len()
            || input[pos + 2] != b'-'
            || input[pos + 3] != b'l'
            || input[pos + 6] != b'-'
        {
            return Err(Error::InvalidData("lha: bad header"));
        }
        match input[pos + 20] {
            0 | 1 => pos = decode_level01(input, pos, &mut entries)?,
            2 => {
                let size16 = u16le(&input[pos..]) as usize;
                pos = decode_level2(input, pos, size16, &mut entries)?;
            }
            _ => return Err(Error::InvalidData("lha: bad header level")),
        }
    }
}

fn decode_level01(input: &[u8], pos: usize, entries: &mut Vec<LhaEntry>) -> Result<usize, Error> {
    let hsize = input[pos] as usize;
    if pos + 2 + hsize > input.len() {
        return Err(Error::InvalidData("lha: truncated header"));
    }
    let hdr = &input[pos + 2..pos + 2 + hsize];
    if hsize < 22 {
        return Err(Error::InvalidData("lha: short header"));
    }
    let checksum = hdr.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    if checksum != input[pos + 1] {
        return Err(Error::InvalidData("lha: header checksum mismatch"));
    }
    let method = method_of(hdr);
    let is_dir = method == b"-lhd-";
    if method != b"-lh0-" && !is_dir {
        return Err(Error::Unsupported("lha: unsupported method"));
    }
    let packed = u32le(&hdr[5..]) as usize;
    let orig = u32le(&hdr[9..]) as usize;
    let mtime = u32le(&hdr[13..]);
    let level = hdr[18];
    if level > 1 {
        return Err(Error::InvalidData("lha: bad header level"));
    }
    let name_len = hdr[19] as usize;
    if 20 + name_len > hsize {
        return Err(Error::InvalidData("lha: truncated filename"));
    }
    let name_field = &hdr[20..20 + name_len];
    let (name, crc16) = if level == 0 {
        // filename + u16 CRC-16
        if 20 + name_len + 2 > hsize {
            return Err(Error::InvalidData("lha: truncated crc"));
        }
        (
            sanitize_name(name_field)?,
            Some(u16le(&hdr[20 + name_len..])),
        )
    } else {
        // level 1: filename + u16 CRC + u8 OS id + ext headers
        if 20 + name_len + 3 > hsize {
            return Err(Error::InvalidData("lha: truncated crc"));
        }
        let crc = u16le(&hdr[20 + name_len..]);
        let (ext_name, dir) = walk_ext_headers(&hdr[20 + name_len + 3..])?;
        let name = match (ext_name, dir) {
            (Some(n), Some(d)) => {
                let mut s = sanitize_name(&d)?;
                if !s.is_empty() && !s.ends_with('/') {
                    s.push('/');
                }
                s.push_str(&sanitize_name(&n)?);
                s
            }
            (Some(n), None) => sanitize_name(&n)?,
            _ => sanitize_name(name_field)?,
        };
        (name, Some(crc))
    };
    let data_start = pos + 2 + hsize;
    let take = if is_dir { 0 } else { packed };
    if data_start + take > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    let data = input[data_start..data_start + take].to_vec();
    if data.len() != orig && !is_dir {
        // For stored entries packed size must equal original size.
        return Err(Error::InvalidData("lha: size mismatch"));
    }
    if let Some(c) = crc16
        && crate::util::crc16::crc16(&data) != c
    {
        return Err(Error::InvalidData("lha: CRC-16 mismatch"));
    }
    entries.push(LhaEntry {
        name,
        level,
        is_dir,
        crc16,
        mtime,
        data,
    });
    Ok(data_start + take)
}

fn decode_level2(
    input: &[u8],
    pos: usize,
    size16: usize,
    entries: &mut Vec<LhaEntry>,
) -> Result<usize, Error> {
    if pos + 2 + size16 > input.len() {
        return Err(Error::InvalidData("lha: truncated header"));
    }
    let hdr = &input[pos + 2..pos + 2 + size16];
    if size16 < 26 {
        return Err(Error::InvalidData("lha: short header"));
    }
    let method = method_of(hdr);
    let is_dir = method == b"-lhd-";
    if method != b"-lh0-" && !is_dir {
        return Err(Error::Unsupported("lha: unsupported method"));
    }
    let packed = u32le(&hdr[5..]) as usize;
    let orig = u32le(&hdr[9..]) as usize;
    let mtime = u32le(&hdr[13..]);
    // byte 17: reserved 0x20, byte 18: level = 2
    if hdr[18] != 2 {
        return Err(Error::InvalidData("lha: bad header level"));
    }
    let crc = u16le(&hdr[19..]);
    // byte 21: OS id, then extended headers.
    let (name, dir) = walk_ext_headers(&hdr[22..])?;
    let mut name = match (name, dir) {
        (Some(n), Some(d)) => {
            let mut s = sanitize_name(&d)?;
            if !s.is_empty() && !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(&sanitize_name(&n)?);
            s
        }
        (Some(n), None) => sanitize_name(&n)?,
        _ => return Err(Error::InvalidData("lha: no filename")),
    };
    if is_dir && !name.ends_with('/') {
        name.push('/');
    }
    let data_start = pos + 2 + size16;
    let take = if is_dir { 0 } else { packed };
    if data_start + take > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    let data = input[data_start..data_start + take].to_vec();
    if data.len() != orig && !is_dir {
        return Err(Error::InvalidData("lha: size mismatch"));
    }
    if !is_dir && crate::util::crc16::crc16(&data) != crc {
        return Err(Error::InvalidData("lha: CRC-16 mismatch"));
    }
    entries.push(LhaEntry {
        name,
        level: 2,
        is_dir,
        crc16: Some(crc),
        mtime,
        data,
    });
    Ok(data_start + take)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level0_roundtrip() {
        let a = crate::archive::lha::encode::encode(&[
            ("hello.txt", b"hello world"),
            ("a/b.bin", &[0, 1, 2, 255]),
        ])
        .unwrap();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "hello.txt");
        assert_eq!(e[0].data, b"hello world");
        assert_eq!(e[1].name, "a/b.bin");
        assert_eq!(e[1].data, &[0, 1, 2, 255]);
        assert_eq!(e[0].level, 0);
    }

    #[test]
    fn dir_entry() {
        let mut enc = crate::archive::lha::encode::LhaEncoder::new();
        enc.add_dir("docs", 0).unwrap();
        enc.add_file("docs/f.txt", b"x", 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert!(e[0].is_dir);
        assert_eq!(e[1].name, "docs/f.txt");
    }

    #[test]
    fn rejects_unsupported_method() {
        let mut a = crate::archive::lha::encode::encode(&[("f", b"x")]).unwrap();
        a[4] = b'1'; // -lh1-
        // recompute checksum
        let hs = a[0] as usize;
        a[1] = a[2..2 + hs].iter().fold(0u8, |x, &b| x.wrapping_add(b));
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_bad_checksum() {
        let mut a = crate::archive::lha::encode::encode(&[("f", b"x")]).unwrap();
        a[1] ^= 0xff;
        assert!(decode(&a).is_err());
    }

    #[test]
    fn level2_decode() {
        // Hand-built level-2 header for "abc" containing "abc".
        let mut h = Vec::new();
        let name = b"abc";
        let ext: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&((3 + name.len()) as u16).to_le_bytes());
            v.push(0x01);
            v.extend_from_slice(name);
            v.extend_from_slice(&0u16.to_le_bytes());
            v
        };
        let hsize = (5 + 4 + 4 + 4 + 1 + 1 + 2 + 1 + ext.len()) as u16;
        h.extend_from_slice(&hsize.to_le_bytes());
        h.extend_from_slice(b"-lh0-");
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.push(0x20);
        h.push(2);
        h.extend_from_slice(&crate::util::crc16::crc16(b"abc").to_le_bytes());
        h.push(b'U');
        h.extend_from_slice(&ext);
        h.extend_from_slice(b"abc");
        h.extend_from_slice(&0u16.to_le_bytes());
        let e = decode(&h).unwrap();
        assert_eq!(e[0].name, "abc");
        assert_eq!(e[0].data, b"abc");
        assert_eq!(e[0].level, 2);
    }
}
