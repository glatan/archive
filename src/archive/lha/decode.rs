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
//! - writing emits `-lh0-`/`-lhd-` entries at header level 0, 1, or 2
//!   (`LhaEncoder::with_level`). Level 0 requires the whole filename to
//!   fit in one byte (at most 255 bytes); levels 1/2 carry the name
//!   through extended headers.
//!
//! Layout (level 0):
//! `[hdr_size u8][checksum u8][method 5B][packed u32le][orig u32le]
//!  [dos time u32le][attr u8][level u8][name_len u8][name][crc16 u16le]
//!  [data]`. `hdr_size` counts bytes from `method` through `crc16` and
//! `checksum` is the byte sum of that range; name components are
//! `'\\'`-separated.
//!
//! Level 1 keeps the same basic-header shape but appends `crc16 + OS id`
//! and terminates the basic header with a `u16` next-header size; the
//! extended-header chain then sits *after* the basic header and the
//! packed-size field is a "skip size" that also counts those
//! extended-header bytes. Level 2 replaces the size/checksum prefix
//! with a single `u16` total header size (counting the size field
//! itself), stores a UNIX timestamp, and carries names in extended
//! headers (`0x01` filename, `0x02` directory, components separated by
//! raw `0xff`). A `0x00` extended block holds the level-2 header CRC-16.
//! The archive is terminated by a zero header-size field.

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
/// directory-path components, consumed bytes). `blocks` starts at the
/// first `u16` extension size; each block is `u16 size` (counting the
/// size field itself) + `u8 type` + payload, and the chain ends with a
/// `u16` zero terminator (counted in `consumed`).
fn walk_ext_headers(mut blocks: &[u8]) -> Result<(ExtNameDir, usize), Error> {
    let mut name = None;
    let mut dir = None;
    let mut consumed = 0usize;
    loop {
        if blocks.len() < 2 {
            return Err(Error::InvalidData("lha: truncated extended header"));
        }
        let size = u16le(blocks) as usize;
        if size == 0 {
            return Ok(((name, dir), consumed + 2));
        }
        if size < 3 || size > blocks.len() {
            return Err(Error::InvalidData("lha: bad extended header"));
        }
        let ty = blocks[2];
        let payload = &blocks[3..size];
        match ty {
            0x01 => name = Some(payload.to_vec()),
            0x02 => dir = Some(payload.to_vec()),
            _ => {}
        }
        blocks = &blocks[size..];
        consumed += size;
    }
}

/// Extended-header payloads separate path components with a raw `0xff`
/// byte (never valid UTF-8 on its own); normalize it before validating.
fn sanitize_name(raw: &[u8]) -> Result<String, Error> {
    let fixed: Vec<u8> = raw
        .iter()
        .map(|&b| if b == 0xff { b'/' } else { b })
        .collect();
    let s = core::str::from_utf8(&fixed)
        .map_err(|_| Error::InvalidData("lha: filename is not UTF-8"))?;
    if s.contains('\0') {
        return Err(Error::InvalidData("lha: NUL in filename"));
    }
    Ok(s.into())
}

/// Basic (level-0/1) name fields use raw `0xff` separators like the
/// extended headers (verified against LHa for UNIX output); `'\\'`
/// is additionally tolerated for DOS-era tools.
fn sanitize_basic_name(raw: &[u8]) -> Result<String, Error> {
    let fixed: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'\\' { b'/' } else { b })
        .collect();
    sanitize_name(&fixed)
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
    let (name, crc16, packed, data_start) = if level == 0 {
        // filename + u16 CRC-16
        if 20 + name_len + 2 > hsize {
            return Err(Error::InvalidData("lha: truncated crc"));
        }
        (
            sanitize_basic_name(name_field)?,
            Some(u16le(&hdr[20 + name_len..])),
            packed,
            pos + 2 + hsize,
        )
    } else {
        // level 1: filename + u16 CRC + u8 OS id (+ old-style padding)
        // + u16 next-header size. The basic `hsize` covers the header
        // through that u16 only; the extended-header chain and data
        // follow it. The `packed` field is a skip size that also counts
        // the extended-header bytes after the basic header.
        if 20 + name_len + 5 > hsize {
            return Err(Error::InvalidData("lha: truncated crc"));
        }
        let crc = u16le(&hdr[20 + name_len..]);
        let ext_area = &input[pos + 2 + hsize - 2..];
        let ((ext_name, dir), consumed) = walk_ext_headers(ext_area)?;
        let ext_bytes = consumed - 2; // u16 size field already in hsize
        let packed = packed
            .checked_sub(ext_bytes)
            .ok_or(Error::InvalidData("lha: bad skip size"))?;
        let name = match (ext_name, dir) {
            (None, None) => sanitize_basic_name(name_field)?,
            (ext_name, dir) => {
                let mut s = match dir {
                    Some(d) => sanitize_name(&d)?,
                    None => String::new(),
                };
                if !s.is_empty() && !s.ends_with('/') {
                    s.push('/');
                }
                let base = match ext_name {
                    Some(n) => sanitize_name(&n)?,
                    None => sanitize_basic_name(name_field)?,
                };
                s.push_str(&base);
                s
            }
        };
        (name, Some(crc), packed, pos + 2 + hsize + ext_bytes)
    };
    let mut name = name;
    if is_dir && !name.ends_with('/') {
        name.push('/');
    }
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
    // Level-2 `header size` counts the u16 size field itself.
    if size16 < 26 || pos + size16 > input.len() {
        return Err(Error::InvalidData("lha: truncated header"));
    }
    let hdr = &input[pos + 2..pos + size16];
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
    // byte 21 (hdr[21]): OS id, then extended headers at hdr[22..]
    // (the u16 next-header size at absolute offset 24).
    let ((name, dir), _) = walk_ext_headers(&hdr[22..])?;
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
    let data_start = pos + size16;
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
        // Hand-built level-2 header for "abc" containing "abc". The
        // u16 size counts itself; the extended chain carries a `0x00`
        // header-CRC block like reference LHa.
        let name = b"abc";
        let mut ext = Vec::new();
        ext.extend_from_slice(&5u16.to_le_bytes()); // header-crc block
        ext.push(0x00);
        ext.extend_from_slice(&0u16.to_le_bytes()); // hcrc placeholder
        ext.extend_from_slice(&((3 + name.len()) as u16).to_le_bytes());
        ext.push(0x01);
        ext.extend_from_slice(name);
        ext.extend_from_slice(&0u16.to_le_bytes()); // terminator
        let hsize = (2 + 5 + 4 + 4 + 4 + 1 + 1 + 2 + 1 + ext.len()) as u16;
        let mut h = Vec::new();
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
        assert_eq!(h.len(), hsize as usize);
        // patch the header CRC-16 (field zeroed during computation)
        let hcrc = crate::util::crc16::crc16(&h);
        h[27..29].copy_from_slice(&hcrc.to_le_bytes());
        h.extend_from_slice(b"abc");
        h.push(0);
        let e = decode(&h).unwrap();
        assert_eq!(e[0].name, "abc");
        assert_eq!(e[0].data, b"abc");
        assert_eq!(e[0].level, 2);
    }

    #[test]
    fn level1_roundtrip() {
        let mut enc = crate::archive::lha::encode::LhaEncoder::with_level(1).unwrap();
        enc.add_file("dir/sub/hello.txt", b"level one", 0x1234)
            .unwrap();
        enc.add_file("top.bin", &[0xde, 0xad], 0).unwrap();
        enc.add_dir("emptydir", 0).unwrap();
        let a = enc.finish();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].level, 1);
        assert_eq!(e[0].name, "dir/sub/hello.txt");
        assert_eq!(e[0].data, b"level one");
        assert_eq!(e[0].mtime, 0x1234);
        assert_eq!(e[1].name, "top.bin");
        assert_eq!(e[1].data, &[0xde, 0xad]);
        assert!(e[2].is_dir);
        assert_eq!(e[2].name, "emptydir/");
    }

    #[test]
    fn level2_roundtrip() {
        let mut enc = crate::archive::lha::encode::LhaEncoder::with_level(2).unwrap();
        enc.add_file("dir/sub/hello.txt", b"level two", 0x60000000)
            .unwrap();
        enc.add_dir("docs", 0).unwrap();
        let a = enc.finish();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].level, 2);
        assert_eq!(e[0].name, "dir/sub/hello.txt");
        assert_eq!(e[0].data, b"level two");
        assert_eq!(e[0].mtime, 0x60000000);
        assert!(e[1].is_dir);
        assert_eq!(e[1].name, "docs/");
    }

    #[test]
    fn level2_long_path() {
        // Level 2 lifts the u8 name-field limit: the path only lives in
        // extended headers.
        let dir = "d".repeat(200);
        let name = alloc::format!("{dir}/x");
        let a = crate::archive::lha::encode::encode_level(&[(&name, b"y")], 2).unwrap();
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, name);
    }

    #[test]
    fn level_rejects_bad_level() {
        assert!(crate::archive::lha::encode::LhaEncoder::with_level(3).is_err());
        assert!(crate::archive::lha::encode::LhaEncoder::with_level(9).is_err());
    }

    #[test]
    fn level1_real_archive() {
        // Produced by reference LHa (`lha a -o1`): basic-header-only
        // `hsize`, skip-size packed field, extended headers outside the
        // basic header, including UNIX ext blocks we must skip.
        let a = include_bytes!("../../../tests/fixtures/lha/level1.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "f1.txt");
        assert_eq!(e[0].level, 1);
        assert_eq!(e[0].data, b"hello level one\n");
        assert_eq!(e[1].name, "f2.txt");
        assert_eq!(e[1].data, b"payload2\n");
    }

    #[test]
    fn level2_real_archive() {
        // Level-2 `hsize` counts the u16 size field itself and the
        // extended chain begins with a `0x00` header-CRC block.
        let a = include_bytes!("../../../tests/fixtures/lha/level2.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "f1.txt");
        assert_eq!(e[0].level, 2);
        assert_eq!(e[0].data, b"hello level one\n");
        assert_eq!(e[1].name, "f2.txt");
        assert_eq!(e[1].data, b"payload2\n");
    }

    #[test]
    fn level1_real_nested_dir() {
        // `0x02` directory ext carries raw 0xff separators and a
        // trailing delimiter; the basename stays in the name field.
        let a = include_bytes!("../../../tests/fixtures/lha/level1_nested.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e[0].name, "dir/sub/deep.txt");
        assert_eq!(e[0].data, b"nested content\n");
        assert_eq!(e[1].name, "f1.txt");
    }

    #[test]
    fn level2_real_nested_dir() {
        let a = include_bytes!("../../../tests/fixtures/lha/level2_nested.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e[0].name, "dir/sub/deep.txt");
        assert_eq!(e[0].data, b"nested content\n");
        assert_eq!(e[1].name, "f1.txt");
    }

    #[test]
    fn level1_long_basename_uses_ext() {
        // Basenames over 230 bytes leave the basic name field empty and
        // go to extended header 0x01.
        let name = "n".repeat(231);
        let a = crate::archive::lha::encode::encode_level(&[(&name, b"d")], 1).unwrap();
        assert_eq!(a[21], 0); // name_len == 0
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, name);
        assert_eq!(e[0].data, b"d");
    }

    #[test]
    fn level2_zero_low_byte_padding() {
        // When the total header size would end on a zero low byte the
        // encoder appends a one-byte padding so the first header byte
        // is not mistaken for the end-of-archive marker.
        let name = "x".repeat(222);
        let a = crate::archive::lha::encode::encode_level(&[(&name, b"z")], 2).unwrap();
        let hsize = u16le(&a) as usize;
        assert_eq!(hsize & 0xff, 1); // 256 + 1 pad
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, name);
        assert_eq!(e[0].data, b"z");
    }
}
