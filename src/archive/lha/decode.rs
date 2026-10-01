//! LHA / LZH archive read and store-method write support.
//!
//! Reference: lha header documentation ("apphead"/lzh_note) as used by
//! the original LHA and GNU `lha`. Supported scope:
//!
//! - header levels 0, 1, 2, and 3 for reading;
//! - methods `-lh0-` (stored), `-lhd-` (directory marker),
//!   `-lh1-`/`-lh2-`/`-lh3-`, `-lh4-` through `-lh7-`,
//!   LArc `-lzs-`/`-lz4-`/`-lz5-`, and PMarc
//!   `-pm0-`/`-pm1-`/`-pm2-` for reading; other methods are rejected with
//!   [Error::Unsupported];
//! - writing emits `-lh0-`/`-lhd-` entries at header level 0, 1, 2, or 3
//!   (`LhaEncoder::with_level`), plus `-lh4-`/`-lh5-`/`-lh6-`/`-lh7-`
//!   file entries via `LhaEncoder::with_method` (stored fallback when
//!   compression does not win). Level 0 requires the whole filename to
//!   fit in one byte (at most 255 bytes); levels 1/2/3 carry the name
//!   through extended headers.
//!
//! Layout (level 0):
//! [hdr_size u8][checksum u8][method 5B][packed u32le][orig u32le]
//!  [dos time u32le][attr u8][level u8][name_len u8][name][crc16 u16le]
//!  [data]. hdr_size counts bytes from method through crc16 and
//!  checksum is the byte sum of that range; name components are
//!  backslash-separated.
//!
//! Level 1 keeps the same basic-header shape but appends crc16 + OS id
//! and terminates the basic header with a u16 next-header size; the
//! extended-header chain then sits *after* the basic header and the
//! packed-size field is a "skip size" that also counts those
//! extended-header bytes. Level 2 replaces the size/checksum prefix
//! with a single u16 total header size (counting the size field
//! itself), stores a UNIX timestamp, and carries names in extended
//! headers (0x01 filename, 0x02 directory, components separated by
//! raw 0xff). A 0x00 extended block holds the level-2 header CRC-16.
//! Level 3 uses a 32-byte base header (u16 word size = 4, u32 packed/
//! original sizes, UNIX time, crc16, OS id, u32 total header length)
//! and u32-sized extended headers, capped at 1 MiB total. The archive
//! is terminated by a zero header-size field.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// One decoded LHA entry.
#[derive(Debug, Clone)]
pub struct LhaEntry {
    /// File or directory name (directories end with `/` when built from
    /// level-2 directory extension blocks or `-lhd-` entries).
    pub name: String,
    /// Header level (0-3) this entry was read with.
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

/// (filename extension, directory extension) pair.
type ExtNameDir = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Walk a level-1/2 extended-header chain and return (filename,
/// directory-path components, consumed bytes). `blocks` starts at the
/// first `u16` extension size; each block is `u16 size` (counting the
/// size field itself) + `u8 type` + payload, and the chain ends with a
/// `u16` zero terminator (counted in `consumed`).
fn walk_ext_headers(blocks: &[u8]) -> Result<(ExtNameDir, usize), Error> {
    walk_ext_headers_sized(blocks, 2)
}

/// As [`walk_ext_headers`], but the size field width is `size_bytes`
/// (2 for levels 1/2, 4 for level 3).
fn walk_ext_headers_sized(
    mut blocks: &[u8],
    size_bytes: usize,
) -> Result<(ExtNameDir, usize), Error> {
    let mut name = None;
    let mut dir = None;
    let mut consumed = 0usize;
    loop {
        if blocks.len() < size_bytes {
            return Err(Error::InvalidData("lha: truncated extended header"));
        }
        let size = match size_bytes {
            2 => u16le(blocks) as usize,
            _ => u32le(blocks) as usize,
        };
        if size == 0 {
            return Ok(((name, dir), consumed + size_bytes));
        }
        if size < size_bytes + 1 || size > blocks.len() {
            return Err(Error::InvalidData("lha: bad extended header"));
        }
        let ty = blocks[size_bytes];
        let payload = &blocks[size_bytes + 1..size];
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
        // All supported levels put the level byte at offset 20 and a
        // `-xxX-` method marker at offset 2 (`-lh1-`, `-pm2-`, `-lz5-`
        // …). Distinguish by level byte: level 2/3 use wider size
        // fields, levels 0/1 use a u8 size.
        if pos + 21 > input.len() || input[pos + 2] != b'-' || input[pos + 6] != b'-' {
            return Err(Error::InvalidData("lha: bad header"));
        }
        match input[pos + 20] {
            0 | 1 => pos = decode_level01(input, pos, &mut entries)?,
            2 => {
                let size16 = u16le(&input[pos..]) as usize;
                pos = decode_level2(input, pos, size16, &mut entries)?;
            }
            3 => pos = decode_level3(input, pos, &mut entries)?,
            _ => return Err(Error::InvalidData("lha: bad header level")),
        }
    }
}

/// Decode the member payload for `method`. `raw` is the packed byte
/// range; `orig` is the header's original size. Stored-like methods
/// return `raw` unchanged (verifying `raw.len() == orig`).
fn decode_member_data(method: &[u8; 5], raw: &[u8], orig: usize) -> Result<Vec<u8>, Error> {
    match method {
        b"-lhd-" => Ok(Vec::new()),
        // Stored / null-decoded methods.
        b"-lh0-" | b"-lz4-" | b"-pm0-" => {
            if raw.len() != orig {
                return Err(Error::InvalidData("lha: size mismatch"));
            }
            Ok(raw.to_vec())
        }
        b"-lh1-" => super::lzhuf::decode(raw, orig),
        _ if super::lzh_dyn::supported(method) => super::lzh_dyn::decode(raw, orig),
        _ if super::lzh_st0::supported(method) => super::lzh_st0::decode(raw, orig),
        b"-lh4-" | b"-lh5-" => crate::compress::lzh::st1::decode(14, 4, raw, orig),
        b"-lh6-" => crate::compress::lzh::st1::decode(16, 5, raw, orig),
        b"-lh7-" => crate::compress::lzh::st1::decode(17, 5, raw, orig),
        _ if super::larc::supported(method) => super::larc::decode(method, raw, orig),
        _ if super::pmarc::supported(method) => super::pmarc::decode(method, raw, orig),
        _ => Err(Error::Unsupported("lha: unsupported method")),
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
    let method: &[u8; 5] = hdr
        .first_chunk::<5>()
        .ok_or(Error::InvalidData("lha: bad method"))?;
    let is_dir = method == b"-lhd-";
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
    let data = decode_member_data(method, &input[data_start..data_start + take], orig)?;
    if let Some(c) = crc16
        && !is_dir
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
    let method: &[u8; 5] = hdr
        .first_chunk::<5>()
        .ok_or(Error::InvalidData("lha: bad method"))?;
    let is_dir = method == b"-lhd-";
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
    let data = decode_member_data(method, &input[data_start..data_start + take], orig)?;
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

/// Level-3 base header (32 bytes):
/// `[word_size u16 = 4][method 5B][packed u32][orig u32]
///  [unix time u32][reserved u8][level u8 = 3][crc16 u16le]
///  [os id u8][header_len u32][ext headers…]`. `header_len` counts the
/// whole header from offset 0 (including the word-size field) and is
/// capped at 1 MiB like the reference. Extended headers use `u32`
/// size fields and end on a `u32` zero.
fn decode_level3(input: &[u8], pos: usize, entries: &mut Vec<LhaEntry>) -> Result<usize, Error> {
    const BASE: usize = 32;
    const MAX: usize = 1024 * 1024;
    if u16le(&input[pos..]) != 4 {
        return Err(Error::InvalidData("lha: bad level-3 word size"));
    }
    if pos + BASE > input.len() {
        return Err(Error::InvalidData("lha: truncated header"));
    }
    let hsize = u32le(&input[pos + 24..]) as usize;
    if !(BASE..=MAX).contains(&hsize) || pos + hsize > input.len() {
        return Err(Error::InvalidData("lha: bad level-3 header size"));
    }
    let hdr = &input[pos + 2..pos + hsize];
    let method: &[u8; 5] = hdr
        .first_chunk::<5>()
        .ok_or(Error::InvalidData("lha: bad method"))?;
    let is_dir = method == b"-lhd-";
    let packed = u32le(&hdr[5..]) as usize;
    let orig = u32le(&hdr[9..]) as usize;
    let mtime = u32le(&hdr[13..]);
    if hdr[18] != 3 {
        return Err(Error::InvalidData("lha: bad header level"));
    }
    let crc = u16le(&hdr[19..]);
    // Extended headers at absolute offset 28 (hdr[26..]), u32 sizes.
    let ((name, dir), _) = walk_ext_headers_sized(&hdr[26..], 4)?;
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
    let data_start = pos + hsize;
    let take = if is_dir { 0 } else { packed };
    if data_start + take > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    let data = decode_member_data(method, &input[data_start..data_start + take], orig)?;
    if !is_dir && crate::util::crc16::crc16(&data) != crc {
        return Err(Error::InvalidData("lha: CRC-16 mismatch"));
    }
    entries.push(LhaEntry {
        name,
        level: 3,
        is_dir,
        crc16: Some(crc),
        mtime,
        data,
    });
    Ok(data_start + take)
}

/// Wrap  in a level-0 member header for  and append
/// the archive terminator. Test-only helper shared by the codec
/// mirror-encoder tests.
#[cfg(test)]
pub(crate) fn level0_archive(
    method: &[u8; 5],
    name: &str,
    payload: &[u8],
    orig: usize,
    data: &[u8],
) -> Vec<u8> {
    let namelen = name.len();
    let hsize = (5 + 4 + 4 + 4 + 1 + 1 + 1 + namelen + 2) as u8;
    let mut a = Vec::new();
    a.push(hsize);
    a.push(0); // checksum, filled below
    a.extend_from_slice(method);
    a.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    a.extend_from_slice(&(orig as u32).to_le_bytes());
    a.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // dos time
    a.push(0x20); // attribute
    a.push(0); // level
    a.push(namelen as u8);
    a.extend_from_slice(name.as_bytes());
    a.extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
    let cksum = a[2..2 + hsize as usize]
        .iter()
        .fold(0u8, |x, &b| x.wrapping_add(b));
    a[1] = cksum;
    a.extend_from_slice(payload);
    a.push(0); // terminator
    a
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
        a[4] = b'1'; // -l10- (unsupported)
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
    fn level3_roundtrip() {
        let mut enc = crate::archive::lha::encode::LhaEncoder::with_level(3).unwrap();
        enc.add_file("dir/sub/hello.txt", b"level three", 0x6000_0000)
            .unwrap();
        enc.add_dir("docs", 0).unwrap();
        let a = enc.finish();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].level, 3);
        assert_eq!(e[0].name, "dir/sub/hello.txt");
        assert_eq!(e[0].data, b"level three");
        assert_eq!(e[0].mtime, 0x6000_0000);
        assert!(e[1].is_dir);
        assert_eq!(e[1].name, "docs/");
    }

    #[test]
    fn level3_wire_layout() {
        // Spot-check the level-3 wire format: u16 word size = 4, level
        // byte 3 at offset 20, u32 total header size at offset 24, and
        // u32-sized extended headers ending on a u32 zero.
        let a = crate::archive::lha::encode::encode_level(&[("f.txt", b"x")], 3).unwrap();
        assert_eq!(&a[..2], &[4, 0]);
        assert_eq!(&a[2..7], b"-lh0-");
        assert_eq!(a[19], 0x20); // reserved
        assert_eq!(a[20], 3); // level
        assert_eq!(u16le(&a[21..]), crate::util::crc16::crc16(b"x"));
        let hsize = u32le(&a[24..]) as usize;
        // First extended block: u32 size 7 + type 0x00 header CRC.
        assert_eq!(u32le(&a[28..]), 7);
        assert_eq!(a[32], 0x00);
        // Second block: u32 size + type 0x01 filename ("f.txt" = 5).
        assert_eq!(u32le(&a[35..]), 4 + 1 + 5);
        assert_eq!(a[39], 0x01);
        assert_eq!(&a[40..45], b"f.txt");
        // Chain ends on a u32 zero at the tail of the header.
        assert_eq!(&a[hsize - 4..hsize], &[0; 4]);
        assert_eq!(a[hsize], b'x'); // payload follows the header
        assert_eq!(a[hsize + 1], 0); // archive terminator
        let e = decode(&a).unwrap();
        assert_eq!(e[0].level, 3);
    }

    #[test]
    fn level3_long_name() {
        // u32 extended-header sizes lift the level-2 64 KiB limit:
        // exercise a filename that does not fit a u16 ext size.
        let name = "n".repeat(70_000);
        let a = crate::archive::lha::encode::encode_level(&[(&name, b"d")], 3).unwrap();
        // 0x01 filename block (second ext) carries a u32 size > u16::MAX.
        assert_eq!(u32le(&a[35..]), 70_000 + 5);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, name);
        assert_eq!(e[0].data, b"d");
    }

    #[test]
    fn level3_header_too_large() {
        // The decoder caps level-3 headers at 1 MiB; the encoder
        // refuses names that would exceed it instead of emitting
        // undecodable bytes.
        let name = "n".repeat(1024 * 1024);
        let mut enc = crate::archive::lha::encode::LhaEncoder::with_level(3).unwrap();
        assert!(enc.add_file(&name, b"d", 0).is_err());
    }

    #[test]
    fn level_rejects_bad_level() {
        assert!(crate::archive::lha::encode::LhaEncoder::with_level(3).is_ok());
        assert!(crate::archive::lha::encode::LhaEncoder::with_level(4).is_err());
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

    /// Packed size field of the first entry (level-0/1 header: u32le
    /// at archive offset 7).
    fn packed_size(a: &[u8]) -> usize {
        u32le(&a[7..]) as usize
    }

    #[test]
    fn lh5_encode_roundtrip() {
        // Compressible data must produce a packed stream smaller than
        // the input and tagged `-lh5-`.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(500);
        let mut enc = crate::archive::lha::encode::LhaEncoder::new()
            .with_method(b"-lh5-")
            .unwrap();
        enc.add_file("fox.txt", &data, 0).unwrap();
        let a = enc.finish();
        assert_eq!(&a[2..7], b"-lh5-");
        assert!(packed_size(&a) < data.len());
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "fox.txt");
        assert_eq!(e[0].data, data.as_slice());
    }

    #[test]
    fn lh4_lh6_lh7_encode_roundtrip() {
        // Same stream format parameterized by window/offset width.
        for (method, tag) in [
            (b"-lh4-", "-lh4-"),
            (b"-lh6-", "-lh6-"),
            (b"-lh7-", "-lh7-"),
        ] {
            let mut data = Vec::new();
            data.extend_from_slice(&b"abcabcabc".repeat(20_000));
            data.extend_from_slice(&b"tail-unique-bytes-0123456789"[..]);
            let mut enc = crate::archive::lha::encode::LhaEncoder::new()
                .with_method(method)
                .unwrap();
            enc.add_file("big.bin", &data, 0).unwrap();
            let a = enc.finish();
            assert_eq!(&a[2..7], tag.as_bytes());
            let e = decode(&a).unwrap();
            assert_eq!(e[0].data, data.as_slice());
        }
    }

    #[test]
    fn lh5_falls_back_to_stored() {
        // Incompressible input: the entry is written `-lh0-`, like
        // real LHA.
        let mut data = Vec::new();
        let mut s = 0x9e3779b9u32;
        while data.len() < 512 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            data.push((s >> 24) as u8);
        }
        let mut enc = crate::archive::lha::encode::LhaEncoder::new()
            .with_method(b"-lh5-")
            .unwrap();
        enc.add_file("rand.bin", &data, 0).unwrap();
        let a = enc.finish();
        assert_eq!(&a[2..7], b"-lh0-");
        let e = decode(&a).unwrap();
        assert_eq!(e[0].data, data.as_slice());
    }

    #[test]
    fn lh5_level2_roundtrip() {
        // Compressed payload behind a level-2 header.
        let data = b"level two lh5 payload ".repeat(300);
        let mut enc = crate::archive::lha::encode::LhaEncoder::with_level(2)
            .unwrap()
            .with_method(b"-lh5-")
            .unwrap();
        enc.add_file("d2/sub/file.txt", &data, 0x6000_0000).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert_eq!(e[0].level, 2);
        assert_eq!(e[0].name, "d2/sub/file.txt");
        assert_eq!(e[0].data, data.as_slice());
    }

    #[test]
    fn with_method_rejects_unsupported() {
        use crate::archive::lha::encode::LhaEncoder;
        assert!(matches!(
            LhaEncoder::new().with_method(b"-lh1-"),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            LhaEncoder::new().with_method(b"-lz5-"),
            Err(Error::Unsupported(_))
        ));
        // `-lh0-` and the stored aliases stay valid selections.
        assert!(LhaEncoder::new().with_method(b"-lh0-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-lz4-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-pm0-").is_ok());
    }

    #[test]
    fn stored_alias_methods_roundtrip() {
        // `-lz4-` / `-pm0-` are stored payloads under a different tag.
        for method in [b"-lz4-", b"-pm0-"] {
            let mut enc = crate::archive::lha::encode::LhaEncoder::new()
                .with_method(method)
                .unwrap();
            enc.add_file("a.bin", b"raw stored bytes", 0).unwrap();
            let a = enc.finish();
            assert_eq!(&a[2..7], method.as_slice());
            let e = decode(&a).unwrap();
            assert_eq!(e[0].data, b"raw stored bytes");
        }
    }
}
