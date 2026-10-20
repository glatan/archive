//! LHA / LZH archive read/write support.
//!
//! Reference: lha header documentation ("apphead"/lzh_note) as used by
//! the original LHA and GNU `lha`. Supported scope:
//!
//! - header levels 0, 1, 2, and 3 for reading;
//! - methods `-lh0-` (stored), `-lhd-` (directory marker),
//!   `-lh4-` through `-lh7-` (Okumura "st1" static Huffman,
//!   de facto 16/64/128 KiB rings), LArc `-lzs-`/`-lz4-`/`-lz5-`,
//!   and PMarc `-pm0-`/`-pm1-`/`-pm2-` for reading; `-lh1-`,
//!   `-lh2-`, and `-lh3-` are intentionally rejected because no
//!   rights-clean format reference exists, and other methods are
//!   rejected with [Error::Unsupported];
//! - writing emits `-lh0-`/`-lhd-` entries at header level 0, 1, 2, or 3
//!   (`LhaEncoder::with_level`), plus `-lz4-`/`-pm0-` stored-alias,
//!   `-lh4-`/`-lh5-`/`-lh6-`/`-lh7-` static-Huffman, and LArc
//!   `-lzs-`/`-lz5-` LZSS file entries via
//!   `LhaEncoder::with_method` (stored fallback when
//!   compression does not win). Level 0 requires the whole filename to
//!   fit in one byte (at most 233 bytes — the u8 header-size field bounds 22 + name); levels 1/2/3 carry the name
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

/// Multi-disk (MDF) segment descriptor from extended header `0x39`.
/// Reassembling the segments into the original file is the caller's
/// responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LhaSpan {
    /// Span-mode byte stored in the block.
    pub mode: u8,
    /// Byte offset of this run within the original file
    /// (`i32` on the wire).
    pub beginning_offset: u32,
    /// Bytes of the original file carried by this member
    /// (`i32` on the wire).
    pub size_of_run: u32,
}

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
    /// MS-DOS attribute byte: the level-0/1 basic-header attribute,
    /// or extended header `0x40` when present.
    pub dos_attr: Option<u8>,
    /// UNIX permission bits from extended header `0x50`.
    pub unix_mode: Option<u16>,
    /// UNIX user id from extended header `0x51`.
    pub unix_uid: Option<u16>,
    /// UNIX group id from extended header `0x51` (the wire stores
    /// gid first, per LHa `header.doc.md`).
    pub unix_gid: Option<u16>,
    /// UNIX `time_t` from extended header `0x54`.
    pub unix_mtime: Option<u32>,
    /// Archive comment from extended header `0x3F`; raw payload
    /// (encoding/layout is application-defined).
    pub comment: Option<Vec<u8>>,
    /// Windows FILETIME record from extended header `0x41`; raw
    /// payload (encoding/layout is application-defined).
    pub windows_filetime: Option<Vec<u8>>,
    /// Large-file size record from extended header `0x42`; raw
    /// payload (encoding/layout is application-defined).
    pub large_file_size: Option<Vec<u8>>,
    /// UNIX group name from extended header `0x52`; raw payload
    /// (encoding/layout is application-defined).
    pub unix_group_name: Option<Vec<u8>>,
    /// UNIX user name from extended header `0x53`; raw payload
    /// (encoding/layout is application-defined).
    pub unix_user_name: Option<Vec<u8>>,
    /// Multi-disk segment descriptor from extended header `0x39`.
    pub span: Option<LhaSpan>,
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

/// Extended-header fields collected while walking a chain: the
/// filename and directory blocks plus any attribute blocks.
#[derive(Default)]
struct ExtHeaders {
    name: Option<Vec<u8>>,
    dir: Option<Vec<u8>>,
    dos_attr: Option<u8>,
    unix_mode: Option<u16>,
    unix_uid: Option<u16>,
    unix_gid: Option<u16>,
    unix_mtime: Option<u32>,
    comment: Option<Vec<u8>>,
    windows_filetime: Option<Vec<u8>>,
    large_file_size: Option<Vec<u8>>,
    unix_group_name: Option<Vec<u8>>,
    unix_user_name: Option<Vec<u8>>,
    span: Option<LhaSpan>,
}

/// Walk a level-1/2 extended-header chain and return (filename,
/// directory-path components, consumed bytes). `blocks` starts at the
/// first `u16` extension size; each block is `u16 size` (counting the
/// size field itself) + `u8 type` + payload, and the chain ends with a
/// `u16` zero terminator (counted in `consumed`).
fn walk_ext_headers(blocks: &[u8]) -> Result<(ExtHeaders, usize), Error> {
    walk_ext_headers_sized(blocks, 2)
}

/// As [`walk_ext_headers`], but the size field width is `size_bytes`
/// (2 for levels 1/2, 4 for level 3).
fn walk_ext_headers_sized(
    mut blocks: &[u8],
    size_bytes: usize,
) -> Result<(ExtHeaders, usize), Error> {
    let mut ext = ExtHeaders::default();
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
            return Ok((ext, consumed + size_bytes));
        }
        if size < size_bytes + 1 || size > blocks.len() {
            return Err(Error::InvalidData("lha: bad extended header"));
        }
        let ty = blocks[size_bytes];
        let payload = &blocks[size_bytes + 1..size];
        match ty {
            0x01 => ext.name = Some(payload.to_vec()),
            0x02 => ext.dir = Some(payload.to_vec()),
            // Multi-disk segment: mode byte + i32 run offset + i32 run
            // size; reassembly is the caller's responsibility.
            0x39 if payload.len() >= 9 => {
                ext.span = Some(LhaSpan {
                    mode: payload[0],
                    beginning_offset: u32le(&payload[1..]),
                    size_of_run: u32le(&payload[5..]),
                });
            }
            // Comment: no length or charset constraint is defined,
            // so the raw payload is exposed.
            0x3F => ext.comment = Some(payload.to_vec()),
            0x40 if !payload.is_empty() => ext.dos_attr = Some(payload[0]),
            // Windows FILETIMEs and the >4 GiB size record: the
            // primary references do not pin down the byte order, so
            // the raw payload is passed through for the caller.
            0x41 => ext.windows_filetime = Some(payload.to_vec()),
            0x42 => ext.large_file_size = Some(payload.to_vec()),
            0x50 if payload.len() >= 2 => ext.unix_mode = Some(u16le(payload)),
            // `header.doc.md` stores gid first, then uid;
            // lzhformat lists the fields in the same order.
            0x51 if payload.len() >= 4 => {
                ext.unix_gid = Some(u16le(payload));
                ext.unix_uid = Some(u16le(&payload[2..]));
            }
            // Group/user names have no defined charset (Shift_JIS
            // variants circulate); expose the raw bytes.
            0x52 => ext.unix_group_name = Some(payload.to_vec()),
            0x53 => ext.unix_user_name = Some(payload.to_vec()),
            0x54 if payload.len() >= 4 => ext.unix_mtime = Some(u32le(payload)),
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
    decode_limited(input, usize::MAX)
}

/// Decode with a maximum total payload size limit across all entries.
///
/// A member whose declared original size exceeds the remaining output
/// budget is rejected with [`Error::OutputLimitExceeded`] before its
/// data is materialized.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<LhaEntry>, Error> {
    decode_limited(input, max_output)
}

fn decode_limited(input: &[u8], max_output: usize) -> Result<Vec<LhaEntry>, Error> {
    let mut entries = Vec::new();
    let mut emitted = 0usize;
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
            0 | 1 => pos = decode_level01(input, pos, &mut entries, max_output, &mut emitted)?,
            2 => {
                let size16 = u16le(&input[pos..]) as usize;
                pos = decode_level2(input, pos, size16, &mut entries, max_output, &mut emitted)?;
            }
            3 => pos = decode_level3(input, pos, &mut entries, max_output, &mut emitted)?,
            _ => return Err(Error::InvalidData("lha: bad header level")),
        }
    }
}

/// Reject a member whose declared original size would push the decoded
/// total past `max_output`, before its data is materialized.
fn check_orig_budget(orig: usize, max_output: usize, emitted: usize) -> Result<(), Error> {
    if orig > max_output.saturating_sub(emitted) {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(())
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
        // `-lh1-` (lzhuf adaptive Huffman), `-lh2-` (LHa `dhuf.c`
        // dynamic Huffman), and `-lh3-` (LHa `shuf.c` static
        // Huffman "st0") are intentionally unsupported: their wire
        // formats are documented only by implementation source
        // (`lzhuf.c` carries no explicit license grant;
        // `dhuf.c`/`shuf.c` sit under LHa for UNIX's non-OSI
        // redistribution terms), so no clean reference exists to
        // implement against.
        b"-lh1-" | b"-lh2-" | b"-lh3-" => {
            Err(Error::Unsupported("lha: method intentionally unsupported"))
        }
        b"-lh4-" | b"-lh5-" => crate::compress::lzh::st1::decode(14, 4, raw, orig),
        b"-lh6-" => crate::compress::lzh::st1::decode(16, 5, raw, orig),
        b"-lh7-" => crate::compress::lzh::st1::decode(17, 5, raw, orig),
        _ if super::larc::supported(method) => super::larc::decode(method, raw, orig),
        _ if super::pmarc::supported(method) => super::pmarc::decode(method, raw, orig),
        _ => Err(Error::Unsupported("lha: unsupported method")),
    }
}

fn decode_level01(
    input: &[u8],
    pos: usize,
    entries: &mut Vec<LhaEntry>,
    max_output: usize,
    emitted: &mut usize,
) -> Result<usize, Error> {
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
    let (name, crc16, packed, data_start, ext) = if level == 0 {
        // filename + u16 CRC-16
        if 20 + name_len + 2 > hsize {
            return Err(Error::InvalidData("lha: truncated crc"));
        }
        (
            sanitize_basic_name(name_field)?,
            Some(u16le(&hdr[20 + name_len..])),
            packed,
            pos + 2 + hsize,
            ExtHeaders::default(),
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
        let (ext, consumed) = walk_ext_headers(ext_area)?;
        let ext_bytes = consumed - 2; // u16 size field already in hsize
        let packed = packed
            .checked_sub(ext_bytes)
            .ok_or(Error::InvalidData("lha: bad skip size"))?;
        let name = match (&ext.name, &ext.dir) {
            (None, None) => sanitize_basic_name(name_field)?,
            (ext_name, dir) => {
                let mut s = match dir {
                    Some(d) => sanitize_name(d)?,
                    None => String::new(),
                };
                if !s.is_empty() && !s.ends_with('/') {
                    s.push('/');
                }
                let base = match ext_name {
                    Some(n) => sanitize_name(n)?,
                    None => sanitize_basic_name(name_field)?,
                };
                s.push_str(&base);
                s
            }
        };
        (name, Some(crc), packed, pos + 2 + hsize + ext_bytes, ext)
    };
    let mut name = name;
    if is_dir && !name.ends_with('/') {
        name.push('/');
    }
    // The packed-size field always advances the stream, even for
    // `-lhd-` directory entries (which should carry packed=0);
    // otherwise a non-conformant packed>0 dir entry would desync
    // the following header scan.
    let take = packed;
    let data_end = data_start
        .checked_add(take)
        .ok_or(Error::InvalidData("lha: truncated entry data"))?;
    if data_end > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    check_orig_budget(orig, max_output, *emitted)?;
    let data = decode_member_data(method, &input[data_start..data_end], orig)?;
    *emitted = emitted.saturating_add(data.len());
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
        // hdr[17] is the basic-header MS-DOS attribute byte; an
        // explicit `0x40` extended attribute takes precedence.
        dos_attr: ext.dos_attr.or(Some(hdr[17])),
        unix_mode: ext.unix_mode,
        unix_uid: ext.unix_uid,
        unix_gid: ext.unix_gid,
        unix_mtime: ext.unix_mtime,
        comment: ext.comment,
        windows_filetime: ext.windows_filetime,
        large_file_size: ext.large_file_size,
        unix_group_name: ext.unix_group_name,
        unix_user_name: ext.unix_user_name,
        span: ext.span,
        data,
    });
    Ok(data_end)
}

fn decode_level2(
    input: &[u8],
    pos: usize,
    size16: usize,
    entries: &mut Vec<LhaEntry>,
    max_output: usize,
    emitted: &mut usize,
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
    let (ext, _) = walk_ext_headers(&hdr[22..])?;
    let mut name = match (&ext.name, &ext.dir) {
        (Some(n), Some(d)) => {
            let mut s = sanitize_name(d)?;
            if !s.is_empty() && !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(&sanitize_name(n)?);
            s
        }
        (Some(n), None) => sanitize_name(n)?,
        _ => return Err(Error::InvalidData("lha: no filename")),
    };
    if is_dir && !name.ends_with('/') {
        name.push('/');
    }
    let data_start = pos + size16;
    // The packed-size field always advances the stream, even for
    // `-lhd-` directory entries (which should carry packed=0);
    // otherwise a non-conformant packed>0 dir entry would desync
    // the following header scan.
    let take = packed;
    let data_end = data_start
        .checked_add(take)
        .ok_or(Error::InvalidData("lha: truncated entry data"))?;
    if data_end > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    check_orig_budget(orig, max_output, *emitted)?;
    let data = decode_member_data(method, &input[data_start..data_end], orig)?;
    *emitted = emitted.saturating_add(data.len());
    if !is_dir && crate::util::crc16::crc16(&data) != crc {
        return Err(Error::InvalidData("lha: CRC-16 mismatch"));
    }
    entries.push(LhaEntry {
        name,
        level: 2,
        is_dir,
        crc16: Some(crc),
        mtime,
        dos_attr: ext.dos_attr,
        unix_mode: ext.unix_mode,
        unix_uid: ext.unix_uid,
        unix_gid: ext.unix_gid,
        unix_mtime: ext.unix_mtime,
        comment: ext.comment,
        windows_filetime: ext.windows_filetime,
        large_file_size: ext.large_file_size,
        unix_group_name: ext.unix_group_name,
        unix_user_name: ext.unix_user_name,
        span: ext.span,
        data,
    });
    Ok(data_end)
}

/// Level-3 base header (32 bytes):
/// `[word_size u16 = 4][method 5B][packed u32][orig u32]
///  [unix time u32][reserved u8][level u8 = 3][crc16 u16le]
///  [os id u8][header_len u32][ext headers…]`. `header_len` counts the
/// whole header from offset 0 (including the word-size field) and is
/// capped at 1 MiB like the reference. Extended headers use `u32`
/// size fields and end on a `u32` zero.
fn decode_level3(
    input: &[u8],
    pos: usize,
    entries: &mut Vec<LhaEntry>,
    max_output: usize,
    emitted: &mut usize,
) -> Result<usize, Error> {
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
    let (ext, _) = walk_ext_headers_sized(&hdr[26..], 4)?;
    let mut name = match (&ext.name, &ext.dir) {
        (Some(n), Some(d)) => {
            let mut s = sanitize_name(d)?;
            if !s.is_empty() && !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(&sanitize_name(n)?);
            s
        }
        (Some(n), None) => sanitize_name(n)?,
        _ => return Err(Error::InvalidData("lha: no filename")),
    };
    if is_dir && !name.ends_with('/') {
        name.push('/');
    }
    let data_start = pos + hsize;
    // The packed-size field always advances the stream, even for
    // `-lhd-` directory entries (which should carry packed=0);
    // otherwise a non-conformant packed>0 dir entry would desync
    // the following header scan.
    let take = packed;
    let data_end = data_start
        .checked_add(take)
        .ok_or(Error::InvalidData("lha: truncated entry data"))?;
    if data_end > input.len() {
        return Err(Error::InvalidData("lha: truncated entry data"));
    }
    check_orig_budget(orig, max_output, *emitted)?;
    let data = decode_member_data(method, &input[data_start..data_end], orig)?;
    *emitted = emitted.saturating_add(data.len());
    if !is_dir && crate::util::crc16::crc16(&data) != crc {
        return Err(Error::InvalidData("lha: CRC-16 mismatch"));
    }
    entries.push(LhaEntry {
        name,
        level: 3,
        is_dir,
        crc16: Some(crc),
        mtime,
        dos_attr: ext.dos_attr,
        unix_mode: ext.unix_mode,
        unix_uid: ext.unix_uid,
        unix_gid: ext.unix_gid,
        unix_mtime: ext.unix_mtime,
        comment: ext.comment,
        windows_filetime: ext.windows_filetime,
        large_file_size: ext.large_file_size,
        unix_group_name: ext.unix_group_name,
        unix_user_name: ext.unix_user_name,
        span: ext.span,
        data,
    });
    Ok(data_end)
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
    fn lhd_nonzero_packed_stays_in_sync() {
        // A non-conformant -lhd- entry carrying packed > 0 must
        // still advance the stream by that many bytes; otherwise
        // the next member header is misread.
        let mut enc = crate::archive::lha::encode::LhaEncoder::new();
        enc.add_dir("docs", 0).unwrap();
        enc.add_file("f.txt", b"x", 0).unwrap();
        let mut a = enc.finish();
        // level-0 header: packed is u32le at bytes 7..11; the
        // whole header spans a[0] + 2 bytes.
        let hlen = a[0] as usize + 2;
        a[7..11].copy_from_slice(&4u32.to_le_bytes());
        // recompute the header checksum (sum of bytes 2..hlen mod 256)
        let sum: u8 = a[2..hlen].iter().fold(0u8, |s, &b| s.wrapping_add(b));
        a[1] = sum;
        // splice 4 junk bytes between the dir header and the file member
        a.splice(hlen..hlen, [0xAA; 4]);
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert!(e[0].is_dir);
        assert_eq!(e[1].name, "f.txt");
        assert_eq!(e[1].data, b"x");
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
        // `-lh0-`, the stored aliases, the LArc LZSS methods, and the
        // PMarc literal-block methods stay valid selections.
        assert!(LhaEncoder::new().with_method(b"-lh0-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-lz4-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-pm0-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-lzs-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-lz5-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-pm1-").is_ok());
        assert!(LhaEncoder::new().with_method(b"-pm2-").is_ok());
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

    #[test]
    fn lzs_lz5_encode_roundtrip() {
        // LArc LZSS methods: compressible data keeps its method tag
        // and shrinks; decode must return the original bytes.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(500);
        for method in [b"-lzs-", b"-lz5-"] {
            let mut enc = crate::archive::lha::encode::LhaEncoder::new()
                .with_method(method)
                .unwrap();
            enc.add_file("fox.txt", &data, 0).unwrap();
            let a = enc.finish();
            assert_eq!(&a[2..7], method.as_slice());
            assert!(packed_size(&a) < data.len());
            let e = decode(&a).unwrap();
            assert_eq!(e.len(), 1);
            assert_eq!(e[0].name, "fox.txt");
            assert_eq!(e[0].data, data.as_slice());
        }
    }

    #[test]
    fn lzs_lz5_fall_back_to_stored() {
        // Incompressible input under `-lzs-`/`-lz5-` is emitted
        // `-lh0-`, like the st1 methods.
        let mut data = Vec::new();
        let mut s = 0x9e3779b9u32;
        while data.len() < 512 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            data.push((s >> 24) as u8);
        }
        for method in [b"-lzs-", b"-lz5-"] {
            let mut enc = crate::archive::lha::encode::LhaEncoder::new()
                .with_method(method)
                .unwrap();
            enc.add_file("rand.bin", &data, 0).unwrap();
            let a = enc.finish();
            assert_eq!(&a[2..7], b"-lh0-");
            let e = decode(&a).unwrap();
            assert_eq!(e[0].data, data.as_slice());
        }
    }

    #[test]
    fn pm1_pm2_archive_roundtrip() {
        // PMarc literal-block streams behind a level-0 header;
        // compressible input keeps the selected method tag.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(500);
        for method in [b"-pm1-", b"-pm2-"] {
            let mut enc = crate::archive::lha::encode::LhaEncoder::new()
                .with_method(method)
                .unwrap();
            enc.add_file("fox.txt", &data, 0).unwrap();
            let a = enc.finish();
            assert_eq!(&a[2..7], method.as_slice());
            assert!(packed_size(&a) < data.len());
            let e = decode(&a).unwrap();
            assert_eq!(e[0].name, "fox.txt");
            assert_eq!(e[0].data, data.as_slice());
        }
    }

    #[test]
    fn level1_unix_ext_attrs() {
        // level1.lzh (reference LHa, OS id 'U') carries UNIX ext
        // blocks: 0x50 permission 0o100644, 0x51 gid+uid 1000 (gid is
        // stored first, per header.doc.md), 0x54 time_t.
        let a = include_bytes!("../../../tests/fixtures/lha/level1.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e[0].unix_mode, Some(0o100644));
        assert_eq!(e[0].unix_gid, Some(1000));
        assert_eq!(e[0].unix_uid, Some(1000));
        assert_eq!(e[0].unix_mtime, Some(0x6ab9_cea1));
        assert_eq!(e[1].unix_mode, Some(0o100644));
        assert_eq!(e[1].unix_gid, Some(1000));
        assert_eq!(e[1].unix_uid, Some(1000));
        assert_eq!(e[1].unix_mtime, Some(0x6ab9_cea1));
    }

    #[test]
    fn dos_attr_from_basic_header() {
        // The level-0/1 basic-header attribute byte surfaces as
        // `dos_attr` (0x20 file, 0x10 directory).
        let mut enc = crate::archive::lha::encode::LhaEncoder::new();
        enc.add_file("f.txt", b"x", 0).unwrap();
        enc.add_dir("d", 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert_eq!(e[0].dos_attr, Some(0x20));
        assert_eq!(e[1].dos_attr, Some(0x10));
        // The level-1 fixture carries the same basic attribute byte.
        let a = include_bytes!("../../../tests/fixtures/lha/level1.lzh");
        let e = decode(a).unwrap();
        assert_eq!(e[0].dos_attr, Some(0x20));
        assert_eq!(e[0].span, None);
    }

    #[test]
    fn span_header_exposed() {
        // Hand-built level-2 header carrying a 0x39 multi-disk (MDF)
        // block: u8 mode + i32 beginning_offset + i32 size_of_run.
        let name = b"abc";
        let mut ext = Vec::new();
        ext.extend_from_slice(&5u16.to_le_bytes()); // header-crc block
        ext.push(0x00);
        ext.extend_from_slice(&0u16.to_le_bytes()); // hcrc placeholder
        ext.extend_from_slice(&((3 + name.len()) as u16).to_le_bytes());
        ext.push(0x01);
        ext.extend_from_slice(name);
        ext.extend_from_slice(&12u16.to_le_bytes()); // size = 2+1+9
        ext.push(0x39);
        ext.push(1); // span mode
        ext.extend_from_slice(&12i32.to_le_bytes());
        ext.extend_from_slice(&3i32.to_le_bytes());
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
        let hcrc = crate::util::crc16::crc16(&h);
        h[27..29].copy_from_slice(&hcrc.to_le_bytes());
        h.extend_from_slice(b"abc");
        h.push(0);
        let e = decode(&h).unwrap();
        assert_eq!(
            e[0].span,
            Some(LhaSpan {
                mode: 1,
                beginning_offset: 12,
                size_of_run: 3,
            })
        );
        assert_eq!(e[0].data, b"abc");
    }

    /// Hand-built level-1 archive: a `-lh0-` member `name`/`data`
    /// plus arbitrary extended blocks given as `(type, payload)`
    /// pairs. The basic `hsize` ends at the first extended block's
    /// `u16` size field, like the reference encoder.
    fn level1_with_ext(name: &[u8], data: &[u8], blocks: &[(u8, &[u8])]) -> Vec<u8> {
        let mut exts = Vec::new();
        for &(ty, payload) in blocks {
            let size = (3 + payload.len()) as u16;
            exts.extend_from_slice(&size.to_le_bytes());
            exts.push(ty);
            exts.extend_from_slice(payload);
        }
        let hsize = 25 + name.len();
        let skip = (data.len() + exts.len()) as u32;
        let mut a = Vec::new();
        a.push(hsize as u8);
        a.push(0); // checksum placeholder
        a.extend_from_slice(b"-lh0-");
        a.extend_from_slice(&skip.to_le_bytes());
        a.extend_from_slice(&(data.len() as u32).to_le_bytes());
        a.extend_from_slice(&0u32.to_le_bytes()); // mtime
        a.push(0x20); // MS-DOS attribute
        a.push(1); // level 1
        a.push(name.len() as u8);
        a.extend_from_slice(name);
        a.extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        a.push(b'U'); // OS id
        a.extend_from_slice(&exts);
        a.extend_from_slice(&0u16.to_le_bytes()); // ext terminator
        a[1] = a[2..2 + hsize].iter().fold(0u8, |x, &b| x.wrapping_add(b));
        a.extend_from_slice(data);
        a.push(0); // archive terminator
        a
    }

    #[test]
    fn comment_header_exposed() {
        // Extended header `0x3F` carries an archive comment; it is
        // exposed as raw bytes (no charset/length is defined).
        let payload = b"packed by hand";
        let a = level1_with_ext(b"f.txt", b"abc", &[(0x3F, payload)]);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].comment.as_deref(), Some(&payload[..]));
        assert_eq!(e[0].data, b"abc");
        assert_eq!(e[0].windows_filetime, None);
        assert_eq!(e[0].large_file_size, None);
    }

    #[test]
    fn windows_filetime_header_exposed() {
        // `0x41` carries Windows FILETIME records (UNLHA32 writes
        // create/access/write as three u64s); the primary docs do
        // not pin the byte order, so raw bytes are exposed.
        let payload = [0xabu8; 24];
        let a = level1_with_ext(b"f.txt", b"abc", &[(0x41, &payload)]);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].windows_filetime.as_deref(), Some(&payload[..]));
        assert_eq!(e[0].comment, None);
    }

    #[test]
    fn large_file_size_header_exposed() {
        // `0x42` carries the >4 GiB size record; raw bytes for the
        // same reason as `0x41`.
        let payload = [0x42u8; 16];
        let a = level1_with_ext(b"f.txt", b"abc", &[(0x42, &payload)]);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].large_file_size.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn level1_unix_ext_names() {
        // `0x52`/`0x53` carry group/user names in an undefined
        // charset (Shift_JIS variants circulate); non-UTF-8 bytes
        // must pass through untouched.
        let group = b"wheel";
        let user = [0x83, 0x86, b'u', b'z']; // non-UTF-8 name bytes
        let a = level1_with_ext(b"f.txt", b"abc", &[(0x52, &group[..]), (0x53, &user[..])]);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].unix_group_name.as_deref(), Some(&group[..]));
        assert_eq!(e[0].unix_user_name.as_deref(), Some(&user[..]));
    }

    /// Regression (fuzz run-1791677246, lha-pm1 corrupt): a corrupt
    /// header declaring `orig = 0xFFFFFF1C` must be rejected by the
    /// bounded entry point before ~4 GiB of output is materialized.
    #[test]
    fn decode_bounded_rejects_oversized_declared_orig() {
        // Level-0 member header: method -pm1-, packed = 4,
        // orig = ~4 GiB, filename "a".
        let mut a = Vec::new();
        a.push(23u8); // hsize = 22 + name_len
        a.push(0u8); // checksum placeholder
        a.extend_from_slice(b"-pm1-");
        a.extend_from_slice(&4u32.to_le_bytes()); // packed
        a.extend_from_slice(&0xFFFF_FF1Cu32.to_le_bytes()); // orig
        a.extend_from_slice(&0u32.to_le_bytes()); // mtime
        a.push(0); // MS-DOS attribute
        a.push(0); // level 0
        a.push(1); // name_len
        a.push(b'a');
        a.extend_from_slice(&0u16.to_le_bytes()); // crc16
        a[1] = a[2..2 + 23].iter().fold(0u8, |s, &b| s.wrapping_add(b));
        a.extend_from_slice(&[0u8; 4]); // packed payload
        a.push(0); // archive terminator
        let err = decode_bounded(&a, 64 << 20).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
    }

    #[test]
    fn decode_bounded_enforces_total_limit() {
        let a = crate::archive::lha::encode::encode(&[
            ("one.bin", b"hello world"),
            ("two.bin", b"second file"),
        ])
        .unwrap();
        let e = decode_bounded(&a, 1024).unwrap();
        assert_eq!(e.len(), 2);
        // The second member's declared orig pushes the total past the
        // limit: rejected before decode.
        let err = decode_bounded(&a, 12).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
        // Exactly the combined payload size still fits.
        let e = decode_bounded(&a, 22).unwrap();
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn truncated_prefix_invariant() {
        // EOF is a legal archive end (terminator 0x00 optional),
        // so cuts after a complete member yield a valid partial
        // archive. Invariant: decode(prefix) is Err or a prefix of
        // the full entry list.
        let a = crate::archive::lha::encode::encode(&[
            ("one.txt", b"first entry data"),
            ("two.bin", &[1, 2, 3, 4, 5, 6]),
        ])
        .unwrap();
        let full = decode(&a).unwrap();
        for cut in 0..a.len() {
            if let Ok(prefix) = decode(&a[..cut]) {
                assert!(
                    prefix.len() <= full.len()
                        && full
                            .iter()
                            .zip(prefix.iter())
                            .all(|(x, y)| x.name == y.name && x.data == y.data),
                    "cut={cut}: entries must be a prefix of the full list"
                );
            }
        }
    }
}
