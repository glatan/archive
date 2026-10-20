//! tar archive decoding with GNU and PAX extension support.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

use super::header::{BLOCK_SIZE, FileType, TarHeader};

/// A single entry in a tar archive.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode, decode};
///
/// let mut enc = encode::TarEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries[0].header.name, "hello.txt");
/// assert_eq!(entries[0].data, b"Hello!");
/// ```
#[derive(Debug, Clone)]
pub struct TarEntry {
    /// Parsed header metadata.
    pub header: TarHeader,
    /// File data (empty for directories and links).
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for TarEntry {
    fn name(&self) -> &str {
        &self.header.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decode a tar archive from a byte slice, yielding all entries.
///
/// Handles GNU long name/link extensions and PAX extended headers automatically.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode, decode};
///
/// let mut enc = encode::TarEncoder::new();
/// enc.add_file("a.txt", b"aaa");
/// enc.add_file("b.txt", b"bbb");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries.len(), 2);
/// ```
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] if the archive is truncated,
/// [`Error::InvalidData`] for checksum mismatches or corrupt headers.
pub fn decode(input: &[u8]) -> Result<Vec<TarEntry>, Error> {
    let mut entries = Vec::new();
    for_each_entry(input, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

/// Visit each tar entry. The entry is dropped when `visit` returns,
/// before the next header is read.
pub fn for_each_entry<F>(input: &[u8], mut visit: F) -> Result<(), Error>
where
    F: FnMut(TarEntry) -> Result<(), Error>,
{
    let mut pos = 0;
    let mut zero_block_count = 0;
    // State for GNU/PAX extensions that apply to the next entry
    let mut pending_long_name: Option<String> = None;
    let mut pending_long_link: Option<String> = None;
    let mut pending_pax_attrs: Option<Vec<(String, String)>> = None;
    // PAX global attributes apply to all subsequent entries
    let mut global_pax_attrs: Vec<(String, String)> = Vec::new();

    while pos + BLOCK_SIZE <= input.len() {
        let block: &[u8; BLOCK_SIZE] = input[pos..pos + BLOCK_SIZE]
            .try_into()
            .map_err(|_| Error::UnexpectedEof)?;

        // Check for EOF (two consecutive zero blocks)
        if block.iter().all(|&b| b == 0) {
            zero_block_count += 1;
            pos += BLOCK_SIZE;
            if zero_block_count >= 2 {
                break;
            }
            continue;
        }
        zero_block_count = 0;

        let mut header = TarHeader::parse(block)?;
        pos += BLOCK_SIZE;

        // POSIX ustar: typeflags '2'-'6' (symlink/char/block/dir/fifo)
        // store no data logical records; a nonzero size on these types
        // must be ignored when reading, or foreign archives desync.
        let has_data = !matches!(
            header.file_type,
            FileType::SymLink
                | FileType::CharDevice
                | FileType::BlockDevice
                | FileType::Directory
                | FileType::Fifo
        );

        // For GNU sparse files, skip extended sparse header blocks and
        // use the on-tape data size instead of the logical size.
        let tape_data_size = if !has_data {
            0
        } else if header.file_type == FileType::GnuSparse {
            // If isextended flag is set, read 512-byte extension blocks
            // until one without the flag is found. Each block has 21
            // sparse entries (24 bytes each = 504 bytes) plus a 1-byte
            // isextended flag at offset 504.
            if header._gnu_sparse_extended {
                loop {
                    if pos + BLOCK_SIZE > input.len() {
                        return Err(Error::UnexpectedEof);
                    }
                    let ext_block: &[u8; BLOCK_SIZE] = input[pos..pos + BLOCK_SIZE]
                        .try_into()
                        .map_err(|_| Error::UnexpectedEof)?;
                    pos += BLOCK_SIZE;
                    header
                        .sparse_map
                        .extend(super::header::parse_gnu_sparse_entries(&ext_block[..504]));
                    // isextended flag at byte 504
                    if ext_block[504] == 0 {
                        break;
                    }
                }
            }
            header._gnu_sparse_data_size as usize
        } else {
            header.size as usize
        };

        // Read file data. For GNU sparse files each map segment is
        // stored in its own 512-byte block (zero padded), per GNU
        // tar's old-sparse layout; a file with no map falls back to
        // the contiguous 'size' interpretation.
        let data = if header.file_type == FileType::GnuSparse && !header.sparse_map.is_empty() {
            let mut buf = Vec::new();
            buf.try_reserve(tape_data_size)
                .map_err(|_| Error::InvalidData("tar: sparse buffer too large"))?;
            for &(_, len) in &header.sparse_map {
                let len = len as usize;
                let seg_end = pos.checked_add(len).ok_or(Error::UnexpectedEof)?;
                let seg = input.get(pos..seg_end).ok_or(Error::UnexpectedEof)?;
                buf.extend_from_slice(seg);
                let padded = round_up_to_block_checked(len).ok_or(Error::UnexpectedEof)?;
                pos = pos.checked_add(padded).ok_or(Error::UnexpectedEof)?;
            }
            buf
        } else {
            let data_size = tape_data_size;
            let data = if data_size > 0 {
                let data_end = pos.checked_add(data_size).ok_or(Error::UnexpectedEof)?;
                input
                    .get(pos..data_end)
                    .ok_or(Error::UnexpectedEof)?
                    .to_vec()
            } else {
                Vec::new()
            };
            let padded = round_up_to_block_checked(data_size).ok_or(Error::UnexpectedEof)?;
            pos = pos.checked_add(padded).ok_or(Error::UnexpectedEof)?;
            data
        };

        match header.file_type {
            FileType::GnuLongName => {
                let long_name = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_string();
                pending_long_name = Some(long_name);
                continue;
            }
            FileType::GnuLongLink => {
                let long_link = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_string();
                pending_long_link = Some(long_link);
                continue;
            }
            FileType::PaxHeader => {
                let attrs = parse_pax_attributes(&data);
                pending_pax_attrs = Some(attrs);
                continue;
            }
            FileType::PaxGlobalHeader => {
                // POSIX: a 'g' record persists per keyword until another
                // 'g' record supplies a new value for that same keyword.
                global_pax_attrs.extend(parse_pax_attributes(&data));
                continue;
            }
            _ => {
                let mut header = header;

                // Apply pending GNU extensions
                if let Some(name) = pending_long_name.take() {
                    header.name = name;
                }
                if let Some(link) = pending_long_link.take() {
                    header.link_name = link;
                }

                // Apply global PAX attributes first, then per-entry overrides.
                if !global_pax_attrs.is_empty() || pending_pax_attrs.is_some() {
                    let mut merged_attrs = global_pax_attrs.clone();
                    if let Some(attrs) = pending_pax_attrs.take() {
                        merged_attrs.extend(attrs);
                    }
                    let merged_attrs = effective_pax_attrs(merged_attrs);
                    apply_pax_attributes(&mut header, &merged_attrs);
                    apply_sparse_pax_attributes(&mut header, &merged_attrs);
                }

                visit(TarEntry { header, data })?;
            }
        }
    }

    Ok(())
}

/// Resolve PAX attribute lists per POSIX.1-2008: an extended-header
/// record with an empty value deletes the attribute (the field from
/// the ustar header is used), and later records override earlier ones.
fn effective_pax_attrs(attrs: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (key, value) in attrs {
        out.retain(|(k, _)| k != &key);
        if !value.is_empty() {
            out.push((key, value));
        }
    }
    out
}

/// Apply PAX extended attributes to a tar header, overriding octal-encoded values.
fn apply_pax_attributes(header: &mut TarHeader, attrs: &[(String, String)]) {
    for (key, value) in attrs {
        match key.as_str() {
            "path" => header.name = value.clone(),
            "GNU.sparse.name" => header.name = value.clone(),
            "mode" => {
                if let Some(mode) = parse_pax_mode(value) {
                    header.mode = mode;
                }
            }
            "linkpath" => header.link_name = value.clone(),
            "size" => {
                if let Ok(sz) = value.parse::<u64>() {
                    header.size = sz;
                }
            }
            "GNU.sparse.size" | "GNU.sparse.realsize" => {
                if let Ok(sz) = value.parse::<u64>() {
                    header.size = sz;
                }
            }
            "uid" => {
                if let Ok(v) = value.parse::<u32>() {
                    header.uid = v;
                }
            }
            "gid" => {
                if let Ok(v) = value.parse::<u32>() {
                    header.gid = v;
                }
            }
            "uname" => header.uname = value.clone(),
            "gname" => header.gname = value.clone(),
            "mtime" => {
                if let Some((secs, nsec)) = parse_pax_time(value) {
                    header.mtime = secs;
                    header.mtime_nsec = nsec;
                }
            }
            "atime" => {
                if let Some((secs, nsec)) = parse_pax_time(value) {
                    header.atime = secs;
                    header.atime_nsec = nsec;
                }
            }
            "ctime" => {
                if let Some((secs, nsec)) = parse_pax_time(value) {
                    header.ctime = secs;
                    header.ctime_nsec = nsec;
                }
            }
            "charset" => header.pax_charset = Some(value.clone()),
            "comment" => header.pax_comment = Some(value.clone()),
            "hdrcharset" => header.pax_hdrcharset = Some(value.clone()),
            _ => {} // Ignore unknown PAX attributes
        }
    }
}

fn apply_sparse_pax_attributes(header: &mut TarHeader, attrs: &[(String, String)]) {
    if let Some(map) = parse_sparse_map(attrs) {
        header.sparse_map = map;
    }
}

fn parse_sparse_map(attrs: &[(String, String)]) -> Option<Vec<(u64, u64)>> {
    if let Some(map_value) = attrs
        .iter()
        .rev()
        .find_map(|(key, value)| (key == "GNU.sparse.map").then_some(value.as_str()))
    {
        return parse_sparse_map_record(map_value);
    }

    let mut expected_numblocks = None;
    let mut pending_offset = None;
    let mut map = Vec::new();
    for (key, value) in attrs {
        match key.as_str() {
            "GNU.sparse.numblocks" => expected_numblocks = value.parse::<usize>().ok(),
            "GNU.sparse.offset" => pending_offset = value.parse::<u64>().ok(),
            "GNU.sparse.numbytes" => {
                let offset = pending_offset.take()?;
                let length = value.parse::<u64>().ok()?;
                map.push((offset, length));
            }
            _ => {}
        }
    }

    if pending_offset.is_some() || map.is_empty() {
        return None;
    }
    if let Some(expected) = expected_numblocks
        && expected != map.len()
    {
        return None;
    }
    Some(map)
}

fn parse_sparse_map_record(value: &str) -> Option<Vec<(u64, u64)>> {
    let mut numbers = Vec::new();
    for part in value.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return None;
        }
        numbers.push(trimmed.parse::<u64>().ok()?);
    }

    if numbers.is_empty() || numbers.len() % 2 != 0 {
        return None;
    }

    let mut map = Vec::with_capacity(numbers.len() / 2);
    let mut i = 0;
    while i < numbers.len() {
        map.push((numbers[i], numbers[i + 1]));
        i += 2;
    }
    Some(map)
}

fn parse_pax_mode(value: &str) -> Option<u32> {
    u32::from_str_radix(value, 8).ok()
}

/// Parse a PAX time value (e.g., "1234567890.123456789" or "-1.5") into
/// normalized seconds and nanoseconds.
///
/// The returned pair satisfies `0 <= nsec < 1_000_000_000` and represents the
/// total time as `secs + nsec / 1e9`.
fn parse_pax_time(value: &str) -> Option<(i64, u32)> {
    let mut parts = value.splitn(2, '.');
    let int_part = parts.next()?;
    let secs = int_part.parse::<i64>().ok()?;
    let negative = value.as_bytes().first() == Some(&b'-');
    let frac_nanos = if let Some(frac_str) = parts.next() {
        let frac_str = frac_str.trim_end_matches('0');
        if frac_str.is_empty() {
            0
        } else {
            let mut nsec = 0u32;
            let mut multiplier = 100_000_000u32;
            let mut saw_digit = false;
            for ch in frac_str.bytes().take(9) {
                if ch.is_ascii_digit() {
                    nsec += (ch - b'0') as u32 * multiplier;
                    multiplier /= 10;
                    saw_digit = true;
                } else {
                    return None;
                }
            }
            if !saw_digit {
                return None;
            }
            nsec
        }
    } else {
        0
    };

    let (secs, nsec) = if negative && frac_nanos > 0 {
        (secs.checked_sub(1)?, 1_000_000_000u32 - frac_nanos)
    } else {
        (secs, frac_nanos)
    };
    Some((secs, nsec))
}

/// Parse PAX extended header data into key-value attribute pairs.
///
/// Format: each record is `length key=value\n` where `length` includes
/// the length field itself, the space, key, `=`, value, and the trailing newline.
fn parse_pax_attributes(data: &[u8]) -> Vec<(String, String)> {
    let mut attrs = Vec::new();
    // Work on raw bytes: the record length counts bytes, and slicing a
    // lossy-decoded `&str` at an arbitrary byte offset can panic on a
    // char boundary.
    let mut remaining = data;

    while !remaining.is_empty() {
        // Find the space that separates the length from the key=value
        let space_pos = match remaining.iter().position(|&b| b == b' ') {
            Some(p) => p,
            None => break,
        };
        let total_len: usize = match core::str::from_utf8(&remaining[..space_pos])
            .ok()
            .and_then(|len_str| len_str.parse().ok())
        {
            Some(n) => n,
            None => break,
        };
        // The record must cover at least the length field, the space,
        // and one payload byte; a smaller `total_len` would make the
        // slice below run backwards.
        if total_len <= space_pos + 1 || total_len > remaining.len() {
            break;
        }

        // The record is total_len bytes (including the length prefix and trailing newline)
        let record = &remaining[space_pos + 1..total_len];
        // Strip trailing newline
        let mut record = record;
        while record.last() == Some(&b'\n') {
            record = &record[..record.len() - 1];
        }

        if let Some(eq_pos) = record.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&record[..eq_pos]);
            let value = String::from_utf8_lossy(&record[eq_pos + 1..]);
            attrs.push((key.to_string(), value.to_string()));
        }

        remaining = &remaining[total_len..];
    }

    attrs
}

/// Round up a decoder-driven byte count to the next 512-byte block
/// boundary, rejecting inputs whose `size + BLOCK_SIZE - 1` overflows.
fn round_up_to_block_checked(size: usize) -> Option<usize> {
    if size == 0 {
        Some(0)
    } else {
        size.checked_add(BLOCK_SIZE - 1)
            .map(|n| n & !(BLOCK_SIZE - 1))
    }
}

/// Decode a tar archive from a [`std::io::Read`] source.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if reading from the source fails, or if the data is malformed.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode, decode};
///
/// let mut enc = encode::TarEncoder::new();
/// enc.add_file("a.txt", b"data");
/// let tar = enc.finish();
/// let entries = decode::decode_reader(tar.as_slice()).unwrap();
/// assert_eq!(entries.len(), 1);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(
    mut reader: R,
) -> Result<Vec<TarEntry>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

#[cfg(test)]
mod tests {
    #[test]
    fn for_each_entry_stops_when_visit_fails() {
        use super::*;
        let mut enc = crate::archive::tar::encode::TarEncoder::new();
        enc.add_file("a.txt", b"aaa");
        enc.add_file("b.txt", b"bbb");
        let archive = enc.finish();
        let mut seen = Vec::new();
        let err = for_each_entry(&archive, |entry| {
            seen.push(entry.header.name.clone());
            Err(Error::InvalidData("stop"))
        });
        assert!(err.is_err());
        assert_eq!(seen, ["a.txt"]);
    }

    use super::*;

    /// Regression (fuzz run-1791310276): a pax record whose declared
    /// length doesn't extend past the space separator ("1 x") must not
    /// panic on the reversed slice.
    #[test]
    fn test_parse_pax_attributes_short_length() {
        assert!(parse_pax_attributes(b"1 x").is_empty());
        assert_eq!(
            parse_pax_attributes(b"7 a=b\n1 x")
                .first()
                .map(|p| p.0.as_str()),
            Some("a")
        );
    }

    /// Tar has no checksum or footer covering the archive; a cut at a
    /// block boundary yields a valid shorter archive, and trailing
    /// partial blocks are ignored. Invariant: decode(prefix) is Err or
    /// a prefix of the full entry list.
    #[test]
    fn test_decode_truncated_prefix_invariant() {
        let mut enc = crate::archive::tar::encode::TarEncoder::new();
        enc.add_file("a.txt", b"first file payload");
        enc.add_file("b.txt", b"second");
        enc.add_file("c.bin", &[0u8, 1, 2, 3, 4, 5, 6]);
        let archive = enc.finish();
        let full = decode(&archive).unwrap();
        for cut in 0..archive.len() {
            if let Ok(prefix) = decode(&archive[..cut]) {
                assert!(
                    prefix.len() <= full.len()
                        && full
                            .iter()
                            .zip(prefix.iter())
                            .all(|(a, b)| a.header.name == b.header.name && a.data == b.data),
                    "cut={cut}: entries must be a prefix of the full list"
                );
            }
        }
    }

    /// Verifies that `round_up_to_block_checked` maps 0→0, non-zero sizes
    /// to the next 512-byte boundary, and rejects overflow.
    #[test]
    fn test_round_up_to_block() {
        assert_eq!(round_up_to_block_checked(0), Some(0));
        assert_eq!(round_up_to_block_checked(1), Some(512));
        assert_eq!(round_up_to_block_checked(512), Some(512));
        assert_eq!(round_up_to_block_checked(513), Some(1024));
        assert_eq!(round_up_to_block_checked(usize::MAX), None);
    }

    /// `decode_reader` produces the same entries as `decode` when reading
    /// from a `Cursor` over the same bytes.
    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader() {
        use crate::archive::tar::encode::TarEncoder;
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"Hello, tar!");
        let archive = encoder.finish();
        let cursor = std::io::Cursor::new(&archive);
        let entries = decode_reader(cursor).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, tar!");
    }

    /// Build a minimal ustar header block for testing.
    fn build_header(name: &[u8], typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
        let mut h = [0u8; BLOCK_SIZE];
        h[..name.len()].copy_from_slice(name);
        fn write_field(field: &mut [u8], value: u64, width: usize) {
            let s = alloc::format!("{value:0>width$o}");
            field[..width].copy_from_slice(&s.as_bytes()[..width]);
        }
        write_field(&mut h[100..108], 0o644, 7); // mode
        write_field(&mut h[108..116], 0, 7); // uid
        write_field(&mut h[116..124], 0, 7); // gid
        write_field(&mut h[124..136], size, 11); // size
        write_field(&mut h[136..148], 0, 11); // mtime
        h[156] = typeflag;
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cksum = alloc::format!("{sum:06o} ");
        h[148..155].copy_from_slice(cksum.as_bytes());
        h
    }

    /// POSIX: typeflags '2'-'6' store no data records; a nonzero size
    /// field (seen in some foreign archives) must be ignored on read,
    /// otherwise the decoder consumes the following header as payload.
    #[test]
    fn test_nonzero_size_directory_does_not_desync() {
        let mut archive = Vec::new();
        archive.extend_from_slice(&build_header(b"dir/", b'5', 512));
        archive.extend_from_slice(&build_header(b"file.txt", b'0', 3));
        archive.extend_from_slice(b"abc");
        archive.extend_from_slice(&[0u8; BLOCK_SIZE - 3]);
        archive.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.name, "dir/");
        assert!(entries[0].data.is_empty());
        assert_eq!(entries[1].header.name, "file.txt");
        assert_eq!(entries[1].data, b"abc");
    }

    /// POSIX: a 'g' global header persists per keyword until another 'g'
    /// supplies a new value for the same keyword.
    #[test]
    fn test_global_pax_headers_merge_per_key() {
        let g1_data = b"15 comment=one\n";
        let g2_data = b"13 charset=x\n";
        let mut archive = Vec::new();
        archive.extend_from_slice(&build_header(
            b"pax_global_header",
            b'g',
            g1_data.len() as u64,
        ));
        archive.extend_from_slice(g1_data);
        archive.resize(archive.len() + BLOCK_SIZE - g1_data.len(), 0);
        archive.extend_from_slice(&build_header(b"a.txt", b'0', 1));
        archive.extend_from_slice(b"a");
        archive.extend_from_slice(&[0u8; BLOCK_SIZE - 1]);
        archive.extend_from_slice(&build_header(
            b"pax_global_header",
            b'g',
            g2_data.len() as u64,
        ));
        archive.extend_from_slice(g2_data);
        archive.resize(archive.len() + BLOCK_SIZE - g2_data.len(), 0);
        archive.extend_from_slice(&build_header(b"b.txt", b'0', 1));
        archive.extend_from_slice(b"b");
        archive.extend_from_slice(&[0u8; BLOCK_SIZE - 1]);
        archive.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        // The second 'g' must not erase `comment` from the first.
        assert_eq!(entries[0].header.pax_comment.as_deref(), Some("one"));
        assert_eq!(entries[1].header.pax_comment.as_deref(), Some("one"));
        assert_eq!(entries[1].header.pax_charset.as_deref(), Some("x"));
    }

    /// GNU base-256 encodes negative values in twos complement;
    /// a field of all 0xFF must decode to -1, not a rejected huge u64.
    #[test]
    fn test_negative_base256_mtime() {
        let mut h = build_header(b"old", b'0', 1);
        h[136..148].fill(0xFF);
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cksum = alloc::format!("{sum:06o} ");
        h[148..155].copy_from_slice(cksum.as_bytes());
        let mut archive = Vec::new();
        archive.extend_from_slice(&h);
        archive.push(b'x');
        archive.extend_from_slice(&[0u8; BLOCK_SIZE - 1]);
        archive.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].header.mtime, -1);
    }

    /// Two consecutive 512-byte zero blocks form a valid empty archive.
    #[test]
    fn test_decode_empty_archive() {
        let data = vec![0u8; BLOCK_SIZE * 2];
        let entries = decode(&data).unwrap();
        assert!(entries.is_empty());
    }

    // ── PAX attribute parsing ────────────────────────────────────────

    /// Two well-formed PAX records (`path` and `linkpath`) are parsed into
    /// the expected key-value pairs.
    #[test]
    fn test_parse_pax_attributes() {
        let data = b"12 path=foo\n16 linkpath=bar\n";
        let attrs = parse_pax_attributes(data);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], ("path".to_string(), "foo".to_string()));
        assert_eq!(attrs[1], ("linkpath".to_string(), "bar".to_string()));
    }

    /// Empty input produces an empty attribute list (no panic).
    #[test]
    fn test_parse_pax_attributes_empty() {
        let attrs = parse_pax_attributes(b"");
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_pax_attributes_empty_value() {
        let attrs = parse_pax_attributes(b"5 k=\n");
        assert_eq!(attrs, vec![("k".to_string(), "".to_string())]);
    }

    #[test]
    fn test_parse_pax_attributes_invalid_length_safely_skipped() {
        let attrs = parse_pax_attributes(b"11 path=ok\n999 bad\n");
        assert_eq!(attrs, vec![("path".to_string(), "ok".to_string())]);
    }

    #[test]
    fn test_pax_mode_applied() {
        let mut header = TarHeader {
            name: "file.txt".to_string(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            atime: 0,
            atime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            file_type: FileType::Regular,
            link_name: String::new(),
            uname: String::new(),
            gname: String::new(),
            devmajor: 0,
            devminor: 0,
            sparse_map: Vec::new(),
            pax_charset: None,
            pax_comment: None,
            pax_hdrcharset: None,
            _gnu_sparse_extended: false,
            _gnu_sparse_data_size: 0,
        };

        apply_pax_attributes(&mut header, &[("mode".to_string(), "000755".to_string())]);
        assert_eq!(header.mode, 0o755);
    }

    #[test]
    fn test_parse_sparse_map_record() {
        let map = parse_sparse_map_record("0,5,2048,7").unwrap();
        assert_eq!(map, vec![(0, 5), (2048, 7)]);
    }

    #[test]
    fn test_parse_sparse_map_record_rejects_odd_field_count() {
        assert!(parse_sparse_map_record("0,5,2048").is_none());
    }

    #[test]
    fn test_apply_pax_sparse_map() {
        let mut header = TarHeader {
            name: "file.txt".to_string(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            size: 10,
            mtime: 0,
            mtime_nsec: 0,
            atime: 0,
            atime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            file_type: FileType::Regular,
            link_name: String::new(),
            uname: String::new(),
            gname: String::new(),
            devmajor: 0,
            devminor: 0,
            sparse_map: Vec::new(),
            pax_charset: None,
            pax_comment: None,
            pax_hdrcharset: None,
            _gnu_sparse_extended: false,
            _gnu_sparse_data_size: 0,
        };

        let attrs = vec![
            ("GNU.sparse.size".to_string(), "4096".to_string()),
            ("GNU.sparse.numblocks".to_string(), "2".to_string()),
            ("GNU.sparse.map".to_string(), "0,5,2048,5".to_string()),
        ];
        apply_pax_attributes(&mut header, &attrs);
        apply_sparse_pax_attributes(&mut header, &attrs);

        assert_eq!(header.size, 4096);
        assert_eq!(header.sparse_map, vec![(0, 5), (2048, 5)]);
    }

    // ── PAX decode: per-entry extended header ─────────────────────────

    /// A PAX extended header (type `'x'`) with a `path` attribute overrides
    /// the name stored in the following entry's base UStar header.
    #[test]
    fn test_pax_header_applied() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"16 path=newname\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"content");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "newname");
        assert_eq!(entries[0].data, b"content");
    }

    // ── PAX decode: mtime with nanosecond precision ───────────────────

    /// Full 9-digit nanosecond fraction is decoded from a PAX `mtime` value.
    #[test]
    fn test_pax_mtime_nanosecond_precision() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"30 mtime=1234567890.123456789\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, 1234567890);
        assert_eq!(entries[0].header.mtime_nsec, 123456789);
    }

    /// Trailing zeros in the fractional part (`"1234567890.100000000"`)
    /// are trimmed during parsing but still yield the correct nanosecond
    /// value (100 000 000 ns = 0.1 s).
    #[test]
    fn test_pax_mtime_fractional_trailing_zeros() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"30 mtime=1234567890.100000000\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, 1234567890);
        assert_eq!(entries[0].header.mtime_nsec, 100_000_000);
    }

    /// An integer-only PAX `mtime` (no decimal point) yields nsec = 0.
    #[test]
    fn test_pax_mtime_no_fraction() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"20 mtime=1234567890\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, 1234567890);
        assert_eq!(entries[0].header.mtime_nsec, 0);
    }

    /// A 6-digit fractional part (microsecond precision) is zero-padded to
    /// nanoseconds during parsing.
    #[test]
    fn test_pax_mtime_microsecond_precision() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"27 mtime=1234567890.123456\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, 1234567890);
        assert_eq!(entries[0].header.mtime_nsec, 123456000);
    }

    // ── GNU long link ──────────────────────────────────────────────

    /// A GNU LongName extension header (type `'L'`) carries the full file
    /// path and overrides the truncated base header name.
    #[test]
    fn test_gnu_long_name() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let long_name = "a/".repeat(60) + "file.txt"; // > 100 chars

        let mut encoder = TarEncoder::new();
        let mut name_bytes = alloc::vec::Vec::from(long_name.as_bytes());
        name_bytes.push(0);
        encoder.add_file_with_options(
            &name_bytes,
            &TarEntryOptions {
                name: alloc::string::String::from("././@LongLink"),
                file_type: FileType::GnuLongName,
                ..Default::default()
            },
        );
        encoder.add_file_with_options(
            b"content",
            &TarEntryOptions {
                name: alloc::string::String::from("truncated.txt"),
                ..Default::default()
            },
        );

        let entries = decode(&encoder.finish()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].data, b"content");
    }

    /// A GNU LongLink extension header (type `'K'`) carries the full link
    /// target and overrides the truncated `link_name` in the base header.
    #[test]
    fn test_gnu_long_link() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let long_target = "a/".repeat(60) + "target.txt"; // > 100 chars

        let mut encoder = TarEncoder::new();
        // GnuLongLink entry: data is the long link name
        encoder.add_file_with_options(
            long_target.as_bytes(),
            &TarEntryOptions {
                name: alloc::string::String::from("././@LongLink"),
                file_type: FileType::GnuLongLink,
                ..Default::default()
            },
        );
        // The actual symlink entry
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("link.txt"),
                file_type: FileType::SymLink,
                link_name: alloc::string::String::from("truncated"),
                ..Default::default()
            },
        );
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::SymLink);
        assert_eq!(entries[0].header.link_name, long_target);
    }

    // ── Error handling ──────────────────────────────────────────────

    /// Truncating the archive to only the header block (no data) returns
    /// `UnexpectedEof`.
    #[test]
    fn test_truncated_archive_header_only() {
        use crate::archive::tar::encode::TarEncoder;
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"Hello!");
        let archive = encoder.finish();
        // Truncate to just the header block (512 bytes), removing the data block
        let truncated = &archive[..BLOCK_SIZE];
        let result = decode(truncated);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }

    /// A filename of exactly 100 bytes fits in the UStar name field without
    /// any extension header.
    #[test]
    fn test_exact_100_byte_filename() {
        use crate::archive::tar::encode::TarEncoder;
        let name = "a".repeat(100);
        let mut encoder = TarEncoder::new();
        encoder.add_file(&name, b"data");
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, name);
        assert_eq!(entries[0].data, b"data");
    }

    /// An archive terminated by a single zero block (instead of the standard
    /// two) is still decoded successfully — the loop exits when no more data
    /// remains after the first zero block.
    #[test]
    fn test_single_zero_block_eof() {
        use crate::archive::tar::encode::TarEncoder;
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"hello");
        let full_archive = encoder.finish();

        // The encoder appends two zero blocks (1024 bytes) at the end.
        // Remove the last 512-byte zero block to leave only one.
        let truncated_len = full_archive.len() - BLOCK_SIZE;
        let single_zero_block_archive = &full_archive[..truncated_len];

        let entries = decode(single_zero_block_archive).unwrap();
        // The decoder should still successfully return the file entry.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    // ── PAX / GNU precedence ────────────────────────────────────────

    /// When both a GNU LongName and a PAX `path` attribute precede the same
    /// entry, the PAX `path` takes precedence (applied after the GNU name).
    #[test]
    fn test_pax_and_gnu_longname_priority() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let gnu_long_name = "gnu_name_that_is_long_enough_to_be_a_longname_entry.txt";
        let pax_name = "pax_overridden_name.txt";

        let mut encoder = TarEncoder::new();

        // 1. Add a GNU LongName entry
        let mut name_bytes = alloc::vec::Vec::from(gnu_long_name.as_bytes());
        name_bytes.push(0);
        encoder.add_file_with_options(
            &name_bytes,
            &TarEntryOptions {
                name: alloc::string::String::from("././@LongLink"),
                file_type: FileType::GnuLongName,
                ..Default::default()
            },
        );

        // 2. Add a PAX header with a different path
        // Recompute: "NN path=pax_overridden_name.txt\n"
        // Need total length including the length prefix itself.
        let pax_data_str = {
            let kv = alloc::format!("path={pax_name}\n");
            // length field = number of digits + 1 (space) + kv.len()
            // Try with 2 digits first
            let trial = alloc::format!("{} {kv}", kv.len() + 3);
            if trial.len() == kv.len() + 3 {
                trial
            } else {
                // recalc
                let total = kv.len() + 4; // try 3 digits
                alloc::format!("{total} {kv}")
            }
        };
        let pax_data = pax_data_str.as_bytes();

        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );

        // 3. Add the actual file entry
        encoder.add_file("placeholder.txt", b"content");

        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();

        assert_eq!(entries.len(), 1);
        // PAX path should take precedence over GNU LongName because the
        // decoder applies GNU long name first, then PAX attributes override.
        assert_eq!(entries[0].header.name, pax_name);
        assert_eq!(entries[0].data, b"content");
    }

    /// Malformed PAX data (no space, oversized length, missing `=`) is
    /// silently skipped without returning an error or panic.
    #[test]
    fn test_pax_malformed_graceful() {
        let garbage = b"not-a-valid-pax-record\n";
        let attrs = parse_pax_attributes(garbage);
        assert!(attrs.is_empty());

        // Length too large
        let bad_len = b"9999 path=foo\n";
        let attrs2 = parse_pax_attributes(bad_len);
        assert!(attrs2.is_empty());

        // No equals sign
        let no_eq = b"10 pathfoo\n";
        let attrs3 = parse_pax_attributes(no_eq);
        assert!(attrs3.is_empty());
    }

    // ── PAX decode: atime / ctime ────────────────────────────────────

    /// PAX `atime` and `ctime` attributes are decoded with sub-second
    /// precision and stored in the corresponding `TarHeader` fields.
    #[test]
    fn test_pax_atime_ctime() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"27 atime=1000000000.500000\n26 ctime=2000000000.75000\n";

        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.atime, 1000000000);
        assert_eq!(entries[0].header.atime_nsec, 500000000);
        assert_eq!(entries[0].header.ctime, 2000000000);
        assert_eq!(entries[0].header.ctime_nsec, 750000000);
    }

    #[test]
    fn test_pax_negative_mtime() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"16 mtime=-86400\n";
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, -86400);
        assert_eq!(entries[0].header.mtime_nsec, 0);
    }

    #[test]
    fn test_pax_negative_fractional_time() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let pax_data = b"21 mtime=-1.500000000\n";
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            pax_data,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/file.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("file.txt", b"data");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, -2);
        assert_eq!(entries[0].header.mtime_nsec, 500_000_000);
    }

    // ── PAX decode: global extended header ───────────────────────────

    /// A PAX global extended header (type `'g'`) applies its attributes to
    /// every subsequent entry in the archive.
    #[test]
    fn test_pax_global_header_applied() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};
        let global_pax = b"20 uname=globaluser\n";

        let mut encoder = TarEncoder::new();
        // Add global PAX header
        encoder.add_file_with_options(
            global_pax,
            &TarEntryOptions {
                name: alloc::string::String::from("pax_global_header"),
                file_type: FileType::PaxGlobalHeader,
                ..Default::default()
            },
        );
        // Add two regular files without per-entry PAX
        encoder.add_file("a.txt", b"aaa");
        encoder.add_file("b.txt", b"bbb");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        // Both entries should have the global uname applied
        assert_eq!(entries[0].header.uname, "globaluser");
        assert_eq!(entries[1].header.uname, "globaluser");
    }

    /// A per-entry PAX header overrides the matching attribute from a
    /// preceding global PAX header for that entry only.
    #[test]
    fn test_pax_per_entry_overrides_global() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let global_pax = b"20 uname=globaluser\n";
        let entry_pax = b"19 uname=localuser\n";

        let mut encoder = TarEncoder::new();
        // Global
        encoder.add_file_with_options(
            global_pax,
            &TarEntryOptions {
                name: alloc::string::String::from("pax_global_header"),
                file_type: FileType::PaxGlobalHeader,
                ..Default::default()
            },
        );
        // First file: no per-entry PAX → global applies
        encoder.add_file("a.txt", b"aaa");
        // Per-entry PAX for second file
        encoder.add_file_with_options(
            entry_pax,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/b.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file("b.txt", b"bbb");
        let archive = encoder.finish();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.uname, "globaluser");
        // Per-entry overrides global
        assert_eq!(entries[1].header.uname, "localuser");
    }

    /// POSIX.1-2008: an extended-header record with an empty value
    /// deletes the attribute; the ustar header field is used instead.
    #[test]
    fn test_pax_empty_value_deletes_attribute() {
        use crate::archive::tar::encode::{TarEncoder, TarEntryOptions};

        let entry_pax = b"9 uname=\n";
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            entry_pax,
            &TarEntryOptions {
                name: alloc::string::String::from("PaxHeaders.0/a.txt"),
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );
        encoder.add_file_with_options(
            b"data",
            &TarEntryOptions {
                name: alloc::string::String::from("a.txt"),
                uname: alloc::string::String::from("ustaruser"),
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        // Empty `uname=` must not clobber the ustar uname field.
        assert_eq!(entries[0].header.uname, "ustaruser");
    }

    /// Decoding a zero-length byte slice succeeds with an empty entry list.
    #[test]
    fn test_decode_empty_input() {
        let entries = decode(&[]).unwrap();
        assert!(entries.is_empty());
    }

    /// Decode a hand-crafted GNU sparse (typeflag 'S') header.
    ///
    /// The header contains one sparse entry (offset=0, numbytes=5) in the
    /// in-header sparse map, the isextended flag is not set, and realsize=1024.
    /// The on-tape data is 5 bytes ("HELLO"), padded to a 512-byte block.
    #[test]
    fn test_gnu_sparse_in_header_decode() {
        use crate::archive::tar::encode::{write_octal, write_size};
        use crate::archive::tar::header::FileType;

        let tape_data = b"HELLO";
        let tape_data_size = tape_data.len() as u64; // 5
        let real_size: u64 = 1024;

        let mut header = [0u8; BLOCK_SIZE];

        // Name (100 bytes)
        header[0..10].copy_from_slice(b"sparse.bin");
        // Mode (8 bytes)
        write_octal(&mut header[100..108], 0o644, 7);
        // UID (8 bytes)
        write_octal(&mut header[108..116], 0, 7);
        // GID (8 bytes)
        write_octal(&mut header[116..124], 0, 7);
        // Size field = on-tape data size
        write_size(&mut header[124..136], tape_data_size);
        // Mtime
        write_octal(&mut header[136..148], 0, 11);
        // Checksum placeholder
        header[148..156].copy_from_slice(b"        ");
        // Typeflag = 'S' (GNU sparse)
        header[156] = b'S';
        // UStar magic + version
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // Sparse map: 4 entries at bytes 386-481 (24 bytes each)
        // Entry 0: offset=0, numbytes=5
        write_octal(&mut header[386..398], 0, 11); // offset
        write_octal(&mut header[398..410], tape_data_size, 11); // numbytes
        // Entries 1-3: all zeros (skipped by parser)

        // isextended flag at byte 482 — not set
        header[482] = 0;

        // realsize at bytes 483-494 (12 bytes, octal)
        write_octal(&mut header[483..495], real_size, 11);

        // Compute checksum
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write_octal(&mut header[148..155], checksum as u64, 6);
        header[155] = b' ';

        // Build the archive: header + data block + 2 zero blocks
        let mut archive = Vec::from(&header[..]);
        // Data block (padded to 512 bytes)
        let mut data_block = [0u8; BLOCK_SIZE];
        data_block[..tape_data.len()].copy_from_slice(tape_data);
        archive.extend_from_slice(&data_block);
        // Two zero blocks (EOF)
        archive.extend_from_slice(&[0u8; BLOCK_SIZE * 2]);

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::GnuSparse);
        assert_eq!(entries[0].header.name, "sparse.bin");
        // Logical size is realsize
        assert_eq!(entries[0].header.size, real_size);
        // Sparse map has 1 entry
        assert_eq!(entries[0].header.sparse_map, vec![(0, 5)]);
        // Data is the on-tape payload
        assert_eq!(entries[0].data, b"HELLO");
    }

    #[test]
    fn test_archive_entry_trait() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::tar::encode::TarEncoder::new();
        enc.add_file("hello.txt", b"Hello!");
        let entries = decode(&enc.finish()).unwrap();
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
    }

    #[test]
    fn test_archive_codec_decode_roundtrip() {
        use crate::archive::tar::{TarArchiveEncoder, TarCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = TarArchiveEncoder::new();
        encoder.add_file("hello.txt", b"Hello!");
        encoder.add_file("world.txt", b"World!");
        let archive = <TarArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = TarCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
        assert_eq!(entries[1].name(), "world.txt");
        assert_eq!(entries[1].data(), b"World!");
    }

    #[test]
    fn test_archive_entry_empty_data() {
        use crate::archive::tar::{TarArchiveEncoder, TarCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = TarArchiveEncoder::new();
        encoder.add_file("empty.txt", b"");
        let archive = <TarArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = TarCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "empty.txt");
        assert_eq!(entries[0].data(), b"");
    }

    #[test]
    fn test_archive_multiple_entries() {
        use crate::archive::tar::{TarArchiveEncoder, TarCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = TarArchiveEncoder::new();
        for i in 0..12 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            encoder.add_file(&name, data.as_bytes());
        }
        let archive = <TarArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = TarCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 12);
        for (i, entry) in entries.iter().enumerate() {
            let expected_name = alloc::format!("file_{i}.txt");
            let expected_data = alloc::format!("Content of file {i}");
            assert_eq!(entry.name(), expected_name);
            assert_eq!(entry.data(), expected_data.as_bytes());
        }
    }
}
