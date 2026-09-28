//! Zstandard Seekable Format (zstd `contrib/seekable_format` specification
//! v0.1.0).
//!
//! The input is split into independent zstd frames and a seek table is
//! appended as a zstd skippable frame (magic `0x184D2A5E`), so the stream
//! remains decodable by any zstd decoder. The seek table maps logical
//! decompressed offsets to physical frame offsets, which enables range
//! decompression without decoding the whole stream.
//!
//! The default encoder emits seek tables without per-frame XXH64 checksums
//! (`Checksum_Flag` clear); [`encode_with_checksums`] sets the flag and stores
//! a checksum per frame. The decoder accepts and verifies them when present.

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::xxhash;

/// Magic number of the skippable frame that carries the seek table.
pub const SKIPPABLE_MAGIC: u32 = 0x184D_2A5E;
/// Magic number terminating the seek table footer.
pub const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;
/// Size of the seek table footer (`Number_Of_Frames` + descriptor + magic).
pub const FOOTER_SIZE: usize = 9;
/// Default decompressed size of each independently compressed frame (4 MiB,
/// matching the reference `parallel_processing` example).
pub const DEFAULT_FRAME_SIZE: usize = 4 * 1024 * 1024;

const ENTRY_SIZE: usize = 8;
const CHECKSUM_SIZE: usize = 4;
const DESCRIPTOR_CHECKSUM_FLAG: u8 = 1 << 7;
const DESCRIPTOR_RESERVED_MASK: u8 = 0b0111_1100;

/// One row of the seek table: physical extent and logical extent of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeekEntry {
    /// Size of the frame in the compressed stream.
    pub compressed_size: u32,
    /// Decompressed size of the frame (0 for skippable/empty frames).
    pub decompressed_size: u32,
    /// Low 32 bits of the XXH64 digest of the decompressed data, when the
    /// stream's `Checksum_Flag` is set.
    pub checksum: Option<u32>,
}

/// Parsed seek table of a seekable zstd stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeekTable {
    /// Whether the stream's `Checksum_Flag` is set.
    pub has_checksums: bool,
    /// One entry per stored frame, in stream order.
    pub entries: Vec<SeekEntry>,
    /// Offset in the compressed stream where the seek-table skippable frame
    /// starts (i.e. the end of the frame data region).
    pub table_offset: usize,
}

impl SeekTable {
    /// Decompressed size of the whole stream.
    pub fn decompressed_size(&self) -> u64 {
        self.entries
            .iter()
            .map(|e| u64::from(e.decompressed_size))
            .sum()
    }
}

fn le32(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Locate and parse the seek table at the end of `input`.
///
/// Returns [`Error::InvalidData`] when the trailing `Seekable_Magic_Number`
/// is absent (the stream is not in the seekable format) and
/// [`Error::UnexpectedEof`] for truncated tables.
///
/// This function does not panic on malformed input.
pub fn seek_table(input: &[u8]) -> Result<SeekTable, Error> {
    if input.len() < FOOTER_SIZE {
        return Err(Error::InvalidData("zstd-seekable: input too short"));
    }
    let footer = &input[input.len() - FOOTER_SIZE..];
    if le32(&footer[5..]) != SEEKABLE_MAGIC {
        return Err(Error::InvalidData("zstd-seekable: no seek table found"));
    }
    let descriptor = footer[4];
    if descriptor & DESCRIPTOR_RESERVED_MASK != 0 {
        return Err(Error::InvalidData(
            "zstd-seekable: reserved descriptor bits set",
        ));
    }
    let has_checksums = descriptor & DESCRIPTOR_CHECKSUM_FLAG != 0;
    let num_frames = le32(footer) as usize;
    let entry_size = if has_checksums {
        ENTRY_SIZE + CHECKSUM_SIZE
    } else {
        ENTRY_SIZE
    };
    let entries_bytes = num_frames
        .checked_mul(entry_size)
        .ok_or(Error::InvalidData("zstd-seekable: table too large"))?;
    let payload_size = entries_bytes + FOOTER_SIZE;
    // The seek table lives inside a skippable frame: magic (4) + size (4).
    let table_offset = input
        .len()
        .checked_sub(8 + payload_size)
        .ok_or(Error::UnexpectedEof)?;
    if le32(&input[table_offset..]) != SKIPPABLE_MAGIC {
        return Err(Error::InvalidData(
            "zstd-seekable: bad skippable frame magic",
        ));
    }
    if le32(&input[table_offset + 4..]) as usize != payload_size {
        return Err(Error::InvalidData(
            "zstd-seekable: frame size does not match table",
        ));
    }

    let mut entries = Vec::with_capacity(num_frames);
    let mut offset = table_offset + 8;
    for _ in 0..num_frames {
        let entry = SeekEntry {
            compressed_size: le32(&input[offset..]),
            decompressed_size: le32(&input[offset + 4..]),
            checksum: has_checksums.then(|| le32(&input[offset + 8..])),
        };
        if entry.compressed_size == 0 {
            return Err(Error::InvalidData("zstd-seekable: zero-sized frame"));
        }
        entries.push(entry);
        offset += entry_size;
    }

    let total_compressed: u64 = entries.iter().map(|e| u64::from(e.compressed_size)).sum();
    if total_compressed != table_offset as u64 {
        return Err(Error::InvalidData(
            "zstd-seekable: frame sizes do not cover stream",
        ));
    }

    Ok(SeekTable {
        has_checksums,
        entries,
        table_offset,
    })
}

/// Returns true when `input` ends with a seek table footer.
pub fn has_seek_table(input: &[u8]) -> bool {
    input.len() >= FOOTER_SIZE && le32(&input[input.len() - 4..]) == SEEKABLE_MAGIC
}

/// Compress `input` as a seekable zstd stream: one independent zstd frame per
/// `frame_size`-sized chunk, followed by the seek table skippable frame.
///
/// The emitted seek table has `Checksum_Flag` clear (no per-frame checksums).
/// An empty input produces a stream with zero data frames.
///
/// # Panics
///
/// Panics if `frame_size` is 0 or greater than `u32::MAX`.
pub fn encode(input: &[u8], frame_size: usize) -> Vec<u8> {
    encode_impl(input, frame_size, false)
}

/// Compress `input` as a seekable zstd stream whose seek table has
/// `Checksum_Flag` set: each entry stores the low 32 bits of the XXH64 digest
/// of the frame's decompressed data.
///
/// # Panics
///
/// Panics if `frame_size` is 0 or greater than `u32::MAX`.
pub fn encode_with_checksums(input: &[u8], frame_size: usize) -> Vec<u8> {
    encode_impl(input, frame_size, true)
}

fn encode_impl(input: &[u8], frame_size: usize, checksums: bool) -> Vec<u8> {
    assert!(
        frame_size > 0 && frame_size <= u32::MAX as usize,
        "zstd-seekable: frame_size must be in 1..=u32::MAX"
    );

    let mut out = Vec::new();
    let mut entries = Vec::new();
    for chunk in input.chunks(frame_size) {
        let frame = super::encode::encode(chunk);
        entries.push(SeekEntry {
            compressed_size: frame.len() as u32,
            decompressed_size: chunk.len() as u32,
            checksum: checksums.then(|| xxhash::xxhash64(chunk, 0) as u32),
        });
        out.extend_from_slice(&frame);
    }

    let entry_size = if checksums {
        ENTRY_SIZE + CHECKSUM_SIZE
    } else {
        ENTRY_SIZE
    };
    let payload_size = entries.len() * entry_size + FOOTER_SIZE;
    out.extend_from_slice(&SKIPPABLE_MAGIC.to_le_bytes());
    out.extend_from_slice(&(payload_size as u32).to_le_bytes());
    for entry in &entries {
        out.extend_from_slice(&entry.compressed_size.to_le_bytes());
        out.extend_from_slice(&entry.decompressed_size.to_le_bytes());
        if let Some(sum) = entry.checksum {
            out.extend_from_slice(&sum.to_le_bytes());
        }
    }
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    out.push(if checksums {
        DESCRIPTOR_CHECKSUM_FLAG
    } else {
        0
    });
    out.extend_from_slice(&SEEKABLE_MAGIC.to_le_bytes());
    out
}

/// Decode a complete seekable zstd stream.
///
/// Requires a valid seek table; plain multi-frame zstd input without one is
/// rejected. Each frame's decompressed size (and checksum when the
/// `Checksum_Flag` is set) is verified against the table.
///
/// This function does not panic on malformed input.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] when no seek table is present or the table
/// is inconsistent, and propagates zstd frame decoding errors.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let table = seek_table(input)?;
    let mut out = Vec::new();
    let mut offset = 0usize;
    for entry in &table.entries {
        let end = offset + entry.compressed_size as usize;
        let frame = super::decode::decode(&input[offset..end])?;
        verify_entry(entry, &frame)?;
        out.extend_from_slice(&frame);
        offset = end;
    }
    Ok(out)
}

/// Decompress `len` bytes of the stream starting at decompressed `offset`,
/// decoding only the frames that cover the requested range.
///
/// This function does not panic on malformed input.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] when no seek table is present, the range
/// exceeds the decompressed size, or the table is inconsistent.
pub fn decode_range(input: &[u8], offset: usize, len: usize) -> Result<Vec<u8>, Error> {
    let table = seek_table(input)?;
    let total = table.decompressed_size();
    if offset as u64 + len as u64 > total {
        return Err(Error::InvalidData("zstd-seekable: range out of bounds"));
    }

    let mut out = Vec::new();
    let mut data_pos = 0usize; // compressed stream offset
    let mut logical_pos = 0u64; // decompressed stream offset
    let range_start = offset as u64;
    let range_end = range_start + len as u64;

    for entry in &table.entries {
        let frame_end_logical = logical_pos + u64::from(entry.decompressed_size);
        if frame_end_logical > range_start && logical_pos < range_end {
            let frame =
                super::decode::decode(&input[data_pos..data_pos + entry.compressed_size as usize])?;
            verify_entry(entry, &frame)?;
            let start = range_start.saturating_sub(logical_pos) as usize;
            let end = (range_end.min(frame_end_logical) - logical_pos) as usize;
            out.extend_from_slice(&frame[start..end]);
        }
        if frame_end_logical >= range_end {
            break;
        }
        data_pos += entry.compressed_size as usize;
        logical_pos = frame_end_logical;
    }
    Ok(out)
}

fn verify_entry(entry: &SeekEntry, frame: &[u8]) -> Result<(), Error> {
    if frame.len() != entry.decompressed_size as usize {
        return Err(Error::InvalidData(
            "zstd-seekable: decompressed size mismatch",
        ));
    }
    if let Some(expected) = entry.checksum {
        let actual = xxhash::xxhash64(frame, 0) as u32;
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0u32..3000 {
            v.extend_from_slice(&i.to_le_bytes());
        }
        v
    }

    #[test]
    fn roundtrip_single_frame() {
        let data = b"hello seekable world".to_vec();
        let compressed = encode(&data, 1024);
        assert!(has_seek_table(&compressed));
        assert_eq!(decode(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_multi_frame() {
        let data = sample();
        let compressed = encode(&data, 4096);
        let table = seek_table(&compressed).unwrap();
        assert_eq!(table.entries.len(), 3);
        assert_eq!(decode(&compressed).unwrap(), data);
    }

    #[test]
    fn roundtrip_empty() {
        let compressed = encode(&[], 1024);
        let table = seek_table(&compressed).unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(decode(&compressed).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn plain_zstd_stream_rejected() {
        let compressed = super::super::encode::encode(b"no table");
        assert!(!has_seek_table(&compressed));
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn range_decode_within_frame() {
        let data = sample();
        let compressed = encode(&data, 4096);
        let range = decode_range(&compressed, 100, 500).unwrap();
        assert_eq!(range, &data[100..600]);
    }

    #[test]
    fn range_decode_across_frames() {
        let data = sample();
        let compressed = encode(&data, 4096);
        let range = decode_range(&compressed, 4000, 5000).unwrap();
        assert_eq!(range, &data[4000..9000]);
    }

    #[test]
    fn range_decode_whole_stream() {
        let data = sample();
        let compressed = encode(&data, 4096);
        assert_eq!(decode_range(&compressed, 0, data.len()).unwrap(), data);
        assert_eq!(
            decode_range(&compressed, data.len(), 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn range_decode_out_of_bounds() {
        let data = sample();
        let compressed = encode(&data, 4096);
        assert!(decode_range(&compressed, data.len() - 1, 2).is_err());
    }

    #[test]
    fn encode_checksum_flag_stream() {
        let data = sample();
        let compressed = encode_with_checksums(&data, 4096);
        let table = seek_table(&compressed).unwrap();
        assert!(table.has_checksums);
        assert_eq!(table.entries.len(), 3);
        for (i, entry) in table.entries.iter().enumerate() {
            let chunk = &data[i * 4096..data.len().min((i + 1) * 4096)];
            assert_eq!(entry.checksum.unwrap(), xxhash::xxhash64(chunk, 0) as u32);
        }
        assert_eq!(decode(&compressed).unwrap(), data);
        assert_eq!(
            decode_range(&compressed, 5000, 100).unwrap(),
            &data[5000..5100]
        );
    }

    #[test]
    fn decode_checksum_flag_stream() {
        let data = sample();
        let compressed = encode_with_checksums(&data, 4096);
        let table = seek_table(&compressed).unwrap();
        assert!(table.has_checksums);
        assert_eq!(decode(&compressed).unwrap(), data);
        assert_eq!(
            decode_range(&compressed, 5000, 100).unwrap(),
            &data[5000..5100]
        );
    }

    #[test]
    fn decode_checksum_flag_corrupted() {
        let data = sample();
        let mut compressed = encode_with_checksums(&data, 4096);
        // Corrupt the first entry's checksum field.
        let table = seek_table(&compressed).unwrap();
        let sum_off = table.table_offset + 8 + ENTRY_SIZE;
        compressed[sum_off] ^= 0xFF;
        assert!(matches!(
            decode(&compressed),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_reserved_bits() {
        let data = sample();
        let mut compressed = encode(&data, 4096);
        let n = compressed.len();
        compressed[n - 5] = 0x04; // set a reserved bit in the descriptor
        assert!(matches!(
            seek_table(&compressed),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn rejects_truncated_table() {
        let data = sample();
        let compressed = encode(&data, 4096);
        assert!(seek_table(&compressed[..compressed.len() - 10]).is_err());
    }

    #[test]
    fn rejects_bad_frame_size() {
        let data = sample();
        let mut compressed = encode(&data, 4096);
        // Corrupt the skippable Frame_Size field.
        let table = seek_table(&compressed).unwrap();
        compressed[table.table_offset + 4] ^= 0xFF;
        assert!(seek_table(&compressed).is_err());
    }

    #[test]
    fn rejects_wrong_cumulative_size() {
        let data = sample();
        let mut compressed = encode(&data, 4096);
        // Inflate the first entry's Compressed_Size.
        let table = seek_table(&compressed).unwrap();
        let first = table.table_offset + 8;
        let c = le32(&compressed[first..]) + 1;
        compressed[first..first + 4].copy_from_slice(&c.to_le_bytes());
        assert!(seek_table(&compressed).is_err());
    }

    #[test]
    fn trailing_garbage_after_footer_rejected() {
        let data = sample();
        let mut compressed = encode(&data, 4096);
        compressed.extend_from_slice(b"trailing");
        assert!(seek_table(&compressed).is_err());
    }

    #[test]
    #[should_panic(expected = "frame_size")]
    fn encode_zero_frame_size_panics() {
        let _ = encode(&[1, 2, 3], 0);
    }
}
