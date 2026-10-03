//! LZ4 frame format decompression.
//!
//! Decodes data compressed with the LZ4 frame format as specified by the
//! [LZ4 specification](https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md).
//!
//! # Examples
//!
//! ```
//! use archive::compress::lz4::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```
//!
//! # Errors
//!
//! Returns [`Error::InvalidData`] if the input is not valid LZ4 frame data.
//!
//! [`Error::InvalidData`]: crate::error::Error::InvalidData

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::xxhash::xxhash32;

/// LZ4 frame magic number.
const MAGIC: u32 = 0x184D2204;

/// LZ4 legacy frame magic number.
const LEGACY_MAGIC: u32 = 0x184C_2102;

/// Minimum match length in the LZ4 block format.
const MIN_MATCH: usize = 4;

/// Maximum dictionary history that an LZ4 block can reference.
const MAX_DICT_SIZE: usize = 65_535;

/// LZ4 dictionary content used as prefix history for independent blocks.
#[derive(Debug, Clone)]
pub struct Lz4Dict {
    /// Optional dictionary identifier carried in LZ4 frame descriptors.
    pub id: Option<u32>,
    /// Raw dictionary bytes.
    pub content: Vec<u8>,
}

impl Lz4Dict {
    /// Create a dictionary without an in-band dictionary ID.
    pub fn new(content: &[u8]) -> Self {
        Self {
            id: None,
            content: content.to_vec(),
        }
    }

    /// Create a dictionary with an explicit frame-visible dictionary ID.
    pub fn with_id(content: &[u8], id: u32) -> Self {
        Self {
            id: Some(id),
            content: content.to_vec(),
        }
    }

    pub(crate) fn tail(&self) -> &[u8] {
        let start = self.content.len().saturating_sub(MAX_DICT_SIZE);
        &self.content[start..]
    }
}

/// Decode LZ4 frame format data.
///
/// Supports independent and dependent block mode, content size, content
/// checksum, and block checksum flags. Multi-frame inputs (concatenated
/// standard and/or legacy frames) are decoded and concatenated.
/// Frames that reference an external dictionary must be decoded with
/// [`decode_with_dict`].
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if the magic number is wrong, the frame descriptor is
/// malformed, or the compressed data is corrupt.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_internal(input, None)
}

/// Decompress a single raw LZ4 block (LZ4 block format, no frame wrapper).
///
/// The block format does not record the decompressed size, so the caller
/// must provide `max_output` as an upper bound.
///
/// # Errors
///
/// Returns `Error::OutputLimitExceeded` if the block would decompress
/// beyond `max_output` bytes, or an error if the block is malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, block!";
/// let block = encode::encode_block(data);
/// let decoded = decode::decode_block(&block, data.len()).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn decode_block(src: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut dst = Vec::new();
    decompress_block(src, &mut dst, &[], max_output)?;
    Ok(dst)
}

/// Decompress a single raw LZ4 block using a caller-provided dictionary.
///
/// The dictionary content supplies prefix history, as in
/// [`decode_with_dict`].
///
/// # Errors
///
/// Returns `Error::OutputLimitExceeded` if the block would decompress
/// beyond `max_output` bytes, or an error if the block is malformed.
pub fn decode_block_with_dict(
    src: &[u8],
    dict: &Lz4Dict,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    let mut dst = Vec::new();
    decompress_block(src, &mut dst, dict.tail(), max_output)?;
    Ok(dst)
}

/// Decode LZ4 frame format data using a caller-provided dictionary.
pub fn decode_with_dict(input: &[u8], dict: &Lz4Dict) -> Result<Vec<u8>, Error> {
    decode_internal(input, Some(dict))
}

fn decode_internal(input: &[u8], dict: Option<&Lz4Dict>) -> Result<Vec<u8>, Error> {
    if input.len() < 4 {
        return Err(Error::InvalidData("lz4: input too short for frame header"));
    }

    let mut pos = 0;
    let mut output = Vec::new();

    // Multi-frame loop: decode concatenated standard and legacy frames
    while pos < input.len() {
        // Not enough bytes for another magic number
        if pos + 4 > input.len() {
            break;
        }

        let magic = peek_u32_le(input, pos);

        if magic == LEGACY_MAGIC {
            decode_legacy_frame(input, &mut pos, &mut output)?;
        } else if (0x184D2A50..=0x184D2A5F).contains(&magic) {
            // Skippable frame
            pos += 4;
            let frame_size = read_u32_le(input, &mut pos)? as usize;
            if pos + frame_size > input.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += frame_size;
        } else if magic == MAGIC {
            decode_standard_frame(input, &mut pos, &mut output, dict)?;
        } else {
            if output.is_empty() {
                return Err(Error::InvalidData("lz4: invalid magic number"));
            }
            // After at least one successful frame, stop on unrecognized data
            break;
        }
    }

    Ok(output)
}

/// Decode a single standard LZ4 frame starting at `pos`.
fn decode_standard_frame(
    input: &[u8],
    pos: &mut usize,
    output: &mut Vec<u8>,
    dict: Option<&Lz4Dict>,
) -> Result<(), Error> {
    // Consume magic
    let magic = read_u32_le(input, pos)?;
    debug_assert_eq!(magic, MAGIC);

    // Frame descriptor
    let desc_start = *pos;
    let flg = read_byte(input, pos)?;
    let bd = read_byte(input, pos)?;

    // FLG byte
    let version = (flg >> 6) & 0x03;
    if version != 1 {
        return Err(Error::InvalidData("lz4: unsupported version"));
    }
    let block_independent = (flg & 0x20) != 0;
    let block_checksum = (flg & 0x10) != 0;
    let content_size_present = (flg & 0x08) != 0;
    let content_checksum = (flg & 0x04) != 0;
    if (flg & 0x02) != 0 {
        return Err(Error::InvalidData("lz4: reserved FLG bits set"));
    }
    let dict_id_present = (flg & 0x01) != 0;

    // BD byte -- block max size
    if (bd & 0x8F) != 0 {
        return Err(Error::InvalidData("lz4: reserved BD bits set"));
    }
    let block_max_id = (bd >> 4) & 0x07;
    if block_max_id < 4 {
        return Err(Error::InvalidData("lz4: invalid block max size"));
    }
    // Block_MaxSize in bytes: id 4 => 64KB, 5 => 256KB, 6 => 1MB, 7 => 4MB.
    let block_max_size = (64 * 1024_usize) << (2 * (block_max_id as usize - 4));

    // Optional content size
    let content_size = if content_size_present {
        Some(read_u64_le(input, pos)?)
    } else {
        None
    };

    // Optional dictionary ID
    if dict_id_present {
        let dict_id = read_u32_le(input, pos)?;
        match dict {
            Some(dict) => {
                if let Some(expected) = dict.id
                    && expected != dict_id
                {
                    return Err(Error::InvalidData("lz4: dictionary ID mismatch"));
                }
            }
            None => return Err(Error::Unsupported("lz4: dictionary required")),
        }
    }

    // Header checksum
    let desc_end = *pos;
    let hc = read_byte(input, pos)?;
    let expected_hc = ((xxhash32(&input[desc_start..desc_end], 0) >> 8) & 0xFF) as u8;
    if hc != expected_hc {
        return Err(Error::InvalidData("lz4: header checksum mismatch"));
    }

    // Allocate frame output
    let frame_start = output.len();
    if let Some(size) = content_size {
        output.reserve(size.min(4 * 1024 * 1024) as usize);
    }

    // Read blocks
    loop {
        let block_size_raw = read_u32_le(input, pos)?;

        // End mark
        if block_size_raw == 0 {
            break;
        }

        let is_uncompressed = (block_size_raw & 0x80000000) != 0;
        let block_data_size = (block_size_raw & 0x7FFFFFFF) as usize;

        // Block_Size must not exceed Block_MaxSize for both compressed
        // and uncompressed (highest bit set) blocks.
        if block_data_size > block_max_size {
            return Err(Error::InvalidData("lz4: block size exceeds block max size"));
        }

        if *pos + block_data_size > input.len() {
            return Err(Error::UnexpectedEof);
        }

        let block_data = &input[*pos..*pos + block_data_size];
        *pos += block_data_size;

        if is_uncompressed {
            output.extend_from_slice(block_data);
        } else {
            let mut block_output = Vec::new();
            let history;
            let prefix = if block_independent {
                dict.map_or(&[][..], Lz4Dict::tail)
            } else {
                history = dependent_history(dict, output);
                history.as_slice()
            };
            // The decompressed block size must not exceed Block_MaxSize.
            decompress_block(block_data, &mut block_output, prefix, block_max_size).map_err(
                |err| match err {
                    Error::OutputLimitExceeded { .. } => {
                        Error::InvalidData("lz4: block decompressed size exceeds block max size")
                    }
                    err => err,
                },
            )?;
            output.extend_from_slice(&block_output);
        }

        // Optional block checksum
        if block_checksum {
            let expected = read_u32_le(input, pos)?;
            let actual = xxhash32(block_data, 0);
            if actual != expected {
                return Err(Error::ChecksumMismatch { expected, actual });
            }
        }
    }

    // Optional content checksum
    if content_checksum {
        let expected = read_u32_le(input, pos)?;
        let frame_output = &output[frame_start..];
        let actual = xxhash32(frame_output, 0);
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }

    // Verify content size
    if let Some(expected_size) = content_size {
        let frame_len = (output.len() - frame_start) as u64;
        if frame_len != expected_size {
            return Err(Error::InvalidData("lz4: content size mismatch"));
        }
    }

    Ok(())
}

/// Decode a legacy LZ4 frame starting at `pos`.
///
/// Legacy frames use magic `0x184C2102` and have a simpler structure:
/// no frame descriptor, no checksums. Each block is preceded by a
/// compressed-size u32. A block of compressed size 0 terminates the frame.
fn decode_legacy_frame(input: &[u8], pos: &mut usize, output: &mut Vec<u8>) -> Result<(), Error> {
    // Consume magic
    let magic = read_u32_le(input, pos)?;
    debug_assert_eq!(magic, LEGACY_MAGIC);

    // Legacy frames contain a sequence of blocks, each preceded by a
    // compressed-size u32. The frame ends when:
    // - a block of compressed size 0 is encountered, or
    // - a new frame magic appears at the current position, or
    // - the input ends.
    loop {
        if *pos + 4 > input.len() {
            // No more data -- end of legacy frame
            break;
        }

        // Peek ahead: if the next 4 bytes are a known magic, this frame is done
        let next = peek_u32_le(input, *pos);
        if next == MAGIC || next == LEGACY_MAGIC || (0x184D2A50..=0x184D2A5F).contains(&next) {
            break;
        }

        let block_size = read_u32_le(input, pos)? as usize;
        if block_size == 0 {
            break;
        }

        if *pos + block_size > input.len() {
            return Err(Error::UnexpectedEof);
        }

        let block_data = &input[*pos..*pos + block_size];
        *pos += block_size;

        let mut block_output = Vec::new();
        decompress_block(block_data, &mut block_output, &[], usize::MAX)?;
        output.extend_from_slice(&block_output);
    }

    Ok(())
}

fn peek_u32_le(data: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

fn dependent_history(dict: Option<&Lz4Dict>, output: &[u8]) -> Vec<u8> {
    let output_start = output.len().saturating_sub(MAX_DICT_SIZE);
    let output_tail = &output[output_start..];
    if output_tail.len() == MAX_DICT_SIZE {
        return output_tail.to_vec();
    }

    let dict_tail = dict.map_or(&[][..], Lz4Dict::tail);
    let dict_take = MAX_DICT_SIZE - output_tail.len();
    let dict_start = dict_tail.len().saturating_sub(dict_take);

    let mut history = Vec::with_capacity(dict_tail.len() - dict_start + output_tail.len());
    history.extend_from_slice(&dict_tail[dict_start..]);
    history.extend_from_slice(output_tail);
    history
}

/// Decompress a single LZ4 block into the output buffer.
///
/// `max_block_output` bounds the total bytes appended to `dst` beyond
/// its current length; standard frames pass their Block_MaxSize and
/// legacy frames pass `usize::MAX`.
fn decompress_block(
    src: &[u8],
    dst: &mut Vec<u8>,
    dict: &[u8],
    max_block_output: usize,
) -> Result<(), Error> {
    let limit = dst.len().saturating_add(max_block_output);
    let mut sp = 0;

    while sp < src.len() {
        // Token byte
        let token = src[sp];
        sp += 1;

        // Literal length
        let mut lit_len = ((token >> 4) & 0x0F) as usize;
        if lit_len == 15 {
            loop {
                if sp >= src.len() {
                    return Err(Error::UnexpectedEof);
                }
                let extra = src[sp] as usize;
                sp += 1;
                lit_len += extra;
                if extra != 255 {
                    break;
                }
            }
        }

        // Copy literals
        if sp + lit_len > src.len() {
            return Err(Error::UnexpectedEof);
        }
        if dst.len() + lit_len > limit {
            return Err(Error::OutputLimitExceeded {
                limit: max_block_output,
            });
        }
        dst.extend_from_slice(&src[sp..sp + lit_len]);
        sp += lit_len;

        // Last sequence has no match
        if sp >= src.len() {
            break;
        }

        // Match offset (2 bytes LE)
        if sp + 2 > src.len() {
            return Err(Error::UnexpectedEof);
        }
        let offset = (src[sp] as usize) | ((src[sp + 1] as usize) << 8);
        sp += 2;

        if offset == 0 {
            return Err(Error::InvalidData("lz4: zero match offset"));
        }
        if offset > dict.len() + dst.len() {
            return Err(Error::InvalidData("lz4: match offset exceeds history"));
        }

        // Match length
        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            loop {
                if sp >= src.len() {
                    return Err(Error::UnexpectedEof);
                }
                let extra = src[sp] as usize;
                sp += 1;
                match_len += extra;
                if extra != 255 {
                    break;
                }
            }
        }
        match_len += MIN_MATCH;
        if dst.len() + match_len > limit {
            return Err(Error::OutputLimitExceeded {
                limit: max_block_output,
            });
        }

        // Copy match from dictionary prefix and/or current output.
        for _ in 0..match_len {
            let history_len = dict.len() + dst.len();
            let match_start = history_len - offset;
            let b = if match_start < dict.len() {
                dict[match_start]
            } else {
                dst[match_start - dict.len()]
            };
            dst.push(b);
        }
    }

    Ok(())
}

fn read_byte(data: &[u8], pos: &mut usize) -> Result<u8, Error> {
    if *pos >= data.len() {
        return Err(Error::UnexpectedEof);
    }
    let b = data[*pos];
    *pos += 1;
    Ok(b)
}

fn read_u32_le(data: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let v = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

fn read_u64_le(data: &[u8], pos: &mut usize) -> Result<u64, Error> {
    if *pos + 8 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let v = u64::from_le_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
        data[*pos + 4],
        data[*pos + 5],
        data[*pos + 6],
        data[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

/// Decode LZ4 frame data from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or the data is not valid LZ4 format.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode_reader(&compressed[..]).unwrap();
/// assert_eq!(decoded, data);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    decode(&buf).map_err(Into::into)
}

/// Decode LZ4 frame data with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let result = decode(input)?;
    if result.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn test_invalid_magic() {
        let result = decode(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("magic")));
    }

    #[test]
    fn test_input_too_short() {
        let result = decode(&[0x04, 0x22, 0x4D, 0x18]);
        assert!(
            result.is_err(),
            "expected error for truncated input, got {result:?}"
        );
    }

    #[test]
    fn test_truncated_frame_header() {
        // Just the 4-byte magic number with no frame descriptor
        let magic = 0x184D2204u32.to_le_bytes();
        let result = decode(&magic);
        assert!(result.is_err());
    }

    #[test]
    fn test_roundtrip_hello() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let data = b"A";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: alloc::vec::Vec<u8> = (0..=255).collect();
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data = alloc::vec![0xABu8; 100_000];
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_english_text() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     The quick brown fox jumps over the lazy dog.";
        let compressed = super::super::encode::encode(data);
        assert!(compressed.len() < data.len(), "should compress");
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_overlap_copy() {
        // Data with long runs triggers overlapping match copies
        let data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_header_checksum_mismatch() {
        let data = b"test";
        let mut compressed = super::super::encode::encode(data);
        // Corrupt the header checksum (last byte of frame descriptor)
        // HC is at position 6 (magic:4 + FLG:1 + BD:1) for frames without content size
        // With content size it's at position 14 (magic:4 + FLG:1 + BD:1 + size:8)
        // Our encoder writes content size, so HC is at offset 14
        if compressed.len() > 14 {
            compressed[14] ^= 0xFF;
        }
        let result = decode(&compressed);
        assert!(result.is_err());
    }

    /// Build a minimal valid LZ4 frame with custom FLG and BD bytes for
    /// testing header validation. The frame encodes an empty payload.
    fn build_frame_with_header(flg: u8, bd: u8) -> alloc::vec::Vec<u8> {
        use crate::util::xxhash::xxhash32;

        let mut frame = alloc::vec::Vec::new();
        // Magic number
        frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
        // FLG + BD
        frame.push(flg);
        frame.push(bd);
        // Content size (0 bytes) — only if content_size_present flag is set
        if (flg & 0x08) != 0 {
            frame.extend_from_slice(&0u64.to_le_bytes());
        }
        // Header checksum over descriptor bytes (FLG, BD, and optional content size)
        let desc_start = 4;
        let desc_end = frame.len();
        let hc = ((xxhash32(&frame[desc_start..desc_end], 0) >> 8) & 0xFF) as u8;
        frame.push(hc);
        // End mark (no blocks)
        frame.extend_from_slice(&0u32.to_le_bytes());
        // Content checksum if flag is set
        if (flg & 0x04) != 0 {
            let checksum = xxhash32(&[], 0);
            frame.extend_from_slice(&checksum.to_le_bytes());
        }
        frame
    }

    fn build_frame_with_dict_id(flg: u8, bd: u8, dict_id: u32) -> alloc::vec::Vec<u8> {
        use crate::util::xxhash::xxhash32;

        let mut frame = alloc::vec::Vec::new();
        frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
        frame.push(flg);
        frame.push(bd);
        if (flg & 0x08) != 0 {
            frame.extend_from_slice(&0u64.to_le_bytes());
        }
        frame.extend_from_slice(&dict_id.to_le_bytes());
        let hc = ((xxhash32(&frame[4..], 0) >> 8) & 0xFF) as u8;
        frame.push(hc);
        frame.extend_from_slice(&0u32.to_le_bytes());
        if (flg & 0x04) != 0 {
            let checksum = xxhash32(&[], 0);
            frame.extend_from_slice(&checksum.to_le_bytes());
        }
        frame
    }

    fn build_frame_with_blocks(
        flg: u8,
        bd: u8,
        content_size: u64,
        blocks: &[(&[u8], bool)],
    ) -> alloc::vec::Vec<u8> {
        use crate::util::xxhash::xxhash32;

        let mut frame = alloc::vec::Vec::new();
        frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
        frame.push(flg);
        frame.push(bd);
        if (flg & 0x08) != 0 {
            frame.extend_from_slice(&content_size.to_le_bytes());
        }
        let hc = ((xxhash32(&frame[4..], 0) >> 8) & 0xFF) as u8;
        frame.push(hc);
        for (block, uncompressed) in blocks {
            let mut block_header = block.len() as u32;
            if *uncompressed {
                block_header |= 0x8000_0000;
            }
            frame.extend_from_slice(&block_header.to_le_bytes());
            frame.extend_from_slice(block);
            if (flg & 0x10) != 0 {
                frame.extend_from_slice(&xxhash32(block, 0).to_le_bytes());
            }
        }
        frame.extend_from_slice(&0u32.to_le_bytes());
        if (flg & 0x04) != 0 {
            let mut content = Vec::new();
            for (block, uncompressed) in blocks {
                if *uncompressed {
                    content.extend_from_slice(block);
                }
            }
            frame.extend_from_slice(&xxhash32(&content, 0).to_le_bytes());
        }
        frame
    }

    #[test]
    fn test_flg_reserved_bit1_rejected() {
        // FLG: version=01, block_independent=1, content_size=1, content_checksum=1,
        //       plus reserved bit 1 set => should be rejected
        let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3) | (1 << 2) | (1 << 1);
        let bd: u8 = 7 << 4; // block max size id = 7
        let frame = build_frame_with_header(flg, bd);
        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("reserved")),
            "expected reserved FLG bits error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_bd_reserved_bits_rejected() {
        // Valid FLG, but BD has reserved low bits set (bits 0-3)
        let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3) | (1 << 2);
        let bd: u8 = (7 << 4) | 0x01; // reserved bit 0 set
        let frame = build_frame_with_header(flg, bd);
        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("reserved")),
            "expected reserved BD bits error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_dict_id_flag_rejected() {
        // FLG with Dictionary_ID flag (bit 0) set
        let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3) | (1 << 2) | (1 << 0);
        let bd: u8 = 7 << 4;
        let frame = build_frame_with_dict_id(flg, bd, 0x12345678);
        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::Unsupported(msg)) if msg.contains("dictionary")),
            "expected unsupported dictionary error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_decode_block_dependent_frame() {
        let flg: u8 = (1 << 6) | (1 << 3);
        let bd: u8 = 4 << 4;
        let blocks: [(&[u8], bool); 2] = [(b"ABCD", true), (&[0x00, 0x04, 0x00], false)];
        let frame = build_frame_with_blocks(flg, bd, 8, &blocks);
        let decoded = decode(&frame).unwrap();
        assert_eq!(decoded, b"ABCDABCD");
    }

    #[test]
    fn test_block_max_size_id_below_4_rejected() {
        // Valid FLG, but BD has block max size id = 3 (below minimum of 4)
        let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3) | (1 << 2);
        let bd: u8 = 3 << 4; // block max size id = 3
        let frame = build_frame_with_header(flg, bd);
        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("block max size")),
            "expected invalid block max size error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_block_size_exceeds_max_rejected() {
        use crate::util::xxhash::xxhash32;

        // BD id 4 => Block_MaxSize = 64KB. A block header declaring
        // 64KB + 1 bytes (compressed) must be rejected.
        let flg: u8 = (1 << 6) | (1 << 5);
        let bd: u8 = 4 << 4;
        let mut frame = alloc::vec::Vec::new();
        frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
        frame.push(flg);
        frame.push(bd);
        let hc = ((xxhash32(&frame[4..], 0) >> 8) & 0xFF) as u8;
        frame.push(hc);
        frame.extend_from_slice(&(65537u32).to_le_bytes());
        frame.extend_from_slice(&[0u8; 8]);
        frame.extend_from_slice(&0u32.to_le_bytes());

        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("block max size")),
            "expected block size exceeds max error, got {result:?}"
        );
    }

    #[test]
    fn test_uncompressed_block_size_exceeds_max_rejected() {
        use crate::util::xxhash::xxhash32;

        // Same as above but with the uncompressed-block bit (bit 31) set.
        let flg: u8 = (1 << 6) | (1 << 5);
        let bd: u8 = 4 << 4;
        let mut frame = alloc::vec::Vec::new();
        frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
        frame.push(flg);
        frame.push(bd);
        let hc = ((xxhash32(&frame[4..], 0) >> 8) & 0xFF) as u8;
        frame.push(hc);
        frame.extend_from_slice(&((65537u32) | 0x8000_0000).to_le_bytes());
        frame.extend_from_slice(&[0u8; 8]);
        frame.extend_from_slice(&0u32.to_le_bytes());

        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("block max size")),
            "expected block size exceeds max error, got {result:?}"
        );
    }

    #[test]
    fn test_block_decompressed_size_exceeds_max_rejected() {
        // BD id 4 => Block_MaxSize = 64KB. A compressed block whose
        // declared size fits but which decodes beyond 64KB must be
        // rejected.
        let flg: u8 = (1 << 6) | (1 << 5);
        let bd: u8 = 4 << 4;

        // Block: 1 literal 'A', then a match of offset=1 and length
        // 65539 producing 65540 bytes of output (> 65536).
        let mut block = alloc::vec::Vec::new();
        block.push(0x1F); // token: literal len 1, match len nibble 15
        block.push(b'A');
        block.extend_from_slice(&1u16.to_le_bytes()); // match offset 1
        block.extend(core::iter::repeat_n(0xFF, 256)); // 256 * 255 = 65280
        block.push(0xF0); // +240 => match len extras total 65520
        // match_len = 15 + 65520 + 4 = 65539; output = 1 + 65539 = 65540

        let frame = build_frame_with_blocks(flg, bd, 0, &[(&block, false)]);
        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("block max size")),
            "expected decompressed size exceeds max error, got {result:?}"
        );
    }

    #[test]
    fn test_block_size_at_max_accepted() {
        // BD id 4 => Block_MaxSize = 64KB. An uncompressed block of
        // exactly 64KB is within the limit and must decode.
        let flg: u8 = (1 << 6) | (1 << 5);
        let bd: u8 = 4 << 4;
        let block = alloc::vec![0xABu8; 64 * 1024];
        let frame = build_frame_with_blocks(flg, bd, 0, &[(&block, true)]);
        let decoded = decode(&frame).unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn test_skippable_frame_decode() {
        // Build a skippable frame followed by a valid LZ4 frame
        let mut input = alloc::vec::Vec::new();

        // Skippable frame: magic 0x184D2A50, 4-byte size, payload
        let skip_magic: u32 = 0x184D2A50;
        let skip_payload = b"skip me!";
        input.extend_from_slice(&skip_magic.to_le_bytes());
        input.extend_from_slice(&(skip_payload.len() as u32).to_le_bytes());
        input.extend_from_slice(skip_payload);

        // Valid LZ4 frame with some data
        let data = b"Hello after skip!";
        let valid_frame = super::super::encode::encode(data);
        input.extend_from_slice(&valid_frame);

        let result = decode(&input).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_content_checksum_mismatch() {
        let data = b"test data for checksum";
        let mut compressed = super::super::encode::encode(data);
        // Corrupt the last 4 bytes (content checksum)
        let len = compressed.len();
        if len >= 4 {
            compressed[len - 1] ^= 0xFF;
        }
        let result = decode(&compressed);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_checksum_mismatch() {
        let data = b"block checksum test payload";
        let mut compressed = super::super::encode::encode(data);

        let mut pos = 15; // default header: magic + FLG + BD + content size + HC
        let block_header = u32::from_le_bytes([
            compressed[pos],
            compressed[pos + 1],
            compressed[pos + 2],
            compressed[pos + 3],
        ]);
        pos += 4;
        let block_len = (block_header & 0x7FFF_FFFF) as usize;
        pos += block_len;
        compressed[pos] ^= 0xFF;

        let result = decode(&compressed);
        assert!(
            matches!(result, Err(Error::ChecksumMismatch { .. })),
            "expected block checksum mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_decode_max_match_offset_65535() {
        use crate::util::xxhash::xxhash32;

        fn build_frame_with_block(block: &[u8], content_size: u64) -> Vec<u8> {
            let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3);
            let bd: u8 = 7 << 4;
            let mut frame = Vec::new();
            frame.extend_from_slice(&0x184D2204u32.to_le_bytes());
            frame.push(flg);
            frame.push(bd);
            frame.extend_from_slice(&content_size.to_le_bytes());
            let hc = ((xxhash32(&frame[4..], 0) >> 8) & 0xFF) as u8;
            frame.push(hc);
            frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
            frame.extend_from_slice(block);
            frame.extend_from_slice(&0u32.to_le_bytes());
            frame
        }

        let prefix: Vec<u8> = (0..65535).map(|i| (i % 251) as u8).collect();
        let mut block = Vec::with_capacity(1 + 257 + prefix.len() + 2);
        block.push(0xF0);
        block.extend(core::iter::repeat_n(0xFF, 256));
        block.push(0xF0);
        block.extend_from_slice(&prefix);
        block.extend_from_slice(&0xFFFFu16.to_le_bytes());

        let frame = build_frame_with_block(&block, (prefix.len() + 4) as u64);
        let decoded = decode(&frame).unwrap();

        let mut expected = prefix;
        let prefix = expected[..4].to_vec();
        expected.extend_from_slice(&prefix);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_with_dict_id_mismatch_rejected() {
        let flg: u8 = (1 << 6) | (1 << 5) | (1 << 3) | (1 << 2) | (1 << 0);
        let bd: u8 = 7 << 4;
        let frame = build_frame_with_dict_id(flg, bd, 7);
        let dict = Lz4Dict::with_id(b"prefix", 8);
        let result = decode_with_dict(&frame, &dict);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("lz4: dictionary ID mismatch"))
            ),
            "expected dictionary ID mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_decode_with_dict_roundtrip() {
        let dict = Lz4Dict::with_id(b"common-prefix-", 0xAABBCCDD);
        let compressed = super::super::encode::encode_with_dict(b"common-prefix-payload", &dict);
        let decoded = decode_with_dict(&compressed, &dict).unwrap();
        assert_eq!(decoded, b"common-prefix-payload");
    }

    // --- Legacy frame tests ---

    #[test]
    fn test_legacy_frame_roundtrip() {
        let data = b"Hello, legacy LZ4 frame!";
        let compressed = super::super::encode::encode_legacy(data);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_legacy_frame_empty() {
        let data = b"";
        let compressed = super::super::encode::encode_legacy(data);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_legacy_frame_large_repeated() {
        let data = alloc::vec![0xABu8; 100_000];
        let compressed = super::super::encode::encode_legacy(&data);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    // --- Multi-frame tests ---

    #[test]
    fn test_multi_frame_standard_concat() {
        let data1 = b"frame one data";
        let data2 = b"frame two data";
        let mut combined = super::super::encode::encode(data1);
        combined.extend_from_slice(&super::super::encode::encode(data2));
        let decoded = decode(&combined).unwrap();
        let mut expected = data1.to_vec();
        expected.extend_from_slice(data2);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_multi_frame_legacy_then_standard() {
        let data1 = b"legacy frame data";
        let data2 = b"standard frame data";
        let mut combined = super::super::encode::encode_legacy(data1);
        combined.extend_from_slice(&super::super::encode::encode(data2));
        let decoded = decode(&combined).unwrap();
        let mut expected = data1.to_vec();
        expected.extend_from_slice(data2);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_multi_frame_standard_then_legacy() {
        let data1 = b"standard frame data";
        let data2 = b"legacy frame data";
        let mut combined = super::super::encode::encode(data1);
        combined.extend_from_slice(&super::super::encode::encode_legacy(data2));
        let decoded = decode(&combined).unwrap();
        let mut expected = data1.to_vec();
        expected.extend_from_slice(data2);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_multi_frame_three_legacy() {
        let d1 = b"one";
        let d2 = b"two";
        let d3 = b"three";
        let mut combined = super::super::encode::encode_legacy(d1);
        combined.extend_from_slice(&super::super::encode::encode_legacy(d2));
        combined.extend_from_slice(&super::super::encode::encode_legacy(d3));
        let decoded = decode(&combined).unwrap();
        let mut expected = d1.to_vec();
        expected.extend_from_slice(d2);
        expected.extend_from_slice(d3);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello lz4 bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_block_roundtrip() {
        let data = b"hello lz4 raw block test data hello lz4 raw block test data";
        let block = super::super::encode::encode_block(data);
        let decoded = decode_block(&block, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_block_roundtrip_with_dict() {
        let dict = Lz4Dict::new(b"shared dictionary prefix shared dictionary prefix");
        let data = b"block payload referencing the dictionary prefix";
        let block = super::super::encode::encode_block_with_dict(data, &dict);
        let decoded = decode_block_with_dict(&block, &dict, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_block_limit_exceeded() {
        let data = b"hello lz4 raw block test data";
        let block = super::super::encode::encode_block(data);
        assert!(matches!(
            decode_block(&block, data.len() - 1),
            Err(Error::OutputLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_decode_block_malformed() {
        assert!(decode_block(&[0x50, 0x01], 64).is_err());
        // Match offset pointing beyond available history.
        assert!(decode_block(&[0x04, 0xFF, 0xFF], 64).is_err());
    }

    #[test]
    fn test_decode_block_empty() {
        assert_eq!(decode_block(&[], 64).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello lz4 bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello lz4 bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello lz4 bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // LZ4 encoding of empty data produces a valid frame with no blocks.
        let compressed = super::super::encode::encode(b"");
        let decoded = decode_bounded(&compressed, 0).unwrap();
        assert!(decoded.is_empty());
    }
}
