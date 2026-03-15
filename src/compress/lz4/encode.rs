//! LZ4 frame format compression.
//!
//! Compresses data using the LZ4 block format, wrapped in the LZ4 frame
//! format as specified by the
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

use alloc::vec;
use alloc::vec::Vec;

use super::decode::Lz4Dict;
use crate::util::xxhash::xxhash32;

/// LZ4 frame magic number.
const MAGIC: u32 = 0x184D2204;

/// LZ4 legacy frame magic number.
const LEGACY_MAGIC: u32 = 0x184C_2102;

/// Default legacy block size (8 MB, matching reference implementation).
const LEGACY_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Minimum match length.
const MIN_MATCH: usize = 4;

/// Last N bytes of input must be literals (LZ4 safety margin).
const LAST_LITERALS: usize = 5;

/// Last match must start at least this many bytes before end.
const MF_LIMIT: usize = 12;

/// Block maximum size options for LZ4 frames.
#[derive(Debug, Clone, Copy)]
pub enum BlockMaxSize {
    /// 64 KB blocks.
    KB64 = 4,
    /// 256 KB blocks.
    KB256 = 5,
    /// 1 MB blocks.
    MB1 = 6,
    /// 4 MB blocks (default).
    MB4 = 7,
}

impl BlockMaxSize {
    /// Returns the maximum block size in bytes for this variant.
    const fn byte_size(self) -> usize {
        match self {
            BlockMaxSize::KB64 => 64 * 1024,
            BlockMaxSize::KB256 => 256 * 1024,
            BlockMaxSize::MB1 => 1024 * 1024,
            BlockMaxSize::MB4 => 4 * 1024 * 1024,
        }
    }
}

/// Compress data using LZ4 frame format with default settings.
///
/// Uses 4MB block max size, content size, block checksum, and content checksum enabled.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, LZ4!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_options(input, BlockMaxSize::MB4, true)
}

/// Compress data using LZ4 frame format with a dictionary.
pub fn encode_with_dict(input: &[u8], dict: &Lz4Dict) -> Vec<u8> {
    encode_with_options_and_dict(input, BlockMaxSize::MB4, true, Some(dict))
}

/// Compress data using the LZ4 legacy frame format.
///
/// Legacy frames use magic `0x184C2102` and have a simpler structure:
/// no frame descriptor, no checksums. Each block is preceded by a
/// compressed-size u32.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, legacy LZ4!";
/// let compressed = encode::encode_legacy(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_legacy(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&LEGACY_MAGIC.to_le_bytes());

    for chunk in input.chunks(LEGACY_BLOCK_SIZE) {
        if chunk.is_empty() {
            break;
        }
        let compressed = compress_block(chunk, &[]);
        if compressed.len() >= chunk.len() {
            // For legacy format, uncompressed blocks are stored as-is
            // with the size being the uncompressed block size.
            // The reference implementation always stores compressed data;
            // we emit the raw block since the decoder handles it.
            output.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            // Legacy format stores literal-only blocks as an LZ4 block
            // containing only literals (no match). Build such a block.
            let mut lit_block = Vec::new();
            emit_literals(&mut lit_block, chunk, true);
            // Rewrite with the literal block
            let len = output.len();
            output.truncate(len - 4);
            output.extend_from_slice(&(lit_block.len() as u32).to_le_bytes());
            output.extend_from_slice(&lit_block);
        } else {
            output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            output.extend_from_slice(&compressed);
        }
    }

    // For empty input, write nothing after the magic (frame terminates
    // naturally when no blocks are present).

    output
}

/// Compress data using LZ4 frame format with block-dependent mode.
///
/// In block-dependent mode (FLG bit 5 = 0), the compressor carries
/// history across block boundaries, potentially improving compression
/// ratio at the cost of requiring sequential decompression.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, dependent blocks! Hello, dependent blocks!";
/// let compressed = encode::encode_block_dependent(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_block_dependent(input: &[u8]) -> Vec<u8> {
    encode_block_dependent_with_options(input, BlockMaxSize::MB4, true)
}

/// Compress data using LZ4 frame format with block-dependent mode and options.
pub fn encode_block_dependent_with_options(
    input: &[u8],
    block_max_size: BlockMaxSize,
    content_checksum: bool,
) -> Vec<u8> {
    let mut output = Vec::new();

    // Magic number
    output.extend_from_slice(&MAGIC.to_le_bytes());

    // Frame descriptor: block_independent bit (bit 5) is NOT set
    let flg: u8 = (1 << 6)      // version = 01
        | (1 << 4)               // block checksum present
        | (1 << 3)               // content size present
        | if content_checksum { 0x04 } else { 0 };
    // Note: bit 5 (block independence) is 0 for dependent mode
    let bd: u8 = (block_max_size as u8) << 4;

    let mut desc = Vec::new();
    desc.push(flg);
    desc.push(bd);
    desc.extend_from_slice(&(input.len() as u64).to_le_bytes());

    let hc = ((xxhash32(&desc, 0) >> 8) & 0xFF) as u8;

    output.extend_from_slice(&desc);
    output.push(hc);

    // Compress blocks with history carried across blocks
    let block_size = block_max_size.byte_size();
    let mut history = Vec::new();

    for chunk in input.chunks(block_size).chain(if input.is_empty() {
        Some(&[][..])
    } else {
        None
    }) {
        if chunk.is_empty() {
            break;
        }

        // Use the tail of previous output as dictionary prefix
        let prefix_start = history.len().saturating_sub(65_535);
        let prefix = &history[prefix_start..];
        let compressed = compress_block(chunk, prefix);

        if compressed.len() >= chunk.len() {
            let block_header = (chunk.len() as u32) | 0x80000000;
            output.extend_from_slice(&block_header.to_le_bytes());
            output.extend_from_slice(chunk);
            output.extend_from_slice(&xxhash32(chunk, 0).to_le_bytes());
        } else {
            let block_header = compressed.len() as u32;
            output.extend_from_slice(&block_header.to_le_bytes());
            output.extend_from_slice(&compressed);
            output.extend_from_slice(&xxhash32(&compressed, 0).to_le_bytes());
        }

        // Accumulate history for dependent mode
        history.extend_from_slice(chunk);
        // Keep only the last 64KB of history
        if history.len() > 65_535 {
            let start = history.len() - 65_535;
            history = history[start..].to_vec();
        }
    }

    // End mark
    output.extend_from_slice(&0u32.to_le_bytes());

    // Content checksum
    if content_checksum {
        let checksum = xxhash32(input, 0);
        output.extend_from_slice(&checksum.to_le_bytes());
    }

    output
}

/// Compress data using LZ4 frame format with specified options.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::{decode, encode};
///
/// let data = b"Hello, LZ4!";
/// let compressed = encode::encode_with_options(
///     data,
///     encode::BlockMaxSize::KB64,
///     true,
/// );
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with_options(
    input: &[u8],
    block_max_size: BlockMaxSize,
    content_checksum: bool,
) -> Vec<u8> {
    encode_with_options_and_dict(input, block_max_size, content_checksum, None)
}

fn encode_with_options_and_dict(
    input: &[u8],
    block_max_size: BlockMaxSize,
    content_checksum: bool,
    dict: Option<&Lz4Dict>,
) -> Vec<u8> {
    let mut output = Vec::new();

    // Magic number
    output.extend_from_slice(&MAGIC.to_le_bytes());

    // Frame descriptor
    let flg: u8 = (1 << 6)      // version = 01
        | (1 << 5)               // block independence
        | (1 << 4)               // block checksum present
        | (1 << 3)               // content size present
        | if content_checksum { 0x04 } else { 0 }
        | if dict.and_then(|d| d.id).is_some() { 0x01 } else { 0 };
    let bd: u8 = (block_max_size as u8) << 4;

    let mut desc = Vec::new();
    desc.push(flg);
    desc.push(bd);
    desc.extend_from_slice(&(input.len() as u64).to_le_bytes());
    if let Some(dict_id) = dict.and_then(|d| d.id) {
        desc.extend_from_slice(&dict_id.to_le_bytes());
    }

    // Header checksum = second byte of xxhash32(descriptor)
    let hc = ((xxhash32(&desc, 0) >> 8) & 0xFF) as u8;

    output.extend_from_slice(&desc);
    output.push(hc);

    // Compress blocks
    let block_size = block_max_size.byte_size();
    for chunk in input.chunks(block_size).chain(
        // Ensure at least one empty block for empty input
        if input.is_empty() {
            Some(&[][..])
        } else {
            None
        },
    ) {
        if chunk.is_empty() {
            // Empty input: write endmark directly (no blocks)
            break;
        }

        let compressed = compress_block(chunk, dict.map_or(&[][..], Lz4Dict::tail));

        if compressed.len() >= chunk.len() {
            // Compression didn't help — store uncompressed
            let block_header = (chunk.len() as u32) | 0x80000000;
            output.extend_from_slice(&block_header.to_le_bytes());
            output.extend_from_slice(chunk);
            output.extend_from_slice(&xxhash32(chunk, 0).to_le_bytes());
        } else {
            let block_header = compressed.len() as u32;
            output.extend_from_slice(&block_header.to_le_bytes());
            output.extend_from_slice(&compressed);
            output.extend_from_slice(&xxhash32(&compressed, 0).to_le_bytes());
        }
    }

    // End mark
    output.extend_from_slice(&0u32.to_le_bytes());

    // Content checksum
    if content_checksum {
        let checksum = xxhash32(input, 0);
        output.extend_from_slice(&checksum.to_le_bytes());
    }

    output
}

/// Compress a single block using LZ4 block format.
fn compress_block(input: &[u8], dict: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    if input.len() < MF_LIMIT {
        // Too small for match finding — emit all as literals
        emit_literals(&mut output, input, true);
        return output;
    }

    let prefix_start = dict.len().saturating_sub(65_535);
    let prefix = &dict[prefix_start..];
    let prefix_len = prefix.len();
    let mut window = Vec::with_capacity(prefix_len + input.len());
    window.extend_from_slice(prefix);
    window.extend_from_slice(input);

    // Hash table: maps 4-byte hash → position in prefix+input window
    let hash_bits = 14;
    let hash_size = 1 << hash_bits;
    let mut hash_table = vec![u32::MAX; hash_size];

    if window.len() >= 4 {
        for p in 0..prefix_len.saturating_sub(3) {
            let h = hash4(&window[p..]) & (hash_size - 1);
            hash_table[h] = p as u32;
        }
    }

    let mut anchor = prefix_len; // Start of current literal run
    let mut pos = prefix_len;

    let limit = window.len() - MF_LIMIT;

    while pos < limit {
        let h = hash4(&window[pos..]) & (hash_size - 1);
        let candidate = hash_table[h];
        hash_table[h] = pos as u32;

        // Check for match
        if candidate != u32::MAX
            && (candidate as usize) < pos
            && pos - (candidate as usize) <= 65535
            && window[candidate as usize..candidate as usize + 4] == window[pos..pos + 4]
        {
            // Found a match — emit literals from anchor to pos
            let offset = pos - candidate as usize;

            // Extend match forward
            let mut match_len = 4;
            let max_match = window.len() - LAST_LITERALS - pos;
            while match_len < max_match
                && window[candidate as usize + match_len] == window[pos + match_len]
            {
                match_len += 1;
            }

            // Emit sequence
            emit_sequence(&mut output, &window[anchor..pos], offset, match_len);

            pos += match_len;
            anchor = pos;
        } else {
            pos += 1;
        }
    }

    // Emit remaining literals (last sequence, no match)
    if anchor < window.len() {
        emit_literals(&mut output, &window[anchor..], true);
    }

    output
}

/// Emit a complete sequence (literals + match).
fn emit_sequence(output: &mut Vec<u8>, literals: &[u8], offset: usize, match_len: usize) {
    let lit_len = literals.len();
    let ml = match_len - MIN_MATCH;

    // Token
    let token = ((lit_len.min(15) as u8) << 4) | (ml.min(15) as u8);
    output.push(token);

    // Literal length overflow
    if lit_len >= 15 {
        write_lsic(output, lit_len - 15);
    }

    // Literals
    output.extend_from_slice(literals);

    // Match offset (2 bytes LE)
    output.push(offset as u8);
    output.push((offset >> 8) as u8);

    // Match length overflow
    if ml >= 15 {
        write_lsic(output, ml - 15);
    }
}

/// Emit a literals-only sequence (last sequence in block).
fn emit_literals(output: &mut Vec<u8>, literals: &[u8], _is_last: bool) {
    let lit_len = literals.len();

    // Token (no match part)
    let token = (lit_len.min(15) as u8) << 4;
    output.push(token);

    // Literal length overflow
    if lit_len >= 15 {
        write_lsic(output, lit_len - 15);
    }

    // Literals
    output.extend_from_slice(literals);
}

/// Write LSIC (Linear Small Integer Code) for overflow lengths.
fn write_lsic(output: &mut Vec<u8>, mut value: usize) {
    while value >= 255 {
        output.push(255);
        value -= 255;
    }
    output.push(value as u8);
}

/// Hash 4 bytes for match finding.
fn hash4(data: &[u8]) -> usize {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    (v.wrapping_mul(2654435761) >> 18) as usize
}

/// Compress data and write to a writer.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::lz4::encode;
///
/// let data = b"Hello, writer!";
/// let mut output = Vec::new();
/// let size = encode::encode_writer(data, &mut output).unwrap();
/// assert!(size > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(input: &[u8], mut writer: W) -> std::io::Result<usize> {
    let encoded = encode(input);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_format() {
        let compressed = encode(b"A");
        assert_eq!(compressed[0], 0x04); // magic LE
        assert_eq!(compressed[1], 0x22);
        assert_eq!(compressed[2], 0x4D);
        assert_eq!(compressed[3], 0x18);
        let flg = compressed[4];
        assert_eq!(flg >> 6, 1); // version
        assert_ne!(flg & 0x20, 0); // block independence
        assert_ne!(flg & 0x10, 0); // block checksum (default)
        assert_ne!(flg & 0x08, 0); // content size
        assert_ne!(flg & 0x04, 0); // content checksum (default)
    }

    #[test]
    fn test_empty_input() {
        let compressed = encode(b"");
        // Should have: magic(4) + FLG(1) + BD(1) + content_size(8) + HC(1) + endmark(4) + checksum(4)
        assert_eq!(compressed.len(), 4 + 1 + 1 + 8 + 1 + 4 + 4);
    }

    #[test]
    fn test_block_checksum_present_for_uncompressed_block() {
        let data: Vec<u8> = (0..256)
            .map(|i| (i as u8).wrapping_mul(127).wrapping_add(31))
            .collect();
        let compressed = encode(&data);

        // Frame header is 15 bytes for default settings.
        let mut pos = 15;
        let block_header = u32::from_le_bytes([
            compressed[pos],
            compressed[pos + 1],
            compressed[pos + 2],
            compressed[pos + 3],
        ]);
        pos += 4;
        let block_len = (block_header & 0x7FFF_FFFF) as usize;
        let block_data = &compressed[pos..pos + block_len];
        pos += block_len;
        let checksum = u32::from_le_bytes([
            compressed[pos],
            compressed[pos + 1],
            compressed[pos + 2],
            compressed[pos + 3],
        ]);
        assert_eq!(checksum, xxhash32(block_data, 0));
    }

    #[test]
    fn test_compression_ratio() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = encode(data);
        assert!(
            compressed.len() < data.len() + 23, // frame overhead
            "compressed {} should be reasonable for {} bytes",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn test_roundtrip_with_block_sizes() {
        let data = b"Hello, LZ4 block sizes!".repeat(100);
        for block_size in &[
            BlockMaxSize::KB64,
            BlockMaxSize::KB256,
            BlockMaxSize::MB1,
            BlockMaxSize::MB4,
        ] {
            let compressed = encode_with_options(&data, *block_size, true);
            let decompressed = super::super::decode::decode(&compressed).unwrap();
            assert_eq!(decompressed, data, "failed for block_size={:?}", block_size);
        }
    }

    #[test]
    fn test_block_max_size_byte_size() {
        assert_eq!(BlockMaxSize::KB64.byte_size(), 65536);
        assert_eq!(BlockMaxSize::KB256.byte_size(), 262144);
        assert_eq!(BlockMaxSize::MB1.byte_size(), 1048576);
        assert_eq!(BlockMaxSize::MB4.byte_size(), 4194304);
    }

    #[test]
    fn test_uncompressed_fallback() {
        // Random-ish data that shouldn't compress well
        let data: Vec<u8> = (0..256)
            .map(|i| (i as u8).wrapping_mul(127).wrapping_add(31))
            .collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_with_dict_roundtrip() {
        let dict = Lz4Dict::with_id(b"common-prefix-", 0xAABBCCDD);
        let data = b"common-prefix-payload";
        let compressed = encode_with_dict(data, &dict);
        let decompressed = super::super::decode::decode_with_dict(&compressed, &dict).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_with_dict_sets_dict_id_flag() {
        let dict = Lz4Dict::with_id(b"prefix", 0x11223344);
        let compressed = encode_with_dict(b"prefix-data", &dict);
        assert_ne!(compressed[4] & 0x01, 0);
        assert_eq!(
            u32::from_le_bytes([
                compressed[14],
                compressed[15],
                compressed[16],
                compressed[17]
            ]),
            0x11223344
        );
    }

    #[test]
    fn test_roundtrip_all_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_writer_roundtrip() {
        let input = b"Hello, LZ4 writer!";
        let mut output = Vec::new();
        let size = encode_writer(input, &mut output).unwrap();
        assert_eq!(size, output.len());
        let decoded = super::super::decode::decode(&output).unwrap();
        assert_eq!(decoded, input);
    }

    // --- Legacy frame encode tests ---

    #[test]
    fn test_legacy_encode_header() {
        let compressed = encode_legacy(b"A");
        assert_eq!(
            u32::from_le_bytes([compressed[0], compressed[1], compressed[2], compressed[3]]),
            LEGACY_MAGIC
        );
    }

    #[test]
    fn test_legacy_encode_roundtrip() {
        let data = b"Hello, legacy LZ4 encoding!";
        let compressed = encode_legacy(data);
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_legacy_encode_empty() {
        let compressed = encode_legacy(b"");
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_legacy_encode_repeated_data() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = encode_legacy(data);
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    // --- Block-dependent encode tests ---

    #[test]
    fn test_block_dependent_header_flag() {
        let compressed = encode_block_dependent(b"test");
        let flg = compressed[4];
        // bit 5 should NOT be set (block_independent = 0)
        assert_eq!(flg & 0x20, 0, "block independence bit should be 0");
        // version should still be 01
        assert_eq!(flg >> 6, 1);
    }

    #[test]
    fn test_block_dependent_roundtrip() {
        let data = b"Hello, block-dependent LZ4! Hello, block-dependent LZ4!";
        let compressed = encode_block_dependent(data);
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_block_dependent_roundtrip_large() {
        // Data large enough to span multiple blocks with small block size
        let data = b"dependent mode test data ".repeat(5000);
        let compressed = encode_block_dependent_with_options(&data, BlockMaxSize::KB64, true);
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_block_dependent_roundtrip_empty() {
        let compressed = encode_block_dependent(b"");
        let decoded = super::super::decode::decode(&compressed).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_block_dependent_with_block_sizes() {
        let data = b"block dependent sizes ".repeat(200);
        for block_size in &[
            BlockMaxSize::KB64,
            BlockMaxSize::KB256,
            BlockMaxSize::MB1,
            BlockMaxSize::MB4,
        ] {
            let compressed = encode_block_dependent_with_options(&data, *block_size, true);
            let decoded = super::super::decode::decode(&compressed).unwrap();
            assert_eq!(decoded, data, "failed for block_size={:?}", block_size);
        }
    }
}
