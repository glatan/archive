//! zstd compression per [RFC 8878].
//!
//! The public encoder emits Raw/RLE/Compressed blocks, optional XXH64 content
//! checksums, and optional dictionary IDs. Compressed blocks use the shared
//! internal LZ77 + predefined-FSE/Huffman helper path when it beats raw output.
//!
//! [RFC 8878]: https://datatracker.ietf.org/doc/html/rfc8878

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::util::xxhash;

use super::frame::ZSTD_MAGIC;
use super::fse::{
    FseTable, default_literal_length_table, default_match_length_table, default_offset_table,
};
use super::sequences::{LL_BASE, LL_EXTRA, ML_BASE, ML_EXTRA};

/// Maximum block content size (128 KB - 1, per RFC 8878 §3.1.1.2).
const MAX_BLOCK_SIZE: usize = 128 * 1024 - 1;

/// Minimum input size to attempt LZ77 compression.
const MIN_COMPRESS_SIZE: usize = 16;
// LZ77 parameters
const MAX_MATCH_LEN: usize = 65539; // ML_BASE max
const MIN_MATCH_LEN: usize = 3;
const WINDOW_SIZE: usize = 32768;
const HASH_BITS: usize = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN_LEN: usize = 32;

/// Options for zstd encoding.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::encode::EncodeOptions;
///
/// let opts = EncodeOptions { checksum: false };
/// ```
pub struct EncodeOptions {
    /// Whether to include an XXH64 content checksum in the frame.
    /// Default: `true`.
    pub checksum: bool,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self { checksum: true }
    }
}

/// Encode data as a zstd frame.
///
/// Emits a zstd frame using Raw/RLE/Compressed blocks plus an XXH64 content checksum.
/// Compressible chunks can take the shared LZ77 + predefined-FSE/Huffman block
/// path when it produces a smaller payload than a raw block.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::{encode, decode};
///
/// let zst = encode::encode(b"Hello, World!");
/// let data = decode::decode(&zst).unwrap();
/// assert_eq!(data, b"Hello, World!");
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    encode_frame(input, &mut output, None, true);
    output
}

/// Encode data as a zstd frame with custom options.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::{encode, decode};
/// use archive::compress::zstd::encode::EncodeOptions;
///
/// let opts = EncodeOptions { checksum: false };
/// let zst = encode::encode_with_options(b"data", &opts);
/// let data = decode::decode(&zst).unwrap();
/// assert_eq!(data, b"data");
/// ```
pub fn encode_with_options(input: &[u8], options: &EncodeOptions) -> Vec<u8> {
    let mut output = Vec::new();
    encode_frame(input, &mut output, None, options.checksum);
    output
}

/// Encode data as a zstd frame tagged with a dictionary ID.
///
/// The public path preserves the dictionary ID in the frame header for
/// decode-side validation and can reuse dictionary content while searching for
/// compressed-block matches.
///
/// This function does not panic.
///
/// # Examples
///
/// ```no_run
/// use archive::compress::zstd::{decode, encode};
/// use archive::compress::zstd::train::{train_dictionary, TrainOptions};
///
/// let dict = train_dictionary(&[b"sample sample sample".as_slice()], &TrainOptions::default())
///     .unwrap();
///
/// let compressed = encode::encode_with_dict(b"some data", &dict);
/// let decompressed = decode::decode_with_dict(&compressed, &dict).unwrap();
/// assert_eq!(decompressed, b"some data");
/// ```
pub fn encode_with_dict(input: &[u8], dict: &super::decode::ZstdDict) -> Vec<u8> {
    let mut output = Vec::new();
    encode_frame(input, &mut output, Some(dict), true);
    output
}

/// Encode data as a zstd frame into an existing Vec.
fn encode_frame(
    input: &[u8],
    output: &mut Vec<u8>,
    dict: Option<&super::decode::ZstdDict>,
    checksum: bool,
) {
    // Magic number
    output.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());

    // Frame header descriptor
    let fcs_flag = fcs_flag_for_size(input.len() as u64);
    let dict_id_flag = match dict {
        Some(_) => 3u8, // 4-byte dictionary ID
        None => 0u8,
    };
    let checksum_bit = if checksum { 1u8 << 2 } else { 0u8 };
    let descriptor = (fcs_flag << 6) | (1 << 5) | checksum_bit | dict_id_flag; // SS=1
    output.push(descriptor);

    // Dictionary ID (if present)
    if let Some(d) = dict {
        output.extend_from_slice(&d.id.to_le_bytes());
    }

    // Frame Content Size field
    write_fcs(input.len() as u64, fcs_flag, output);

    let dict_content: &[u8] = match dict {
        Some(d) => &d.content,
        None => &[],
    };

    // Blocks
    if input.is_empty() {
        write_block_header(output, true, 0b00, 0);
    } else {
        let mut pos = 0;
        while pos < input.len() {
            let remaining = input.len() - pos;
            let chunk_size = remaining.min(MAX_BLOCK_SIZE);
            let is_last = pos + chunk_size >= input.len();
            let chunk = &input[pos..pos + chunk_size];

            // The match searcher's virtual buffer must mirror the decoder's
            // `[dict | output]` history window. Only the first block can
            // reference the dictionary: at pos > 0 an offset into the dict
            // prefix would resolve against the frame output the decoder has
            // already produced, silently copying the wrong bytes. Later
            // blocks therefore search the real frame history (the last
            // WINDOW_SIZE input bytes), which is also all the decoder's
            // window can reach — the dictionary tail is never within
            // WINDOW_SIZE once pos >= MAX_BLOCK_SIZE > WINDOW_SIZE.
            let history: &[u8] = if pos == 0 {
                dict_content
            } else {
                &input[pos.saturating_sub(WINDOW_SIZE)..pos]
            };
            encode_best_block(chunk, is_last, output, history);
            pos += chunk_size;
        }
    }

    // Content checksum
    if checksum {
        let hash = xxhash::xxhash64(input, 0);
        let cksum = (hash & 0xFFFFFFFF) as u32;
        output.extend_from_slice(&cksum.to_le_bytes());
    }
}

/// Encode a single block using the best strategy.
///
/// `history` is the decoder-visible history prefix for this block: the
/// dictionary content for the first block, or the preceding frame bytes
/// (at most the last `WINDOW_SIZE`) for later blocks.
fn encode_best_block(chunk: &[u8], is_last: bool, output: &mut Vec<u8>, history: &[u8]) {
    // RLE: all same byte
    if chunk.len() > 1 && chunk.iter().all(|&b| b == chunk[0]) {
        write_block_header(output, is_last, 0b01, chunk.len() as u32);
        output.push(chunk[0]);
        return;
    }

    if chunk.len() >= MIN_COMPRESS_SIZE {
        let compressed = build_compressed_block(chunk, history);
        if compressed.len() < chunk.len() {
            write_block_header(output, is_last, 0b10, compressed.len() as u32);
            output.extend_from_slice(&compressed);
            return;
        }
    }

    // Fallback: raw block
    write_block_header(output, is_last, 0b00, chunk.len() as u32);
    output.extend_from_slice(chunk);
}

// ============================================================
// Compressed block encoding
// ============================================================

/// A sequence produced by LZ77 matching.
struct EncSequence {
    literal_length: u32,
    offset_raw: u32, // For new offsets: real_offset + 3
    match_length: u32,
}

/// Build a compressed block's content bytes.
fn build_compressed_block(input: &[u8], history: &[u8]) -> Vec<u8> {
    let (literals, sequences) = lz77_compress_with_dict(input, history);

    if sequences.is_empty() {
        // No matches found — emit literals-only compressed block
        let mut block = Vec::new();
        write_raw_literals_section(&literals, &mut block);
        // Sequences header: 0 sequences
        block.push(0x00);
        return block;
    }

    // Build predefined-table block first
    let predefined_block = build_predefined_block(&literals, &sequences);

    // Try custom FSE tables — use if smaller
    #[cfg(test)]
    if let Some(custom_block) =
        try_build_with_custom_fse(&literals, &sequences, predefined_block.len())
    {
        custom_block
    } else {
        predefined_block
    }
    #[cfg(not(test))]
    {
        predefined_block
    }
}

/// Write a Raw_Literals_Block header + data.
fn write_raw_literals_section(literals: &[u8], output: &mut Vec<u8>) {
    let size = literals.len();
    // Literals_Block_Type = 0 (Raw), Size_Format determines header size
    if size < 32 {
        // 1-byte header: size_format=0b00 or 0b10 (both mean 5-bit size, 1-byte header)
        // header_byte = (size << 3) | (0 << 2) | 0b00
        output.push((size as u8) << 3);
    } else if size < 4096 {
        // 2-byte header: size_format=0b01
        // byte0 = (size[3:0] << 4) | (0b01 << 2) | 0b00
        // byte1 = size[11:4]
        output.push(((size as u8 & 0x0F) << 4) | 0x04);
        output.push((size >> 4) as u8);
    } else {
        // 3-byte header: size_format=0b11
        // byte0 = (size[3:0] << 4) | (0b11 << 2) | 0b00
        // byte1 = size[11:4]
        // byte2 = size[19:12]
        output.push(((size as u8 & 0x0F) << 4) | 0x0C);
        output.push((size >> 4) as u8);
        output.push((size >> 12) as u8);
    }
    output.extend_from_slice(literals);
}

// ============================================================
// Huffman literal compression
// ============================================================

/// Minimum number of distinct byte values to use Huffman encoding.
/// With fewer, raw literals are more efficient.
const MIN_HUFFMAN_SYMBOLS: usize = 3;
const MAX_SAFE_HUFFMAN_SYMBOLS: usize = 64;

/// Maximum regen_size for single-stream Huffman (size_format=0, 10-bit field).
const MAX_SINGLE_STREAM_SIZE: usize = 1023;

/// Maximum regen_size for 4-stream Huffman with size_format=2 (14-bit field).
const MAX_FOUR_STREAM_SIZE: usize = 16383;

/// Try to write a Huffman-compressed literals section.
/// Uses single stream for small literals (≤1023 bytes), 4 streams for larger.
/// Returns `true` if Huffman was used, `false` if caller should fall back to raw.
fn try_write_huffman_literals_section(literals: &[u8], output: &mut Vec<u8>) -> bool {
    if literals.is_empty() || literals.len() > MAX_FOUR_STREAM_SIZE {
        return false;
    }

    // Count byte frequencies
    let mut freq = [0u32; 256];
    for &b in literals {
        freq[b as usize] += 1;
    }

    let num_distinct = freq.iter().filter(|&&f| f > 0).count();
    if !(MIN_HUFFMAN_SYMBOLS..=MAX_SAFE_HUFFMAN_SYMBOLS).contains(&num_distinct) {
        return false;
    }

    // Build Huffman code lengths
    let code_lengths = build_huffman_lengths(&freq);
    let max_cl = *code_lengths.iter().max().unwrap_or(&0);
    if max_cl == 0 || max_cl > 11 {
        return false;
    }

    // Convert code lengths to weights: weight = max_cl + 1 - code_length
    let mut weights = Vec::new();
    let mut last_active = 0usize;
    for (i, &cl) in code_lengths.iter().enumerate() {
        if cl > 0 {
            last_active = i;
        }
    }
    for &code_length in code_lengths.iter().take(last_active + 1) {
        if code_length > 0 {
            weights.push(max_cl + 1 - code_length);
        } else {
            weights.push(0);
        }
    }

    // Verify the implicit last weight mechanism works
    let last_sym_weight = weights[last_active];
    let explicit_weights = &weights[..last_active];

    if explicit_weights.len() > 128 {
        return false;
    }

    let explicit_sum: u32 = explicit_weights
        .iter()
        .filter(|&&w| w > 0)
        .map(|&w| 1u32 << (w - 1))
        .sum();

    let total_sum = explicit_sum + (1u32 << (last_sym_weight - 1));
    if !total_sum.is_power_of_two() {
        return false;
    }
    if explicit_sum.is_power_of_two() && explicit_sum == total_sum {
        return false;
    }

    if weights.iter().any(|&w| w > 15) {
        return false;
    }

    let codes = build_canonical_codes(&code_lengths, max_cl);
    let weights_bytes = serialize_weights_direct(explicit_weights);
    let regen_size = literals.len();

    // Choose single stream or 4 streams based on regen_size
    if regen_size <= MAX_SINGLE_STREAM_SIZE {
        // Single stream (size_format=0)
        let huff_stream = encode_huffman_stream(literals, &codes);
        let compressed_size = weights_bytes.len() + huff_stream.len();

        if compressed_size >= regen_size {
            return false;
        }

        write_compressed_literals_header(output, 0, regen_size, compressed_size);
        output.extend_from_slice(&weights_bytes);
        output.extend_from_slice(&huff_stream);
        true
    } else {
        // 4 streams (size_format=2 for regen_size up to 16383)
        let segment_size = regen_size.div_ceil(4);
        let mut streams: [Vec<u8>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];

        for (i, stream) in streams.iter_mut().enumerate() {
            let start = i * segment_size;
            let end = ((i + 1) * segment_size).min(regen_size);
            if start < end {
                *stream = encode_huffman_stream(&literals[start..end], &codes);
            }
        }

        // Jump table: 3 x u16 LE (sizes of streams 0, 1, 2)
        let jump_table_size = 6;
        let streams_total: usize = streams.iter().map(|s| s.len()).sum();
        let compressed_size = weights_bytes.len() + jump_table_size + streams_total;

        if compressed_size >= regen_size {
            return false;
        }

        // Check stream sizes fit in u16
        if streams[0].len() > u16::MAX as usize
            || streams[1].len() > u16::MAX as usize
            || streams[2].len() > u16::MAX as usize
        {
            return false;
        }

        write_compressed_literals_header(output, 2, regen_size, compressed_size);
        output.extend_from_slice(&weights_bytes);

        // Jump table
        output.extend_from_slice(&(streams[0].len() as u16).to_le_bytes());
        output.extend_from_slice(&(streams[1].len() as u16).to_le_bytes());
        output.extend_from_slice(&(streams[2].len() as u16).to_le_bytes());

        // Stream data
        for stream in &streams {
            output.extend_from_slice(stream);
        }
        true
    }
}

/// Write the Compressed_Literals_Block header.
/// `size_format`: 0 = single stream (3B header), 1 = 4 streams (3B), 2 = 4 streams (4B), 3 = 4 streams (5B)
fn write_compressed_literals_header(
    output: &mut Vec<u8>,
    size_format: u8,
    regen_size: usize,
    compressed_size: usize,
) {
    let lit_type = 2u8; // Compressed_Literals_Block
    match size_format {
        0 | 1 => {
            // 3 bytes header
            let byte0 =
                ((regen_size & 0x0F) << 4) | ((size_format as usize) << 2) | lit_type as usize;
            let byte1 = ((compressed_size & 0x03) << 6) | ((regen_size >> 4) & 0x3F);
            let byte2 = (compressed_size >> 2) & 0xFF;
            output.push(byte0 as u8);
            output.push(byte1 as u8);
            output.push(byte2 as u8);
        }
        2 => {
            // 4 bytes header
            let byte0 =
                ((regen_size & 0x0F) << 4) | ((size_format as usize) << 2) | lit_type as usize;
            let byte1 = (regen_size >> 4) & 0xFF;
            let byte2 = ((compressed_size & 0x3F) << 2) | ((regen_size >> 12) & 0x03);
            let byte3 = (compressed_size >> 6) & 0xFF;
            output.push(byte0 as u8);
            output.push(byte1 as u8);
            output.push(byte2 as u8);
            output.push(byte3 as u8);
        }
        3 => {
            // 5 bytes header
            let byte0 =
                ((regen_size & 0x0F) << 4) | ((size_format as usize) << 2) | lit_type as usize;
            let byte1 = (regen_size >> 4) & 0xFF;
            let byte2 = ((compressed_size & 0x03) << 6) | ((regen_size >> 12) & 0x3F);
            let byte3 = (compressed_size >> 2) & 0xFF;
            let byte4 = (compressed_size >> 10) & 0xFF;
            output.push(byte0 as u8);
            output.push(byte1 as u8);
            output.push(byte2 as u8);
            output.push(byte3 as u8);
            output.push(byte4 as u8);
        }
        _ => unreachable!(),
    }
}

/// Serialize weights using direct representation (4-bit nibbles).
/// `weights` should NOT include the implicit last symbol.
fn serialize_weights_direct(weights: &[u8]) -> Vec<u8> {
    let num_symbols = weights.len();
    let header_byte = (num_symbols as u8) + 127;
    let bytes_needed = num_symbols.div_ceil(2);
    let mut result = Vec::with_capacity(1 + bytes_needed);
    result.push(header_byte);
    for i in (0..num_symbols).step_by(2) {
        let high = weights[i];
        let low = if i + 1 < num_symbols {
            weights[i + 1]
        } else {
            0
        };
        result.push((high << 4) | low);
    }
    result
}

/// Build Huffman code lengths from byte frequencies using two-queue merge.
/// Returns [code_length; 256] where 0 means unused symbol.
fn build_huffman_lengths(freq: &[u32; 256]) -> [u8; 256] {
    let mut symbols: Vec<(u32, u16)> = freq
        .iter()
        .enumerate()
        .filter(|(_, f)| **f > 0)
        .map(|(s, f)| (*f, s as u16))
        .collect();

    let n = symbols.len();
    let mut lengths = [0u8; 256];
    if n == 0 {
        return lengths;
    }
    if n == 1 {
        lengths[symbols[0].1 as usize] = 1;
        return lengths;
    }

    // Sort by frequency (ascending), then by symbol for stability
    symbols.sort();

    // Two-queue merge to build Huffman tree.
    // Each node is identified by an index: 0..n are leaves, n.. are internal.
    let mut parent = vec![0u16; 2 * n];

    let mut q1: VecDeque<(u32, u16)> = VecDeque::with_capacity(n);
    for (i, &(f, _)) in symbols.iter().enumerate() {
        q1.push_back((f, i as u16));
    }
    let mut q2: VecDeque<(u32, u16)> = VecDeque::new();

    let mut next_internal = n as u16;

    let pick_smallest =
        |q1: &mut VecDeque<(u32, u16)>, q2: &mut VecDeque<(u32, u16)>| -> (u32, u16) {
            match (q1.front(), q2.front()) {
                (Some(&a), Some(&b)) => {
                    if a.0 <= b.0 {
                        q1.pop_front().unwrap()
                    } else {
                        q2.pop_front().unwrap()
                    }
                }
                (Some(_), None) => q1.pop_front().unwrap(),
                (None, Some(_)) => q2.pop_front().unwrap(),
                (None, None) => unreachable!(),
            }
        };

    for _ in 0..n - 1 {
        let a = pick_smallest(&mut q1, &mut q2);
        let b = pick_smallest(&mut q1, &mut q2);
        parent[a.1 as usize] = next_internal;
        parent[b.1 as usize] = next_internal;
        q2.push_back((a.0 + b.0, next_internal));
        next_internal += 1;
    }

    // Root is the last created internal node
    let root = (next_internal - 1) as usize;
    parent[root] = root as u16; // self-parent for root

    // Compute depths by following parent chains from each leaf
    for (leaf_idx, &(_, sym)) in symbols.iter().enumerate() {
        let mut depth = 0u8;
        let mut node = leaf_idx;
        while node != root {
            node = parent[node] as usize;
            depth += 1;
        }
        lengths[sym as usize] = depth;
    }

    // Cap at 11 bits (zstd max). If exceeded, flatten.
    let max_depth = *lengths.iter().max().unwrap_or(&0);
    if max_depth > 11 {
        length_limit_huffman(&mut lengths, freq, 11);
    }

    lengths
}

/// Limit Huffman code lengths to `max_bits` by redistributing.
/// Simple heuristic: repeatedly reduce longest codes until all fit.
fn length_limit_huffman(lengths: &mut [u8; 256], _freq: &[u32; 256], max_bits: u8) {
    loop {
        let over = lengths.iter().filter(|&&l| l > max_bits).count();
        if over == 0 {
            break;
        }
        // Cap all to max_bits
        for l in lengths.iter_mut() {
            if *l > max_bits {
                *l = max_bits;
            }
        }
        // Now Kraft sum may exceed 1. Reduce shortest codes to compensate.
        // Find shortest non-zero code length and increment it.
        let mut min_len = max_bits;
        for &l in lengths.iter() {
            if l > 0 && l < min_len {
                min_len = l;
            }
        }
        // Increment the first symbol at min_len
        for l in lengths.iter_mut() {
            if *l == min_len {
                *l += 1;
                break;
            }
        }
        // Check Kraft inequality: sum(2^(max_bits - l)) for l > 0 should be <= 2^max_bits
        let kraft_sum: u32 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1u32 << (max_bits - l))
            .sum();
        if kraft_sum <= (1u32 << max_bits) {
            break;
        }
    }
}

/// Build canonical Huffman codes from code lengths.
/// Returns [(code, length); 256].
fn build_canonical_codes(code_lengths: &[u8; 256], max_cl: u8) -> [(u32, u8); 256] {
    let mut bl_count = [0u32; 12]; // indices 0..=11
    for &cl in code_lengths.iter() {
        if cl > 0 {
            bl_count[cl as usize] += 1;
        }
    }

    let mut next_code = [0u32; 12];
    let mut code = 0u32;
    for bits in 1..=max_cl as usize {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
    }

    let mut codes = [(0u32, 0u8); 256];
    for (sym, &cl) in code_lengths.iter().enumerate() {
        if cl > 0 {
            codes[sym] = (next_code[cl as usize], cl);
            next_code[cl as usize] += 1;
        }
    }
    codes
}

/// Encode literals into a Huffman bitstream (single stream, reverse format).
fn encode_huffman_stream(literals: &[u8], codes: &[(u32, u8); 256]) -> Vec<u8> {
    let mut writer = MsbBitWriter::new();
    for &byte in literals {
        let (code, len) = codes[byte as usize];
        writer.write(code, len);
    }
    writer.finish()
}

/// Build block content using predefined FSE tables.
fn build_predefined_block(literals: &[u8], sequences: &[EncSequence]) -> Vec<u8> {
    let mut block = Vec::new();

    // Literals section — try Huffman first, fall back to Raw
    if !try_write_huffman_literals_section(literals, &mut block) {
        write_raw_literals_section(literals, &mut block);
    }

    // Sequences header
    write_sequences_header(sequences.len(), &mut block);

    // Compression modes byte: all Predefined (mode=0)
    block.push(0x00);

    // FSE bitstream
    let ll_table = default_literal_length_table();
    let of_table = default_offset_table();
    let ml_table = default_match_length_table();
    let bitstream = encode_fse_bitstream(sequences, &ll_table, &of_table, &ml_table);
    block.extend_from_slice(&bitstream);

    block
}

// ============================================================
// Custom FSE table encoding
// ============================================================

/// LSB-first bit writer for FSE table serialization.
#[cfg(test)]
struct LsbBitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bits_in_current: u8,
}

#[cfg(test)]
impl LsbBitWriter {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current_byte: 0,
            bits_in_current: 0,
        }
    }

    fn write(&mut self, value: u32, n: u8) {
        let mut val = value;
        let mut remaining = n;
        while remaining > 0 {
            let space = 8 - self.bits_in_current;
            let to_write = remaining.min(space);
            self.current_byte |= ((val & ((1u32 << to_write) - 1)) as u8) << self.bits_in_current;
            self.bits_in_current += to_write;
            val >>= to_write;
            remaining -= to_write;
            if self.bits_in_current == 8 {
                self.bytes.push(self.current_byte);
                self.current_byte = 0;
                self.bits_in_current = 0;
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_in_current > 0 {
            self.bytes.push(self.current_byte);
        }
        self.bytes
    }
}

/// Normalize raw frequency counts to sum to `2^accuracy_log`.
/// Returns normalized probabilities (i16), where -1 means "less than 1".
#[cfg(test)]
fn normalize_counts(freqs: &[u32], accuracy_log: u8) -> Vec<i16> {
    let table_size = 1u32 << accuracy_log;
    let total: u32 = freqs.iter().sum();
    if total == 0 {
        return vec![0i16; freqs.len()];
    }

    let mut probs = vec![0i16; freqs.len()];
    let mut distributed = 0i32;

    // First pass: assign proportional counts, minimum 1 for non-zero symbols
    for (i, &freq) in freqs.iter().enumerate() {
        if freq == 0 {
            continue;
        }
        let prob = ((freq as u64 * table_size as u64) / total as u64) as i16;
        if prob == 0 {
            // Symbol present but very rare → assign -1
            probs[i] = -1;
            distributed += 1;
        } else {
            probs[i] = prob;
            distributed += prob as i32;
        }
    }

    // Adjust to make distributed == table_size
    let diff = table_size as i32 - distributed;
    if diff != 0 {
        // Find the symbol with the largest frequency and adjust
        let mut max_idx = 0;
        let mut max_prob = 0i16;
        for (i, &p) in probs.iter().enumerate() {
            if p > max_prob {
                max_prob = p;
                max_idx = i;
            }
        }
        if max_prob > 0 {
            let new_val = (max_prob as i32 + diff).max(1);
            probs[max_idx] = new_val as i16;
        }
    }

    probs
}

/// Serialize normalized probabilities into the FSE bitstream format.
/// This is the inverse of `FseTable::from_bitstream`.
#[cfg(test)]
fn serialize_fse_table(probs: &[i16], accuracy_log: u8) -> Vec<u8> {
    let mut writer = LsbBitWriter::new();

    // Write accuracy log (4 bits): stored as accuracy_log - 5
    writer.write((accuracy_log - 5) as u32, 4);

    let table_size = 1i32 << accuracy_log;
    let mut remaining = table_size + 1;

    let mut i = 0;
    while i < probs.len() && remaining > 1 {
        let prob = probs[i];
        let val = (prob + 1) as u32; // prob = val - 1

        // RFC 8878 §4.1.1: max = floor(log2(remaining)) + 1
        let max_bits_needed = highest_bit_enc(remaining as u32) + 1;
        let threshold = 1u32 << (max_bits_needed - 1);
        let max = ((2 * threshold as i32) - 1 - remaining) as u32;

        if val < max {
            writer.write(val, max_bits_needed as u8 - 1);
        } else {
            let encoded = if val < threshold { val } else { val + max };
            writer.write(encoded, max_bits_needed as u8);
        }

        remaining -= if prob < 0 { -prob as i32 } else { prob as i32 };
        i += 1;

        // Handle repeat-zero coding (decoder always reads at least one 2-bit group)
        if prob == 0 {
            let mut zero_run = 0usize;
            while i + zero_run < probs.len() && probs[i + zero_run] == 0 {
                zero_run += 1;
            }
            // Encode the run using 2-bit groups.
            // Each group: 0-2 means that many zeros then stop, 3 means 3 zeros and continue.
            let mut written = 0;
            loop {
                let remaining_zeros = zero_run - written;
                if remaining_zeros >= 3 {
                    writer.write(3, 2);
                    written += 3;
                } else {
                    writer.write(remaining_zeros as u32, 2);
                    break;
                }
            }
            i += zero_run;
        }
    }

    writer.finish()
}

/// highest_bit for encoding (same as fse.rs highest_bit but local)
#[cfg(test)]
const fn highest_bit_enc(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    31 - val.leading_zeros()
}

/// Count symbol frequencies for LL, OF, ML codes from sequences.
#[cfg(test)]
fn count_sequence_symbols(sequences: &[EncSequence]) -> ([u32; 36], [u32; 32], [u32; 53]) {
    let mut ll_freq = [0u32; 36];
    let mut of_freq = [0u32; 32];
    let mut ml_freq = [0u32; 53];

    for seq in sequences {
        let (llc, _, _) = encode_ll_code(seq.literal_length);
        let (ofc, _, _) = encode_of_code(seq.offset_raw);
        let (mlc, _, _) = encode_ml_code(seq.match_length);
        ll_freq[llc as usize] += 1;
        of_freq[ofc as usize] += 1;
        ml_freq[mlc as usize] += 1;
    }

    (ll_freq, of_freq, ml_freq)
}

/// Try to build a compressed block using custom FSE tables.
/// Returns the block bytes, or None if predefined tables are better.
#[cfg(test)]
fn try_build_with_custom_fse(
    literals: &[u8],
    sequences: &[EncSequence],
    predefined_block_size: usize,
) -> Option<Vec<u8>> {
    if sequences.len() < 16 {
        // Too few sequences for custom tables to be worthwhile
        return None;
    }

    let (ll_freq, of_freq, ml_freq) = count_sequence_symbols(sequences);

    // Normalize and build custom tables
    let ll_al = 6u8;
    let of_al = 5u8;
    let ml_al = 6u8;

    let ll_probs = normalize_counts(&ll_freq, ll_al);
    let of_probs = normalize_counts(&of_freq, of_al);
    let ml_probs = normalize_counts(&ml_freq, ml_al);

    // Try building tables — if normalization is bad, bail out
    let ll_table = FseTable::from_probabilities(&ll_probs, ll_al).ok()?;
    let of_table = FseTable::from_probabilities(&of_probs, of_al).ok()?;
    let ml_table = FseTable::from_probabilities(&ml_probs, ml_al).ok()?;

    // Serialize the table descriptions
    let ll_desc = serialize_fse_table(&ll_probs, ll_al);
    let of_desc = serialize_fse_table(&of_probs, of_al);
    let ml_desc = serialize_fse_table(&ml_probs, ml_al);

    // Build block with custom tables
    let mut block = Vec::new();

    // Literals section
    if !try_write_huffman_literals_section(literals, &mut block) {
        write_raw_literals_section(literals, &mut block);
    }

    // Sequences header
    write_sequences_header(sequences.len(), &mut block);

    // Compression modes byte: all Compressed_Mode (mode=2)
    // Byte layout: (LL_mode << 6) | (OF_mode << 4) | (ML_mode << 2)
    // mode=2 for all three = (2 << 6) | (2 << 4) | (2 << 2) = 0b10_10_10_00 = 0xA8
    block.push(0xA8);

    // FSE table descriptions (LL, OF, ML order per spec)
    block.extend_from_slice(&ll_desc);
    block.extend_from_slice(&of_desc);
    block.extend_from_slice(&ml_desc);

    // FSE bitstream
    let bitstream = encode_fse_bitstream(sequences, &ll_table, &of_table, &ml_table);
    block.extend_from_slice(&bitstream);

    // Only use custom tables if they produce a smaller block
    if block.len() < predefined_block_size {
        Some(block)
    } else {
        None
    }
}

/// Write the sequences section header (number of sequences).
fn write_sequences_header(n: usize, output: &mut Vec<u8>) {
    if n < 128 {
        output.push(n as u8);
    } else if n < 0x7F00 {
        output.push(((n >> 8) as u8) + 128);
        output.push((n & 0xFF) as u8);
    } else {
        output.push(255);
        let adj = n - 0x7F00;
        output.push((adj & 0xFF) as u8);
        output.push(((adj >> 8) & 0xFF) as u8);
    }
}

// ============================================================
// FSE bitstream encoding
// ============================================================

/// Encoding table entry: for a given symbol, which decode-table states
/// correspond to it, and what are their baseline/num_bits.
struct FseEncEntry {
    state_index: usize,
    baseline: u16,
    num_bits: u8,
}

/// Build a symbol → entries mapping from a decode table.
fn build_encode_table(table: &FseTable) -> Vec<Vec<FseEncEntry>> {
    let max_sym = table.entries.iter().map(|e| e.symbol).max().unwrap_or(0) as usize;
    let mut enc: Vec<Vec<FseEncEntry>> = (0..=max_sym).map(|_| Vec::new()).collect();
    for (i, entry) in table.entries.iter().enumerate() {
        enc[entry.symbol as usize].push(FseEncEntry {
            state_index: i,
            baseline: entry.baseline,
            num_bits: entry.num_bits,
        });
    }
    enc
}

/// Find a state for `sym` whose decode entry can transition to `target_state`.
/// Returns (state_index, bits_to_output, num_bits).
fn find_encode_state(
    enc: &[Vec<FseEncEntry>],
    sym: u8,
    target_state: usize,
) -> Option<(usize, u32, u8)> {
    if (sym as usize) >= enc.len() {
        return None;
    }
    for entry in &enc[sym as usize] {
        let base = entry.baseline as usize;
        let range = 1usize << entry.num_bits;
        if target_state >= base && target_state < base + range {
            return Some((
                entry.state_index,
                (target_state - base) as u32,
                entry.num_bits,
            ));
        }
    }
    None
}

/// Find any valid state for the given symbol (used for the last sequence).
fn find_any_state(enc: &[Vec<FseEncEntry>], sym: u8) -> usize {
    enc[sym as usize][0].state_index
}

/// Encode LL/OF/ML code from a value.
fn encode_ll_code(val: u32) -> (u8, u32, u8) {
    for i in (0..LL_BASE.len()).rev() {
        if val >= LL_BASE[i] {
            return (i as u8, val - LL_BASE[i], LL_EXTRA[i]);
        }
    }
    (0, val, 0)
}

fn encode_ml_code(val: u32) -> (u8, u32, u8) {
    for i in (0..ML_BASE.len()).rev() {
        if val >= ML_BASE[i] {
            return (i as u8, val - ML_BASE[i], ML_EXTRA[i]);
        }
    }
    (0, val - 3, 0)
}

const fn encode_of_code(offset_raw: u32) -> (u8, u32, u8) {
    if offset_raw == 0 {
        return (0, 0, 0);
    }
    let code = 31 - offset_raw.leading_zeros();
    let extra = offset_raw - (1 << code);
    (code as u8, extra, code as u8)
}

/// Encode sequences into the FSE reverse bitstream.
fn encode_fse_bitstream(
    sequences: &[EncSequence],
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
) -> Vec<u8> {
    let ll_enc = build_encode_table(ll_table);
    let of_enc = build_encode_table(of_table);
    let ml_enc = build_encode_table(ml_table);

    let n = sequences.len();
    if n == 0 {
        return Vec::new();
    }

    // Compute codes and extra bits for each sequence
    let mut ll_codes = Vec::with_capacity(n);
    let mut of_codes = Vec::with_capacity(n);
    let mut ml_codes = Vec::with_capacity(n);
    let mut ll_extras = Vec::with_capacity(n);
    let mut of_extras = Vec::with_capacity(n);
    let mut ml_extras = Vec::with_capacity(n);

    for seq in sequences {
        let (llc, lle, lleb) = encode_ll_code(seq.literal_length);
        let (ofc, ofe, ofeb) = encode_of_code(seq.offset_raw);
        let (mlc, mle, mleb) = encode_ml_code(seq.match_length);
        ll_codes.push(llc);
        of_codes.push(ofc);
        ml_codes.push(mlc);
        ll_extras.push((lle, lleb));
        of_extras.push((ofe, ofeb));
        ml_extras.push((mle, mleb));
    }

    // Build a spec-compatible reverse bitstream using the same logical order as
    // upstream zstd's BIT_CStream/FSE encoder.
    let mut writer = BitCstreamWriter::new();

    // Initialize current states from the last sequence.
    let mut ll_state = find_any_state(&ll_enc, ll_codes[n - 1]);
    let mut of_state = find_any_state(&of_enc, of_codes[n - 1]);
    let mut ml_state = find_any_state(&ml_enc, ml_codes[n - 1]);

    // Extra bits for the last sequence are pushed before any prior FSE symbols.
    let (ll_ev, ll_eb) = ll_extras[n - 1];
    writer.write(ll_ev, ll_eb);
    let (ml_ev, ml_eb) = ml_extras[n - 1];
    writer.write(ml_ev, ml_eb);
    let (of_ev, of_eb) = of_extras[n - 1];
    writer.write(of_ev, of_eb);

    for i in (0..n - 1).rev() {
        let (next_of_state, of_bits, of_nb) = find_encode_state(&of_enc, of_codes[i], of_state)
            .unwrap_or_else(|| {
                let state = find_any_state(&of_enc, of_codes[i]);
                (state, 0, 0)
            });
        let (next_ml_state, ml_bits, ml_nb) = find_encode_state(&ml_enc, ml_codes[i], ml_state)
            .unwrap_or_else(|| {
                let state = find_any_state(&ml_enc, ml_codes[i]);
                (state, 0, 0)
            });
        let (next_ll_state, ll_bits, ll_nb) = find_encode_state(&ll_enc, ll_codes[i], ll_state)
            .unwrap_or_else(|| {
                let state = find_any_state(&ll_enc, ll_codes[i]);
                (state, 0, 0)
            });

        // Encode symbols first (reverse direction), then append the extra bits.
        writer.write(of_bits, of_nb);
        writer.write(ml_bits, ml_nb);
        writer.write(ll_bits, ll_nb);

        let (ll_ev, ll_eb) = ll_extras[i];
        writer.write(ll_ev, ll_eb);
        let (ml_ev, ml_eb) = ml_extras[i];
        writer.write(ml_ev, ml_eb);
        let (of_ev, of_eb) = of_extras[i];
        writer.write(of_ev, of_eb);

        of_state = next_of_state;
        ml_state = next_ml_state;
        ll_state = next_ll_state;
    }

    // Flush final states. Decoder reads them back in reverse flush order:
    // LL, OF, ML.
    writer.write(ml_state as u32, ml_table.accuracy_log);
    writer.write(of_state as u32, of_table.accuracy_log);
    writer.write(ll_state as u32, ll_table.accuracy_log);

    writer.finish()
}

/// Reverse bitstream writer compatible with zstd's BIT_CStream.
struct BitCstreamWriter {
    bytes: Vec<u8>,
    bit_container: u64,
    bit_pos: u8,
}

impl BitCstreamWriter {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            bit_container: 0,
            bit_pos: 0,
        }
    }

    /// Write the lower `n` bits of `value` in the same order as BIT_addBits().
    fn write(&mut self, value: u32, n: u8) {
        if n == 0 {
            return;
        }
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        while self.bit_pos as u16 + n as u16 >= 64 {
            self.flush_full_bytes();
        }
        self.bit_container |= ((value & mask) as u64) << self.bit_pos;
        self.bit_pos += n;
    }

    fn flush_full_bytes(&mut self) {
        let nb_bytes = self.bit_pos / 8;
        for _ in 0..nb_bytes {
            self.bytes.push(self.bit_container as u8);
            self.bit_container >>= 8;
        }
        self.bit_pos &= 7;
    }

    fn finish(mut self) -> Vec<u8> {
        // endMark
        self.write(1, 1);
        self.flush_full_bytes();
        if self.bit_pos > 0 {
            self.bytes.push(self.bit_container as u8);
        }
        self.bytes
    }
}

/// Legacy MSB-first reverse writer used by the Huffman literals path.
struct MsbBitWriter {
    bits: Vec<bool>,
}

impl MsbBitWriter {
    const fn new() -> Self {
        Self { bits: Vec::new() }
    }

    fn write(&mut self, value: u32, n: u8) {
        for i in (0..n).rev() {
            self.bits.push((value >> i) & 1 != 0);
        }
    }

    fn finish(self) -> Vec<u8> {
        if self.bits.is_empty() {
            return vec![0x01];
        }

        let total_bits = 1 + self.bits.len();
        let padded = (total_bits + 7) & !7;
        let mut all_bits = Vec::with_capacity(padded);
        all_bits.push(true);
        all_bits.extend_from_slice(&self.bits);
        all_bits.resize(padded, false);

        let mut bytes = Vec::with_capacity(all_bits.len() / 8);
        for chunk in all_bits.chunks(8) {
            let mut byte = 0u8;
            for (j, &bit) in chunk.iter().enumerate() {
                if bit {
                    byte |= 1 << (7 - j);
                }
            }
            bytes.push(byte);
        }

        bytes.reverse();
        bytes
    }
}

// ============================================================
// LZ77 compression
// ============================================================

/// Run LZ77 on input, returning (literals, sequences).
///
/// `history` is the decoder-visible byte prefix the block may match
/// against (dictionary content for the first block of a dict frame,
/// otherwise the preceding frame bytes within the window).
fn lz77_compress_with_dict(input: &[u8], history: &[u8]) -> (Vec<u8>, Vec<EncSequence>) {
    let mut literals = Vec::new();
    let mut sequences = Vec::new();
    let mut pos = 0;
    let mut literal_start = 0;

    // Build a virtual buffer: [history | input]
    // All positions in hash chains are in this virtual space.
    let history_len = history.len();
    let virt_len = history_len + input.len();

    let mut head = vec![0u32; HASH_SIZE];
    let mut prev = vec![0u32; WINDOW_SIZE];

    // Helper to read a byte from virtual buffer
    let virt_byte = |vpos: usize| -> u8 {
        if vpos < history_len {
            history[vpos]
        } else {
            input[vpos - history_len]
        }
    };

    // Pre-populate hash chains with the history tail reachable through
    // the window.
    let history_start = history_len.saturating_sub(WINDOW_SIZE);
    for hp in history_start..history_len {
        if hp + 3 <= virt_len {
            let h = hash3_virt(virt_byte(hp), virt_byte(hp + 1), virt_byte(hp + 2));
            prev[hp % WINDOW_SIZE] = head[h] as u32;
            head[h] = hp as u32;
        }
    }

    // Now compress input, using virtual positions (input pos = history_len + pos)
    while pos < input.len() {
        if pos + MIN_MATCH_LEN > input.len() {
            pos += 1;
            continue;
        }

        let vpos = history_len + pos;
        let hash = hash3(&input[pos..pos + 3]);
        let mut best_len = MIN_MATCH_LEN - 1;
        let mut best_dist = 0usize;

        let mut chain_pos = head[hash] as usize;
        let min_vpos = vpos.saturating_sub(WINDOW_SIZE);
        let mut chain_count = 0;

        while chain_pos >= min_vpos && chain_pos < vpos && chain_count < MAX_CHAIN_LEN {
            let dist = vpos - chain_pos;
            if dist > 0 && dist <= WINDOW_SIZE {
                // Count match between chain_pos and vpos in virtual buffer
                let max_len = MAX_MATCH_LEN.min(input.len() - pos);
                let mut match_len = 0;
                while match_len < max_len
                    && virt_byte(chain_pos + match_len) == input[pos + match_len]
                {
                    match_len += 1;
                }
                if match_len > best_len {
                    best_len = match_len;
                    best_dist = dist;
                    if best_len >= 128 {
                        break;
                    }
                }
            }
            let p = prev[chain_pos % WINDOW_SIZE] as usize;
            if p >= chain_pos {
                break;
            }
            chain_pos = p;
            chain_count += 1;
        }

        prev[vpos % WINDOW_SIZE] = head[hash] as u32;
        head[hash] = vpos as u32;

        if best_len >= MIN_MATCH_LEN {
            let lit_len = pos - literal_start;
            literals.extend_from_slice(&input[literal_start..pos]);
            // offset_raw = real_offset + 3 (to avoid repeat offset codes 1/2/3)
            let offset_raw = best_dist as u32 + 3;
            sequences.push(EncSequence {
                literal_length: lit_len as u32,
                offset_raw,
                match_length: best_len as u32,
            });

            for i in 1..best_len {
                let p = pos + i;
                if p + 3 <= input.len() {
                    let vp = history_len + p;
                    let h = hash3(&input[p..p + 3]);
                    prev[vp % WINDOW_SIZE] = head[h] as u32;
                    head[h] = vp as u32;
                }
            }

            pos += best_len;
            literal_start = pos;
        } else {
            pos += 1;
        }
    }

    // Trailing literals
    if literal_start < input.len() {
        literals.extend_from_slice(&input[literal_start..]);
    }

    (literals, sequences)
}

const fn hash3_virt(b0: u8, b1: u8, b2: u8) -> usize {
    let h = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16);
    (h.wrapping_mul(2654435769) >> (32 - HASH_BITS)) as usize
}

fn hash3(data: &[u8]) -> usize {
    let h = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
    (h.wrapping_mul(2654435769) >> (32 - HASH_BITS)) as usize
}

// ============================================================
// Frame structure helpers
// ============================================================

/// Write a 3-byte block header.
fn write_block_header(output: &mut Vec<u8>, last: bool, block_type: u8, block_size: u32) {
    let val = (block_size << 3) | ((block_type as u32) << 1) | (last as u32);
    output.push(val as u8);
    output.push((val >> 8) as u8);
    output.push((val >> 16) as u8);
}

const fn fcs_flag_for_size(size: u64) -> u8 {
    if size <= 255 {
        0
    } else if size <= 65791 {
        1
    } else if size <= u32::MAX as u64 {
        2
    } else {
        3
    }
}

fn write_fcs(size: u64, fcs_flag: u8, output: &mut Vec<u8>) {
    match fcs_flag {
        0 => output.push(size as u8),
        1 => {
            let val = (size - 256) as u16;
            output.extend_from_slice(&val.to_le_bytes());
        }
        2 => output.extend_from_slice(&(size as u32).to_le_bytes()),
        3 => output.extend_from_slice(&size.to_le_bytes()),
        _ => unreachable!(),
    }
}

/// Encode data as a zstd frame and write to a [`std::io::Write`] sink.
///
/// Returns the number of bytes written.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::encode::encode_writer;
///
/// let mut buf = Vec::new();
/// let len = encode_writer(b"Hello!", &mut buf).unwrap();
/// assert!(len > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(input: &[u8], mut writer: W) -> std::io::Result<usize> {
    let encoded = encode(input);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    extern crate alloc;
    use crate::compress::zstd::decode;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_roundtrip_empty() {
        let encoded = encode(b"");
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_roundtrip_small() {
        let input = b"Hello, zstd!";
        let encoded = encode(input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_roundtrip_rle() {
        let input = vec![0xAA; 1000];
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert!(encoded.len() < 50, "RLE encoded size: {}", encoded.len());
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let input = b"X";
        let encoded = encode(input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_roundtrip_large() {
        let input: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fcs_sizes() {
        assert_eq!(fcs_flag_for_size(0), 0);
        assert_eq!(fcs_flag_for_size(255), 0);
        assert_eq!(fcs_flag_for_size(256), 1);
        assert_eq!(fcs_flag_for_size(65791), 1);
        assert_eq!(fcs_flag_for_size(65792), 2);
        assert_eq!(fcs_flag_for_size(u32::MAX as u64), 2);
        assert_eq!(fcs_flag_for_size(u32::MAX as u64 + 1), 3);
    }

    #[test]
    fn test_frame_structure() {
        let input = b"test";
        let encoded = encode(input);
        assert_eq!(&encoded[0..4], &ZSTD_MAGIC.to_le_bytes());
        let desc = encoded[4];
        assert_eq!((desc >> 6) & 0x03, 0); // FCS_Flag=0
        assert!(desc & (1 << 5) != 0); // single_segment
        assert!(desc & (1 << 2) != 0); // content_checksum
        assert_eq!(encoded[5], 4); // FCS = 4
    }

    #[test]
    fn test_checksum_present() {
        let input = b"Hello";
        let encoded = encode(input);
        let hash = xxhash::xxhash64(input, 0);
        let expected_checksum = (hash & 0xFFFFFFFF) as u32;
        let len = encoded.len();
        let stored_checksum = u32::from_le_bytes([
            encoded[len - 4],
            encoded[len - 3],
            encoded[len - 2],
            encoded[len - 1],
        ]);
        assert_eq!(stored_checksum, expected_checksum);
    }

    #[test]
    fn test_roundtrip_fcs_2byte() {
        let input = vec![0x42; 300];
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_fcs_4byte() {
        let input: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_writer() {
        let input = b"Hello, zstd writer!";
        let mut output = Vec::new();
        let len = encode_writer(input, &mut output).unwrap();
        assert_eq!(len, output.len());
        let decoded = decode::decode(&output).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_roundtrip_repetitive() {
        // Highly repetitive data should round-trip regardless of whether the
        // encoder chooses a compressed or raw block.
        let input = "abcabc".repeat(200);
        let encoded = encode(input.as_bytes());
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
    }

    #[test]
    fn test_roundtrip_prose() {
        let input = b"The quick brown fox jumps over the lazy dog. \
                       The quick brown fox jumps over the lazy dog. \
                       The quick brown fox jumps over the lazy dog.";
        let encoded = encode(input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_roundtrip_binary() {
        // Random-ish binary data — may not compress well but must round-trip
        let input: Vec<u8> = (0..1000).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_public_encoder_frame_roundtrip() {
        // Repetitive data should remain interoperable while the public encoder
        // is free to choose the smallest supported block representation.
        let input = "hello world! ".repeat(100);
        let encoded = encode(input.as_bytes());
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
        assert!(encoded.starts_with(&super::ZSTD_MAGIC.to_le_bytes()));
    }

    #[test]
    fn test_public_encoder_emits_compressed_block_for_compressible_input() {
        use crate::compress::zstd::frame::{BlockHeader, BlockType, FrameHeader};

        let input = "abcdefghij".repeat(100);
        let encoded = encode(input.as_bytes());
        let frame = FrameHeader::parse(&encoded).unwrap();
        let block = BlockHeader::parse(&encoded[frame.header_size..]).unwrap();

        assert_eq!(block.block_type, BlockType::Compressed);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
    }

    #[test]
    fn test_huffman_literals_roundtrip() {
        // Data with many distinct byte values but skewed distribution must
        // still round-trip when the public encoder evaluates its compressed path.
        let mut input = Vec::new();
        for _ in 0..100 {
            input.extend_from_slice(b"aaabbbcccddeef");
        }
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_huffman_build_lengths() {
        let mut freq = [0u32; 256];
        freq[b'a' as usize] = 100;
        freq[b'b' as usize] = 50;
        freq[b'c' as usize] = 25;
        freq[b'd' as usize] = 10;
        let lengths = build_huffman_lengths(&freq);
        // 'a' should have shortest code, 'd' should have longest
        assert!(lengths[b'a' as usize] > 0);
        assert!(lengths[b'd' as usize] > 0);
        assert!(lengths[b'a' as usize] <= lengths[b'd' as usize]);
        // Unused symbols should have length 0
        assert_eq!(lengths[b'z' as usize], 0);
    }

    #[test]
    fn test_huffman_canonical_codes() {
        let mut lengths = [0u8; 256];
        lengths[0] = 1;
        lengths[1] = 2;
        lengths[2] = 2;
        let codes = build_canonical_codes(&lengths, 2);
        // Code length 1: one code (0b0)
        assert_eq!(codes[0], (0b0, 1));
        // Code length 2: two codes (0b10, 0b11)
        assert_eq!(codes[1], (0b10, 2));
        assert_eq!(codes[2], (0b11, 2));
    }

    #[test]
    fn test_huffman_stream_encode_decode() {
        // Test the Huffman stream encoding directly
        let mut freq = [0u32; 256];
        freq[b'a' as usize] = 50;
        freq[b'b' as usize] = 30;
        freq[b'c' as usize] = 20;
        let lengths = build_huffman_lengths(&freq);
        let max_cl = *lengths.iter().max().unwrap();
        let codes = build_canonical_codes(&lengths, max_cl);

        let input = b"aababcaabcaab";
        let stream = encode_huffman_stream(input, &codes);
        // The stream should be non-empty and smaller than input
        assert!(!stream.is_empty());
        assert!(stream.len() <= input.len());
    }

    #[test]
    fn test_roundtrip_english_text() {
        // English text has skewed byte frequency — good Huffman candidate
        let input = b"The quick brown fox jumps over the lazy dog. \
                       She sells seashells by the seashore. \
                       Peter Piper picked a peck of pickled peppers. \
                       How much wood would a woodchuck chuck if a woodchuck could chuck wood?";
        let encoded = encode(input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_custom_fse_roundtrip() {
        // Large enough to trigger custom FSE tables (needs > 16 sequences)
        // Repetitive pattern that compresses well with LZ77
        let input = "abcdefghij".repeat(100);
        let encoded = encode(input.as_bytes());
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
    }

    #[test]
    fn test_custom_fse_with_huffman_roundtrip() {
        // Test that custom FSE + Huffman literals works together
        // Needs: > 16 sequences + Huffman-friendly literals + custom FSE smaller than predefined
        let mut input = Vec::new();
        // Build data with many distinct bytes and repetitive structure
        for _ in 0..50 {
            input.extend_from_slice(b"The quick brown fox jumps over the lazy dog. ");
        }
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fse_table_serialize_roundtrip() {
        // Test with the predefined LL table probabilities
        let probs: Vec<i16> = vec![
            4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1,
            1, 1, 1, -1, -1, -1, -1,
        ];
        let al = 6u8;
        let serialized = serialize_fse_table(&probs, al);

        // Deserialize using from_bitstream
        use crate::compress::zstd::fse::FseTable;
        let (table, _consumed) = FseTable::from_bitstream(&serialized, 35, 9).unwrap();
        assert_eq!(table.accuracy_log, al);

        // Verify symbol distribution matches
        let mut counts = [0u32; 36];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }
        for (sym, &prob) in probs.iter().enumerate() {
            let expected = if prob == -1 { 1 } else { prob as u32 };
            assert_eq!(
                counts[sym], expected,
                "symbol {} count: expected {}, got {}",
                sym, expected, counts[sym]
            );
        }
    }

    #[test]
    fn test_normalize_counts_basic() {
        let mut freqs = [0u32; 8];
        freqs[0] = 100;
        freqs[1] = 50;
        freqs[2] = 25;
        freqs[3] = 10;
        let probs = normalize_counts(&freqs, 6);
        let non_zero_sum: i32 = probs
            .iter()
            .filter(|&&p| p != 0)
            .map(|&p| if p < 0 { 1 } else { p as i32 })
            .sum();
        assert_eq!(non_zero_sum, 64, "probs: {:?}", probs);
    }

    #[test]
    fn test_normalize_counts_mixed_probabilities_serialize_roundtrip() {
        let mut freqs = [0u32; 8];
        freqs[0] = 1000;
        freqs[1] = 1;
        freqs[2] = 1;
        let probs = normalize_counts(&freqs, 6);

        assert!(
            probs.iter().any(|&p| p > 0),
            "expected positive probability: {probs:?}"
        );
        assert!(
            probs.contains(&-1),
            "expected low-probability marker: {probs:?}"
        );
        assert!(
            probs.contains(&0),
            "expected zero-probability symbol: {probs:?}"
        );

        let serialized = serialize_fse_table(&probs, 6);
        let (table, _) = FseTable::from_bitstream(&serialized, 7, 9).unwrap();

        let mut counts = [0u32; 8];
        for entry in &table.entries {
            counts[entry.symbol as usize] += 1;
        }

        for (sym, &prob) in probs.iter().enumerate() {
            let expected = if prob < 0 { 1 } else { prob as u32 };
            assert_eq!(counts[sym], expected, "symbol {sym} mismatch");
        }
    }

    #[test]
    fn test_compressed_literals_header_size_formats_roundtrip() {
        let cases = [
            (0u8, 0x123usize, 0x155usize),
            (1u8, 0x234usize, 0x166usize),
            (2u8, 0x1234usize, 0x2345usize),
            (3u8, 0x12345usize, 0x3456usize),
        ];

        for (size_format, regen_size, compressed_size) in cases {
            let mut header = Vec::new();
            write_compressed_literals_header(&mut header, size_format, regen_size, compressed_size);

            let (parsed_regen, parsed_comp) = match size_format {
                0 | 1 => (
                    ((header[0] as usize) >> 4) | (((header[1] as usize) & 0x3F) << 4),
                    ((header[1] as usize) >> 6) | ((header[2] as usize) << 2),
                ),
                2 => (
                    ((header[0] as usize) >> 4)
                        | ((header[1] as usize) << 4)
                        | (((header[2] as usize) & 0x03) << 12),
                    ((header[2] as usize) >> 2) | ((header[3] as usize) << 6),
                ),
                3 => (
                    ((header[0] as usize) >> 4)
                        | ((header[1] as usize) << 4)
                        | (((header[2] as usize) & 0x3F) << 12),
                    ((header[2] as usize) >> 6)
                        | ((header[3] as usize) << 2)
                        | ((header[4] as usize) << 10),
                ),
                _ => unreachable!(),
            };

            assert_eq!(
                parsed_regen, regen_size,
                "regen mismatch for format {size_format}"
            );
            assert_eq!(
                parsed_comp, compressed_size,
                "compressed mismatch for format {size_format}"
            );
        }
    }

    #[test]
    fn test_custom_fse_serialize_deserialize() {
        // Simulate what happens with English text - concentrated OF codes
        let of_freq: [u32; 32] = {
            let mut f = [0u32; 32];
            f[3] = 10; // offset code 3
            f[4] = 8;
            f[5] = 5;
            f[6] = 3;
            f[7] = 2;
            f[8] = 1;
            f
        };
        let of_al = 5u8;
        let of_probs = normalize_counts(&of_freq, of_al);

        // Verify table builds
        let table = FseTable::from_probabilities(&of_probs, of_al);
        assert!(table.is_ok(), "table build failed: {:?}", table.err());

        // Verify serialization roundtrip
        let serialized = serialize_fse_table(&of_probs, of_al);
        let result = FseTable::from_bitstream(&serialized, 31, 8);
        assert!(
            result.is_ok(),
            "deserialization failed: {:?} (serialized={:?}, probs={:?})",
            result.err(),
            serialized,
            of_probs
        );
    }

    #[test]
    fn test_encode_ll_code() {
        assert_eq!(encode_ll_code(0), (0, 0, 0));
        assert_eq!(encode_ll_code(15), (15, 0, 0));
        assert_eq!(encode_ll_code(16), (16, 0, 1));
        assert_eq!(encode_ll_code(17), (16, 1, 1));
    }

    #[test]
    fn test_encode_ml_code() {
        assert_eq!(encode_ml_code(3), (0, 0, 0));
        assert_eq!(encode_ml_code(34), (31, 0, 0));
        assert_eq!(encode_ml_code(35), (32, 0, 1));
    }

    #[test]
    fn test_encode_of_code() {
        assert_eq!(encode_of_code(1), (0, 0, 0));
        assert_eq!(encode_of_code(4), (2, 0, 2));
        assert_eq!(encode_of_code(5), (2, 1, 2));
    }

    #[test]
    fn test_large_literals_roundtrip() {
        // Large literals payloads must still round-trip even if the encoder
        // decides that a raw block beats the compressed helper path.
        let mut input = Vec::with_capacity(8000);
        for i in 0..2000 {
            match i % 13 {
                0..=3 => input.push(b'a'),
                4..=6 => input.push(b'b'),
                7..=8 => input.push(b'c'),
                9 => input.push(b'd'),
                10 => input.push(b'e'),
                11 => input.push(b'f'),
                _ => input.push(b'g' + (i % 20) as u8),
            }
        }
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_large_text_roundtrip() {
        let phrases = [
            b"the quick brown fox ".as_slice(),
            b"jumps over the lazy ",
            b"dog and the cat sat ",
            b"on the mat quickly. ",
        ];
        let mut input = Vec::new();
        for i in 0..200 {
            input.extend_from_slice(phrases[i % phrases.len()]);
        }
        assert!(input.len() > 1023);
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_normalize_counts_uniform() {
        // All 256 symbols with freq=1 (uniform distribution)
        let mut freqs = [0u32; 256];
        for f in freqs.iter_mut() {
            *f = 1;
        }
        let accuracy_log = 8u8; // table_size = 256
        let probs = normalize_counts(&freqs, accuracy_log);
        let table_size = 1u32 << accuracy_log;

        // All non-zero entries should have probability >= 1 (or -1 for rare)
        for &p in &probs {
            assert!(p == 0 || p >= -1, "invalid probability: {}", p);
        }

        // Sum of actual probabilities should equal table_size
        let sum: i32 = probs
            .iter()
            .filter(|&&p| p != 0)
            .map(|&p| if p < 0 { 1 } else { p as i32 })
            .sum();
        assert_eq!(
            sum, table_size as i32,
            "probability sum {} != table_size {}",
            sum, table_size
        );

        // All symbols should be present (non-zero)
        for (i, &p) in probs.iter().enumerate() {
            if freqs[i] > 0 {
                assert!(p != 0, "symbol {} with freq>0 has prob=0", i);
            }
        }
    }

    #[test]
    fn test_normalize_counts_extreme_skew() {
        // One symbol with freq=10000, all others freq=1
        let mut freqs = [1u32; 256];
        freqs[0] = 10000;
        let accuracy_log = 8u8;
        let probs = normalize_counts(&freqs, accuracy_log);
        let table_size = 1u32 << accuracy_log;

        // Sum of probabilities should equal table_size
        let sum: i32 = probs
            .iter()
            .filter(|&&p| p != 0)
            .map(|&p| if p < 0 { 1 } else { p as i32 })
            .sum();
        assert_eq!(
            sum, table_size as i32,
            "probability sum {} != table_size {}; probs: {:?}",
            sum, table_size, probs
        );

        // The dominant symbol should have the largest probability
        assert!(
            probs[0] > 0,
            "dominant symbol should have positive probability"
        );
        for &p in &probs[1..] {
            if p > 0 {
                assert!(
                    p <= probs[0],
                    "non-dominant symbol has larger probability than dominant"
                );
            }
        }
    }

    #[test]
    fn test_encode_with_dict_roundtrip() {
        // Test that encode_with_dict produces output decodable by decode_with_dict.
        // We construct a minimal dictionary by hand for testing purposes.
        // The dictionary format (RFC 8878 §5):
        //   Magic(4) + DictID(4) + HuffWeights + FSE_OF + FSE_ML + FSE_LL + RepOffsets(12) + Content

        // Use system zstd to train a real dictionary if available, otherwise skip
        #[cfg(feature = "std")]
        {
            use std::process::Command;

            let has_zstd = Command::new("zstd").arg("--version").output().is_ok();
            if !has_zstd {
                return;
            }

            let tmp_dir = std::env::temp_dir().join("archive_encode_dict_test");
            let _ = std::fs::create_dir_all(&tmp_dir);
            let samples_dir = tmp_dir.join("samples");
            let _ = std::fs::create_dir_all(&samples_dir);

            // Create training samples with enough data for good dictionary training
            let phrases = [
                "the quick brown fox jumps over the lazy dog",
                "a stitch in time saves nine",
                "all that glitters is not gold",
                "actions speak louder than words",
                "the pen is mightier than the sword",
            ];
            for (i, phrase) in phrases.iter().enumerate() {
                let content = phrase.repeat(50);
                std::fs::write(samples_dir.join(format!("s{i}.txt")), content.as_bytes()).unwrap();
            }

            let dict_path = tmp_dir.join("test.dict");
            let train = Command::new("zstd")
                .arg("--train")
                .args(["--maxdict", "4096"])
                .arg("-o")
                .arg(&dict_path)
                .arg("-r")
                .arg(&samples_dir)
                .output();

            let ok = train.map(|o| o.status.success()).unwrap_or(false);
            if !ok {
                let _ = std::fs::remove_dir_all(&tmp_dir);
                return;
            }

            let dict_data = std::fs::read(&dict_path).unwrap();
            let _ = std::fs::remove_dir_all(&tmp_dir);

            let dict = decode::ZstdDict::parse(&dict_data).unwrap();

            // Encode with dict
            let input =
                b"the quick brown fox jumps over the lazy dog and all that glitters is not gold";
            let encoded = encode_with_dict(input, &dict);

            // Our decoder should handle it
            let decoded = decode::decode_with_dict(&encoded, &dict).unwrap();
            assert_eq!(decoded, input.as_slice());

            // The encoded frame should reference the dictionary
            // (dict_id_flag should be non-zero in descriptor)
            assert_eq!(encoded[0..4], ZSTD_MAGIC.to_le_bytes());
            let descriptor = encoded[4];
            let dict_id_flag = descriptor & 0x03;
            assert_eq!(dict_id_flag, 3, "should use 4-byte dict ID");
        }
    }

    #[test]
    fn test_encode_with_dict_multiblock_roundtrip() {
        // Regression for a fuzz-found corruption: blocks after the first
        // must not emit match offsets into the dictionary prefix. The
        // decoder resolves offsets against `[dict | frame output]`, so a
        // dict-referencing offset from block 2+ lands on already-produced
        // output bytes instead of the dict — silent corruption caught only
        // by the content checksum. Span > MAX_BLOCK_SIZE and place a marker
        // that exists only in the dictionary tail at the start of block 2.
        let marker = b"UNIQUE-DICT-TAIL-MARKER-0xDEADBEEF!";
        let mut dict_content = Vec::new();
        while dict_content.len() < 4096 {
            dict_content.extend_from_slice(b"dictionary body without the marker. ");
        }
        dict_content.truncate(4096);
        dict_content.extend_from_slice(marker);
        let dict = decode::ZstdDict::from_content(0x1234_5678, &dict_content).unwrap();

        let filler = b"compressible frame filler text, absent from the dict. ";
        let mut input = Vec::with_capacity(3 * MAX_BLOCK_SIZE);
        while input.len() < MAX_BLOCK_SIZE {
            input.extend_from_slice(filler);
        }
        input.truncate(MAX_BLOCK_SIZE);
        // Block 2 starts with the dict-tail marker: the buggy encoder
        // matched it against the dictionary and emitted a wrong offset.
        input.extend_from_slice(marker);
        while input.len() < 2 * MAX_BLOCK_SIZE + 500 {
            input.extend_from_slice(filler);
        }

        let encoded = encode_with_dict(&input, &dict);
        let decoded = decode::decode_with_dict(&encoded, &dict).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_length_limit_huffman() {
        // Create code lengths where some exceed max_bits=11
        let mut lengths = [0u8; 256];
        // Set up a few symbols with lengths exceeding 11
        lengths[0] = 13;
        lengths[1] = 12;
        lengths[2] = 11;
        lengths[3] = 5;
        lengths[4] = 4;

        let freq = [0u32; 256]; // unused by current impl
        length_limit_huffman(&mut lengths, &freq, 11);

        // All non-zero lengths should be <= 11
        for &l in &lengths {
            if l > 0 {
                assert!(l <= 11, "code length {} exceeds max_bits 11", l);
            }
        }

        // The symbols that had lengths > 0 should still have lengths > 0
        assert!(lengths[0] > 0);
        assert!(lengths[1] > 0);
        assert!(lengths[2] > 0);
        assert!(lengths[3] > 0);
        assert!(lengths[4] > 0);

        // Verify Kraft inequality: sum(2^(max_bits - l)) <= 2^max_bits
        let kraft_sum: u32 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1u32 << (11 - l))
            .sum();
        assert!(
            kraft_sum <= (1u32 << 11),
            "Kraft inequality violated: {} > {}",
            kraft_sum,
            1u32 << 11
        );
    }

    #[test]
    fn test_encode_no_checksum() {
        let input = b"Hello, zstd! This is a test of the no-checksum encoding path.";

        let with_checksum = encode(input);
        let without_checksum = encode_with_options(input, &EncodeOptions { checksum: false });

        // Without checksum should be 4 bytes shorter (no XXH64 low-32 trailer)
        assert_eq!(
            with_checksum.len(),
            without_checksum.len() + 4,
            "no-checksum output should be 4 bytes shorter"
        );

        // Frame descriptor checksum bit (bit 2) should be 0
        // Descriptor is at offset 4 (after 4-byte magic)
        let descriptor = without_checksum[4];
        assert_eq!(
            descriptor & (1 << 2),
            0,
            "checksum bit in frame descriptor should be 0"
        );

        // With-checksum descriptor should have bit 2 set
        let descriptor_ck = with_checksum[4];
        assert_ne!(
            descriptor_ck & (1 << 2),
            0,
            "checksum bit in frame descriptor should be 1 for default encode"
        );

        // Output is valid zstd (decodable)
        let decoded = decode::decode(&without_checksum).unwrap();
        assert_eq!(&decoded, input);
    }
}
