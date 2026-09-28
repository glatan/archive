//! DEFLATE compression per [RFC 1951].
//!
//! Supports three compression levels: no compression (stored blocks),
//! fast (fixed Huffman), and default (dynamic Huffman with LZ77).
//!
//! [RFC 1951]: https://datatracker.ietf.org/doc/html/rfc1951

use alloc::vec;
use alloc::vec::Vec;

use super::tables::*;

/// DEFLATE compression level.
///
/// # Examples
///
/// ```
/// use archive::compress::deflate::encode::Level;
///
/// let level = Level::Default;
/// assert_ne!(level, Level::NoCompression);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// No compression (stored blocks only).
    NoCompression,
    /// Fast compression (short match search, fixed Huffman).
    Fast,
    /// Default compression (balanced, dynamic Huffman).
    Default,
}

/// Encode data using DEFLATE compression.
///
/// Returns a raw DEFLATE stream (no gzip/zlib wrapper).
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::deflate::{encode, decode};
///
/// let compressed = encode::encode(b"Hello!", encode::Level::Default);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, b"Hello!");
/// ```
pub fn encode(input: &[u8], level: Level) -> Vec<u8> {
    match level {
        Level::NoCompression => encode_stored(input),
        Level::Fast => encode_compressed(input, level),
        Level::Default => encode_dynamic(input, level),
    }
}

/// Encode like `encode` but cap LZ77 match lengths at `max_match`.
///
/// Deflate64 is a DEFLATE superset whose only behavioural difference
/// within the classic tables is that length code 285 takes 16 extra
/// bits instead of meaning 258. Restricting matches to <=257 keeps
/// the stream free of code 285, so the output is a valid Deflate64
/// stream (32 KB distances are likewise a subset of the 64 KB
/// Deflate64 window).
pub(crate) fn encode_max_match(input: &[u8], level: Level, max_match: usize) -> Vec<u8> {
    match level {
        Level::NoCompression => encode_stored(input),
        Level::Fast => encode_compressed_with(input, level, max_match),
        Level::Default => encode_dynamic_with(input, level, max_match),
    }
}

/// Encode data using DEFLATE compression with a preset dictionary.
///
/// The dictionary is used to pre-seed the LZ77 hash chains so that
/// back-references can reference dictionary content for better compression.
/// The dictionary itself is not included in the output stream.
///
/// Always uses `Level::Default` compression.
pub(crate) fn encode_with_dict(input: &[u8], dict: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1); // BFINAL
        writer.write_bits(0b01, 2); // BTYPE=01 (fixed Huffman)
        write_fixed_literal(&mut writer, 256);
        return writer.finish();
    }

    let matches = lz77_compress_with_dict(input, Level::Default, dict);

    let mut writer = BitWriter::new();
    writer.write_bits(1, 1); // BFINAL
    writer.write_bits(0b01, 2); // BTYPE=01 (fixed Huffman)

    for token in &matches {
        match *token {
            LZ77Token::Literal(byte) => {
                write_fixed_literal(&mut writer, byte as u16);
            }
            LZ77Token::Match { length, distance } => {
                let (len_code, len_extra_bits, len_extra_val) = encode_length(length);
                write_fixed_literal(&mut writer, len_code);
                if len_extra_bits > 0 {
                    writer.write_bits(len_extra_val as u32, len_extra_bits);
                }

                let (dist_code, dist_extra_bits, dist_extra_val) = encode_distance(distance);
                writer.write_bits_reversed(dist_code as u32, 5);
                if dist_extra_bits > 0 {
                    writer.write_bits(dist_extra_val as u32, dist_extra_bits);
                }
            }
        }
    }

    // End of block
    write_fixed_literal(&mut writer, 256);

    writer.finish()
}

/// Encode as stored (uncompressed) blocks.
fn encode_stored(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let max_block = 65535; // max u16
    let chunks: Vec<&[u8]> = input.chunks(max_block).collect();
    let num_chunks = chunks.len().max(1);

    for (i, chunk) in chunks.iter().enumerate() {
        let is_final = i == num_chunks - 1;
        // BFINAL (1 bit) + BTYPE=00 (2 bits) = 3 bits, then align to byte
        output.push(if is_final { 0x01 } else { 0x00 });
        let len = chunk.len() as u16;
        output.extend_from_slice(&len.to_le_bytes());
        output.extend_from_slice(&(!len).to_le_bytes());
        output.extend_from_slice(chunk);
    }

    if input.is_empty() {
        // Single empty stored block
        output.push(0x01); // BFINAL=1, BTYPE=00
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&(!0u16).to_le_bytes());
    }

    output
}

/// Encode using LZ77 + fixed Huffman codes (BTYPE=01).
fn encode_compressed(input: &[u8], level: Level) -> Vec<u8> {
    encode_compressed_with(input, level, MAX_MATCH_LEN)
}

fn encode_compressed_with(input: &[u8], level: Level, max_match: usize) -> Vec<u8> {
    if input.is_empty() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1); // BFINAL
        writer.write_bits(0b01, 2); // BTYPE=01 (fixed Huffman)
        write_fixed_literal(&mut writer, 256);
        return writer.finish();
    }

    let matches = lz77_compress_max(input, level, max_match);

    let mut writer = BitWriter::new();
    writer.write_bits(1, 1); // BFINAL
    writer.write_bits(0b01, 2); // BTYPE=01 (fixed Huffman)

    for token in &matches {
        match *token {
            LZ77Token::Literal(byte) => {
                write_fixed_literal(&mut writer, byte as u16);
            }
            LZ77Token::Match { length, distance } => {
                let (len_code, len_extra_bits, len_extra_val) = encode_length(length);
                write_fixed_literal(&mut writer, len_code);
                if len_extra_bits > 0 {
                    writer.write_bits(len_extra_val as u32, len_extra_bits);
                }

                let (dist_code, dist_extra_bits, dist_extra_val) = encode_distance(distance);
                writer.write_bits_reversed(dist_code as u32, 5);
                if dist_extra_bits > 0 {
                    writer.write_bits(dist_extra_val as u32, dist_extra_bits);
                }
            }
        }
    }

    // End of block
    write_fixed_literal(&mut writer, 256);

    writer.finish()
}

/// Encode using LZ77 + dynamic Huffman codes (BTYPE=10).
/// Falls back to fixed Huffman if dynamic doesn't improve size.
fn encode_dynamic(input: &[u8], level: Level) -> Vec<u8> {
    encode_dynamic_with(input, level, MAX_MATCH_LEN)
}

fn encode_dynamic_with(input: &[u8], level: Level, max_match: usize) -> Vec<u8> {
    if input.is_empty() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        writer.write_bits(0b01, 2);
        write_fixed_literal(&mut writer, 256);
        return writer.finish();
    }

    let matches = lz77_compress_max(input, level, max_match);

    // Count symbol frequencies
    let mut lit_freq = vec![0u32; 286]; // 0-255 literals, 256 EOB, 257-285 length codes
    let mut dist_freq = vec![0u32; 30]; // 0-29 distance codes
    lit_freq[256] = 1; // EOB always present

    for token in &matches {
        match *token {
            LZ77Token::Literal(byte) => {
                lit_freq[byte as usize] += 1;
            }
            LZ77Token::Match { length, distance } => {
                let (len_code, _, _) = encode_length(length);
                lit_freq[len_code as usize] += 1;
                let (dist_code, _, _) = encode_distance(distance);
                dist_freq[dist_code as usize] += 1;
            }
        }
    }

    // Build optimal code lengths from frequencies
    let lit_lengths = build_code_lengths(&lit_freq, 15);
    let mut dist_lengths = build_code_lengths(&dist_freq, 15);

    // Determine HLIT and HDIST (trim trailing zeros but keep minimums)
    let hlit = {
        let mut n = lit_lengths.len();
        while n > 257 && lit_lengths[n - 1] == 0 {
            n -= 1;
        }
        n
    };
    let hdist = {
        let mut n = dist_lengths.len();
        while n > 1 && dist_lengths[n - 1] == 0 {
            n -= 1;
        }
        n
    };

    // Ensure at least one distance code exists
    if dist_lengths[..hdist].iter().all(|&l| l == 0) {
        dist_lengths[0] = 1;
    }

    // RLE-encode the combined code lengths
    let combined: Vec<u8> = lit_lengths[..hlit]
        .iter()
        .chain(dist_lengths[..hdist].iter())
        .copied()
        .collect();
    let cl_symbols = rle_encode_code_lengths(&combined);

    // Count code length alphabet frequencies
    let mut cl_freq = vec![0u32; 19];
    for &(sym, _) in &cl_symbols {
        cl_freq[sym as usize] += 1;
    }
    let cl_lengths_arr = build_code_lengths(&cl_freq, 7);

    // Determine HCLEN
    let hclen = {
        let mut n = 19;
        while n > 4 && cl_lengths_arr[CODE_LENGTH_ORDER[n - 1]] == 0 {
            n -= 1;
        }
        n
    };

    // Build canonical codes
    let lit_codes = build_canonical_codes(&lit_lengths[..hlit]);
    let dist_codes = build_canonical_codes(&dist_lengths[..hdist]);
    let cl_codes = build_canonical_codes(&cl_lengths_arr);

    // Write dynamic Huffman block
    let mut writer = BitWriter::new();
    writer.write_bits(1, 1); // BFINAL
    writer.write_bits(0b10, 2); // BTYPE=10

    writer.write_bits((hlit - 257) as u32, 5);
    writer.write_bits((hdist - 1) as u32, 5);
    writer.write_bits((hclen - 4) as u32, 4);

    // Code length code lengths in spec order
    for i in 0..hclen {
        writer.write_bits(cl_lengths_arr[CODE_LENGTH_ORDER[i]] as u32, 3);
    }

    // RLE-encoded code lengths
    for &(sym, extra) in &cl_symbols {
        let len = cl_lengths_arr[sym as usize];
        let code = cl_codes[sym as usize];
        writer.write_bits_reversed(code, len);
        match sym {
            16 => writer.write_bits(extra as u32, 2),
            17 => writer.write_bits(extra as u32, 3),
            18 => writer.write_bits(extra as u32, 7),
            _ => {}
        }
    }

    // Compressed data
    for token in &matches {
        match *token {
            LZ77Token::Literal(byte) => {
                let sym = byte as usize;
                writer.write_bits_reversed(lit_codes[sym], lit_lengths[sym]);
            }
            LZ77Token::Match { length, distance } => {
                let (len_code, len_extra_bits, len_extra_val) = encode_length(length);
                let sym = len_code as usize;
                writer.write_bits_reversed(lit_codes[sym], lit_lengths[sym]);
                if len_extra_bits > 0 {
                    writer.write_bits(len_extra_val as u32, len_extra_bits);
                }

                let (dist_code, dist_extra_bits, dist_extra_val) = encode_distance(distance);
                let dsym = dist_code as usize;
                writer.write_bits_reversed(dist_codes[dsym], dist_lengths[dsym]);
                if dist_extra_bits > 0 {
                    writer.write_bits(dist_extra_val as u32, dist_extra_bits);
                }
            }
        }
    }

    // End of block
    writer.write_bits_reversed(lit_codes[256], lit_lengths[256]);

    let dynamic_output = writer.finish();

    // Compare with fixed Huffman, use whichever is smaller
    let fixed_output = encode_fixed_block(&matches);
    if fixed_output.len() <= dynamic_output.len() {
        fixed_output
    } else {
        dynamic_output
    }
}

/// Encode LZ77 tokens as a fixed Huffman block (BTYPE=01).
fn encode_fixed_block(matches: &[LZ77Token]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_bits(1, 1); // BFINAL
    writer.write_bits(0b01, 2); // BTYPE=01

    for token in matches {
        match *token {
            LZ77Token::Literal(byte) => {
                write_fixed_literal(&mut writer, byte as u16);
            }
            LZ77Token::Match { length, distance } => {
                let (len_code, len_extra_bits, len_extra_val) = encode_length(length);
                write_fixed_literal(&mut writer, len_code);
                if len_extra_bits > 0 {
                    writer.write_bits(len_extra_val as u32, len_extra_bits);
                }
                let (dist_code, dist_extra_bits, dist_extra_val) = encode_distance(distance);
                writer.write_bits_reversed(dist_code as u32, 5);
                if dist_extra_bits > 0 {
                    writer.write_bits(dist_extra_val as u32, dist_extra_bits);
                }
            }
        }
    }
    write_fixed_literal(&mut writer, 256);
    writer.finish()
}

// ============================================================
// Huffman tree construction for dynamic blocks
// ============================================================

/// Build optimal code lengths from symbol frequencies.
/// Uses a simple Huffman algorithm with length limiting.
fn build_code_lengths(freq: &[u32], max_bits: u8) -> Vec<u8> {
    let n = freq.len();
    let mut lengths = vec![0u8; n];

    // Collect symbols with non-zero frequency
    let active: Vec<(usize, u32)> = freq
        .iter()
        .enumerate()
        .filter(|&(_, f)| *f > 0)
        .map(|(i, f)| (i, *f))
        .collect();

    if active.is_empty() {
        return lengths;
    }
    if active.len() == 1 {
        lengths[active[0].0] = 1;
        return lengths;
    }

    // Build Huffman tree and get code lengths
    let raw = huffman_tree_lengths(&active);

    // Limit code lengths and adjust via Kraft inequality
    let mut limited: Vec<(usize, u8)> = raw
        .into_iter()
        .map(|(sym, len)| (sym, len.min(max_bits)))
        .collect();

    // Sort by (length desc, frequency asc) for Kraft adjustment
    kraft_limit(&mut limited, max_bits);

    for &(sym, len) in &limited {
        lengths[sym] = len;
    }
    lengths
}

/// Build a Huffman tree from (symbol, frequency) pairs and return code lengths.
fn huffman_tree_lengths(symbols: &[(usize, u32)]) -> Vec<(usize, u8)> {
    let n = symbols.len();
    if n <= 1 {
        return symbols.iter().map(|&(s, _)| (s, 1u8)).collect();
    }

    // Sort by frequency ascending
    let mut sorted: Vec<(usize, u32)> = symbols.to_vec();
    sorted.sort_by_key(|&(_, f)| f);

    // Array-based Huffman tree with two queues
    // Leaves: indices 0..n, Internal: indices n..2n-1
    let total = 2 * n - 1;
    let mut node_freq = vec![0u64; total];
    let mut parent = vec![usize::MAX; total];

    for (i, &(_, f)) in sorted.iter().enumerate() {
        node_freq[i] = f as u64;
    }

    let mut q1 = 0usize; // next leaf
    let mut q2 = 0usize; // next internal (index into internal nodes starting at n)
    let mut num_internal = 0usize;

    for _ in 0..n - 1 {
        // Pick two smallest from the two queues
        let a = pick_smallest(&node_freq, n, &mut q1, &mut q2, num_internal);
        let b = pick_smallest(&node_freq, n, &mut q1, &mut q2, num_internal);
        let internal_idx = n + num_internal;
        node_freq[internal_idx] = node_freq[a] + node_freq[b];
        parent[a] = internal_idx;
        parent[b] = internal_idx;
        num_internal += 1;
    }

    // Compute depths from root (root = n + num_internal - 1)
    let mut depth = vec![0u8; total];
    let root = n + num_internal - 1;
    for i in (0..root).rev() {
        if parent[i] != usize::MAX {
            depth[i] = depth[parent[i]] + 1;
        }
    }

    sorted
        .iter()
        .enumerate()
        .map(|(i, &(sym, _))| (sym, depth[i]))
        .collect()
}

/// Pick the smallest-frequency node from leaf queue or internal queue.
fn pick_smallest(
    freq: &[u64],
    n: usize,
    q1: &mut usize,
    q2: &mut usize,
    num_internal: usize,
) -> usize {
    let q1_avail = *q1 < n;
    let q2_avail = *q2 < num_internal;

    match (q1_avail, q2_avail) {
        (true, true) => {
            let q1_idx = *q1;
            let q2_idx = n + *q2;
            if freq[q1_idx] <= freq[q2_idx] {
                *q1 += 1;
                q1_idx
            } else {
                *q2 += 1;
                q2_idx
            }
        }
        (true, false) => {
            let idx = *q1;
            *q1 += 1;
            idx
        }
        (false, true) => {
            let idx = n + *q2;
            *q2 += 1;
            idx
        }
        (false, false) => unreachable!(),
    }
}

/// Limit code lengths to max_bits using the Kraft inequality.
fn kraft_limit(symbols: &mut [(usize, u8)], max_bits: u8) {
    if symbols.is_empty() {
        return;
    }

    // Sort by length descending
    symbols.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    loop {
        let kraft_sum: u64 = symbols
            .iter()
            .map(|&(_, len)| {
                if len == 0 {
                    0
                } else {
                    1u64 << (max_bits - len)
                }
            })
            .sum();
        let target = 1u64 << max_bits;

        if kraft_sum <= target {
            break;
        }

        // Over budget: increase the shortest code length
        let mut found = false;
        for item in symbols.iter_mut().rev() {
            if item.1 < max_bits {
                item.1 += 1;
                found = true;
                break;
            }
        }
        if !found {
            break;
        }

        symbols.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    }
}

/// Build canonical Huffman codes from code lengths.
/// Returns (code, length) for each symbol index.
fn build_canonical_codes(lengths: &[u8]) -> Vec<u32> {
    let n = lengths.len();
    let mut codes = vec![0u32; n];
    let max_bits = *lengths.iter().max().unwrap_or(&0);
    if max_bits == 0 {
        return codes;
    }

    // Count codes of each length
    let mut bl_count = vec![0u32; max_bits as usize + 1];
    for &len in lengths {
        if len > 0 {
            bl_count[len as usize] += 1;
        }
    }

    // Find smallest code for each length
    let mut next_code = vec![0u32; max_bits as usize + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[bits as usize - 1]) << 1;
        next_code[bits as usize] = code;
    }

    // Assign codes
    for (sym, &len) in lengths.iter().enumerate() {
        if len > 0 {
            codes[sym] = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }

    codes
}

/// RLE-encode code lengths using DEFLATE code length alphabet (symbols 0-18).
/// Returns Vec of (symbol, extra_value) pairs.
fn rle_encode_code_lengths(lengths: &[u8]) -> Vec<(u8, u8)> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < lengths.len() {
        let val = lengths[i];

        if val == 0 {
            // Count run of zeros
            let mut run = 1;
            while i + run < lengths.len() && lengths[i + run] == 0 {
                run += 1;
            }
            i += run;

            // Encode using code 18 (11-138 zeros) and code 17 (3-10 zeros)
            while run >= 11 {
                let count = run.min(138);
                result.push((18u8, (count - 11) as u8));
                run -= count;
            }
            if run >= 3 {
                result.push((17u8, (run - 3) as u8));
                run = 0;
            }
            // Remaining zeros as literal 0s
            for _ in 0..run {
                result.push((0u8, 0));
            }
        } else {
            // Non-zero value
            result.push((val, 0));
            i += 1;

            // Check for repeats of same value (code 16)
            let mut run = 0;
            while i + run < lengths.len() && lengths[i + run] == val {
                run += 1;
            }
            i += run;

            while run >= 3 {
                let count = run.min(6);
                result.push((16u8, (count - 3) as u8));
                run -= count;
            }
            for _ in 0..run {
                result.push((val, 0));
            }
        }
    }

    result
}

/// Write a literal/length code using fixed Huffman encoding.
fn write_fixed_literal(writer: &mut BitWriter, symbol: u16) {
    match symbol {
        0..=143 => {
            // 8-bit codes: 00110000 + symbol
            let code = 0x30 + symbol as u32;
            writer.write_bits_reversed(code, 8);
        }
        144..=255 => {
            // 9-bit codes: 110010000 + (symbol - 144)
            let code = 0x190 + (symbol - 144) as u32;
            writer.write_bits_reversed(code, 9);
        }
        256..=279 => {
            // 7-bit codes: 0000000 + (symbol - 256)
            let code = (symbol - 256) as u32;
            writer.write_bits_reversed(code, 7);
        }
        280..=287 => {
            // 8-bit codes: 11000000 + (symbol - 280)
            let code = 0xC0 + (symbol - 280) as u32;
            writer.write_bits_reversed(code, 8);
        }
        _ => unreachable!(),
    }
}

/// Encode a match length (3..=258) to (code, extra_bits, extra_value).
fn encode_length(length: u16) -> (u16, u8, u16) {
    for i in (0..LENGTH_BASE.len()).rev() {
        if length >= LENGTH_BASE[i] {
            let code = 257 + i as u16;
            let extra_val = length - LENGTH_BASE[i];
            return (code, LENGTH_EXTRA[i], extra_val);
        }
    }
    unreachable!()
}

/// Encode a match distance (1..=32768) to (code, extra_bits, extra_value).
fn encode_distance(distance: u16) -> (u16, u8, u16) {
    for i in (0..DISTANCE_BASE.len()).rev() {
        if distance >= DISTANCE_BASE[i] {
            let extra_val = distance - DISTANCE_BASE[i];
            return (i as u16, DISTANCE_EXTRA[i], extra_val);
        }
    }
    unreachable!()
}

// ============================================================
// LZ77 compression
// ============================================================

#[derive(Debug, Clone)]
enum LZ77Token {
    Literal(u8),
    Match { length: u16, distance: u16 },
}

const MAX_MATCH_LEN: usize = 258;
const MIN_MATCH_LEN: usize = 3;
const WINDOW_SIZE: usize = 32768;
const HASH_BITS: usize = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// Simple hash-chain LZ77 compressor.
fn lz77_compress_max(input: &[u8], level: Level, max_match: usize) -> Vec<LZ77Token> {
    lz77_compress_with_dict_max(input, level, &[], max_match)
}

/// Simple hash-chain LZ77 compressor with optional preset dictionary.
///
/// The dictionary is used to pre-seed the hash chains so that
/// back-references can reach into dictionary content, but no tokens
/// are emitted for the dictionary bytes.
fn lz77_compress_with_dict(input: &[u8], level: Level, dict: &[u8]) -> Vec<LZ77Token> {
    lz77_compress_with_dict_max(input, level, dict, MAX_MATCH_LEN)
}

fn lz77_compress_with_dict_max(
    input: &[u8],
    level: Level,
    dict: &[u8],
    max_match: usize,
) -> Vec<LZ77Token> {
    let max_chain = match level {
        Level::NoCompression => 0,
        Level::Fast => 4,
        Level::Default => 32,
    };

    // Concatenate dict + input into a single buffer for uniform addressing.
    let dict_len = dict.len().min(WINDOW_SIZE);
    let dict_used = &dict[dict.len() - dict_len..];
    let mut combined = Vec::with_capacity(dict_len + input.len());
    combined.extend_from_slice(dict_used);
    combined.extend_from_slice(input);

    let mut tokens = Vec::new();

    // Hash chain: head[hash] = most recent position with that hash
    let mut head = alloc::vec![0u32; HASH_SIZE];
    // prev[pos % WINDOW_SIZE] = previous position in chain
    let mut prev = alloc::vec![0u32; WINDOW_SIZE];

    // Pre-seed hash chains with dictionary bytes
    for pos in 0..dict_len {
        if pos + MIN_MATCH_LEN <= combined.len() {
            let hash = hash3(&combined[pos..pos + 3]);
            prev[pos % WINDOW_SIZE] = head[hash] as u32;
            head[hash] = pos as u32;
        }
    }

    let mut pos = dict_len;

    while pos < combined.len() {
        if pos + MIN_MATCH_LEN > combined.len() {
            tokens.push(LZ77Token::Literal(combined[pos]));
            pos += 1;
            continue;
        }

        let hash = hash3(&combined[pos..pos + 3]);
        let mut best_len = MIN_MATCH_LEN - 1;
        let mut best_dist = 0u16;

        // Search the hash chain
        let mut chain_pos = head[hash] as usize;
        let min_pos = pos.saturating_sub(WINDOW_SIZE);
        let mut chain_count = 0;

        while chain_pos >= min_pos && chain_pos < pos && chain_count < max_chain {
            let dist = pos - chain_pos;
            if dist > 0 && dist <= WINDOW_SIZE {
                let max_len = max_match.min(combined.len() - pos);
                let match_len = count_match(&combined[chain_pos..], &combined[pos..], max_len);
                if match_len > best_len {
                    best_len = match_len;
                    best_dist = dist as u16;
                    if best_len == max_match {
                        break;
                    }
                }
            }
            let p = prev[chain_pos % WINDOW_SIZE] as usize;
            if p >= chain_pos {
                break; // avoid infinite loop
            }
            chain_pos = p;
            chain_count += 1;
        }

        // Update hash chain
        prev[pos % WINDOW_SIZE] = head[hash] as u32;
        head[hash] = pos as u32;

        if best_len >= MIN_MATCH_LEN {
            tokens.push(LZ77Token::Match {
                length: best_len as u16,
                distance: best_dist,
            });
            // Update hash for all positions in the match
            for i in 1..best_len {
                let p = pos + i;
                if p + 3 <= combined.len() {
                    let h = hash3(&combined[p..p + 3]);
                    prev[p % WINDOW_SIZE] = head[h] as u32;
                    head[h] = p as u32;
                }
            }
            pos += best_len;
        } else {
            tokens.push(LZ77Token::Literal(combined[pos]));
            pos += 1;
        }
    }

    tokens
}

/// 3-byte hash function.
fn hash3(data: &[u8]) -> usize {
    let h = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
    // Multiply-shift hash
    (h.wrapping_mul(2654435769) >> (32 - HASH_BITS)) as usize
}

/// Count matching bytes between two slices.
fn count_match(a: &[u8], b: &[u8], max_len: usize) -> usize {
    let mut len = 0;
    let limit = max_len.min(a.len()).min(b.len());
    while len < limit && a[len] == b[len] {
        len += 1;
    }
    len
}

// ============================================================
// Bit writer (LSB-first)
// ============================================================

struct BitWriter {
    data: Vec<u8>,
    bit_buf: u32,
    bit_count: u8,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            data: Vec::new(),
            bit_buf: 0,
            bit_count: 0,
        }
    }

    /// Write `n` bits (LSB-first, value already in correct order).
    fn write_bits(&mut self, value: u32, n: u8) {
        self.bit_buf |= value << self.bit_count;
        self.bit_count += n;
        self.flush_bytes();
    }

    /// Write `n` bits with the value reversed (for Huffman codes which are MSB-first).
    fn write_bits_reversed(&mut self, value: u32, n: u8) {
        let reversed = reverse_bits(value, n);
        self.write_bits(reversed, n);
    }

    fn flush_bytes(&mut self) {
        while self.bit_count >= 8 {
            self.data.push(self.bit_buf as u8);
            self.bit_buf >>= 8;
            self.bit_count -= 8;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.data.push(self.bit_buf as u8);
        }
        self.data
    }
}

fn reverse_bits(value: u32, num_bits: u8) -> u32 {
    let mut result = 0;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    result
}

/// Encode data using DEFLATE compression and write to a [`std::io::Write`] sink.
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
/// use archive::compress::deflate::encode::{encode_writer, Level};
///
/// let mut buf = Vec::new();
/// let len = encode_writer(b"Hello!", Level::Fast, &mut buf).unwrap();
/// assert!(len > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(
    input: &[u8],
    level: Level,
    mut writer: W,
) -> std::io::Result<usize> {
    let encoded = encode(input, level);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::deflate::decode;

    #[test]
    fn test_roundtrip_empty() {
        let encoded = encode(b"", Level::NoCompression);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_roundtrip_stored() {
        let input = b"Hello, DEFLATE!";
        let encoded = encode(input, Level::NoCompression);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_compressed_short() {
        let input = b"Hello, World!";
        let encoded = encode(input, Level::Fast);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_compressed_repetitive() {
        let input = "abcabc".repeat(100);
        let encoded = encode(input.as_bytes(), Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
        // Compressed should be much smaller
        assert!(encoded.len() < input.len() / 2);
    }

    #[test]
    fn test_roundtrip_compressed_empty() {
        let encoded = encode(b"", Level::Fast);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_encode_length() {
        let (code, extra, val) = encode_length(3);
        assert_eq!(code, 257);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);

        let (code, extra, val) = encode_length(258);
        assert_eq!(code, 285);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);

        let (code, extra, val) = encode_length(11);
        assert_eq!(code, 265);
        assert_eq!(extra, 1);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_encode_distance() {
        let (code, extra, _val) = encode_distance(1);
        assert_eq!(code, 0);
        assert_eq!(extra, 0);

        let (code, extra, val) = encode_distance(5);
        assert_eq!(code, 4);
        assert_eq!(extra, 1);
        assert_eq!(val, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_writer() {
        let input = b"Hello, deflate!";
        let mut output = Vec::new();
        let len = encode_writer(input, Level::Fast, &mut output).unwrap();
        assert_eq!(len, output.len());
        let decoded = decode::decode(&output).unwrap();
        assert_eq!(decoded, input);
    }

    // Phase 3: Boundary value tests

    #[test]
    fn test_stored_block_max_65535() {
        let input = vec![0xABu8; 65535];
        let encoded = encode(&input, Level::NoCompression);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_stored_block_multi() {
        let input = vec![0xCDu8; 65536];
        let encoded = encode(&input, Level::NoCompression);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert!(encoded.len() > 65535 + 5);
    }

    #[test]
    fn test_roundtrip_large_distance() {
        let mut input = Vec::new();
        let pattern = b"UNIQUE_PATTERN_HERE!";
        input.extend_from_slice(pattern);
        input.resize(input.len() + 32768, b'X');
        input.extend_from_slice(pattern);
        let encoded = encode(&input, Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_length_boundaries() {
        let (code, extra, val) = encode_length(3);
        assert_eq!(code, 257);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);

        let (code, extra, val) = encode_length(10);
        assert_eq!(code, 264);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);

        let (code, extra, val) = encode_length(258);
        assert_eq!(code, 285);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_encode_distance_boundaries() {
        let (code, extra, val) = encode_distance(1);
        assert_eq!(code, 0);
        assert_eq!(extra, 0);
        assert_eq!(val, 0);

        let (code, extra, val) = encode_distance(32768);
        assert_eq!(code, 29);
        assert_eq!(extra, 13);
        assert_eq!(val, 8191);
    }

    #[test]
    fn test_encode_distance_all_code_boundaries() {
        // RFC 1951 Table: verify each distance code's base value encodes correctly
        use crate::compress::deflate::tables::{DISTANCE_BASE, DISTANCE_EXTRA};
        for i in 0..DISTANCE_BASE.len() {
            let dist = DISTANCE_BASE[i];
            let (code, extra, val) = encode_distance(dist);
            assert_eq!(
                code, i as u16,
                "base distance {} should map to code {}",
                dist, i
            );
            assert_eq!(
                extra, DISTANCE_EXTRA[i],
                "code {} should have {} extra bits",
                i, DISTANCE_EXTRA[i]
            );
            assert_eq!(val, 0, "base distance should have extra_val=0");
        }
    }

    #[test]
    #[should_panic]
    fn test_encode_length_zero_panics() {
        encode_length(0);
    }

    #[test]
    #[should_panic]
    fn test_encode_distance_zero_panics() {
        encode_distance(0);
    }

    #[test]
    fn test_max_match_length_258() {
        let mut input = Vec::new();
        let pattern = b"ABCDEFGH";
        input.extend_from_slice(pattern);
        for _ in 0..33 {
            input.extend_from_slice(pattern);
        }
        let encoded = encode(&input, Level::Default);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_min_distance_match() {
        let input = vec![b'A'; 100];
        let encoded = encode(&input, Level::Fast);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert!(encoded.len() < input.len());
    }

    #[test]
    fn test_very_small_input() {
        let input = b"AB";
        let encoded = encode(input, Level::Fast);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_all_levels_same_output() {
        let input = "Hello, DEFLATE! ".repeat(30);
        for level in [Level::NoCompression, Level::Fast, Level::Default] {
            let encoded = encode(input.as_bytes(), level);
            let decoded = super::super::decode::decode(&encoded).unwrap();
            assert_eq!(decoded, input.as_bytes(), "failed for {:?}", level);
        }
    }

    // Dynamic Huffman specific tests

    #[test]
    fn test_dynamic_huffman_roundtrip() {
        // Data with skewed frequency distribution benefits from dynamic Huffman
        let input = "aaaaaabbbbccd".repeat(100);
        let encoded = encode(input.as_bytes(), Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
    }

    #[test]
    fn test_dynamic_vs_fixed_compression_ratio() {
        // Highly skewed data should compress better with dynamic Huffman
        let mut input = Vec::new();
        input.extend(core::iter::repeat_n(b'a', 1000));
        input.extend(core::iter::repeat_n(b'z', 10));

        let dynamic = encode(&input, Level::Default);
        let fixed = encode(&input, Level::Fast);
        let decoded = decode::decode(&dynamic).unwrap();
        assert_eq!(decoded, input);
        // Dynamic should be at most as large as fixed for skewed data
        assert!(dynamic.len() <= fixed.len());
    }

    #[test]
    fn test_dynamic_huffman_all_byte_values() {
        // Input using all 256 byte values
        let mut input: Vec<u8> = (0..=255).collect();
        input.extend_from_slice(&input.clone());
        let encoded = encode(&input, Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_dynamic_huffman_english_text() {
        let input = "The quick brown fox jumps over the lazy dog. \
                      Pack my box with five dozen liquor jugs. \
                      How vexingly quick daft zebras jump. "
            .repeat(20);
        let encoded = encode(input.as_bytes(), Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
        assert!(encoded.len() < input.len());
    }

    #[test]
    fn test_build_code_lengths_single_symbol() {
        let mut freq = vec![0u32; 286];
        freq[65] = 10; // only 'A'
        let lengths = build_code_lengths(&freq, 15);
        assert_eq!(lengths[65], 1);
        // All others should be 0
        assert!(lengths.iter().enumerate().all(|(i, &l)| i == 65 || l == 0));
    }

    #[test]
    fn test_build_code_lengths_two_symbols() {
        let mut freq = vec![0u32; 286];
        freq[65] = 50; // 'A'
        freq[66] = 50; // 'B'
        let lengths = build_code_lengths(&freq, 15);
        assert_eq!(lengths[65], 1);
        assert_eq!(lengths[66], 1);
    }

    #[test]
    fn test_build_canonical_codes() {
        // RFC 1951 example: lengths [3,3,3,3,3,2,4,4]
        let lengths: Vec<u8> = vec![3, 3, 3, 3, 3, 2, 4, 4];
        let codes = build_canonical_codes(&lengths);
        // F (symbol 5) has length 2, code 00
        assert_eq!(codes[5], 0b00);
        // A (symbol 0) has length 3, code 010
        assert_eq!(codes[0], 0b010);
        // G (symbol 6) has length 4, code 1110
        assert_eq!(codes[6], 0b1110);
        // H (symbol 7) has length 4, code 1111
        assert_eq!(codes[7], 0b1111);
    }

    #[test]
    fn test_rle_encode_code_lengths() {
        // Test zero runs
        let lengths = vec![0, 0, 0, 0, 5, 5, 5, 5, 0, 0, 0];
        let encoded = rle_encode_code_lengths(&lengths);
        // 4 zeros → code 17 (extra=1, count=4), then 5, then 3 repeats → code 16, then 3 zeros → code 17
        let mut decoded = Vec::new();
        for &(sym, extra) in &encoded {
            match sym {
                0..=15 => decoded.push(sym),
                16 => {
                    let prev = *decoded
                        .last()
                        .expect("symbol 16 requires a previous length");
                    for _ in 0..(extra as usize + 3) {
                        decoded.push(prev);
                    }
                }
                17 => {
                    decoded.extend(core::iter::repeat_n(0, extra as usize + 3));
                }
                18 => {
                    decoded.extend(core::iter::repeat_n(0, extra as usize + 11));
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(decoded, lengths);
    }

    #[test]
    fn test_rle_encode_long_zero_run() {
        // 150 zeros should use code 18 (138) + code 17 (12)
        let lengths = vec![0u8; 150];
        let encoded = rle_encode_code_lengths(&lengths);
        let mut decoded = Vec::new();
        for &(sym, extra) in &encoded {
            match sym {
                0..=15 => decoded.push(sym),
                17 => {
                    decoded.extend(core::iter::repeat_n(0, extra as usize + 3));
                }
                18 => {
                    decoded.extend(core::iter::repeat_n(0, extra as usize + 11));
                }
                _ => {}
            }
        }
        assert_eq!(decoded, lengths);
    }

    #[test]
    fn test_rle_encode_150_zeros() {
        // 150 zeros: code 18 encodes 138 zeros (extra=127), then 12 remaining.
        // Since 12 >= 11, code 18 is used again (extra = 12-11 = 1).
        let lengths = vec![0u8; 150];
        let encoded = rle_encode_code_lengths(&lengths);
        assert_eq!(encoded.len(), 2);
        // First entry: code 18, extra = 138-11 = 127
        assert_eq!(encoded[0], (18u8, 127u8));
        // Second entry: code 18, extra = 12-11 = 1
        assert_eq!(encoded[1], (18u8, 1u8));
    }

    #[test]
    fn test_roundtrip_single_byte() {
        for &level in &[Level::NoCompression, Level::Fast, Level::Default] {
            let encoded = encode(&[0x42], level);
            let decoded = decode::decode(&encoded).unwrap();
            assert_eq!(decoded, &[0x42]);
        }
    }

    #[test]
    fn test_roundtrip_all_zeros() {
        let input = vec![0u8; 255];
        for &level in &[Level::NoCompression, Level::Fast, Level::Default] {
            let encoded = encode(&input, level);
            let decoded = decode::decode(&encoded).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn test_rle_encode_two_repeats_no_code16() {
        // [5, 5, 3]: only 2 consecutive 5s, code 16 requires min 3 repeats after initial
        // So the second 5 should NOT use code 16, it should emit literal 5 twice then 3.
        let lengths = vec![5u8, 5, 3];
        let encoded = rle_encode_code_lengths(&lengths);
        // Verify code 16 is not used
        for &(sym, _) in &encoded {
            assert_ne!(
                sym, 16,
                "code 16 should not be used for only 2 consecutive values"
            );
        }
        // Should be: (5,0), (5,0), (3,0) — first 5 emitted, then 1 repeat (not enough for code 16), then 3
        assert_eq!(encoded, vec![(5u8, 0), (5u8, 0), (3u8, 0)]);
    }

    // C-5 #33: empty input with Default level
    #[test]
    fn test_encode_decode_empty_input_default() {
        let encoded = encode(&[], Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }
}
