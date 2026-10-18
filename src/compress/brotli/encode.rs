// LZ77 compressed metablock strategies: context modeling, multi-block-type,
// and single-block. Each is tried in order and used when it beats the
// uncompressed representation.
//! Brotli encoder with LZ77 matching, static dictionary, multi-block-type,
//! and context modeling support.
//!
//! The encoder tries increasingly sophisticated strategies and falls back to
//! simpler representations when the compressed output would be larger:
//!
//! 1. Literal-only compressed (for repeated patterns / low-cardinality data)
//! 2. Context modeling (LSB6, 2 context groups) + LZ77
//! 3. Multi-block-type (2 literal block types) + LZ77
//! 4. Single-block LZ77
//! 5. Uncompressed metablock (fallback)

use super::huffman;
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// RFC 7932 command/distance tables
// ---------------------------------------------------------------------------

const COMMAND_CELL_POS: [usize; 11] = [0, 1, 0, 1, 8, 9, 2, 16, 10, 17, 18];
const INSERT_LENGTH_EXTRA_BITS: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];
const COPY_LENGTH_EXTRA_BITS: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24,
];
const INSERT_LENGTH_OFFSETS: [usize; 24] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210,
    22594,
];
const COPY_LENGTH_OFFSETS: [usize; 24] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118,
];

const MAX_METABLOCK_LEN: usize = 0xFF_FFFF;
const MIN_COMPRESSED_RUN_LEN: usize = 64;
const MAX_COMPRESSED_PATTERN_LEN: usize = 4;
const MAX_COMPRESSED_LITERAL_SYMBOLS: usize = 4;
const MIN_LOW_CARDINALITY_LITERAL_LEN: usize = 128;

const HASH_TABLE_SIZE: usize = 32768;
const HASH_TABLE_MASK: usize = HASH_TABLE_SIZE - 1;
const MIN_MATCH_LEN: usize = 4;
const MAX_MATCH_LEN: usize = 1024;
const MAX_DISTANCE: usize = 65520;

const NPOSTFIX: u8 = 0;
const DISTANCE_ALPHABET_SIZE: usize = 64;

const CODE_LENGTH_CODE_ORDER: [u8; 18] =
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15];

const BLOCK_LENGTH_PREFIX_OFFSETS: [usize; 26] = [
    1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265,
    2289, 4337, 8433, 16625,
];
const BLOCK_LENGTH_PREFIX_EXTRA_BITS: [u8; 26] = [
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24,
];

const DICTIONARY_DATA: &[u8] = include_bytes!("dictionary.bin");

include!("dict_index_build.rs");

const _: () = assert!(DICT_WORD_HASH_MASK == HASH_TABLE_MASK);

// ---------------------------------------------------------------------------
// LZ77 command representation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Lz77Command {
    InsertCopy {
        literals: Vec<u8>,
        copy_len: usize,
        distance: usize,
    },
    InsertOnly {
        literals: Vec<u8>,
    },
}

#[derive(Debug)]
struct EncodedCommand {
    command_symbol: u16,
    insert_extra: u32,
    insert_extra_bits: u8,
    copy_extra: u32,
    copy_extra_bits: u8,
    distance_code: u16,
    distance_extra: u32,
    distance_extra_bits: u8,
    has_distance: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encode a Brotli stream.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_bits(0, 1);
    let mut start = 0usize;
    while start < input.len() {
        write_best_metablock(&mut writer, input, start);
        start += MAX_METABLOCK_LEN.min(input.len() - start);
    }
    writer.write_bits(1, 1);
    writer.write_bits(1, 1);
    writer.finish()
}

/// Encode a Brotli stream prefixed with a metadata metablock.
pub fn encode_with_metadata(input: &[u8], metadata: &[u8]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_bits(0, 1);
    if !metadata.is_empty() {
        write_metadata_metablock(&mut writer, metadata);
    }
    let mut start = 0usize;
    while start < input.len() {
        write_best_metablock(&mut writer, input, start);
        start += MAX_METABLOCK_LEN.min(input.len() - start);
    }
    writer.write_bits(1, 1);
    writer.write_bits(1, 1);
    writer.finish()
}

#[cfg(feature = "std")]
/// Encode a Brotli stream and write it to a [`std::io::Write`] sink.
pub fn encode_writer<W: std::io::Write>(input: &[u8], mut writer: W) -> std::io::Result<usize> {
    let encoded = encode(input);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

// ---------------------------------------------------------------------------
// Strategy selection
// ---------------------------------------------------------------------------

// Emit one metablock using the first strategy (in fixed order:
// literal-only, context-modeled LZ77, multi-block LZ77, single-block
// LZ77) whose encoded size beats the uncompressed metablock size.
// This is a first-match-wins policy, not a global minimum search.
fn write_best_metablock(writer: &mut BitWriter, input: &[u8], start: usize) {
    let chunk = &input[start..(start + MAX_METABLOCK_LEN).min(input.len())];
    let stream_offset = start;
    let uncompressed_size = 4 + chunk.len();

    let uncomp_bits = uncompressed_size * 8;

    // Strategy 1: Literal-only (repeated patterns / low-cardinality)
    if let Some(symbols) = compressed_literal_symbols(chunk) {
        let mut tmp = BitWriter::with_limit(uncomp_bits);
        write_compressed_literal_metablock(&mut tmp, chunk, &symbols);
        if let Some((bits, tb)) = tmp.finish_if_within_limit()
            && tb < uncomp_bits
        {
            writer.write_raw(&bits, tb);
            return;
        }
    }

    // LZ77 command generation (match finder + dictionary index) is
    // shared across the compressed strategies.
    let cmds = generate_lz77_commands(chunk, stream_offset);
    if cmds
        .iter()
        .any(|c| matches!(c, Lz77Command::InsertCopy { .. }))
    {
        // Strategy 2: Context modeling (LSB6) + LZ77
        if let Some((bits, tb)) = try_context_modeling_lz77(input, start, &cmds, uncomp_bits) {
            if tb < uncomp_bits {
                writer.write_raw(&bits, tb);
                return;
            }
        }
        // Strategy 3: Multi-block-type (two literal block types) + LZ77
        if let Some((bits, tb)) = try_multi_block_lz77(chunk, &cmds, uncomp_bits) {
            if tb < uncomp_bits {
                writer.write_raw(&bits, tb);
                return;
            }
        }
        // Strategy 4: Single-block LZ77
        if let Some((bits, tb)) = try_lz77_metablock(chunk, &cmds, uncomp_bits) {
            if tb < uncomp_bits {
                writer.write_raw(&bits, tb);
                return;
            }
        }
    }

    // Strategy 5: Uncompressed fallback
    writer.write_bits(0, 1);
    write_metablock_len(writer, chunk.len());
    writer.write_bits(1, 1);
    writer.align_zero();
    writer.write_bytes(chunk);
}

// ---------------------------------------------------------------------------
// Metadata metablock
// ---------------------------------------------------------------------------

fn write_metadata_metablock(writer: &mut BitWriter, metadata: &[u8]) {
    assert!(!metadata.is_empty());
    writer.write_bits(0, 1);
    writer.write_bits(3, 2);
    writer.write_bits(0, 1);
    let len = metadata.len();
    if len <= 0x100 {
        writer.write_bits(1, 2);
        writer.write_bits((len - 1) as u32, 8);
    } else if len <= 0x1_0000 {
        writer.write_bits(2, 2);
        writer.write_bits((len - 1) as u32, 16);
    } else {
        writer.write_bits(3, 2);
        writer.write_bits((len - 1) as u32, 24);
    }
    writer.align_zero();
    writer.write_bytes(metadata);
}

// ---------------------------------------------------------------------------
// LZ77 engine
// ---------------------------------------------------------------------------

fn generate_lz77_commands(input: &[u8], stream_offset: usize) -> Vec<Lz77Command> {
    let mut commands = Vec::new();
    let mut pos = 0usize;
    let mut hash_table = vec![u32::MAX; HASH_TABLE_SIZE];
    let mut pending_literals: Vec<u8> = Vec::new();
    let dict_index = embedded_dict_index();

    while pos + MIN_MATCH_LEN <= input.len() {
        let hash = hash4(&input[pos..]);
        let prev_pos_raw = hash_table[hash];
        hash_table[hash] = pos as u32;

        let mut best_len = 0usize;
        let mut best_dist = 0usize;

        if prev_pos_raw != u32::MAX {
            let prev_pos = prev_pos_raw as usize;
            if prev_pos < pos {
                let dist = pos - prev_pos;
                if dist <= MAX_DISTANCE && dist <= pos + stream_offset {
                    let max_len = (input.len() - pos).min(MAX_MATCH_LEN);
                    let match_len = count_match(&input[prev_pos..], &input[pos..], max_len);
                    if match_len >= MIN_MATCH_LEN {
                        best_len = match_len;
                        best_dist = dist;
                    }
                }
            }
        }

        // The decoder resolves dictionary references against
        // min(output_len, window_size); the stream declares
        // WBITS=16, so the window is 2^16 - 16 = MAX_DISTANCE.
        if best_len < 6
            && let Some((dict_len, dict_dist)) = find_dictionary_match(
                &input[pos..],
                (pos + stream_offset).min(MAX_DISTANCE),
                &dict_index,
            )
        {
            if dict_len > best_len {
                best_len = dict_len;
                best_dist = dict_dist;
            }
        }

        if best_len >= MIN_MATCH_LEN {
            let lits = core::mem::take(&mut pending_literals);
            commands.push(Lz77Command::InsertCopy {
                literals: lits,
                copy_len: best_len,
                distance: best_dist,
            });
            for i in 1..best_len {
                if pos + i + MIN_MATCH_LEN <= input.len() {
                    let h = hash4(&input[pos + i..]);
                    hash_table[h] = (pos + i) as u32;
                }
            }
            pos += best_len;
        } else {
            pending_literals.push(input[pos]);
            pos += 1;
        }
    }

    while pos < input.len() {
        pending_literals.push(input[pos]);
        pos += 1;
    }

    if !pending_literals.is_empty() {
        commands.push(Lz77Command::InsertOnly {
            literals: pending_literals,
        });
    }
    commands
}

fn hash4(data: &[u8]) -> usize {
    dict_hash(data) & HASH_TABLE_MASK
}

fn count_match(a: &[u8], b: &[u8], max_len: usize) -> usize {
    crate::compress::match_ops::match_len(a, b, max_len)
}

// ---------------------------------------------------------------------------
// Static dictionary matching
// ---------------------------------------------------------------------------

/// Chained hash index over the static dictionary.
///
/// The tables are the little-endian image built from `dictionary.bin`.
/// Lookups read one word at a time, so the bytes do not need to be copied
/// into an aligned `Vec` at startup.
struct DictIndex {
    head: &'static [u8],
    next: &'static [u8],
    /// Packed `word_len << 20 | word_idx` entries.
    entry: &'static [u8],
}

static DICT_INDEX_BYTES: &[u8] = include_bytes!(env!("BROTLI_DICT_INDEX"));

fn embedded_dict_index() -> DictIndex {
    let head_bytes = DICT_HASH_SIZE * 4;
    let rest = &DICT_INDEX_BYTES[head_bytes..];
    let words = rest.len() / 8;
    let (next, entry) = rest.split_at(words * 4);
    DictIndex {
        head: &DICT_INDEX_BYTES[..head_bytes],
        next,
        entry,
    }
}

fn index_u32(bytes: &[u8], index: usize) -> u32 {
    let offset = index * 4;
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn find_dictionary_match(
    input: &[u8],
    max_distance: usize,
    index: &DictIndex,
) -> Option<(usize, usize)> {
    if input.len() < MIN_MATCH_LEN {
        return None;
    }
    let h = hash4(input) & (DICT_HASH_SIZE - 1);
    let mut e = index_u32(index.head, h);
    let mut best: Option<(usize, usize)> = None;
    while e != u32::MAX {
        let slot = e as usize;
        let packed = index_u32(index.entry, slot);
        e = index_u32(index.next, slot);
        let word_len = (packed >> 20) as usize;
        if word_len > input.len() {
            continue;
        }
        if best.is_some_and(|(l, _)| l >= word_len) {
            continue;
        }
        let word_idx = (packed & 0xF_FFFF) as usize;
        let dict_offset = OFFSETS_BY_LENGTH[word_len] + word_idx * word_len;
        if DICTIONARY_DATA[dict_offset..dict_offset + word_len] == input[..word_len] {
            // Transform 0 is the identity transform; other transforms
            // change the emitted length, which must match the decoded
            // dictionary output exactly.
            let distance = max_distance + 1 + word_idx;
            if encode_distance(distance).is_some() {
                best = Some((word_len, distance));
            }
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Distance encoding
// ---------------------------------------------------------------------------

fn encode_distance(distance: usize) -> Option<(u16, u32, u8)> {
    if distance == 0 {
        return None;
    }
    // Distance codes come in pairs. Pair `m` (1..=24) holds
    // `1 << (m + 1)` values starting at `1 << (m + 1) - 3`, and
    // `m = floor(log2(distance + 3)) - 1`. This is the same partition
    // the linear scan used: `ndistbits = m`, even code then odd code.
    let adjusted = distance.checked_add(3)?;
    let floor_log = usize::BITS - adjusted.leading_zeros() - 1;
    if floor_log < 2 {
        return None;
    }
    let pair = floor_log as usize - 1;
    if pair > 24 {
        return None;
    }
    let start = (1usize << (pair + 1)) - 3;
    let half = 1usize << pair;
    let odd = distance >= start + half;
    let hcode = 2 * (pair - 1) + usize::from(odd);
    let base = if odd { start + half } else { start };
    Some(((16 + hcode) as u16, (distance - base) as u32, pair as u8))
}

// ---------------------------------------------------------------------------
// Command symbol encoding
// ---------------------------------------------------------------------------

fn find_command_symbol(insert_len: usize, copy_len: usize) -> Option<(u16, u32, u8, u32, u8)> {
    let ic = find_length_code(
        insert_len,
        &INSERT_LENGTH_OFFSETS,
        &INSERT_LENGTH_EXTRA_BITS,
    )?;
    let cc = find_length_code(copy_len, &COPY_LENGTH_OFFSETS, &COPY_LENGTH_EXTRA_BITS)?;
    let ie = (insert_len - INSERT_LENGTH_OFFSETS[ic]) as u32;
    let ce = (copy_len - COPY_LENGTH_OFFSETS[cc]) as u32;
    let tp = ((ic >> 3) << 3) | (cc >> 3);
    for (ci, &pos) in COMMAND_CELL_POS.iter().enumerate() {
        if pos == tp && ci >= 2 {
            let sym = (ci << 6) | ((ic & 7) << 3) | (cc & 7);
            if sym < 704 {
                return Some((
                    sym as u16,
                    ie,
                    INSERT_LENGTH_EXTRA_BITS[ic],
                    ce,
                    COPY_LENGTH_EXTRA_BITS[cc],
                ));
            }
        }
    }
    None
}

fn find_length_code(len: usize, offsets: &[usize; 24], extra_bits: &[u8; 24]) -> Option<usize> {
    for code in (0..24).rev() {
        if len >= offsets[code] && len <= offsets[code] + ((1usize << extra_bits[code]) - 1) {
            return Some(code);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Huffman tree building
// ---------------------------------------------------------------------------

fn build_code_lengths(freqs: &[u32], max_bits: u8) -> Vec<u8> {
    let alphabet_size = freqs.len();
    let mut code_lengths = vec![0u8; alphabet_size];
    let mut symbols: Vec<(usize, u32)> = freqs
        .iter()
        .copied()
        .enumerate()
        .filter(|&(_, f)| f > 0)
        .collect();
    if symbols.is_empty() {
        return code_lengths;
    }
    if symbols.len() == 1 {
        code_lengths[symbols[0].0] = 1;
        return code_lengths;
    }
    symbols.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let n = symbols.len();
    let mut depths = vec![0u8; n];
    let leaf_freqs: Vec<u64> = symbols.iter().map(|&(_, f)| f as u64).collect();
    let mut int_freqs: Vec<u64> = Vec::with_capacity(n);
    let mut int_leaves: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut li = 0usize;
    let mut ii = 0usize;
    for _ in 0..n - 1 {
        let (f1, l1) = pick_min(&leaf_freqs, &mut li, &int_freqs, &int_leaves, &mut ii);
        let (f2, l2) = pick_min(&leaf_freqs, &mut li, &int_freqs, &int_leaves, &mut ii);
        for &idx in l1.iter().chain(l2.iter()) {
            depths[idx] += 1;
        }
        let mut merged = l1;
        merged.extend_from_slice(&l2);
        int_freqs.push(f1 + f2);
        int_leaves.push(merged);
    }
    for d in depths.iter_mut() {
        if *d > max_bits {
            *d = max_bits;
        }
    }
    fix_kraft(&mut depths, max_bits);
    for (i, &d) in depths.iter().enumerate() {
        code_lengths[symbols[i].0] = d;
    }
    code_lengths
}

fn pick_min(
    lf: &[u64],
    li: &mut usize,
    inf: &[u64],
    inl: &[Vec<usize>],
    ii: &mut usize,
) -> (u64, Vec<usize>) {
    let la = *li < lf.len();
    let ia = *ii < inf.len();
    match (la, ia) {
        (true, false) => {
            let i = *li;
            *li += 1;
            (lf[i], vec![i])
        }
        (false, true) => {
            let i = *ii;
            *ii += 1;
            (inf[i], inl[i].clone())
        }
        (true, true) => {
            if lf[*li] <= inf[*ii] {
                let i = *li;
                *li += 1;
                (lf[i], vec![i])
            } else {
                let i = *ii;
                *ii += 1;
                (inf[i], inl[i].clone())
            }
        }
        _ => unreachable!(),
    }
}

fn fix_kraft(depths: &mut [u8], max_bits: u8) {
    let limit = max_bits as i64;
    for _ in 0..1000 {
        let kraft: i64 = depths
            .iter()
            .filter(|&&d| d > 0)
            .map(|&d| 1i64 << (limit - d as i64))
            .sum();
        let target = 1i64 << limit;
        if kraft == target {
            return;
        }
        if kraft > target {
            let mut best_i = None;
            let mut best_d = max_bits + 1;
            for (i, &d) in depths.iter().enumerate() {
                if d > 0 && d < max_bits && d < best_d {
                    best_d = d;
                    best_i = Some(i);
                }
            }
            if let Some(i) = best_i {
                depths[i] += 1;
            } else {
                break;
            }
        } else {
            let mut best_i = None;
            let mut best_d = 0u8;
            for (i, &d) in depths.iter().enumerate() {
                if d > 1 && d > best_d {
                    best_d = d;
                    best_i = Some(i);
                }
            }
            if let Some(i) = best_i {
                depths[i] -= 1;
            } else {
                break;
            }
        }
    }
}

fn build_codebook_from_lengths(code_lengths: &[u8]) -> Vec<Option<(u32, u8)>> {
    let sz = code_lengths.len();
    // A code with a single non-zero length is a singleton prefix
    // code: the decoder consumes zero bits per symbol (RFC 7932
    // §3.4), so the emitted code must be zero bits too.
    if code_lengths.iter().filter(|&&l| l != 0).count() == 1 {
        let mut cb = vec![None; sz];
        for (i, &l) in code_lengths.iter().enumerate() {
            if l > 0 {
                cb[i] = Some((0, 0));
            }
        }
        return cb;
    }
    let max_bits = code_lengths.iter().copied().max().unwrap_or(0);
    if max_bits == 0 {
        let mut cb = vec![None; sz];
        for (i, &l) in code_lengths.iter().enumerate() {
            if l > 0 {
                cb[i] = Some((0, 0));
            }
        }
        return cb;
    }
    let mut bl_count = vec![0u32; max_bits as usize + 1];
    for &len in code_lengths.iter() {
        if len != 0 {
            bl_count[len as usize] += 1;
        }
    }
    let mut next_code = vec![0u32; max_bits as usize + 1];
    let mut code = 0u32;
    for bits in 1..=max_bits {
        code = (code + bl_count[(bits - 1) as usize]) << 1;
        next_code[bits as usize] = code;
    }
    let mut cb = vec![None; sz];
    for (sym, &len) in code_lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let c = next_code[len as usize];
        next_code[len as usize] += 1;
        cb[sym] = Some((reverse_bits(c, len), len));
    }
    cb
}

// ---------------------------------------------------------------------------
// Complex prefix code writing
// ---------------------------------------------------------------------------

fn write_prefix_code(writer: &mut BitWriter, code_lengths: &[u8], alpha_bits: u8) {
    if writer.exceeded {
        return;
    }
    let nz: Vec<u16> = code_lengths
        .iter()
        .enumerate()
        .filter(|&(_, &l)| l > 0)
        .map(|(i, _)| i as u16)
        .collect();
    if nz.is_empty() {
        write_singleton_prefix_code(writer, 0, alpha_bits);
        return;
    }
    if nz.len() == 1 {
        write_singleton_prefix_code(writer, nz[0], alpha_bits);
        return;
    }
    if nz.len() <= 4 {
        if let Some(ts) = matches_simple_code(code_lengths, &nz) {
            write_simple_prefix_code(writer, &nz, alpha_bits, ts);
            return;
        }
    }
    write_complex_prefix_code(writer, code_lengths);
}

fn matches_simple_code(cl: &[u8], nz: &[u16]) -> Option<Option<bool>> {
    let lens: Vec<u8> = nz.iter().map(|&s| cl[s as usize]).collect();
    match lens.as_slice() {
        [1, 1] => Some(None),
        [1, 2, 2] => Some(None),
        [2, 2, 2, 2] => Some(Some(false)),
        [1, 2, 3, 3] => Some(Some(true)),
        _ => None,
    }
}

fn write_complex_prefix_code(writer: &mut BitWriter, code_lengths: &[u8]) {
    let mut cl_freqs = [0u32; 18];
    for &len in code_lengths.iter() {
        cl_freqs[len as usize] += 1;
    }
    let cl_cl = build_cl_code_lengths(&cl_freqs);

    let mut hskip: u8 = 0;
    for &sym in &CODE_LENGTH_CODE_ORDER {
        if cl_cl[sym as usize] != 0 {
            break;
        }
        hskip += 1;
    }
    if hskip == 1 {
        hskip = 0;
    }
    if hskip > 3 {
        hskip = 3;
    }

    writer.write_bits(u32::from(hskip), 2);

    let mut space = 32i32;
    for (i, &sym) in CODE_LENGTH_CODE_ORDER.iter().enumerate() {
        if (i as u8) < hskip {
            continue;
        }
        let cl_len = cl_cl[sym as usize];
        write_small_code_length(writer, cl_len);
        if cl_len != 0 {
            space -= 32 >> cl_len;
            if space <= 0 {
                break;
            }
        }
    }

    // RFC 7932 §3.5: the decoder stops reading code lengths once the
    // code is complete (kraft space exhausted) or all symbols are
    // covered. Emit only up to the same point — trailing symbols
    // would desync the stream.
    let cl_cb = build_codebook_from_lengths(&cl_cl);
    let mut space = 32768i64;
    for &len in code_lengths.iter() {
        let (bits, nbits) = cl_cb[len as usize].unwrap_or((0, 0));
        writer.write_bits(bits, nbits);
        if len != 0 {
            space -= 32768 >> len;
            if space == 0 {
                break;
            }
        }
    }
}

fn build_cl_code_lengths(freqs: &[u32; 18]) -> [u8; 18] {
    let mut lengths = [0u8; 18];
    let mut symbols: Vec<(usize, u32)> = freqs
        .iter()
        .copied()
        .enumerate()
        .filter(|&(_, f)| f > 0)
        .collect();
    if symbols.is_empty() {
        return lengths;
    }
    if symbols.len() == 1 {
        lengths[symbols[0].0] = 1;
        return lengths;
    }
    symbols.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let n = symbols.len();
    if n == 2 {
        lengths[symbols[0].0] = 1;
        lengths[symbols[1].0] = 1;
        return lengths;
    }
    let mut depths = vec![0u8; n];
    let lf: Vec<u64> = symbols.iter().map(|&(_, f)| f as u64).collect();
    let mut inf: Vec<u64> = Vec::with_capacity(n);
    let mut inl: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut li = 0usize;
    let mut ii = 0usize;
    for _ in 0..n - 1 {
        let (f1, l1) = pick_min(&lf, &mut li, &inf, &inl, &mut ii);
        let (f2, l2) = pick_min(&lf, &mut li, &inf, &inl, &mut ii);
        for &idx in l1.iter().chain(l2.iter()) {
            depths[idx] += 1;
        }
        let mut m = l1;
        m.extend_from_slice(&l2);
        inf.push(f1 + f2);
        inl.push(m);
    }
    for d in depths.iter_mut() {
        if *d > 5 {
            *d = 5;
        }
    }
    fix_kraft(&mut depths, 5);
    for (i, &d) in depths.iter().enumerate() {
        lengths[symbols[i].0] = d;
    }
    lengths
}

fn write_small_code_length(writer: &mut BitWriter, value: u8) {
    match value {
        0 => writer.write_bits(0b00, 2),
        4 => writer.write_bits(0b01, 2),
        3 => writer.write_bits(0b10, 2),
        2 => writer.write_bits(0b011, 3),
        1 => writer.write_bits(0b0111, 4),
        5 => writer.write_bits(0b1111, 4),
        _ => writer.write_bits(0b1111, 4),
    }
}

// ---------------------------------------------------------------------------
// VarLenUint8
// ---------------------------------------------------------------------------

fn write_var_len_uint8(writer: &mut BitWriter, value: usize) {
    assert!(value >= 1 && value <= 256);
    if value == 1 {
        writer.write_bits(0, 1);
    } else {
        writer.write_bits(1, 1);
        let v = value - 1;
        if v == 1 {
            writer.write_bits(0, 3);
        } else {
            let nbits = 63 - (v as u64).leading_zeros();
            let extra = v - (1usize << nbits);
            writer.write_bits(nbits, 3);
            writer.write_bits(extra as u32, nbits as u8);
        }
    }
}

// ---------------------------------------------------------------------------
// Context map writing
// ---------------------------------------------------------------------------

fn write_context_map(writer: &mut BitWriter, _size: usize, ntrees: usize, map: &[u8]) {
    writer.write_bits(0, 1); // rlemax=0
    let mut freqs = vec![0u32; ntrees];
    for &v in map {
        freqs[v as usize] += 1;
    }
    let cl = build_code_lengths(&freqs, 15);
    let cb = build_codebook_from_lengths(&cl);
    write_prefix_code(writer, &cl, alphabet_bits(ntrees));
    for &v in map {
        if let Some((bits, nbits)) = cb[v as usize] {
            writer.write_bits(bits, nbits);
        }
    }
    writer.write_bits(0, 1); // imtf=0
}

fn find_block_length_symbol(length: usize) -> Option<(usize, u32, u8)> {
    for (s, (&o, &e)) in BLOCK_LENGTH_PREFIX_OFFSETS
        .iter()
        .zip(BLOCK_LENGTH_PREFIX_EXTRA_BITS.iter())
        .enumerate()
    {
        if (o..=o + (1usize << e) - 1).contains(&length) {
            return Some((s, (length - o) as u32, e));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Single-block LZ77
// ---------------------------------------------------------------------------

fn try_lz77_metablock(
    chunk: &[u8],
    commands: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    write_lz77_single_block(chunk, commands, bit_limit)
}

fn encode_commands(
    commands: &[Lz77Command],
) -> Option<(Vec<EncodedCommand>, Vec<u32>, Vec<u32>, Vec<u32>)> {
    let mut lf = vec![0u32; 256];
    let mut cf = vec![0u32; 704];
    let mut df = vec![0u32; DISTANCE_ALPHABET_SIZE];
    let mut enc = Vec::with_capacity(commands.len());
    for cmd in commands {
        match cmd {
            Lz77Command::InsertCopy {
                literals,
                copy_len,
                distance,
            } => {
                for &l in literals.iter() {
                    lf[l as usize] += 1;
                }
                let (sym, ie, ieb, ce, ceb) = find_command_symbol(literals.len(), *copy_len)?;
                cf[sym as usize] += 1;
                let (dc, de, dnb) = encode_distance(*distance)?;
                df[dc as usize] += 1;
                enc.push(EncodedCommand {
                    command_symbol: sym,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: ce,
                    copy_extra_bits: ceb,
                    distance_code: dc,
                    distance_extra: de,
                    distance_extra_bits: dnb,
                    has_distance: true,
                });
            }
            Lz77Command::InsertOnly { literals } => {
                for &l in literals.iter() {
                    lf[l as usize] += 1;
                }
                let (sym, ie, ieb, ceb) = find_insert_only_command(literals.len())?;
                cf[sym as usize] += 1;
                enc.push(EncodedCommand {
                    command_symbol: sym,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: 0,
                    copy_extra_bits: ceb,
                    distance_code: 0,
                    distance_extra: 0,
                    distance_extra_bits: 0,
                    has_distance: false,
                });
            }
        }
    }
    Some((enc, lf, cf, df))
}

fn write_lz77_single_block(
    chunk: &[u8],
    commands: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    let (enc, lf, cf, df) = encode_commands(commands)?;
    let lcl = build_code_lengths(&lf, 15);
    let ccl = build_code_lengths(&cf, 15);
    let dcl = build_code_lengths(&df, 15);
    let lcb = build_codebook_from_lengths(&lcl);
    let ccb = build_codebook_from_lengths(&ccl);
    let dcb = build_codebook_from_lengths(&dcl);
    let mut w = BitWriter::with_limit(bit_limit);
    w.write_bits(0, 1);
    write_metablock_len(&mut w, chunk.len());
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(u32::from(NPOSTFIX), 2);
    w.write_bits(0, 4);
    w.write_bits(0, 2);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    write_prefix_code(&mut w, &lcl, alphabet_bits(256));
    write_prefix_code(&mut w, &ccl, alphabet_bits(704));
    write_prefix_code(&mut w, &dcl, alphabet_bits(DISTANCE_ALPHABET_SIZE));
    write_cmd_data(&mut w, commands, &enc, &lcb, &ccb, &dcb);
    w.finish_if_within_limit()
}

fn write_cmd_data(
    w: &mut BitWriter,
    cmds: &[Lz77Command],
    enc: &[EncodedCommand],
    lcb: &[Option<(u32, u8)>],
    ccb: &[Option<(u32, u8)>],
    dcb: &[Option<(u32, u8)>],
) {
    for (cmd, e) in cmds.iter().zip(enc.iter()) {
        if w.exceeded {
            return;
        }
        let lits = match cmd {
            Lz77Command::InsertCopy { literals, .. } | Lz77Command::InsertOnly { literals } => {
                literals.as_slice()
            }
        };
        if let Some((b, n)) = ccb[e.command_symbol as usize] {
            w.write_bits(b, n);
        }
        w.write_bits(e.insert_extra, e.insert_extra_bits);
        w.write_bits(e.copy_extra, e.copy_extra_bits);
        for &l in lits {
            if let Some((b, n)) = lcb[l as usize] {
                w.write_bits(b, n);
            }
        }
        if e.has_distance {
            if let Some((b, n)) = dcb[e.distance_code as usize] {
                w.write_bits(b, n);
            }
            w.write_bits(e.distance_extra, e.distance_extra_bits);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_cmd_data_ctx(
    w: &mut BitWriter,
    input: &[u8],
    start: usize,
    cmds: &[Lz77Command],
    enc: &[EncodedCommand],
    lcbs: &[Vec<Option<(u32, u8)>>],
    ccb: &[Option<(u32, u8)>],
    dcb: &[Option<(u32, u8)>],
    cmap: &[u8],
) {
    let mut out = start;
    for (cmd, e) in cmds.iter().zip(enc.iter()) {
        if w.exceeded {
            return;
        }
        let lits = match cmd {
            Lz77Command::InsertCopy { literals, .. } | Lz77Command::InsertOnly { literals } => {
                literals.as_slice()
            }
        };
        if let Some((b, n)) = ccb[e.command_symbol as usize] {
            w.write_bits(b, n);
        }
        w.write_bits(e.insert_extra, e.insert_extra_bits);
        w.write_bits(e.copy_extra, e.copy_extra_bits);
        for &l in lits {
            // The decoder derives the literal context from the last
            // produced byte; produced plaintext equals `input`.
            let p1 = if out == 0 { 0 } else { input[out - 1] };
            let ci = (p1 & 0x3F) as usize;
            let ti = cmap[ci] as usize;
            if let Some((b, n)) = lcbs[ti][l as usize] {
                w.write_bits(b, n);
            }
            out += 1;
        }
        if e.has_distance {
            if let Some((b, n)) = dcb[e.distance_code as usize] {
                w.write_bits(b, n);
            }
            w.write_bits(e.distance_extra, e.distance_extra_bits);
            if let Lz77Command::InsertCopy { copy_len, .. } = cmd {
                out += copy_len;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_cmd_data_bt(
    w: &mut BitWriter,
    cmds: &[Lz77Command],
    enc: &[EncodedCommand],
    lcbs: &[Vec<Option<(u32, u8)>>],
    ccb: &[Option<(u32, u8)>],
    dcb: &[Option<(u32, u8)>],
    mid: usize,
    blcb: &[Option<(u32, u8)>],
    second_len: (usize, u32, u8),
) {
    let mut lp = 0usize;
    let mut switched = false;
    for (cmd, e) in cmds.iter().zip(enc.iter()) {
        if w.exceeded {
            return;
        }
        let lits = match cmd {
            Lz77Command::InsertCopy { literals, .. } | Lz77Command::InsertOnly { literals } => {
                literals.as_slice()
            }
        };
        if let Some((b, n)) = ccb[e.command_symbol as usize] {
            w.write_bits(b, n);
        }
        w.write_bits(e.insert_extra, e.insert_extra_bits);
        w.write_bits(e.copy_extra, e.copy_extra_bits);
        for &l in lits {
            // The literal block type counts literals only. The decoder
            // consumes the block switch lazily, immediately before
            // reading literal `mid` and after the enclosing command's
            // symbol and extra bits, so emit it at that exact point.
            if lp == mid && !switched {
                // The block-type tree is a singleton prefix code, so
                // the type code itself emits zero bits; only the
                // block-length code and its extra bits are written.
                let (bs, be, beb) = second_len;
                if let Some((b, n)) = blcb[bs] {
                    w.write_bits(b, n);
                }
                w.write_bits(be, beb);
                switched = true;
            }
            let ti = usize::from(lp >= mid);
            if let Some((b, n)) = lcbs[ti][l as usize] {
                w.write_bits(b, n);
            }
            lp += 1;
        }
        if e.has_distance {
            if let Some((b, n)) = dcb[e.distance_code as usize] {
                w.write_bits(b, n);
            }
            w.write_bits(e.distance_extra, e.distance_extra_bits);
        }
    }
}
// ---------------------------------------------------------------------------
// Multi-block-type
// ---------------------------------------------------------------------------

fn try_multi_block_lz77(
    chunk: &[u8],
    cmds: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    write_multi_block(chunk, cmds, bit_limit)
}

fn write_multi_block(
    chunk: &[u8],
    cmds: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    let len = chunk.len();
    let total_lits: usize = cmds
        .iter()
        .map(|c| match c {
            Lz77Command::InsertCopy { literals, .. } | Lz77Command::InsertOnly { literals } => {
                literals.len()
            }
        })
        .sum();
    let mid = total_lits / 2;
    if mid == 0 || mid >= total_lits {
        return None;
    }
    let mut lf0 = vec![0u32; 256];
    let mut lf1 = vec![0u32; 256];
    let mut cf = vec![0u32; 704];
    let mut df = vec![0u32; DISTANCE_ALPHABET_SIZE];
    let mut lp = 0usize;
    let mut enc: Vec<EncodedCommand> = Vec::with_capacity(cmds.len());
    for cmd in cmds {
        match cmd {
            Lz77Command::InsertCopy {
                literals,
                copy_len,
                distance,
            } => {
                for &l in literals.iter() {
                    if lp < mid {
                        lf0[l as usize] += 1;
                    } else {
                        lf1[l as usize] += 1;
                    }
                    lp += 1;
                }
                let (s, ie, ieb, ce, ceb) = find_command_symbol(literals.len(), *copy_len)?;
                cf[s as usize] += 1;
                let (dc, de, dnb) = encode_distance(*distance)?;
                df[dc as usize] += 1;
                enc.push(EncodedCommand {
                    command_symbol: s,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: ce,
                    copy_extra_bits: ceb,
                    distance_code: dc,
                    distance_extra: de,
                    distance_extra_bits: dnb,
                    has_distance: true,
                });
            }
            Lz77Command::InsertOnly { literals } => {
                for &l in literals.iter() {
                    if lp < mid {
                        lf0[l as usize] += 1;
                    } else {
                        lf1[l as usize] += 1;
                    }
                    lp += 1;
                }
                let (s, ie, ieb, ceb) = find_insert_only_command(literals.len())?;
                cf[s as usize] += 1;
                enc.push(EncodedCommand {
                    command_symbol: s,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: 0,
                    copy_extra_bits: ceb,
                    distance_code: 0,
                    distance_extra: 0,
                    distance_extra_bits: 0,
                    has_distance: false,
                });
            }
        }
    }
    if !lf0.iter().any(|&f| f > 0) || !lf1.iter().any(|&f| f > 0) {
        return None;
    }
    let lcl0 = build_code_lengths(&lf0, 15);
    let lcl1 = build_code_lengths(&lf1, 15);
    let ccl = build_code_lengths(&cf, 15);
    let dcl = build_code_lengths(&df, 15);
    let lcb0 = build_codebook_from_lengths(&lcl0);
    let lcb1 = build_codebook_from_lengths(&lcl1);
    let ccb = build_codebook_from_lengths(&ccl);
    let dcb = build_codebook_from_lengths(&dcl);
    let rem = total_lits.saturating_sub(mid);
    let (bs0, be0, beb0) = find_block_length_symbol(mid.max(1)).unwrap_or((25, 0, 24));
    let (bs1, be1, beb1) = find_block_length_symbol(rem.max(1)).unwrap_or((25, 0, 24));
    let mut w = BitWriter::with_limit(bit_limit);
    w.write_bits(0, 1);
    write_metablock_len(&mut w, len);
    w.write_bits(0, 1);
    write_var_len_uint8(&mut w, 2);
    write_singleton_prefix_code(&mut w, 1, alphabet_bits(4));
    if bs0 == bs1 {
        write_singleton_prefix_code(&mut w, bs0 as u16, alphabet_bits(26));
    } else {
        let syms = if bs0 < bs1 {
            [bs0 as u16, bs1 as u16]
        } else {
            [bs1 as u16, bs0 as u16]
        };
        write_simple_prefix_code(&mut w, &syms, alphabet_bits(26), None);
    }
    let mut blcb = vec![None; 26];
    if bs0 == bs1 {
        // singleton block-length tree: zero bits per symbol
        blcb[bs0] = Some((0, 0));
    } else {
        let mut cl = vec![0u8; 26];
        cl[bs0] = 1;
        cl[bs1] = 1;
        blcb = build_codebook_from_lengths(&cl);
        if let Some((b, n)) = blcb[bs0] {
            w.write_bits(b, n);
        }
    }
    w.write_bits(be0, beb0);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(u32::from(NPOSTFIX), 2);
    w.write_bits(0, 4);
    w.write_bits(0, 2);
    w.write_bits(0, 2);
    write_var_len_uint8(&mut w, 2);
    let cmap: Vec<u8> = (0..128).map(|i| if i < 64 { 0 } else { 1 }).collect();
    write_context_map(&mut w, 128, 2, &cmap);
    w.write_bits(0, 1);
    write_prefix_code(&mut w, &lcl0, alphabet_bits(256));
    write_prefix_code(&mut w, &lcl1, alphabet_bits(256));
    write_prefix_code(&mut w, &ccl, alphabet_bits(704));
    write_prefix_code(&mut w, &dcl, alphabet_bits(DISTANCE_ALPHABET_SIZE));
    write_cmd_data_bt(
        &mut w,
        cmds,
        &enc,
        &[lcb0, lcb1],
        &ccb,
        &dcb,
        mid,
        &blcb,
        (bs1, be1, beb1),
    );
    w.finish_if_within_limit()
}

// ---------------------------------------------------------------------------
// Context modeling
// ---------------------------------------------------------------------------

fn try_context_modeling_lz77(
    input: &[u8],
    start: usize,
    cmds: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    write_ctx_model(input, start, cmds, bit_limit)
}

fn write_ctx_model(
    input: &[u8],
    start: usize,
    cmds: &[Lz77Command],
    bit_limit: usize,
) -> Option<(Vec<u8>, usize)> {
    let chunk = &input[start..start + (input.len() - start).min(MAX_METABLOCK_LEN)];
    let len = chunk.len();
    let mut lf0 = vec![0u32; 256];
    let mut lf1 = vec![0u32; 256];
    let mut cf = vec![0u32; 704];
    let mut df = vec![0u32; DISTANCE_ALPHABET_SIZE];
    // `out` tracks the absolute output position. The produced
    // plaintext equals `input`, so the literal context byte is
    // `input[out - 1]`; this keeps the encoder's context identical
    // to the decoder's across metablock boundaries, backward
    // copies, and dictionary references.
    let mut out = start;
    let mut enc: Vec<EncodedCommand> = Vec::with_capacity(cmds.len());
    for cmd in cmds {
        match cmd {
            Lz77Command::InsertCopy {
                literals,
                copy_len,
                distance,
            } => {
                for &l in literals.iter() {
                    let p1 = if out == 0 { 0 } else { input[out - 1] };
                    let ci = (p1 & 0x3F) as usize;
                    if ci < 32 {
                        lf0[l as usize] += 1;
                    } else {
                        lf1[l as usize] += 1;
                    }
                    out += 1;
                }
                let (s, ie, ieb, ce, ceb) = find_command_symbol(literals.len(), *copy_len)?;
                cf[s as usize] += 1;
                let (dc, de, dnb) = encode_distance(*distance)?;
                df[dc as usize] += 1;
                out += copy_len;
                enc.push(EncodedCommand {
                    command_symbol: s,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: ce,
                    copy_extra_bits: ceb,
                    distance_code: dc,
                    distance_extra: de,
                    distance_extra_bits: dnb,
                    has_distance: true,
                });
            }
            Lz77Command::InsertOnly { literals } => {
                for &l in literals.iter() {
                    let p1 = if out == 0 { 0 } else { input[out - 1] };
                    let ci = (p1 & 0x3F) as usize;
                    if ci < 32 {
                        lf0[l as usize] += 1;
                    } else {
                        lf1[l as usize] += 1;
                    }
                    out += 1;
                }
                let (s, ie, ieb, ceb) = find_insert_only_command(literals.len())?;
                cf[s as usize] += 1;
                enc.push(EncodedCommand {
                    command_symbol: s,
                    insert_extra: ie,
                    insert_extra_bits: ieb,
                    copy_extra: 0,
                    copy_extra_bits: ceb,
                    distance_code: 0,
                    distance_extra: 0,
                    distance_extra_bits: 0,
                    has_distance: false,
                });
            }
        }
    }
    if !lf0.iter().any(|&f| f > 0) || !lf1.iter().any(|&f| f > 0) {
        return None;
    }
    let lcl0 = build_code_lengths(&lf0, 15);
    let lcl1 = build_code_lengths(&lf1, 15);
    let ccl = build_code_lengths(&cf, 15);
    let dcl = build_code_lengths(&df, 15);
    let lcb0 = build_codebook_from_lengths(&lcl0);
    let lcb1 = build_codebook_from_lengths(&lcl1);
    let ccb = build_codebook_from_lengths(&ccl);
    let dcb = build_codebook_from_lengths(&dcl);
    let mut w = BitWriter::with_limit(bit_limit);
    w.write_bits(0, 1);
    write_metablock_len(&mut w, len);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(0, 1);
    w.write_bits(u32::from(NPOSTFIX), 2);
    w.write_bits(0, 4);
    w.write_bits(0, 2);
    write_var_len_uint8(&mut w, 2);
    let cmap: Vec<u8> = (0..64).map(|i| if i < 32 { 0 } else { 1 }).collect();
    write_context_map(&mut w, 64, 2, &cmap);
    w.write_bits(0, 1);
    write_prefix_code(&mut w, &lcl0, alphabet_bits(256));
    write_prefix_code(&mut w, &lcl1, alphabet_bits(256));
    write_prefix_code(&mut w, &ccl, alphabet_bits(704));
    write_prefix_code(&mut w, &dcl, alphabet_bits(DISTANCE_ALPHABET_SIZE));
    write_cmd_data_ctx(
        &mut w,
        input,
        start,
        cmds,
        &enc,
        &[lcb0, lcb1],
        &ccb,
        &dcb,
        &cmap,
    );
    w.finish_if_within_limit()
}

// ---------------------------------------------------------------------------
// Legacy literal-only path
// ---------------------------------------------------------------------------

fn compressed_literal_symbols(chunk: &[u8]) -> Option<Vec<u16>> {
    let _ = chunk.first()?;
    if repeated_pattern(chunk).is_some() {
        return Some(distinct_symbols_in_order(chunk));
    }
    if chunk.len() < MIN_LOW_CARDINALITY_LITERAL_LEN {
        return None;
    }
    let symbols = distinct_symbols_in_order(chunk);
    (symbols.len() <= MAX_COMPRESSED_LITERAL_SYMBOLS).then_some(symbols)
}

fn repeated_pattern(chunk: &[u8]) -> Option<&[u8]> {
    let _ = chunk.first()?;
    if chunk.len() < MIN_COMPRESSED_RUN_LEN {
        return None;
    }
    let max_pattern_len = chunk.len().min(MAX_COMPRESSED_PATTERN_LEN);
    for pattern_len in 1..=max_pattern_len {
        if !chunk.len().is_multiple_of(pattern_len) {
            continue;
        }
        let pattern = &chunk[..pattern_len];
        if chunk
            .iter()
            .enumerate()
            .all(|(i, &b)| b == pattern[i % pattern_len])
        {
            return Some(pattern);
        }
    }
    None
}

fn write_compressed_literal_metablock(
    writer: &mut BitWriter,
    chunk: &[u8],
    literal_symbols: &[u16],
) {
    let len = chunk.len();
    let (command_symbol, insert_extra, insert_extra_bits, copy_extra_bits) =
        find_insert_only_command(len).expect("insert-only command must exist for supported len");
    let tree_select = (literal_symbols.len() == 4).then_some(false);
    let codebook = build_simple_codebook(literal_symbols, 256, tree_select);
    writer.write_bits(0, 1);
    write_metablock_len(writer, len);
    writer.write_bits(0, 1);
    writer.write_bits(0, 1);
    writer.write_bits(0, 1);
    writer.write_bits(0, 1);
    writer.write_bits(0, 2);
    writer.write_bits(0, 4);
    writer.write_bits(0, 2);
    writer.write_bits(0, 1);
    writer.write_bits(0, 1);
    write_simple_prefix_code(writer, literal_symbols, 8, tree_select);
    write_singleton_prefix_code(writer, command_symbol, 10);
    write_singleton_prefix_code(writer, 0, 6);
    writer.write_bits(insert_extra, insert_extra_bits);
    writer.write_bits(0, copy_extra_bits);
    for &byte in chunk {
        if writer.exceeded {
            return;
        }
        let (bits, nbits) = codebook[byte as usize].expect("literal must be in codebook");
        writer.write_bits(bits, nbits);
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn write_metablock_len(writer: &mut BitWriter, len: usize) {
    assert!(len > 0 && len <= MAX_METABLOCK_LEN);
    let (code, nibbles) = if len <= 0x1_0000 {
        (0u32, 4u8)
    } else if len <= 0x10_0000 {
        (1u32, 5u8)
    } else {
        (2u32, 6u8)
    };
    writer.write_bits(code, 2);
    writer.write_bits((len - 1) as u32, nibbles * 4);
}

fn write_singleton_prefix_code(writer: &mut BitWriter, symbol: u16, width: u8) {
    writer.write_bits(1, 2);
    writer.write_bits(0, 2);
    writer.write_bits(symbol.into(), width);
}

fn write_simple_prefix_code(
    writer: &mut BitWriter,
    symbols: &[u16],
    width: u8,
    tree_select: Option<bool>,
) {
    assert!(!symbols.is_empty() && symbols.len() <= 4);
    writer.write_bits(1, 2);
    writer.write_bits((symbols.len() - 1) as u32, 2);
    for &s in symbols {
        writer.write_bits(s.into(), width);
    }
    if symbols.len() == 4 {
        writer.write_bits(u32::from(tree_select.unwrap_or(false)), 1);
    }
}

fn distinct_symbols_in_order(pattern: &[u8]) -> Vec<u16> {
    let mut symbols = Vec::with_capacity(pattern.len());
    for &byte in pattern {
        let s = u16::from(byte);
        if !symbols.contains(&s) {
            symbols.push(s);
        }
    }
    symbols
}

fn build_simple_codebook(
    symbols: &[u16],
    alphabet_size: usize,
    tree_select: Option<bool>,
) -> Vec<Option<(u32, u8)>> {
    if symbols.len() == 1 {
        let mut cb = vec![None; alphabet_size];
        cb[symbols[0] as usize] = Some((0, 0));
        return cb;
    }
    let cl = huffman::simple_code_lengths(symbols, tree_select, alphabet_size)
        .expect("simple prefix code");
    build_codebook_from_lengths(&cl)
}

fn reverse_bits(mut value: u32, num_bits: u8) -> u32 {
    let mut result = 0u32;
    for _ in 0..num_bits {
        result = (result << 1) | (value & 1);
        value >>= 1;
    }
    result
}

fn find_insert_only_command(len: usize) -> Option<(u16, u32, u8, u8)> {
    for symbol in 0..704usize {
        let cell_pos = *COMMAND_CELL_POS.get(symbol >> 6)?;
        let insert_code = (cell_pos & 0x18) + ((symbol >> 3) & 0x7);
        let copy_code = ((cell_pos << 3) & 0x18) + (symbol & 0x7);
        let base = *INSERT_LENGTH_OFFSETS.get(insert_code)?;
        let extra_bits = *INSERT_LENGTH_EXTRA_BITS.get(insert_code)?;
        let max = base + ((1usize << extra_bits) - 1);
        if (base..=max).contains(&len) {
            return Some((
                symbol as u16,
                (len - base) as u32,
                extra_bits,
                COPY_LENGTH_EXTRA_BITS[copy_code],
            ));
        }
    }
    None
}

const fn alphabet_bits(alphabet_size: usize) -> u8 {
    let mut bits = 0u8;
    let mut limit = 1usize;
    while limit < alphabet_size {
        bits += 1;
        limit <<= 1;
    }
    bits
}

// ---------------------------------------------------------------------------
// BitWriter
// ---------------------------------------------------------------------------

struct BitWriter {
    bytes: Vec<u8>,
    current: u8,
    bit_pos: u8,
    total_bits: usize,
    /// Stop storing bits once `total_bits` would reach this value.
    limit: Option<usize>,
    exceeded: bool,
}

impl BitWriter {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            current: 0,
            bit_pos: 0,
            total_bits: 0,
            limit: None,
            exceeded: false,
        }
    }

    fn with_limit(limit: usize) -> Self {
        Self {
            limit: Some(limit),
            ..Self::new()
        }
    }

    fn write_bits(&mut self, value: u32, nbits: u8) {
        if self.exceeded || nbits == 0 {
            return;
        }
        let next = self.total_bits.saturating_add(usize::from(nbits));
        if self.limit.is_some_and(|limit| next >= limit) {
            self.exceeded = true;
            return;
        }
        self.total_bits = next;
        for i in 0..nbits {
            self.current |= (((value >> i) & 1) as u8) << self.bit_pos;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bytes.push(self.current);
                self.current = 0;
                self.bit_pos = 0;
            }
        }
    }
    fn align_zero(&mut self) {
        if self.exceeded {
            return;
        }
        if self.bit_pos != 0 {
            self.bytes.push(self.current);
            self.current = 0;
            self.bit_pos = 0;
        }
    }
    fn write_bytes(&mut self, bytes: &[u8]) {
        if self.exceeded {
            return;
        }
        self.align_zero();
        self.bytes.extend_from_slice(bytes);
    }
    fn write_raw(&mut self, bytes: &[u8], total_bits: usize) {
        let mut left = total_bits;
        for &b in bytes {
            let n = left.min(8) as u8;
            self.write_bits(u32::from(b), n);
            left -= n as usize;
            if left == 0 {
                break;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        self.align_zero();
        self.bytes
    }

    /// Bytes and bit count when the stream stayed strictly under `limit`.
    fn finish_if_within_limit(self) -> Option<(Vec<u8>, usize)> {
        if self.exceeded {
            None
        } else {
            let total_bits = self.total_bits;
            Some((self.finish(), total_bits))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::brotli::decode;

    #[test]
    fn test_brotli_encode_roundtrip_empty() {
        let e = encode(b"");
        assert_eq!(decode::decode(&e).unwrap(), b"");
    }
    #[test]
    fn test_brotli_encode_roundtrip_small_payload() {
        let i = b"Hello, Brotli encoder!";
        let e = encode(i);
        assert_eq!(decode::decode(&e).unwrap(), i);
    }
    #[test]
    fn test_brotli_encode_roundtrip_large_payload() {
        let i = b"abcde".repeat(70_000);
        let e = encode(&i);
        assert_eq!(decode::decode(&e).unwrap(), i);
    }
    #[test]
    fn test_brotli_encode_repeated_run_uses_compressed_metablock() {
        let i = vec![b'A'; 64];
        let e = encode(&i);
        assert_eq!(decode::decode(&e).unwrap(), i);
        assert!(e.len() < 20);
    }
    #[test]
    fn test_brotli_encode_large_repeated_run_roundtrips() {
        let i = vec![b'Z'; 4096];
        let e = encode(&i);
        assert_eq!(decode::decode(&e).unwrap(), i);
        assert!(e.len() < 32);
    }
    #[test]
    fn test_brotli_encode_two_byte_pattern_uses_compressed_metablock() {
        let i = b"ab".repeat(128);
        let e = encode(&i);
        assert_eq!(decode::decode(&e).unwrap(), i);
        assert!(e.len() < 48);
    }
    #[test]
    fn test_brotli_encode_four_byte_pattern_uses_compressed_metablock() {
        let i = b"ABCD".repeat(128);
        let e = encode(&i);
        assert_eq!(decode::decode(&e).unwrap(), i);
        assert!(e.len() < 160);
    }

    #[test]
    fn test_brotli_encode_low_cardinality_literals_use_compressed_metablock() {
        let mut state = 0x1234_5678u32;
        let alphabet = *b"ABCD";
        let input: Vec<u8> = (0..1024)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                alphabet[((state >> 16) & 0x3) as usize]
            })
            .collect();
        assert!(repeated_pattern(&input).is_none());
        let symbols = compressed_literal_symbols(&input).unwrap();
        assert_eq!(symbols.len(), 4);
        let encoded = encode(&input);
        assert_eq!(decode::decode(&encoded).unwrap(), input);
        assert!(encoded.len() < input.len());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_brotli_encode_writer_matches_encode() {
        let i = b"writer path";
        let e = encode(i);
        let mut o = Vec::new();
        let w = encode_writer(i, &mut o).unwrap();
        assert_eq!(w, e.len());
        assert_eq!(o, e);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_brotli_encode_writer_matches_encode_for_repeated_pattern() {
        let i = b"abcd".repeat(96);
        let e = encode(&i);
        let mut o = Vec::new();
        let w = encode_writer(&i, &mut o).unwrap();
        assert_eq!(w, e.len());
        assert_eq!(o, e);
    }

    #[test]
    fn test_lz77_english_text_roundtrip() {
        let input = b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
        let encoded = encode(input);
        assert_eq!(decode::decode(&encoded).unwrap(), input);
    }

    #[test]
    fn test_lz77_repetitive_data_compresses() {
        let mut input = Vec::new();
        for _ in 0..100 {
            input.extend_from_slice(b"Hello World! This is a test of the LZ77 encoder. ");
        }
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert!(encoded.len() < input.len() / 2);
    }

    #[test]
    fn test_dictionary_match_roundtrip() {
        let i = b"the of and in to for a that with from";
        let e = encode(i);
        assert_eq!(decode::decode(&e).unwrap(), i);
    }
    #[test]
    fn test_metadata_roundtrip() {
        let i = b"Hello, metadata world!";
        let m = b"custom metadata payload";
        let e = encode_with_metadata(i, m);
        assert_eq!(decode::decode(&e).unwrap(), i);
    }

    #[test]
    fn test_multi_block_roundtrip() {
        let mut input = Vec::new();
        for _ in 0..200 {
            input.extend_from_slice(b"aaabbbccc");
        }
        for _ in 0..200 {
            input.extend_from_slice(b"xxxyyyzzzwww");
        }
        let encoded = encode(&input);
        assert_eq!(decode::decode(&encoded).unwrap(), input);
    }

    #[test]
    fn test_context_modeling_roundtrip() {
        let mut input = Vec::new();
        for _ in 0..50 {
            input.extend_from_slice(b"hello world ");
            input.extend_from_slice(b"12345 67890 ");
        }
        let encoded = encode(&input);
        assert_eq!(decode::decode(&encoded).unwrap(), input);
    }

    /// Wrap a single encoded metablock (`bits`, `total_bits`) in a
    /// complete Brotli stream (default window + trailing empty
    /// last metablock), mirroring the framing in [`encode`].
    fn metablock_stream(bits: &[u8], total_bits: usize) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_bits(0, 1);
        w.write_raw(bits, total_bits);
        w.write_bits(1, 1);
        w.write_bits(1, 1);
        w.finish()
    }

    /// Deterministic low-cardinality pseudo-random data: exercises
    /// the LZ77 match finder while producing enough inserted
    /// literals to cross literal block boundaries.
    fn low_cardinality_data(len: usize, seed: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut s = seed;
        while v.len() < len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            v.push(b"abcdefgh"[(s >> 33) as usize & 7]);
        }
        v
    }

    #[test]
    fn test_single_block_lz77_path_produces_valid_stream() {
        let mut input = Vec::new();
        for _ in 0..50 {
            input.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
            input.extend_from_slice(&low_cardinality_data(32, 9));
        }
        let cmds = generate_lz77_commands(&input, 0);
        let (bits, tb) = try_lz77_metablock(&input, &cmds, usize::MAX).expect("lz77 metablock");
        let stream = metablock_stream(&bits, tb);
        assert_eq!(decode::decode(&stream).unwrap(), input);
    }

    #[test]
    fn test_multi_block_lz77_path_produces_valid_stream() {
        // Low-cardinality data crosses the literal block boundary
        // mid-stream; several seeds cover the boundary landing both
        // inside a command's literal run and at a command boundary
        // (the latter previously desynced the bitstream).
        let mut seen = 0;
        for seed in 1..=6u64 {
            let input = low_cardinality_data(8000, seed);
            let cmds = generate_lz77_commands(&input, 0);
            if let Some((bits, tb)) = try_multi_block_lz77(&input, &cmds, usize::MAX) {
                let stream = metablock_stream(&bits, tb);
                assert_eq!(decode::decode(&stream).unwrap(), input);
                seen += 1;
            }
        }
        assert!(seen > 0, "multi-block path was not exercised");
    }

    #[test]
    fn test_context_modeling_lz77_path_produces_valid_stream() {
        // Dictionary words force dictionary copies whose produced
        // bytes must feed back into the simulated literal context.
        let mut input = Vec::new();
        for _ in 0..30 {
            input.extend_from_slice(b"the of and in to for a that with from ");
            input.extend_from_slice(&low_cardinality_data(48, 5));
        }
        let cmds = generate_lz77_commands(&input, 0);
        let (bits, tb) =
            try_context_modeling_lz77(&input, 0, &cmds, usize::MAX).expect("ctx metablock");
        let stream = metablock_stream(&bits, tb);
        assert_eq!(decode::decode(&stream).unwrap(), input);
    }

    #[test]
    fn test_encode_output_is_stable_across_strategies() {
        // Mixed input exercising the strategy chain end-to-end.
        let mut input = Vec::new();
        for _ in 0..20 {
            input.extend_from_slice(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            input.extend_from_slice(&low_cardinality_data(96, 3));
            input.extend_from_slice(b"the of and in to for ");
        }
        let encoded = encode(&input);
        assert_eq!(decode::decode(&encoded).unwrap(), input);
    }

    fn encode_distance_scan(distance: usize) -> Option<(u16, u32, u8)> {
        if distance == 0 {
            return None;
        }
        for hcode in 0u16..48 {
            let ndistbits = 1 + (hcode as usize >> 1);
            if ndistbits > 24 {
                break;
            }
            let offset = ((2 + (hcode as usize & 1)) << ndistbits) - 4;
            let base = offset + 1;
            let max = base + (1usize << ndistbits) - 1;
            if distance >= base && distance <= max {
                return Some((16 + hcode, (distance - base) as u32, ndistbits as u8));
            }
        }
        None
    }

    #[test]
    fn test_encode_distance_matches_linear_scan() {
        assert_eq!(encode_distance(0), None);
        for distance in 1..=80_000 {
            assert_eq!(
                encode_distance(distance),
                encode_distance_scan(distance),
                "{distance}"
            );
        }
        for pair in 1..=24 {
            let start = (1usize << (pair + 1)) - 3;
            let half = 1usize << pair;
            let end = start + half * 2 - 1;
            for distance in [start, start + half - 1, start + half, end] {
                assert_eq!(
                    encode_distance(distance),
                    encode_distance_scan(distance),
                    "{distance}"
                );
            }
        }
        let past = (1usize << 26) - 3;
        assert_eq!(encode_distance(past), None);
        assert_eq!(encode_distance_scan(past), None);
    }

    #[test]
    fn test_embedded_dict_index_matches_runtime_build() {
        let built = build_dict_index(DICTIONARY_DATA);
        let embedded = embedded_dict_index();
        assert_eq!(built.head.len(), DICT_HASH_SIZE);
        assert_eq!(embedded.head.len(), DICT_HASH_SIZE * 4);
        for (i, &word) in built.head.iter().enumerate() {
            assert_eq!(index_u32(embedded.head, i), word);
        }
        assert_eq!(embedded.next.len(), built.next.len() * 4);
        assert_eq!(embedded.entry.len(), built.entry.len() * 4);
        for (i, &word) in built.next.iter().enumerate() {
            assert_eq!(index_u32(embedded.next, i), word);
        }
        for (i, &word) in built.entry.iter().enumerate() {
            assert_eq!(index_u32(embedded.entry, i), word);
        }
    }

    #[test]
    fn test_bitwriter_stops_before_limit() {
        let mut writer = BitWriter::with_limit(10);
        writer.write_bits(0xFF, 8);
        assert!(!writer.exceeded);
        assert_eq!(writer.total_bits, 8);
        writer.write_bits(0xFF, 8);
        assert!(writer.exceeded);
        assert_eq!(writer.bytes.len(), 1);
        assert!(writer.finish_if_within_limit().is_none());
    }
}
