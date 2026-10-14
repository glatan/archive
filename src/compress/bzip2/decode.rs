//! bzip2 decompression.
//!
//! Decodes bzip2 compressed data using the pipeline:
//! Huffman decode → undo RLE2 → undo MTF → inverse BWT → undo RLE1.
//!
//! # Examples
//!
//! ```
//! use archive::compress::bzip2::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```
//!
//! # Errors
//!
//! Returns [`Error::InvalidData`] if the input is not valid bzip2 data.
//! Returns [`Error::ChecksumMismatch`] if a CRC32 check fails.
//!
//! [`Error::InvalidData`]: crate::error::Error::InvalidData
//! [`Error::ChecksumMismatch`]: crate::error::Error::ChecksumMismatch

use alloc::vec;
use alloc::vec::Vec;

use super::crc32::Bz2Crc32;
use crate::error::Error;

use super::bitstream::BitReader;
use super::bwt;
use super::huffman::{self, GROUP_SIZE, MAX_TABLES};

/// Block magic: the hex digits of pi (0x314159265359).
const BLOCK_MAGIC: u64 = 0x314159265359;

/// Stream trailer magic (sqrt(pi): 0x177245385090).
const TRAILER_MAGIC: u64 = 0x177245385090;

/// RUNA symbol index.
const RUNA: u16 = 0;

/// RUNB symbol index.
const RUNB: u16 = 1;

/// Maximum number of selectors (reference bzip2 limit: 2 + 900000/50).
const MAX_SELECTORS: usize = 18002;

// Constant data carried over verbatim from the reference implementation's
// `randtable.c` (BSD-style bzip2 license, Copyright (C) 1996-2019 Julian
// Seward <jseward@acm.org>); see THIRD_PARTY_NOTICES. Part of the de facto
// format definition (randomized-RLE substitution table).
const BZ2_RNUMS: [i32; 512] = [
    619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949,
    214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680,
    480, 51, 878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807,
    591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476,
    693, 425, 174, 647, 73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874,
    474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533,
    221, 400, 386, 867, 600, 782, 382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163,
    354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68,
    770, 919, 190, 373, 294, 822, 808, 206, 184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715,
    67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940,
    652, 934, 970, 447, 318, 353, 859, 672, 112, 785, 645, 863, 803, 350, 139, 93, 354, 99, 820,
    908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626,
    789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250, 170, 774, 972, 275, 999, 639, 495,
    78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992,
    809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81, 344, 805, 988, 739, 511,
    655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268,
    926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700, 946, 670, 656,
    610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879,
    194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679, 297,
    59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
    343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430,
    305, 170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790,
    288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293,
    465, 502, 56, 661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286,
    215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645,
    210, 389, 550, 919, 135, 780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713,
    857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];

/// Decompress bzip2 data, including concatenated streams.
///
/// Multiple bzip2 streams concatenated together (e.g. produced by
/// `cat file1.bz2 file2.bz2`) are transparently decoded. After each
/// stream trailer, if the remaining bytes start with `BZh[1-9]` a new
/// stream is decoded; otherwise the function returns.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the input is not valid bzip2 data.
/// Returns [`Error::ChecksumMismatch`] if a block CRC or stream CRC check fails.
///
/// # Examples
///
/// ```
/// use archive::compress::bzip2::{decode, encode};
///
/// let original = b"Hello, bzip2!";
/// let compressed = encode::encode(original);
/// let decoded = decode::decode(&compressed).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut remaining = input.to_vec();
    let mut output = Vec::new();

    loop {
        let (stream_data, rest) = decode_single_stream(&remaining)?;
        output.extend_from_slice(&stream_data);

        // Check if remaining bytes start with another bzip2 stream: "BZh" + [1-9]
        if rest.len() >= 4
            && rest[0] == b'B'
            && rest[1] == b'Z'
            && rest[2] == b'h'
            && (b'1'..=b'9').contains(&rest[3])
        {
            remaining = rest;
            continue;
        }

        return Ok(output);
    }
}

/// Decompress a single bzip2 stream. Returns `(decoded_data, remaining_bytes)`.
///
/// The remaining bytes are the unconsumed data after the stream trailer.
fn decode_single_stream(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let mut reader = BitReader::new(input);
    let mut output = Vec::new();

    // Parse stream header: "BZh" + block_size
    let b = reader.read_u8()?;
    let z = reader.read_u8()?;
    let h = reader.read_u8()?;
    if b != b'B' || z != b'Z' || h != b'h' {
        return Err(Error::InvalidData("invalid bzip2 magic"));
    }

    let block_size_char = reader.read_u8()?;
    if !(b'1'..=b'9').contains(&block_size_char) {
        return Err(Error::InvalidData("invalid bzip2 block size"));
    }
    let block_size100k = (block_size_char - b'0') as usize;

    let mut combined_crc = 0u32;

    loop {
        let magic = reader.read_bits_u64(48)?;

        if magic == TRAILER_MAGIC {
            // Stream trailer
            let stored_crc = reader.read_u32()?;
            if stored_crc != combined_crc {
                return Err(Error::ChecksumMismatch {
                    expected: stored_crc,
                    actual: combined_crc,
                });
            }
            let remaining = reader.into_remaining();
            return Ok((output, remaining));
        }

        if magic != BLOCK_MAGIC {
            return Err(Error::InvalidData("invalid bzip2 block magic"));
        }

        let (block_data, block_crc) = decode_block(&mut reader, block_size100k)?;

        // Update combined CRC: combined = ((combined << 1) | (combined >> 31)) ^ block_crc
        combined_crc = combined_crc.rotate_left(1) ^ block_crc;

        output.extend_from_slice(&block_data);
    }
}

/// Decode a single bzip2 block. Returns `(decoded_data, verified_block_crc)`.
fn decode_block(reader: &mut BitReader, block_size100k: usize) -> Result<(Vec<u8>, u32), Error> {
    // Block CRC (stored)
    let stored_crc = reader.read_u32()?;

    // Randomized flag
    let randomized = reader.read_bool()?;

    // Original BWT pointer (24 bits)
    let orig_ptr = reader.read_bits(24)?;

    // Parse symbol map (which byte values are used)
    let in_use = parse_symbol_map(reader)?;
    let n_in_use = in_use.iter().filter(|&&b| b).count();
    if n_in_use == 0 {
        return Err(Error::InvalidData("bzip2 block has no symbols in use"));
    }

    // Build the used-symbol list
    let mut seq_to_unseq = vec![0u8; n_in_use];
    let mut j = 0;
    for (i, &used) in in_use.iter().enumerate() {
        if used {
            seq_to_unseq[j] = i as u8;
            j += 1;
        }
    }

    // Number of Huffman tables (2-6)
    let num_tables = reader.read_bits(3)? as usize;
    if !(2..=MAX_TABLES).contains(&num_tables) {
        return Err(Error::InvalidData("invalid number of bzip2 Huffman tables"));
    }

    // Number of selectors
    let num_selectors = reader.read_bits(15)? as usize;
    if num_selectors == 0 || num_selectors > MAX_SELECTORS {
        return Err(Error::InvalidData("invalid bzip2 selector count"));
    }

    // Parse selectors (unary coded, then MTF decoded)
    let selectors = parse_selectors(reader, num_selectors, num_tables)?;

    // Total symbols: RUNA + RUNB + n_in_use MTF values + EOB
    let num_symbols = n_in_use + 2;

    // Parse Huffman tables
    let tables = huffman::parse_huffman_tables(reader, num_tables, num_symbols)?;

    // EOB is the last symbol in the alphabet (n_in_use + 1)
    let eob_symbol = (n_in_use + 1) as u16;

    // Decode symbols
    let mtf_rle = decode_symbols(reader, &tables, &selectors, eob_symbol)?;

    // Undo RLE2 + MTF (with block size limit to prevent memory exhaustion)
    let max_block_bytes = block_size100k * 100_000;
    let bwt_data = undo_mtf_rle2(&mtf_rle, &seq_to_unseq, n_in_use, max_block_bytes)?;

    // Inverse BWT
    if orig_ptr as usize >= bwt_data.len() && !bwt_data.is_empty() {
        return Err(Error::InvalidData("bzip2 original pointer out of range"));
    }
    let mut after_bwt = bwt::inverse_bwt(&bwt_data, orig_ptr);
    if randomized {
        apply_bzip2_randomization(&mut after_bwt);
    }

    // Undo RLE1
    let decoded = undo_rle1(&after_bwt)?;

    // Verify block CRC
    let mut crc = Bz2Crc32::new();
    crc.update(&decoded);
    let actual_crc = crc.finish();
    if actual_crc != stored_crc {
        return Err(Error::ChecksumMismatch {
            expected: stored_crc,
            actual: actual_crc,
        });
    }

    Ok((decoded, actual_crc))
}

fn apply_bzip2_randomization(data: &mut [u8]) {
    let mut r_n_to_go = 0i32;
    let mut r_t_pos = 0usize;

    for byte in data {
        if r_n_to_go == 0 {
            r_n_to_go = BZ2_RNUMS[r_t_pos];
            r_t_pos = (r_t_pos + 1) % BZ2_RNUMS.len();
        }
        r_n_to_go -= 1;
        if r_n_to_go == 1 {
            *byte ^= 1;
        }
    }
}

/// Parse the two-level symbol bitmap.
pub(crate) fn parse_symbol_map(reader: &mut BitReader) -> Result<[bool; 256], Error> {
    let mut in_use = [false; 256];
    let used_groups = reader.read_bits(16)?;

    for group in 0..16 {
        if used_groups & (1 << (15 - group)) != 0 {
            let group_bits = reader.read_bits(16)?;
            for bit in 0..16 {
                if group_bits & (1 << (15 - bit)) != 0 {
                    in_use[group * 16 + bit] = true;
                }
            }
        }
    }

    Ok(in_use)
}

/// Parse and MTF-decode the selector list.
fn parse_selectors(
    reader: &mut BitReader,
    num_selectors: usize,
    num_tables: usize,
) -> Result<Vec<u8>, Error> {
    // Read unary-coded selector indices
    let mut mtf_selectors = Vec::with_capacity(num_selectors);
    for _ in 0..num_selectors {
        let mut val = 0u8;
        while reader.read_bool()? {
            val += 1;
            if val as usize >= num_tables {
                return Err(Error::InvalidData("bzip2 selector index out of range"));
            }
        }
        mtf_selectors.push(val);
    }

    // MTF-decode selectors
    let mut mtf_list: Vec<u8> = (0..num_tables as u8).collect();
    let mut selectors = Vec::with_capacity(num_selectors);
    for &idx in &mtf_selectors {
        let val = mtf_list[idx as usize];
        selectors.push(val);
        // Move to front
        for i in (1..=idx as usize).rev() {
            mtf_list[i] = mtf_list[i - 1];
        }
        mtf_list[0] = val;
    }

    Ok(selectors)
}

/// Decode Huffman-coded symbols from the bitstream.
fn decode_symbols(
    reader: &mut BitReader,
    tables: &[huffman::HuffmanTable],
    selectors: &[u8],
    eob_symbol: u16,
) -> Result<Vec<u16>, Error> {
    let mut symbols = Vec::new();
    let mut group_idx = 0usize;
    let mut group_pos = 0usize;

    loop {
        if group_idx >= selectors.len() {
            return Err(Error::InvalidData("bzip2 ran out of selectors"));
        }

        let table = &tables[selectors[group_idx] as usize];
        let symbol = table.decode_symbol(reader)?;

        if symbol == eob_symbol {
            break;
        }

        symbols.push(symbol);

        group_pos += 1;
        if group_pos >= GROUP_SIZE {
            group_pos = 0;
            group_idx += 1;
        }
    }

    Ok(symbols)
}

/// Undo RLE2 (zero-run decoding) and MTF transform.
///
/// `max_output` limits the output size to prevent memory exhaustion on crafted input.
fn undo_mtf_rle2(
    symbols: &[u16],
    seq_to_unseq: &[u8],
    n_in_use: usize,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut mtf_list: Vec<u8> = (0..n_in_use).map(|i| i as u8).collect();

    let mut i = 0;
    while i < symbols.len() {
        let sym = symbols[i];

        if sym == RUNA || sym == RUNB {
            // Decode zero-run using bijective base-2.
            // Use u64 to detect overflow before allocating.
            let mut run_len = 0u64;
            let mut power = 1u64;
            while i < symbols.len() && (symbols[i] == RUNA || symbols[i] == RUNB) {
                // Saturating: a wrapped u64 would let run_len slip under
                // the max_output check below (and panic in debug builds).
                run_len = run_len.saturating_add((symbols[i] as u64 + 1).saturating_mul(power));
                power = power.saturating_mul(2);
                i += 1;
            }
            // Validate run length before allocating; compare as a
            // subtraction since run_len may have saturated to u64::MAX.
            if run_len > (max_output as u64).saturating_sub(output.len() as u64) {
                return Err(Error::InvalidData(
                    "bzip2 block data exceeds declared block size",
                ));
            }
            // Emit `run_len` copies of the MTF[0] symbol
            let byte = seq_to_unseq[mtf_list[0] as usize];
            let run_len = run_len as usize;
            for _ in 0..run_len {
                output.push(byte);
            }
        } else {
            // MTF index (shifted by 2: symbol 2 = MTF index 1, etc.)
            let mtf_idx = (sym - 1) as usize;
            if mtf_idx >= mtf_list.len() {
                return Err(Error::InvalidData("bzip2 MTF index out of range"));
            }
            let val = mtf_list[mtf_idx];
            let byte = seq_to_unseq[val as usize];
            if output.len() >= max_output {
                return Err(Error::InvalidData(
                    "bzip2 block data exceeds declared block size",
                ));
            }
            output.push(byte);

            // Move to front
            for j in (1..=mtf_idx).rev() {
                mtf_list[j] = mtf_list[j - 1];
            }
            mtf_list[0] = val;

            i += 1;
        }
    }

    Ok(output)
}

/// Undo RLE1: expand runs of 4+ identical bytes.
///
/// In the RLE1 encoding, a sequence of 4 identical bytes followed by a count
/// byte encodes `4 + count` repetitions of that byte.
fn undo_rle1(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        output.push(b);
        i += 1;

        let mut run = 1;
        while i < data.len() && data[i] == b && run < 4 {
            output.push(b);
            run += 1;
            i += 1;
        }

        if run == 4 {
            if i >= data.len() {
                return Err(Error::InvalidData(
                    "bzip2 RLE1: missing count byte after 4 identical bytes",
                ));
            }
            let count = data[i] as usize;
            i += 1;
            for _ in 0..count {
                output.push(b);
            }
        }
    }

    Ok(output)
}

/// Decompress bzip2 data from a reader.
///
/// # Errors
///
/// Returns an error if reading from the underlying reader fails or if the
/// data is not valid bzip2.
///
/// # Examples
///
/// ```
/// use archive::compress::bzip2::{decode, encode};
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

/// Decode with a maximum output size limit.
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

    #[test]
    fn test_undo_rle1_no_runs() {
        let data = [1, 2, 3, 4];
        let result = undo_rle1(&data).unwrap();
        assert_eq!(result, [1, 2, 3, 4]);
    }

    #[test]
    fn test_undo_rle1_run_of_4() {
        // 4 copies of 'A' then count=3 → 7 copies total
        let data = [b'A', b'A', b'A', b'A', 3];
        let result = undo_rle1(&data).unwrap();
        assert_eq!(result, vec![b'A'; 7]);
    }

    #[test]
    fn test_undo_rle1_run_of_4_zero_extra() {
        // 4 copies of 'A' then count=0 → 4 copies
        let data = [b'A', b'A', b'A', b'A', 0];
        let result = undo_rle1(&data).unwrap();
        assert_eq!(result, vec![b'A'; 4]);
    }

    #[test]
    fn test_undo_rle1_short_run() {
        // Only 3 copies — no count byte follows
        let data = *b"AAAB";
        let result = undo_rle1(&data).unwrap();
        assert_eq!(result, [b'A', b'A', b'A', b'B']);
    }

    #[test]
    fn test_undo_mtf_rle2_simple() {
        let seq_to_unseq = *b"ABC";
        // Symbol 2 = MTF index 1 = 'B', then RUNA(0) = 1 copy of MTF[0] which is now 'B'
        let symbols = [2u16, 0]; // MTF[1]='B', then RUNA → 1×MTF[0]='B'
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 3, 900_000).unwrap();
        assert_eq!(result, [b'B', b'B']);
    }

    #[test]
    fn test_undo_mtf_rle2_runb() {
        let seq_to_unseq = *b"X";
        // bijective base-2: RUNA,RUNB = (0+1)*1 + (1+1)*2 = 1 + 4 = 5
        let symbols = [0u16, 1]; // RUNA, RUNB
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 1, 900_000).unwrap();
        assert_eq!(result, vec![b'X'; 5]);
    }

    #[test]
    fn test_undo_mtf_rle2_invalid_index() {
        let seq_to_unseq = *b"AB";
        // Symbol 10 → MTF index 9, but only 2 symbols in MTF list
        let symbols = [10u16];
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 2, 900_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_undo_mtf_rle2_run_exceeds_block_size() {
        let seq_to_unseq = *b"A";
        // 30 RUNB symbols → run_len ≈ 2^31, far exceeds max_output of 100
        let symbols = vec![RUNB; 30];
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 1, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_undo_mtf_rle2_run_saturates_instead_of_overflowing() {
        let seq_to_unseq = *b"A";
        // 64+ consecutive RUNB symbols would wrap the u64 accumulator;
        // the run length must saturate and be rejected, not panic.
        let symbols = vec![RUNB; 128];
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 1, 100);
        assert!(result.is_err());
    }

    /// Regression (fuzz run-1791677246): with a non-empty output the
    /// `output.len() + run_len` bound check itself overflowed once
    /// run_len saturated to u64::MAX, panicking instead of erroring.
    #[test]
    fn test_undo_mtf_rle2_saturated_run_with_nonempty_output() {
        let seq_to_unseq = *b"AB";
        // Symbol 2 = MTF index 1 emits one byte, then 128 RUNB symbols
        // saturate the run-length accumulator.
        let mut symbols = vec![2u16];
        symbols.extend_from_slice(&[RUNB; 128]);
        let result = undo_mtf_rle2(&symbols, &seq_to_unseq, 2, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_symbol_map() {
        // Only byte 0 is in use: group 0 bit is set, within group 0 bit 0 is set
        let mut writer = super::super::bitstream::BitWriter::new();
        writer.write_bits(0x8000, 16); // group 0 enabled
        writer.write_bits(0x8000, 16); // bit 0 of group 0
        let data = writer.finish();
        let mut reader = BitReader::new(&data);
        let map = parse_symbol_map(&mut reader).unwrap();
        assert!(map[0]);
        assert!(!map[1]);
        assert!(!map[255]);
    }

    #[test]
    fn test_invalid_magic() {
        let data = *b"XZh9";
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_invalid_block_size() {
        let data = *b"BZh0";
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_truncated_header() {
        let data = *b"BZ";
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_roundtrip_via_encode() {
        let input = b"hello bzip2 world";
        let compressed = crate::compress::bzip2::encode::encode(input);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_decode_system_bzip2() {
        // "x" compressed with system bzip2 -9
        let data: Vec<u8> = vec![
            0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x77, 0x4b, 0xb0, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x20, 0x00, 0x21, 0x18, 0x46, 0x82, 0xee,
            0x48, 0xa7, 0x0a, 0x12, 0x0e, 0xe9, 0x76, 0x02, 0x80,
        ];
        let result = decode(&data).unwrap();
        assert_eq!(result, b"x");
    }

    #[test]
    fn test_decode_empty_stream() {
        // Valid bzip2 stream with header + trailer but zero blocks
        let mut writer = super::super::bitstream::BitWriter::new();
        writer.write_u8(b'B');
        writer.write_u8(b'Z');
        writer.write_u8(b'h');
        writer.write_u8(b'9');
        writer.write_bits_u64(TRAILER_MAGIC, 48);
        writer.write_u32(0); // combined CRC = 0 (no blocks)
        let data = writer.finish();
        let result = decode(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_invalid_selector_count() {
        // Build a stream with selector count exceeding MAX_SELECTORS
        let mut writer = super::super::bitstream::BitWriter::new();
        writer.write_u8(b'B');
        writer.write_u8(b'Z');
        writer.write_u8(b'h');
        writer.write_u8(b'9');
        writer.write_bits_u64(BLOCK_MAGIC, 48);
        writer.write_u32(0); // block CRC
        writer.write_bool(false); // not randomized
        writer.write_bits(0, 24); // orig_ptr
        // Symbol map: only byte 0 in use
        writer.write_bits(0x8000, 16); // group 0
        writer.write_bits(0x8000, 16); // bit 0
        writer.write_bits(2, 3); // 2 Huffman tables
        writer.write_bits(MAX_SELECTORS as u32 + 1, 15); // too many selectors
        let data = writer.finish();
        let result = decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_randomized_block_fixture() {
        let data = crate::compress::bzip2::encode::encode_randomized_for_test(b"randomized block");
        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, b"randomized block");
    }

    #[test]
    fn test_randomization_helper_roundtrip() {
        let mut data = b"abcdef".to_vec();
        let original = data.clone();
        apply_bzip2_randomization(&mut data);
        apply_bzip2_randomization(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_decode_concatenated_streams() {
        let payload1 = b"Hello, first stream!";
        let payload2 = b"Second stream here.";
        let compressed1 = crate::compress::bzip2::encode::encode(payload1);
        let compressed2 = crate::compress::bzip2::encode::encode(payload2);

        let mut concatenated = compressed1;
        concatenated.extend_from_slice(&compressed2);

        let decoded = decode(&concatenated).unwrap();
        let mut expected = payload1.to_vec();
        expected.extend_from_slice(payload2);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_concatenated_three_streams() {
        let payload1 = b"Stream one.";
        let payload2 = b"Stream two.";
        let payload3 = b"Stream three.";
        let compressed1 = crate::compress::bzip2::encode::encode(payload1);
        let compressed2 = crate::compress::bzip2::encode::encode(payload2);
        let compressed3 = crate::compress::bzip2::encode::encode(payload3);

        let mut concatenated = compressed1;
        concatenated.extend_from_slice(&compressed2);
        concatenated.extend_from_slice(&compressed3);

        let decoded = decode(&concatenated).unwrap();
        let mut expected = payload1.to_vec();
        expected.extend_from_slice(payload2);
        expected.extend_from_slice(payload3);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = crate::compress::bzip2::encode::encode(data);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = crate::compress::bzip2::encode::encode(data);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = crate::compress::bzip2::encode::encode(data);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = crate::compress::bzip2::encode::encode(data);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_trailing_garbage_ignored() {
        // bzip2 reference behavior: after the stream trailer the decoder
        // does not read further bytes; trailing garbage is ignored.
        let data = b"trailing garbage boundary";
        let mut compressed = crate::compress::bzip2::encode::encode(data);
        compressed.extend_from_slice(b"\x00\xFFgarbage-after-stream");
        assert_eq!(decode(&compressed).unwrap(), data);
    }

    #[test]
    fn test_decode_truncated_at_every_position() {
        // Every proper prefix of a single stream must fail: a cut lands
        // inside the header, block payload, trailer magic, or stream CRC.
        let data = b"bzip2 truncation sweep payload: abcabcabc";
        let compressed = crate::compress::bzip2::encode::encode(data);
        for cut in 1..compressed.len() {
            assert!(
                decode(&compressed[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }
}
