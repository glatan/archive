//! bzip2 compression.
//!
//! Compresses data using the bzip2 pipeline:
//! RLE1 → BWT → MTF → RLE2 → Huffman coding.
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

use alloc::vec;
use alloc::vec::Vec;

use super::crc32::Bz2Crc32;

use super::bitstream::BitWriter;
use super::bwt;
use super::huffman::{self, GROUP_SIZE};

/// Block magic: the hex digits of pi (0x314159265359).
const BLOCK_MAGIC: u64 = 0x314159265359;

/// Stream trailer magic (sqrt(pi): 0x177245385090).
const TRAILER_MAGIC: u64 = 0x177245385090;

/// RUNA symbol index.
const RUNA: u16 = 0;

/// RUNB symbol index.
const RUNB: u16 = 1;

/// Default block size (900KB, block size level 9).
const DEFAULT_BLOCK_SIZE: u8 = 9;

#[cfg(test)]
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

/// Compress data using bzip2.
///
/// Uses the default block size of 900KB (level 9).
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::bzip2::{decode, encode};
///
/// let data = b"Hello, bzip2!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode(&compressed).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_level(input, DEFAULT_BLOCK_SIZE)
}

/// Compress data using bzip2 with specified block size level (1-9).
///
/// The block size is `level * 100KB`. Level 9 (900KB) gives the best
/// compression ratio; level 1 (100KB) uses less memory.
///
/// # Examples
///
/// ```
/// use archive::compress::bzip2::{decode, encode};
///
/// let data = b"Hello, bzip2!";
/// let compressed = encode::encode_with_level(data, 1);
/// let decoded = decode::decode(&compressed).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub fn encode_with_level(input: &[u8], level: u8) -> Vec<u8> {
    let level = level.clamp(1, 9);
    // Reference bzip2 uses blockSize100k * 100000 - 19 as the maximum
    // RLE1 output per block, leaving headroom for safety.
    let block_size = level as usize * 100_000 - 19;

    let mut writer = BitWriter::new();

    // Stream header: "BZh" + level digit
    writer.write_u8(b'B');
    writer.write_u8(b'Z');
    writer.write_u8(b'h');
    writer.write_u8(b'0' + level);

    let mut combined_crc = 0u32;

    // Split input into blocks based on RLE1 output size (per bzip2 spec,
    // block size limit applies to RLE1 output, not raw input).
    let mut offset = 0;
    if input.is_empty() {
        // Empty input: write just the stream header + trailer with no blocks,
        // matching the reference bzip2 behavior.
    } else {
        while offset < input.len() {
            let (rle1_data, consumed) = apply_rle1_bounded(&input[offset..], block_size);
            let original_block = &input[offset..offset + consumed];
            encode_block_inner(
                &mut writer,
                original_block,
                &rle1_data,
                false,
                &mut combined_crc,
            );
            offset += consumed;
        }
    }

    // Stream trailer
    writer.write_bits_u64(TRAILER_MAGIC, 48);
    writer.write_u32(combined_crc);

    writer.finish()
}

/// Encode a single bzip2 block.
///
/// `original_data` is used for CRC computation (pre-RLE1).
/// `rle1_data` is the RLE1-encoded data fed into BWT and the rest of the pipeline.
fn encode_block_inner(
    writer: &mut BitWriter,
    original_data: &[u8],
    rle1_data: &[u8],
    randomized: bool,
    combined_crc: &mut u32,
) {
    // Compute block CRC on original data (bzip2 uses big-endian CRC-32)
    let mut crc = Bz2Crc32::new();
    crc.update(original_data);
    let block_crc = crc.finish();
    *combined_crc = (*combined_crc).rotate_left(1) ^ block_crc;

    // BWT (on RLE1 output)
    #[cfg(test)]
    let mut block_data = rle1_data.to_vec();
    #[cfg(not(test))]
    let block_data = rle1_data.to_vec();
    #[cfg(test)]
    if randomized {
        apply_bzip2_randomization(&mut block_data);
    }
    let (bwt_data, orig_ptr) = bwt::forward_bwt(&block_data);

    // Determine which byte values are in use
    let mut in_use = [false; 256];
    for &b in &bwt_data {
        in_use[b as usize] = true;
    }
    if bwt_data.is_empty() {
        // Need at least one symbol for the encoding to work
        in_use[0] = true;
    }

    let n_in_use = in_use.iter().filter(|&&b| b).count();
    let mut unseq_to_seq = [0u8; 256];
    let mut seq_to_unseq = vec![0u8; n_in_use];
    let mut j = 0usize;
    for i in 0..256 {
        if in_use[i] {
            unseq_to_seq[i] = j as u8;
            seq_to_unseq[j] = i as u8;
            j += 1;
        }
    }

    // MTF + RLE2
    let symbols = apply_mtf_rle2(&bwt_data, &unseq_to_seq, n_in_use);

    // Number of symbols for Huffman: RUNA + RUNB + n_in_use + EOB
    // Actually: RUNA(0), RUNB(1), symbols 2..n_in_use+1, EOB = n_in_use + 1
    let num_huffman_symbols = n_in_use + 2;
    let eob_symbol = (n_in_use + 1) as u16;

    // Build Huffman tables
    let num_tables = select_num_tables(symbols.len());
    let (tables, selectors) =
        build_tables_and_selectors(&symbols, num_tables, num_huffman_symbols, eob_symbol);

    // Write block header
    writer.write_bits_u64(BLOCK_MAGIC, 48);
    writer.write_u32(block_crc);
    writer.write_bool(randomized);
    writer.write_bits(orig_ptr, 24);

    // Write symbol map
    write_symbol_map(writer, &in_use);

    // Write number of tables and selectors
    // The selectors field is 15 bits, so max 32767. In practice, selectors.len()
    // = ceil(symbols.len() / 50) which only exceeds 32767 for >1.6M symbols.
    // The bzip2 block size limit (900KB) ensures this never happens.
    writer.write_bits(num_tables as u32, 3);
    writer.write_bits(selectors.len().min(32767) as u32, 15);

    // Write selectors (MTF-encoded, unary coded)
    write_selectors(writer, &selectors, num_tables);

    // Write Huffman tables
    huffman::write_huffman_tables(writer, &tables);

    // Write encoded symbols
    let mut group_idx = 0usize;
    let mut group_pos = 0usize;
    for &sym in &symbols {
        let table = &tables[selectors[group_idx] as usize];
        table.encode_symbol(writer, sym);
        group_pos += 1;
        if group_pos >= GROUP_SIZE {
            group_pos = 0;
            group_idx += 1;
        }
    }

    // Write EOB
    let table = &tables[selectors[group_idx] as usize];
    table.encode_symbol(writer, eob_symbol);
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn encode_randomized_for_test(input: &[u8]) -> Vec<u8> {
    let mut writer = BitWriter::new();
    writer.write_u8(b'B');
    writer.write_u8(b'Z');
    writer.write_u8(b'h');
    writer.write_u8(b'9');

    let mut combined_crc = 0u32;
    let (rle1_data, _consumed) = apply_rle1_bounded(input, 9 * 100_000 - 19);
    encode_block_inner(&mut writer, input, &rle1_data, true, &mut combined_crc);
    writer.write_bits_u64(TRAILER_MAGIC, 48);
    writer.write_u32(combined_crc);
    writer.finish()
}

/// Apply RLE1: encode runs of 4+ identical bytes.
#[cfg(test)]
fn apply_rle1(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        let mut run = 1;
        while i + run < data.len() && data[i + run] == b && run < 259 {
            run += 1;
        }

        if run >= 4 {
            output.push(b);
            output.push(b);
            output.push(b);
            output.push(b);
            output.push((run - 4) as u8);
            i += run;
        } else {
            output.push(b);
            i += 1;
        }
    }

    output
}

/// Apply RLE1 with a maximum output size bound.
///
/// Returns `(rle1_output, input_bytes_consumed)`. The block size limit in bzip2
/// applies to the RLE1 output, so this function stops when the output reaches
/// `max_output` bytes.
fn apply_rle1_bounded(data: &[u8], max_output: usize) -> (Vec<u8>, usize) {
    let mut output = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let b = data[i];
        let mut run = 1;
        while i + run < data.len() && data[i + run] == b && run < 259 {
            run += 1;
        }

        if run >= 4 {
            // RLE1 encoding produces 5 bytes (4 copies + count)
            if output.len() + 5 > max_output && !output.is_empty() {
                break;
            }
            output.push(b);
            output.push(b);
            output.push(b);
            output.push(b);
            output.push((run - 4) as u8);
            i += run;
        } else {
            if output.len() + 1 > max_output && !output.is_empty() {
                break;
            }
            output.push(b);
            i += 1;
        }
    }

    (output, i)
}

/// Apply MTF transform and RLE2 (zero-run encoding).
fn apply_mtf_rle2(bwt_data: &[u8], unseq_to_seq: &[u8; 256], n_in_use: usize) -> Vec<u16> {
    let mut symbols = Vec::new();
    let mut mtf_list: Vec<u8> = (0..n_in_use).map(|i| i as u8).collect();

    let mut zero_run = 0u32;

    for &b in bwt_data {
        let seq = unseq_to_seq[b as usize];

        // Find position in MTF list
        let pos = mtf_list.iter().position(|&x| x == seq).unwrap();

        // Move to front
        if pos > 0 {
            let val = mtf_list[pos];
            for j in (1..=pos).rev() {
                mtf_list[j] = mtf_list[j - 1];
            }
            mtf_list[0] = val;
        }

        if pos == 0 {
            zero_run += 1;
        } else {
            // Flush any pending zero run
            if zero_run > 0 {
                encode_zero_run(&mut symbols, zero_run);
                zero_run = 0;
            }
            // Emit MTF index + 1 (shifted because RUNA=0, RUNB=1)
            symbols.push(pos as u16 + 1);
        }
    }

    // Flush final zero run
    if zero_run > 0 {
        encode_zero_run(&mut symbols, zero_run);
    }

    symbols
}

/// Encode a zero run using RUNA/RUNB bijective base-2.
fn encode_zero_run(symbols: &mut Vec<u16>, mut run: u32) {
    // Bijective base-2 encoding:
    // run = sum of (bit_i + 1) * 2^i
    // To encode: repeatedly extract the least significant "digit"
    while run > 0 {
        if run % 2 == 1 {
            symbols.push(RUNA);
            run = (run - 1) / 2;
        } else {
            symbols.push(RUNB);
            run = (run - 2) / 2;
        }
    }
}

/// Select the number of Huffman tables based on data length.
const fn select_num_tables(num_symbols: usize) -> usize {
    if num_symbols < 200 {
        2
    } else if num_symbols < 600 {
        3
    } else if num_symbols < 1200 {
        4
    } else if num_symbols < 2400 {
        5
    } else {
        6
    }
}

/// Build Huffman tables and assign selectors.
fn build_tables_and_selectors(
    symbols: &[u16],
    num_tables: usize,
    num_huffman_symbols: usize,
    eob_symbol: u16,
) -> (Vec<huffman::HuffmanTable>, Vec<u8>) {
    // Count total symbol frequencies (including EOB)
    let mut total_freqs = vec![0u32; num_huffman_symbols];
    for &sym in symbols {
        total_freqs[sym as usize] += 1;
    }
    total_freqs[eob_symbol as usize] = 1;

    // For simplicity, start with a single table covering all symbols.
    // Then do iterative refinement if multiple tables are used.
    // EOB counts as one extra symbol in the last group
    let total_symbols_with_eob = symbols.len() + 1;
    let total_groups = total_symbols_with_eob.div_ceil(GROUP_SIZE);
    let mut selectors = vec![0u8; total_groups];

    if num_tables == 1 {
        // Single table
        let table = huffman::build_huffman_table(&total_freqs, num_huffman_symbols);
        return (vec![table], selectors);
    }

    // Initialize tables by splitting symbol frequency space evenly
    let mut table_freqs = vec![vec![0u32; num_huffman_symbols]; num_tables];

    // Initial assignment: distribute groups evenly across tables
    let groups_per_table = total_groups.div_ceil(num_tables);
    for (g, selector) in selectors.iter_mut().enumerate() {
        *selector = (g / groups_per_table).min(num_tables - 1) as u8;
    }

    // Accumulate frequencies for initial assignment
    for (g, &sel) in selectors.iter().enumerate() {
        let start = (g * GROUP_SIZE).min(symbols.len());
        let group_end = if g * GROUP_SIZE < symbols.len() {
            ((g + 1) * GROUP_SIZE).min(symbols.len())
        } else {
            symbols.len()
        };
        for &sym in &symbols[start..group_end] {
            table_freqs[sel as usize][sym as usize] += 1;
        }
    }
    // EOB goes to the last group's table
    if let Some(&last_sel) = selectors.last() {
        table_freqs[last_sel as usize][eob_symbol as usize] += 1;
    }

    // Build initial tables
    let mut tables: Vec<huffman::HuffmanTable> = table_freqs
        .iter()
        .map(|f| huffman::build_huffman_table(f, num_huffman_symbols))
        .collect();

    // Iterative refinement (4 iterations, similar to reference implementation)
    for _ in 0..4 {
        // Reset frequencies
        for f in &mut table_freqs {
            for x in f.iter_mut() {
                *x = 0;
            }
        }

        // Reassign each group to the table that encodes it most efficiently
        for (g, selector) in selectors.iter_mut().enumerate() {
            let start = (g * GROUP_SIZE).min(symbols.len());
            let end = ((g + 1) * GROUP_SIZE).min(symbols.len());

            // If this is the last group, it includes EOB
            let is_last = g == total_groups - 1;

            let mut best_table = 0u8;
            let mut best_cost = u64::MAX;

            for (t, table) in tables.iter().enumerate() {
                let mut cost = 0u64;
                for &sym in &symbols[start..end] {
                    cost += table.lengths[sym as usize] as u64;
                }
                if is_last {
                    cost += table.lengths[eob_symbol as usize] as u64;
                }
                if cost < best_cost {
                    best_cost = cost;
                    best_table = t as u8;
                }
            }

            *selector = best_table;

            // Accumulate frequencies
            for &sym in &symbols[start..end] {
                table_freqs[best_table as usize][sym as usize] += 1;
            }
            if is_last {
                table_freqs[best_table as usize][eob_symbol as usize] += 1;
            }
        }

        // Rebuild tables from new frequencies
        tables = table_freqs
            .iter()
            .map(|f| {
                // Ensure all tables have at least some symbols with non-zero frequency
                let has_any = f.iter().any(|&x| x > 0);
                if has_any {
                    huffman::build_huffman_table(f, num_huffman_symbols)
                } else {
                    // Unused table: assign uniform lengths
                    huffman::build_huffman_table(
                        &vec![1u32; num_huffman_symbols],
                        num_huffman_symbols,
                    )
                }
            })
            .collect();
    }

    (tables, selectors)
}

/// Write the two-level symbol bitmap.
fn write_symbol_map(writer: &mut BitWriter, in_use: &[bool; 256]) {
    let mut group_mask = 0u16;
    for group in 0..16 {
        for bit in 0..16 {
            if in_use[group * 16 + bit] {
                group_mask |= 1 << (15 - group);
                break;
            }
        }
    }
    writer.write_bits(group_mask as u32, 16);

    for group in 0..16 {
        if group_mask & (1 << (15 - group)) != 0 {
            let mut bits = 0u16;
            for bit in 0..16 {
                if in_use[group * 16 + bit] {
                    bits |= 1 << (15 - bit);
                }
            }
            writer.write_bits(bits as u32, 16);
        }
    }
}

/// Write selectors (MTF-encoded, unary coded).
fn write_selectors(writer: &mut BitWriter, selectors: &[u8], num_tables: usize) {
    // MTF-encode the selectors
    let mut mtf_list: Vec<u8> = (0..num_tables as u8).collect();

    for &sel in selectors {
        let pos = mtf_list.iter().position(|&x| x == sel).unwrap();

        // Unary code: pos ones followed by a zero
        for _ in 0..pos {
            writer.write_bool(true);
        }
        writer.write_bool(false);

        // Move to front
        if pos > 0 {
            let val = mtf_list[pos];
            for j in (1..=pos).rev() {
                mtf_list[j] = mtf_list[j - 1];
            }
            mtf_list[0] = val;
        }
    }
}

/// Compress data using bzip2 and write to a writer.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::bzip2::encode;
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
    use crate::compress::bzip2::decode;

    #[test]
    fn test_rle1_no_runs() {
        let data = [1, 2, 3, 4, 5];
        let result = apply_rle1(&data);
        assert_eq!(result, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_rle1_run_of_5() {
        let data = [b'A'; 5];
        let result = apply_rle1(&data);
        assert_eq!(result, [b'A', b'A', b'A', b'A', 1]);
    }

    #[test]
    fn test_rle1_run_of_4() {
        let data = [b'A'; 4];
        let result = apply_rle1(&data);
        assert_eq!(result, [b'A', b'A', b'A', b'A', 0]);
    }

    #[test]
    fn test_rle1_long_run() {
        let data = [b'X'; 259];
        let result = apply_rle1(&data);
        assert_eq!(result, [b'X', b'X', b'X', b'X', 255]);
    }

    #[test]
    fn test_rle1_run_of_3_no_encoding() {
        let data = [b'A', b'A', b'A', b'B'];
        let result = apply_rle1(&data);
        assert_eq!(result, [b'A', b'A', b'A', b'B']);
    }

    #[test]
    fn test_zero_run_encoding() {
        let mut symbols = Vec::new();
        encode_zero_run(&mut symbols, 1);
        assert_eq!(symbols, [RUNA]); // 1 = (0+1)*1

        symbols.clear();
        encode_zero_run(&mut symbols, 2);
        assert_eq!(symbols, [RUNB]); // 2 = (1+1)*1

        symbols.clear();
        encode_zero_run(&mut symbols, 3);
        assert_eq!(symbols, [RUNA, RUNA]); // 3 = (0+1)*1 + (0+1)*2 = 1+2 = 3

        symbols.clear();
        encode_zero_run(&mut symbols, 5);
        assert_eq!(symbols, [RUNA, RUNB]); // 5 = (0+1)*1 + (1+1)*2 = 1+4 = 5
    }

    #[test]
    fn test_zero_run_encoding_values() {
        // Verify encoding/decoding are inverse
        for run in 1..=20 {
            let mut symbols = Vec::new();
            encode_zero_run(&mut symbols, run);

            // Decode
            let mut decoded = 0u32;
            let mut power = 1u32;
            for &sym in &symbols {
                decoded += (sym as u32 + 1) * power;
                power *= 2;
            }
            assert_eq!(decoded, run, "run={}", run);
        }
    }

    #[test]
    fn test_roundtrip_empty() {
        let input = b"";
        let compressed = encode(input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input.as_slice());
    }

    #[test]
    fn test_roundtrip_hello() {
        let input = b"Hello, bzip2 World!";
        let compressed = encode(input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let input = b"aaaaaaaaaaaabbbbbbbbcccccc";
        let compressed = encode(input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let input = b"x";
        let compressed = encode(input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_level_1() {
        let input = b"Hello, bzip2! Testing level 1.";
        let compressed = encode_with_level(input, 1);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_binary_data() {
        let input: Vec<u8> = (0..1000).map(|i| (i * 37 % 256) as u8).collect();
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_long_runs() {
        // Test RLE1 path with many runs
        let mut input = Vec::new();
        for b in 0..10u8 {
            for _ in 0..50 {
                input.push(b);
            }
        }
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_select_num_tables() {
        assert_eq!(select_num_tables(50), 2);
        assert_eq!(select_num_tables(500), 3);
        assert_eq!(select_num_tables(1000), 4);
        assert_eq!(select_num_tables(2000), 5);
        assert_eq!(select_num_tables(5000), 6);
    }

    #[test]
    fn test_roundtrip_multi_block() {
        // Use level 1 (100KB block size) with >100KB input to force multiple blocks
        let input: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
        let compressed = encode_with_level(&input, 1);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_multi_block_with_runs() {
        // Data with long runs that expand differently under RLE1,
        // ensuring block splitting based on RLE1 output size works correctly
        let mut input = Vec::new();
        for _ in 0..500 {
            // 300 copies of 'A' → RLE1 produces [A,A,A,A,255, A,A,A,A,36] = 10 bytes
            input.extend(core::iter::repeat_n(b'A', 300));
            // 10 different bytes → 10 bytes in RLE1
            for b in 0..10u8 {
                input.push(b);
            }
        }
        let compressed = encode_with_level(&input, 1);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_level_clamping() {
        let input = b"test data for level clamping";
        // Level 0 should be clamped to 1
        let c0 = encode_with_level(input, 0);
        let c1 = encode_with_level(input, 1);
        assert_eq!(c0, c1);
        // Level 10 should be clamped to 9
        let c10 = encode_with_level(input, 10);
        let c9 = encode_with_level(input, 9);
        assert_eq!(c10, c9);
        // Both should decode correctly
        assert_eq!(decode::decode(&c0).unwrap(), input);
        assert_eq!(decode::decode(&c10).unwrap(), input);
    }

    #[test]
    fn test_apply_rle1_bounded() {
        // Verify bounded RLE1 respects the output limit
        let input: Vec<u8> = (0..200).map(|i| (i % 50) as u8).collect();
        let (output, consumed) = apply_rle1_bounded(&input, 100);
        assert!(output.len() <= 100);
        assert!(consumed <= input.len());
        // Full RLE1 should produce the same result as bounded with large limit
        let (full_output, full_consumed) = apply_rle1_bounded(&input, usize::MAX);
        assert_eq!(full_consumed, input.len());
        assert_eq!(full_output, apply_rle1(&input));
    }

    #[test]
    fn test_roundtrip_max_rle1_run() {
        // 259 bytes is the maximum RLE1 run length (4 + count byte 255)
        let mut input = vec![b'A'; 259];
        input.extend_from_slice(b"tail"); // add different bytes after
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_single_byte_large() {
        // Large block of all-same bytes: BWT produces all-same output,
        // MTF produces all zeros, RLE2 encodes as a long zero-run.
        let input = vec![0x00u8; 100_000];
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_block_boundary_run() {
        // Create data where a long run of identical bytes spans the block boundary
        // when using level 1 (block size ~99981 after -19 headroom).
        let mut input = Vec::new();
        // Fill most of a block with mixed data
        for i in 0..99_900u32 {
            input.push((i % 251) as u8);
        }
        // Add a long run that will straddle the block boundary
        input.extend(vec![b'Z'; 500]);
        // More data for the second block
        for i in 0..1000u32 {
            input.push((i % 199) as u8);
        }
        let compressed = encode_with_level(&input, 1);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_symbol_map_roundtrip() {
        let mut in_use = [false; 256];
        in_use[0] = true;
        in_use[65] = true; // 'A'
        in_use[255] = true;

        let mut writer = BitWriter::new();
        write_symbol_map(&mut writer, &in_use);
        let data = writer.finish();

        let mut reader = crate::compress::bzip2::bitstream::BitReader::new(&data);
        let parsed = crate::compress::bzip2::decode::parse_symbol_map(&mut reader).unwrap();
        assert_eq!(in_use, parsed);
    }

    #[test]
    fn test_large_zero_run_roundtrip() {
        // 100,000 zeros exercises the bijective base-2 zero-run encoding with
        // large values: after BWT+MTF, all-zero input produces a single very
        // long RUNA/RUNB run that must round-trip correctly.
        let input = vec![0u8; 100_000];
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_single_symbol_block() {
        // Input with only one distinct byte value (n_in_use=1).
        // The Huffman alphabet has only 3 symbols: RUNA, RUNB, EOB.
        let input = vec![b'A'; 500];
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_selector_boundary() {
        // Create data large enough to produce many selectors near the
        // GROUP_SIZE=50 boundary. With varied data the MTF/RLE2 output
        // has roughly as many symbols as input bytes, so ~5000 bytes
        // yields ~100 groups (each 50 symbols), exercising selector
        // encoding/decoding at scale.
        let input: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
        let compressed = encode(&input);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }
}
