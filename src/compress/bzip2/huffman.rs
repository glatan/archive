//! bzip2-specific Huffman coding.
//!
//! bzip2 uses canonical Huffman codes with MSB-first bit ordering,
//! code lengths 1-20, and multiple tables per block with selectors.

use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::error::Error;

use super::bitstream::{BitReader, BitWriter};

/// Maximum Huffman code length in bzip2.
pub(crate) const MAX_CODE_LEN: u8 = 20;

/// Maximum number of Huffman tables per block.
pub(crate) const MAX_TABLES: usize = 6;

/// Number of symbols per selector group.
pub(crate) const GROUP_SIZE: usize = 50;

/// A bzip2 Huffman table.
#[derive(Clone)]
pub(crate) struct HuffmanTable {
    /// Code lengths for each symbol.
    pub(crate) lengths: Vec<u8>,
    /// Minimum code length.
    min_len: u8,
    /// Maximum code length.
    max_len: u8,
    /// For decoding: limit[i] is the maximum code value at length i.
    limits: Vec<i32>,
    /// For decoding: base[i] is the first code value at length i.
    bases: Vec<i32>,
    /// For decoding: perm_base[i] is the perm offset for length i.
    perm_base: Vec<usize>,
    /// For decoding: permutation table mapping sorted position to symbol.
    perms: Vec<u16>,
    /// For encoding: canonical codes per symbol.
    codes: Vec<u32>,
}

impl HuffmanTable {
    /// Build a Huffman table from code lengths.
    pub(crate) fn from_lengths(lengths: &[u8]) -> Result<Self, Error> {
        let n = lengths.len();
        if n == 0 {
            return Err(Error::InvalidData("empty Huffman table"));
        }

        let min_len = *lengths.iter().filter(|&&l| l > 0).min().unwrap_or(&1);
        let max_len = *lengths.iter().max().unwrap_or(&1);

        if max_len > MAX_CODE_LEN {
            return Err(Error::InvalidData("bzip2 Huffman code length exceeds 20"));
        }

        // Count codes per length
        let mut count = vec![0u32; (max_len as usize) + 1];
        for &l in lengths {
            if l > 0 {
                count[l as usize] += 1;
            }
        }

        // Build canonical code bases and limits per length, and perm offsets
        let size = (max_len as usize) + 1;
        let mut bases = vec![-1i32; size];
        let mut limits = vec![-1i32; size];
        let mut perm_base = vec![0usize; size];

        let mut code = 0i32;
        let mut perm_offset = 0usize;
        for i in min_len..=max_len {
            let c = count[i as usize] as i32;
            bases[i as usize] = code;
            perm_base[i as usize] = perm_offset;
            code += c;
            if c > 0 {
                limits[i as usize] = code - 1;
            } else {
                limits[i as usize] = -1; // no valid code at this length
            }
            perm_offset += c as usize;
            code <<= 1;
        }

        // Build permutation: for each length, list symbols in order of appearance
        let total_symbols: usize = count.iter().sum::<u32>() as usize;
        let mut perms = vec![0u16; total_symbols];
        let mut idx = perm_base.clone();
        for (sym, &l) in lengths.iter().enumerate() {
            if l > 0 {
                perms[idx[l as usize]] = sym as u16;
                idx[l as usize] += 1;
            }
        }

        // Build encoding codes (canonical)
        let mut codes = vec![0u32; n];
        let mut next_code = vec![0u32; size];
        let mut c = 0u32;
        for i in min_len..=max_len {
            next_code[i as usize] = c;
            c = (c + count[i as usize]) << 1;
        }
        for (sym, &l) in lengths.iter().enumerate() {
            if l > 0 {
                codes[sym] = next_code[l as usize];
                next_code[l as usize] += 1;
            }
        }

        Ok(Self {
            lengths: lengths.to_vec(),
            min_len,
            max_len,
            limits,
            bases,
            perm_base,
            perms,
            codes,
        })
    }

    /// Decode a single symbol from the bitstream.
    pub(crate) fn decode_symbol(&self, reader: &mut BitReader) -> Result<u16, Error> {
        // Read min_len bits to start
        let mut code = reader.read_bits(self.min_len)? as i32;
        let mut len = self.min_len;

        loop {
            let limit = self.limits[len as usize];
            if limit >= 0 && code <= limit {
                let idx = self.perm_base[len as usize] + (code - self.bases[len as usize]) as usize;
                return Ok(self.perms[idx]);
            }
            len += 1;
            if len > self.max_len {
                return Err(Error::InvalidData("invalid bzip2 Huffman code"));
            }
            code = (code << 1) | reader.read_bits(1)? as i32;
        }
    }

    /// Encode a symbol to the bitstream.
    pub(crate) fn encode_symbol(&self, writer: &mut BitWriter, symbol: u16) {
        let len = self.lengths[symbol as usize];
        let code = self.codes[symbol as usize];
        writer.write_bits(code, len);
    }
}

/// Parse Huffman tables from the bzip2 bitstream.
///
/// Reads `num_tables` tables, each with `num_symbols` entries, using
/// delta-encoded bit lengths (5-bit start + up/down deltas).
pub(crate) fn parse_huffman_tables(
    reader: &mut BitReader,
    num_tables: usize,
    num_symbols: usize,
) -> Result<Vec<HuffmanTable>, Error> {
    let mut tables = Vec::with_capacity(num_tables);

    for _ in 0..num_tables {
        let mut lengths = vec![0u8; num_symbols];
        let mut curr = reader.read_bits(5)? as i32;

        for length in lengths.iter_mut() {
            loop {
                if curr < 1 || curr > MAX_CODE_LEN as i32 {
                    return Err(Error::InvalidData("bzip2 Huffman code length out of range"));
                }
                if !reader.read_bool()? {
                    break;
                }
                if reader.read_bool()? {
                    curr -= 1;
                } else {
                    curr += 1;
                }
            }
            *length = curr as u8;
        }

        tables.push(HuffmanTable::from_lengths(&lengths)?);
    }

    Ok(tables)
}

/// Write Huffman tables to the bitstream using delta encoding.
pub(crate) fn write_huffman_tables(writer: &mut BitWriter, tables: &[HuffmanTable]) {
    for table in tables {
        let mut curr = table.lengths[0] as i32;
        writer.write_bits(curr as u32, 5);

        for &len in &table.lengths {
            let target = len as i32;
            while curr != target {
                writer.write_bool(true);
                if target > curr {
                    writer.write_bool(false); // increment
                    curr += 1;
                } else {
                    writer.write_bool(true); // decrement
                    curr -= 1;
                }
            }
            writer.write_bool(false); // end of deltas for this symbol
        }
    }
}

/// Build a Huffman table from symbol frequencies with length-limited codes.
///
/// Uses a simple algorithm: assign lengths based on frequency ranking,
/// with a maximum code length of `MAX_CODE_LEN` (20).
pub(crate) fn build_huffman_table(freqs: &[u32], num_symbols: usize) -> HuffmanTable {
    let mut lengths = vec![0u8; num_symbols];

    // All symbols must get a non-zero length in bzip2.
    // Use frequency + 1 to ensure every symbol participates in the tree.
    let mut adjusted_freqs: Vec<(u32, usize)> = (0..num_symbols)
        .map(|i| {
            let f = if freqs[i] > 0 { freqs[i] } else { 1 };
            (f, i)
        })
        .collect();
    adjusted_freqs.sort_by_key(|a| Reverse(a.0));

    if num_symbols == 1 {
        lengths[0] = 1;
        return HuffmanTable::from_lengths(&lengths).unwrap();
    }

    let code_lengths = compute_huffman_lengths(&adjusted_freqs);
    for (i, &(_, sym)) in adjusted_freqs.iter().enumerate() {
        lengths[sym] = code_lengths[i].max(1);
    }

    // Enforce maximum code length while maintaining Kraft inequality.
    // If any length exceeds MAX_CODE_LEN, iteratively redistribute:
    // shorten the longest codes and lengthen the shortest to compensate.
    enforce_max_code_length(&mut lengths, MAX_CODE_LEN);

    HuffmanTable::from_lengths(&lengths).unwrap()
}

/// Enforce a maximum code length while maintaining a valid prefix code.
///
/// Iteratively clamps lengths that exceed `max_len` and redistributes
/// excess code space to shorter lengths to satisfy the Kraft inequality.
fn enforce_max_code_length(lengths: &mut [u8], max_len: u8) {
    let n = lengths.len();
    if n <= 1 {
        return;
    }

    // Check if any length exceeds max_len
    let needs_fix = lengths.iter().any(|&l| l > max_len);
    if !needs_fix {
        return;
    }

    // Clamp all lengths to max_len
    for l in lengths.iter_mut() {
        if *l > max_len {
            *l = max_len;
        }
    }

    // Repair Kraft inequality: sum of 2^(max_len - len_i) must equal 2^max_len.
    // If the sum exceeds the target (over-complete), we need to increase some lengths.
    loop {
        let target = 1u64 << max_len;
        let kraft_sum: u64 = lengths
            .iter()
            .filter(|&&l| l > 0)
            .map(|&l| 1u64 << (max_len - l))
            .sum();

        if kraft_sum <= target {
            break;
        }

        // Find the shortest code length and increase it by 1
        let min_len = *lengths.iter().filter(|&&l| l > 0).min().unwrap();
        for l in lengths.iter_mut() {
            if *l == min_len {
                *l += 1;
                break; // Only fix one at a time
            }
        }
    }
}

/// Compute Huffman code lengths for symbols sorted by frequency (descending).
fn compute_huffman_lengths(sorted: &[(u32, usize)]) -> Vec<u8> {
    let n = sorted.len();
    if n <= 1 {
        return vec![1; n];
    }

    // Build Huffman tree via parent pointers and two-queue merging
    let total = 2 * n - 1;
    let mut tree_freq = vec![0u64; total];
    let mut parent = vec![0usize; total];
    let mut depth = vec![0u8; total];

    // Sort leaf frequencies ascending, remember original indices
    let mut indexed: Vec<(u64, usize)> = sorted
        .iter()
        .enumerate()
        .map(|(i, &(f, _))| (f as u64, i))
        .collect();
    indexed.sort();

    for (i, &(f, _)) in indexed.iter().enumerate() {
        tree_freq[i] = f;
    }

    let mut leaf_ptr = 0usize;
    let mut int_ptr = n;
    let mut next_internal = n;

    for _ in 0..(n - 1) {
        // Pick two smallest
        let a = pick_smallest(&tree_freq, &mut leaf_ptr, &mut int_ptr, n, next_internal);
        let b = pick_smallest(&tree_freq, &mut leaf_ptr, &mut int_ptr, n, next_internal);
        tree_freq[next_internal] = tree_freq[a] + tree_freq[b];
        parent[a] = next_internal;
        parent[b] = next_internal;
        next_internal += 1;
    }

    // Root has no parent
    let root = next_internal - 1;
    depth[root] = 0;
    for i in (0..root).rev() {
        depth[i] = depth[parent[i]] + 1;
    }

    // Map back to original symbol order
    let mut result = vec![0u8; n];
    for (i, &(_, orig_idx)) in indexed.iter().enumerate() {
        result[orig_idx] = depth[i].min(MAX_CODE_LEN);
    }

    result
}

fn pick_smallest(
    freq: &[u64],
    leaf_ptr: &mut usize,
    int_ptr: &mut usize,
    n: usize,
    next_internal: usize,
) -> usize {
    let leaf_available = *leaf_ptr < n;
    let int_available = *int_ptr < next_internal;

    if !leaf_available && !int_available {
        unreachable!();
    }
    if !int_available || (leaf_available && freq[*leaf_ptr] <= freq[*int_ptr]) {
        let idx = *leaf_ptr;
        *leaf_ptr += 1;
        idx
    } else {
        let idx = *int_ptr;
        *int_ptr += 1;
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_roundtrip() {
        let lengths = [2u8, 2, 3, 3, 3, 3];
        let table = HuffmanTable::from_lengths(&lengths).unwrap();

        let symbols = [0u16, 1, 2, 3, 4, 5, 0, 1];
        let mut writer = BitWriter::new();
        for &s in &symbols {
            table.encode_symbol(&mut writer, s);
        }
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        for &expected in &symbols {
            assert_eq!(table.decode_symbol(&mut reader).unwrap(), expected);
        }
    }

    #[test]
    fn test_parse_write_huffman_tables() {
        let lengths1 = vec![3u8, 3, 3, 3, 2, 2, 4, 4];
        let lengths2 = vec![2u8, 2, 3, 3, 4, 4, 4, 4];
        let t1 = HuffmanTable::from_lengths(&lengths1).unwrap();
        let t2 = HuffmanTable::from_lengths(&lengths2).unwrap();

        let mut writer = BitWriter::new();
        write_huffman_tables(&mut writer, &[t1.clone(), t2.clone()]);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        let tables = parse_huffman_tables(&mut reader, 2, 8).unwrap();
        assert_eq!(tables[0].lengths, lengths1);
        assert_eq!(tables[1].lengths, lengths2);
    }

    #[test]
    fn test_build_huffman_table() {
        let freqs = [100u32, 50, 25, 10, 5, 1];
        let table = build_huffman_table(&freqs, 6);
        // All active symbols should have valid lengths
        for i in 0..6 {
            assert!(table.lengths[i] >= 1);
            assert!(table.lengths[i] <= MAX_CODE_LEN);
        }
        // Most frequent symbol should have shortest code
        assert!(table.lengths[0] <= table.lengths[5]);
    }

    #[test]
    fn test_code_length_exceeds_20() {
        let lengths = vec![21u8; 4];
        let result = HuffmanTable::from_lengths(&lengths);
        assert!(result.is_err());
    }

    #[test]
    fn test_huffman_uniform_lengths() {
        // All symbols have the same code length (min_len == max_len)
        let lengths = vec![4u8; 16]; // 16 symbols, all length 4 → 2^4 = 16, exact fit
        let table = HuffmanTable::from_lengths(&lengths).unwrap();

        let symbols: Vec<u16> = (0..16).collect();
        let mut writer = BitWriter::new();
        for &s in &symbols {
            table.encode_symbol(&mut writer, s);
        }
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        for &expected in &symbols {
            assert_eq!(table.decode_symbol(&mut reader).unwrap(), expected);
        }
    }

    #[test]
    fn test_enforce_max_code_length() {
        // Build a table from very skewed frequencies to exercise depth limiting
        let mut freqs = vec![1u32; 258];
        freqs[0] = 1_000_000; // one very frequent symbol
        let table = build_huffman_table(&freqs, 258);
        for &l in &table.lengths {
            assert!((1..=MAX_CODE_LEN).contains(&l), "length {} out of range", l);
        }
        // Verify the table produces valid encode/decode roundtrip
        let mut writer = BitWriter::new();
        for s in 0..258u16 {
            table.encode_symbol(&mut writer, s);
        }
        let data = writer.finish();
        let mut reader = BitReader::new(&data);
        for s in 0..258u16 {
            assert_eq!(table.decode_symbol(&mut reader).unwrap(), s);
        }
    }
}
