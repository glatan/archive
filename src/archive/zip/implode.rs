//! ZIP Imploding (Method 6) codec.
//!
//! Implements the Implode/Explode algorithm described in APPNOTE §5.3,
//! matching the reference implementation (hwzip, public domain).
//!
//! The general purpose bit flag controls the parameters:
//! - Bit 1 (0x0002): 8 KiB dictionary when set, 4 KiB when clear.
//! - Bit 2 (0x0004): 3 Shannon-Fano trees when set (literal + length +
//!   distance), 2 trees when clear (length + distance, literals stored raw).
//!
//! The code tables are stored as run-length encoded codeword lengths: one
//! byte giving the number of length-records minus one, then records with the
//! code length minus one in the low nibble and the run length minus one in
//! the high nibble. Codewords on the wire are the bit-complement of the
//! canonical code, transmitted MSB-first.
//!
//! Stream items start with a flag bit: 1 for a literal, 0 for a back
//! reference. A back reference carries the low distance bits verbatim
//! (7 bits for an 8 KiB dictionary, 6 for 4 KiB), then the high distance
//! bits and the length as Shannon-Fano coded symbols. Length symbol 63 is
//! followed by an extra length byte.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Number of symbols in the literal tree.
const LIT_SYMS: usize = 256;
/// Number of symbols in the length and distance trees.
const MATCH_SYMS: usize = 64;
/// Maximum codeword length.
const MAX_CODE_LEN: u8 = 16;
/// Maximum extra value carried by length symbol 63.
const EXTRA_LEN: usize = 255;
/// Number of buffered tokens used to build the code tables.
const TREE_WINDOW: usize = 32 * 1024;

// ======================================================================
// Decoder
// ======================================================================

/// Decompress data compressed with ZIP method 6 (Imploding).
///
/// `flags` is the general purpose bit flag from the ZIP entry header;
/// `expected_size` is the uncompressed size.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the bitstream or the code tables are
/// malformed, or the stream ends before `expected_size` bytes are produced.
pub(super) fn implode(input: &[u8], flags: u16, expected_size: usize) -> Result<Vec<u8>, Error> {
    if expected_size > crate::util::bounded::DECLARED_OUTPUT_LIMIT {
        return Err(Error::OutputLimitExceeded {
            limit: crate::util::bounded::DECLARED_OUTPUT_LIMIT,
        });
    }
    let large_wnd = (flags & 0x0002) != 0;
    let lit_tree = (flags & 0x0004) != 0;
    let dist_bits = if large_wnd { 7u32 } else { 6u32 };
    let min_len = if lit_tree { 3usize } else { 2usize };

    let mut reader = BitReader::new(input);
    let lit_code = if lit_tree {
        Some(read_code_table(&mut reader, LIT_SYMS)?)
    } else {
        None
    };
    let len_code = read_code_table(&mut reader, MATCH_SYMS)?;
    let dist_code = read_code_table(&mut reader, MATCH_SYMS)?;

    let mut output = Vec::new();
    output
        .try_reserve(expected_size)
        .map_err(|_| Error::InvalidData("zip implode: output too large"))?;
    while output.len() < expected_size {
        let bit = reader
            .try_read_bits(1)
            .ok_or(Error::InvalidData("zip implode: truncated stream"))?;
        if bit == 1 {
            let sym = match &lit_code {
                Some(code) => decode_symbol(&mut reader, code)?,
                None => reader
                    .try_read_bits(8)
                    .ok_or(Error::InvalidData("zip implode: truncated stream"))?
                    as usize,
            };
            output.push(sym as u8);
            continue;
        }

        // Back reference: low distance bits, then high-distance and length
        // symbols.
        let low = reader
            .try_read_bits(dist_bits)
            .ok_or(Error::InvalidData("zip implode: truncated stream"))?;
        let high = decode_symbol(&mut reader, &dist_code)?;
        let dist = ((high as u32) << dist_bits) as usize | low as usize;
        let dist = dist + 1;

        let len_sym = decode_symbol(&mut reader, &len_code)?;
        let mut len = len_sym + min_len;
        if len_sym == 63 {
            let extra = reader
                .try_read_bits(8)
                .ok_or(Error::InvalidData("zip implode: truncated stream"))?;
            len += extra as usize;
        }

        if len > expected_size - output.len() {
            return Err(Error::InvalidData("zip implode: backref overruns output"));
        }
        for _ in 0..len {
            if dist > output.len() {
                // Back references may point into the "implicit zeros" area
                // before the start of the output.
                output.push(0);
                continue;
            }
            let b = output[output.len() - dist];
            output.push(b);
        }
    }

    Ok(output)
}

/// A decoding table: `entries[len][k]` are (flipped_codeword, symbol) pairs.
struct CodeTable {
    /// For each length 1..=16, a sorted list of (flipped code, symbol).
    entries: [Vec<(u16, u16)>; MAX_CODE_LEN as usize],
}

/// Read one run-length encoded code table of `num_syms` symbols.
fn read_code_table(reader: &mut BitReader<'_>, num_syms: usize) -> Result<CodeTable, Error> {
    let num_records = reader.try_read_bits(8).ok_or(Error::UnexpectedEof)? as usize + 1;

    let mut lens = vec![0u8; num_syms];
    let mut idx = 0usize;
    let mut len_count = [0i32; MAX_CODE_LEN as usize + 1];
    for _ in 0..num_records {
        let byte = reader.try_read_bits(8).ok_or(Error::UnexpectedEof)? as usize;
        let len = (byte & 0x0f) + 1;
        let run = (byte >> 4) + 1;
        len_count[len] += run as i32;
        if idx + run > num_syms {
            return Err(Error::InvalidData("zip implode: too many code lengths"));
        }
        for l in lens[idx..idx + run].iter_mut() {
            *l = len as u8;
        }
        idx += run;
    }
    if idx < num_syms {
        return Err(Error::InvalidData("zip implode: too few code lengths"));
    }

    // The tree must be full (Kraft sum exactly one).
    let mut avail = 1i32;
    for &count in len_count.iter().skip(1) {
        avail = avail * 2 - count;
        if avail < 0 {
            return Err(Error::InvalidData("zip implode: over-subscribed code"));
        }
    }
    if avail != 0 {
        return Err(Error::InvalidData("zip implode: incomplete code"));
    }

    Ok(build_code_table(&lens))
}

/// Build the decode table for codeword lengths in symbol order.
fn build_code_table(lens: &[u8]) -> CodeTable {
    let canonical = canonical_codes(lens);
    let mut entries: [Vec<(u16, u16)>; MAX_CODE_LEN as usize] = Default::default();
    for (sym, (&len, &code)) in lens.iter().zip(canonical.iter()).enumerate() {
        if len == 0 {
            continue;
        }
        let flipped = (!code) & ((1u32 << len) - 1);
        entries[len as usize - 1].push((flipped as u16, sym as u16));
    }
    CodeTable { entries }
}

/// Decode one symbol, consuming bits MSB-first of the flipped codeword.
fn decode_symbol(reader: &mut BitReader<'_>, table: &CodeTable) -> Result<usize, Error> {
    let mut code = 0u16;
    for len in 1..=MAX_CODE_LEN {
        let bit = reader
            .try_read_bits(1)
            .ok_or(Error::InvalidData("zip implode: truncated stream"))?;
        code = (code << 1) | bit as u16;
        for &(c, sym) in &table.entries[len as usize - 1] {
            if c == code {
                return Ok(sym as usize);
            }
        }
    }
    Err(Error::InvalidData("zip implode: invalid codeword"))
}

/// Assign canonical codes: sorted by (length, symbol), sequential within a
/// length, left-shifted when the length increases.
fn canonical_codes(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; MAX_CODE_LEN as usize + 1];
    for &l in lens {
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut next = [0u32; MAX_CODE_LEN as usize + 1];
    let mut code = 0u32;
    for l in 1..=MAX_CODE_LEN as usize {
        code = (code + count[l - 1]) << 1;
        next[l] = code;
    }
    let mut codes = vec![0u32; lens.len()];
    for (sym, &l) in lens.iter().enumerate() {
        if l != 0 {
            codes[sym] = next[l as usize];
            next[l as usize] += 1;
        }
    }
    codes
}

// ======================================================================
// Encoder
// ======================================================================

/// Compress data with the ZIP Implode algorithm.
///
/// `large_wnd` selects the 8 KiB dictionary (otherwise 4 KiB); `lit_tree`
/// selects the 3-tree mode with Huffman-coded literals (otherwise literals
/// are stored as raw bytes). These correspond to general purpose flag bits 1
/// and 2 in the ZIP entry header.
pub(super) fn implode_encode(input: &[u8], large_wnd: bool, lit_tree: bool) -> Vec<u8> {
    let max_dist = if large_wnd { 8192 } else { 4096 };
    let min_len = if lit_tree { 3 } else { 2 };
    let max_len = min_len + 63 + EXTRA_LEN;
    let dist_bits = if large_wnd { 7u32 } else { 6u32 };

    let tokens = super::lzmatch::lz_match(input, max_dist, max_len, min_len, true);

    // Frequency tables over the first TREE_WINDOW tokens.
    let mut lit_freq = [0u32; LIT_SYMS];
    let mut len_freq = [0u32; MATCH_SYMS];
    let mut dist_freq = [0u32; MATCH_SYMS];
    for t in tokens.iter().take(TREE_WINDOW) {
        if t.dist == 0 {
            lit_freq[t.litlen as usize] += 1;
        } else {
            len_freq[len_sym(t.litlen as usize, lit_tree)] += 1;
            dist_freq[dist_sym(t.dist as usize, large_wnd)] += 1;
        }
    }

    let lit_lens = if lit_tree {
        Some(code_lengths(&lit_freq))
    } else {
        None
    };
    let len_lens = code_lengths(&len_freq);
    let dist_lens = code_lengths(&dist_freq);
    let lit_codes = lit_lens.as_deref().map(canonical_codes);
    let len_codes = canonical_codes(&len_lens);
    let dist_codes = canonical_codes(&dist_lens);

    let mut out = BitWriter::new();
    if let Some(lens) = &lit_lens {
        write_code_table(&mut out, lens);
    }
    write_code_table(&mut out, &len_lens);
    write_code_table(&mut out, &dist_lens);

    for t in &tokens {
        if t.dist == 0 {
            out.write_bits(1, 1);
            match (lit_tree, &lit_lens, &lit_codes) {
                (true, Some(lens), Some(codes)) => {
                    write_codeword(&mut out, codes[t.litlen as usize], lens[t.litlen as usize]);
                }
                _ => out.write_bits(t.litlen as u32, 8),
            }
            continue;
        }
        // Back reference.
        let dist = t.dist as usize;
        let len = t.litlen as usize;
        out.write_bits(0, 1);
        out.write_bits(((dist - 1) & ((1 << dist_bits) - 1)) as u32, dist_bits);
        let dsym = dist_sym(dist, large_wnd);
        write_codeword(&mut out, dist_codes[dsym], dist_lens[dsym]);
        let lsym = len_sym(len, lit_tree);
        write_codeword(&mut out, len_codes[lsym], len_lens[lsym]);
        if lsym == 63 {
            out.write_bits((len - 63 - min_len) as u32, 8);
        }
    }
    out.finish()
}

/// Distance tree symbol for a 1-based distance.
const fn dist_sym(dist: usize, large_wnd: bool) -> usize {
    let shift = if large_wnd { 7 } else { 6 };
    (dist - 1) >> shift
}

/// Length tree symbol for a match length.
const fn len_sym(len: usize, lit_tree: bool) -> usize {
    let adj = len - if lit_tree { 3 } else { 2 };
    if adj < 63 { adj } else { 63 }
}

/// Write a flipped canonical codeword, MSB-first.
fn write_codeword(out: &mut BitWriter, code: u32, len: u8) {
    let flipped = !code & ((1u32 << len) - 1);
    for i in (0..len as u32).rev() {
        out.write_bits((flipped >> i) & 1, 1);
    }
}

/// Write a code table as run-length encoded lengths (high nibble = run-1,
/// low nibble = len-1).
fn write_code_table(out: &mut BitWriter, lens: &[u8]) {
    let mut records: Vec<(u8, u8)> = Vec::new(); // (len, run)
    for &l in lens {
        debug_assert!((1..=MAX_CODE_LEN).contains(&l));
        match records.last_mut() {
            Some(&mut (len, ref mut run)) if len == l && *run < 16 => *run += 1,
            _ => records.push((l, 1)),
        }
    }
    out.write_bits(records.len() as u32 - 1, 8);
    for &(len, run) in &records {
        out.write_bits(((run as u32 - 1) << 4) | (len as u32 - 1), 8);
    }
}

/// Compute Kraft-complete codeword lengths (1..=16) for every symbol.
///
/// Every symbol receives a non-zero frequency (Implode requires a full
/// tree), then Huffman code lengths are computed. When the Huffman depth
/// exceeds 16 the code degrades to a flat, still valid, assignment.
fn code_lengths(freqs: &[u32]) -> Vec<u8> {
    let n = freqs.len();
    let mut f = [0u32; LIT_SYMS];
    for (i, &x) in freqs.iter().enumerate() {
        f[i] = x.max(1);
    }

    // Standard Huffman over the adjusted frequencies.
    let lengths = huffman_lengths(&f[..n]);
    if *lengths.iter().max().unwrap_or(&0) <= MAX_CODE_LEN {
        return lengths;
    }

    // Fallback: a balanced code is always Kraft-complete.
    let bits = (usize::BITS - (n - 1).leading_zeros()) as u8;
    let bits = bits.max(1);
    vec![bits; n]
}

/// Huffman code lengths for frequencies (all non-zero).
fn huffman_lengths(freqs: &[u32]) -> Vec<u8> {
    let n = freqs.len();
    let mut lens = vec![0u8; n];
    if n == 1 {
        lens[0] = 1;
        return lens;
    }
    // Sort leaves by frequency ascending.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| freqs[i]);
    let total = 2 * n - 1;
    let mut node_freq = vec![0u64; total];
    let mut parent = vec![usize::MAX; total];
    for (i, &sym) in order.iter().enumerate() {
        node_freq[i] = freqs[sym] as u64;
    }
    let mut q1 = 0usize;
    let mut q2 = 0usize;
    for k in 0..n - 1 {
        let internal = n + k;
        let take = |nodes: &[u64], q1: &mut usize, q2: &mut usize| -> usize {
            let a = if *q1 < n { Some(*q1) } else { None };
            let b = if n + *q2 < internal {
                Some(n + *q2)
            } else {
                None
            };
            match (a, b) {
                (Some(x), Some(y)) if nodes[x] <= nodes[y] => {
                    *q1 += 1;
                    x
                }
                (Some(_), Some(y)) => {
                    *q2 += 1;
                    y
                }
                (Some(x), None) => {
                    *q1 += 1;
                    x
                }
                (None, Some(y)) => {
                    *q2 += 1;
                    y
                }
                (None, None) => unreachable!(),
            }
        };
        let a = take(&node_freq, &mut q1, &mut q2);
        let b = take(&node_freq, &mut q1, &mut q2);
        node_freq[internal] = node_freq[a] + node_freq[b];
        parent[a] = internal;
        parent[b] = internal;
    }
    let mut depth = vec![0u8; total];
    let root = total - 1;
    for i in (0..root).rev() {
        if parent[i] != usize::MAX {
            depth[i] = depth[parent[i]] + 1;
        }
    }
    for (i, &sym) in order.iter().enumerate() {
        lens[sym] = depth[i].max(1);
    }
    lens
}

// ======================================================================
// Bit-level I/O (LSB-first)
// ======================================================================

/// LSB-first bitstream reader.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Read `count` bits; returns `None` past the end of input.
    fn try_read_bits(&mut self, count: u32) -> Option<u32> {
        if count == 0 {
            return Some(0);
        }
        if self.bit_pos + count as usize > self.data.len() * 8 {
            return None;
        }
        let mut result = 0u32;
        for i in 0..count as usize {
            let idx = self.bit_pos + i;
            if (self.data[idx / 8] >> (idx % 8)) & 1 != 0 {
                result |= 1 << i;
            }
        }
        self.bit_pos += count as usize;
        Some(result)
    }
}

/// LSB-first bitstream writer.
struct BitWriter {
    buf: Vec<u8>,
    bit_pos: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }

    /// Write the low `count` bits of `value`, LSB-first.
    fn write_bits(&mut self, value: u32, count: u32) {
        for i in 0..count as usize {
            let idx = self.bit_pos + i;
            if idx / 8 == self.buf.len() {
                self.buf.push(0);
            }
            if (value >> i) & 1 != 0 {
                self.buf[idx / 8] |= 1 << (idx % 8);
            }
        }
        self.bit_pos += count as usize;
    }

    /// Return the byte buffer, zero-padding the final partial byte.
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;

    fn rt(data: &[u8], large_wnd: bool, lit_tree: bool) {
        let flags = (large_wnd as u16) << 1 | (lit_tree as u16) << 2;
        let compressed = implode_encode(data, large_wnd, lit_tree);
        assert_eq!(implode(&compressed, flags, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_all_modes() {
        let data = b"implode test data with some repetition repetition repetition";
        for &lw in &[false, true] {
            for &lt in &[false, true] {
                rt(data, lw, lt);
            }
        }
    }

    #[test]
    fn roundtrip_repetitive() {
        let mut data = Vec::new();
        for i in 0..3000 {
            data.extend_from_slice(b"hello world ");
            data.push(i as u8);
        }
        for &lw in &[false, true] {
            for &lt in &[false, true] {
                let flags = (lw as u16) << 1 | (lt as u16) << 2;
                let compressed = implode_encode(&data, lw, lt);
                assert!(compressed.len() < data.len() / 3);
                assert_eq!(implode(&compressed, flags, data.len()).unwrap(), data);
            }
        }
    }

    #[test]
    fn roundtrip_random() {
        let mut state = 99u32;
        let data: Vec<u8> = (0..60_000)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 16) as u8
            })
            .collect();
        rt(&data, true, true);
        rt(&data, false, false);
    }

    #[test]
    fn roundtrip_empty() {
        rt(b"", true, true);
        rt(b"", false, false);
    }

    #[test]
    fn roundtrip_long_match() {
        // Force extra-length-byte backrefs (len > 63 + min_len).
        let data: Vec<u8> = b"Q".repeat(500);
        rt(&data, true, true);
        rt(&data, false, false);
    }

    #[test]
    fn implode_bad_table_overrun() {
        // First table byte says 200 records: exhausts 64 symbols quickly.
        let mut buf = vec![200u8];
        // Each record: len 1, run 16 -> 200*16 = 3200 > 64 symbols.
        buf.extend(core::iter::repeat_n(0xF0, 10));
        let flags = 0x0006u16;
        assert!(implode(&buf, flags, 100).is_err());
    }

    #[test]
    fn implode_incomplete_code() {
        // A code that does not form a complete tree must be rejected.
        // lit tree: one record len=1 run=1 -> only 1 of 256 symbols covered.
        let mut buf = vec![0u8]; // lit: 1 record, len 1 run 1
        buf.push(0x00);
        buf.push(0u8); // len tree: 1 record len 1 run 1
        buf.push(0x00);
        buf.push(0u8); // dist tree: 1 record len 1 run 1
        buf.push(0x00);
        let flags = 0x0006u16;
        assert!(implode(&buf, flags, 100).is_err());
    }

    #[test]
    fn implode_truncated() {
        let data = b"truncate me truncate me truncate me";
        let compressed = implode_encode(data, true, true);
        assert!(implode(&compressed[..2], 0x0006, data.len()).is_err());
    }
}
