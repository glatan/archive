//! ZIP Expanding (Methods 2-5) codec.
//!
//! Implements the Reduce/Expand algorithm as described in APPNOTE §5.2,
//! matching the reference implementation (hwzip, public domain).
//!
//! The format combines LZ77 dictionary compression with follower-set
//! statistical coding:
//!
//! - The LZ layer emits literal bytes and back references. Back references
//!   are introduced by a DLE marker (byte 144 = 0x90), followed by a `V` byte
//!   combining distance-high and length bits, an optional extra length byte,
//!   and a `W` byte with the low distance bits. A literal 0x90 is written as
//!   DLE followed by a zero byte.
//! - The resulting byte stream is then coded with per-byte "follower sets":
//!   for each predecessor byte value, up to 32 common successor bytes are
//!   stored in a table. When the previous byte has followers, a 0 bit selects
//!   a follower index; a 1 bit precedes a literal byte.
//!
//! The compression factor (methods 2-5 map to factors 1-4) splits the `V`
//! byte between distance-high bits (`factor` bits) and length bits
//! (`8 - factor` bits).

use alloc::vec::Vec;

use crate::error::Error;

/// The DLE marker byte introducing back references (0x90).
const DLE_BYTE: u8 = 144;
/// Maximum number of followers per predecessor byte.
const MAX_FOLLOWERS: usize = 32;
/// Number of raw bytes used to compute the follower sets.
const FOLLOWER_WINDOW: usize = 64 * 1024;

/// Bits used for follower indices for a follower set of size `n`.
const fn follower_idx_bw(n: usize) -> u32 {
    if n > 16 {
        5
    } else if n > 8 {
        4
    } else if n > 4 {
        3
    } else if n > 2 {
        2
    } else if n > 0 {
        1
    } else {
        0
    }
}

/// Maximum back-reference length for a compression factor.
const fn max_len(factor: u8) -> usize {
    let v_len_bits = 8 - factor as usize;
    ((1usize << v_len_bits) - 1) + 255 + 3
}

/// Maximum back-reference distance for a compression factor.
const fn max_dist(factor: u8) -> usize {
    ((1usize << factor as usize) - 1) * 256 + 255 + 1
}

// ======================================================================
// Decoder
// ======================================================================

/// Expand (decompress) data compressed with ZIP methods 2-5 (Reducing).
///
/// `factor` must be 1-4, corresponding to methods 2-5. `expected_size` is the
/// uncompressed size from the ZIP entry header.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the stream is malformed or ends before
/// `expected_size` bytes have been produced.
pub(super) fn expand(input: &[u8], factor: u8, expected_size: usize) -> Result<Vec<u8>, Error> {
    if !(1..=4).contains(&factor) {
        return Err(Error::InvalidData("zip expand: factor must be 1-4"));
    }

    let mut reader = BitReader::new(input);

    // Follower sets are stored for bytes 255 down to 0.
    let mut fset_size = [0usize; 256];
    let mut fset_idx_bw = [0u32; 256];
    let mut fsets: [Vec<u8>; 256] = core::array::from_fn(|_| Vec::new());
    for i in (0..256usize).rev() {
        let n = reader.try_read_bits(6).ok_or(Error::UnexpectedEof)? as usize;
        if n > MAX_FOLLOWERS {
            return Err(Error::InvalidData(
                "zip expand: follower count exceeds maximum",
            ));
        }
        fset_size[i] = n;
        fset_idx_bw[i] = follower_idx_bw(n);
        for _ in 0..n {
            let f = reader.try_read_bits(8).ok_or(Error::UnexpectedEof)? as u8;
            fsets[i].push(f);
        }
    }

    let v_len_bits = 8 - factor as u32;
    let mut output = Vec::with_capacity(expected_size);
    let mut prev = 0u8; // The first "previous byte" is implicitly zero.

    while output.len() < expected_size {
        let b = read_next_byte(&mut reader, prev, &fsets, &fset_idx_bw)
            .ok_or(Error::InvalidData("zip expand: truncated stream"))?;
        if b != DLE_BYTE {
            output.push(b);
            prev = b;
            continue;
        }
        // DLE: read the V byte.
        let v = read_next_byte(&mut reader, b, &fsets, &fset_idx_bw)
            .ok_or(Error::InvalidData("zip expand: truncated stream"))?;
        if v == 0 {
            // Literal DLE byte; the last raw byte was the zero.
            output.push(DLE_BYTE);
            prev = 0;
            continue;
        }
        let mut len = (v as u32) & ((1u32 << v_len_bits) - 1);
        prev = v;
        if len == (1u32 << v_len_bits) - 1 {
            // Extra length byte.
            let elb = read_next_byte(&mut reader, prev, &fsets, &fset_idx_bw)
                .ok_or(Error::InvalidData("zip expand: truncated stream"))?;
            len += elb as u32;
            prev = elb;
        }
        len += 3;

        // W byte: low distance bits.
        let w = read_next_byte(&mut reader, prev, &fsets, &fset_idx_bw)
            .ok_or(Error::InvalidData("zip expand: truncated stream"))?;
        prev = w;
        let dist = ((v as u32) >> v_len_bits) as usize * 256 + w as usize + 1;
        let len = len as usize;

        if len > expected_size - output.len() {
            return Err(Error::InvalidData("zip expand: backref overruns output"));
        }
        // Copy, handling overlap and implicit zeros for dist > position.
        for _ in 0..len {
            if dist > output.len() {
                output.push(0);
                continue;
            }
            let byte = output[output.len() - dist];
            output.push(byte);
        }
    }

    Ok(output)
}

/// Read the next byte from the stream, decoded via the follower sets.
/// Returns `None` when the stream is exhausted.
fn read_next_byte(
    reader: &mut BitReader<'_>,
    prev: u8,
    fsets: &[Vec<u8>; 256],
    fset_idx_bw: &[u32; 256],
) -> Option<u8> {
    let set = &fsets[prev as usize];
    if set.is_empty() {
        return Some(reader.try_read_bits(8)? as u8);
    }
    if reader.try_read_bits(1)? == 1 {
        // Literal byte.
        return Some(reader.try_read_bits(8)? as u8);
    }
    let idx = reader.try_read_bits(fset_idx_bw[prev as usize])? as usize;
    if idx >= set.len() {
        return None; // out-of-range index
    }
    Some(set[idx])
}

// ======================================================================
// Encoder
// ======================================================================

/// Compress data with the ZIP Reduce algorithm.
///
/// `factor` must be 1-4, corresponding to methods 2-5.
pub(super) fn reduce(input: &[u8], factor: u8) -> Vec<u8> {
    debug_assert!((1..=4).contains(&factor));

    // Stage 1: LZ77 compression into a raw byte stream (literals and
    // DLE-escaped back references).
    let mut raw = Vec::new();
    for t in super::lzmatch::lz_match(input, max_dist(factor), max_len(factor), 4, false) {
        if t.dist == 0 {
            emit_literal(&mut raw, t.litlen as u8);
        } else {
            emit_backref(&mut raw, t.dist as usize, t.litlen as usize, factor);
        }
    }

    // Stage 2: compute follower sets over the first FOLLOWER_WINDOW bytes.
    let table_bytes = &raw[..raw.len().min(FOLLOWER_WINDOW)];
    let mut counts = [[0u32; 256]; 256];
    let mut prev = 0usize;
    for &b in table_bytes {
        counts[prev][b as usize] += 1;
        prev = b as usize;
    }

    // For each predecessor byte choose the follower set minimising total cost.
    let mut chosen: [Vec<u8>; 256] = core::array::from_fn(|_| Vec::new());
    for pred in 0..256usize {
        let mut followers: Vec<(u8, u32)> = counts[pred]
            .iter()
            .enumerate()
            .map(|(b, &c)| (b as u8, c))
            .collect();
        // Sort by count descending, then byte value ascending.
        followers.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut best_n = 0usize;
        let mut best_cost = followers_cost(&followers, 0);
        for n in 1..=MAX_FOLLOWERS {
            let cost = followers_cost(&followers, n);
            if cost < best_cost {
                best_cost = cost;
                best_n = n;
            }
        }
        chosen[pred] = followers[..best_n].iter().map(|f| f.0).collect();
    }

    // Map (prev, byte) -> follower index, and per-prev index width.
    let mut follower_idx = [[0xffu8; 256]; 256];
    let mut idx_bw = [0u32; 256];
    for pred in 0..256usize {
        idx_bw[pred] = follower_idx_bw(chosen[pred].len());
        for (i, &b) in chosen[pred].iter().enumerate() {
            follower_idx[pred][b as usize] = i as u8;
        }
    }

    let mut out = BitWriter::new();
    // Follower sets for bytes 255 down to 0.
    for i in (0..256usize).rev() {
        out.write_bits(chosen[i].len() as u32, 6);
        for &f in &chosen[i] {
            out.write_bits(f as u32, 8);
        }
    }
    // Encode the raw stream.
    let mut prev = 0u8;
    for &b in &raw {
        let fi = follower_idx[prev as usize][b as usize];
        if fi != 0xff {
            // 0 bit + follower index.
            out.write_bits((fi as u32) << 1, idx_bw[prev as usize] + 1);
        } else if idx_bw[prev as usize] != 0 {
            // 1 bit + literal byte.
            out.write_bits(((b as u32) << 1) | 1, 9);
        } else {
            // No follower set: raw literal.
            out.write_bits(b as u32, 8);
        }
        prev = b;
    }
    out.finish()
}

/// Cost in bits of coding with follower set size `n` for sorted `followers`.
fn followers_cost(followers: &[(u8, u32)], n: usize) -> u64 {
    let mut cost = (n * 8) as u64;
    for (i, &(_, count)) in followers.iter().enumerate() {
        if i < n {
            cost += count as u64 * (1 + follower_idx_bw(n) as u64);
        } else if n == 0 {
            cost += count as u64 * 8;
        } else {
            cost += count as u64 * 9;
        }
    }
    cost
}

/// Emit a literal byte, escaping DLE as DLE + 0.
fn emit_literal(raw: &mut Vec<u8>, b: u8) {
    raw.push(b);
    if b == DLE_BYTE {
        raw.push(0);
    }
}

/// Emit a back reference as DLE + V + [extra len] + W.
fn emit_backref(raw: &mut Vec<u8>, dist: usize, len: usize, factor: u8) {
    // Length 3 is unencodable: it would produce V == 0, the literal-DLE escape.
    debug_assert!(len >= 4 && len <= max_len(factor) && dist <= max_dist(factor));
    let v_len_bits = 8 - factor as usize;
    let len = len - 3;
    let dist = dist - 1;
    raw.push(DLE_BYTE);
    let mut v = len.min((1usize << v_len_bits) - 1) as u8;
    v |= ((dist / 256) as u8) << v_len_bits;
    raw.push(v);
    if len >= (1usize << v_len_bits) - 1 {
        raw.push((len - ((1usize << v_len_bits) - 1)) as u8);
    }
    raw.push((dist % 256) as u8);
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

    fn rt(data: &[u8], factor: u8) {
        let compressed = reduce(data, factor);
        assert_eq!(expand(&compressed, factor, data.len()).unwrap(), data);
    }

    #[test]
    fn roundtrip_all_factors() {
        let data = b"the quick brown fox jumps over the lazy dog.                      the quick brown fox jumps over the lazy dog.";
        for f in 1..=4 {
            rt(data, f);
        }
    }

    #[test]
    fn roundtrip_repetitive() {
        let mut data = Vec::new();
        for i in 0..2000 {
            data.extend_from_slice(b"abcabcabc");
            data.push(i as u8);
        }
        for f in 1..=4 {
            let compressed = reduce(&data, f);
            assert!(compressed.len() < data.len() / 2);
            assert_eq!(expand(&compressed, f, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn roundtrip_dle_bytes() {
        // Data containing the DLE marker byte 0x90 heavily.
        let data: Vec<u8> = (0..5000)
            .map(|i| if i % 3 == 0 { 0x90 } else { i as u8 })
            .collect();
        for f in 1..=4 {
            rt(&data, f);
        }
    }

    #[test]
    fn roundtrip_random() {
        let mut state = 42u32;
        let data: Vec<u8> = (0..100_000)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 16) as u8
            })
            .collect();
        for f in 1..=4 {
            rt(&data, f);
        }
    }

    #[test]
    fn roundtrip_empty() {
        for f in 1..=4 {
            rt(b"", f);
        }
    }

    #[test]
    fn roundtrip_short() {
        for f in 1..=4 {
            rt(b"ab", f);
            rt(b"x", f);
        }
    }

    #[test]
    fn expand_follower_count_too_large() {
        // First table byte: count 63 > 32 maximum.
        let buf = vec![63u8];
        assert!(expand(&buf, 1, 10).is_err());
    }

    #[test]
    fn expand_truncated_table() {
        // Claims followers then ends.
        let buf = vec![5u8, 1, 2];
        assert!(expand(&buf, 1, 10).is_err());
    }

    #[test]
    fn expand_truncated_stream() {
        let data = b"hello hello hello hello";
        let compressed = reduce(data, 2);
        assert!(expand(&compressed[..3], 2, data.len()).is_err());
    }

    #[test]
    fn expand_factor_range() {
        assert!(expand(&[], 0, 0).is_err());
        assert!(expand(&[], 5, 0).is_err());
    }
}
