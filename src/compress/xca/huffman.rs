//! LZ77+Huffman ("Xpress Huffman") compression — MS-XCA §2.1/§2.2.
//!
//! The stream is a sequence of blocks; each block produces up to 64 KiB of
//! output. A block starts with a 256-byte table holding the 4-bit code
//! length of each of the 512 Huffman symbols (even symbols in the low
//! nibble, odd in the high nibble), followed by a Huffman bit stream read
//! through a 32-bit register refilled in 16-bit little-endian chunks.
//!
//! Symbols 0–255 are literal bytes; symbol 256 is the end-of-data marker;
//! symbols 257–511 encode matches as `length_class + 16 * offset_bits`.
//! Long lengths carry extra bytes that are interleaved into the stream at
//! the position where the decoder's 16-bit reads have reached.

use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::error::Error;

use super::lz77::MatchTable;

const BLOCK_SIZE: usize = 1 << 16;
const MAX_OFFSET: usize = (1 << 16) - 1;
const MIN_MATCH: usize = 3;
const NUM_SYMBOLS: usize = 512;
const EOF_SYMBOL: usize = 256;

fn high_bit(v: usize) -> usize {
    debug_assert!(v > 0);
    usize::BITS as usize - 1 - v.leading_zeros() as usize
}

// ============================================================
// Decoder
// ============================================================

/// Bit-level reader matching the spec's 32-bit register refilled with
/// 16-bit little-endian words. `pos` also serves as the byte cursor for
/// interleaved extra-length bytes.
struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    bits: u32,
    extra: i32,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8], pos: usize) -> Result<Self, Error> {
        let mut r = Self {
            input,
            pos,
            bits: 0,
            extra: 0,
        };
        r.bits = (r.read_u16()? as u32) << 16;
        r.bits |= r.read_u16()? as u32;
        r.extra = 16;
        Ok(r)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        if self.pos + 2 > self.input.len() {
            return Err(Error::InvalidData("xpress-huff: truncated bit stream"));
        }
        let v = u16::from_le_bytes(self.input[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(Error::InvalidData("xpress-huff: truncated length byte"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Consume `n` bits from the top of the register.
    fn consume(&mut self, n: i32) -> Result<(), Error> {
        self.bits <<= n;
        self.extra -= n;
        if self.extra < 0 {
            let w = self.read_u16()? as u32;
            self.bits |= w << (-self.extra);
            self.extra += 16;
        }
        Ok(())
    }

    /// Read `n` bits (MSB-first) from the stream.
    fn take(&mut self, n: i32) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        let v = self.bits >> (32 - n);
        self.consume(n)?;
        Ok(v)
    }
}

fn decode_block(
    input: &[u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    expected: Option<usize>,
    max_output: usize,
) -> Result<bool, Error> {
    let remaining = input.len() - *pos;
    if remaining < 256 {
        return match expected {
            Some(n) if out.len() >= n => Ok(true),
            _ => Err(Error::InvalidData("xpress-huff: truncated huffman table")),
        };
    }

    // 256-byte code-length table: even symbol in low nibble.
    let mut lengths = [0u8; NUM_SYMBOLS];
    for i in 0..256 {
        lengths[2 * i] = input[*pos + i] & 0x0f;
        lengths[2 * i + 1] = input[*pos + i] >> 4;
    }
    *pos += 256;

    // Build the canonical decoding table: 2^15 slots filled in
    // (bit length, symbol) order.
    let mut table = [0u16; 1 << 15];
    let mut slot = 0usize;
    for bit_len in 1..=15u8 {
        for (sym, &l) in lengths.iter().enumerate() {
            if l == bit_len {
                let count = 1usize << (15 - bit_len);
                if slot + count > table.len() {
                    return Err(Error::InvalidData("xpress-huff: over-subscribed code"));
                }
                for _ in 0..count {
                    table[slot] = sym as u16;
                    slot += 1;
                }
            }
        }
    }
    if slot != table.len() {
        return Err(Error::InvalidData("xpress-huff: incomplete code"));
    }

    let mut reader = BitReader::new(input, *pos)?;
    let block_end = out.len() + BLOCK_SIZE;

    loop {
        if out.len() >= block_end {
            *pos = reader.pos;
            return Ok(false); // continue with next block
        }
        let sym = table[(reader.bits >> 17) as usize] as usize;
        reader.consume(lengths[sym] as i32)?;
        if sym < 256 {
            if out.len() >= max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            out.push(sym as u8);
            continue;
        }
        if sym == EOF_SYMBOL && reader.pos >= input.len() && expected.is_none_or(|n| out.len() >= n)
        {
            *pos = reader.pos;
            return Ok(true);
        }
        // Match symbol (or misplaced EOF with output incomplete).
        let m = sym - 256;
        let mut len = m % 16;
        let off_bits = m / 16;
        if len == 15 {
            len = reader.read_u8()? as usize;
            if len == 255 {
                len = reader.read_u16()? as usize;
                if len < 15 {
                    return Err(Error::InvalidData("xpress-huff: invalid length escape"));
                }
                len -= 15;
            }
            len += 15;
        }
        len += 3;
        let offset = reader.take(off_bits as i32)? as usize + (1usize << off_bits);
        if offset > out.len() {
            return Err(Error::InvalidData("xpress-huff: match offset before start"));
        }
        if out.len() + len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        let start = out.len() - offset;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
        }
    }
}

/// Decode an LZ77+Huffman stream of unknown decompressed size.
///
/// The stream ends with the EOF symbol; a truncated stream is an error.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_inner(input, None, usize::MAX)
}

/// Decode an LZ77+Huffman stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_inner(input, None, max_output)
}

/// Decode an LZ77+Huffman stream whose decompressed size is known.
pub fn decode_with_size(input: &[u8], output_size: usize) -> Result<Vec<u8>, Error> {
    decode_inner(input, Some(output_size), output_size)
}

fn decode_inner(
    input: &[u8],
    expected: Option<usize>,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let done = decode_block(input, &mut pos, &mut out, expected, max_output)?;
        if done {
            return Ok(out);
        }
    }
}

// ============================================================
// Encoder
// ============================================================

/// Bit stream writer implementing the spec's interleaved layout. The
/// encoder tracks three positions exactly as in MS-XCA §2.1.4.3: `pos1`
/// and `pos2` hold the next two Huffman word slots, while `pos` is the
/// running byte cursor where extra-length bytes are written. Completed
/// 16-bit words are emitted into the oldest pending slot so the output
/// words always trail the byte cursor by two words, matching the decoder's
/// 32-bit register refill pattern.
struct BitWriter {
    buf: Vec<u8>,
    pos1: usize,
    pos2: usize,
    pos: usize,
    word: u32,
    /// Unemitted bits in `word` (LSB-aligned, `have` bits used).
    have: u32,
}

impl BitWriter {
    fn new(table: &[u8; 256]) -> Self {
        let mut buf = Vec::with_capacity(260);
        buf.extend_from_slice(table);
        buf.extend_from_slice(&[0; 4]);
        Self {
            buf,
            pos1: 256,
            pos2: 258,
            pos: 260,
            word: 0,
            have: 0,
        }
    }

    fn write_at(&mut self, pos: usize, byte: u8) {
        if pos >= self.buf.len() {
            self.buf.resize(pos + 1, 0);
        }
        self.buf[pos] = byte;
    }

    /// Emit a complete 16-bit word into the oldest pending slot and shift
    /// the slot pipeline forward.
    fn emit_word(&mut self, value: u16) {
        self.write_at(self.pos1, (value & 0xff) as u8);
        self.write_at(self.pos1 + 1, (value >> 8) as u8);
        self.pos1 = self.pos2;
        self.pos2 = self.pos;
        self.pos += 2;
    }

    /// Append `n` bits (n <= 16), MSB-first. A word is emitted only when a
    /// write overflows it — this keeps the emitted-word count in lockstep
    /// with the decoder's on-demand 16-bit refills.
    fn bits(&mut self, n: u32, value: u32) {
        debug_assert!(n <= 16 && (value as u64) < (1u64 << n));
        if n == 0 {
            return;
        }
        let free = 16 - self.have;
        if n <= free {
            self.word = (self.word << n) | value;
            self.have += n;
        } else {
            // Top `free` bits of `value` complete the current word.
            self.word = (self.word << free) | (value >> (n - free));
            self.emit_word(self.word as u16);
            let rem = n - free;
            self.word = value & ((1 << rem) - 1);
            self.have = rem;
        }
    }

    fn byte(&mut self, b: u8) {
        self.write_at(self.pos, b);
        self.pos += 1;
    }

    fn u16(&mut self, v: u16) {
        self.write_at(self.pos, (v & 0xff) as u8);
        self.write_at(self.pos + 1, (v >> 8) as u8);
        self.pos += 2;
    }

    fn u32(&mut self, v: u32) {
        for i in 0..4 {
            self.write_at(self.pos + i, ((v >> (8 * i)) & 0xff) as u8);
        }
        self.pos += 4;
    }

    fn flush(mut self) -> Vec<u8> {
        // The spec's FlushBits writes the final (zero-padded) word to
        // OutputPosition1 and a zero word to OutputPosition2 — the two
        // pending slots — without advancing the byte cursor. The stream
        // then ends at `pos`.
        let emit = if self.have > 0 {
            (self.word << (16 - self.have)) as u16
        } else {
            0
        };
        self.write_at(self.pos1, (emit & 0xff) as u8);
        self.write_at(self.pos1 + 1, (emit >> 8) as u8);
        self.write_at(self.pos2, 0);
        self.write_at(self.pos2 + 1, 0);
        self.buf.truncate(self.pos);
        self.buf
    }
}

/// Compute length-limited (<= 15 bit) canonical code lengths for the
/// 512-symbol alphabet from symbol frequencies.
fn code_lengths(freq: &[u32; NUM_SYMBOLS]) -> [u8; NUM_SYMBOLS] {
    const MAX_BITS: usize = 15;
    let mut lengths = [0u8; NUM_SYMBOLS];

    let mut active: Vec<(usize, u64)> = freq
        .iter()
        .enumerate()
        .filter(|&(_, f)| *f > 0)
        .map(|(s, f)| (s, *f as u64))
        .collect();
    if active.is_empty() {
        return lengths;
    }
    if active.len() == 1 {
        lengths[active[0].0] = 1;
        return lengths;
    }

    // Huffman tree via the two-queue method (stable: lower symbol index
    // wins ties), giving optimal code lengths.
    active.sort_by_key(|a| (a.1, a.0));
    let n = active.len();
    let total = 2 * n - 1;
    let mut node_freq = vec![0u64; total];
    let mut parent = vec![usize::MAX; total];
    for (i, &(_, f)) in active.iter().enumerate() {
        node_freq[i] = f;
    }
    let mut q1 = 0usize; // next leaf
    let mut q2 = 0usize; // next internal (offset by n)
    let mut internals = 0usize;
    for _ in 0..n - 1 {
        let a = pick(&node_freq, n, &mut q1, &mut q2, internals);
        let b = pick(&node_freq, n, &mut q1, &mut q2, internals);
        let idx = n + internals;
        node_freq[idx] = node_freq[a] + node_freq[b];
        parent[a] = idx;
        parent[b] = idx;
        internals += 1;
    }
    let mut depth = vec![0u16; total];
    let root = n + internals - 1;
    for i in (0..root).rev() {
        if parent[i] != usize::MAX {
            depth[i] = depth[parent[i]] + 1;
        }
    }

    // Count lengths, capping at MAX_BITS.
    let mut bl_count = [0u32; MAX_BITS + 1];
    for (i, &(sym, _)) in active.iter().enumerate() {
        let l = depth[i].min(MAX_BITS as u16) as u8;
        lengths[sym] = l;
        bl_count[l as usize] += 1;
    }

    // Resolve over-subscription the standard way: repeatedly move one leaf
    // down from the deepest populated shorter length and pull one leaf up
    // from the maximum.
    let mut overflow: i64 = bl_count
        .iter()
        .enumerate()
        .map(|(l, &c)| (c as i64) << (MAX_BITS - l))
        .sum::<i64>()
        - (1i64 << MAX_BITS);
    while overflow > 0 {
        let mut bits = MAX_BITS - 1;
        while bl_count[bits] == 0 {
            bits -= 1;
        }
        bl_count[bits] -= 1;
        bl_count[bits + 1] += 2;
        bl_count[MAX_BITS] -= 1;
        overflow -= 2;
    }

    // Redistribute lengths: least frequent symbols get the longest codes.
    active.sort_by_key(|a| Reverse((a.1, a.0))); // freq desc, sym desc
    let mut idx = 0usize;
    for l in (1..=MAX_BITS).rev() {
        for _ in 0..bl_count[l] {
            lengths[active[idx].0] = l as u8;
            idx += 1;
        }
    }
    lengths
}

fn pick(freq: &[u64], n: usize, q1: &mut usize, q2: &mut usize, internals: usize) -> usize {
    let a = *q1 < n;
    let b = *q2 < internals;
    match (a, b) {
        (true, true) => {
            if freq[*q1] <= freq[n + *q2] {
                let i = *q1;
                *q1 += 1;
                i
            } else {
                let i = n + *q2;
                *q2 += 1;
                i
            }
        }
        (true, false) => {
            let i = *q1;
            *q1 += 1;
            i
        }
        (false, true) => {
            let i = n + *q2;
            *q2 += 1;
            i
        }
        (false, false) => unreachable!(),
    }
}

/// Canonical codes: sort symbols by (length, symbol) and assign successive
/// code values, MSB-aligned to the code length.
fn canonical_codes(lengths: &[u8; NUM_SYMBOLS]) -> [u16; NUM_SYMBOLS] {
    let mut codes = [0u16; NUM_SYMBOLS];
    let mut idx = 0u32;
    for bit_len in 1..=15u8 {
        for (sym, &l) in lengths.iter().enumerate() {
            if l == bit_len {
                codes[sym] = (idx >> (15 - bit_len)) as u16;
                idx += 1 << (15 - bit_len);
            }
        }
    }
    codes
}

/// Item produced by the LZ77 parse.
enum Item {
    Lit(u8),
    Match { len: usize, dist: usize },
}

/// Encode data as an LZ77+Huffman stream.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2 + 300);
    let mut table = MatchTable::new(input);
    let mut pos = 0usize;
    let mut block_start = 0usize;

    while block_start < input.len() || (block_start == 0 && input.is_empty()) {
        let block_limit = (block_start + BLOCK_SIZE).min(input.len());

        // LZ77 parse of this block; matches may reference earlier output
        // within the 64 KiB window but must not cross the block boundary.
        let mut items: Vec<Item> = Vec::new();
        let mut freq = [0u32; NUM_SYMBOLS];
        while pos < block_limit {
            let max_len = block_limit - pos;
            let m = table
                .find(input, pos, MAX_OFFSET.min(pos))
                .map(|(d, l)| (d, l.min(max_len)))
                .filter(|&(_, l)| l >= MIN_MATCH);
            match m {
                Some((dist, len)) => {
                    items.push(Item::Match { len, dist });
                    let sym = 256 + (len - 3).min(15) + 16 * high_bit(dist);
                    freq[sym] += 1;
                    pos += len;
                }
                None => {
                    items.push(Item::Lit(input[pos]));
                    freq[input[pos] as usize] += 1;
                    pos += 1;
                }
            }
        }
        let last_block = pos >= input.len();
        if last_block {
            freq[EOF_SYMBOL] += 1;
        }
        // A one-symbol alphabet cannot fill the 2^15 decode table; pad a
        // second symbol so the code is complete.
        if freq.iter().filter(|&&f| f > 0).count() == 1 {
            let extra = if freq[0] > 0 { 1 } else { 0 };
            freq[extra] = 1;
        }

        let lengths = code_lengths(&freq);
        let codes = canonical_codes(&lengths);

        let mut table_bytes = [0u8; 256];
        for i in 0..256 {
            table_bytes[i] = lengths[2 * i] | (lengths[2 * i + 1] << 4);
        }

        let mut w = BitWriter::new(&table_bytes);
        for item in &items {
            match *item {
                Item::Lit(b) => {
                    let s = b as usize;
                    w.bits(lengths[s] as u32, codes[s] as u32);
                }
                Item::Match { len, dist } => {
                    let s = 256 + (len - 3).min(15) + 16 * high_bit(dist);
                    w.bits(lengths[s] as u32, codes[s] as u32);
                    let mut l = len - 3;
                    if l >= 15 {
                        l -= 15;
                        if l < 255 {
                            w.byte(l as u8);
                        } else {
                            w.byte(255);
                            let full = len - 3;
                            if full < (1 << 16) {
                                w.u16(full as u16);
                            } else {
                                w.u16(0);
                                w.u32(full as u32);
                            }
                        }
                    }
                    let hb = high_bit(dist);
                    w.bits(hb as u32, (dist - (1 << hb)) as u32);
                }
            }
        }
        if last_block {
            w.bits(lengths[EOF_SYMBOL] as u32, codes[EOF_SYMBOL] as u32);
        }
        out.extend_from_slice(&w.flush());
        block_start = pos;
        if input.is_empty() {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, data);
        let dec2 = decode_with_size(&enc, data.len()).unwrap();
        assert_eq!(dec2, data);
    }

    #[test]
    fn roundtrip_various() {
        rt(b"");
        rt(b"a");
        rt(b"ab");
        rt(b"abcdefghijklmnopqrstuvwxyz");
        rt(&[0u8; 70000]); // crosses a block boundary
        rt(b"abcabcabcabcabcabcabcabcabcabcabc");
        let mut big = Vec::new();
        for i in 0..50000u32 {
            big.extend_from_slice(&i.to_le_bytes());
        }
        rt(&big);
        let mut rep = Vec::new();
        for _ in 0..3000 {
            rep.extend_from_slice(b"the quick brown fox. ");
        }
        rt(&rep);
    }

    #[test]
    fn multi_block() {
        // >64 KiB forces a second Huffman block.
        let mut data = Vec::new();
        for i in 0..200000u32 {
            data.push((i.wrapping_mul(2654435761) >> 24) as u8);
        }
        // add repetition so matches appear in both blocks
        let tail = data[..50000].to_vec();
        data.extend_from_slice(&tail);
        rt(&data);
        assert!(data.len() > BLOCK_SIZE);
    }

    #[test]
    fn code_lengths_kraft() {
        // Constructed frequencies must produce a complete canonical code:
        // the decode table builder fills exactly 2^15 slots or errors.
        let mut freq = [0u32; NUM_SYMBOLS];
        for (i, f) in freq.iter_mut().enumerate() {
            *f = (i as u32 % 7) + 1;
        }
        let lengths = code_lengths(&freq);
        let mut slot = 0usize;
        for l in 1..=15u8 {
            for &ll in lengths.iter() {
                if ll == l {
                    slot += 1 << (15 - l);
                }
            }
        }
        assert_eq!(slot, 1 << 15);
    }

    #[test]
    fn rejects_truncated() {
        let enc = encode(b"hello hello hello hello hello");
        // Truncating inside the code-length table must fail.
        assert!(decode(&enc[..10]).is_err());
        // Cutting mid-stream means the EOF symbol is never reached.
        assert!(decode(&enc[..enc.len() / 2]).is_err());
    }

    #[test]
    fn rejects_bad_table() {
        // All-zero code lengths -> incomplete canonical code.
        let mut input = vec![0u8; 256];
        input.extend_from_slice(&[0xff; 16]);
        assert!(decode(&input).is_err());
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'q'; 10000];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
    }
}
