//! ZX2 compression (Einar Saukas, BSD 3-Clause).
//!
//! ZX2 raw stream: an interleaved sequence of control-bit bytes and data
//! bytes. Bits are read MSB-first from control bytes; literal bytes and
//! offset bytes occupy whole input bytes in consumption order. ZX2 is the
//! minimalist variant of ZX1: the new-offset field is a single byte and the
//! state machine matches ZX1.
//!
//! Block types:
//! - literal: `0` + `elias(len)` + `len` raw bytes
//! - copy from last offset: `0` + `elias(len)`
//! - copy from new offset: `1` + offset byte + `elias(len-1)`
//!
//! The stream always opens with a literal block whose leading `0` bit is
//! omitted. After a literal block bit `0` selects copy-from-last-offset;
//! after any copy block `0` selects literal and `1` a new offset.
//!
//! Like ZX1, the interlaced Elias gamma coding uses `1` as the continuation
//! bit and `0` as the terminator, with non-inverted data bits. The new-offset
//! byte stores `255 - offset`, so byte `0xff` (offset 0) is the
//! end-of-stream marker.
//!
//! Variant flags:
//! - `-z` (ignore default offset): [`decode_no_default_offset`] starts
//!   with `last_offset = 0` instead of 1; [`encode_no_default_offset`]
//!   produces matching streams. The first match is always emitted as a
//!   new-offset block, so the output also decodes with [`decode`].
//! - `-x` (skip length increment): [`decode_no_length_increment`] reads
//!   new-offset block lengths as `elias(len)` without the -1 bias;
//!   [`encode_no_length_increment`] produces matching streams.
//! - `-y` (limit block length) only constrains the encoder:
//!   [`encode_max_len`] splits match blocks at a caller-chosen bound;
//!   such streams decode with [`decode`].
//! - `+N` prefix compression: [`decode_with_prefix`] lets match offsets
//!   reach into caller-supplied external history; [`encode_with_prefix`]
//!   produces matching streams.
//! [`decode_variant`] covers arbitrary combinations of the above.
//!
//! Backwards (`-b`) mode: the stream is the byte-reversed form of a
//! forward stream whose new-offset byte stores `offset - 1` instead of
//! `255 - offset`; byte `0xff` remains the end marker in both modes.
//! [`decode_backwards`] reverses the input, decodes, and reverses the
//! output; [`decode_backwards_with_suffix`] accepts the upstream `-b +N`
//! trailing history in normal (unreversed) order. The `-z`, `-x` and
//! `-y` flags combine orthogonally through [`decode_backwards_variant`]
//! and [`encode_backwards_variant`]; [`encode_backwards`] and
//! [`encode_backwards_with_suffix`] produce matching streams.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Largest encodable offset (ZX2 limit; byte `0xff` is reserved for EOF).
const MAX_OFFSET: usize = 255;
const MIN_MATCH: usize = 3;

struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    value: u8,
    mask: u8,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        BitReader {
            input,
            pos: 0,
            value: 0,
            mask: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(Error::InvalidData("zx2: unexpected end of input"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bit(&mut self) -> Result<u32, Error> {
        if self.mask == 0 {
            self.value = self.read_byte()?;
            self.mask = 0x80;
        }
        let bit = self.value & self.mask;
        self.mask >>= 1;
        Ok((bit != 0) as u32)
    }

    fn elias(&mut self) -> Result<u32, Error> {
        let mut value = 1u32;
        while self.read_bit()? == 1 {
            if value >= (1 << 20) {
                return Err(Error::InvalidData("zx2: elias value too large"));
            }
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }
}

/// Decode a ZX2 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a ZX2 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output, 1, false, false)
}

/// Decode a ZX2 stream produced with `-z` (ignore default offset): the
/// initial last-offset is 0, so a copy-from-last-offset is invalid until
/// a new-offset block sets one.
pub fn decode_no_default_offset(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], usize::MAX, 0, false, false)
}

/// Decode a ZX2 stream produced with `-x` (skip length increment):
/// new-offset block lengths are stored as `elias(len)` without the
/// usual -1 bias.
pub fn decode_no_length_increment(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], usize::MAX, 1, true, false)
}

/// Decode a ZX2 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, 1, false, false)
}

/// Decode a ZX2 stream with arbitrary combinations of the upstream
/// variant flags applied.
///
/// * `prefix` — external history logically prepended to the output
///   (the `+N` option); may be empty.
/// * `initial_offset` — initial last-offset value: 0 for `-z` streams,
///   1 (the default) otherwise.
/// * `skip_len_increment` — `true` for `-x` streams where new-offset
///   block lengths are stored without the -1 bias.
pub fn decode_variant(
    input: &[u8],
    prefix: &[u8],
    initial_offset: usize,
    skip_len_increment: bool,
) -> Result<Vec<u8>, Error> {
    decode_impl(
        input,
        prefix,
        usize::MAX,
        initial_offset,
        skip_len_increment,
        false,
    )
}

/// Decode a ZX2 stream produced with `-b` (backwards mode): the stream
/// is the byte-reversed form of a forward stream whose new-offset byte
/// stores `offset - 1` instead of `255 - offset`.
pub fn decode_backwards(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_backwards_bounded(input, usize::MAX)
}

/// Decode a backwards (`-b`) ZX2 stream with an output size limit.
pub fn decode_backwards_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_backwards_variant(input, &[], 1, false, max_output)
}

/// Decode a backwards (`-b`) ZX2 stream whose match offsets may reach
/// into `suffix`, external history logically appended to the output in
/// the original data direction (the upstream `-b +N` option). `suffix`
/// is given in normal (unreversed) order.
pub fn decode_backwards_with_suffix(input: &[u8], suffix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_backwards_variant(input, suffix, 1, false, usize::MAX)
}

/// Decode a backwards (`-b`) ZX2 stream with arbitrary combinations of
/// the upstream variant flags applied.
///
/// * `suffix` — external history logically appended to the output in
///   the original data direction (the `-b +N` option); given in normal
///   (unreversed) order, may be empty.
/// * `initial_offset` — initial last-offset value: 0 for `-z` streams,
///   1 (the default) otherwise.
/// * `skip_len_increment` — `true` for `-x` streams where new-offset
///   block lengths are stored without the -1 bias.
/// * `max_output` — bound on the decoded size; exceeding it returns
///   [`Error::OutputLimitExceeded`].
pub fn decode_backwards_variant(
    input: &[u8],
    suffix: &[u8],
    initial_offset: usize,
    skip_len_increment: bool,
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    // A backwards stream is a forward stream stored in reverse byte
    // order: reversing the input exposes the regular block grammar, and
    // the decoded output is likewise produced in reverse order. The
    // same applies to the external history, which precedes the reversed
    // input data in the reversed domain.
    let mut stream = input.to_vec();
    stream.reverse();
    let mut history = suffix.to_vec();
    history.reverse();
    let mut out = decode_impl(
        &stream,
        &history,
        max_output,
        initial_offset,
        skip_len_increment,
        true,
    )?;
    out.reverse();
    Ok(out)
}

/// Append `len` bytes copied `offset` back in the virtual history
/// `prefix ++ out`.
fn copy_match(
    prefix: &[u8],
    out: &mut Vec<u8>,
    offset: usize,
    len: usize,
    max_output: usize,
    msg: &'static str,
) -> Result<(), Error> {
    let avail = prefix.len() + out.len();
    if offset == 0 || offset > avail {
        return Err(Error::InvalidData(msg));
    }
    if out.len() + len > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    for vpos in (avail - offset)..(avail - offset + len) {
        let b = if vpos < prefix.len() {
            prefix[vpos]
        } else {
            out[vpos - prefix.len()]
        };
        out.push(b);
    }
    Ok(())
}

fn decode_impl(
    input: &[u8],
    prefix: &[u8],
    max_output: usize,
    initial_offset: usize,
    skip_len_increment: bool,
    backwards: bool,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut last_offset = initial_offset;

    // The first block is always a literal block without an indicator bit.
    let mut literals = true;
    loop {
        if literals {
            let len = r.elias()? as usize;
            if r.pos + len > input.len() {
                return Err(Error::InvalidData("zx2: truncated literals"));
            }
            if out.len() + len > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            for _ in 0..len {
                let b = r.read_byte()?;
                out.push(b);
            }
            // After literals: 0 = copy from last offset, 1 = new offset.
            if r.read_bit()? == 0 {
                let len = r.elias()? as usize;
                copy_match(
                    prefix,
                    &mut out,
                    last_offset,
                    len,
                    max_output,
                    "zx2: offset before start",
                )?;
                literals = r.read_bit()? == 0;
                continue;
            }
        }

        // COPY_FROM_NEW_OFFSET: forward streams store `255 - offset`,
        // the backwards (`-b`) variant stores `offset - 1`; byte 0xff is
        // the EOF marker in both modes.
        let byte = r.read_byte()?;
        if byte == 0xff {
            // EOF marker: the reference decoder requires the input to be
            // fully consumed at this point.
            if r.pos != input.len() {
                return Err(Error::InvalidData("zx2: trailing data after end"));
            }
            return Ok(out);
        }
        let offset = if backwards {
            byte as usize + 1
        } else {
            255 - byte as usize
        };
        last_offset = offset;
        // `-x` stores the length verbatim; the default stores len - 1.
        let len = r.elias()? as usize + if skip_len_increment { 0 } else { 1 };
        copy_match(
            prefix,
            &mut out,
            last_offset,
            len,
            max_output,
            "zx2: bad match offset",
        )?;
        literals = r.read_bit()? == 0;
    }
}

struct BitWriter {
    out: Vec<u8>,
    bit_index: usize,
    mask: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            out: Vec::new(),
            bit_index: 0,
            mask: 0,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if self.mask == 0 {
            self.mask = 0x80;
            self.bit_index = self.out.len();
            self.out.push(0);
        }
        if bit {
            self.out[self.bit_index] |= self.mask;
        }
        self.mask >>= 1;
    }

    fn write_byte(&mut self, b: u8) {
        self.out.push(b);
    }

    fn write_elias(&mut self, value: usize) {
        let mut i = 2usize;
        while i <= value {
            i <<= 1;
        }
        i >>= 1;
        while i > 1 {
            i >>= 1;
            self.write_bit(true);
            self.write_bit((value & i) != 0);
        }
        self.write_bit(false);
    }
}

/// Encode data as a ZX2 stream (forward mode).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX2 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    // An unbounded max_len can never be exceeded, so this cannot fail.
    encode_variant(input, 1, false, usize::MAX).expect("zx2: unbounded encode cannot fail")
}

/// Encode data as a ZX2 stream decodable by [`decode_no_default_offset`]
/// (the upstream `-z` option): the initial last-offset is 0, so the
/// first match is always emitted as a new-offset block. Because the
/// produced stream contains no copy-from-last-offset before the first
/// new-offset block, it also decodes correctly with [`decode`].
pub fn encode_no_default_offset(input: &[u8]) -> Vec<u8> {
    encode_variant(input, 0, false, usize::MAX).expect("zx2: unbounded encode cannot fail")
}

/// Encode data as a ZX2 stream decodable by
/// [`decode_no_length_increment`] (the upstream `-x` option): new-offset
/// block lengths are stored as `elias(len)` without the usual -1 bias.
pub fn encode_no_length_increment(input: &[u8]) -> Vec<u8> {
    encode_variant(input, 1, true, usize::MAX).expect("zx2: unbounded encode cannot fail")
}

/// Encode data as a ZX2 stream with every emitted block limited to at
/// most `max_len` decoded bytes (the upstream `-y` "limit block length"
/// option, parameterized). The wire format is unchanged, so the output
/// decodes with [`decode`]. Passing `max_len = 255` additionally keeps
/// every stored Elias value within a byte, matching upstream `-y`.
///
/// Match blocks are split as needed. Since ZX2 does not allow
/// consecutive literal blocks, a byte run without a usable match cannot
/// be split: [`Error::InvalidData`] is returned when such a run exceeds
/// `max_len`, or when `max_len` is 0 for non-empty input.
pub fn encode_max_len(input: &[u8], max_len: usize) -> Result<Vec<u8>, Error> {
    encode_variant(input, 1, false, max_len)
}

/// Encode data as a ZX2 stream decodable by [`decode_with_prefix`] (the
/// upstream `+N` prefix option): the matcher treats `prefix` as history
/// logically prepended to `input`, so emitted matches may copy from it
/// using normal wire offsets. Only the last 255 bytes of `prefix` are
/// reachable (ZX2's maximum offset); older prefix bytes are ignored.
///
/// The first block must be a literal, so a match starting at `input[0]`
/// is never emitted even when the prefix offers one.
pub fn encode_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix, 1, false, usize::MAX, false)
        .expect("zx2: unbounded encode cannot fail")
}

/// Encode data as a backwards (`-b`) ZX2 stream decodable by
/// [`decode_backwards`]: the reversed input is compressed as a forward
/// stream whose new-offset byte stores `offset - 1`, and the resulting
/// stream itself is reversed.
///
/// The encoder uses greedy single-candidate matching; the emitted stream
/// is valid ZX2 but does not aim to match the reference compressor's
/// optimal parsing output.
pub fn encode_backwards(input: &[u8]) -> Vec<u8> {
    encode_backwards_variant(input, &[], 1, false, usize::MAX)
        .expect("zx2: unbounded encode cannot fail")
}

/// Encode data as a backwards (`-b`) ZX2 stream decodable by
/// [`decode_backwards_with_suffix`] (the upstream `-b +N` option):
/// `suffix` is external history logically appended to `input` in the
/// original data direction and is given in normal (unreversed) order.
/// Only the first 255 bytes of `suffix` are reachable (ZX2's maximum
/// offset); later suffix bytes are ignored.
///
/// The first block must be a literal, so a match starting at `input[0]`
/// is never emitted even when the suffix offers one.
pub fn encode_backwards_with_suffix(input: &[u8], suffix: &[u8]) -> Vec<u8> {
    encode_backwards_variant(input, suffix, 1, false, usize::MAX)
        .expect("zx2: unbounded encode cannot fail")
}

/// Encode a backwards (`-b`) ZX2 stream with selectable variant flags,
/// mirroring [`decode_backwards_variant`].
///
/// * `suffix` — external history logically appended to `input` in the
///   original data direction (the `-b +N` option); given in normal
///   (unreversed) order, may be empty.
/// * `initial_offset` — initial last-offset value: 0 for `-z`
///   compatibility, 1 (the default) otherwise.
/// * `skip_len_increment` — `true` for `-x` compatibility: new-offset
///   block lengths are stored as `elias(len)` without the -1 bias.
/// * `max_len` — bound on the decoded length of every emitted block
///   (the `-y` constraint); `usize::MAX` disables it. An unmatchable
///   literal run longer than `max_len` is an error since literal blocks
///   cannot be consecutive.
pub fn encode_backwards_variant(
    input: &[u8],
    suffix: &[u8],
    initial_offset: usize,
    skip_len_increment: bool,
    max_len: usize,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        // Same convention as encode_impl: the ZX2 format cannot
        // represent an empty output; emit an empty stream.
        return Ok(Vec::new());
    }
    // Compress the reversed input with the reversed suffix as prepend
    // history, then reverse the emitted stream itself.
    let mut rev_input = input.to_vec();
    rev_input.reverse();
    let mut rev_suffix = suffix.to_vec();
    rev_suffix.reverse();
    let mut out = encode_impl(
        &rev_input,
        &rev_suffix,
        initial_offset,
        skip_len_increment,
        max_len,
        true,
    )?;
    out.reverse();
    Ok(out)
}

/// Encode a ZX2 stream with selectable variant flags, mirroring
/// [`decode_variant`].
///
/// * `initial_offset` — initial last-offset value: 0 for `-z`
///   compatibility, 1 (the default) otherwise.
/// * `skip_len_increment` — `true` for `-x` compatibility: new-offset
///   block lengths are stored as `elias(len)` without the -1 bias.
/// * `max_len` — bound on the decoded length of every emitted block
///   (the `-y` constraint); `usize::MAX` disables it. An unmatchable
///   literal run longer than `max_len` is an error since literal blocks
///   cannot be consecutive.
fn encode_variant(
    input: &[u8],
    initial_offset: usize,
    skip_len_increment: bool,
    max_len: usize,
) -> Result<Vec<u8>, Error> {
    encode_impl(
        input,
        &[],
        initial_offset,
        skip_len_increment,
        max_len,
        false,
    )
}

/// Shared encoder core. `prefix` is external history logically prepended
/// to the output as in [`decode_with_prefix`]; it may be empty. When
/// `backwards` is set the new-offset byte is stored as `offset - 1`
/// (the `-b` variant) instead of `255 - offset`.
fn encode_impl(
    input: &[u8],
    prefix: &[u8],
    initial_offset: usize,
    skip_len_increment: bool,
    max_len: usize,
    backwards: bool,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        // The ZX2 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Ok(Vec::new());
    }
    if max_len == 0 {
        return Err(Error::InvalidData("zx2: max_len must be at least 1"));
    }

    // Offsets are limited to MAX_OFFSET, so only the tail of the prefix
    // is reachable history.
    let prefix = &prefix[prefix.len().saturating_sub(MAX_OFFSET)..];
    let plen = prefix.len();
    // Byte at virtual position `i` of the `prefix ++ input` history.
    let hist = |i: usize| {
        if i < plen { prefix[i] } else { input[i - plen] }
    };

    let mut w = BitWriter::new();
    let mut head = vec![-1i32; 1 << 15];
    // Seed the matcher with the reachable prefix positions.
    for c in 0..plen {
        if c + MIN_MATCH > plen + input.len() {
            break;
        }
        let h = (((hist(c) as usize) << 8) ^ ((hist(c + 1) as usize) << 4) ^ hist(c + 2) as usize)
            & ((1 << 15) - 1);
        head[h] = c as i32;
    }
    let mut last_offset = initial_offset;
    let mut lit_start = 0usize;
    let mut pos = 0usize;
    let mut first_block = true;
    let mut after_literals = false;

    while pos < input.len() {
        // Search for a match at pos. Candidates are virtual positions
        // in `prefix ++ input`, so `dist` may reach into the prefix.
        let mut best: Option<(usize, usize)> = None;
        if pos + MIN_MATCH <= input.len() {
            let h = (((input[pos] as usize) << 8)
                ^ ((input[pos + 1] as usize) << 4)
                ^ input[pos + 2] as usize)
                & ((1 << 15) - 1);
            let cand = head[h];
            head[h] = (plen + pos) as i32;
            if cand >= 0 {
                let c = cand as usize;
                let dist = plen + pos - c;
                if dist <= MAX_OFFSET
                    && hist(c) == input[pos]
                    && hist(c + 1) == input[pos + 1]
                    && hist(c + 2) == input[pos + 2]
                {
                    let mut len = MIN_MATCH;
                    while pos + len < input.len() && hist(c + len) == input[pos + len] {
                        len += 1;
                    }
                    best = Some((len, dist));
                }
            }
        }

        if let Some((mut len, dist)) = best {
            let lit_len = pos - lit_start;

            // The opening block is always a literal (the format omits
            // its indicator bit), so a match at the very start - only
            // possible through prefix history - stays a literal.
            if first_block && lit_len == 0 {
                pos += 1;
                continue;
            }

            // `-y`: cap the emitted block length. A new-offset block
            // stores `len - 1` (or `len` with `-x`), so its minimum
            // encodable length is 2 (or 1); a copy-from-last-offset
            // stores `len` and may only follow a literal block.
            len = len.min(max_len);
            let rep_ok = (after_literals || lit_len > 0) && dist == last_offset;
            let min_new = if skip_len_increment { 1 } else { 2 };
            if len < min_new && !rep_ok {
                // Too short to emit as a match; leave it to literals.
                pos += 1;
                continue;
            }

            // Flush pending literals first.
            if lit_len > max_len {
                // Consecutive literal blocks are not representable.
                return Err(Error::InvalidData("zx2: literal run exceeds max_len"));
            }
            if lit_len > 0 || first_block {
                debug_assert!(lit_len > 0); // first match implies >=1 literal
                if !first_block {
                    w.write_bit(false); // literal indicator after a match
                }
                w.write_elias(lit_len);
                for &b in &input[lit_start..pos] {
                    w.write_byte(b);
                }
                first_block = false;
                after_literals = true;
            }

            if after_literals && dist == last_offset {
                // Copy from last offset.
                w.write_bit(false);
                w.write_elias(len);
            } else {
                // Copy from new offset.
                w.write_bit(true);
                // The backwards (`-b`) variant stores `offset - 1`
                // instead of `255 - offset`.
                w.write_byte(if backwards {
                    (dist - 1) as u8
                } else {
                    (255 - dist) as u8
                });
                // `-x` stores the length verbatim; the default stores
                // len - 1 (upstream min_length 1 vs 2).
                w.write_elias(if skip_len_increment { len } else { len - 1 });
                last_offset = dist;
            }
            after_literals = false;
            pos += len;
            lit_start = pos;
        } else {
            pos += 1;
        }
    }

    // Trailing literal block, if any.
    let lit_len = input.len() - lit_start;
    if lit_len > max_len {
        return Err(Error::InvalidData("zx2: literal run exceeds max_len"));
    }
    if lit_len > 0 {
        if !first_block {
            w.write_bit(false);
        }
        w.write_elias(lit_len);
        for &b in &input[lit_start..] {
            w.write_byte(b);
        }
    }

    // End marker: new-offset indicator + 0xff.
    w.write_bit(true);
    w.write_byte(0xff);
    Ok(w.out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    #[test]
    fn decode_no_default_offset_variant() {
        // literal 'a', copy-from-last-offset len 3, EOF.
        //   bits: elias(1)=`0` | 'a' | `0` lastoff | elias(3)=`1,1,0` |
        //         `1` newoff | 0xff
        let stream = [0x34, b'a', 0xff];
        assert_eq!(decode(&stream).unwrap(), b"aaaa");
        // With `-z` the initial last-offset is 0: the copy is invalid.
        assert!(decode_no_default_offset(&stream).is_err());
        // A new-offset block is still fine under `-z`.
        //   bits: elias(1)=`0` | 'a' | `1` newoff | 0xfe (dist 1) |
        //         len elias(2)=`1,0,0` | `1` newoff | 0xff
        let stream = [0x64, b'a', 0xfe, 0xff];
        assert_eq!(decode_no_default_offset(&stream).unwrap(), b"aaaa");
        assert_eq!(decode(&stream).unwrap(), b"aaaa");
    }

    #[test]
    fn decode_no_length_increment_variant() {
        // `-x` stores the new-offset length without the -1 bias, so the
        // same bytes mean a shorter match.
        let stream = [0x64, b'a', 0xfe, 0xff];
        assert_eq!(decode(&stream).unwrap(), b"aaaa"); // elias 2 -> len 3
        assert_eq!(decode_no_length_increment(&stream).unwrap(), b"aaa"); // len 2
        // Combined `-x -z` via decode_variant.
        assert_eq!(decode_variant(&stream, &[], 0, true).unwrap(), b"aaa");
        // elias 1 stores len 1 under `-x` (len 2 by default).
        let stream = [0x50, b'a', 0xfe, 0xff];
        assert_eq!(decode(&stream).unwrap(), b"aaa");
        assert_eq!(decode_no_length_increment(&stream).unwrap(), b"aa");
    }

    #[test]
    fn decode_prefix_history() {
        // literal 'a', then a distance-4 len-3 match reaching into the
        // 3-byte prefix "XYZ", then EOF.
        //   bits: elias(1)=`0` | 'a' | `1` newoff | 0xfb (dist 4) |
        //         len elias(2)=`1,0,0` | `1` newoff | 0xff
        let stream = [0x64, b'a', 0xfb, 0xff];
        assert!(decode(&stream).is_err());
        assert_eq!(decode_with_prefix(&stream, b"XYZ").unwrap(), b"aXYZ");
        // Same via the general variant form.
        assert_eq!(decode_variant(&stream, b"XYZ", 1, false).unwrap(), b"aXYZ");
    }

    #[test]
    fn decode_minimal_literal() {
        let enc = encode(b"A");
        assert_eq!(decode(&enc).unwrap(), b"A");
    }

    #[test]
    fn decode_copy_last_offset() {
        rt(b"aaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn decode_new_offset() {
        rt(b"abcabcabcabcabcabc");
    }

    #[test]
    fn decode_far_offset() {
        // Distances near the 255-byte offset limit.
        let mut data = Vec::new();
        data.extend(0u8..=250);
        data.extend_from_slice(b"PATTERN!");
        data.extend(0u8..=250);
        data.extend_from_slice(b"PATTERN!");
        rt(&data);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x80]).is_err()); // literal len but no byte
        assert!(decode(&[0xc0]).is_err()); // incomplete
    }

    #[test]
    fn rejects_bad_offset() {
        let enc = encode(b"abababababab");
        let mut any_err = false;
        for i in 0..enc.len() {
            let mut c = enc.clone();
            c[i] = 0x00;
            if decode(&c).is_err() {
                any_err = true;
            }
        }
        assert!(any_err);
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'z'; 500];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&enc, 500).unwrap(), data);
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b""), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    /// Largest decoded block length in a default-flags ZX2 `stream`
    /// (literal runs and matches counted in decoded bytes).
    fn max_block_len(stream: &[u8]) -> usize {
        let mut r = BitReader::new(stream);
        let mut max = 0usize;
        let mut literals = true;
        loop {
            if literals {
                let len = r.elias().unwrap() as usize;
                max = max.max(len);
                for _ in 0..len {
                    r.read_byte().unwrap();
                }
                if r.read_bit().unwrap() == 0 {
                    let len = r.elias().unwrap() as usize;
                    max = max.max(len);
                    literals = r.read_bit().unwrap() == 0;
                    continue;
                }
            }
            let offset = 255 - r.read_byte().unwrap() as usize;
            if offset == 0 {
                return max;
            }
            let len = r.elias().unwrap() as usize + 1;
            max = max.max(len);
            literals = r.read_bit().unwrap() == 0;
        }
    }

    #[test]
    fn encode_no_default_offset_roundtrip() {
        let cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"abcabcabcabcabcabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaa".to_vec(),
            b"hello world hello world hello world".to_vec(),
            vec![0u8; 2000],
        ];
        for data in &cases {
            let enc = encode_no_default_offset(data);
            assert_eq!(decode_no_default_offset(&enc).unwrap(), *data);
            assert_eq!(decode_variant(&enc, &[], 0, false).unwrap(), *data);
            // No copy-from-last-offset is emitted before the first
            // new-offset block, so the default decoder accepts it too.
            assert_eq!(decode(&enc).unwrap(), *data);
        }
        // The `-z` stream really differs: "aaaa" uses a rep-offset under
        // the default initial offset 1, a new-offset block under `-z`.
        let rep = encode(b"aaaa");
        let zed = encode_no_default_offset(b"aaaa");
        assert_ne!(rep, zed);
        // And the default stream's early rep-offset is invalid under `-z`.
        assert!(decode_no_default_offset(&rep).is_err());
    }

    #[test]
    fn encode_no_length_increment_roundtrip() {
        let cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"abcabcabcabcabcabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaa".to_vec(),
            b"hello world hello world hello world".to_vec(),
            vec![7u8; 1500],
        ];
        for data in &cases {
            let enc = encode_no_length_increment(data);
            assert_eq!(decode_no_length_increment(&enc).unwrap(), *data);
            assert_eq!(decode_variant(&enc, &[], 1, true).unwrap(), *data);
        }
        // New-offset lengths are stored one higher than the default
        // decoder expects, so a stream containing a new-offset block must
        // not decode correctly under the default flags (it either errors
        // or produces different bytes).
        let enc = encode_no_length_increment(b"abcabcabcabcabcabc");
        assert!(decode(&enc).map_or(true, |v| v != b"abcabcabcabcabcabc"));
        // Rep-offset lengths carry no bias, so a stream without any
        // new-offset block is identical in both variants.
        let enc = encode_no_length_increment(b"aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(decode(&enc).unwrap(), b"aaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn encode_max_len_roundtrip() {
        // Inputs whose longest literal run fits small bounds.
        let cases: Vec<Vec<u8>> = vec![
            b"abcabcabcabcabcabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaa".to_vec(),
            vec![0u8; 2000],
        ];
        for max_len in [4usize, 8, 255] {
            for data in &cases {
                let enc = encode_max_len(data, max_len).unwrap();
                assert_eq!(decode(&enc).unwrap(), *data);
                assert!(max_block_len(&enc) <= max_len);
            }
        }
        // The opening unmatched run of this text is ~32 bytes, so it
        // needs a proportionally larger bound.
        let mut text = Vec::new();
        for _ in 0..80 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        let enc = encode_max_len(&text, 64).unwrap();
        assert_eq!(decode(&enc).unwrap(), text);
        assert!(max_block_len(&enc) <= 64);
    }

    #[test]
    fn encode_max_len_errors() {
        // max_len 0 cannot encode any block of non-empty input.
        assert!(encode_max_len(b"abc", 0).is_err());
        assert_eq!(encode_max_len(b"", 0).unwrap(), Vec::<u8>::new());
        // A byte run with no usable match within 255 bytes stays one
        // literal block; it cannot be split below max_len.
        let literal_run: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        assert!(encode_max_len(&literal_run, 64).is_err());
        let enc = encode_max_len(&literal_run, 300).unwrap();
        assert_eq!(decode(&enc).unwrap(), literal_run);
        // A bound of 1 still works for a single literal byte, but a
        // match can never cover the last two input bytes (the matcher
        // needs 3 lookahead bytes), so any longer input fails.
        assert_eq!(decode(&encode_max_len(b"a", 1).unwrap()).unwrap(), b"a");
        assert!(encode_max_len(b"ab", 1).is_err());
        assert!(encode_max_len(&[b'a'; 100], 1).is_err());
        // Bound 2 covers self-repeating data via len-2 copy blocks.
        let enc = encode_max_len(&[b'a'; 100], 2).unwrap();
        assert_eq!(decode(&enc).unwrap(), vec![b'a'; 100]);
        assert!(max_block_len(&enc) <= 2);
    }

    #[test]
    fn encode_with_prefix_roundtrip() {
        // literal 'Z', then a distance-4 len-3 match reaching into the
        // 3-byte prefix "abc", then EOF.
        let enc = encode_with_prefix(b"Zabc", b"abc");
        assert_eq!(enc, [0x64, b'Z', 0xfb, 0xff]);
        assert_eq!(decode_with_prefix(&enc, b"abc").unwrap(), b"Zabc");
        assert_eq!(decode_variant(&enc, b"abc", 1, false).unwrap(), b"Zabc");

        // A mix of prefix-referencing and in-input matches.
        let enc = encode_with_prefix(b"xabcabc", b"abc");
        assert_eq!(decode_with_prefix(&enc, b"abc").unwrap(), b"xabcabc");

        // Only the last 255 prefix bytes are reachable; longer prefixes
        // still roundtrip through the matching decoder.
        let prefix: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let mut data = Vec::new();
        data.extend_from_slice(&prefix[200..]);
        data.extend_from_slice(b" -- ");
        data.extend_from_slice(&prefix[200..]);
        let enc = encode_with_prefix(&data, &prefix);
        assert_eq!(decode_with_prefix(&enc, &prefix).unwrap(), data);

        let mut text = Vec::new();
        for _ in 0..40 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        let enc = encode_with_prefix(&text, b"the quick brown fox ");
        assert_eq!(
            decode_with_prefix(&enc, b"the quick brown fox ").unwrap(),
            text
        );
    }

    #[test]
    fn encode_with_prefix_empty_prefix() {
        // An empty prefix leaves the input history unchanged, so the
        // output is identical to plain encode() and decodes plainly.
        for data in [
            &b"abcabcabcabc"[..],
            &b"hello world hello world hello world"[..],
        ] {
            let enc = encode_with_prefix(data, b"");
            assert_eq!(enc, encode(data));
            assert_eq!(decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn encode_with_prefix_requires_prefix() {
        // The emitted match copies from prefix history; decoding the
        // same stream without the prefix must not reproduce the input
        // (the offset exceeds the produced output, so it errors).
        let enc = encode_with_prefix(b"Zabc", b"abc");
        assert!(decode(&enc).map_or(true, |v| v != b"Zabc"));
        // A wrong prefix decodes but yields different bytes.
        assert_eq!(decode_with_prefix(&enc, b"XYZ").unwrap(), b"ZXYZ");
    }

    #[test]
    fn encode_variants_edge_cases() {
        // Empty input: the format has no empty-output representation.
        assert_eq!(encode_no_default_offset(b""), Vec::<u8>::new());
        assert_eq!(encode_no_length_increment(b""), Vec::<u8>::new());
        assert_eq!(decode_no_default_offset(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(decode_no_length_increment(&[]).unwrap(), Vec::<u8>::new());
        // All-literal input (no repeats at all).
        let lit = b"abcdefghijklmnop";
        assert_eq!(
            decode_no_default_offset(&encode_no_default_offset(lit)).unwrap(),
            lit
        );
        assert_eq!(
            decode_no_length_increment(&encode_no_length_increment(lit)).unwrap(),
            lit
        );
        // Long runs through every variant.
        let run = vec![b'x'; 3000];
        assert_eq!(
            decode_no_default_offset(&encode_no_default_offset(&run)).unwrap(),
            run
        );
        assert_eq!(
            decode_no_length_increment(&encode_no_length_increment(&run)).unwrap(),
            run
        );
        let enc = encode_max_len(&run, 16).unwrap();
        assert_eq!(decode(&enc).unwrap(), run);
        assert!(max_block_len(&enc) <= 16);
    }

    #[test]
    fn roundtrip_various() {
        rt(b"a");
        rt(b"ab");
        rt(b"abcabcabc");
        rt(b"hello world hello world hello world");
        rt(&[0u8; 2000]);
        let mut text = Vec::new();
        for _ in 0..150 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&text);
        let mut binary = Vec::new();
        for i in 0..4000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        rt(&binary);
        let mut mixed = Vec::new();
        for _ in 0..50 {
            mixed.extend_from_slice(b"aaaaa");
            mixed.extend_from_slice(b"abcdef");
        }
        rt(&mixed);
        let mut rep = b"abcd".to_vec();
        rep.extend_from_slice(b"abcdabcdabcd");
        rt(&rep);
        // Offset-limit exercise: reuse a pattern near 255 bytes back.
        let mut far = vec![0u8; 200];
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        far.extend_from_slice(&[1u8; 40]);
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        rt(&far);
    }

    // -- Backwards (`-b`) variant ------------------------------------

    // Streams produced by upstream `zx2` v1.1.
    const ZX2B_FOX: &[u8] = &[
        0xff, 0xb9, 0x2c, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0xe6, 0x6f, 0x76, 0x65, 0x72, 0xa0,
        0x0d, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78,
        0x2e, 0x0a, 0x68, 0xff,
    ];
    const ZX2B_A300: &[u8] = &[0xff, 0xe4, 0xee, 0x61, 0x00, 0x8a];
    const ZX2B_T4K: &[u8] = &[
        0xff, 0x40, 0xff, 0xfe, 0x13, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20,
        0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x7f, 0xba,
    ];
    // `zx2 -b -x`.
    const ZX2B_FOX_X: &[u8] = &[
        0xff, 0xd0, 0x2c, 0x6b, 0x6a, 0x6d, 0x70, 0x73, 0xc0, 0x1c, 0x6f, 0x76, 0x65, 0x72, 0xa4,
        0x0d, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x74, 0x68, 0x65, 0x20,
        0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78,
        0x2e, 0x0a, 0x6c, 0xff,
    ];
    // `zx2 -b -z`.
    const ZX2B_A300_Z: &[u8] = &[0xff, 0xb4, 0xee, 0x00, 0x61, 0x00, 0x9a];
    // `zx2 -b +20` on the 4100-byte T4K input: covers the first 4080
    // bytes with the last 20 ("the quick brown fox ") as suffix history.
    const ZX2B_T4K_P20: &[u8] = &[0xff, 0x40, 0xfe, 0xfe, 0x13, 0x20, 0x7f];

    const FOX_TEXT: &[u8] = b"the quick brown fox jumps over the lazy dog. the quick brown fox.\n";

    fn rtb(data: &[u8]) {
        let enc = encode_backwards(data);
        // A backwards stream is the reversed forward stream, so it
        // always opens with the EOF marker byte.
        assert_eq!(enc[0], 0xff);
        assert_eq!(decode_backwards(&enc).unwrap(), data);
    }

    #[test]
    fn decode_backwards_kat() {
        assert_eq!(decode_backwards(ZX2B_FOX).unwrap(), FOX_TEXT);
        let mut a300 = vec![b'a'; 299];
        a300.push(0);
        assert_eq!(decode_backwards(ZX2B_A300).unwrap(), a300);
        let pat = b"the quick brown fox ";
        let mut t4k = Vec::new();
        for _ in 0..205 {
            t4k.extend_from_slice(pat);
        }
        assert_eq!(decode_backwards(ZX2B_T4K).unwrap(), t4k);
    }

    #[test]
    fn decode_backwards_variant_kat() {
        // `-b -x` and `-b -z` streams through the general variant form.
        assert_eq!(
            decode_backwards_variant(ZX2B_FOX_X, &[], 1, true, usize::MAX).unwrap(),
            FOX_TEXT
        );
        let mut a300 = vec![b'a'; 299];
        a300.push(0);
        assert_eq!(
            decode_backwards_variant(ZX2B_A300_Z, &[], 0, false, usize::MAX).unwrap(),
            a300
        );
    }

    #[test]
    fn decode_backwards_suffix_kat() {
        // `zx2 -b +20`: the match at the start of the stream reaches
        // into the 20-byte suffix history.
        let suffix = b"the quick brown fox ";
        let mut expected = Vec::new();
        for _ in 0..204 {
            expected.extend_from_slice(suffix);
        }
        assert_eq!(
            decode_backwards_with_suffix(ZX2B_T4K_P20, suffix).unwrap(),
            expected
        );
        assert_eq!(
            decode_backwards_variant(ZX2B_T4K_P20, suffix, 1, false, usize::MAX).unwrap(),
            expected
        );
        // Without the suffix the first match points beyond the output.
        assert!(decode_backwards(ZX2B_T4K_P20).is_err());
        // A wrong suffix decodes but yields different bytes.
        let mut expected_bad = Vec::new();
        for _ in 0..204 {
            expected_bad.extend_from_slice(b"the quick brown FOX ");
        }
        assert_eq!(
            decode_backwards_with_suffix(ZX2B_T4K_P20, b"the quick brown FOX ").unwrap(),
            expected_bad
        );
    }

    #[test]
    fn decode_backwards_offset_byte() {
        // The backwards offset byte stores `offset - 1`: byte 0x00 is a
        // distance-1 match (0xfe would be distance 1 in forward mode).
        //   F: literal 'a' | newoff byte 0x00 (dist 1) len elias(2) | EOF
        //   B = reverse(F)
        let stream = [0xff, 0x00, b'a', 0x64];
        assert_eq!(decode_backwards(&stream).unwrap(), b"aaaa");
        // Byte 0xfe encodes offset 255, beyond the single byte of
        // available history.
        assert!(decode_backwards(&[0xff, 0xfe, b'a', 0x64]).is_err());
        // A rep-offset block carries no offset byte and is identical in
        // both modes.
        let stream = [0xff, b'a', 0x34];
        assert_eq!(decode_backwards(&stream).unwrap(), b"aaaa");
    }

    #[test]
    fn decode_backwards_rejects_malformed() {
        let enc = encode_backwards(b"the quick brown fox jumps over the lazy dog");
        // Truncating the backwards stream drops the leading control
        // byte of the forward stream.
        assert!(decode_backwards(&enc[..enc.len() - 1]).is_err());
        // Bytes prepended to a backwards stream are trailing data after
        // the EOF marker in the forward view.
        let mut c = Vec::new();
        c.push(0xaa);
        c.extend_from_slice(&enc);
        assert!(decode_backwards(&c).is_err());
        // Corruption is detected somewhere in the stream.
        let mut any_err = false;
        for i in 0..enc.len() {
            let mut c = enc.clone();
            c[i] = 0x00;
            if decode_backwards(&c).is_err() {
                any_err = true;
            }
        }
        assert!(any_err);
        // Empty input maps to empty output in both directions.
        assert_eq!(decode_backwards(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(
            decode_backwards_variant(&[], b"sfx", 0, true, 7).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(encode_backwards(b""), Vec::<u8>::new());
        assert_eq!(
            encode_backwards_variant(b"", b"sfx", 0, true, 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn decode_backwards_bounded_limit() {
        let data = vec![b'z'; 500];
        let enc = encode_backwards(&data);
        assert!(matches!(
            decode_backwards_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_backwards_bounded(&enc, 500).unwrap(), data);
    }

    #[test]
    fn encode_backwards_roundtrip() {
        rtb(b"a");
        rtb(b"ab");
        rtb(b"abcabcabc");
        rtb(b"aaaaaaaaaaaaaaaaaaaa");
        rtb(b"hello world hello world hello world");
        rtb(&[0u8; 2000]);
        let mut text = Vec::new();
        for _ in 0..150 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rtb(&text);
        let mut binary = Vec::new();
        for i in 0..4000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        rtb(&binary);
        let mut mixed = Vec::new();
        for _ in 0..50 {
            mixed.extend_from_slice(b"aaaaa");
            mixed.extend_from_slice(b"abcdef");
        }
        rtb(&mixed);
        // Distances near the 255-byte offset limit.
        let mut far = Vec::new();
        far.extend(0u8..=250);
        far.extend_from_slice(b"PATTERN!");
        far.extend(0u8..=250);
        far.extend_from_slice(b"PATTERN!");
        rtb(&far);
        // Backwards encoding differs from forward encoding.
        assert_ne!(encode_backwards(b"abcabcabc"), encode(b"abcabcabc"));
    }

    #[test]
    fn encode_backwards_with_suffix_roundtrip() {
        // The input tail "abc" repeats the suffix start; in the
        // reversed (forward) domain this is a distance-4 new-offset
        // match after literal 'Q', stored with backwards byte 0x03.
        //   F = [0x64, 'Q', 0x03, 0xff]  ->  B = [0xff, 0x03, 'Q', 0x64]
        let enc = encode_backwards_with_suffix(b"abcQ", b"abc");
        assert_eq!(enc, [0xff, 0x03, b'Q', 0x64]);
        assert_eq!(decode_backwards_with_suffix(&enc, b"abc").unwrap(), b"abcQ");

        // A mix of suffix-referencing and in-input matches.
        let enc = encode_backwards_with_suffix(b"xabcabc", b"abc");
        assert_eq!(
            decode_backwards_with_suffix(&enc, b"abc").unwrap(),
            b"xabcabc"
        );

        // Only the first 255 suffix bytes are reachable; the emitted
        // match must reference the suffix, so decoding without it fails.
        let suffix: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let mut data = vec![b'x'; 40];
        data.extend_from_slice(&suffix[..20]);
        let enc = encode_backwards_with_suffix(&data, &suffix);
        assert_eq!(decode_backwards_with_suffix(&enc, &suffix).unwrap(), data);
        assert!(decode_backwards(&enc).map_or(true, |v| v != data));

        // A wrong suffix decodes but yields different bytes.
        assert_ne!(
            decode_backwards_with_suffix(&[0xff, 0x03, b'Q', 0x64], b"XYZ").unwrap(),
            b"abcQ"
        );
    }

    #[test]
    fn encode_backwards_variant_roundtrip() {
        let cases: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"abcabcabcabcabcabc".to_vec(),
            b"aaaaaaaaaaaaaaaaaaaa".to_vec(),
            b"hello world hello world hello world".to_vec(),
            vec![7u8; 1500],
        ];
        for data in &cases {
            // -z: the first match is always a new-offset block, so the
            // stream also decodes with the default flags.
            let enc = encode_backwards_variant(data, &[], 0, false, usize::MAX).unwrap();
            assert_eq!(
                decode_backwards_variant(&enc, &[], 0, false, usize::MAX).unwrap(),
                *data
            );
            assert_eq!(decode_backwards(&enc).unwrap(), *data);
            // -x: new-offset lengths are stored without the -1 bias.
            let enc = encode_backwards_variant(data, &[], 1, true, usize::MAX).unwrap();
            assert_eq!(
                decode_backwards_variant(&enc, &[], 1, true, usize::MAX).unwrap(),
                *data
            );
            // -b -z -x + suffix combined.
            let enc = encode_backwards_variant(data, b"tail history", 0, true, usize::MAX).unwrap();
            assert_eq!(
                decode_backwards_variant(&enc, b"tail history", 0, true, usize::MAX).unwrap(),
                *data
            );
        }
        // `-y` (max_len) constrains the backwards encoder as well.
        let mut text = Vec::new();
        for _ in 0..80 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        let enc = encode_backwards_variant(&text, &[], 1, false, 64).unwrap();
        assert_eq!(decode_backwards(&enc).unwrap(), text);
        // max_block_len inspects the forward (unreversed) form; the
        // offset byte encoding differs but 0xff is EOF in both modes.
        let mut f = enc.clone();
        f.reverse();
        assert!(max_block_len(&f) <= 64);
    }
}
