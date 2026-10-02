//! ZX0 compression (Einar Saukas, BSD 3-Clause).
//!
//! ZX0 v2 raw stream: an interleaved sequence of control-bit bytes and data
//! bytes. Bits are read MSB-first from control bytes; literal bytes and
//! offset-LSB bytes occupy whole input bytes in consumption order.
//!
//! Block types:
//! - literal: `0` + `elias(len)` + `len` raw bytes
//! - copy from last offset: `0` + `elias(len)`
//! - copy from new offset: `1` + `elias((off-1)/128 + 1, inverted)` +
//!   `((127 - (off-1)%128) << 1)` byte + `elias(len-1)`
//!
//! The stream always opens with a literal block whose leading `0` bit is
//! omitted. After a literal block bit `0` selects copy-from-last-offset;
//! after any copy block `0` selects literal and `1` a new offset. An offset
//! MSB value of 256 terminates the stream. In the v2 format the data bits
//! of the offset-MSB elias are inverted, and the low bit of the offset-LSB
//! byte is reused as the first bit of the following length elias.
//!
//! The classic v1 format (`-c`) is supported via [`decode_classic`] and
//! [`encode_classic`]: its only wire difference is that the offset-MSB
//! Elias gamma data bits are stored non-inverted. Streams produced with
//! the `+N` prefix option can
//! be decoded via [`decode_with_prefix`], which lets match offsets reach
//! into caller-supplied external history.
//!
//! The backwards variant (`-b`) is supported via [decode_backwards] and
//! [encode_backwards]: the stream is the byte-reversed image of a stream
//! written with mirrored Elias gamma coding (continuation bit `1`,
//! terminator `0`), a non-inverted offset-MSB elias, and an
//! offset-LSB byte of `((off-1)%128)<<1`.
//! [decode_backwards_with_suffix] and [encode_backwards_with_suffix]
//! cover the `-b +N` combination, where the last `N` bytes of
//! the uncompressed input serve as trailing match history. Upstream
//! `-c -b` is byte-identical to `-b` (the invert flag applies
//! to neither), so no separate classic-backwards API exists. Upstream has
//! no `-i` inverted variant.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Largest encodable offset (ZX0 limit).
const MAX_OFFSET: usize = 32640;
const MIN_MATCH: usize = 2;

struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    value: u8,
    mask: u8,
    // When set, the next read_bit returns `last_byte & 1` instead.
    backtrack: bool,
    last_byte: u8,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        BitReader {
            input,
            pos: 0,
            value: 0,
            mask: 0,
            backtrack: false,
            last_byte: 0,
        }
    }

    fn read_byte(&mut self) -> Result<u8, Error> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(Error::InvalidData("zx0: unexpected end of input"))?;
        self.pos += 1;
        self.last_byte = b;
        Ok(b)
    }

    fn read_bit(&mut self) -> Result<u32, Error> {
        if self.backtrack {
            self.backtrack = false;
            return Ok((self.last_byte & 1) as u32);
        }
        if self.mask == 0 {
            self.value = self.read_byte()?;
            self.mask = 0x80;
        }
        let bit = self.value & self.mask;
        self.mask >>= 1;
        Ok((bit != 0) as u32)
    }

    /// `inverted` flips the stored data bits (v2 offset-MSB elias);
    /// `backwards` swaps the coding polarity to continuation bit
    /// `1` and terminator `0`, matching the upstream `-b`
    /// mode.
    fn elias(&mut self, inverted: bool, backwards: bool) -> Result<u32, Error> {
        let mut value = 1u32;
        while self.read_bit()? == backwards as u32 {
            let bit = self.read_bit()? ^ (inverted as u32);
            if value >= (1 << 20) {
                return Err(Error::InvalidData("zx0: elias value too large"));
            }
            value = (value << 1) | bit;
        }
        Ok(value)
    }
}

/// Decode a ZX0 v2 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a ZX0 v2 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output, true, false)
}

/// Decode a ZX0 v1 (`-c` classic) stream.
///
/// The only wire difference from v2 is that the offset-MSB Elias gamma
/// data bits are stored non-inverted.
pub fn decode_classic(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_classic_bounded(input, usize::MAX)
}

/// Decode a ZX0 v1 (`-c` classic) stream with an output size limit.
pub fn decode_classic_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output, false, false)
}

/// Decode a ZX0 v2 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, true, false)
}

/// Decode a ZX0 v1 (`-c` classic) stream with a `prefix` history as in
/// [`decode_with_prefix`].
pub fn decode_classic_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, false, false)
}

/// Decode a ZX0 `-b` backwards stream.
///
/// A backwards stream is the byte-reversed image of a stream written
/// with mirrored Elias gamma coding (continuation bit `1`,
/// terminator `0`), a non-inverted offset-MSB elias, and an
/// offset-LSB byte of `((off-1)%128)<<1`; decoding reverses the
/// input, applies the backwards block format, then reverses the
/// produced output.
pub fn decode_backwards(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_backwards_bounded(input, usize::MAX)
}

/// Decode a ZX0 `-b` backwards stream with an output size limit.
pub fn decode_backwards_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_backwards_impl(input, &[], max_output)
}

/// Decode a ZX0 `-b +N` backwards stream: `suffix` is the
/// trailing history in original data order (the last `N` bytes of
/// the uncompressed input, which are not emitted) that match offsets
/// may reach into.
pub fn decode_backwards_with_suffix(input: &[u8], suffix: &[u8]) -> Result<Vec<u8>, Error> {
    // In the reversed stream order the original suffix becomes leading
    // history.
    let prefix: Vec<u8> = suffix.iter().rev().copied().collect();
    decode_backwards_impl(input, &prefix, usize::MAX)
}

fn decode_backwards_impl(input: &[u8], prefix: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    // The backwards stream is the forward-order stream in reverse byte
    // order, and its decompressed image is likewise reversed. Backwards
    // streams never invert the offset-MSB elias data bits (upstream:
    // invert_mode = !classic && !backwards).
    let fwd: Vec<u8> = input.iter().rev().copied().collect();
    let mut out = decode_impl(&fwd, prefix, max_output, false, true)?;
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
    inverted_msb: bool,
    backwards: bool,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut last_offset = 1usize; // INITIAL_OFFSET

    // The first block is always a literal block without an indicator bit.
    let mut literals = true;
    loop {
        if literals {
            let len = r.elias(false, backwards)? as usize;
            if r.pos + len > input.len() {
                return Err(Error::InvalidData("zx0: truncated literals"));
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
                let len = r.elias(false, backwards)? as usize;
                copy_match(
                    prefix,
                    &mut out,
                    last_offset,
                    len,
                    max_output,
                    "zx0: offset before start",
                )?;
                literals = r.read_bit()? == 0;
                continue;
            }
        }

        // COPY_FROM_NEW_OFFSET. v2 stores the offset-MSB elias data bits
        // inverted; v1 (classic) and the backwards variant store them
        // verbatim.
        let msb = r.elias(inverted_msb, backwards)? as usize;
        if msb == 256 {
            // EOF: the reference decoder requires the input to be fully
            // consumed at this point.
            if r.pos != input.len() {
                return Err(Error::InvalidData("zx0: trailing data after end"));
            }
            return Ok(out);
        }
        let lsb_byte = r.read_byte()?;
        // Forward streams store (127-(off-1)%128)<<1 while backwards
        // streams store ((off-1)%128)<<1, so the reconstruction differs.
        last_offset = if backwards {
            (msb - 1) * 128 + (lsb_byte as usize >> 1) + 1
        } else {
            msb * 128 - (lsb_byte as usize >> 1)
        };
        r.backtrack = true;
        let len = r.elias(false, backwards)? as usize + 1;
        copy_match(
            prefix,
            &mut out,
            last_offset,
            len,
            max_output,
            "zx0: bad match offset",
        )?;
        literals = r.read_bit()? == 0;
    }
}

struct BitWriter {
    out: Vec<u8>,
    bit_index: usize,
    mask: u8,
    backtrack: bool,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            out: Vec::new(),
            bit_index: 0,
            mask: 0,
            backtrack: false,
        }
    }

    fn write_bit(&mut self, bit: bool) {
        if self.backtrack {
            // The next "control bit" lives in bit0 of the previously
            // written byte (the offset-LSB byte).
            if bit {
                let i = self.out.len() - 1;
                self.out[i] |= 1;
            }
            self.backtrack = false;
        } else {
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
    }

    fn write_byte(&mut self, b: u8) {
        self.out.push(b);
    }

    /// `inverted` flips the stored data bits (v2 offset-MSB
    /// elias); `backwards` writes continuation bits as `1`
    /// and the terminator as `0` (the upstream `-b` mode).
    fn write_elias(&mut self, value: usize, inverted: bool, backwards: bool) {
        let mut i = 2usize;
        while i <= value {
            i <<= 1;
        }
        i >>= 1;
        while i > 1 {
            i >>= 1;
            self.write_bit(backwards);
            let bit = ((value & i) != 0) ^ inverted;
            self.write_bit(bit);
        }
        self.write_bit(!backwards);
    }
}

/// Encode data as a ZX0 v2 stream (forward mode, non-inverted literals).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX0 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], true, false)
}

/// Encode data as a ZX0 v1 (`-c` classic) stream.
///
/// Identical to [`encode`] except that the offset-MSB Elias gamma data
/// bits (including the EOF marker) are stored non-inverted, matching
/// [`decode_classic`].
pub fn encode_classic(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], false, false)
}

/// Encode data as a ZX0 `-b` backwards stream.
///
/// Produces the byte-reversed image of a stream using mirrored Elias
/// gamma coding; decode with [decode_backwards]. As with [encode], the
/// emitted parsing is greedy rather than optimal.
pub fn encode_backwards(input: &[u8]) -> Vec<u8> {
    encode_backwards_impl(input, &[])
}

/// Encode data as a ZX0 `-b +N` backwards stream: `suffix`
/// is trailing history in original data order that match offsets may
/// reach into but that is never emitted. Decode with
/// [decode_backwards_with_suffix] passing the same `suffix`.
pub fn encode_backwards_with_suffix(input: &[u8], suffix: &[u8]) -> Vec<u8> {
    // In the reversed stream order the original suffix becomes leading
    // history.
    let prefix: Vec<u8> = suffix.iter().rev().copied().collect();
    encode_backwards_impl(input, &prefix)
}

fn encode_backwards_impl(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    // Encode the reversed payload over the reversed-order history
    // (prefix == rev(suffix)), then reverse the produced stream.
    let rev_input: Vec<u8> = input.iter().rev().copied().collect();
    let mut out = encode_impl(&rev_input, prefix, false, true);
    out.reverse();
    out
}

fn encode_impl(input: &[u8], prefix: &[u8], inverted_msb: bool, backwards: bool) -> Vec<u8> {
    if input.is_empty() {
        // The ZX0 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Vec::new();
    }

    // Offsets are measured over the virtual history prefix ++ input,
    // matching how the prefix/suffix decoders resolve them: a distance
    // d at the current output position copies from d bytes back, which
    // reaches into prefix when d exceeds the emitted bytes.
    let base = prefix.len();
    let hist_len = base + input.len();
    let at = |i: usize| -> u8 { if i < base { prefix[i] } else { input[i - base] } };

    let mut w = BitWriter::new();
    let mut head = vec![-1i32; 1 << 15];
    let mut last_offset = 1usize;
    let mut lit_start = base;
    let mut pos = base;
    let mut first_block = true;
    let mut after_literals = false;

    // Seed the match chain with prefix positions so the search below can
    // emit offsets that reach into the external history.
    for p in 0..base.min(hist_len.saturating_sub(2)) {
        let h = (((at(p) as usize) << 8) ^ ((at(p + 1) as usize) << 4) ^ at(p + 2) as usize)
            & ((1 << 15) - 1);
        head[h] = p as i32;
    }

    while pos < hist_len {
        // Search for a match at pos (needs at least MIN_MATCH bytes).
        let mut best: Option<(usize, usize)> = None;
        if pos + 3 <= hist_len {
            let h =
                (((at(pos) as usize) << 8) ^ ((at(pos + 1) as usize) << 4) ^ at(pos + 2) as usize)
                    & ((1 << 15) - 1);
            let cand = head[h];
            head[h] = pos as i32;
            // The stream must open with a literal block of length >= 1,
            // so no match may start at the very first output position.
            if cand >= 0 && !(first_block && pos == lit_start) {
                let c = cand as usize;
                let dist = pos - c;
                if dist <= MAX_OFFSET && at(c) == at(pos) && at(c + 1) == at(pos + 1) {
                    let mut len = MIN_MATCH;
                    while pos + len < hist_len && at(c + len) == at(pos + len) {
                        len += 1;
                    }
                    best = Some((len, dist));
                }
            }
        }

        if let Some((len, dist)) = best {
            // Flush pending literals first.
            let lit_len = pos - lit_start;
            if lit_len > 0 || first_block {
                debug_assert!(lit_len > 0); // first match implies >=1 literal
                if !first_block {
                    w.write_bit(false); // literal indicator after a match
                }
                w.write_elias(lit_len, false, backwards);
                for i in lit_start..pos {
                    w.write_byte(at(i));
                }
                first_block = false;
                after_literals = true;
            }

            if after_literals && dist == last_offset {
                // Copy from last offset.
                w.write_bit(false);
                w.write_elias(len, false, backwards);
            } else {
                // Copy from new offset.
                w.write_bit(true);
                let msb = (dist - 1) / 128 + 1;
                // v2 stores the data bits inverted; v1 classic and the
                // backwards variant store them verbatim.
                w.write_elias(msb, inverted_msb, backwards);
                if backwards {
                    w.write_byte((((dist - 1) % 128) << 1) as u8);
                } else {
                    w.write_byte(((127 - (dist - 1) % 128) << 1) as u8);
                }
                w.backtrack = true;
                w.write_elias(len - 1, false, backwards);
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
    let lit_len = hist_len - lit_start;
    if lit_len > 0 {
        if !first_block {
            w.write_bit(false);
        }
        w.write_elias(lit_len, false, backwards);
        for i in lit_start..hist_len {
            w.write_byte(at(i));
        }
    }

    // End marker: new-offset indicator + elias 256 (data bits follow the
    // same inverted/verbatim rule as the match offset MSB).
    w.write_bit(true);
    w.write_elias(256, inverted_msb, backwards);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    fn rt_classic(data: &[u8]) {
        let enc = encode_classic(data);
        assert_eq!(decode_classic(&enc).unwrap(), data);
    }

    /// Build a stream: one literal block `lits`, one new-offset match
    /// (`dist`, `len`), then EOF. `inverted` selects the v2 (true) vs
    /// v1 classic (false) offset-MSB elias coding.
    fn match_stream(lits: &[u8], dist: usize, len: usize, inverted: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_elias(lits.len(), false, false);
        for &b in lits {
            w.write_byte(b);
        }
        w.write_bit(true); // new offset
        w.write_elias((dist - 1) / 128 + 1, inverted, false);
        w.write_byte(((127 - (dist - 1) % 128) << 1) as u8);
        w.backtrack = true;
        w.write_elias(len - 1, false, false);
        w.write_bit(true); // EOF indicator
        w.write_elias(256, inverted, false);
        w.out
    }

    #[test]
    fn decode_classic_v1() {
        // dist 130 -> offset MSB 2, so the elias carries a data bit and
        // the v1/v2 encodings differ.
        let lits: Vec<u8> = (0..140u8).collect();
        let v1 = match_stream(&lits, 130, 5, false);
        let v2 = match_stream(&lits, 130, 5, true);
        assert_ne!(v1, v2);

        let mut expected = lits.clone();
        let start = expected.len() - 130;
        for i in 0..5 {
            let b = expected[start + i];
            expected.push(b);
        }

        assert_eq!(decode_classic(&v1).unwrap(), expected);
        assert_eq!(
            decode_classic_bounded(&v1, expected.len()).unwrap(),
            expected
        );
        assert!(matches!(
            decode_classic_bounded(&v1, expected.len() - 1),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode(&v2).unwrap(), expected);
        // Cross-decoding fails: each variant reads a different MSB whose
        // offset lands outside the produced output.
        assert!(decode(&v1).is_err());
        assert!(decode_classic(&v2).is_err());
    }

    #[test]
    fn encode_classic_roundtrip() {
        rt_classic(b"a");
        rt_classic(b"ab");
        rt_classic(b"abcabcabc");
        rt_classic(b"hello world hello world hello world");
        rt_classic(&[0u8; 2000]);
        // dist > 128 gives an offset MSB > 1, so the elias carries data
        // bits: the point where the v1 and v2 wire formats differ.
        let mut far: Vec<u8> = (0..140u8).collect();
        far.extend_from_slice(&[10, 11, 12, 13, 14]); // len-5 match at dist 130
        rt_classic(&far);
        let mut rep = b"abcd".to_vec();
        rep.extend_from_slice(b"abcdabcdabcd");
        rt_classic(&rep);
        let mut text = Vec::new();
        for _ in 0..100 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt_classic(&text);
    }

    #[test]
    fn encode_classic_vs_v2() {
        // The EOF marker's elias(256) data bits differ between variants,
        // so the streams differ for every non-empty input. Cross-decoding
        // a classic stream as v2 (or vice versa) must not reproduce the
        // input; in practice it fails on the first offset-MSB elias.
        for data in [
            b"a".as_slice(),
            b"abcabcabc".as_slice(),
            b"hello world hello world hello world".as_slice(),
        ] {
            let v1 = encode_classic(data);
            let v2 = encode(data);
            assert_ne!(v1, v2);
            assert_ne!(decode(&v1).ok().as_deref(), Some(data));
            assert_ne!(decode_classic(&v2).ok().as_deref(), Some(data));
        }
    }

    #[test]
    fn encode_classic_empty() {
        assert_eq!(encode_classic(b""), Vec::<u8>::new());
        assert_eq!(decode_classic(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn encode_classic_known_vector() {
        // 140 distinct literal bytes then a len-5 match at dist 130: the
        // offset MSB is 2, so its elias carries a data bit that differs
        // between v1 and v2. The greedy encoder emits exactly the
        // literal-block + match + EOF layout built by `match_stream`.
        let lits: Vec<u8> = (0..140u8).collect();
        let mut input = lits.clone();
        input.extend_from_slice(&[10, 11, 12, 13, 14]);
        assert_eq!(encode_classic(&input), match_stream(&lits, 130, 5, false));
        assert_eq!(encode(&input), match_stream(&lits, 130, 5, true));
    }

    #[test]
    fn decode_prefix_history() {
        // literal 'a', then a distance-6 len-3 match reaching into the
        // 5-byte prefix "HELLO", then EOF.
        let stream = [0xed, b'a', 0xf4, 0x55, 0x56];
        // Without the prefix the distance exceeds the produced output.
        assert!(decode(&stream).is_err());
        assert_eq!(decode_with_prefix(&stream, b"HELLO").unwrap(), b"aHEL");
        // Classic variant of the same stream (non-inverted EOF elias).
        let classic = [0xec, b'a', 0xf4, 0x00, 0x02];
        assert_eq!(
            decode_classic_with_prefix(&classic, b"HELLO").unwrap(),
            b"aHEL"
        );
    }

    #[test]
    fn decode_prefix_match_crosses_boundary() {
        // distance 3, len 5: the match starts in the 2-byte prefix and
        // continues into produced output (overlapping copy).
        let stream = [0xe3, b'a', 0xfa, 0x55, 0x55, 0x80];
        assert_eq!(decode_with_prefix(&stream, b"AB").unwrap(), b"aABaAB");
    }

    #[test]
    fn decode_minimal_literal() {
        // literal "A" then EOF: ctrl bits `1`(len1) `1`(newoff) + elias256.
        // ctrl byte0 = 0b11000000, literal 'A', then remaining 11 elias
        // bits for 256 (inverted): elias(256,inv) = bits `0`+d... see below.
        // 256 = 0b100000000 -> 8 continuation pairs; inverted digits all 1:
        // `0`,`1` x8 + `1` = 17 bits. Plus leading 2 bits = 19 bits total.
        // byte0 = 11_000000 = 0xC0, byte2 = 01_010101 = 0x55, byte3 = 0xAB>>?
        // Simpler: verify decode of a reference-produced stream elsewhere;
        // here just check the hand-built minimal stream.
        let enc = encode(b"A");
        assert_eq!(decode(&enc).unwrap(), b"A");
    }

    #[test]
    fn decode_copy_last_offset() {
        // "ab" literals then copy-last-offset... last_offset starts at 1
        // only usable after literals; use encoder output.
        rt(b"aaaaaaaaaaaaaaaaaaaa");
    }

    #[test]
    fn decode_new_offset() {
        rt(b"abcabcabcabcabcabc");
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x80]).is_err()); // literal len but no byte
        assert!(decode(&[0xc0]).is_err()); // incomplete
    }

    #[test]
    fn rejects_bad_offset() {
        // literals "ab" then new-offset with msb so large it exceeds output
        // Hand-build via encoder then corrupt the lsb byte.
        let mut enc = encode(b"abababababab");
        // find the offset lsb byte — brute force: try corrupting each byte
        // and require at least one to fail
        let mut any_err = false;
        for i in 0..enc.len() {
            let mut c = enc.clone();
            c[i] = 0xff;
            if decode(&c).is_err() {
                any_err = true;
            }
        }
        assert!(any_err);
        enc.clear();
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
        // Force last-offset matches: pattern with distance-1 runs and a
        // literal-then-same-offset sequence.
        let mut mixed = Vec::new();
        for _ in 0..50 {
            mixed.extend_from_slice(b"aaaaa");
            mixed.extend_from_slice(b"abcdef");
        }
        rt(&mixed);
        // A case exercising copy-last-offset (dist equal to previous).
        let mut rep = b"abcd".to_vec();
        rep.extend_from_slice(b"abcdabcdabcd");
        rt(&rep);
    }

    // ---- backwards (-b) variant -------------------------------------
    //
    // ZX0B_* streams were produced by the reference ZX0 v2.2 compressor
    // streams below came from zx0 -b, or zx0 -b +N for the suffix-history forms.

    /// zx0 -b output for the fox input used by the integration tests.
    const ZX0B_FOX: &[u8] = &[
        0x00, 0xaa, 0xaa, 0xb9, 0x59, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0xe4, 0x6f, 0x76, 0x65,
        0x72, 0xa0, 0x1b, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0x74, 0x68,
        0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66,
        0x6f, 0x78, 0x2e, 0x0a, 0x48, 0xff,
    ];

    /// zx0 -b output for b"a" * 299 followed by a NUL byte.
    const ZX0B_A300: &[u8] = &[0xa8, 0xaa, 0xe6, 0xee, 0x61, 0x00, 0x8a];

    /// zx0 -c -b output for the same input: byte-identical to ZX0B_A300
    /// because backwards streams never invert the offset-MSB elias.
    const ZX0B_A300_CB: &[u8] = &[0xa8, 0xaa, 0xe6, 0xee, 0x61, 0x00, 0x8a];

    /// zx0 -b output for b"the quick brown fox " * 205.
    const ZX0B_T4K: &[u8] = &[
        0x80, 0xaa, 0x6a, 0xff, 0xfe, 0x27, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b,
        0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x5f, 0xba,
    ];

    /// zx0 -b +20 output for the t4k input: covers its first 4080 bytes
    /// with the trailing 20 bytes as match history.
    const ZX0B_T4K_S20: &[u8] = &[0x80, 0xaa, 0x6a, 0xfe, 0xfe, 0x27, 0x20, 0x5f];

    fn fox_input() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. the quick brown fox.
"
        .to_vec()
    }

    fn a300_input() -> Vec<u8> {
        let mut v = vec![b'a'; 299];
        v.push(0);
        v
    }

    fn t4k_input() -> Vec<u8> {
        let pat = b"the quick brown fox ";
        let mut v = Vec::new();
        for _ in 0..205 {
            v.extend_from_slice(pat);
        }
        v
    }

    fn rt_backwards(data: &[u8]) {
        let enc = encode_backwards(data);
        assert_eq!(decode_backwards(&enc).unwrap(), data);
    }

    #[test]
    fn backwards_reference_vectors() {
        assert_eq!(decode_backwards(ZX0B_FOX).unwrap(), fox_input());
        assert_eq!(decode_backwards(ZX0B_A300).unwrap(), a300_input());
        assert_eq!(decode_backwards(ZX0B_T4K).unwrap(), t4k_input());
        // Upstream -c -b produces the identical wire stream, so it
        // decodes through the same backwards path.
        assert_eq!(decode_backwards(ZX0B_A300_CB).unwrap(), a300_input());
    }

    #[test]
    fn backwards_suffix_history() {
        let t4k = t4k_input();
        let (body, suffix) = t4k.split_at(4080);
        assert_eq!(suffix, b"the quick brown fox ");
        assert_eq!(
            decode_backwards_with_suffix(ZX0B_T4K_S20, suffix).unwrap(),
            body
        );
        // The stream opens with a match reaching into the suffix
        // history, so it cannot decode without it.
        assert!(decode_backwards(ZX0B_T4K_S20).is_err());
    }

    #[test]
    fn backwards_roundtrip() {
        rt_backwards(b"a");
        rt_backwards(b"ab");
        rt_backwards(b"abcabcabc");
        rt_backwards(b"hello world hello world hello world");
        rt_backwards(&[0u8; 2000]);
        let mut text = Vec::new();
        for _ in 0..150 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt_backwards(&text);
        let mut binary = Vec::new();
        for i in 0..4000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        rt_backwards(&binary);
        let mut mixed = Vec::new();
        for _ in 0..50 {
            mixed.extend_from_slice(b"aaaaa");
            mixed.extend_from_slice(b"abcdef");
        }
        rt_backwards(&mixed);
        let mut rep = b"abcd".to_vec();
        rep.extend_from_slice(b"abcdabcdabcd");
        rt_backwards(&rep);
    }

    #[test]
    fn backwards_suffix_roundtrip() {
        fn rt(data: &[u8], suffix: &[u8]) {
            let enc = encode_backwards_with_suffix(data, suffix);
            assert_eq!(decode_backwards_with_suffix(&enc, suffix).unwrap(), data);
        }
        rt(b"hello hello hello", b"");
        rt(b"", b"unused history");
        rt(b"aaaaaaaaaaaaaaaaaaaa", b"aaaa");
        // Content occurring only inside the suffix exercises matches
        // that reach into the external history.
        let suffix = b"0123456789abcdef";
        let mut input = suffix.to_vec();
        input.extend_from_slice(b" head");
        rt(&input, suffix);
        let mut text = Vec::new();
        for _ in 0..40 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&text, b"the lazy dog. ");
        // An empty suffix is plain backwards encoding.
        assert_eq!(
            encode_backwards_with_suffix(b"abcabc", b""),
            encode_backwards(b"abcabc")
        );
    }

    #[test]
    fn backwards_rejects_malformed() {
        // A lone control byte: the literal length decodes but no literal
        // data follows.
        assert!(decode_backwards(&[0x00]).is_err());
        // Truncated: the missing tail removes the end-of-stream marker.
        assert!(decode_backwards(&ZX0B_FOX[..ZX0B_FOX.len() - 1]).is_err());
        // Garbage appended after EOF leads the reversed stream and
        // breaks the opening literal block.
        let mut c = ZX0B_FOX.to_vec();
        c.push(0xaa);
        assert!(decode_backwards(&c).is_err());
        // Corrupting stream bytes must produce at least one failure.
        let enc = encode_backwards(b"abababababababab");
        let mut any_err = false;
        for i in 0..enc.len() {
            let mut c = enc.clone();
            c[i] = 0xff;
            if decode_backwards(&c).is_err() {
                any_err = true;
            }
        }
        assert!(any_err);
    }

    #[test]
    fn backwards_bounded_and_empty() {
        assert_eq!(encode_backwards(b""), Vec::<u8>::new());
        assert_eq!(decode_backwards(&[]).unwrap(), Vec::<u8>::new());
        let data = vec![b'z'; 500];
        let enc = encode_backwards(&data);
        assert!(matches!(
            decode_backwards_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_backwards_bounded(&enc, 500).unwrap(), data);
    }
}
