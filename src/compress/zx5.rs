//! ZX5 compression (Einar Saukas, BSD 3-Clause).
//!
//! ZX5 raw stream: an interleaved sequence of control-bit bytes and data
//! bytes, derived from ZX0. Bits are read MSB-first from control bytes;
//! literal bytes and offset bytes occupy whole input bytes in consumption
//! order. ZX5 extends ZX0 with two additional block types that reuse the
//! second-to-last and third-to-last offsets.
//!
//! Block types:
//! - literal: `0` + `elias(len)` + `len` raw bytes
//! - copy from last offset: `0` + `elias(len)`
//! - copy from 2nd last offset: `1 0 0` + `elias(len)`
//! - copy from 3rd last offset: `1 0 1` + `elias(len)`
//! - copy from new offset: `1 1 *` + `elias(msb+1)` + `lsb` + `elias(len-1)`
//!
//! The stream always opens with a literal block whose leading `0` bit is
//! omitted. After a literal block bit `0` selects copy-from-last-offset and
//! `1` selects the other-offset group; after any copy block `0` selects
//! literal and `1` the other-offset group.
//!
//! Like ZX0, the interlaced Elias gamma coding uses `0` as the continuation
//! bit and `1` as the terminator. The offset-MSB elias uses inverted data
//! bits in format v2 (default); literal/length elias are non-inverted.
//! The `*` bit in the new-offset block is the first bit of the following
//! `elias(len-1)` emitted ahead of the offset fields; the decoder replays
//! it when reading the length. Offset MSB value 256 is the EOF marker.
//!
//! The classic v1 format (`-c`) is supported via [`decode_classic`]: its
//! only wire difference is that the offset-MSB Elias gamma data bits are
//! stored non-inverted. Streams produced with the `+N` prefix option can
//! be decoded via [`decode_with_prefix`], which lets match offsets reach
//! into caller-supplied external history. The `-q` quick mode only
//! constrains the encoder (offsets <= 2176); such streams decode with
//! [`decode`].
//!
//! Backwards (`-b`) mode is outside the current scope.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Largest encodable offset (ZX5 v2 limit).
const MAX_OFFSET: usize = 65280;
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
            .ok_or(Error::InvalidData("zx5: unexpected end of input"))?;
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

    /// Interlaced Elias gamma: continuation `0`, terminator `1`.
    /// `first` substitutes the initial bit when it was already emitted in
    /// the stream (the `*` bit of a new-offset block).
    fn elias(&mut self, first: Option<u32>, inverted: bool) -> Result<u32, Error> {
        let mut value = 1u32;
        let mut first = first;
        loop {
            let bit = match first.take() {
                Some(b) => b,
                None => self.read_bit()?,
            };
            if bit != 0 {
                return Ok(value);
            }
            if value >= (1 << 20) {
                return Err(Error::InvalidData("zx5: elias value too large"));
            }
            value = (value << 1) | (self.read_bit()? ^ inverted as u32);
        }
    }
}

/// Decode a ZX5 v2 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a ZX5 v2 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output, true)
}

/// Decode a ZX5 v1 (`-c` classic) stream.
///
/// The only wire difference from v2 is that the offset-MSB Elias gamma
/// data bits are stored non-inverted.
pub fn decode_classic(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_classic_bounded(input, usize::MAX)
}

/// Decode a ZX5 v1 (`-c` classic) stream with an output size limit.
pub fn decode_classic_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output, false)
}

/// Decode a ZX5 v2 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, true)
}

/// Decode a ZX5 v1 (`-c` classic) stream with a `prefix` history as in
/// [`decode_with_prefix`].
pub fn decode_classic_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, false)
}

fn decode_impl(
    input: &[u8],
    prefix: &[u8],
    max_output: usize,
    inverted_msb: bool,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = BitReader::new(input);
    let mut out: Vec<u8> = Vec::new();
    let mut last1 = 1usize; // INITIAL_OFFSET
    let mut last2 = 0usize;
    let mut last3 = 0usize;

    let copy = |out: &mut Vec<u8>, offset: usize, len: usize| -> Result<(), Error> {
        // Offsets may reach into the external `prefix` history.
        let avail = prefix.len() + out.len();
        if offset == 0 || offset > avail {
            return Err(Error::InvalidData("zx5: bad match offset"));
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
    };

    // The first block is always a literal block without an indicator bit.
    let mut literals = true;
    loop {
        if literals {
            let len = r.elias(None, false)? as usize;
            if r.pos + len > input.len() {
                return Err(Error::InvalidData("zx5: truncated literals"));
            }
            if out.len() + len > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            for _ in 0..len {
                let b = r.read_byte()?;
                out.push(b);
            }
            // After literals: 0 = copy from last offset, 1 = other offsets.
            if r.read_bit()? == 0 {
                let len = r.elias(None, false)? as usize;
                copy(&mut out, last1, len)?;
                literals = r.read_bit()? == 0;
                continue;
            }
        }

        // OTHER_OFFSETS: 0 = previous offset, 1 = new offset.
        if r.read_bit()? == 0 {
            // Copy from 2nd (0) or 3rd (1) last offset.
            if r.read_bit()? == 0 {
                core::mem::swap(&mut last1, &mut last2);
            } else {
                let o3 = last3;
                last3 = last2;
                last2 = last1;
                last1 = o3;
            }
            let len = r.elias(None, false)? as usize;
            copy(&mut out, last1, len)?;
        } else {
            // COPY_FROM_NEW_OFFSET. v2 stores the offset-MSB elias data
            // bits inverted; v1 (classic) stores them verbatim.
            let ahead = r.read_bit()?;
            last3 = last2;
            last2 = last1;
            let msb = r.elias(None, inverted_msb)? as usize;
            if msb == 256 {
                // EOF marker: the reference decoder requires the input to
                // be fully consumed at this point.
                if r.pos != input.len() {
                    return Err(Error::InvalidData("zx5: trailing data after end"));
                }
                return Ok(out);
            }
            last1 = msb * 256 - r.read_byte()? as usize;
            let len = r.elias(Some(ahead), false)? as usize + 1;
            copy(&mut out, last1, len)?;
        }
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

    /// Interlaced Elias gamma: continuation `0`, terminator `1`, data bits
    /// optionally inverted.
    fn write_elias(&mut self, value: usize, inverted: bool) {
        let mut i = 1usize;
        while i <= value {
            i <<= 1;
        }
        i >>= 1;
        while i > 1 {
            i >>= 1;
            self.write_bit(false);
            self.write_bit(((value & i) != 0) ^ inverted);
        }
        self.write_bit(true);
    }

    /// Emit `elias(value)` minus its leading bit, which was already written
    /// as the `*` bit of a new-offset block (the `*` bit is `value <= 1`,
    /// i.e. the terminator when the elias is a single bit).
    fn write_elias_tail(&mut self, value: usize, inverted: bool) {
        if value <= 1 {
            return;
        }
        let mut i = 1usize;
        while i <= value {
            i <<= 1;
        }
        i >>= 1;
        let mut j = i >> 1;
        // Data bit paired with the skipped leading continuation bit.
        self.write_bit(((value & j) != 0) ^ inverted);
        while j > 1 {
            j >>= 1;
            self.write_bit(false);
            self.write_bit(((value & j) != 0) ^ inverted);
        }
        self.write_bit(true);
    }
}

/// Encode data as a ZX5 stream (forward v2 mode).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX5 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        // The ZX5 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Vec::new();
    }

    let mut w = BitWriter::new();
    let mut head = vec![-1i32; 1 << 15];
    let mut last1 = 1usize;
    let mut last2 = 0usize;
    let mut last3 = 0usize;
    let mut lit_start = 0usize;
    let mut pos = 0usize;
    let mut first_block = true;
    let mut after_literals = false;

    while pos < input.len() {
        // Search for a match at pos.
        let mut best: Option<(usize, usize)> = None;
        if pos + MIN_MATCH <= input.len() {
            let h = (((input[pos] as usize) << 8)
                ^ ((input[pos + 1] as usize) << 4)
                ^ input[pos + 2] as usize)
                & ((1 << 15) - 1);
            let cand = head[h];
            head[h] = pos as i32;
            if cand >= 0 {
                let c = cand as usize;
                let dist = pos - c;
                if dist <= MAX_OFFSET && input[c] == input[pos] && input[c + 1] == input[pos + 1] {
                    let mut len = MIN_MATCH;
                    while pos + len < input.len() && input[c + len] == input[pos + len] {
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
                w.write_elias(lit_len, false);
                for &b in &input[lit_start..pos] {
                    w.write_byte(b);
                }
                first_block = false;
                after_literals = true;
            }

            if after_literals && dist == last1 {
                // Copy from last offset (only valid right after literals).
                w.write_bit(false);
                w.write_elias(len, false);
            } else {
                // Other-offsets group (valid after literals and after copies).
                w.write_bit(true);
                if dist == last2 {
                    w.write_bit(false);
                    w.write_bit(false);
                    w.write_elias(len, false);
                    core::mem::swap(&mut last1, &mut last2);
                } else if dist == last3 {
                    w.write_bit(false);
                    w.write_bit(true);
                    w.write_elias(len, false);
                    last3 = last2;
                    last2 = last1;
                    last1 = dist;
                } else {
                    w.write_bit(true);
                    w.write_bit(len <= 2); // `*` bit: first bit of elias(len-1)
                    w.write_elias((dist - 1) / 256 + 1, true);
                    w.write_byte((255 - (dist - 1) % 256) as u8);
                    w.write_elias_tail(len - 1, false);
                    last3 = last2;
                    last2 = last1;
                    last1 = dist;
                }
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
    if lit_len > 0 {
        if !first_block {
            w.write_bit(false);
        }
        w.write_elias(lit_len, false);
        for &b in &input[lit_start..] {
            w.write_byte(b);
        }
    }

    // End marker: other-offsets indicator + new-offset + `*` + elias(256).
    w.write_bit(true);
    w.write_bit(true);
    w.write_bit(false);
    w.write_elias(256, true);
    w.out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    /// Build a stream: one literal block `lits`, one new-offset match
    /// (`dist`, `len`), then EOF. `inverted` selects the v2 (true) vs
    /// v1 classic (false) offset-MSB elias coding.
    fn match_stream(lits: &[u8], dist: usize, len: usize, inverted: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_elias(lits.len(), false);
        for &b in lits {
            w.write_byte(b);
        }
        w.write_bit(true); // other-offsets group
        w.write_bit(true); // new offset
        w.write_bit(len <= 2); // `*`: first bit of elias(len - 1)
        w.write_elias((dist - 1) / 256 + 1, inverted);
        w.write_byte((255 - (dist - 1) % 256) as u8);
        w.write_elias_tail(len - 1, false);
        w.write_bit(true); // EOF: other-offsets, new-offset, `*` = 0
        w.write_bit(true);
        w.write_bit(false);
        w.write_elias(256, inverted);
        w.out
    }

    #[test]
    fn decode_classic_v1() {
        // dist 257 -> offset MSB 2, so the elias carries a data bit and
        // the v1/v2 encodings differ.
        let lits: Vec<u8> = (0..260u16).map(|i| i as u8).collect();
        let v1 = match_stream(&lits, 257, 6, false);
        let v2 = match_stream(&lits, 257, 6, true);
        assert_ne!(v1, v2);

        let mut expected = lits.clone();
        let start = expected.len() - 257;
        for i in 0..6 {
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
    fn decode_prefix_history() {
        // literal 'a', then a distance-4 len-3 match reaching into the
        // 3-byte prefix "XYZ", then EOF.
        //   bits: elias(1)=`1` | 'a' | `1` other | `1` new | `0` * |
        //         msb elias(1)=`1` | lsb 0xfc | len tail `0`,`1` |
        //         `1` `1` `0` | elias(256,inv) 17 bits
        let stream = [0xeb, b'a', 0xfc, 0x95, 0x55, 0x60];
        assert!(decode(&stream).is_err());
        assert_eq!(decode_with_prefix(&stream, b"XYZ").unwrap(), b"aXYZ");
        // Classic variant of the same stream (non-inverted EOF elias).
        let classic = [0xeb, b'a', 0xfc, 0x80, 0x00, 0x20];
        assert_eq!(
            decode_classic_with_prefix(&classic, b"XYZ").unwrap(),
            b"aXYZ"
        );
    }

    #[test]
    fn decode_prefix_match_crosses_boundary() {
        // distance 3, len 5: the match starts in the 2-byte prefix and
        // continues into produced output (overlapping copy).
        let stream = [0xe8, b'a', 0xfd, 0xe5, 0x55, 0x58];
        assert_eq!(decode_with_prefix(&stream, b"AB").unwrap(), b"aABaAB");
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
    fn decode_second_third_offset() {
        // Alternating patterns exercise the 2nd/3rd-last offset blocks.
        let mut data = Vec::new();
        for _ in 0..8 {
            data.extend_from_slice(b"ABCDEFGH");
            data.extend_from_slice(b"12345678");
            data.extend_from_slice(b"ijklmnop");
        }
        rt(&data);
    }

    #[test]
    fn decode_far_offset() {
        // Distance > 255 forces a multi-bit offset MSB.
        let mut data = vec![b'x'; 400];
        data.extend_from_slice(b"0123456789abcdef");
        data.extend_from_slice(&[0u8; 400]);
        data.extend_from_slice(b"0123456789abcdef");
        rt(&data);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x80]).is_err()); // literal len but no byte
        assert!(decode(&[0x40]).is_err()); // incomplete
    }

    #[test]
    fn rejects_bad_offset() {
        let enc = encode(b"abababababab");
        let mut any_err = false;
        for i in 0..enc.len() {
            let mut c = enc.clone();
            c[i] = 0xff;
            if decode(&c).is_err() {
                any_err = true;
            }
        }
        assert!(any_err);
    }

    #[test]
    fn rejects_zero_prev_offset() {
        // `1 0 0` after the opening literal selects the 2nd last offset,
        // which is 0 before any new-offset block: invalid.
        // Bits: literal len=1 (1), 'a', other(1), prev(0), 2nd(0), len=1 (1).
        assert!(decode(&[0xc8, b'a']).is_err());
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
        let mut mixed = Vec::new();
        for _ in 0..50 {
            mixed.extend_from_slice(b"aaaaa");
            mixed.extend_from_slice(b"abcdef");
        }
        rt(&mixed);
        // 2nd/3rd offset exercise.
        let mut alt = Vec::new();
        for _ in 0..12 {
            alt.extend_from_slice(b"ABCDEFGH");
            alt.extend_from_slice(b"12345678");
            alt.extend_from_slice(b"abcdefgh");
        }
        rt(&alt);
        let mut far = vec![0u8; 300];
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        far.extend_from_slice(&[1u8; 300]);
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        rt(&far);
    }
}
