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
//! Variant flags are supported on the decode side:
//! - `-z` (ignore default offset): [`decode_no_default_offset`] starts
//!   with `last_offset = 0` instead of 1.
//! - `-x` (skip length increment): [`decode_no_length_increment`] stores
//!   new-offset block lengths as `elias(len)` without the -1 bias.
//! - `-y` (limit block length) only constrains the encoder; such streams
//!   decode with [`decode`].
//! - `+N` prefix compression: [`decode_with_prefix`] lets match offsets
//!   reach into caller-supplied external history.
//! [`decode_variant`] covers arbitrary combinations of the above.
//!
//! Backwards (`-b`) mode is outside the current scope.

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
    decode_impl(input, &[], max_output, 1, false)
}

/// Decode a ZX2 stream produced with `-z` (ignore default offset): the
/// initial last-offset is 0, so a copy-from-last-offset is invalid until
/// a new-offset block sets one.
pub fn decode_no_default_offset(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], usize::MAX, 0, false)
}

/// Decode a ZX2 stream produced with `-x` (skip length increment):
/// new-offset block lengths are stored as `elias(len)` without the
/// usual -1 bias.
pub fn decode_no_length_increment(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], usize::MAX, 1, true)
}

/// Decode a ZX2 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, 1, false)
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
    )
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

        // COPY_FROM_NEW_OFFSET: single byte `255 - offset`; 0xff is EOF.
        let offset = 255 - r.read_byte()? as usize;
        if offset == 0 {
            // EOF marker: the reference decoder requires the input to be
            // fully consumed at this point.
            if r.pos != input.len() {
                return Err(Error::InvalidData("zx2: trailing data after end"));
            }
            return Ok(out);
        }
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
    if input.is_empty() {
        // The ZX2 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Vec::new();
    }

    let mut w = BitWriter::new();
    let mut head = vec![-1i32; 1 << 15];
    let mut last_offset = 1usize;
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
                w.write_byte((255 - dist) as u8);
                w.write_elias(len - 1);
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
    w.out
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
}
