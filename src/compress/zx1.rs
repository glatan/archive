//! ZX1 compression (Einar Saukas, BSD 3-Clause).
//!
//! ZX1 raw stream: an interleaved sequence of control-bit bytes and data
//! bytes. Bits are read MSB-first from control bytes; literal bytes and
//! offset bytes occupy whole input bytes in consumption order.
//!
//! Block types:
//! - literal: `0` + `elias(len)` + `len` raw bytes
//! - copy from last offset: `0` + `elias(len)`
//! - copy from new offset: `1` + offset bytes + `elias(len-1)`
//!
//! The stream always opens with a literal block whose leading `0` bit is
//! omitted. After a literal block bit `0` selects copy-from-last-offset;
//! after any copy block `0` selects literal and `1` a new offset.
//!
//! Unlike ZX0, the interlaced Elias gamma coding uses `1` as the
//! continuation bit and `0` as the terminator, with non-inverted data bits.
//! The new-offset field is stored raw in one or two bytes (the lowest bit
//! of the first byte indicates whether a second byte follows) using a
//! reflected encoding centred on MAX_OFFSET+1; any decoded offset <= 0 is
//! the end-of-stream marker.
//!
//! Backwards (`-b`) mode is outside the current scope.

use alloc::vec::Vec;

use crate::error::Error;

/// Largest encodable offset (ZX1 limit).
const MAX_OFFSET: usize = 32512;
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
            .ok_or(Error::InvalidData("zx1: unexpected end of input"))?;
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
                return Err(Error::InvalidData("zx1: elias value too large"));
            }
            value = (value << 1) | self.read_bit()?;
        }
        Ok(value)
    }
}

/// Decode a ZX1 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a ZX1 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
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
            let len = r.elias()? as usize;
            if r.pos + len > input.len() {
                return Err(Error::InvalidData("zx1: truncated literals"));
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
                if last_offset > out.len() {
                    return Err(Error::InvalidData("zx1: offset before start"));
                }
                if out.len() + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                let start = out.len() - last_offset;
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
                literals = r.read_bit()? == 0;
                continue;
            }
        }

        // COPY_FROM_NEW_OFFSET.
        let v = r.read_byte()? as usize;
        let offset = if v & 1 != 0 {
            let i = r.read_byte()? as usize;
            32512i64 - ((i & 254) * 128) as i64 - (v & 254) as i64 - (i & 1) as i64
        } else {
            128 - (v / 2) as i64
        };
        if offset <= 0 {
            // EOF marker: the reference decoder requires the input to be
            // fully consumed at this point.
            if r.pos != input.len() {
                return Err(Error::InvalidData("zx1: trailing data after end"));
            }
            return Ok(out);
        }
        last_offset = offset as usize;
        let len = r.elias()? as usize + 1;
        if last_offset > out.len() {
            return Err(Error::InvalidData("zx1: bad match offset"));
        }
        if out.len() + len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        let start = out.len() - last_offset;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
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

/// Encode data as a ZX1 stream (forward mode).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX1 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        // The ZX1 format cannot represent an empty output (the opening
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
                if dist <= 128 {
                    w.write_byte((256 - 2 * dist) as u8);
                } else {
                    let m = dist - 1;
                    w.write_byte((255 - (m & 254)) as u8);
                    w.write_byte((252 - (m >> 8) * 2 + (dist & 1)) as u8);
                }
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

    // End marker: new-offset indicator + offset bytes decoding to <= 0.
    w.write_bit(true);
    w.write_byte(0xff);
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
        // Distance > 128 forces the two-byte offset form.
        let mut data = vec![b'x'; 200];
        data.extend_from_slice(b"0123456789abcdef");
        data.extend_from_slice(&[0u8; 200]);
        data.extend_from_slice(b"0123456789abcdef");
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
            c[i] = 0xff;
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
        // Large offset exercise: reuse a pattern beyond 128 bytes back.
        let mut far = vec![0u8; 300];
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        far.extend_from_slice(&[1u8; 100]);
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        rt(&far);
    }
}
