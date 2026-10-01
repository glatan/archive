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
//! Streams produced with the `+N` prefix option can be decoded via
//! [`decode_with_prefix`], which lets match offsets reach into
//! caller-supplied external history; [`encode_with_prefix`] produces
//! such streams.
//!
//! Backwards (`-b`) mode is outside the current scope.

use alloc::vec;
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
    decode_impl(input, &[], max_output)
}

/// Decode a ZX1 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX)
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

fn decode_impl(input: &[u8], prefix: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
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
                copy_match(
                    prefix,
                    &mut out,
                    last_offset,
                    len,
                    max_output,
                    "zx1: offset before start",
                )?;
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
        copy_match(
            prefix,
            &mut out,
            last_offset,
            len,
            max_output,
            "zx1: bad match offset",
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

/// Encode data as a ZX1 stream (forward mode).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX1 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[])
}

/// Encode data as a ZX1 stream whose match offsets may reach into
/// `prefix`, external history logically prepended to the input (the
/// upstream `+N` prefix option). The result must be decoded with
/// [`decode_with_prefix`] using the same `prefix`.
pub fn encode_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix)
}

fn encode_impl(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        // The ZX1 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Vec::new();
    }

    // Offsets are measured over the virtual history `prefix ++ input`,
    // matching how decode_with_prefix resolves them: a distance `d` at the
    // current output position copies from `d` bytes back, which reaches
    // into `prefix` when `d` exceeds the bytes emitted so far.
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
    for p in 0..base.min(hist_len.saturating_sub(MIN_MATCH - 1)) {
        let h = (((at(p) as usize) << 8) ^ ((at(p + 1) as usize) << 4) ^ at(p + 2) as usize)
            & ((1 << 15) - 1);
        head[h] = p as i32;
    }

    while pos < hist_len {
        // Search for a match at pos.
        let mut best: Option<(usize, usize)> = None;
        if pos + MIN_MATCH <= hist_len {
            let h =
                (((at(pos) as usize) << 8) ^ ((at(pos + 1) as usize) << 4) ^ at(pos + 2) as usize)
                    & ((1 << 15) - 1);
            let cand = head[h];
            head[h] = pos as i32;
            // The stream must open with a literal block of length >= 1, so
            // no match may start at the very first output position.
            if cand >= 0 && !(first_block && pos == lit_start) {
                let c = cand as usize;
                let dist = pos - c;
                if dist <= MAX_OFFSET
                    && at(c) == at(pos)
                    && at(c + 1) == at(pos + 1)
                    && at(c + 2) == at(pos + 2)
                {
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
                w.write_elias(lit_len);
                for i in lit_start..pos {
                    w.write_byte(at(i));
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
    let lit_len = hist_len - lit_start;
    if lit_len > 0 {
        if !first_block {
            w.write_bit(false);
        }
        w.write_elias(lit_len);
        for i in lit_start..hist_len {
            w.write_byte(at(i));
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

    fn rt_prefix(data: &[u8], prefix: &[u8]) {
        let enc = encode_with_prefix(data, prefix);
        assert_eq!(decode_with_prefix(&enc, prefix).unwrap(), data);
    }

    #[test]
    fn encode_with_prefix_uses_prefix_match() {
        // The input opens with a literal byte (the first block is always a
        // literal) followed by bytes that only occur inside the prefix, so
        // the match must reach back into the external history.
        let prefix = b"0123456789abcdef";
        let mut input = b"Z".to_vec();
        input.extend_from_slice(prefix);
        input.extend_from_slice(b" tail tail tail");

        let enc = encode_with_prefix(&input, prefix);
        assert_eq!(decode_with_prefix(&enc, prefix).unwrap(), input);
        // Using the prefix dictionary must beat plain encoding here.
        assert!(enc.len() < encode(&input).len());
    }

    #[test]
    fn encode_with_prefix_first_block_stays_literal() {
        // Input starts exactly with prefix content: a match at position 0
        // is not representable, so the encoder must emit a leading literal
        // before matching into the prefix.
        let prefix = b"abcdefghij";
        let mut input = prefix.to_vec();
        input.extend_from_slice(b"XYZ");
        input.extend_from_slice(prefix);
        rt_prefix(&input, prefix);
    }

    #[test]
    fn encode_with_prefix_roundtrip() {
        rt_prefix(b"hello hello hello", b"prefix data");
        rt_prefix(b"aaaaaaaaaaaaaaaaaaaa", b"aaaa");
        // Match crossing the prefix/output boundary plus rep-offset reuse.
        let prefix = b"the quick brown fox jumps over the lazy dog. ";
        let mut input = b"!".to_vec();
        for _ in 0..4 {
            input.extend_from_slice(prefix);
        }
        input.extend_from_slice(b"0123456789");
        rt_prefix(&input, prefix);
        // Larger binary input with a sizeable dictionary.
        let dict: Vec<u8> = (0u16..1000).flat_map(|i| i.to_le_bytes()).collect();
        let mut binary = dict[1500..1800].to_vec();
        for i in 0..2000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        binary.extend_from_slice(&dict[0..300]);
        rt_prefix(&binary, &dict);
    }

    #[test]
    fn encode_with_empty_prefix_matches_encode() {
        let data = b"abcabcabc---abcabcabc";
        assert_eq!(encode_with_prefix(data, b""), encode(data));
        assert_eq!(encode_with_prefix(b"", b"prefix"), Vec::<u8>::new());
    }

    #[test]
    fn encode_with_prefix_stream_needs_prefix() {
        // Decoding a prefix-compressed stream without the prefix must not
        // silently produce the original data.
        let prefix = b"0123456789abcdef";
        let mut input = b"Z".to_vec();
        input.extend_from_slice(prefix);
        let enc = encode_with_prefix(&input, prefix);
        if let Ok(v) = decode(&enc) {
            assert_ne!(v, input);
        }
    }

    #[test]
    fn decode_prefix_history() {
        // literal 'a', then a distance-6 len-3 match reaching into the
        // 5-byte prefix "HELLO", then EOF. Distance 6 uses the 1-byte
        // offset form: byte = 256 - 2*6 = 0xf4.
        let stream = [0x64, b'a', 0xf4, 0xff, 0xff];
        assert!(decode(&stream).is_err());
        assert_eq!(decode_with_prefix(&stream, b"HELLO").unwrap(), b"aHEL");
    }

    #[test]
    fn decode_prefix_match_crosses_boundary() {
        // literal 'a', distance 3 len 4: the match starts in the 2-byte
        // prefix and continues into produced output.
        //   bits: elias(1)=`0` | 'a' | `1` newoff | 0xfa |
        //         len elias(3)=`1`,`1`,`0` | `1` EOF | 0xff 0xff
        let stream = [0x74, b'a', 0xfa, 0xff, 0xff];
        assert_eq!(decode_with_prefix(&stream, b"AB").unwrap(), b"aABaA");
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
