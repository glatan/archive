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
//! it when reading the length. In forward streams it is `1` when
//! `len <= 2` (the forward terminator); in backwards streams it is `1`
//! when `len > 2` (the backwards continuation bit). Offset MSB value 256
//! is the EOF marker.
//!
//! The classic v1 format (`-c`) is supported via [`decode_classic`] and
//! [`encode_classic`]: its only wire difference is that the offset-MSB
//! Elias gamma data bits are stored non-inverted. Streams produced with
//! the `+N` prefix option can be decoded via [`decode_with_prefix`], which
//! lets match offsets reach into caller-supplied external history;
//! [`encode_with_prefix`] emits such streams. The `-q` quick mode only
//! constrains the encoder (offsets <= 2176, the ZX7 limit);
//! [`encode_quick`] emits such streams and they decode with
//! [`decode`].
//!
//! The backwards variant (`-b`) is supported via [`decode_backwards`]
//! and [`encode_backwards`]: the stream is the byte-reversed image of a
//! stream written with mirrored Elias gamma coding (continuation bit
//! `1`, terminator `0`), a non-inverted offset-MSB elias, and an
//! offset-LSB byte of `(off-1)%256`. [`decode_backwards_with_suffix`]
//! and [`encode_backwards_with_suffix`] cover the `-b +N` combination,
//! where the last `N` bytes of the uncompressed input serve as trailing
//! match history. Upstream `-c -b` is byte-identical to `-b` (the invert
//! flag applies to neither: `invert_mode = !classic && !backwards`), so
//! no separate classic-backwards API exists. The `-q` constraint also
//! applies to backwards streams; [`encode_backwards_quick`] emits them.
//! Upstream has no `-i` inverted variant.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Largest encodable offset (ZX5 v2 limit).
const MAX_OFFSET: usize = 65280;
/// Largest encodable offset in `-q` quick mode (the ZX7 limit).
const MAX_OFFSET_QUICK: usize = 2176;
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

    /// Interlaced Elias gamma. `first` substitutes the initial bit when
    /// it was already emitted in the stream (the `*` bit of a new-offset
    /// block). `inverted` flips the stored data bits (v2 offset-MSB
    /// elias); `backwards` swaps the coding polarity to continuation bit
    /// `1` and terminator `0` (the upstream `-b` mode).
    fn elias(&mut self, first: Option<u32>, inverted: bool, backwards: bool) -> Result<u32, Error> {
        let mut value = 1u32;
        let mut first = first;
        loop {
            let bit = match first.take() {
                Some(b) => b,
                None => self.read_bit()?,
            };
            if bit != backwards as u32 {
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
    decode_impl(input, &[], max_output, true, false)
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
    decode_impl(input, &[], max_output, false, false)
}

/// Decode a ZX5 v2 stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `+N` prefix option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, true, false)
}

/// Decode a ZX5 v1 (`-c` classic) stream with a `prefix` history as in
/// [`decode_with_prefix`].
pub fn decode_classic_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX, false, false)
}

/// Decode a ZX5 `-b` backwards stream.
///
/// A backwards stream is the byte-reversed image of a stream written
/// with mirrored Elias gamma coding (continuation bit `1`, terminator
/// `0`), a non-inverted offset-MSB elias, and an offset-LSB byte of
/// `(off-1)%256`; decoding reverses the input, applies the backwards
/// block format, then reverses the produced output.
pub fn decode_backwards(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_backwards_bounded(input, usize::MAX)
}

/// Decode a ZX5 `-b` backwards stream with an output size limit.
pub fn decode_backwards_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_backwards_impl(input, &[], max_output)
}

/// Decode a ZX5 `-b +N` backwards stream: `suffix` is the trailing
/// history in original data order (the last `N` bytes of the
/// uncompressed input, which are not emitted) that match offsets may
/// reach into.
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
            let len = r.elias(None, false, backwards)? as usize;
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
                let len = r.elias(None, false, backwards)? as usize;
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
            let len = r.elias(None, false, backwards)? as usize;
            copy(&mut out, last1, len)?;
        } else {
            // COPY_FROM_NEW_OFFSET. v2 stores the offset-MSB elias data
            // bits inverted; v1 (classic) and the backwards variant store
            // them verbatim.
            let ahead = r.read_bit()?;
            last3 = last2;
            last2 = last1;
            let msb = r.elias(None, inverted_msb, backwards)? as usize;
            if msb == 256 {
                // EOF marker: the reference decoder requires the input to
                // be fully consumed at this point.
                if r.pos != input.len() {
                    return Err(Error::InvalidData("zx5: trailing data after end"));
                }
                return Ok(out);
            }
            // Forward streams store 255-(off-1)%256 while backwards
            // streams store (off-1)%256, so the reconstruction differs.
            let lsb = r.read_byte()? as usize;
            last1 = if backwards {
                (msb - 1) * 256 + lsb + 1
            } else {
                msb * 256 - lsb
            };
            let len = r.elias(Some(ahead), false, backwards)? as usize + 1;
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

    /// Interlaced Elias gamma: continuation bit `0` and terminator `1`
    /// in forward mode, swapped in `backwards` mode (the upstream `-b`
    /// mode); data bits optionally `inverted`.
    fn write_elias(&mut self, value: usize, inverted: bool, backwards: bool) {
        let mut i = 1usize;
        while i <= value {
            i <<= 1;
        }
        i >>= 1;
        while i > 1 {
            i >>= 1;
            self.write_bit(backwards);
            self.write_bit(((value & i) != 0) ^ inverted);
        }
        self.write_bit(!backwards);
    }

    /// Emit `elias(value)` minus its leading bit, which was already written
    /// as the `*` bit of a new-offset block (in forward mode the `*` bit
    /// is `value <= 1`, i.e. the terminator when the elias is a single
    /// bit; in backwards mode it is `value > 1`, i.e. the continuation
    /// bit when the elias has data bits).
    fn write_elias_tail(&mut self, value: usize, inverted: bool, backwards: bool) {
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
            self.write_bit(backwards);
            self.write_bit(((value & j) != 0) ^ inverted);
        }
        self.write_bit(!backwards);
    }
}

/// Encode data as a ZX5 stream (forward v2 mode).
///
/// The encoder uses greedy single-candidate matching; the emitted stream is
/// valid ZX5 but does not aim to match the reference compressor's optimal
/// parsing output.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], true, false, MAX_OFFSET)
}

/// Encode data as a ZX5 v1 (`-c` classic) stream.
///
/// The only wire difference from [`encode`] (v2) is that the offset-MSB
/// Elias gamma data bits are stored non-inverted. Decode with
/// [`decode_classic`].
pub fn encode_classic(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], false, false, MAX_OFFSET)
}

/// Encode data as a ZX5 v2 stream with the `-q` quick-mode constraint:
/// match offsets are limited to 2176 (the ZX7 limit). The wire format
/// is unchanged; decode with [`decode`].
pub fn encode_quick(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], true, false, MAX_OFFSET_QUICK)
}

/// Encode data as a ZX5 v2 stream whose match offsets may reach into
/// `prefix`, external history logically prepended to the input (the
/// upstream `+N` prefix option). Decode with [`decode_with_prefix`].
pub fn encode_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix, true, false, MAX_OFFSET)
}

/// Encode data as a ZX5 v1 (`-c` classic) stream with a `prefix`
/// history as in [`encode_with_prefix`]. Decode with
/// [`decode_classic_with_prefix`].
pub fn encode_classic_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix, false, false, MAX_OFFSET)
}

/// Encode data as a ZX5 `-b` backwards stream.
///
/// Produces the byte-reversed image of a stream using mirrored Elias
/// gamma coding (continuation bit `1`, terminator `0`), a non-inverted
/// offset-MSB elias, and an offset-LSB byte of `(off-1)%256`; decode
/// with [`decode_backwards`]. As with [`encode`], the emitted parsing
/// is greedy rather than optimal.
pub fn encode_backwards(input: &[u8]) -> Vec<u8> {
    encode_backwards_impl(input, &[], MAX_OFFSET)
}

/// Encode data as a ZX5 `-b` backwards stream with the `-q` quick-mode
/// constraint: match offsets are limited to 2176 (the ZX7 limit). The
/// wire format is unchanged; decode with [`decode_backwards`].
pub fn encode_backwards_quick(input: &[u8]) -> Vec<u8> {
    encode_backwards_impl(input, &[], MAX_OFFSET_QUICK)
}

/// Encode data as a ZX5 `-b +N` backwards stream: `suffix` is trailing
/// history in original data order that match offsets may reach into
/// but that is never emitted. Decode with
/// [`decode_backwards_with_suffix`] passing the same `suffix`.
pub fn encode_backwards_with_suffix(input: &[u8], suffix: &[u8]) -> Vec<u8> {
    // In the reversed stream order the original suffix becomes leading
    // history.
    let prefix: Vec<u8> = suffix.iter().rev().copied().collect();
    encode_backwards_impl(input, &prefix, MAX_OFFSET)
}

fn encode_backwards_impl(input: &[u8], prefix: &[u8], max_offset: usize) -> Vec<u8> {
    // Encode the reversed payload over the reversed-order history
    // (prefix == rev(suffix)), then reverse the produced stream.
    let rev_input: Vec<u8> = input.iter().rev().copied().collect();
    let mut out = encode_impl(&rev_input, prefix, false, true, max_offset);
    out.reverse();
    out
}

/// `prefix` is external history logically prepended to `input`: matches
/// may copy from it using normal wire offsets, as `decode_with_prefix`
/// expects. Match positions are tracked in the virtual `prefix ++ input`
/// coordinate space.
fn encode_impl(
    input: &[u8],
    prefix: &[u8],
    inverted_msb: bool,
    backwards: bool,
    max_offset: usize,
) -> Vec<u8> {
    if input.is_empty() {
        // The ZX5 format cannot represent an empty output (the opening
        // literal block requires a length >= 1); emit an empty stream which
        // decode() maps back to empty output.
        return Vec::new();
    }

    let plen = prefix.len();
    // Byte at virtual position `v` of the `prefix ++ input` history.
    let byte_at = |v: usize| -> u8 { if v < plen { prefix[v] } else { input[v - plen] } };
    let hash = |v: usize| -> usize {
        (((byte_at(v) as usize) << 8) ^ ((byte_at(v + 1) as usize) << 4) ^ byte_at(v + 2) as usize)
            & ((1 << 15) - 1)
    };

    let mut w = BitWriter::new();
    let mut head = vec![-1i32; 1 << 15];
    // Seed the matcher with the prefix history so matches can reach
    // into it via normal wire offsets.
    let mut v = 0usize;
    while v < plen && v + MIN_MATCH <= plen + input.len() {
        head[hash(v)] = v as i32;
        v += 1;
    }
    let mut last1 = 1usize;
    let mut last2 = 0usize;
    let mut last3 = 0usize;
    let mut lit_start = 0usize;
    let mut pos = 0usize;
    let mut first_block = true;
    let mut after_literals = false;

    while pos < input.len() {
        // Search for a match at pos (virtual position plen + pos).
        let pos_v = plen + pos;
        let mut best: Option<(usize, usize)> = None;
        if pos + MIN_MATCH <= input.len() {
            let h = hash(pos_v);
            let cand = head[h];
            head[h] = pos_v as i32;
            if cand >= 0 {
                let c = cand as usize;
                let dist = pos_v - c;
                if dist <= max_offset
                    && byte_at(c) == byte_at(pos_v)
                    && byte_at(c + 1) == byte_at(pos_v + 1)
                {
                    let mut len = MIN_MATCH;
                    while pos + len < input.len() && byte_at(c + len) == byte_at(pos_v + len) {
                        len += 1;
                    }
                    best = Some((len, dist));
                }
            }
        }

        if let Some((len, dist)) = best {
            // Flush pending literals first.
            let lit_len = pos - lit_start;
            if lit_len == 0 && first_block {
                // The stream must open with a literal block of length
                // >= 1, so a match at position 0 cannot be emitted;
                // the byte is emitted as a literal instead.
                pos += 1;
                continue;
            }
            if lit_len > 0 || first_block {
                debug_assert!(lit_len > 0); // first match implies >=1 literal
                if !first_block {
                    w.write_bit(false); // literal indicator after a match
                }
                w.write_elias(lit_len, false, backwards);
                for &b in &input[lit_start..pos] {
                    w.write_byte(b);
                }
                first_block = false;
                after_literals = true;
            }

            if after_literals && dist == last1 {
                // Copy from last offset (only valid right after literals).
                w.write_bit(false);
                w.write_elias(len, false, backwards);
            } else {
                // Other-offsets group (valid after literals and after copies).
                w.write_bit(true);
                if dist == last2 {
                    w.write_bit(false);
                    w.write_bit(false);
                    w.write_elias(len, false, backwards);
                    core::mem::swap(&mut last1, &mut last2);
                } else if dist == last3 {
                    w.write_bit(false);
                    w.write_bit(true);
                    w.write_elias(len, false, backwards);
                    last3 = last2;
                    last2 = last1;
                    last1 = dist;
                } else {
                    w.write_bit(true);
                    // `*` bit: first bit of elias(len-1). Forward stores
                    // the terminator for len <= 2; backwards stores the
                    // continuation bit for len > 2 (upstream:
                    // write_bit((len > 2) == backwards_mode)).
                    w.write_bit((len > 2) == backwards);
                    w.write_elias((dist - 1) / 256 + 1, inverted_msb, backwards);
                    if backwards {
                        w.write_byte(((dist - 1) % 256) as u8);
                    } else {
                        w.write_byte((255 - (dist - 1) % 256) as u8);
                    }
                    w.write_elias_tail(len - 1, false, backwards);
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
        w.write_elias(lit_len, false, backwards);
        for &b in &input[lit_start..] {
            w.write_byte(b);
        }
    }

    // End marker: other-offsets indicator + new-offset + `*` + elias(256).
    w.write_bit(true);
    w.write_bit(true);
    w.write_bit(false);
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

    /// Build a stream: one literal block `lits`, one new-offset match
    /// (`dist`, `len`), then EOF. `inverted` selects the v2 (true) vs
    /// v1 classic (false) offset-MSB elias coding; `backwards` selects
    /// the `-b` polarity/LSB conventions. The result is in internal
    /// (forward byte) order; a `-b` stream on disk is its byte reverse.
    fn match_stream(
        lits: &[u8],
        dist: usize,
        len: usize,
        inverted: bool,
        backwards: bool,
    ) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_elias(lits.len(), false, backwards);
        for &b in lits {
            w.write_byte(b);
        }
        w.write_bit(true); // other-offsets group
        w.write_bit(true); // new offset
        w.write_bit((len > 2) == backwards); // `*`: first bit of elias(len - 1)
        w.write_elias((dist - 1) / 256 + 1, inverted, backwards);
        if backwards {
            w.write_byte(((dist - 1) % 256) as u8);
        } else {
            w.write_byte((255 - (dist - 1) % 256) as u8);
        }
        w.write_elias_tail(len - 1, false, backwards);
        w.write_bit(true); // EOF: other-offsets, new-offset, `*` = 0
        w.write_bit(true);
        w.write_bit(false);
        w.write_elias(256, inverted, backwards);
        w.out
    }

    /// Decode `stream`, returning every match offset it references in
    /// emission order. Mirrors `decode_impl`'s offset bookkeeping so
    /// tests can inspect which offsets an encoder emitted. `inverted`
    /// selects the v2 (true) vs v1 classic (false) offset-MSB elias,
    /// `backwards` the `-b` polarity/LSB conventions.
    fn used_offsets(stream: &[u8], inverted: bool, backwards: bool) -> Vec<usize> {
        let mut offsets = Vec::new();
        if stream.is_empty() {
            return offsets;
        }
        let mut r = BitReader::new(stream);
        let mut last1 = 1usize;
        let mut last2 = 0usize;
        let mut last3 = 0usize;
        let mut literals = true;
        loop {
            if literals {
                let len = r.elias(None, false, backwards).unwrap() as usize;
                for _ in 0..len {
                    r.read_byte().unwrap();
                }
                if r.read_bit().unwrap() == 0 {
                    r.elias(None, false, backwards).unwrap();
                    offsets.push(last1);
                    literals = r.read_bit().unwrap() == 0;
                    continue;
                }
            }
            if r.read_bit().unwrap() == 0 {
                if r.read_bit().unwrap() == 0 {
                    core::mem::swap(&mut last1, &mut last2);
                } else {
                    let o3 = last3;
                    last3 = last2;
                    last2 = last1;
                    last1 = o3;
                }
                r.elias(None, false, backwards).unwrap();
                offsets.push(last1);
            } else {
                let ahead = r.read_bit().unwrap();
                last3 = last2;
                last2 = last1;
                let msb = r.elias(None, inverted, backwards).unwrap() as usize;
                if msb == 256 {
                    return offsets;
                }
                let lsb = r.read_byte().unwrap() as usize;
                last1 = if backwards {
                    (msb - 1) * 256 + lsb + 1
                } else {
                    msb * 256 - lsb
                };
                r.elias(Some(ahead), false, backwards).unwrap();
                offsets.push(last1);
            }
            literals = r.read_bit().unwrap() == 0;
        }
    }

    fn rt_classic(data: &[u8]) {
        let enc = encode_classic(data);
        assert_eq!(decode_classic(&enc).unwrap(), data);
        assert_eq!(decode_classic_bounded(&enc, data.len()).unwrap(), data);
    }

    #[test]
    fn encode_classic_roundtrip() {
        rt_classic(b"");
        rt_classic(b"a");
        rt_classic(b"ab");
        rt_classic(b"abcabcabc");
        rt_classic(b"aaaaaaaaaaaaaaaaaaaa");
        rt_classic(b"hello world hello world hello world");
        rt_classic(&[0u8; 2000]);
        // Alternating patterns exercise the 2nd/3rd-last offset blocks.
        let mut alt = Vec::new();
        for _ in 0..12 {
            alt.extend_from_slice(b"ABCDEFGH");
            alt.extend_from_slice(b"12345678");
            alt.extend_from_slice(b"abcdefgh");
        }
        rt_classic(&alt);
        // Distance > 255 forces a multi-bit offset MSB where the v1/v2
        // elias encodings actually differ.
        let mut far = vec![0u8; 300];
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        far.extend_from_slice(&[1u8; 300]);
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        rt_classic(&far);
        assert_eq!(encode_classic(b""), Vec::<u8>::new());
    }

    #[test]
    fn encode_classic_wire_format() {
        // Known vector: literal 'A' + EOF marker. v1 stores the eight
        // offset-MSB elias data bits verbatim; v2 inverts them.
        assert_eq!(encode_classic(b"A"), [0xe0, b'A', 0x00, 0x08]);
        assert_eq!(encode(b"A"), [0xe5, b'A', 0x55, 0x58]);
        // The EOF elias(256) has 8 data bits (all zero -> all ones when
        // inverted), so v1/v2 streams differ even when every offset MSB
        // is 1.
        assert_ne!(encode_classic(b"abcabcabc"), encode(b"abcabcabc"));
        // Cross-decoding fails: the EOF marker resolves to MSB 511.
        assert!(decode(&encode_classic(b"abcabcabc")).is_err());
        assert!(decode_classic(&encode(b"abcabcabc")).is_err());
    }

    #[test]
    fn encode_quick_roundtrip() {
        let rt_quick = |data: &[u8]| {
            assert_eq!(decode(&encode_quick(data)).unwrap(), data);
            // Same cap under the v1 wire.
            assert_eq!(
                decode_classic(&encode_impl(data, &[], false, false, MAX_OFFSET_QUICK)).unwrap(),
                data
            );
        };
        rt_quick(b"");
        rt_quick(b"a");
        rt_quick(b"ab");
        rt_quick(b"abcabcabc");
        rt_quick(b"aaaaaaaaaaaaaaaaaaaa");
        rt_quick(&[0u8; 2000]);
        let mut text = Vec::new();
        for _ in 0..150 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt_quick(&text);
        assert_eq!(encode_quick(b""), Vec::<u8>::new());
    }

    #[test]
    fn encode_quick_caps_offsets() {
        // A block repeated just beyond the quick limit: the default
        // encoder uses a match there, the quick encoder cannot.
        let mut data = Vec::new();
        data.extend_from_slice(b"FAR-APART-REPEATED-BLOCK-0123456789");
        data.extend_from_slice(&[0u8; 3000]);
        data.extend_from_slice(b"FAR-APART-REPEATED-BLOCK-0123456789");

        let normal = encode(&data);
        let quick = encode_quick(&data);
        assert_eq!(decode(&normal).unwrap(), data);
        assert_eq!(decode(&quick).unwrap(), data);

        let normal_offsets = used_offsets(&normal, true, false);
        assert!(normal_offsets.iter().any(|&o| o > MAX_OFFSET_QUICK));
        assert!(normal_offsets.iter().all(|&o| o <= MAX_OFFSET));
        assert!(
            used_offsets(&quick, true, false)
                .iter()
                .all(|&o| o <= MAX_OFFSET_QUICK)
        );
        // Forfeiting the far match costs bytes.
        assert!(quick.len() > normal.len());

        // The cap also holds for the classic v1 wire variant.
        let quick_classic = encode_impl(&data, &[], false, false, MAX_OFFSET_QUICK);
        assert_eq!(decode_classic(&quick_classic).unwrap(), data);
        assert!(
            used_offsets(&quick_classic, false, false)
                .iter()
                .all(|&o| o <= MAX_OFFSET_QUICK)
        );
    }

    #[test]
    fn encode_with_prefix_roundtrip() {
        // The repeated block occurs only in the prefix: the emitted
        // match offset must reach into the external history.
        let prefix = b"HELLO-PREFIX-DATA-0123456789";
        let input = b"xHELLO-PREFIX-DATA-0123456789!";
        let enc = encode_with_prefix(input, prefix);
        assert_eq!(decode_with_prefix(&enc, prefix).unwrap(), input);
        assert_eq!(used_offsets(&enc, true, false), [prefix.len() + 1]);
        // Reusing the prefix history saves bytes vs standalone encoding.
        assert!(enc.len() < encode(input).len());
        // Without the prefix the offset exceeds the produced output.
        assert!(decode(&enc).is_err());
    }

    #[test]
    fn encode_with_prefix_various() {
        let rt_prefix = |input: &[u8], prefix: &[u8]| {
            let enc = encode_with_prefix(input, prefix);
            assert_eq!(decode_with_prefix(&enc, prefix).unwrap(), input);
        };
        // Match crossing the prefix/output boundary (overlapping copy).
        rt_prefix(b"aABaAB", b"AB");
        rt_prefix(b"abcabcabc", b"abcabc");
        // Input that repeats the whole prefix; the match crosses the
        // prefix/output boundary for its second half.
        rt_prefix(b"hello world hello world", b"hello world ");
        // Far prefix match: distance > 255 exercises the multi-bit
        // offset MSB into the prefix region.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(b"FAR-PREFIX-BLOCK");
        prefix.extend_from_slice(&[7u8; 600]);
        let mut input = b"z".to_vec();
        input.extend_from_slice(b"FAR-PREFIX-BLOCK");
        rt_prefix(&input, &prefix);
        let enc = encode_with_prefix(&input, &prefix);
        assert!(used_offsets(&enc, true, false).iter().any(|&o| o > 256));
        // Larger mixed data.
        let mut prefix = Vec::new();
        let mut input = Vec::new();
        for i in 0..40u32 {
            prefix.extend_from_slice(&i.to_le_bytes());
        }
        input.extend_from_slice(&prefix[20..80]);
        input.extend_from_slice(b"unique-tail-data");
        input.extend_from_slice(&prefix[..60]);
        rt_prefix(&input, &prefix);
        // Empty input still yields an empty stream.
        assert_eq!(encode_with_prefix(b"", b"prefix"), Vec::<u8>::new());
        assert_eq!(decode_with_prefix(&[], b"prefix").unwrap(), b"");
    }

    #[test]
    fn encode_with_prefix_empty_prefix() {
        // An empty prefix must produce exactly the standalone encoding.
        for data in [
            &b"a"[..],
            b"abcabcabc",
            b"aaaaaaaaaaaaaaaaaaaa",
            b"hello world hello world hello world",
        ] {
            assert_eq!(encode_with_prefix(data, b""), encode(data));
            assert_eq!(encode_classic_with_prefix(data, b""), encode_classic(data));
        }
    }

    #[test]
    fn encode_classic_with_prefix_roundtrip() {
        let prefix = b"HELLO-PREFIX-DATA-0123456789";
        let input = b"xHELLO-PREFIX-DATA-0123456789!";
        let enc = encode_classic_with_prefix(input, prefix);
        assert_eq!(decode_classic_with_prefix(&enc, prefix).unwrap(), input);
        assert_eq!(used_offsets(&enc, false, false), [prefix.len() + 1]);
        assert!(decode_classic(&enc).is_err());
        // The v2 wire decodes it differently / rejects it.
        assert!(decode_with_prefix(&enc, prefix).is_err());
    }

    #[test]
    fn decode_classic_v1() {
        // dist 257 -> offset MSB 2, so the elias carries a data bit and
        // the v1/v2 encodings differ.
        let lits: Vec<u8> = (0..260u16).map(|i| i as u8).collect();
        let v1 = match_stream(&lits, 257, 6, false, false);
        let v2 = match_stream(&lits, 257, 6, true, false);
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

    fn rt_backwards(data: &[u8]) {
        let enc = encode_backwards(data);
        assert_eq!(decode_backwards(&enc).unwrap(), data);
        assert_eq!(decode_backwards_bounded(&enc, data.len()).unwrap(), data);
        if data.is_empty() {
            assert_eq!(enc, Vec::<u8>::new());
        }
    }

    #[test]
    fn encode_backwards_roundtrip() {
        rt_backwards(b"");
        rt_backwards(b"a");
        rt_backwards(b"ab");
        rt_backwards(b"abcabcabc");
        rt_backwards(b"aaaaaaaaaaaaaaaaaaaa");
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
        // Alternating patterns exercise the 2nd/3rd-last offset blocks.
        let mut alt = Vec::new();
        for _ in 0..12 {
            alt.extend_from_slice(b"ABCDEFGH");
            alt.extend_from_slice(b"12345678");
            alt.extend_from_slice(b"abcdefgh");
        }
        rt_backwards(&alt);
        // Distance > 255 forces a multi-bit offset MSB.
        let mut far = vec![0u8; 300];
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        far.extend_from_slice(&[1u8; 300]);
        far.extend_from_slice(b"PATTERN-AT-DISTANCE");
        rt_backwards(&far);
    }

    #[test]
    fn encode_backwards_wire_format() {
        // The backwards stream is the byte-reversed image of the
        // internal forward-order stream, and never inverts the
        // offset-MSB elias data bits (upstream: `-c -b` == `-b`).
        let data = b"abcabcabcabcabcabc";
        let rev: Vec<u8> = data.iter().rev().copied().collect();
        let mut expect = encode_impl(&rev, &[], false, true, MAX_OFFSET);
        expect.reverse();
        assert_eq!(encode_backwards(data), expect);
        // The two wire flavors do not decode each other's streams to
        // the original data.
        if let Ok(out) = decode(&encode_backwards(data)) {
            assert_ne!(out, data);
        }
        if let Ok(out) = decode_backwards(&encode(data)) {
            assert_ne!(out, data);
        }
    }

    #[test]
    fn encode_backwards_quick_roundtrip() {
        let rt_quick = |data: &[u8]| {
            let enc = encode_backwards_quick(data);
            assert_eq!(decode_backwards(&enc).unwrap(), data);
        };
        rt_quick(b"a");
        rt_quick(b"abcabcabc");
        rt_quick(&[0u8; 2000]);
        let mut text = Vec::new();
        for _ in 0..150 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt_quick(&text);

        // A repeat just beyond the quick limit: the default encoder uses
        // the match, the quick encoder cannot. Offsets are inspected on
        // the internal forward-order stream (the byte reverse).
        let mut data = Vec::new();
        data.extend_from_slice(b"FAR-APART-REPEATED-BLOCK-0123456789");
        data.extend_from_slice(&[0u8; 3000]);
        data.extend_from_slice(b"FAR-APART-REPEATED-BLOCK-0123456789");
        let normal = encode_backwards(&data);
        let quick = encode_backwards_quick(&data);
        assert_eq!(decode_backwards(&normal).unwrap(), data);
        assert_eq!(decode_backwards(&quick).unwrap(), data);
        let rev = |s: &[u8]| s.iter().rev().copied().collect::<Vec<u8>>();
        assert!(
            used_offsets(&rev(&normal), false, true)
                .iter()
                .any(|&o| o > MAX_OFFSET_QUICK)
        );
        assert!(
            used_offsets(&rev(&quick), false, true)
                .iter()
                .all(|&o| o <= MAX_OFFSET_QUICK)
        );
        assert!(quick.len() > normal.len());
    }

    #[test]
    fn decode_backwards_len2_match() {
        // len = 2 exercises the `*` = 0 path of the backwards new-offset
        // block: `*` is the backwards elias terminator, so elias(len-1)
        // ends immediately and len = 2.
        let mut stream = match_stream(b"abcd", 3, 2, false, true);
        stream.reverse();
        // Internal decode produces "abcd" + copy of "bc" = "abcdbc";
        // the backwards output is its reverse.
        assert_eq!(decode_backwards(&stream).unwrap(), b"cbdcba");
        // The same match with len = 3 uses `*` = 1 (continuation).
        let mut stream3 = match_stream(b"abcd", 3, 3, false, true);
        stream3.reverse();
        assert_eq!(decode_backwards(&stream3).unwrap(), b"dcbdcba");
    }

    #[test]
    fn backwards_suffix_history() {
        // input's tail reversed spells the suffix, so the encoder can
        // emit a match reaching into the reversed-suffix history.
        let suffix = b"XYZ";
        let input = b"aaaXYZZ";
        let enc = encode_backwards_with_suffix(input, suffix);
        assert!(decode_backwards(&enc).is_err());
        assert_eq!(
            decode_backwards_with_suffix(&enc, suffix).unwrap(),
            input.as_slice()
        );
        // A wrong suffix is either rejected or yields wrong bytes.
        if let Ok(out) = decode_backwards_with_suffix(&enc, b"123") {
            assert_ne!(out, input);
        }

        // Roundtrip over a larger payload.
        let mut input2 = Vec::new();
        for _ in 0..40 {
            input2.extend_from_slice(b"the quick brown fox ");
        }
        let suffix2: Vec<u8> = input2[input2.len() - 30..].to_vec();
        let enc2 = encode_backwards_with_suffix(&input2[..input2.len() - 30], &suffix2);
        let dec2 = decode_backwards_with_suffix(&enc2, &suffix2).unwrap();
        assert_eq!(dec2, &input2[..input2.len() - 30]);
    }

    #[test]
    fn decode_backwards_rejects() {
        // Empty input decodes to empty output.
        assert_eq!(decode_backwards(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(encode_backwards(b""), Vec::<u8>::new());

        let enc = encode_backwards(b"hello hello hello hello");
        // Truncated stream (drops a byte the internal stream needs).
        assert!(decode_backwards(&enc[..enc.len() - 1]).is_err());
        // Trailing data after EOF in the internal stream = a leading
        // extra byte in the backwards stream.
        let mut c = Vec::new();
        c.push(0xaa);
        c.extend_from_slice(&enc);
        assert!(decode_backwards(&c).is_err());

        // `1 0 0` after the opening literal selects the 2nd last
        // offset, which is 0 before any new-offset block: invalid.
        // Internal stream: literal elias(1)=`0`, 'a', then bits
        // 1(other) 0(prev) 0(2nd) 0(elias term) packed as 0x40.
        let fwd = [0x40, b'a'];
        let mut bwd = fwd.to_vec();
        bwd.reverse();
        assert!(decode_backwards(&bwd).is_err());

        // Offset beyond produced output.
        let mut bwd = match_stream(b"ab", 300, 3, false, true);
        bwd.reverse();
        assert!(decode_backwards(&bwd).is_err());

        // Bounded decode.
        let data = vec![b'z'; 500];
        let enc = encode_backwards(&data);
        assert!(matches!(
            decode_backwards_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_backwards_bounded(&enc, 500).unwrap(), data);
    }
}
