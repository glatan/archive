//! LZSA compression (Emmanuel Marty, zlib license).
//!
//! Two layers:
//! - stream format: 3-byte header `7b 9e traits` (bits 7..5 = version:
//!   0 = LZSA1 blocks, 1 = LZSA2 blocks; bits 4..0 reserved), then frames
//!   of `DSZ0 DSZ1 DSZ2` where DSZ2 bit 7 marks a verbatim frame, bit 0 is
//!   compressed length bit 16, bits 1..6 reserved; a zero DSZ ends the
//!   stream. Each frame expands to at most 64 KiB and match offsets may
//!   reach into data produced by earlier frames.
//! - raw blocks (as produced by `lzsa -r`): a single LZSA1/LZSA2 command
//!   stream terminated by a dedicated EOD marker.
//!
//! Match offsets are stored negative (unexpressed high bits set): the
//! decoder computes a positive distance via `dist = (stored ^ mask) + 1`.
//! LZSA1 commands are `<O|LLL|MMMM>`; LZSA2 commands are `<XYZ|LL|MMM>`
//! with a shared nibble stream spanning the block.
//!
//! Streams produced with the upstream `-D` dictionary option (matches
//! reaching before the start of the decoded data) decode via
//! [`decode_with_prefix`]; raw-block equivalents are
//! [`decode_lzsa1_block_with_prefix`] and [`decode_lzsa2_block_with_prefix`].
//! [`encode_with_prefix`] and [`encode_lzsa2_with_prefix`] emit such
//! streams.
//!
//! The upstream backwards `-b` option applies only to raw blocks
//! (`-r`), never to the stream container, and is a pure byte-reversal
//! wrapper over the same block grammar: the compressed block is the
//! byte-reversed image of a forward block for the reversed input. See
//! [`decode_lzsa1_block_backwards`], [`decode_lzsa2_block_backwards`],
//! [`encode_lzsa1_block_backwards`] and [`encode_lzsa2_block_backwards`].

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

const MAGIC: [u8; 2] = [0x7b, 0x9e];

const L1_MIN_MATCH: usize = 3;
const L1_MAX_DIST: usize = 65536;
const L1_MAX_RUN: usize = 65535; // u16 literal/match length fields
const L2_MIN_MATCH: usize = 2;
const L2_MAX_DIST: usize = 65535;
const L2_MAX_RUN: usize = 65535;

/// Decode an LZSA stream (block variant selected by the traits byte).
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZSA stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_impl(input, &[], max_output)
}

/// Decode an LZSA stream whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `-D` dictionary option).
pub fn decode_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    decode_impl(input, prefix, usize::MAX)
}

fn decode_impl(input: &[u8], prefix: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() < 3 {
        return Err(Error::InvalidData("lzsa: truncated header"));
    }
    if input[0] != MAGIC[0] || input[1] != MAGIC[1] {
        return Err(Error::InvalidData("lzsa: bad signature"));
    }
    let traits = input[2];
    if traits & 0x1f != 0 {
        return Err(Error::InvalidData("lzsa: reserved trait bits set"));
    }
    let level2 = match traits >> 5 {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidData("lzsa: unknown block encoding")),
    };

    let mut out: Vec<u8> = Vec::new();
    let mut pos = 3usize;
    loop {
        if pos + 3 > input.len() {
            return Err(Error::InvalidData("lzsa: truncated frame header"));
        }
        let dsz = input[pos] as usize
            | ((input[pos + 1] as usize) << 8)
            | (((input[pos + 2] as usize) & 1) << 16);
        let uncompressed = input[pos + 2] & 0x80 != 0;
        if input[pos + 2] & 0x7e != 0 {
            return Err(Error::InvalidData("lzsa: reserved length bits set"));
        }
        pos += 3;
        if dsz == 0 {
            break;
        }
        if pos + dsz > input.len() {
            return Err(Error::InvalidData("lzsa: truncated block data"));
        }
        let block = &input[pos..pos + dsz];
        pos += dsz;
        if uncompressed {
            if out.len() + dsz > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            out.extend_from_slice(block);
        } else if level2 {
            decode_lzsa2_commands(block, &mut out, max_output, false, prefix)?;
        } else {
            decode_lzsa1_commands(block, &mut out, max_output, false, prefix)?;
        }
    }
    Ok(out)
}

/// Decode a raw LZSA1 block (terminated by the EOD marker).
pub fn decode_lzsa1_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa1_commands(input, &mut out, usize::MAX, true, &[])?;
    Ok(out)
}

/// Decode a raw LZSA1 block whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `-D` dictionary option).
pub fn decode_lzsa1_block_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa1_commands(input, &mut out, usize::MAX, true, prefix)?;
    Ok(out)
}

/// Decode a raw LZSA2 block (terminated by the EOD marker).
pub fn decode_lzsa2_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa2_commands(input, &mut out, usize::MAX, true, &[])?;
    Ok(out)
}

/// Decode a raw LZSA2 block whose match offsets may reach into `prefix`,
/// external history logically prepended to the output (the upstream
/// `-D` dictionary option).
pub fn decode_lzsa2_block_with_prefix(input: &[u8], prefix: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa2_commands(input, &mut out, usize::MAX, true, prefix)?;
    Ok(out)
}

/// Decode a raw LZSA1 block produced in backwards (`-b`) mode.
///
/// A backwards block is the byte-reversed image of the equivalent
/// forward block: undoing the reversal yields a standard LZSA1 command
/// stream whose decoded bytes are the original input reversed, so the
/// output is reversed back here. The wire format itself is unchanged,
/// so a backwards block is not valid input for [`decode_lzsa1_block`].
///
/// Upstream supports `-b` only for raw blocks (`-r`), never for the
/// `7b 9e` stream container.
pub fn decode_lzsa1_block_backwards(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_lzsa1_block_backwards_with_prefix(input, &[])
}

/// Decode a backwards (`-b`) raw LZSA1 block whose match offsets may
/// reach into `prefix` (the upstream `-b -D` combination).
///
/// **Note:** `prefix` is forward-order history (a `-D` dictionary or an
/// earlier block's decoded output), used as-is — upstream reverses only
/// the new block data, never the history window. This differs from the
/// ZX-family backwards decoders, where the `suffix` argument is the
/// tail of the uncompressed data.
pub fn decode_lzsa1_block_backwards_with_prefix(
    input: &[u8],
    prefix: &[u8],
) -> Result<Vec<u8>, Error> {
    decode_block_backwards_impl(input, prefix, false)
}

/// Decode a raw LZSA2 block produced in backwards (`-b`) mode; see
/// [`decode_lzsa1_block_backwards`].
pub fn decode_lzsa2_block_backwards(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_lzsa2_block_backwards_with_prefix(input, &[])
}

/// Decode a backwards (`-b`) raw LZSA2 block whose match offsets may
/// reach into `prefix` (the upstream `-b -D` combination); see
/// [`decode_lzsa1_block_backwards_with_prefix`] for the forward-order
/// history convention.
pub fn decode_lzsa2_block_backwards_with_prefix(
    input: &[u8],
    prefix: &[u8],
) -> Result<Vec<u8>, Error> {
    decode_block_backwards_impl(input, prefix, true)
}

fn decode_block_backwards_impl(
    input: &[u8],
    prefix: &[u8],
    level2: bool,
) -> Result<Vec<u8>, Error> {
    let mut block = input.to_vec();
    block.reverse();
    let mut out = Vec::new();
    if level2 {
        decode_lzsa2_commands(&block, &mut out, usize::MAX, true, prefix)?;
    } else {
        decode_lzsa1_commands(&block, &mut out, usize::MAX, true, prefix)?;
    }
    out.reverse();
    Ok(out)
}

/// Append `len` bytes copied `distance` back in the virtual history
/// `prefix ++ out`.
fn copy_match(
    prefix: &[u8],
    out: &mut Vec<u8>,
    distance: usize,
    len: usize,
    max_output: usize,
    msg: &'static str,
) -> Result<(), Error> {
    let avail = prefix.len() + out.len();
    if distance == 0 || distance > avail {
        return Err(Error::InvalidData(msg));
    }
    if out.len() + len > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    for vpos in (avail - distance)..(avail - distance + len) {
        let b = if vpos < prefix.len() {
            prefix[vpos]
        } else {
            out[vpos - prefix.len()]
        };
        out.push(b);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LZSA1 block decoding
// ---------------------------------------------------------------------------

fn decode_lzsa1_commands(
    input: &[u8],
    out: &mut Vec<u8>,
    max_output: usize,
    raw: bool,
    prefix: &[u8],
) -> Result<(), Error> {
    let mut pos = 0usize;
    loop {
        if !raw && pos >= input.len() {
            // Stream blocks end after the literals of the last command.
            return Ok(());
        }
        let token = *input
            .get(pos)
            .ok_or(Error::InvalidData("lzsa1: truncated command"))?;
        pos += 1;

        let mut lit_len = ((token >> 4) & 7) as usize;
        if lit_len == 7 {
            let b = *input
                .get(pos)
                .ok_or(Error::InvalidData("lzsa1: truncated literal length"))?;
            pos += 1;
            lit_len = match b {
                249 => {
                    if pos + 2 > input.len() {
                        return Err(Error::InvalidData("lzsa1: truncated literal length"));
                    }
                    let v = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
                    pos += 2;
                    v
                }
                250 => {
                    let b2 = *input
                        .get(pos)
                        .ok_or(Error::InvalidData("lzsa1: truncated literal length"))?;
                    pos += 1;
                    256 + b2 as usize
                }
                _ => 7 + b as usize,
            };
        }
        if pos + lit_len > input.len() {
            return Err(Error::InvalidData("lzsa1: truncated literals"));
        }
        if out.len() + lit_len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        out.extend_from_slice(&input[pos..pos + lit_len]);
        pos += lit_len;

        if pos >= input.len() {
            if !raw {
                return Ok(());
            }
            return Err(Error::InvalidData("lzsa1: missing EOD marker"));
        }

        // Match offset, stored negative: distance = 0x10000 - stored.
        let low = input[pos] as usize;
        pos += 1;
        let high = if token & 0x80 != 0 {
            if pos >= input.len() {
                return Err(Error::InvalidData("lzsa1: truncated match offset"));
            }
            let h = input[pos] as usize;
            pos += 1;
            h
        } else {
            0xff
        };
        let distance = 0x10000 - ((high << 8) | low);

        let mut m = (token & 0x0f) as usize;
        let mut len = m + L1_MIN_MATCH;
        if m == 15 {
            let b = *input
                .get(pos)
                .ok_or(Error::InvalidData("lzsa1: truncated match length"))?;
            pos += 1;
            len = match b {
                238 => {
                    if pos + 2 > input.len() {
                        return Err(Error::InvalidData("lzsa1: truncated match length"));
                    }
                    let v = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
                    pos += 2;
                    if v == 0 {
                        // EOD marker: end of a raw block.
                        if raw && pos != input.len() {
                            return Err(Error::InvalidData("lzsa1: trailing data after EOD"));
                        }
                        return Ok(());
                    }
                    v
                }
                239 => {
                    let b2 = *input
                        .get(pos)
                        .ok_or(Error::InvalidData("lzsa1: truncated match length"))?;
                    pos += 1;
                    256 + b2 as usize
                }
                _ => 18 + b as usize,
            };
        }
        let _ = &mut m;

        copy_match(
            prefix,
            out,
            distance,
            len,
            max_output,
            "lzsa1: bad match offset",
        )?;
    }
}

// ---------------------------------------------------------------------------
// LZSA2 block decoding
// ---------------------------------------------------------------------------

struct NibbleReader<'a> {
    input: &'a [u8],
    pos: usize,
    pending: Option<u8>,
}

impl<'a> NibbleReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        NibbleReader {
            input,
            pos: 0,
            pending: None,
        }
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self
            .input
            .get(self.pos)
            .ok_or(Error::InvalidData("lzsa2: unexpected end of input"))?;
        self.pos += 1;
        Ok(b)
    }

    fn nibble(&mut self) -> Result<u8, Error> {
        if let Some(n) = self.pending.take() {
            return Ok(n);
        }
        let b = self.byte()?;
        self.pending = Some(b & 0x0f);
        Ok(b >> 4)
    }
}

fn decode_lzsa2_commands(
    input: &[u8],
    out: &mut Vec<u8>,
    max_output: usize,
    raw: bool,
    prefix: &[u8],
) -> Result<(), Error> {
    let mut r = NibbleReader::new(input);
    let mut last_dist = 0usize;

    loop {
        if !raw && r.pos >= input.len() {
            return Ok(());
        }
        let token = r.byte()?;
        let xyz = token >> 5;
        let z = (xyz & 1) as usize;
        let mut lit_len = ((token >> 3) & 3) as usize;
        if lit_len == 3 {
            let nib = r.nibble()?;
            lit_len = 3 + nib as usize;
            if nib == 15 {
                let b = r.byte()?;
                lit_len = match b {
                    239 => {
                        let lo = r.byte()?;
                        let hi = r.byte()?;
                        u16::from_le_bytes([lo, hi]) as usize
                    }
                    238 => 0, // never emitted by the reference encoder
                    _ => 18 + b as usize,
                };
            }
        }
        if r.pos + lit_len > input.len() {
            return Err(Error::InvalidData("lzsa2: truncated literals"));
        }
        if out.len() + lit_len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        out.extend_from_slice(&input[r.pos..r.pos + lit_len]);
        r.pos += lit_len;

        if r.pos >= input.len() {
            if !raw {
                return Ok(());
            }
            return Err(Error::InvalidData("lzsa2: missing EOD marker"));
        }

        // Positive match distance, or reuse of the previous one.
        let distance = match xyz {
            0b000 | 0b001 => (((r.nibble()? as usize) << 1 | z) ^ 0x1e) + 1,
            0b010 | 0b011 => (((z << 8) | r.byte()? as usize) ^ 0xff) + 1,
            0b100 | 0b101 => {
                let nib = r.nibble()? as usize;
                let b = r.byte()? as usize;
                (((nib << 9) | (z << 8) | b) ^ 0x1eff) + 513
            }
            0b110 => {
                let hi = r.byte()? as usize;
                let lo = r.byte()? as usize;
                (((hi << 8) | lo) ^ 0xffff) + 1
            }
            _ => last_dist, // 0b111: rep-match
        };
        if xyz != 0b111 {
            last_dist = distance;
        }

        let m = (token & 7) as usize;
        let mut len = m + L2_MIN_MATCH;
        if m == 7 {
            let nib = r.nibble()?;
            len = 9 + nib as usize;
            if nib == 15 {
                let b = r.byte()?;
                if b == 233 {
                    let lo = r.byte()?;
                    let hi = r.byte()?;
                    len = u16::from_le_bytes([lo, hi]) as usize;
                } else if b == 232 {
                    // EOD marker.
                    if raw && r.pos != input.len() {
                        return Err(Error::InvalidData("lzsa2: trailing data after EOD"));
                    }
                    return Ok(());
                } else {
                    len = 24 + b as usize;
                }
            }
        }

        copy_match(
            prefix,
            out,
            distance,
            len,
            max_output,
            "lzsa2: bad match offset",
        )?;
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode data as an LZSA stream using LZSA1 blocks.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], false)
}

/// Encode data as an LZSA stream using LZSA2 blocks.
pub fn encode_lzsa2(input: &[u8]) -> Vec<u8> {
    encode_impl(input, &[], true)
}

/// Encode data as an LZSA stream (LZSA1 blocks) whose match offsets may
/// reach into `prefix`, external history logically prepended to the
/// input (the upstream `-D` dictionary option). The result must be
/// decoded with [`decode_with_prefix`] using the same `prefix`.
pub fn encode_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix, false)
}

/// Encode data as an LZSA stream (LZSA2 blocks) with `prefix` history
/// as in [`encode_with_prefix`]. Decode with [`decode_with_prefix`].
pub fn encode_lzsa2_with_prefix(input: &[u8], prefix: &[u8]) -> Vec<u8> {
    encode_impl(input, prefix, true)
}

/// Encode a raw LZSA1 block terminated by the EOD marker, in the format
/// read by `lzsa -r -f1` (decode with [`decode_lzsa1_block`]).
///
/// Returns `None` when `input` cannot be represented as a single block
/// (a literal run exceeding 64 KiB): a raw block has no verbatim
/// fallback, and the reference compressor reports failure as well.
pub fn encode_lzsa1_block(input: &[u8]) -> Option<Vec<u8>> {
    encode_block_impl(input, &[], false)
}

/// Encode a raw LZSA1 block whose match offsets may reach into
/// `prefix`, external history logically prepended to `input` (the
/// upstream `-r -D` combination). Decode with
/// [`decode_lzsa1_block_with_prefix`] using the same `prefix`.
pub fn encode_lzsa1_block_with_prefix(input: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    encode_block_impl(input, prefix, false)
}

/// Encode a raw LZSA2 block terminated by the EOD marker, in the format
/// read by `lzsa -r -f2` (decode with [`decode_lzsa2_block`]). See
/// [`encode_lzsa1_block`] for the failure condition.
pub fn encode_lzsa2_block(input: &[u8]) -> Option<Vec<u8>> {
    encode_block_impl(input, &[], true)
}

/// Encode a raw LZSA2 block whose match offsets may reach into
/// `prefix`, external history logically prepended to `input` (the
/// upstream `-r -D` combination). Decode with
/// [`decode_lzsa2_block_with_prefix`] using the same `prefix`.
pub fn encode_lzsa2_block_with_prefix(input: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    encode_block_impl(input, prefix, true)
}

/// Encode a backwards (`-b`) raw LZSA1 block, in the format written by
/// `lzsa -r -b -f1` (decode with [`decode_lzsa1_block_backwards`]).
///
/// The result is the byte-reversed image of the forward block for the
/// reversed input; the block grammar itself is unchanged. See
/// [`encode_lzsa1_block`] for the failure condition.
pub fn encode_lzsa1_block_backwards(input: &[u8]) -> Option<Vec<u8>> {
    encode_block_backwards_impl(input, &[], false)
}

/// Encode a backwards (`-b`) raw LZSA1 block whose match offsets may
/// reach into `prefix` (the upstream `-r -b -D` combination). Decode
/// with [`decode_lzsa1_block_backwards_with_prefix`] using the same
/// `prefix`.
///
/// **Note:** `prefix` is forward-order history — upstream reverses only
/// the new block data, never the history window, so unlike the
/// ZX-family backwards encoders `prefix` must *not* be reversed first.
pub fn encode_lzsa1_block_backwards_with_prefix(input: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    encode_block_backwards_impl(input, prefix, false)
}

/// Encode a backwards (`-b`) raw LZSA2 block, in the format written by
/// `lzsa -r -b -f2` (decode with [`decode_lzsa2_block_backwards`]). See
/// [`encode_lzsa1_block_backwards`].
pub fn encode_lzsa2_block_backwards(input: &[u8]) -> Option<Vec<u8>> {
    encode_block_backwards_impl(input, &[], true)
}

/// Encode a backwards (`-b`) raw LZSA2 block whose match offsets may
/// reach into `prefix` (the upstream `-r -b -D` combination). See
/// [`encode_lzsa1_block_backwards_with_prefix`] for the forward-order
/// history convention.
pub fn encode_lzsa2_block_backwards_with_prefix(input: &[u8], prefix: &[u8]) -> Option<Vec<u8>> {
    encode_block_backwards_impl(input, prefix, true)
}

/// `prefix` is forward-order history logically prepended to `input`,
/// as `decode_*_block_with_prefix` expects.
fn encode_block_impl(input: &[u8], prefix: &[u8], level2: bool) -> Option<Vec<u8>> {
    let combined;
    let window: &[u8] = if prefix.is_empty() {
        input
    } else {
        let mut v = Vec::with_capacity(prefix.len() + input.len());
        v.extend_from_slice(prefix);
        v.extend_from_slice(input);
        combined = v;
        &combined
    };
    if level2 {
        encode_lzsa2_block_window(window, prefix.len(), true)
    } else {
        encode_lzsa1_block_window(window, prefix.len(), true)
    }
}

/// The backwards wrapper reverses only the new block data (`input`),
/// matching upstream's `lzsa_reverse_buffer(pInWindow +
/// nPreviousBlockSize, ...)`; the `prefix` history stays in forward
/// order.
fn encode_block_backwards_impl(input: &[u8], prefix: &[u8], level2: bool) -> Option<Vec<u8>> {
    let mut window = Vec::with_capacity(prefix.len() + input.len());
    window.extend_from_slice(prefix);
    window.extend(input.iter().rev().copied());
    let mut block = if level2 {
        encode_lzsa2_block_window(&window, prefix.len(), true)?
    } else {
        encode_lzsa1_block_window(&window, prefix.len(), true)?
    };
    block.reverse();
    Some(block)
}

/// `prefix` is external history logically prepended to `input`: matches
/// may copy from it using normal wire offsets, as `decode_with_prefix`
/// expects. Match positions are tracked in the virtual `prefix ++ input`
/// history, so a distance that exceeds the output produced so far lands
/// inside `prefix`. Unlike ZX1 the first command may be a match, so no
/// leading literal is required.
fn encode_impl(input: &[u8], prefix: &[u8], level2: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + input.len() / 8);
    out.extend_from_slice(&MAGIC);
    out.push(if level2 { 1 << 5 } else { 0 });
    // `window` is the virtual `prefix ++ input` history and `base` the
    // input's start inside it; an empty prefix aliases `input` directly.
    let combined;
    let window: &[u8] = if prefix.is_empty() {
        input
    } else {
        let mut v = Vec::with_capacity(prefix.len() + input.len());
        v.extend_from_slice(prefix);
        v.extend_from_slice(input);
        combined = v;
        &combined
    };
    let base = window.len() - input.len();
    // Frames of up to 64 KiB of decompressed data; a frame's match
    // offsets may reach back into earlier frames (and into `prefix`).
    let mut frame_start = 0usize;
    while frame_start < input.len() {
        let frame_end = (frame_start + 0x10000).min(input.len());
        let block = if level2 {
            encode_lzsa2_block_window(&window[..base + frame_end], base + frame_start, false)
        } else {
            encode_lzsa1_block_window(&window[..base + frame_end], base + frame_start, false)
        };
        match block {
            Some(b) if b.len() < frame_end - frame_start => {
                let dsz = b.len();
                out.push((dsz & 0xff) as u8);
                out.push(((dsz >> 8) & 0xff) as u8);
                out.push(((dsz >> 16) & 1) as u8);
                out.extend_from_slice(&b);
            }
            _ => {
                // Incompressible (or unencodable) data: verbatim frame.
                let chunk = &input[frame_start..frame_end];
                let dsz = chunk.len();
                out.push((dsz & 0xff) as u8);
                out.push(((dsz >> 8) & 0xff) as u8);
                out.push((((dsz >> 16) & 1) as u8) | 0x80);
                out.extend_from_slice(chunk);
            }
        }
        frame_start = frame_end;
    }
    out.extend_from_slice(&[0, 0, 0]);
    out
}

/// Encode a raw LZSA1 block (with EOD marker). `window` is the history
/// prefix ending at the data to compress; `block_start` is the offset
/// inside `window` where this block's input begins (matches may reach
/// back before it). Returns `None` when a literal run cannot be encoded.
fn encode_lzsa1_block_window(window: &[u8], block_start: usize, eod: bool) -> Option<Vec<u8>> {
    let input = &window[block_start..];
    let mut out = Vec::with_capacity(input.len() + input.len() / 8 + 8);
    let mut head = vec![-1i32; 1 << 16];
    // Index the history part of the window.
    for gpos in 0..block_start {
        if gpos + 3 <= window.len() {
            let h = hash3(&window[gpos..gpos + 3]);
            head[h] = gpos as i32;
        }
    }

    let mut pos = 0usize;
    let mut lit_start = 0usize;
    while pos + L1_MIN_MATCH <= input.len() {
        let gpos = block_start + pos;
        let h = hash3(&window[gpos..gpos + 3]);
        let cand = head[h];
        head[h] = gpos as i32;
        let mut len = 0usize;
        if cand >= 0 {
            let c = cand as usize;
            let dist = gpos - c;
            if dist <= L1_MAX_DIST
                && window[c..c + L1_MIN_MATCH] == window[gpos..gpos + L1_MIN_MATCH]
            {
                len = L1_MIN_MATCH;
                while gpos + len < window.len() && window[c + len] == window[gpos + len] {
                    len += 1;
                }
                let max_len = (input.len() - pos).min(L1_MAX_RUN);
                if len > max_len {
                    len = max_len;
                }
            }
        }
        if len >= L1_MIN_MATCH {
            l1_command(
                &mut out,
                &input[lit_start..pos],
                L1Tail::Match {
                    dist: gpos - cand as usize,
                    len,
                },
            )?;
            pos += len;
            lit_start = pos;
        } else {
            if pos - lit_start > L1_MAX_RUN {
                return None;
            }
            pos += 1;
        }
    }
    l1_command(
        &mut out,
        &input[lit_start..],
        if eod { L1Tail::Eod } else { L1Tail::Lit },
    )?;
    Some(out)
}

fn hash3(b: &[u8]) -> usize {
    (((b[0] as usize) << 10) ^ ((b[1] as usize) << 5) ^ b[2] as usize) & 0xffff
}

enum L1Tail {
    Lit,
    Match { dist: usize, len: usize },
    Eod,
}

fn l1_command(out: &mut Vec<u8>, lits: &[u8], tail: L1Tail) -> Option<()> {
    if lits.len() > L1_MAX_RUN {
        return None;
    }
    let tp = out.len();
    out.push(0);
    let l = lits.len();
    if l <= 6 {
        out[tp] = (l as u8) << 4;
    } else {
        out[tp] = 7 << 4;
        if l < 256 {
            out.push((l - 7) as u8);
        } else if l < 512 {
            out.push(250);
            out.push((l - 256) as u8);
        } else {
            out.push(249);
            out.extend_from_slice(&(l as u16).to_le_bytes());
        }
    }
    out.extend_from_slice(lits);
    match tail {
        L1Tail::Lit => {}
        L1Tail::Eod => {
            // Offset byte (ignored) + M=15 extension: 238, then u16 zero.
            out[tp] |= 15;
            out.extend_from_slice(&[0, 238, 0, 0]);
        }
        L1Tail::Match { dist, len } => {
            if dist <= 256 {
                out.push((256 - dist) as u8);
            } else {
                out[tp] |= 0x80;
                let off = 0x10000 - dist;
                out.push((off & 0xff) as u8);
                out.push((off >> 8) as u8);
            }
            if len < 256 {
                out[tp] |= if len - L1_MIN_MATCH <= 14 {
                    (len - L1_MIN_MATCH) as u8
                } else {
                    out.push((len - 18) as u8);
                    15
                };
            } else if len < 512 {
                out[tp] |= 15;
                out.push(239);
                out.push((len - 256) as u8);
            } else {
                out[tp] |= 15;
                out.push(238);
                out.extend_from_slice(&(len as u16).to_le_bytes());
            }
        }
    }
    Some(())
}

fn encode_lzsa2_block_window(window: &[u8], block_start: usize, eod: bool) -> Option<Vec<u8>> {
    let input = &window[block_start..];
    let mut enc = Lzsa2Encoder {
        out: Vec::with_capacity(input.len() + input.len() / 8 + 8),
        nibble_slot: None,
        last_dist: None,
    };
    let mut head = vec![-1i32; 1 << 16];
    for gpos in 0..block_start {
        if gpos + 2 <= window.len() {
            head[pair(&window[gpos..gpos + 2])] = gpos as i32;
        }
    }

    let mut pos = 0usize;
    let mut lit_start = 0usize;
    while pos + L2_MIN_MATCH <= input.len() {
        let gpos = block_start + pos;
        let h = pair(&window[gpos..gpos + 2]);
        let cand = head[h];
        head[h] = gpos as i32;
        let mut len = 0usize;
        if cand >= 0 {
            let c = cand as usize;
            let dist = gpos - c;
            if dist <= L2_MAX_DIST
                && window[c..c + L2_MIN_MATCH] == window[gpos..gpos + L2_MIN_MATCH]
            {
                len = L2_MIN_MATCH;
                while gpos + len < window.len() && window[c + len] == window[gpos + len] {
                    len += 1;
                }
                let max_len = (input.len() - pos).min(L2_MAX_RUN);
                if len > max_len {
                    len = max_len;
                }
            }
        }
        if len >= L2_MIN_MATCH {
            enc.command(
                &input[lit_start..pos],
                L2Tail::Match {
                    dist: gpos - cand as usize,
                    len,
                },
            )?;
            pos += len;
            lit_start = pos;
        } else {
            if pos - lit_start > L2_MAX_RUN {
                return None;
            }
            pos += 1;
        }
    }
    enc.command(
        &input[lit_start..],
        if eod { L2Tail::Eod } else { L2Tail::Lit },
    )?;
    if enc.nibble_slot.is_some() {
        // Pad the open nibble byte with a zero low half.
        enc.nibble(0);
    }
    Some(enc.out)
}

fn pair(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}

struct Lzsa2Encoder {
    out: Vec<u8>,
    nibble_slot: Option<usize>,
    last_dist: Option<usize>,
}

enum L2Tail {
    Lit,
    Match { dist: usize, len: usize },
    Eod,
}

impl Lzsa2Encoder {
    fn byte(&mut self, b: u8) {
        self.out.push(b);
    }

    /// Write a nibble: reserve a new byte for the high half, or backfill
    /// the low half of a previously reserved byte.
    fn nibble(&mut self, n: u8) {
        match self.nibble_slot {
            Some(i) => {
                self.out[i] |= n & 0x0f;
                self.nibble_slot = None;
            }
            None => {
                self.nibble_slot = Some(self.out.len());
                self.out.push(n << 4);
            }
        }
    }

    fn command(&mut self, lits: &[u8], tail: L2Tail) -> Option<()> {
        if lits.len() > L2_MAX_RUN {
            return None;
        }
        let l = lits.len();
        let ll = if l <= 2 { l as u8 } else { 3 };
        let (xyz, m, dist, len) = match tail {
            L2Tail::Lit => (0u8, 0u8, 0usize, 0usize),
            L2Tail::Eod => (0b111u8, 7u8, 0, 0),
            L2Tail::Match { dist, len } => {
                let xyz = if self.last_dist == Some(dist) {
                    0b111
                } else if dist <= 32 {
                    (((dist - 1) ^ 0x1e) & 1) as u8
                } else if dist <= 512 {
                    0b010 | (((dist - 1) ^ 0xff) >> 8) as u8
                } else if dist <= 8704 {
                    0b100 | ((((dist - 513) ^ 0x1eff) >> 8) & 1) as u8
                } else {
                    0b110
                };
                (
                    xyz,
                    if len - L2_MIN_MATCH <= 6 {
                        (len - L2_MIN_MATCH) as u8
                    } else {
                        7
                    },
                    dist,
                    len,
                )
            }
        };
        self.byte((xyz << 5) | (ll << 3) | m);

        // Extended literal length.
        if l > 2 {
            if l < 18 {
                self.nibble((l - 3) as u8);
            } else {
                self.nibble(15);
                if l < 256 {
                    self.byte((l - 18) as u8);
                } else {
                    self.byte(239);
                    self.byte((l & 0xff) as u8);
                    self.byte((l >> 8) as u8);
                }
            }
        }
        for &b in lits {
            self.byte(b);
        }

        match tail {
            L2Tail::Lit => {}
            L2Tail::Eod => {
                self.nibble(15);
                self.byte(232);
            }
            L2Tail::Match { .. } => {
                // Offset.
                match xyz {
                    0b000 | 0b001 => {
                        self.nibble((((dist - 1) ^ 0x1e) >> 1) as u8);
                    }
                    0b010 | 0b011 => {
                        self.byte((((dist - 1) ^ 0xff) & 0xff) as u8);
                    }
                    0b100 | 0b101 => {
                        let v = (dist - 513) ^ 0x1eff;
                        self.nibble(((v >> 9) & 0x0f) as u8);
                        self.byte((v & 0xff) as u8);
                    }
                    0b110 => {
                        let v = (dist - 1) ^ 0xffff;
                        self.byte((v >> 8) as u8);
                        self.byte((v & 0xff) as u8);
                    }
                    _ => {} // rep-match: no offset bits
                }
                if xyz != 0b111 {
                    self.last_dist = Some(dist);
                }
                // Extended match length.
                let enc_len = len - L2_MIN_MATCH;
                if enc_len > 6 {
                    if enc_len < 22 {
                        self.nibble((enc_len - 7) as u8);
                    } else {
                        self.nibble(15);
                        if len < 256 {
                            self.byte((len - 24) as u8);
                        } else {
                            self.byte(233);
                            self.byte((len & 0xff) as u8);
                            self.byte((len >> 8) as u8);
                        }
                    }
                }
            }
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        assert_eq!(decode(&encode(data)).unwrap(), data);
        assert_eq!(decode(&encode_lzsa2(data)).unwrap(), data);
    }

    #[test]
    fn decode_stream_uncompressed_frame() {
        let input = [
            0x7b, 0x9e, 0x00, 0x03, 0x00, 0x80, b'a', b'b', b'c', 0, 0, 0,
        ];
        assert_eq!(decode(&input).unwrap(), b"abc");
    }

    #[test]
    fn decode_l1_hand_built() {
        // token 0x31: O=0 L=3 M=1; literals "abc"; 1-byte offset 0xff
        // (dist 1); match len 4 -> "abccccc". Block ends with an L=0
        // literals-only command.
        let block = [
            0x7b, 0x9e, 0x00, 0x06, 0x00, 0x00, 0x31, b'a', b'b', b'c', 0xff, 0x00, 0x00, 0x00,
            0x00,
        ];
        assert_eq!(decode(&block).unwrap(), b"abccccc");
    }

    #[test]
    fn decode_l1_eod_raw() {
        // token 0x3f: L=3 M=15; "abc"; offset 0; ext 238 + u16 0 -> EOD.
        let raw = [0x3f, b'a', b'b', b'c', 0x00, 238, 0x00, 0x00];
        assert_eq!(decode_lzsa1_block(&raw).unwrap(), b"abc");
        // missing EOD in raw mode
        assert!(decode_lzsa1_block(&raw[..4]).is_err());
    }

    #[test]
    fn decode_l2_eod_raw() {
        // token 0xef: XYZ=111(rep) L=1 M=7; lit 'a'; nibble 15 + byte 232.
        let raw = [0xef, b'a', 0xf0, 232];
        assert_eq!(decode_lzsa2_block(&raw).unwrap(), b"a");
        assert!(decode_lzsa2_block(&raw[..2]).is_err());
    }

    #[test]
    fn decode_lzsa1_block_with_dict() {
        // token 0x10: L=1 'a', 1-byte offset 0xfa (distance 6 reaches
        // into the 5-byte dictionary "HELLO"), match len 3; then EOD.
        let raw = [0x10, b'a', 0xfa, 0x0f, 0x00, 238, 0x00, 0x00];
        assert!(decode_lzsa1_block(&raw).is_err());
        assert_eq!(
            decode_lzsa1_block_with_prefix(&raw, b"HELLO").unwrap(),
            b"aHEL"
        );
    }

    #[test]
    fn decode_lzsa2_block_with_dict() {
        // token 0x29: XYZ=001 L=1 M=1; 'a'; offset nibble 0xd ->
        // distance 6, match len 3; then rep-match token 0xe7 +
        // nibble 15 + byte 232 = EOD.
        let raw = [0x29, b'a', 0xdf, 0xe7, 0xe8];
        assert!(decode_lzsa2_block(&raw).is_err());
        assert_eq!(
            decode_lzsa2_block_with_prefix(&raw, b"HELLO").unwrap(),
            b"aHEL"
        );
    }

    #[test]
    fn decode_stream_with_dict() {
        // LZSA1 frame: one command = literal 'a' + match distance 6
        // len 3 reaching into the dictionary.
        let stream = [
            0x7b, 0x9e, 0x00, 0x03, 0x00, 0x00, 0x10, b'a', 0xfa, 0x00, 0x00, 0x00,
        ];
        assert!(decode(&stream).is_err());
        assert_eq!(decode_with_prefix(&stream, b"HELLO").unwrap(), b"aHEL");
    }

    #[test]
    fn rejects_bad_signature() {
        assert!(decode(&[0x7b, 0x9d, 0x00]).is_err());
        assert!(decode(&[0x7b]).is_err());
        assert!(decode(&[0x7b, 0x9e, 0x01]).is_err()); // reserved trait bits
        assert!(decode(&[0x7b, 0x9e, 0x40]).is_err()); // unknown version
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0x7b, 0x9e, 0x00, 0x05, 0x00]).is_err());
        assert!(decode_lzsa1_block(&[0x31, b'a']).is_err());
    }

    #[test]
    fn empty_input() {
        assert_eq!(decode(&encode(b"")).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&encode_lzsa2(b"")).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_various() {
        for data in [
            b"a".as_slice(),
            b"ab",
            b"abc",
            b"abcabcabcabcabc",
            b"hello world hello world hello world",
        ] {
            rt(data);
        }
        rt(&[0u8; 2000]);
        rt(&[9u8; 90000]); // multi-frame
        let mut text = Vec::new();
        for _ in 0..300 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&text);
        let mut binary = Vec::new();
        for i in 0..30000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        rt(&binary);
        // distances covering the LZSA2 offset tiers
        let mut tier = Vec::new();
        for _ in 0..40 {
            tier.extend_from_slice(b"0123456789abcdef");
        }
        tier.extend_from_slice(&[7u8; 100]);
        for _ in 0..40 {
            tier.extend_from_slice(b"0123456789abcdef");
        }
        rt(&tier);
    }

    #[test]
    fn verbatim_frame_for_incompressible() {
        // Incompressible input must fall back to a verbatim frame
        // (StreamFormat: DSZ byte2 bit7). xorshift32 fills the buffer.
        let mut noise = vec![0u8; 70000];
        let mut x = 0x9e3779b9u32;
        for b in noise.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        for enc in [encode(&noise), encode_lzsa2(&noise)] {
            assert_eq!(&enc[..2], &[0x7b, 0x9e]);
            assert_eq!(enc[5] & 0x80, 0x80, "verbatim flag not set");
            assert_eq!(decode(&enc).unwrap(), noise);
        }
    }

    #[test]
    fn rejects_reserved_dsz_bits() {
        // StreamFormat: DSZ byte2 bits1-6 are reserved; nonzero is rejected.
        for enc in [encode(b"hello"), encode_lzsa2(b"hello")] {
            for bits in [0x02u8, 0x40, 0x7e] {
                let mut s = enc.clone();
                s[5] |= bits;
                assert!(decode(&s).is_err(), "bits={bits:#04x}");
            }
            // bit0 (dsz bit16) and bit7 (uncompressed flag) are legal.
            let s = enc;
            assert!(decode(&s).is_ok());
        }
    }

    #[test]
    fn lzsa1_defensive_marker_bytes() {
        // Marker bytes the reference encoder never emits (spec 24): the
        // decoder still interprets them deterministically.
        // lit-len marker 249 -> u16 LE literal length.
        let mut b = vec![0x70, 249, 0x05, 0x00];
        b.extend_from_slice(b"abcde");
        b.extend_from_slice(&[0xff, 0x0f, 0x00, 238, 0x00, 0x00]);
        assert_eq!(decode_lzsa1_block(&b).unwrap(), b"abcdeeee");
        // lit-len marker 250 -> 256 + b2.
        let mut b = vec![0x70, 250, 0x00];
        b.extend_from_slice(&[0xabu8; 256]);
        b.extend_from_slice(&[0xff, 0x0f, 0x00, 238, 0x00, 0x00]);
        // match len3 dist1 appends 3 more -> 259 bytes
        assert_eq!(decode_lzsa1_block(&b).unwrap(), vec![0xabu8; 259]);
        // match-len marker 238 -> u16 LE match length (nonzero).
        let b = [
            0x1f, b'a', 0xff, 238, 0x05, 0x00, 0x0f, 0x00, 238, 0x00, 0x00,
        ];
        assert_eq!(decode_lzsa1_block(&b).unwrap(), b"aaaaaa");
        // match-len marker 239 -> 256 + b2.
        let b = [0x1f, b'a', 0xff, 239, 0x00, 0x0f, 0x00, 238, 0x00, 0x00];
        assert_eq!(decode_lzsa1_block(&b).unwrap(), vec![b'a'; 257]);
    }

    #[test]
    fn lzsa2_defensive_marker_bytes() {
        // lit-len marker 238 is never emitted by the reference encoder;
        // the decoder treats it as a literal length of 0.
        // lit-len marker 239 -> u16 LE; match-len marker 233 -> u16 LE;
        // match-len marker 232 -> EOD.
        let b = [
            0x48, b'a', 0xff, // lit1 'a', byte-offset dist1, len2 -> "aaa"
            0x18, 0xfe, 0xee, // lit-ext nib + marker 238 -> 0 lit; dist3, len2
            0x07, 0xff, 0xe9, 0x04, 0x00, // rep1; m7 nib15 + marker 233 -> len 4
            0x07, 0xff, 0xe8, // rep1; m7 nib15 + marker 232 -> EOD
        ];
        assert_eq!(decode_lzsa2_block(&b).unwrap(), b"aaaaaaaaa");
        // lit-len marker 239 -> u16 LE literal length (3).
        let b = [0x1f, 0xfe, 0xef, 0x03, 0x00, b'x', b'y', b'z', 0xf0, 0xe8];
        assert_eq!(decode_lzsa2_block(&b).unwrap(), b"xyz");
    }

    fn rt_prefix(data: &[u8], prefix: &[u8]) {
        assert_eq!(
            decode_with_prefix(&encode_with_prefix(data, prefix), prefix).unwrap(),
            data
        );
        assert_eq!(
            decode_with_prefix(&encode_lzsa2_with_prefix(data, prefix), prefix).unwrap(),
            data
        );
    }

    #[test]
    fn encode_with_prefix_uses_prefix_match() {
        // The input opens with bytes that only occur inside the prefix:
        // the very first command is a match reaching back into the
        // external history (LZSA needs no leading literal).
        let prefix = b"0123456789abcdef";
        let mut input = prefix.to_vec();
        input.extend_from_slice(b" tail tail tail");

        let enc1 = encode_with_prefix(&input, prefix);
        let enc2 = encode_lzsa2_with_prefix(&input, prefix);
        assert_eq!(decode_with_prefix(&enc1, prefix).unwrap(), input);
        assert_eq!(decode_with_prefix(&enc2, prefix).unwrap(), input);
        // Using the prefix dictionary beats plain encoding here.
        assert!(enc1.len() < encode(&input).len());
        assert!(enc2.len() < encode_lzsa2(&input).len());
    }

    #[test]
    fn encode_with_prefix_roundtrip() {
        rt_prefix(b"hello hello hello", b"prefix data");
        rt_prefix(b"aaaaaaaaaaaaaaaaaaaa", b"aaaa");
        rt_prefix(b"", b"nonempty prefix");
        // Distance-2 match at position 0: starts in the 2-byte prefix
        // and continues into produced output (boundary crossing).
        rt_prefix(b"ababab", b"ab");
        // Match into the prefix after some output, then rep-matches.
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
        // Prefix still usable as history across a frame boundary.
        let mut big = b"0123456789abcdef".to_vec();
        big.extend_from_slice(&[0u8; 70000]);
        big.extend_from_slice(b"0123456789abcdef");
        rt_prefix(&big, b"0123456789abcdef");
    }

    #[test]
    fn encode_with_empty_prefix_matches_encode() {
        for data in [
            b"abcabcabc---abcabcabc".as_slice(),
            &[7u8; 70000][..], // multi-frame
        ] {
            assert_eq!(encode_with_prefix(data, b""), encode(data));
            assert_eq!(encode_lzsa2_with_prefix(data, b""), encode_lzsa2(data));
        }
        // Empty input with a prefix still yields a valid empty stream.
        assert_eq!(
            decode_with_prefix(&encode_with_prefix(b"", b"prefix"), b"prefix").unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn encode_with_prefix_stream_needs_prefix() {
        // Decoding a prefix-compressed stream without the prefix must
        // not silently produce the original data.
        let prefix = b"0123456789abcdef";
        let mut input = prefix.to_vec();
        input.extend_from_slice(b" tail tail tail");
        for enc in [
            encode_with_prefix(&input, prefix),
            encode_lzsa2_with_prefix(&input, prefix),
        ] {
            if let Ok(v) = decode(&enc) {
                assert_ne!(v, input);
            }
        }
    }

    // -----------------------------------------------------------------
    // Backwards (`-b`) raw blocks: a pure byte-reversal wrapper over the
    // same block grammar (raw blocks only, no stream container).
    // -----------------------------------------------------------------

    fn rt_backwards(data: &[u8]) {
        let b1 = encode_lzsa1_block_backwards(data).unwrap();
        let b2 = encode_lzsa2_block_backwards(data).unwrap();
        assert_eq!(decode_lzsa1_block_backwards(&b1).unwrap(), data);
        assert_eq!(decode_lzsa2_block_backwards(&b2).unwrap(), data);
        // A backwards block is the byte-reversed forward block for the
        // reversed input: rev(b) must decode forward to rev(data).
        let mut rev = data.to_vec();
        rev.reverse();
        let mut fwd = b1.clone();
        fwd.reverse();
        assert_eq!(decode_lzsa1_block(&fwd).unwrap(), rev);
        let mut fwd = b2.clone();
        fwd.reverse();
        assert_eq!(decode_lzsa2_block(&fwd).unwrap(), rev);
        // Encoder equivalence: bwd(data) == rev(fwd(rev(data))).
        let mut expect = encode_lzsa1_block(&rev).unwrap();
        expect.reverse();
        assert_eq!(b1, expect);
        let mut expect = encode_lzsa2_block(&rev).unwrap();
        expect.reverse();
        assert_eq!(b2, expect);
        // The forward decoder does not silently accept a backwards
        // block as the same data.
        if let Ok(v) = decode_lzsa1_block(&b1) {
            assert_ne!(v, data);
        }
        if let Ok(v) = decode_lzsa2_block(&b2) {
            assert_ne!(v, data);
        }
    }

    #[test]
    fn backwards_roundtrip() {
        for data in [
            b"a".as_slice(),
            b"ab",
            b"abc",
            b"abcabcabcabcabc",
            b"hello world hello world hello world",
        ] {
            rt_backwards(data);
        }
        rt_backwards(&[0u8; 2000]);
        rt_backwards(&[9u8; 90000]); // len > 64 KiB, runs of one byte
        let mut text = Vec::new();
        for _ in 0..300 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt_backwards(&text);
        // Rep-matches and distances covering the LZSA2 offset tiers.
        let mut tier = Vec::new();
        for _ in 0..40 {
            tier.extend_from_slice(b"0123456789abcdef");
        }
        tier.extend_from_slice(&[7u8; 100]);
        for _ in 0..40 {
            tier.extend_from_slice(b"0123456789abcdef");
        }
        rt_backwards(&tier);
    }

    #[test]
    fn backwards_empty_input() {
        // Empty input encodes to the reversed EOD-only blocks.
        let b1 = encode_lzsa1_block_backwards(b"").unwrap();
        assert_eq!(b1, [0x00, 0x00, 0xee, 0x00, 0x0f]);
        assert_eq!(decode_lzsa1_block_backwards(&b1).unwrap(), b"");
        let b2 = encode_lzsa2_block_backwards(b"").unwrap();
        assert_eq!(b2, [0xe8, 0xf0, 0xe7]);
        assert_eq!(decode_lzsa2_block_backwards(&b2).unwrap(), b"");
    }

    #[test]
    fn backwards_rejects_malformed() {
        assert!(decode_lzsa1_block_backwards(&[]).is_err());
        assert!(decode_lzsa2_block_backwards(&[]).is_err());
        assert!(decode_lzsa1_block_backwards(&[0x00]).is_err());
        assert!(decode_lzsa2_block_backwards(&[0x00]).is_err());
        // Reversed truncated forward block: no (reversed) EOD head.
        assert!(decode_lzsa1_block_backwards(&[0x0f, 0x00, 0xee]).is_err());
        // Bytes before a backwards block land after the EOD marker once
        // the reversal is undone: still rejected as trailing data.
        let mut b = vec![0xde, 0xad];
        b.extend_from_slice(&encode_lzsa1_block_backwards(b"abc").unwrap());
        assert!(decode_lzsa1_block_backwards(&b).is_err());
    }

    #[test]
    fn backwards_decode_hand_built_with_prefix() {
        // Byte-reversed copies of the dictionary blocks used in the
        // forward tests above: [0x10,'a',0xfa, 0x0f,0x00,238,0x00,0x00]
        // decodes to "aHEL" with prefix "HELLO"; backwards, to "LEHa".
        let raw = [0x00, 0x00, 238, 0x00, 0x0f, 0xfa, b'a', 0x10];
        assert!(decode_lzsa1_block_backwards(&raw).is_err());
        assert_eq!(
            decode_lzsa1_block_backwards_with_prefix(&raw, b"HELLO").unwrap(),
            b"LEHa"
        );
        // LZSA2: forward [0x29,'a',0xdf, 0xe7,0xe8] -> "aHEL".
        let raw = [0xe8, 0xe7, 0xdf, b'a', 0x29];
        assert!(decode_lzsa2_block_backwards(&raw).is_err());
        assert_eq!(
            decode_lzsa2_block_backwards_with_prefix(&raw, b"HELLO").unwrap(),
            b"LEHa"
        );
    }

    #[test]
    fn backwards_prefix_is_forward_history() {
        // In backwards mode `prefix` stays in forward order: upstream
        // reverses only the new block data, never the history window
        // (unlike the ZX-family `suffix`, which is the data tail).
        // `input` contains reverse(prefix), so the reversed block data
        // contains a forward substring of the prefix and can match
        // into it.
        let prefix = b"0123456789abcdef";
        let mut input = b" fedcba9876543210".to_vec(); // space + reverse(prefix)
        input.extend_from_slice(b" tail tail tail");

        let b1 = encode_lzsa1_block_backwards_with_prefix(&input, prefix).unwrap();
        let b2 = encode_lzsa2_block_backwards_with_prefix(&input, prefix).unwrap();
        // History only: the prefix itself is not part of the output.
        assert_eq!(
            decode_lzsa1_block_backwards_with_prefix(&b1, prefix).unwrap(),
            input
        );
        assert_eq!(
            decode_lzsa2_block_backwards_with_prefix(&b2, prefix).unwrap(),
            input
        );
        // The encoder actually emitted a match reaching into `prefix`:
        // decoding without it fails on the out-of-range offset.
        assert!(decode_lzsa1_block_backwards(&b1).is_err());
        assert!(decode_lzsa2_block_backwards(&b2).is_err());
        // Feeding the prefix in reverse (ZX-style suffix semantics)
        // must not reproduce the input.
        let mut rev_prefix = prefix.to_vec();
        rev_prefix.reverse();
        if let Ok(v) = decode_lzsa1_block_backwards_with_prefix(&b1, &rev_prefix) {
            assert_ne!(v, input);
        }
        if let Ok(v) = decode_lzsa2_block_backwards_with_prefix(&b2, &rev_prefix) {
            assert_ne!(v, input);
        }
    }

    #[test]
    fn raw_block_encode_roundtrip() {
        for data in [
            b"abcabcabc---abcabcabc".as_slice(),
            &[7u8; 70000][..],
            b"the quick brown fox jumps over the lazy dog. ",
        ] {
            assert_eq!(
                decode_lzsa1_block(&encode_lzsa1_block(data).unwrap()).unwrap(),
                data
            );
            assert_eq!(
                decode_lzsa2_block(&encode_lzsa2_block(data).unwrap()).unwrap(),
                data
            );
            let prefix = b"dict: the quick brown fox ";
            assert_eq!(
                decode_lzsa1_block_with_prefix(
                    &encode_lzsa1_block_with_prefix(data, prefix).unwrap(),
                    prefix
                )
                .unwrap(),
                data
            );
            assert_eq!(
                decode_lzsa2_block_with_prefix(
                    &encode_lzsa2_block_with_prefix(data, prefix).unwrap(),
                    prefix
                )
                .unwrap(),
                data
            );
        }
        // Empty prefix aliases plain encoding.
        assert_eq!(
            encode_lzsa1_block_with_prefix(b"abcabc", b"").unwrap(),
            encode_lzsa1_block(b"abcabc").unwrap()
        );
        assert_eq!(
            encode_lzsa2_block_with_prefix(b"abcabc", b"").unwrap(),
            encode_lzsa2_block(b"abcabc").unwrap()
        );
        // Empty input is a valid EOD-only block.
        assert_eq!(
            decode_lzsa1_block(&encode_lzsa1_block(b"").unwrap()).unwrap(),
            b""
        );
        assert_eq!(
            decode_lzsa2_block(&encode_lzsa2_block(b"").unwrap()).unwrap(),
            b""
        );
    }
}
