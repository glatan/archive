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
            decode_lzsa2_commands(block, &mut out, max_output, false)?;
        } else {
            decode_lzsa1_commands(block, &mut out, max_output, false)?;
        }
    }
    Ok(out)
}

/// Decode a raw LZSA1 block (terminated by the EOD marker).
pub fn decode_lzsa1_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa1_commands(input, &mut out, usize::MAX, true)?;
    Ok(out)
}

/// Decode a raw LZSA2 block (terminated by the EOD marker).
pub fn decode_lzsa2_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    decode_lzsa2_commands(input, &mut out, usize::MAX, true)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// LZSA1 block decoding
// ---------------------------------------------------------------------------

fn decode_lzsa1_commands(
    input: &[u8],
    out: &mut Vec<u8>,
    max_output: usize,
    raw: bool,
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

        if distance > out.len() {
            return Err(Error::InvalidData("lzsa1: bad match offset"));
        }
        if out.len() + len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        let start = out.len() - distance;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
        }
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

        if distance == 0 || distance > out.len() {
            return Err(Error::InvalidData("lzsa2: bad match offset"));
        }
        if out.len() + len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        let start = out.len() - distance;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode data as an LZSA stream using LZSA1 blocks.
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with(input, false)
}

/// Encode data as an LZSA stream using LZSA2 blocks.
pub fn encode_lzsa2(input: &[u8]) -> Vec<u8> {
    encode_with(input, true)
}

fn encode_with(input: &[u8], level2: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + input.len() / 8);
    out.extend_from_slice(&MAGIC);
    out.push(if level2 { 1 << 5 } else { 0 });
    // Frames of up to 64 KiB of decompressed data; a frame's match
    // offsets may reach back into earlier frames.
    let mut frame_start = 0usize;
    while frame_start < input.len() {
        let frame_end = (frame_start + 0x10000).min(input.len());
        let block = if level2 {
            encode_lzsa2_block(&input[..frame_end], frame_start, false)
        } else {
            encode_lzsa1_block(&input[..frame_end], frame_start, false)
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
fn encode_lzsa1_block(window: &[u8], block_start: usize, eod: bool) -> Option<Vec<u8>> {
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

fn encode_lzsa2_block(window: &[u8], block_start: usize, eod: bool) -> Option<Vec<u8>> {
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
}
