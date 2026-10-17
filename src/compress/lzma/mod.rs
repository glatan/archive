//! LZMA compression and decompression core.
//!
//! Implements the shared LZMA algorithm used by lzip, xz, lrzip, zip method 14,
//! squashfs (LZMA1), erofs (MicroLZMA), and 7z-style paths.
//!
//! The default configuration matches lzip (`lc=3, lp=0, pb=2`), but the
//! core can also decode and encode other valid property combinations.
//!
//! Format definition: LZMA SDK `lzma-specification.txt` (public domain).
//! The range coder follows the public-domain Subbotin carry-less design
//! (`util::range_coder`). See THIRD_PARTY_NOTICES.

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::range_coder::{PROB_INIT, RangeDecoder, RangeEncoder};

// ── LZMA constants ────────────────────────────────────────────────────────

const MAX_LC_LP: usize = 4;
const MAX_PB: usize = 4;
const MAX_POS_STATES: usize = 1 << MAX_PB; // 16
const MAX_LIT_CODERS: usize = 1 << MAX_LC_LP; // 16
const LIT_CODER_SIZE: usize = 0x300; // 768

const NUM_STATES: usize = 12;
const NUM_LEN_TO_POS_STATES: usize = 4;
const NUM_DIST_SLOTS: usize = 64;
const NUM_ALIGN_BITS: u32 = 4;
const NUM_ALIGN: usize = 1 << NUM_ALIGN_BITS; // 16
const END_POS_MODEL_INDEX: usize = 14;

/// Minimum match length in LZMA.
const MATCH_MIN_LEN: usize = 2;

/// Maximum match length in LZMA.
const MATCH_MAX_LEN: usize = 273;

/// LZMA literal/position properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LzmaProperties {
    /// Number of literal context bits.
    pub lc: u8,
    /// Number of literal position bits.
    pub lp: u8,
    /// Number of position bits.
    pub pb: u8,
}

impl LzmaProperties {
    /// The canonical lzip property tuple.
    pub const LZIP: Self = Self {
        lc: 3,
        lp: 0,
        pb: 2,
    };

    /// Validate the property tuple.
    pub const fn is_valid(self) -> bool {
        (self.lc as usize + self.lp as usize) <= MAX_LC_LP && (self.pb as usize) <= MAX_PB
    }

    /// Decode an LZMA properties byte.
    pub(crate) const fn from_props_byte(props_byte: u8) -> Result<Self, Error> {
        let lc = props_byte % 9;
        let rem = props_byte / 9;
        let lp = rem % 5;
        let pb = rem / 5;
        let props = Self { lc, lp, pb };
        if !props.is_valid() {
            return Err(Error::InvalidData("lzma: invalid properties"));
        }
        Ok(props)
    }

    /// Encode an LZMA properties byte.
    pub(crate) const fn to_props_byte(self) -> u8 {
        (self.pb * 5 + self.lp) * 9 + self.lc
    }

    #[inline]
    const fn pos_state_mask(self) -> usize {
        (1usize << self.pb as usize) - 1
    }
}

// ── State transitions ────────────────────────────────────────────────────

#[inline]
const fn state_after_literal(state: usize) -> usize {
    if state < 4 {
        0
    } else if state < 10 {
        state - 3
    } else {
        state - 6
    }
}

#[inline]
const fn state_after_match(state: usize) -> usize {
    if state < 7 { 7 } else { 10 }
}

#[inline]
const fn state_after_rep(state: usize) -> usize {
    if state < 7 { 8 } else { 11 }
}

#[inline]
const fn state_after_short_rep(state: usize) -> usize {
    if state < 7 { 9 } else { 11 }
}

#[inline]
const fn state_is_literal(state: usize) -> bool {
    state < 7
}

// ── Length coder probabilities ───────────────────────────────────────────

struct LenProbs {
    choice: u16,
    choice2: u16,
    low: [[u16; 8]; MAX_POS_STATES],
    mid: [[u16; 8]; MAX_POS_STATES],
    high: [u16; 256],
}

impl LenProbs {
    const fn new() -> Self {
        Self {
            choice: PROB_INIT,
            choice2: PROB_INIT,
            low: [[PROB_INIT; 8]; MAX_POS_STATES],
            mid: [[PROB_INIT; 8]; MAX_POS_STATES],
            high: [PROB_INIT; 256],
        }
    }

    fn decode(&mut self, rc: &mut RangeDecoder, pos_state: usize) -> Result<u32, Error> {
        if rc.decode_bit(&mut self.choice)? == 0 {
            return rc.decode_bit_tree(&mut self.low[pos_state], 3);
        }
        if rc.decode_bit(&mut self.choice2)? == 0 {
            return Ok(8 + rc.decode_bit_tree(&mut self.mid[pos_state], 3)?);
        }
        Ok(16 + rc.decode_bit_tree(&mut self.high, 8)?)
    }

    fn encode(&mut self, rc: &mut RangeEncoder, pos_state: usize, len: u32) {
        if len < 8 {
            rc.encode_bit(&mut self.choice, 0);
            rc.encode_bit_tree(&mut self.low[pos_state], 3, len);
        } else if len < 16 {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 0);
            rc.encode_bit_tree(&mut self.mid[pos_state], 3, len - 8);
        } else {
            rc.encode_bit(&mut self.choice, 1);
            rc.encode_bit(&mut self.choice2, 1);
            rc.encode_bit_tree(&mut self.high, 8, len - 16);
        }
    }
}

// ── Distance special probabilities ──────────────────────────────────────

/// Number of context-coded distance bits for slots 4..END_POS_MODEL_INDEX.
/// Slot k uses (k >> 1) - 1 bits. Total probs needed:
/// Sum over k=4..13 of 2^((k>>1)-1) = 2+2+4+4+8+8+16+16+32+32 = 124
/// But we index by (base_offset + tree_index), where base for slot k is
/// the cumulative count. We use a flat array indexed by
/// slot_base[slot - 4] .. slot_base[slot - 4] + (1 << num_bits).
const DIST_SPECIAL_SIZE: usize = 128; // slight over-allocation for simplicity

fn dist_slot_base(slot: usize) -> usize {
    // For slots 4..14, base position = slot - (isOdd ? 3 : 2)
    // Actually we compute: ((2 | (slot & 1)) << num_bits) - slot
    // It's simpler to just use: slot itself as distance base minus 2.
    // The flat array maps slot k -> offset = k - 2 - (1 << ((k>>1)-1))
    // Let's use a direct approach: for slot k, num_bits = (k>>1)-1,
    // dist_base_in_array = sum of (1<<((j>>1)-1)) for j=4..k-1
    let mut base = 0;
    for j in 4..slot {
        base += 1usize << ((j >> 1) - 1);
    }
    base
}

// ── LZMA Probability Model ──────────────────────────────────────────────

struct LzmaModel {
    is_match: [[u16; MAX_POS_STATES]; NUM_STATES],
    is_rep: [u16; NUM_STATES],
    is_rep_g0: [u16; NUM_STATES],
    is_rep_g1: [u16; NUM_STATES],
    is_rep_g2: [u16; NUM_STATES],
    is_rep0_long: [[u16; MAX_POS_STATES]; NUM_STATES],
    literal: [[u16; LIT_CODER_SIZE]; MAX_LIT_CODERS],
    len_dec: LenProbs,
    rep_len_dec: LenProbs,
    dist_slot: [[u16; NUM_DIST_SLOTS]; NUM_LEN_TO_POS_STATES],
    dist_special: [u16; DIST_SPECIAL_SIZE],
    dist_align: [u16; NUM_ALIGN],
}

impl LzmaModel {
    const fn new() -> Self {
        Self {
            is_match: [[PROB_INIT; MAX_POS_STATES]; NUM_STATES],
            is_rep: [PROB_INIT; NUM_STATES],
            is_rep_g0: [PROB_INIT; NUM_STATES],
            is_rep_g1: [PROB_INIT; NUM_STATES],
            is_rep_g2: [PROB_INIT; NUM_STATES],
            is_rep0_long: [[PROB_INIT; MAX_POS_STATES]; NUM_STATES],
            literal: [[PROB_INIT; LIT_CODER_SIZE]; MAX_LIT_CODERS],
            len_dec: LenProbs::new(),
            rep_len_dec: LenProbs::new(),
            dist_slot: [[PROB_INIT; NUM_DIST_SLOTS]; NUM_LEN_TO_POS_STATES],
            dist_special: [PROB_INIT; DIST_SPECIAL_SIZE],
            dist_align: [PROB_INIT; NUM_ALIGN],
        }
    }
}

// ── Literal coding helpers ──────────────────────────────────────────────

const fn get_literal_context(prev_byte: u8, pos: usize, props: LzmaProperties) -> usize {
    let hi = if props.lc == 0 {
        0
    } else {
        (prev_byte as usize) >> (8 - props.lc as usize)
    };
    let lo = if props.lp == 0 {
        0
    } else {
        (pos & ((1 << props.lp as usize) - 1)) << props.lc as usize
    };
    hi | lo
}

fn decode_literal(
    rc: &mut RangeDecoder,
    probs: &mut [u16; LIT_CODER_SIZE],
    is_match_context: bool,
    match_byte: u8,
) -> Result<u8, Error> {
    let mut symbol = 1u32;

    if is_match_context {
        let mut mb = match_byte as u32;
        loop {
            mb <<= 1;
            let match_bit = (mb >> 8) & 1;
            let offset = ((1 + match_bit) << 8) + symbol;
            let bit = rc.decode_bit(&mut probs[offset as usize])?;
            symbol = (symbol << 1) | bit;
            if symbol >= 0x100 {
                break;
            }
            if match_bit != bit {
                // Once bits diverge, decode remaining without match context
                while symbol < 0x100 {
                    let b = rc.decode_bit(&mut probs[symbol as usize])?;
                    symbol = (symbol << 1) | b;
                }
                break;
            }
        }
    } else {
        while symbol < 0x100 {
            let bit = rc.decode_bit(&mut probs[symbol as usize])?;
            symbol = (symbol << 1) | bit;
        }
    }

    Ok(symbol as u8)
}

fn encode_literal(
    rc: &mut RangeEncoder,
    probs: &mut [u16; LIT_CODER_SIZE],
    is_match_context: bool,
    match_byte: u8,
    byte: u8,
) {
    let mut symbol = 1u32;
    let byte_val = byte as u32;

    if is_match_context {
        let mut mb = match_byte as u32;
        for i in (0..8).rev() {
            mb <<= 1;
            let match_bit = (mb >> 8) & 1;
            let bit = (byte_val >> i) & 1;
            let offset = ((1 + match_bit) << 8) + symbol;
            rc.encode_bit(&mut probs[offset as usize], bit);
            symbol = (symbol << 1) | bit;
            if match_bit != bit {
                // Once diverged, encode remaining without match context
                for j in (0..i).rev() {
                    let b = (byte_val >> j) & 1;
                    rc.encode_bit(&mut probs[symbol as usize], b);
                    symbol = (symbol << 1) | b;
                }
                break;
            }
        }
    } else {
        for i in (0..8).rev() {
            let bit = (byte_val >> i) & 1;
            rc.encode_bit(&mut probs[symbol as usize], bit);
            symbol = (symbol << 1) | bit;
        }
    }
}

// ── Distance coding helpers ─────────────────────────────────────────────

const fn get_len_to_pos_state(len: usize) -> usize {
    let len = len - MATCH_MIN_LEN;
    if len < NUM_LEN_TO_POS_STATES {
        len
    } else {
        NUM_LEN_TO_POS_STATES - 1
    }
}

fn decode_distance(rc: &mut RangeDecoder, model: &mut LzmaModel, len: usize) -> Result<u32, Error> {
    let lps = get_len_to_pos_state(len);
    let slot = rc.decode_bit_tree(&mut model.dist_slot[lps], 6)? as usize;

    if slot < 4 {
        return Ok(slot as u32);
    }

    let num_direct_bits = ((slot >> 1) - 1) as u32;
    let mut dist = ((2 | (slot & 1)) as u32) << num_direct_bits;

    if slot < END_POS_MODEL_INDEX {
        let base = dist_slot_base(slot);
        dist += rc.decode_reverse_bit_tree(&mut model.dist_special[base..], num_direct_bits)?;
    } else {
        dist += rc.decode_direct_bits(num_direct_bits - NUM_ALIGN_BITS)? << NUM_ALIGN_BITS;
        dist += rc.decode_reverse_bit_tree(&mut model.dist_align, NUM_ALIGN_BITS)?;
    }

    Ok(dist)
}

fn encode_distance(rc: &mut RangeEncoder, model: &mut LzmaModel, len: usize, dist: u32) {
    let lps = get_len_to_pos_state(len);
    let slot = distance_to_slot(dist);

    rc.encode_bit_tree(&mut model.dist_slot[lps], 6, slot as u32);

    if slot >= 4 {
        let num_direct_bits = ((slot >> 1) - 1) as u32;
        let base_dist = ((2 | (slot & 1)) as u32) << num_direct_bits;
        let extra = dist - base_dist;

        if slot < END_POS_MODEL_INDEX {
            let base = dist_slot_base(slot);
            rc.encode_reverse_bit_tree(&mut model.dist_special[base..], num_direct_bits, extra);
        } else {
            rc.encode_direct_bits(extra >> NUM_ALIGN_BITS, num_direct_bits - NUM_ALIGN_BITS);
            rc.encode_reverse_bit_tree(&mut model.dist_align, NUM_ALIGN_BITS, extra & 0xF);
        }
    }
}

const fn distance_to_slot(dist: u32) -> usize {
    if dist < 4 {
        return dist as usize;
    }
    let bits = 32 - dist.leading_zeros() as usize; // floor(log2(dist)) + 1

    (bits - 1) * 2 + ((dist >> (bits - 2)) & 1) as usize
}

// ── Public decode/encode API ─────────────────────────────────────────────

/// Decode an LZMA stream (as used in lzip).
///
/// Returns `(decoded_data, bytes_consumed)`.
pub(crate) fn lzma_decode(data: &[u8], dict_size: u32) -> Result<(Vec<u8>, usize), Error> {
    lzma_decode_with_props(data, dict_size, LzmaProperties::LZIP)
}

/// Decode an LZMA stream with an explicit property tuple.
pub(crate) fn lzma_decode_with_props(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
) -> Result<(Vec<u8>, usize), Error> {
    let mut decoder_state = LzmaDecoderState::new();
    lzma_decode_impl(data, dict_size, props, None, &[], &mut decoder_state)
}

/// Decode an LZMA stream with an explicit property tuple and expected output size.
///
/// This is used by raw-LZMA containers like 7z that terminate the stream via an
/// externally known unpack size instead of an in-band EOS marker.
#[cfg_attr(not(feature = "sevenz"), allow(dead_code))]
pub(crate) fn lzma_decode_with_props_and_size(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
    expected_size: usize,
) -> Result<(Vec<u8>, usize), Error> {
    lzma_decode_with_props_and_size_and_history(data, dict_size, props, expected_size, &[])
}

/// Decode an LZMA stream with an explicit property tuple, output size, and seed history.
///
/// `history` seeds the dictionary window and must contain the *entire* output
/// produced since the last dictionary reset — not just the trailing
/// `dict_size` bytes. Position-dependent contexts (pos_state, literal lp
/// bits) count uncompressed bytes since the reset, and the absolute position
/// is derived from `history.len()`; a trimmed history desynchronizes the
/// range coder. The returned vector contains only the bytes decoded from
/// `data`, not the seed history.
pub(crate) fn lzma_decode_with_props_and_size_and_history(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
    expected_size: usize,
    history: &[u8],
) -> Result<(Vec<u8>, usize), Error> {
    let mut decoder_state = LzmaDecoderState::new();
    lzma_decode_with_props_and_size_and_history_and_state(
        data,
        dict_size,
        props,
        expected_size,
        history,
        &mut decoder_state,
    )
}

/// Variant of [`lzma_decode_with_props_and_size_and_history`] that reuses the
/// range-coder models across chunk calls. `history` must likewise contain the
/// entire output since the last dictionary reset.
pub(crate) fn lzma_decode_with_props_and_size_and_history_and_state(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
    expected_size: usize,
    history: &[u8],
    decoder_state: &mut LzmaDecoderState,
) -> Result<(Vec<u8>, usize), Error> {
    lzma_decode_impl(
        data,
        dict_size,
        props,
        Some(expected_size),
        history,
        decoder_state,
    )
}

fn lzma_decode_impl(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
    expected_size: Option<usize>,
    history: &[u8],
    decoder_state: &mut LzmaDecoderState,
) -> Result<(Vec<u8>, usize), Error> {
    if !props.is_valid() {
        return Err(Error::InvalidData("lzma: invalid properties"));
    }
    if let Some(limit) = expected_size
        && limit > crate::util::bounded::DECLARED_OUTPUT_LIMIT
    {
        return Err(Error::OutputLimitExceeded {
            limit: crate::util::bounded::DECLARED_OUTPUT_LIMIT,
        });
    }

    let mut rc = RangeDecoder::new(data)?;
    let model = &mut decoder_state.model;

    let dict_size = dict_size as usize;
    let history_len = history.len().min(dict_size);
    // `output` only keeps the tail of `history`, but position contexts
    // (pos_state / literal lp bits) count uncompressed bytes since the last
    // dictionary reset, so index math must use the untrimmed position.
    let pos_base = history.len() - history_len;
    // The capacity hint is clamped: a corrupt container can declare an
    // astronomical unpack size, and `with_capacity` must not overflow
    // or abort on it. The Vec still grows on demand.
    let mut output =
        Vec::with_capacity(history_len.saturating_add(expected_size.unwrap_or(0).min(1 << 24)));
    output.extend_from_slice(&history[history.len().saturating_sub(history_len)..]);

    let mut state = decoder_state.state;
    let mut rep0 = decoder_state.rep0;
    let mut rep1 = decoder_state.rep1;
    let mut rep2 = decoder_state.rep2;
    let mut rep3 = decoder_state.rep3;

    let mut saw_eos = false;

    loop {
        if let Some(limit) = expected_size {
            let decoded_len = output.len() - history_len;
            if decoded_len == limit {
                break;
            }
            if decoded_len > limit {
                return Err(Error::InvalidData("lzma: decoded past expected size"));
            }
        }

        let pos_state = (pos_base + output.len()) & props.pos_state_mask();

        if rc.decode_bit(&mut model.is_match[state][pos_state])? == 0 {
            // ── Literal ──
            let prev_byte = if output.is_empty() {
                0
            } else {
                output[output.len() - 1]
            };
            let ctx = get_literal_context(prev_byte, pos_base + output.len(), props);
            let is_mc = !state_is_literal(state);
            let match_byte = if is_mc && !output.is_empty() && (rep0 as usize) < output.len() {
                output[output.len() - 1 - rep0 as usize]
            } else {
                0
            };
            let byte = decode_literal(&mut rc, &mut model.literal[ctx], is_mc, match_byte)?;
            output.push(byte);
            state = state_after_literal(state);
        } else if rc.decode_bit(&mut model.is_rep[state])? == 0 {
            // ── Match (new distance) ──
            let len = model.len_dec.decode(&mut rc, pos_state)? as usize + MATCH_MIN_LEN;
            let dist = decode_distance(&mut rc, model, len)?;

            // EOS marker: distance = 0xFFFFFFFF, length = MATCH_MIN_LEN
            if dist == 0xFFFF_FFFF {
                if len != MATCH_MIN_LEN {
                    return Err(Error::InvalidData("lzma: invalid EOS marker"));
                }
                saw_eos = true;
                break;
            }

            rep3 = rep2;
            rep2 = rep1;
            rep1 = rep0;
            rep0 = dist;

            // lzip manual 6.2: distances range from 0 to dict_size - 1,
            // and a distance of position references a virtual zero byte
            // preceding the first output byte.
            if rep0 as usize > output.len() || rep0 as usize >= dict_size {
                return Err(Error::InvalidData("lzma: distance out of range"));
            }

            let distance = rep0 as usize + 1;
            for _ in 0..len {
                let idx = output.len().wrapping_sub(distance);
                output.push(if idx == usize::MAX { 0 } else { output[idx] });
            }
            state = state_after_match(state);
        } else if rc.decode_bit(&mut model.is_rep_g0[state])? == 0 {
            if rc.decode_bit(&mut model.is_rep0_long[state][pos_state])? == 0 {
                // ── ShortRep (rep0, length=1) ──
                if rep0 as usize > output.len() || rep0 as usize >= dict_size {
                    return Err(Error::InvalidData("lzma: distance out of range"));
                }
                let idx = output.len().wrapping_sub(rep0 as usize + 1);
                output.push(if idx == usize::MAX { 0 } else { output[idx] });
                state = state_after_short_rep(state);
            } else {
                // ── LongRep0 ──
                let len = model.rep_len_dec.decode(&mut rc, pos_state)? as usize + MATCH_MIN_LEN;
                if rep0 as usize > output.len() || rep0 as usize >= dict_size {
                    return Err(Error::InvalidData("lzma: distance out of range"));
                }
                let distance = rep0 as usize + 1;
                for _ in 0..len {
                    let idx = output.len().wrapping_sub(distance);
                    output.push(if idx == usize::MAX { 0 } else { output[idx] });
                }
                state = state_after_rep(state);
            }
        } else {
            let dist;
            if rc.decode_bit(&mut model.is_rep_g1[state])? == 0 {
                // ── LongRep1 ──
                dist = rep1;
                rep1 = rep0;
            } else if rc.decode_bit(&mut model.is_rep_g2[state])? == 0 {
                // ── LongRep2 ──
                dist = rep2;
                rep2 = rep1;
                rep1 = rep0;
            } else {
                // ── LongRep3 ──
                dist = rep3;
                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
            }
            rep0 = dist;

            let len = model.rep_len_dec.decode(&mut rc, pos_state)? as usize + MATCH_MIN_LEN;
            if rep0 as usize > output.len() || rep0 as usize >= dict_size {
                return Err(Error::InvalidData("lzma: distance out of range"));
            }
            let distance = rep0 as usize + 1;
            for _ in 0..len {
                let idx = output.len().wrapping_sub(distance);
                output.push(if idx == usize::MAX { 0 } else { output[idx] });
            }
            state = state_after_rep(state);
        }
    }

    if let Some(limit) = expected_size {
        if output.len() - history_len != limit {
            return Err(Error::UnexpectedEof);
        }
    } else if !saw_eos {
        return Err(Error::InvalidData("lzma: missing EOS marker"));
    }

    // Verify range coder finished cleanly for EOS-terminated streams.
    if expected_size.is_none() && !rc.is_finished() {
        return Err(Error::InvalidData("lzma: range coder not finished cleanly"));
    }

    decoder_state.state = state;
    decoder_state.rep0 = rep0;
    decoder_state.rep1 = rep1;
    decoder_state.rep2 = rep2;
    decoder_state.rep3 = rep3;

    let consumed = rc.position();
    Ok((output[history_len..].to_vec(), consumed))
}

pub(crate) struct LzmaDecoderState {
    model: LzmaModel,
    state: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
}

impl LzmaDecoderState {
    pub(crate) const fn new() -> Self {
        Self {
            model: LzmaModel::new(),
            state: 0,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
        }
    }

    pub(crate) const fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Encode data as an LZMA stream (as used in lzip).
///
/// Returns the LZMA byte stream including the leading 0x00 byte.
pub(crate) fn lzma_encode(data: &[u8], dict_size: u32) -> Vec<u8> {
    lzma_encode_with_props(data, dict_size, LzmaProperties::LZIP)
}

/// Encode an LZMA stream with an explicit property tuple.
pub(crate) fn lzma_encode_with_props(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
) -> Vec<u8> {
    lzma_encode_with_props_inner(data, dict_size, props, true)
}

/// Encode a size-terminated raw LZMA stream for containers like LZMA2.
pub(crate) fn lzma_encode_with_props_no_eos(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
) -> Vec<u8> {
    lzma_encode_with_props_inner(data, dict_size, props, false)
}

fn lzma_encode_with_props_inner(
    data: &[u8],
    dict_size: u32,
    props: LzmaProperties,
    emit_eos: bool,
) -> Vec<u8> {
    debug_assert!(
        props.is_valid(),
        "lzma properties must satisfy lc+lp<=4 and pb<=4"
    );

    let mut rc = RangeEncoder::new();
    let mut model = LzmaModel::new();

    let mut state = 0usize;
    let mut rep0 = 0u32;
    let mut rep1 = 0u32;
    let mut rep2 = 0u32;
    let mut rep3 = 0u32;

    let dict_size_usize = dict_size as usize;
    let mut pos = 0usize;

    while pos < data.len() {
        let pos_state = pos & props.pos_state_mask();

        // Try to find a match using a simple hash-based approach
        let best = find_match(data, pos, dict_size_usize, rep0, rep1, rep2, rep3);

        match best {
            MatchResult::Literal => {
                rc.encode_bit(&mut model.is_match[state][pos_state], 0);
                let prev_byte = if pos == 0 { 0 } else { data[pos - 1] };
                let ctx = get_literal_context(prev_byte, pos, props);
                let is_mc = !state_is_literal(state);
                let match_byte = if is_mc && pos > 0 && (rep0 as usize) < pos {
                    data[pos - 1 - rep0 as usize]
                } else {
                    0
                };
                encode_literal(
                    &mut rc,
                    &mut model.literal[ctx],
                    is_mc,
                    match_byte,
                    data[pos],
                );
                state = state_after_literal(state);
                pos += 1;
            }
            MatchResult::ShortRep => {
                rc.encode_bit(&mut model.is_match[state][pos_state], 1);
                rc.encode_bit(&mut model.is_rep[state], 1);
                rc.encode_bit(&mut model.is_rep_g0[state], 0);
                rc.encode_bit(&mut model.is_rep0_long[state][pos_state], 0);
                state = state_after_short_rep(state);
                pos += 1;
            }
            MatchResult::Rep { rep_index, len } => {
                rc.encode_bit(&mut model.is_match[state][pos_state], 1);
                rc.encode_bit(&mut model.is_rep[state], 1);

                match rep_index {
                    0 => {
                        rc.encode_bit(&mut model.is_rep_g0[state], 0);
                        rc.encode_bit(&mut model.is_rep0_long[state][pos_state], 1);
                    }
                    1 => {
                        rc.encode_bit(&mut model.is_rep_g0[state], 1);
                        rc.encode_bit(&mut model.is_rep_g1[state], 0);
                        core::mem::swap(&mut rep1, &mut rep0);
                    }
                    2 => {
                        rc.encode_bit(&mut model.is_rep_g0[state], 1);
                        rc.encode_bit(&mut model.is_rep_g1[state], 1);
                        rc.encode_bit(&mut model.is_rep_g2[state], 0);
                        let tmp = rep2;
                        rep2 = rep1;
                        rep1 = rep0;
                        rep0 = tmp;
                    }
                    _ => {
                        rc.encode_bit(&mut model.is_rep_g0[state], 1);
                        rc.encode_bit(&mut model.is_rep_g1[state], 1);
                        rc.encode_bit(&mut model.is_rep_g2[state], 1);
                        let tmp = rep3;
                        rep3 = rep2;
                        rep2 = rep1;
                        rep1 = rep0;
                        rep0 = tmp;
                    }
                }

                let enc_len = (len - MATCH_MIN_LEN) as u32;
                model.rep_len_dec.encode(&mut rc, pos_state, enc_len);
                state = state_after_rep(state);
                pos += len;
            }
            MatchResult::Match { dist, len } => {
                rc.encode_bit(&mut model.is_match[state][pos_state], 1);
                rc.encode_bit(&mut model.is_rep[state], 0);

                let enc_len = (len - MATCH_MIN_LEN) as u32;
                model.len_dec.encode(&mut rc, pos_state, enc_len);
                encode_distance(&mut rc, &mut model, len, dist);

                rep3 = rep2;
                rep2 = rep1;
                rep1 = rep0;
                rep0 = dist;
                state = state_after_match(state);
                pos += len;
            }
        }
    }

    if emit_eos {
        // Emit EOS marker: match with distance=0xFFFFFFFF, length=MATCH_MIN_LEN
        let pos_state = pos & props.pos_state_mask();
        rc.encode_bit(&mut model.is_match[state][pos_state], 1);
        rc.encode_bit(&mut model.is_rep[state], 0);
        model.len_dec.encode(&mut rc, pos_state, 0);
        let lps = get_len_to_pos_state(MATCH_MIN_LEN);
        rc.encode_bit_tree(&mut model.dist_slot[lps], 6, 63);
        let extra = 0x3FFF_FFFFu32;
        rc.encode_direct_bits(extra >> NUM_ALIGN_BITS, 30 - NUM_ALIGN_BITS);
        rc.encode_reverse_bit_tree(&mut model.dist_align, NUM_ALIGN_BITS, extra & 0xF);
    }

    let rc_data = rc.finish();

    // Prepend the 0x00 byte
    let mut result = Vec::with_capacity(1 + rc_data.len());
    result.push(0x00);
    result.extend_from_slice(&rc_data);
    result
}

// ── Match finding ────────────────────────────────────────────────────────

enum MatchResult {
    Literal,
    ShortRep,
    Rep { rep_index: usize, len: usize },
    Match { dist: u32, len: usize },
}

/// Simple match finder: check rep distances first, then use a hash lookup.
fn find_match(
    data: &[u8],
    pos: usize,
    dict_size: usize,
    rep0: u32,
    rep1: u32,
    rep2: u32,
    rep3: u32,
) -> MatchResult {
    let remaining = data.len() - pos;
    if remaining == 0 {
        return MatchResult::Literal;
    }

    // Check rep matches
    let reps = [rep0, rep1, rep2, rep3];
    let mut best_rep_idx = None;
    let mut best_rep_len = 0usize;

    for (idx, &rep) in reps.iter().enumerate() {
        let dist = rep as usize;
        if dist >= pos || dist >= dict_size {
            continue;
        }
        let start = pos - dist - 1;
        let max_len = remaining.min(MATCH_MAX_LEN);
        let mut len = 0;
        while len < max_len && data[start + len] == data[pos + len] {
            len += 1;
        }
        if len > best_rep_len {
            best_rep_len = len;
            best_rep_idx = Some(idx);
        }
    }

    // ShortRep: rep0, length 1
    if best_rep_idx == Some(0) && (1..MATCH_MIN_LEN).contains(&best_rep_len) {
        return MatchResult::ShortRep;
    }

    // Rep match with sufficient length
    if best_rep_len >= MATCH_MIN_LEN {
        if best_rep_idx == Some(0) && best_rep_len == 1 {
            return MatchResult::ShortRep;
        }
        return MatchResult::Rep {
            rep_index: best_rep_idx.unwrap(),
            len: best_rep_len,
        };
    }

    // Try to find a new match using simple hash lookup
    if remaining < MATCH_MIN_LEN {
        // Check if ShortRep is available (rep0, length 1)
        if rep0 < pos as u32 && (rep0 as usize) < dict_size {
            let dist = rep0 as usize;
            if data[pos - dist - 1] == data[pos] {
                return MatchResult::ShortRep;
            }
        }
        return MatchResult::Literal;
    }

    // Simple 3-byte hash match finding
    let max_search_dist = pos.min(dict_size);
    let max_len = remaining.min(MATCH_MAX_LEN);

    let mut best_dist = 0u32;
    let mut best_len = 0usize;

    // Search backwards through the window for matches
    let search_limit = max_search_dist.min(4096); // limit search depth
    for offset in 1..=search_limit {
        let start = pos - offset;
        if data[start] != data[pos] || data[start + 1] != data[pos + 1] {
            continue;
        }
        let mut len = 2;
        while len < max_len && data[start + len] == data[pos + len] {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_dist = (offset - 1) as u32;
            if len >= 32 {
                break; // good enough
            }
        }
    }

    if best_len >= MATCH_MIN_LEN {
        // Prefer rep match over new match if similar length
        if best_rep_len >= MATCH_MIN_LEN && best_rep_len >= best_len {
            return MatchResult::Rep {
                rep_index: best_rep_idx.unwrap(),
                len: best_rep_len,
            };
        }
        return MatchResult::Match {
            dist: best_dist,
            len: best_len,
        };
    }

    // Check ShortRep
    if rep0 < pos as u32 && (rep0 as usize) < dict_size {
        let dist = rep0 as usize;
        if data[pos - dist - 1] == data[pos] {
            return MatchResult::ShortRep;
        }
    }

    MatchResult::Literal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_with_size_rejects_declared_output_above_limit() {
        let err = lzma_decode_with_props_and_size(&[], 4096, LzmaProperties::LZIP, (1 << 30) + 1)
            .unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
    }

    #[test]
    fn test_lzip_properties_constant() {
        let props = LzmaProperties::LZIP;
        assert_eq!(props.lc, 3);
        assert_eq!(props.lp, 0);
        assert_eq!(props.pb, 2);
        assert_eq!(props.to_props_byte(), 93);
        assert_eq!(LzmaProperties::from_props_byte(93).unwrap(), props);
    }

    #[test]
    fn test_lzma_roundtrip_empty() {
        let data = b"";
        let encoded = lzma_encode(data, 4096);
        let (decoded, _) = lzma_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_roundtrip_hello() {
        let data = b"Hello, World!";
        let encoded = lzma_encode(data, 4096);
        let (decoded, _) = lzma_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_roundtrip_repeated() {
        let data = b"abcabcabcabcabcabc";
        let encoded = lzma_encode(data, 4096);
        let (decoded, _) = lzma_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = lzma_encode(&data, 4096);
        let (decoded, _) = lzma_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_roundtrip_long_runs() {
        let mut data = Vec::new();
        for b in 0..10u8 {
            for _ in 0..100 {
                data.push(b);
            }
        }
        let encoded = lzma_encode(&data, 8192);
        let (decoded, _) = lzma_decode(&encoded, 8192).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_roundtrip_1kb() {
        let data: Vec<u8> = (0..1024).map(|i| (i * 37 % 256) as u8).collect();
        let encoded = lzma_encode(&data, 65536);
        let (decoded, _) = lzma_decode(&encoded, 65536).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_distance_to_slot() {
        // Slots 0-3: direct mapping
        assert_eq!(distance_to_slot(0), 0);
        assert_eq!(distance_to_slot(1), 1);
        assert_eq!(distance_to_slot(2), 2);
        assert_eq!(distance_to_slot(3), 3);
        // Slot 4: dists 4-5 (1 extra bit, base=4)
        assert_eq!(distance_to_slot(4), 4);
        assert_eq!(distance_to_slot(5), 4);
        // Slot 5: dists 6-7 (1 extra bit, base=6)
        assert_eq!(distance_to_slot(6), 5);
        assert_eq!(distance_to_slot(7), 5);
        // Slot 6: dists 8-11 (2 extra bits, base=8)
        assert_eq!(distance_to_slot(8), 6);
        assert_eq!(distance_to_slot(11), 6);
        // Slot 7: dists 12-15 (2 extra bits, base=12)
        assert_eq!(distance_to_slot(12), 7);
        assert_eq!(distance_to_slot(15), 7);
    }

    #[test]
    fn test_state_transitions() {
        assert_eq!(state_after_literal(0), 0);
        assert_eq!(state_after_literal(4), 1);
        assert_eq!(state_after_literal(10), 4);
        assert_eq!(state_after_match(0), 7);
        assert_eq!(state_after_match(7), 10);
        assert_eq!(state_after_rep(0), 8);
        assert_eq!(state_after_rep(7), 11);
        assert_eq!(state_after_short_rep(0), 9);
        assert_eq!(state_after_short_rep(7), 11);
    }

    #[test]
    fn test_max_match_length_273() {
        // Create data that forces a match of maximum length 273 bytes.
        // Write a 273-byte pattern, then repeat it so the encoder finds
        // a full MATCH_MAX_LEN match.
        let pattern: Vec<u8> = (0..273).map(|i| (i * 41 % 256) as u8).collect();
        let mut data = Vec::new();
        data.extend_from_slice(&pattern);
        data.extend_from_slice(&pattern); // exact repeat triggers max-length match
        let encoded = lzma_encode(&data, 65536);
        let (decoded, _) = lzma_decode(&encoded, 65536).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_min_match_length_2() {
        // Create data that exercises minimum match length of 2 bytes.
        // Short two-byte patterns repeated with different bytes in between
        // so matches are only length 2.
        let mut data = Vec::new();
        for _ in 0..50 {
            data.extend_from_slice(b"xy");
            data.push(b'z'); // break so match cannot extend beyond 2
        }
        let encoded = lzma_encode(&data, 4096);
        let (decoded, _) = lzma_decode(&encoded, 4096).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lzma_truncated_stream_rejected() {
        let data = b"abracadabra abracadabra abracadabra abracadabra";
        let mut encoded = lzma_encode(data, 4096);
        encoded.truncate(encoded.len().saturating_sub(4));

        let result = lzma_decode(&encoded, 4096);
        assert!(
            matches!(
                result,
                Err(Error::UnexpectedEof) | Err(Error::InvalidData(_))
            ),
            "expected truncated-stream error, got {result:?}"
        );
    }

    #[test]
    fn test_from_props_byte_rejects_lc_plus_lp_greater_than_4() {
        // props_byte = (pb * 5 + lp) * 9 + lc
        // lc=4, lp=1, pb=0 → byte = (0*5 + 1)*9 + 4 = 13 → lc+lp = 5 > MAX_LC_LP
        assert!(LzmaProperties::from_props_byte(13).is_err());
        // lc=8, lp=0, pb=0 → byte = 8 → lc+lp = 8 > MAX_LC_LP
        assert!(LzmaProperties::from_props_byte(8).is_err());
        // Sanity: lc=4, lp=0, pb=0 → byte = 4 → lc+lp = 4 == MAX_LC_LP → valid
        assert!(LzmaProperties::from_props_byte(4).is_ok());
    }

    #[test]
    fn test_lzma_invalid_eos_marker_wrong_length() {
        let mut rc = RangeEncoder::new();
        let mut model = LzmaModel::new();
        let mut state = 0usize;
        let mut output_len = 0usize;

        let props = LzmaProperties::LZIP;
        let pos_state = output_len & props.pos_state_mask();
        rc.encode_bit(&mut model.is_match[state][pos_state], 0);
        let ctx = get_literal_context(0, output_len, props);
        encode_literal(&mut rc, &mut model.literal[ctx], false, 0, b'A');
        state = state_after_literal(state);
        output_len += 1;

        let pos_state = output_len & props.pos_state_mask();
        rc.encode_bit(&mut model.is_match[state][pos_state], 1);
        rc.encode_bit(&mut model.is_rep[state], 0);
        model.len_dec.encode(&mut rc, pos_state, 1); // len = MATCH_MIN_LEN + 1

        let lps = get_len_to_pos_state(MATCH_MIN_LEN + 1);
        rc.encode_bit_tree(&mut model.dist_slot[lps], 6, 63);
        let extra = 0x3FFF_FFFFu32;
        rc.encode_direct_bits(extra >> NUM_ALIGN_BITS, 30 - NUM_ALIGN_BITS);
        rc.encode_reverse_bit_tree(&mut model.dist_align, NUM_ALIGN_BITS, extra & 0xF);

        let mut encoded = Vec::new();
        encoded.push(0x00);
        encoded.extend_from_slice(&rc.finish());

        let result = lzma_decode(&encoded, 4096);
        assert!(
            matches!(result, Err(Error::InvalidData("lzma: invalid EOS marker"))),
            "expected invalid EOS marker error, got {result:?}"
        );
    }
}

#[test]
fn test_lzma_roundtrip_various_sizes() {
    for size in [0, 1, 10, 50, 100, 200, 274, 500, 1024, 4096] {
        let data: Vec<u8> = (0..size).map(|i: usize| (i * 37 % 256) as u8).collect();
        let encoded = lzma_encode(&data, 65536);
        let (decoded, _) = lzma_decode(&encoded, 65536).unwrap();
        assert_eq!(decoded, data, "roundtrip failed at size {}", size);
    }
}
