//! Context-mixing predictor with 9 component types.
//!
//! The predictor maintains an array of components that each produce
//! a probability prediction.  Components are chained: each can use
//! the output of previous components and the context hashes from
//! the ZPAQL VM.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::zpaql::ZPAQL;

// ── Squash / stretch tables ─────────────────────────────────────

/// Squash: convert a signed log probability (-2048..2047) to a
/// probability (1..65534).  squash(x) = 1/(1 + exp(-x/64)) * 65536.
fn squash(x: i32) -> u32 {
    if x < -2047 {
        return 1;
    }
    if x > 2047 {
        return 65534;
    }
    // Piecewise linear approximation using a lookup table
    let idx = (x + 2048) as usize;
    SQUASH_TABLE[idx.min(SQUASH_TABLE.len() - 1)] as u32
}

/// Stretch: inverse of squash. Convert probability (1..65534) to
/// signed log probability (-2047..2047).
fn stretch(p: u32) -> i32 {
    STRETCH_TABLE[((p >> 6) as usize).min(STRETCH_TABLE.len() - 1)] as i32
}

// ── State table ─────────────────────────────────────────────────

/// State table: maps (state, bit) -> next state.
/// States 0-255 represent the history of bits seen in a context.
/// Each state encodes a count of 0s and 1s.
fn next_state(state: u8, bit: u8) -> u8 {
    STATE_TABLE[state as usize * 2 + bit as usize]
}

/// Return the probability that the next bit is 1 given a state.
fn state_prob(state: u8) -> i32 {
    STATE_PROB_TABLE[state as usize] as i32
}

// ── Component types ─────────────────────────────────────────────

/// Component type identifiers.
const CONS: u8 = 0;
const CM: u8 = 1;
const ICM: u8 = 2;
const MATCH: u8 = 3;
const AVG: u8 = 4;
const MIX2: u8 = 5;
const MIX: u8 = 6;
const ISSE: u8 = 7;
const SSE: u8 = 8;

/// A single predictor component.
pub(crate) struct Component {
    ctype: u8,
    // Context hash index into z.h[]
    context_index: usize,
    // Component-specific memory
    cm_table: Vec<u32>, // CM/ICM context table (maps context -> count/prediction)
    state_table: Vec<u8>, // ICM/ISSE state table
    match_buf: Vec<u8>, // MATCH buffer
    match_pos: u32,     // MATCH current position
    match_len: u32,     // MATCH current match length
    match_ref: u32,     // MATCH reference position
    match_bit: u8,      // MATCH expected bit
    // Mixer weights
    weights: Vec<i32>,
    // Input component indices
    inputs: Vec<usize>,
    // Prediction output
    pub prediction: i32,
    // Table size mask
    mask: u32,
    // SSE/ISSE inner state
    sse_table: Vec<u32>,
    // Limit for CM update rate
    cm_limit: u32,
}

impl Component {
    const fn new() -> Self {
        Self {
            ctype: CONS,
            context_index: 0,
            cm_table: Vec::new(),
            state_table: Vec::new(),
            match_buf: Vec::new(),
            match_pos: 0,
            match_len: 0,
            match_ref: 0,
            match_bit: 0,
            weights: Vec::new(),
            inputs: Vec::new(),
            prediction: 0,
            mask: 0,
            sse_table: Vec::new(),
            cm_limit: 0,
        }
    }
}

/// The predictor manages a chain of components and the ZPAQL VM.
pub(crate) struct Predictor {
    pub components: Vec<Component>,
    pub z: ZPAQL,
    bit_count: u32,
    current_byte: u32,
}

impl Predictor {
    /// Create a new predictor from a model configuration.
    pub fn new(z: ZPAQL, config: &[u8]) -> Self {
        let mut pred = Self {
            components: Vec::new(),
            z,
            bit_count: 0,
            current_byte: 1,
        };
        pred.parse_config(config)
            .expect("crate built-in ZPAQ model configs should be valid");
        pred
    }

    /// Create a predictor from an upstream model configuration, validating
    /// that known component layouts are not truncated.
    pub fn try_new(z: ZPAQL, config: &[u8]) -> Result<Self, Error> {
        let mut pred = Self {
            components: Vec::new(),
            z,
            bit_count: 0,
            current_byte: 1,
        };
        pred.parse_config(config)?;
        Ok(pred)
    }

    /// Update the predictor with the actual bit (0 or 1) for built-in models.
    pub fn update(&mut self, bit: u8) {
        self.try_update(bit)
            .expect("crate built-in ZPAQ HCOMP bytecode should terminate within the cycle limit");
    }

    /// Update the predictor with the actual bit (0 or 1) for upstream models,
    /// propagating HCOMP runtime failures.
    pub fn try_update(&mut self, bit: u8) -> Result<(), Error> {
        self.update_impl(bit)
    }

    fn parse_config(&mut self, config: &[u8]) -> Result<(), Error> {
        const INCOMPLETE_CONFIG: Error =
            Error::InvalidData("zpaq: incomplete component configuration");
        const INVALID_SIZE: Error = Error::InvalidData("zpaq: invalid component size");
        const INVALID_MIX_ARITY: Error = Error::InvalidData("zpaq: invalid mix arity");

        fn next_byte(config: &[u8], pos: &mut usize) -> Result<u8, Error> {
            let byte = *config.get(*pos).ok_or(Error::InvalidData(
                "zpaq: incomplete component configuration",
            ))?;
            *pos += 1;
            Ok(byte)
        }

        fn pow2_size(size_log: usize) -> Result<usize, Error> {
            1usize
                .checked_shl(size_log as u32)
                .ok_or(Error::InvalidData("zpaq: invalid component size"))
        }

        const fn validate_input(input: usize, max_input: usize) -> Result<(), Error> {
            if input >= max_input {
                return Err(Error::InvalidData(
                    "zpaq: invalid component input reference",
                ));
            }
            Ok(())
        }

        let mut pos = 0;

        // Number of components
        let n = next_byte(config, &mut pos)? as usize;

        for _ in 0..n {
            let ctype = next_byte(config, &mut pos)?;

            let mut comp = Component::new();
            comp.ctype = ctype;

            match ctype {
                CONS => {
                    // Constant prediction: next byte is the prediction value
                    comp.prediction = (next_byte(config, &mut pos)? as i32 - 128) * 16;
                }
                CM => {
                    // Context Model: size (log2), limit
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let limit = next_byte(config, &mut pos)? as u32;
                    let size = pow2_size(size_log)?;
                    comp.cm_table = vec![1u32 << 15; size]; // initial p = 0.5
                    comp.mask = (size - 1) as u32;
                    comp.cm_limit = limit;
                    comp.context_index = self.components.len();
                }
                ICM => {
                    // Indirect Context Model: size (log2)
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let size = pow2_size(size_log.checked_add(8).ok_or(INVALID_SIZE)?)?;
                    comp.state_table = vec![0u8; size];
                    comp.cm_table = vec![1u32 << 15; 256]; // 256 state predictions
                    comp.mask = (size - 1) as u32;
                    comp.context_index = self.components.len();
                }
                MATCH => {
                    // Match Model: buffer size (log2)
                    let buf_log = next_byte(config, &mut pos)? as usize;
                    let buf_size = pow2_size(buf_log)?;
                    comp.match_buf = vec![0u8; buf_size];
                    comp.mask = (buf_size - 1) as u32;
                    comp.match_pos = 0;
                    comp.match_len = 0;
                    comp.match_ref = 0;
                    comp.context_index = self.components.len();
                    // Also need a hash table for finding matches
                    comp.cm_table = vec![0u32; buf_size];
                }
                AVG => {
                    // Average: two input indices + weight
                    let i1 = next_byte(config, &mut pos)? as usize;
                    let i2 = next_byte(config, &mut pos)? as usize;
                    let w = next_byte(config, &mut pos)? as i32;
                    validate_input(i1, self.components.len())?;
                    validate_input(i2, self.components.len())?;
                    comp.inputs = vec![i1, i2];
                    comp.weights = vec![w];
                }
                MIX2 => {
                    // 2-input adaptive mixer: size (log2), i1, i2, learning rate
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let i1 = next_byte(config, &mut pos)? as usize;
                    let i2 = next_byte(config, &mut pos)? as usize;
                    let rate = next_byte(config, &mut pos)? as i32;
                    validate_input(i1, self.components.len())?;
                    validate_input(i2, self.components.len())?;
                    let size = pow2_size(size_log)?;
                    comp.cm_table = vec![1u32 << 15; size]; // weights initialized to 0.5
                    comp.mask = (size - 1) as u32;
                    comp.inputs = vec![i1, i2];
                    comp.weights = vec![rate];
                    comp.context_index = self.components.len();
                }
                MIX => {
                    // M-input adaptive mixer: size (log2), M, inputs..., learning rate
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let m = next_byte(config, &mut pos)? as usize;
                    if m == 0 {
                        return Err(INVALID_MIX_ARITY);
                    }
                    let size = pow2_size(size_log)?;
                    comp.mask = (size - 1) as u32;
                    comp.inputs = Vec::with_capacity(m);
                    for _ in 0..m {
                        let input = next_byte(config, &mut pos)? as usize;
                        validate_input(input, self.components.len())?;
                        comp.inputs.push(input);
                    }
                    let _rate = next_byte(config, &mut pos)?;
                    let weight_count = size.checked_mul(m).ok_or(INVALID_SIZE)?;
                    comp.weights = vec![0i32; weight_count];
                    // Initialize to equal weights
                    for i in 0..size {
                        for j in 0..m {
                            comp.weights[i * m + j] = 65536 / m as i32;
                        }
                    }
                    comp.context_index = self.components.len();
                }
                ISSE => {
                    // Indirect SSE: size (log2), input index
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let input = next_byte(config, &mut pos)? as usize;
                    validate_input(input, self.components.len())?;
                    let size = pow2_size(size_log.checked_add(8).ok_or(INVALID_SIZE)?)?;
                    comp.state_table = vec![0u8; size];
                    comp.sse_table = vec![1u32 << 15; size]; // predictions
                    comp.mask = (size - 1) as u32;
                    comp.inputs = vec![input];
                    comp.context_index = self.components.len();
                }
                SSE => {
                    // Secondary Symbol Estimation: size (log2), input, start, end
                    let size_log = next_byte(config, &mut pos)? as usize;
                    let input = next_byte(config, &mut pos)? as usize;
                    let _start = next_byte(config, &mut pos)?;
                    let _end = next_byte(config, &mut pos)?;
                    validate_input(input, self.components.len())?;
                    let size = pow2_size(size_log)?;
                    let table_len = size.checked_mul(64).ok_or(INVALID_SIZE)?;
                    comp.sse_table = vec![1u32 << 15; table_len]; // 64 quantized probs
                    comp.mask = (size - 1) as u32;
                    comp.inputs = vec![input];
                    comp.context_index = self.components.len();
                }
                _ => return Err(Error::InvalidData("zpaq: unknown component type")),
            }

            self.components.push(comp);
        }

        if pos > config.len() {
            return Err(INCOMPLETE_CONFIG);
        }
        Ok(())
    }

    /// Predict the next bit. Returns probability (1..65534) that the
    /// bit is 1.
    pub fn predict(&mut self) -> u32 {
        let n = self.components.len();
        if n == 0 {
            return 1 << 15;
        }

        // Run each component to produce its prediction
        for i in 0..n {
            let ctype = self.components[i].ctype;
            match ctype {
                CONS => {
                    // prediction already set
                }
                CM => {
                    let ci = self.components[i].context_index;
                    let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                    let idx = (ctx & self.components[i].mask) as usize;
                    if idx < self.components[i].cm_table.len() {
                        let p = self.components[i].cm_table[idx];
                        self.components[i].prediction = stretch(p);
                    }
                }
                ICM => {
                    let ci = self.components[i].context_index;
                    let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                    let idx = (ctx & self.components[i].mask) as usize;
                    if idx < self.components[i].state_table.len() {
                        let state = self.components[i].state_table[idx];
                        if (state as usize) < self.components[i].cm_table.len() {
                            let p = self.components[i].cm_table[state as usize];
                            self.components[i].prediction = stretch(p);
                        }
                    }
                }
                MATCH => {
                    if self.components[i].match_len > 0 {
                        let ref_pos = self.components[i].match_ref;
                        let buf_mask = self.components[i].mask;
                        let ref_byte = self.components[i].match_buf[(ref_pos & buf_mask) as usize];
                        let bit_pos = 7 - (self.bit_count % 8);
                        let expected = (ref_byte >> bit_pos) & 1;
                        self.components[i].match_bit = expected;
                        let len = self.components[i].match_len.min(255) as i32;
                        self.components[i].prediction =
                            if expected != 0 { len * 4 } else { -(len * 4) };
                    } else {
                        self.components[i].prediction = 0;
                    }
                }
                AVG => {
                    if self.components[i].inputs.len() >= 2
                        && !self.components[i].weights.is_empty()
                    {
                        let i1 = self.components[i].inputs[0];
                        let i2 = self.components[i].inputs[1];
                        let w = self.components[i].weights[0];
                        let p1 = if i1 < n {
                            self.components[i1].prediction
                        } else {
                            0
                        };
                        let p2 = if i2 < n {
                            self.components[i2].prediction
                        } else {
                            0
                        };
                        self.components[i].prediction = (p1 * (256 - w) + p2 * w) >> 8;
                    }
                }
                MIX2 => {
                    if self.components[i].inputs.len() >= 2 {
                        let i1 = self.components[i].inputs[0];
                        let i2 = self.components[i].inputs[1];
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        let w = if idx < self.components[i].cm_table.len() {
                            self.components[i].cm_table[idx]
                        } else {
                            1u32 << 15
                        };
                        let p1 = if i1 < n {
                            self.components[i1].prediction
                        } else {
                            0
                        };
                        let p2 = if i2 < n {
                            self.components[i2].prediction
                        } else {
                            0
                        };
                        self.components[i].prediction =
                            ((p1 as i64 * (65536 - w as i64) + p2 as i64 * w as i64) >> 16) as i32;
                    }
                }
                MIX => {
                    let m = self.components[i].inputs.len();
                    if m > 0 {
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        let mut sum: i64 = 0;
                        for j in 0..m {
                            let inp = self.components[i].inputs[j];
                            let p = if inp < n {
                                self.components[inp].prediction
                            } else {
                                0
                            };
                            let w_idx = idx * m + j;
                            let w = if w_idx < self.components[i].weights.len() {
                                self.components[i].weights[w_idx]
                            } else {
                                0
                            };
                            sum += p as i64 * w as i64;
                        }
                        self.components[i].prediction = (sum >> 16) as i32;
                    }
                }
                ISSE => {
                    if !self.components[i].inputs.is_empty() {
                        let inp = self.components[i].inputs[0];
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        let state = if idx < self.components[i].state_table.len() {
                            self.components[i].state_table[idx]
                        } else {
                            0
                        };
                        let p_in = if inp < n {
                            squash(self.components[inp].prediction) as i32
                        } else {
                            1 << 15
                        };
                        // Mix with state-based prediction
                        let sp = state_prob(state);
                        self.components[i].prediction = (p_in + sp) >> 1;
                        self.components[i].prediction =
                            stretch(self.components[i].prediction as u32);
                    }
                }
                SSE => {
                    if !self.components[i].inputs.is_empty() {
                        let inp = self.components[i].inputs[0];
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        let p_in = if inp < n {
                            squash(self.components[inp].prediction)
                        } else {
                            1u32 << 15
                        };
                        // Quantize input probability to 0..63
                        let q = (p_in >> 10).min(63) as usize;
                        let table_idx = idx * 64 + q;
                        if table_idx < self.components[i].sse_table.len() {
                            let p = self.components[i].sse_table[table_idx];
                            self.components[i].prediction = stretch(p);
                        }
                    }
                }
                _ => {}
            }
        }

        // Return the last component's prediction, squashed to 1..65534
        let p = self.components[n - 1].prediction;
        squash(p)
    }

    fn update_impl(&mut self, bit: u8) -> Result<(), Error> {
        let n = self.components.len();
        let y = bit as u32;

        // Update each component in reverse order
        for i in (0..n).rev() {
            let ctype = self.components[i].ctype;
            match ctype {
                CM => {
                    let ci = self.components[i].context_index;
                    let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                    let idx = (ctx & self.components[i].mask) as usize;
                    if idx < self.components[i].cm_table.len() {
                        let p = self.components[i].cm_table[idx];
                        let limit = self.components[i].cm_limit;
                        // Update towards the actual bit
                        let error = ((y as i32) << 16) - p as i32;
                        let rate = if limit > 0 { limit } else { 4 };
                        let new_p = (p as i32 + error / rate as i32).clamp(1, 65534) as u32;
                        self.components[i].cm_table[idx] = new_p;
                    }
                }
                ICM => {
                    let ci = self.components[i].context_index;
                    let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                    let idx = (ctx & self.components[i].mask) as usize;
                    if idx < self.components[i].state_table.len() {
                        let state = self.components[i].state_table[idx];
                        // Update state
                        self.components[i].state_table[idx] = next_state(state, bit);
                        // Update CM entry for this state
                        if (state as usize) < self.components[i].cm_table.len() {
                            let p = self.components[i].cm_table[state as usize];
                            let error = ((y as i32) << 16) - p as i32;
                            let new_p = (p as i32 + error / 4).clamp(1, 65534) as u32;
                            self.components[i].cm_table[state as usize] = new_p;
                        }
                    }
                }
                MATCH => {
                    // Update match buffer
                    let pos = self.components[i].match_pos;
                    let buf_mask = self.components[i].mask;

                    // On byte boundary, update match state
                    if self.bit_count.is_multiple_of(8) {
                        let byte = (self.current_byte & 0xFF) as u8;
                        self.components[i].match_buf[(pos & buf_mask) as usize] = byte;

                        // Check if match continues
                        if self.components[i].match_len > 0 {
                            let ref_byte = self.components[i].match_buf
                                [(self.components[i].match_ref & buf_mask) as usize];
                            if ref_byte == byte {
                                self.components[i].match_ref =
                                    self.components[i].match_ref.wrapping_add(1);
                            } else {
                                self.components[i].match_len = 0;
                            }
                        }

                        // Try to find a new match if none active
                        if self.components[i].match_len == 0 {
                            let ci = self.components[i].context_index;
                            let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                            let hash_idx = (ctx & buf_mask) as usize;
                            if hash_idx < self.components[i].cm_table.len() {
                                let candidate = self.components[i].cm_table[hash_idx];
                                if candidate != pos {
                                    self.components[i].match_ref = candidate;
                                    self.components[i].match_len = 1;
                                }
                                self.components[i].cm_table[hash_idx] = pos;
                            }
                        }

                        self.components[i].match_pos = pos.wrapping_add(1);
                    }
                }
                MIX2 => {
                    if self.components[i].inputs.len() >= 2 {
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        if idx < self.components[i].cm_table.len() {
                            let rate = if !self.components[i].weights.is_empty() {
                                self.components[i].weights[0].max(1)
                            } else {
                                4
                            };
                            let p = self.components[i].cm_table[idx];
                            let error = ((y as i32) << 16) - p as i32;
                            let new_p = (p as i32 + error / rate).clamp(1, 65534) as u32;
                            self.components[i].cm_table[idx] = new_p;
                        }
                    }
                }
                ISSE => {
                    let ci = self.components[i].context_index;
                    let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                    let idx = (ctx & self.components[i].mask) as usize;
                    if idx < self.components[i].state_table.len() {
                        let state = self.components[i].state_table[idx];
                        self.components[i].state_table[idx] = next_state(state, bit);
                    }
                }
                SSE => {
                    if !self.components[i].inputs.is_empty() {
                        let inp = self.components[i].inputs[0];
                        let ci = self.components[i].context_index;
                        let ctx = if ci < self.z.h.len() { self.z.h[ci] } else { 0 };
                        let idx = (ctx & self.components[i].mask) as usize;
                        let p_in = if inp < n {
                            squash(self.components[inp].prediction)
                        } else {
                            1u32 << 15
                        };
                        let q = (p_in >> 10).min(63) as usize;
                        let table_idx = idx * 64 + q;
                        if table_idx < self.components[i].sse_table.len() {
                            let p = self.components[i].sse_table[table_idx];
                            let error = ((y as i32) << 16) - p as i32;
                            let new_p = (p as i32 + error / 4).clamp(1, 65534) as u32;
                            self.components[i].sse_table[table_idx] = new_p;
                        }
                    }
                }
                _ => {}
            }
        }

        // Update bit count and current byte
        self.current_byte = (self.current_byte << 1) | y;
        self.bit_count += 1;

        // On byte boundary, run the ZPAQL VM
        if self.bit_count.is_multiple_of(8) {
            let byte = self.current_byte & 0xFF;
            self.z.try_run(byte)?;
            self.current_byte = 1;
        }

        Ok(())
    }
}

// ── Lookup tables ───────────────────────────────────────────────

/// Squash lookup table: 4096 entries mapping -2048..2047 to 1..65534.
/// Generated by: squash(x) = round(65536 / (1 + exp(-x/64)))
static SQUASH_TABLE: [u16; 4096] = {
    let mut table = [0u16; 4096];
    let mut i = 0;
    while i < 4096 {
        let x = i as i32 - 2048;
        // Piecewise linear approximation
        let p = if x < -512 {
            let t_signed = x + 2048;
            let t = (if t_signed > 0 { t_signed } else { 0 }) as u32;
            let v = t * 32 / 2048;
            (if v < 65534 { v } else { 65534 }) as u16
        } else if x > 512 {
            let t_signed = 2047 - x;
            let t = (if t_signed > 0 { t_signed } else { 0 }) as u32;
            let v = 65534 - t * 32 / 2048;
            (if v < 65534 { v } else { 65534 }) as u16
        } else {
            // Linear region: map -512..512 to ~1024..64512
            let t = (x + 512) as u32;
            let v = 1024 + t * 62464 / 1024;
            (if v < 65534 { v } else { 65534 }) as u16
        };
        table[i] = if p == 0 { 1 } else { p };
        i += 1;
    }
    table
};

/// Stretch lookup table: 1024 entries mapping 0..65535 (>>6) to -2047..2047.
/// Inverse of squash.
static STRETCH_TABLE: [i16; 1024] = {
    let mut table = [0i16; 1024];
    let mut i = 0;
    while i < 1024 {
        let p = (i * 64) as u32;
        let s = if p < 1024 {
            -512 - ((1024 - p) as i32 * 1536 / 1024)
        } else if p > 64512 {
            512 + ((p - 64512) as i32 * 1536 / 1024)
        } else {
            (p as i32 - 32768) * 1024 / 62464
        };
        let clamped = if s < -2047 {
            -2047
        } else if s > 2047 {
            2047
        } else {
            s
        };
        table[i] = clamped as i16;
        i += 1;
    }
    table
};

/// State transition table: 512 entries for (state, bit) pairs.
/// Simplified version: states encode a count of (n0, n1) bits.
static STATE_TABLE: [u8; 512] = {
    let mut table = [0u8; 512];
    let mut s = 0u16;
    while s < 256 {
        // State s represents approximately (n0, n1) counts
        // On bit 0: increment n0 count
        // On bit 1: increment n1 count
        let n0 = s & 0x0F;
        let n1 = (s >> 4) & 0x0F;

        // Transition on bit 0
        let new_n0 = if n0 < 15 { n0 + 1 } else { 15 };
        let new_n1_0 = if n1 > 1 { n1 - 1 } else { n1 };
        table[s as usize * 2] = ((new_n1_0 << 4) | new_n0) as u8;

        // Transition on bit 1
        let new_n1 = if n1 < 15 { n1 + 1 } else { 15 };
        let new_n0_1 = if n0 > 1 { n0 - 1 } else { n0 };
        table[s as usize * 2 + 1] = ((new_n1 << 4) | new_n0_1) as u8;

        s += 1;
    }
    table
};

/// State probability table: probability of bit 1 given state.
static STATE_PROB_TABLE: [i16; 256] = {
    let mut table = [0i16; 256];
    let mut s = 0u16;
    while s < 256 {
        let n0 = (s & 0x0F) as i32 + 1;
        let n1 = ((s >> 4) & 0x0F) as i32 + 1;
        // Probability of 1 = n1 / (n0 + n1), scaled to 0..65536
        let p = (n1 * 65536) / (n0 + n1);
        let v = p - 32768;
        let clamped = if v < -2047 {
            -2047
        } else if v > 2047 {
            2047
        } else {
            v
        };
        table[s as usize] = clamped as i16;
        s += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    fn config_for_size_sweep(ctype: u8, size_log: u8) -> Vec<u8> {
        match ctype {
            CONS => vec![1, CONS, 128],
            CM => vec![1, CM, size_log, 4],
            ICM => vec![1, ICM, size_log],
            MATCH => vec![1, MATCH, size_log],
            AVG => vec![3, CONS, 128, CONS, 160, AVG, 0, 1, 64],
            MIX2 => vec![3, CONS, 128, CONS, 160, MIX2, size_log, 0, 1, 4],
            MIX => vec![3, CONS, 128, CONS, 160, MIX, size_log, 2, 0, 1, 4],
            ISSE => vec![2, CONS, 160, ISSE, size_log, 0],
            SSE => vec![2, CONS, 160, SSE, size_log, 0, 0, 255],
            _ => unreachable!(),
        }
    }

    fn bounded_size_logs_for(ctype: u8) -> &'static [u8] {
        match ctype {
            CONS | AVG => &[0],
            CM | MATCH | MIX2 | MIX | SSE => &[0, 1, 4, 8, 12, 16],
            ICM | ISSE => &[0, 1, 4, 8, 12],
            _ => &[],
        }
    }

    #[test]
    fn test_try_new_rejects_truncated_mix_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [2, CONS, 128, MIX, 0, 2, 0];
        assert!(matches!(
            Predictor::try_new(z, &config),
            Err(Error::InvalidData(
                "zpaq: incomplete component configuration"
            ))
        ));
    }

    #[test]
    fn test_try_new_rejects_truncated_sse_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, SSE, 0, 0, 0];
        assert!(matches!(
            Predictor::try_new(z, &config),
            Err(Error::InvalidData(
                "zpaq: incomplete component configuration"
            ))
        ));
    }

    #[test]
    fn test_try_new_rejects_unknown_component_type() {
        let z = ZPAQL::new(0, 0, Vec::new());
        assert!(matches!(
            Predictor::try_new(z, &[1, 99]),
            Err(Error::InvalidData("zpaq: unknown component type"))
        ));
    }

    #[test]
    fn test_try_new_rejects_invalid_component_input_reference() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [2, CONS, 128, AVG, 0, 1, 64];
        assert!(matches!(
            Predictor::try_new(z, &config),
            Err(Error::InvalidData(
                "zpaq: invalid component input reference"
            ))
        ));
    }

    #[test]
    fn test_try_new_rejects_invalid_component_size() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, CM, u8::MAX, 4];
        assert!(matches!(
            Predictor::try_new(z, &config),
            Err(Error::InvalidData("zpaq: invalid component size"))
        ));
    }

    #[test]
    fn test_try_new_rejects_zero_mix_arity() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, MIX, 0, 0, 4];
        assert!(matches!(
            Predictor::try_new(z, &config),
            Err(Error::InvalidData("zpaq: invalid mix arity"))
        ));
    }

    #[test]
    fn test_try_new_accepts_match_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, MATCH, 4];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 1);
    }

    #[test]
    fn test_try_new_accepts_mix_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [4, CONS, 128, CONS, 64, CONS, 96, MIX, 0, 3, 0, 1, 2, 4];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 4);
    }

    #[test]
    fn test_try_new_accepts_sse_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [2, CM, 0, 4, SSE, 0, 0, 0, 255];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 2);
    }

    #[test]
    fn test_try_new_accepts_cons_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, CONS, 128];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 1);
    }

    #[test]
    fn test_try_new_accepts_icm_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [1, ICM, 4];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 1);
    }

    #[test]
    fn test_try_new_accepts_isse_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [2, CONS, 128, ISSE, 4, 0];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 2);
    }

    #[test]
    fn test_try_new_accepts_mix2_component_config() {
        let z = ZPAQL::new(0, 0, Vec::new());
        let config = [3, CONS, 128, CONS, 64, MIX2, 0, 0, 1, 4];
        let pred = Predictor::try_new(z, &config).unwrap();
        assert_eq!(pred.components.len(), 3);
    }

    #[test]
    fn test_try_update_advances_cm_component_state() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred = Predictor::try_new(z, &[1, CM, 0, 4]).unwrap();
        let before = pred.components[0].cm_table[0];
        let _ = pred.predict();
        pred.try_update(1).unwrap();
        assert!(pred.components[0].cm_table[0] > before);
    }

    #[test]
    fn test_try_update_advances_icm_component_state() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred = Predictor::try_new(z, &[1, ICM, 0]).unwrap();
        let before = pred.components[0].cm_table[0];
        let _ = pred.predict();
        pred.try_update(1).unwrap();
        assert_ne!(pred.components[0].state_table[0], 0);
        assert!(pred.components[0].cm_table[0] > before);
    }

    #[test]
    fn test_try_update_advances_match_component_and_runs_hcomp_at_byte_boundary() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred = Predictor::try_new(z, &[1, MATCH, 2]).unwrap();
        let bits = [1, 0, 1, 0, 0, 1, 0, 1, 0];
        for bit in bits {
            let _ = pred.predict();
            pred.try_update(bit).unwrap();
        }
        assert_eq!(pred.components[0].match_pos, 2);
        assert_eq!(pred.components[0].match_buf[0], 1);
        assert_eq!(pred.components[0].match_buf[1], 1);
        assert_eq!(pred.z.a, 0xA5);
    }

    #[test]
    fn test_predict_and_try_update_exercise_mix_and_sse_components() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred = Predictor::try_new(
            z,
            &[4, CONS, 128, CONS, 160, MIX2, 0, 0, 1, 4, SSE, 0, 2, 0, 255],
        )
        .unwrap();
        let p = pred.predict();
        assert!((1..65535).contains(&p));
        pred.try_update(1).unwrap();
        assert!(pred.components[2].cm_table.iter().any(|&v| v != (1 << 15)));
        assert!(pred.components[3].sse_table.iter().any(|&v| v != (1 << 15)));
    }

    #[test]
    fn test_predict_exercises_mix_component_output_path() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred =
            Predictor::try_new(z, &[3, CONS, 128, CONS, 160, MIX, 0, 2, 0, 1, 4]).unwrap();
        let p = pred.predict();
        assert!((1..65535).contains(&p));
    }

    #[test]
    fn test_try_update_advances_isse_component_state() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let mut pred = Predictor::try_new(z, &[2, CONS, 160, ISSE, 0, 0]).unwrap();
        let _ = pred.predict();
        pred.try_update(1).unwrap();
        assert_ne!(pred.components[1].state_table[0], 0);
    }

    #[test]
    fn test_try_new_accepts_representative_component_matrix() {
        for ctype in [CONS, CM, ICM, MATCH, AVG, MIX2, MIX, ISSE, SSE] {
            for size_log in [0u8, 4, 8] {
                let z = ZPAQL::new(8, 8, vec![56]);
                let config = config_for_size_sweep(ctype, size_log);
                let pred = Predictor::try_new(z, &config).unwrap();
                assert!(
                    !pred.components.is_empty(),
                    "ctype={ctype} size_log={size_log}"
                );
            }
        }
    }

    #[test]
    fn test_try_new_accepts_bounded_component_size_sweep() {
        for ctype in [CONS, CM, ICM, MATCH, AVG, MIX2, MIX, ISSE, SSE] {
            for &size_log in bounded_size_logs_for(ctype) {
                let z = ZPAQL::new(8, 8, vec![56]);
                let config = config_for_size_sweep(ctype, size_log);
                let pred = Predictor::try_new(z, &config).unwrap();
                assert!(
                    !pred.components.is_empty(),
                    "ctype={ctype} size_log={size_log}"
                );
            }
        }
    }

    #[test]
    fn test_try_new_rejects_extreme_component_sizes() {
        for config in [
            vec![1, CM, u8::MAX, 4],
            vec![1, ICM, u8::MAX],
            vec![1, MATCH, u8::MAX],
            vec![3, CONS, 128, CONS, 160, MIX2, u8::MAX, 0, 1, 4],
            vec![3, CONS, 128, CONS, 160, MIX, u8::MAX, 2, 0, 1, 4],
            vec![2, CONS, 160, ISSE, u8::MAX, 0],
            vec![2, CONS, 160, SSE, u8::MAX, 0, 0, 255],
        ] {
            let z = ZPAQL::new(8, 8, vec![56]);
            assert!(matches!(
                Predictor::try_new(z, &config),
                Err(Error::InvalidData("zpaq: invalid component size"))
            ));
        }
    }

    #[test]
    fn test_predict_and_try_update_exercise_deep_mix2_sse_chain() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let config = [
            5, CONS, 128, CM, 4, 4, ICM, 4, MIX2, 4, 1, 2, 4, SSE, 4, 3, 0, 255,
        ];
        let mut pred = Predictor::try_new(z, &config).unwrap();
        let p = pred.predict();
        assert!((1..65535).contains(&p));
        pred.try_update(1).unwrap();
        assert!(pred.components[3].cm_table.iter().any(|&v| v != (1 << 15)));
        assert!(pred.components[4].sse_table.iter().any(|&v| v != (1 << 15)));
    }

    #[test]
    fn test_predict_and_try_update_exercise_avg_isse_mix_chain() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let config = [
            5, CONS, 128, CONS, 160, AVG, 0, 1, 64, ISSE, 4, 2, MIX, 4, 2, 2, 3, 4,
        ];
        let mut pred = Predictor::try_new(z, &config).unwrap();
        let p = pred.predict();
        assert!((1..65535).contains(&p));
        assert_ne!(pred.components[4].prediction, 0);
        pred.try_update(1).unwrap();
        assert_ne!(pred.components[3].state_table[0], 0);
    }

    #[test]
    fn test_try_update_exercises_match_component_inside_deep_chain() {
        let z = ZPAQL::new(0, 0, vec![56]);
        let config = [4, MATCH, 4, CONS, 160, CONS, 96, MIX, 4, 3, 0, 1, 2, 4];
        let mut pred = Predictor::try_new(z, &config).unwrap();
        let bits = [1, 0, 1, 0, 0, 1, 0, 1, 0];
        for bit in bits {
            let _ = pred.predict();
            pred.try_update(bit).unwrap();
        }
        assert_eq!(pred.components[0].match_pos, 2);
        assert_eq!(pred.components[0].match_buf[0], 1);
        assert_eq!(pred.components[0].match_buf[1], 1);
        assert_eq!(pred.z.a, 0xA5);
    }
}
