//! Context-mixing predictor (upstream-compatible).
//!
//! This is a port of `Predictor`, `Component`, and `StateTable` from
//! upstream `libzpaq.cpp` (public domain). All arithmetic matches the
//! reference implementation bit for bit, including 32-bit wraparound
//! semantics, so that the compressed bitstream is identical.
//!
//! Components (upstream type ids): `0=NONE`, `1=CONST`, `2=CM`,
//! `3=ICM`, `4=MATCH`, `5=AVG`, `6=MIX2`, `7=MIX`, `8=ISSE`, `9=SSE`.

use alloc::vec::Vec;

use crate::error::Error;

use super::builtin::{Hcomp1, Hcomp2, Hcomp3};
use super::tables::{SDT, SDT2K, SNS, build_squasht, build_stretcht};
use super::zpaql::{COMP_SIZE, Zpaql};

/// squash(x) = floor(32768 / (1 + exp(-x / 64))), clamped to
/// `0..=32767`, for `x` in `-2048..=2047`.
const SQUASHT: [u16; 4096] = build_squasht();

/// stretch(x) = round(64 * log((x + 0.5) / (32767.5 - x))) for
/// `x` in `0..=32767` (inverse of `squash`).
static STRETCHT: [i16; 32768] = build_stretcht();

// Component type ids (upstream numbering).
const CONST: u8 = 1;
const CM: u8 = 2;
const ICM: u8 = 3;
const MATCH: u8 = 4;
const AVG: u8 = 5;
const MIX2: u8 = 6;
const MIX: u8 = 7;
const ISSE: u8 = 8;
const SSE: u8 = 9;

#[inline]
fn squash(x: i32) -> i32 {
    debug_assert!((-2048..=2047).contains(&x));
    SQUASHT[(x + 2048).clamp(0, 4095) as usize] as i32
}

#[inline]
fn stretch(x: i32) -> i32 {
    debug_assert!((0..=32767).contains(&x));
    STRETCHT[x.clamp(0, 32767) as usize] as i32
}

#[inline]
fn clamp2k(x: i32) -> i32 {
    x.clamp(-2048, 2047)
}

#[inline]
fn clamp512k(x: i32) -> i32 {
    x.clamp(-(1 << 19), (1 << 19) - 1)
}

/// Next state after coding bit `y` (0 or 1).
#[inline]
fn next_state(state: u8, y: u32) -> u8 {
    SNS[state as usize * 4 + y as usize]
}

/// Initial probability of a 1 bit for a bit-history state, times 2^23.
#[inline]
fn cminit(state: u8) -> i32 {
    let n0 = SNS[state as usize * 4 + 2] as i32;
    let n1 = SNS[state as usize * 4 + 3] as i32;
    ((n1 * 2 + 1) << 22) / (n0 + n1 + 1)
}

/// One predictor component, mirroring upstream `struct Component`.
#[derive(Default)]
struct Component {
    /// Component type id and its COMP record parameter bytes.
    ctype: u8,
    params: [u8; 8],
    /// Max count for CM/SSE; match position for MATCH.
    limit: usize,
    /// Saved context.
    cxt: usize,
    /// Multi-purpose: MATCH match length.
    a: usize,
    /// Multi-purpose: MATCH offset.
    b: usize,
    /// Multi-purpose: MATCH predicted bit; ICM/ISSE hash row base;
    /// MIX/MIX2 table size (number of contexts).
    c: usize,
    /// `cm[cxt & (size-1)]`: packed prediction+count for CM/SSE,
    /// adaptive counters for ICM, weight pairs for ISSE, weights for
    /// MIX, context->position index for MATCH.
    cm: Vec<u32>,
    /// ICM/ISSE context hash table (rows of 16) or MATCH history buffer.
    ht: Vec<u8>,
    /// MIX2 16-bit weights.
    a16: Vec<u16>,
}

fn try_alloc_u32s(size: usize) -> Result<Vec<u32>, Error> {
    let mut v = Vec::new();
    v.try_reserve(size)
        .map_err(|_| Error::InvalidData("zpaq: memory allocation failed"))?;
    Ok(v)
}

fn try_alloc_u8s(size: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve(size)
        .map_err(|_| Error::InvalidData("zpaq: memory allocation failed"))?;
    Ok(v)
}

/// The ZPAQ context-mixing predictor.
pub(crate) struct Predictor {
    z: Zpaql,
    /// Partial byte `1, 1x, 1xx, ...` of bits coded so far.
    c8: u32,
    /// `c8` split into nibbles (9-bit value).
    hmap4: u32,
    /// Component outputs (logistic domain).
    p: [i32; 256],
    /// Unrolled copy of `z.h` (context hashes).
    h: [u32; 256],
    /// The component array, length `n` (0..255).
    comp: Vec<Component>,
    /// COMP record bytes, `n` records total (parsed in `init`).
    comp_bytes: Vec<u8>,
    /// `0` runs HCOMP in the interpreter. `1..=3` uses the native program.
    builtin: u8,
    hcomp1: Hcomp1,
    hcomp2: Hcomp2,
    hcomp3: Hcomp3,
}

impl Predictor {
    /// Build and initialize a predictor from a parsed ZPAQL header.
    ///
    /// This mirrors upstream `Predictor::init`: it initializes the VM
    /// with `hh`/`hm`, zeroes the context array and parses the COMP
    /// section. Errors correspond to upstream `error()` conditions on
    /// malformed component specifications.
    pub fn new(z: Zpaql) -> Result<Self, Error> {
        Self::from_vm(z, 0)
    }

    /// Predictor for a built-in level. Component tables match the
    /// interpreter; HCOMP and the component order are native.
    pub fn new_builtin(z: Zpaql, level: u32) -> Result<Self, Error> {
        Self::from_vm(z, level as u8)
    }

    fn from_vm(z: Zpaql, builtin: u8) -> Result<Self, Error> {
        let mut pr = Self {
            z,
            c8: 1,
            hmap4: 1,
            p: [0; 256],
            h: [0; 256],
            comp: Vec::new(),
            comp_bytes: Vec::new(),
            builtin,
            hcomp1: Hcomp1::new(),
            hcomp2: Hcomp2::new(),
            hcomp3: Hcomp3::new(),
        };
        pr.init()?;
        Ok(pr)
    }

    /// `true` if the model has at least one component (level 1).
    /// An empty component array means uncompressed data (level 2).
    pub(crate) fn is_modeled(&self) -> bool {
        self.z.component_count() != 0
    }

    /// Attach a shared decode budget to the HCOMP VM.
    pub(crate) fn set_cycle_budget(&mut self, budget: super::zpaql::CycleBudget) {
        self.z.set_cycle_budget(budget);
    }

    fn init(&mut self) -> Result<(), Error> {
        self.z.inith()?;
        self.c8 = 1;
        self.hmap4 = 1;
        self.p = [0; 256];
        self.h = [0; 256];

        let n = self.z.component_count();
        // COMP records start at header[7]; `comp()` returns the record
        // bytes (the trailing 0 terminator excluded).
        self.comp_bytes = self.z.comp().to_vec();
        let comp_bytes = self.comp_bytes.clone();
        let mut cp = 0usize;
        self.comp.clear();
        for i in 0..n {
            if cp >= comp_bytes.len() {
                return Err(Error::InvalidData(
                    "zpaq: incomplete component configuration",
                ));
            }
            let ctype = comp_bytes[cp];
            let rec = &comp_bytes[cp..];
            let mut cr = Component {
                ctype,
                ..Component::default()
            };
            let plen = rec.len().min(cr.params.len());
            cr.params[..plen].copy_from_slice(&rec[..plen]);
            let rec = &cr.params;
            match ctype {
                CONST => {
                    // c
                    self.p[i] = (rec[1] as i32 - 128) * 4;
                }
                CM => {
                    // sizebits limit
                    let s = rec[1] as usize;
                    if s > 32 {
                        return Err(Error::InvalidData("zpaq: max size for CM is 32"));
                    }
                    let size = 1usize << s;
                    cr.cm = try_alloc_u32s(size)?;
                    cr.cm.resize(size, 0x8000_0000);
                    cr.limit = rec[2] as usize * 4;
                }
                ICM => {
                    // sizebits
                    let s = rec[1] as usize;
                    if s > 26 {
                        return Err(Error::InvalidData("zpaq: max size for ICM is 26"));
                    }
                    cr.limit = 1023;
                    cr.cm = try_alloc_u32s(256)?;
                    for j in 0..256usize {
                        cr.cm.push(cminit(j as u8) as u32);
                    }
                    cr.ht = try_alloc_u8s(64usize << s)?;
                    cr.ht.resize(64usize << s, 0);
                }
                MATCH => {
                    // sizebits bufbits
                    let s = rec[1] as usize;
                    let b = rec[2] as usize;
                    if s > 32 || b > 32 {
                        return Err(Error::InvalidData("zpaq: max size for MATCH is 32 32"));
                    }
                    cr.cm = try_alloc_u32s(1usize << s)?; // index
                    cr.cm.resize(1usize << s, 0);
                    cr.ht = try_alloc_u8s(1usize << b)?; // buf
                    cr.ht.resize(1usize << b, 0);
                    cr.ht[0] = 1;
                }
                AVG => {
                    // j k wt
                    if rec[1] as usize >= i || rec[2] as usize >= i {
                        return Err(Error::InvalidData("zpaq: AVG j/k >= i"));
                    }
                }
                MIX2 => {
                    // sizebits j k rate mask
                    let s = rec[1] as usize;
                    if s > 32 {
                        return Err(Error::InvalidData("zpaq: max size for MIX2 is 32"));
                    }
                    if rec[2] as usize >= i || rec[3] as usize >= i {
                        return Err(Error::InvalidData("zpaq: MIX2 j/k >= i"));
                    }
                    cr.c = 1usize << s;
                    let size = cr.c;
                    let mut w = Vec::new();
                    w.try_reserve(size)
                        .map_err(|_| Error::InvalidData("zpaq: memory allocation failed"))?;
                    w.resize(size, 32768u16);
                    cr.a16 = w;
                }
                MIX => {
                    // sizebits j m rate mask
                    let s = rec[1] as usize;
                    if s > 32 {
                        return Err(Error::InvalidData("zpaq: max size for MIX is 32"));
                    }
                    let j = rec[2] as usize;
                    let m = rec[3] as usize;
                    if j >= i {
                        return Err(Error::InvalidData("zpaq: MIX j >= i"));
                    }
                    if m < 1 || m > i - j {
                        return Err(Error::InvalidData("zpaq: MIX m not in 1..i-j"));
                    }
                    cr.c = 1usize << s;
                    cr.cm = try_alloc_u32s(cr.c * m)?;
                    cr.cm.resize(cr.c * m, 65536 / m as u32);
                }
                ISSE => {
                    // sizebits j
                    let s = rec[1] as usize;
                    if s > 32 {
                        return Err(Error::InvalidData("zpaq: max size for ISSE is 32"));
                    }
                    if rec[2] as usize >= i {
                        return Err(Error::InvalidData("zpaq: ISSE j >= i"));
                    }
                    cr.ht = try_alloc_u8s(64usize << s)?;
                    cr.ht.resize(64usize << s, 0);
                    cr.cm = try_alloc_u32s(512)?;
                    for j in 0..256usize {
                        cr.cm.push(1 << 15);
                        cr.cm
                            .push(clamp512k(stretch(cminit(j as u8) >> 8) * 1024) as u32);
                    }
                }
                SSE => {
                    // sizebits j start limit
                    let s = rec[1] as usize;
                    if s > 32 {
                        return Err(Error::InvalidData("zpaq: max size for SSE is 32"));
                    }
                    if rec[2] as usize >= i {
                        return Err(Error::InvalidData("zpaq: SSE j >= i"));
                    }
                    let start = rec[3] as u32;
                    let limit = rec[4] as usize * 4;
                    if rec[3] as usize > rec[4] as usize * 4 {
                        return Err(Error::InvalidData("zpaq: SSE start > limit*4"));
                    }
                    cr.cm = try_alloc_u32s(32usize << s)?;
                    for j in 0..(32usize << s) {
                        cr.cm
                            .push(((squash((j as i32 & 31) * 64 - 992) as u32) << 17) | start);
                    }
                    cr.limit = limit;
                }
                _ => return Err(Error::InvalidData("zpaq: unknown component type")),
            }
            let step = COMP_SIZE.get(ctype as usize).copied().unwrap_or(0) as usize;
            if step == 0 {
                return Err(Error::InvalidData("zpaq: unknown component type"));
            }
            cp += step;
            self.comp.push(cr);
        }
        Ok(())
    }

    /// Return the probability that the next bit is 1, as `0..=32767`.
    /// Callers feed `predict() * 2 + 1` to the arithmetic coder.
    pub fn predict(&mut self) -> i32 {
        debug_assert!(self.is_modeled());
        match self.builtin {
            1 => {
                self.predict_icm(0);
                self.predict_isse(1);
                return squash(self.p[1]);
            }
            2 => {
                self.predict_icm(0);
                self.predict_isse(1);
                self.predict_isse(2);
                self.predict_isse(3);
                self.predict_isse(4);
                self.predict_isse(5);
                self.predict_match(6);
                self.predict_mix(7);
                return squash(self.p[7]);
            }
            3 => {
                self.predict_icm(1);
                self.predict_isse(2);
                self.predict_isse(3);
                self.predict_isse(4);
                self.predict_isse(5);
                self.predict_isse(6);
                self.predict_isse(7);
                self.predict_match(8);
                self.predict_icm(9);
                self.predict_isse(10);
                self.predict_icm(11);
                self.predict_icm(12);
                self.predict_icm(13);
                self.predict_icm(14);
                self.predict_mix(15);
                self.predict_mix(16);
                self.predict_mix2(17);
                self.predict_sse(18);
                self.predict_mix2(19);
                self.predict_sse(20);
                self.predict_mix2(21);
                return squash(self.p[21]);
            }
            _ => {}
        }
        let n = self.comp.len();
        for i in 0..n {
            match self.comp[i].ctype {
                CONST => {}
                CM => self.predict_cm(i),
                ICM => self.predict_icm(i),
                MATCH => self.predict_match(i),
                AVG => self.predict_avg(i),
                MIX2 => self.predict_mix2(i),
                MIX => self.predict_mix(i),
                ISSE => self.predict_isse(i),
                SSE => self.predict_sse(i),
                _ => unreachable!("validated in init"),
            }
        }
        squash(self.p[n - 1])
    }

    fn predict_cm(&mut self, i: usize) {
        let cr = &mut self.comp[i];
        cr.cxt = (self.h[i] ^ self.hmap4) as usize;
        self.p[i] = stretch((cr.cm[cr.cxt & (cr.cm.len() - 1)] >> 17) as i32);
    }

    fn predict_icm(&mut self, i: usize) {
        let sizebits = self.comp[i].params[1] as usize;
        if self.c8 == 1 || (self.c8 & 0xf0) == 16 {
            let ctx = self.h[i].wrapping_add(16 * self.c8);
            self.comp[i].c = self.find(sizebits + 2, ctx, i);
        }
        let cr = &mut self.comp[i];
        cr.cxt = cr.ht[cr.c + (self.hmap4 as usize & 15)] as usize;
        self.p[i] = stretch((cr.cm[cr.cxt & 255] >> 8) as i32);
    }

    fn predict_match(&mut self, i: usize) {
        let cr = &mut self.comp[i];
        if cr.a == 0 {
            self.p[i] = 0;
        } else {
            cr.c = ((cr.ht[cr.limit.wrapping_sub(cr.b) & (cr.ht.len() - 1)] >> (7 - cr.cxt)) & 1)
                as usize;
            self.p[i] = stretch((SDT2K[cr.a] as i32).wrapping_mul(cr.c as i32 * -2 + 1) & 32767);
        }
    }

    fn predict_avg(&mut self, i: usize) {
        let params = self.comp[i].params;
        let j = params[1] as usize;
        let k = params[2] as usize;
        let wt = params[3] as i32;
        self.p[i] = (self.p[j] * wt + self.p[k] * (256 - wt)) >> 8;
    }

    fn predict_mix2(&mut self, i: usize) {
        let params = self.comp[i].params;
        let cr = &mut self.comp[i];
        cr.cxt = (self.h[i].wrapping_add(self.c8 & params[5] as u32) as usize) & (cr.c - 1);
        let w = cr.a16[cr.cxt] as i32;
        self.p[i] =
            (w * self.p[params[2] as usize] + (65536 - w) * self.p[params[3] as usize]) >> 16;
    }

    fn predict_mix(&mut self, i: usize) {
        let params = self.comp[i].params;
        let m = params[3] as usize;
        let cr = &mut self.comp[i];
        cr.cxt = (self.h[i].wrapping_add(self.c8 & params[5] as u32) as usize) & (cr.c - 1);
        cr.cxt *= m;
        let base = cr.cxt;
        let mut sum: i32 = 0;
        for j in 0..m {
            let w = cr.cm[base + j] as i32;
            sum = sum.wrapping_add((w >> 8).wrapping_mul(self.p[params[2] as usize + j]));
        }
        self.p[i] = clamp2k(sum >> 8);
    }

    fn predict_isse(&mut self, i: usize) {
        let params = self.comp[i].params;
        if self.c8 == 1 || (self.c8 & 0xf0) == 16 {
            let ctx = self.h[i].wrapping_add(16 * self.c8);
            self.comp[i].c = self.find(params[1] as usize + 2, ctx, i);
        }
        let cr = &mut self.comp[i];
        cr.cxt = cr.ht[cr.c + (self.hmap4 as usize & 15)] as usize;
        let wt0 = cr.cm[cr.cxt * 2] as i32;
        let wt1 = cr.cm[cr.cxt * 2 + 1] as i32;
        self.p[i] = clamp2k((wt0.wrapping_mul(self.p[params[2] as usize]) + wt1 * 64) >> 16);
    }

    fn predict_sse(&mut self, i: usize) {
        let params = self.comp[i].params;
        let cr = &mut self.comp[i];
        cr.cxt = (self.h[i].wrapping_add(self.c8) as usize) * 32;
        let mut pq = self.p[params[2] as usize] + 992;
        pq = pq.clamp(0, 1983);
        let wt = (pq & 63) as u32;
        pq >>= 6;
        cr.cxt += pq as usize;
        let cxt = cr.cxt;
        let v = ((cr.cm[cxt & (cr.cm.len() - 1)] >> 10) * (64 - wt)
            + (cr.cm[(cxt + 1) & (cr.cm.len() - 1)] >> 10) * wt)
            >> 13;
        self.p[i] = stretch(v as i32);
        cr.cxt += (wt >> 5) as usize;
    }

    /// Update the model after bit `y` (0 or 1) has been coded.
    pub fn update(&mut self, y: u32) -> Result<(), Error> {
        debug_assert!(y <= 1);
        match self.builtin {
            1 => {
                self.update_icm(0, y);
                self.update_isse(1, y);
            }
            2 => {
                self.update_icm(0, y);
                self.update_isse(1, y);
                self.update_isse(2, y);
                self.update_isse(3, y);
                self.update_isse(4, y);
                self.update_isse(5, y);
                self.update_match(6, y);
                self.update_mix(7, y);
            }
            3 => {
                self.update_icm(1, y);
                self.update_isse(2, y);
                self.update_isse(3, y);
                self.update_isse(4, y);
                self.update_isse(5, y);
                self.update_isse(6, y);
                self.update_isse(7, y);
                self.update_match(8, y);
                self.update_icm(9, y);
                self.update_isse(10, y);
                self.update_icm(11, y);
                self.update_icm(12, y);
                self.update_icm(13, y);
                self.update_icm(14, y);
                self.update_mix(15, y);
                self.update_mix(16, y);
                self.update_mix2(17, y);
                self.train(18, y);
                self.update_mix2(19, y);
                self.train(20, y);
                self.update_mix2(21, y);
            }
            _ => {
                let n = self.comp.len();
                for i in 0..n {
                    match self.comp[i].ctype {
                        CONST | AVG => {}
                        CM | SSE => self.train(i, y),
                        ICM => self.update_icm(i, y),
                        MATCH => self.update_match(i, y),
                        MIX2 => self.update_mix2(i, y),
                        MIX => self.update_mix(i, y),
                        ISSE => self.update_isse(i, y),
                        _ => unreachable!("validated in init"),
                    }
                }
            }
        }

        // Save bit y in c8, hmap4; run HCOMP at each byte boundary.
        self.c8 = self.c8 + self.c8 + y;
        if self.c8 >= 256 {
            let byte = self.c8 - 256;
            let n = self.comp.len();
            match self.builtin {
                1 => {
                    self.hcomp1.update(byte as u8);
                    self.h[..n].copy_from_slice(&self.hcomp1.hashes()[..n]);
                }
                2 => {
                    self.hcomp2.update(byte as u8);
                    self.h[..n].copy_from_slice(&self.hcomp2.hashes()[..n]);
                }
                3 => {
                    self.hcomp3.update(byte as u8);
                    let src = self.hcomp3.hashes();
                    self.h[..n].copy_from_slice(&src[..n]);
                }
                _ => {
                    self.z.run(byte)?;
                    for i in 0..n {
                        self.h[i] = self.z.hash_at(i);
                    }
                }
            }
            self.hmap4 = 1;
            self.c8 = 1;
        } else if (16..32).contains(&self.c8) {
            self.hmap4 = (self.hmap4 & 0xf) << 5 | y << 4 | 1;
        } else {
            self.hmap4 = (self.hmap4 & 0x1f0) | (((self.hmap4 & 0xf) * 2 + y) & 0xf);
        }
        Ok(())
    }

    fn update_icm(&mut self, i: usize, y: u32) {
        let cr = &mut self.comp[i];
        let idx = cr.c + (self.hmap4 as usize & 15);
        cr.ht[idx] = next_state(cr.ht[idx], y);
        let pn = &mut cr.cm[cr.cxt & 255];
        let d = ((y * 32767).wrapping_sub(*pn >> 8)) as i32;
        *pn = pn.wrapping_add((d >> 2) as u32);
    }

    fn update_match(&mut self, i: usize, y: u32) {
        let bufmask = self.comp[i].ht.len() - 1;
        let cmask = self.comp[i].cm.len() - 1;
        let cr = &mut self.comp[i];
        if cr.c != y as usize {
            cr.a = 0;
        }
        let li = cr.limit & bufmask;
        cr.ht[li] = cr.ht[li].wrapping_add(cr.ht[li]).wrapping_add(y as u8);
        cr.cxt += 1;
        if cr.cxt == 8 {
            cr.cxt = 0;
            cr.limit = cr.limit.wrapping_add(1) & bufmask;
            if cr.a == 0 {
                cr.b = cr
                    .limit
                    .wrapping_sub(cr.cm[self.h[i] as usize & cmask] as usize);
                if cr.b & bufmask != 0 {
                    while cr.a < 255
                        && cr.ht[cr.limit.wrapping_sub(cr.a).wrapping_sub(1) & bufmask]
                            == cr.ht[cr
                                .limit
                                .wrapping_sub(cr.a)
                                .wrapping_sub(cr.b)
                                .wrapping_sub(1)
                                & bufmask]
                    {
                        cr.a += 1;
                    }
                }
            } else {
                cr.a += usize::from(cr.a < 255);
            }
            cr.cm[self.h[i] as usize & cmask] = cr.limit as u32;
        }
    }

    fn update_mix2(&mut self, i: usize, y: u32) {
        let params = self.comp[i].params;
        let rate = params[4] as i32;
        let j = params[2] as usize;
        let k = params[3] as usize;
        let err = ((y as i32 * 32767 - squash(self.p[i])) * rate) >> 5;
        let diff = self.p[j] - self.p[k];
        let cr = &mut self.comp[i];
        let mut w = cr.a16[cr.cxt] as i32;
        w += (err.wrapping_mul(diff) + (1 << 12)) >> 13;
        cr.a16[cr.cxt] = w.clamp(0, 65535) as u16;
    }

    fn update_mix(&mut self, i: usize, y: u32) {
        let params = self.comp[i].params;
        let m = params[3] as usize;
        let rate = params[4] as i32;
        let j0 = params[2] as usize;
        let err = ((y as i32 * 32767 - squash(self.p[i])) * rate) >> 4;
        let cr = &mut self.comp[i];
        let base = cr.cxt;
        for j in 0..m {
            let w = cr.cm[base + j] as i32;
            let nw = w.wrapping_add((err.wrapping_mul(self.p[j0 + j]) + (1 << 12)) >> 13);
            cr.cm[base + j] = clamp512k(nw) as u32;
        }
    }

    fn update_isse(&mut self, i: usize, y: u32) {
        let j = self.comp[i].params[2] as usize;
        let err = y as i32 * 32767 - squash(self.p[i]);
        let cr = &mut self.comp[i];
        let cxt = cr.cxt;
        let w0 = cr.cm[cxt * 2] as i32;
        let w1 = cr.cm[cxt * 2 + 1] as i32;
        cr.cm[cxt * 2] =
            clamp512k(w0.wrapping_add((err.wrapping_mul(self.p[j]) + (1 << 12)) >> 13)) as u32;
        cr.cm[cxt * 2 + 1] = clamp512k(w1.wrapping_add((err + 16) >> 5)) as u32;
        let idx = cr.c + (self.hmap4 as usize & 15);
        cr.ht[idx] = next_state(cr.ht[idx], y);
    }

    /// Reduce prediction error in `cm` (CM and SSE components).
    fn train(&mut self, i: usize, y: u32) {
        let cr = &mut self.comp[i];
        let idx = cr.cxt & (cr.cm.len() - 1);
        let pn = &mut cr.cm[idx];
        let count = (*pn & 0x3ff) as usize;
        let error = y as i32 * 32767 - (*pn >> 17) as i32;
        *pn = pn.wrapping_add(
            ((error.wrapping_mul(SDT[count] as i32)) & !0x3ff) as u32 + u32::from(count < cr.limit),
        );
    }

    /// Find context row in an ICM/ISSE hash table. Each row is 16 bytes:
    /// element 0 holds the next higher 8 context bits for collision
    /// detection. After 3 adjacent misses, evict the row whose element
    /// 1 is smallest.
    fn find(&mut self, sizebits: usize, cxt: u32, i: usize) -> usize {
        let chk = ((cxt >> sizebits) & 255) as u8;
        // Upstream computes cxt*16 in 32 bits; keep the wrap.
        let h0 = (cxt.wrapping_mul(16) as usize) & (self.comp[i].ht.len() - 16);
        if self.comp[i].ht[h0] == chk {
            return h0;
        }
        let h1 = h0 ^ 16;
        if self.comp[i].ht[h1] == chk {
            return h1;
        }
        let h2 = h0 ^ 32;
        if self.comp[i].ht[h2] == chk {
            return h2;
        }
        let evict = if self.comp[i].ht[h0 + 1] <= self.comp[i].ht[h1 + 1]
            && self.comp[i].ht[h0 + 1] <= self.comp[i].ht[h2 + 1]
        {
            h0
        } else if self.comp[i].ht[h1 + 1] < self.comp[i].ht[h2 + 1] {
            h1
        } else {
            h2
        };
        for j in 0..16 {
            self.comp[i].ht[evict + j] = 0;
        }
        self.comp[i].ht[evict] = chk;
        evict
    }
}
