//! ZPAQL virtual machine (upstream-compatible).
//!
//! This is a port of the ZPAQL interpreter from upstream `libzpaq.cpp`
//! (public domain). The VM has four registers (`a`, `b`, `c`, `d`), a
//! condition flag `f`, 256 general-purpose registers `r`, a byte memory
//! array `m` (`2^mbits` bytes), a 32-bit hash array `h` (`2^hbits`
//! entries), and a program stored inside `header` at `hbegin..hend`.
//!
//! The header layout on the wire is:
//!
//! ```text
//! hsize(2 LE) | hh hm ph pm n | COMP section | 0 | program | 0
//! ```
//!
//! where `hsize` counts every byte after the 2-byte size field, the COMP
//! section is `n` component records terminated by a `0` byte, and the
//! program region holds HCOMP (and conceptually PCOMP) opcodes terminated
//! by a `0` byte. In memory a 128-byte guard gap separates the COMP
//! section from the program region (`hbegin == cend + 128`), matching
//! upstream so that absolute jump (`LJ`) targets are identical.
//!
//! Divergences from upstream behavior, all of which only affect
//! malformed inputs: a per-run instruction budget is enforced (upstream
//! would loop forever), and register indices are bounds-checked.

use alloc::vec::Vec;

use crate::error::Error;

/// Instruction budget for a single `run` call. Upstream loops until
/// HALT without a bound; a malformed program would hang the decoder.
const MAX_CYCLES: u32 = 1 << 24;

/// In-memory gap between the COMP section and the program region.
const HEADER_GAP: usize = 128;

/// Byte size of each COMP record by component type (including the type
/// byte). `0` marks the COMP terminator / an invalid type.
pub(crate) const COMP_SIZE: [u8; 10] = [0, 2, 3, 2, 3, 4, 6, 6, 3, 5];

/// ZPAQL virtual machine state.
#[derive(Debug, Clone)]
pub(crate) struct Zpaql {
    /// Header: `hsize(2)` `hh hm ph pm n` `COMP...0` `[128 gap]` `program...0`.
    header: Vec<u8>,
    /// End of the COMP section (`header[cend]` onwards is the gap).
    cend: usize,
    /// Start of the program region (always `cend + 128`).
    hbegin: usize,
    /// End of the program region (one past the final `0` terminator).
    hend: usize,
    /// Registers.
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    /// Condition flag.
    f: bool,
    /// Program counter (index into `header`).
    pc: usize,
    /// Byte memory `m`, size `2^mbits`.
    m: Vec<u8>,
    /// Hash memory `h`, `2^hbits` 32-bit words.
    h: Vec<u32>,
    /// Register file `r[256]`.
    r: [u32; 256],
    /// Bytes emitted by `OUT` instructions (PCOMP output).
    out: Vec<u8>,
}

impl Zpaql {
    /// Create an empty VM. Call [`Zpaql::read`] or
    /// [`Zpaql::set_header`] before running programs.
    pub fn new() -> Self {
        Self {
            header: Vec::new(),
            cend: 0,
            hbegin: 0,
            hend: 0,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            f: false,
            pc: 0,
            m: Vec::new(),
            h: Vec::new(),
            r: [0; 256],
            out: Vec::new(),
        }
    }

    fn get(input: &[u8], pos: &mut usize) -> Result<u8, Error> {
        let byte = *input.get(*pos).ok_or(Error::UnexpectedEof)?;
        *pos += 1;
        Ok(byte)
    }

    /// Read a ZPAQL header from `input` at `*pos`, upstream
    /// `ZPAQL::read` semantics. Returns the number of bytes consumed.
    pub fn read(&mut self, input: &[u8], pos: &mut usize) -> Result<usize, Error> {
        let start = *pos;
        let hsize = Self::get(input, pos)? as usize | ((Self::get(input, pos)? as usize) << 8);
        self.header.clear();
        self.header
            .try_reserve(hsize + 300)
            .map_err(|_| Error::InvalidData("zpaq: header allocation failed"))?;
        self.header.resize(hsize + 300, 0);
        self.cend = 0;
        self.header[self.cend] = (hsize & 0xff) as u8;
        self.cend += 1;
        self.header[self.cend] = (hsize >> 8) as u8;
        self.cend += 1;
        // hh hm ph pm n
        while self.cend < 7 {
            self.header[self.cend] = Self::get(input, pos)?;
            self.cend += 1;
        }

        // Read COMP section.
        let n = self.header[self.cend - 1] as usize;
        for _ in 0..n {
            let ctype = Self::get(input, pos)?;
            self.header[self.cend] = ctype;
            self.cend += 1;
            let size = COMP_SIZE.get(ctype as usize).copied().unwrap_or(0) as usize;
            if size < 1 {
                return Err(Error::InvalidData("zpaq: invalid component type"));
            }
            // Upstream bound: `cend` counts header bytes including the
            // 2-byte size field while `hsize` excludes it, so this is
            // two bytes stricter than a pure bounds check.
            if self.cend + size > hsize {
                return Err(Error::InvalidData("zpaq: COMP overflows header"));
            }
            for _ in 1..size {
                self.header[self.cend] = Self::get(input, pos)?;
                self.cend += 1;
            }
        }
        if Self::get(input, pos)? != 0 {
            return Err(Error::InvalidData("zpaq: missing COMP END"));
        }
        self.header[self.cend] = 0;
        self.cend += 1;

        // Insert the guard gap, then read the program region
        // (HCOMP followed by PCOMP, terminated by a 0 byte).
        self.hbegin = self.cend + HEADER_GAP;
        self.hend = self.hbegin;
        if self.hend > hsize + HEADER_GAP + 1 {
            return Err(Error::InvalidData("zpaq: missing HCOMP"));
        }
        while self.hend < hsize + HEADER_GAP + 1 {
            let op = Self::get(input, pos)?;
            self.header[self.hend] = op;
            self.hend += 1;
        }
        if Self::get(input, pos)? != 0 {
            return Err(Error::InvalidData("zpaq: missing HCOMP END"));
        }
        self.header[self.hend] = 0;
        self.hend += 1;
        debug_assert_eq!(hsize, self.cend - 2 + self.hend - self.hbegin);
        Ok(*pos - start)
    }

    /// Install a header constructed in memory with upstream layout
    /// (used by the encoder, which owns precompiled model headers).
    ///
    /// `comp` must already contain `hh hm ph pm n` plus `n` COMP records;
    /// `program` is the HCOMP/PCOMP opcode stream without its trailing
    /// `0` terminator.
    pub(crate) fn set_header(comp: &[u8], program: &[u8]) -> Result<Self, Error> {
        // comp must hold the 5-byte preamble (hh hm ph pm n) plus
        // exactly n COMP records.
        if comp.len() < 5 {
            return Err(Error::InvalidData(
                "zpaq: incomplete component configuration",
            ));
        }
        let n = comp[4] as usize;
        let mut pos = 5;
        for _ in 0..n {
            if pos >= comp.len() {
                return Err(Error::InvalidData(
                    "zpaq: incomplete component configuration",
                ));
            }
            let ctype = comp[pos] as usize;
            let size = COMP_SIZE.get(ctype).copied().unwrap_or(0) as usize;
            if size < 1 || pos + size > comp.len() {
                return Err(Error::InvalidData(
                    "zpaq: incomplete component configuration",
                ));
            }
            pos += size;
        }
        if pos != comp.len() {
            return Err(Error::InvalidData("zpaq: trailing COMP bytes"));
        }
        // hsize counts bytes after the size field: comp bytes (hh..COMP
        // records) + COMP END + program bytes + program END.
        let hsize = comp.len() + program.len() + 2;
        if hsize > 0xFFFF {
            return Err(Error::InvalidData("zpaq: header too large"));
        }
        let mut z = Self::new();
        z.header
            .try_reserve(hsize + 300)
            .map_err(|_| Error::InvalidData("zpaq: header allocation failed"))?;
        z.header.resize(hsize + 300, 0);
        z.header[0] = (hsize & 0xff) as u8;
        z.header[1] = (hsize >> 8) as u8;
        z.header[2..2 + comp.len()].copy_from_slice(comp);
        z.cend = 2 + comp.len();
        // COMP terminator
        z.header[z.cend] = 0;
        z.cend += 1;
        z.hbegin = z.cend + HEADER_GAP;
        z.hend = z.hbegin + program.len();
        z.header[z.hbegin..z.hend].copy_from_slice(program);
        z.header[z.hend] = 0;
        z.hend += 1;
        Ok(z)
    }

    /// Write the wire-format header (size field + COMP + program)
    /// to `out`.
    pub(crate) fn write_header(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header[0..self.cend]);
        out.extend_from_slice(&self.header[self.hbegin..self.hend]);
    }

    /// Raw header byte at `i` (`0` past the end — upstream reads
    /// through a padded header buffer).
    pub(crate) fn header_at(&self, i: usize) -> u8 {
        self.header.get(i).copied().unwrap_or(0)
    }

    /// Install the synthetic header upstream `PostProcessor` builds for
    /// a PCOMP program: an empty COMP section (`n = 0`, terminator at
    /// `header[7]`), `ph`/`pm` memory sizes, and `program` at `hbegin`.
    /// The 2-byte `hsize` field is computed as upstream does:
    /// `cend - 2 + (hend - hbegin)` with `cend = 8`.
    pub(crate) fn set_pcomp_header(ph: u8, pm: u8, program: &[u8]) -> Result<Self, Error> {
        let hsize = 6 + program.len(); // cend-2 + program bytes
        if hsize > 0xFFFF {
            return Err(Error::InvalidData("zpaq: PCOMP too large"));
        }
        let mut z = Self::new();
        z.header
            .try_reserve(hsize + 300)
            .map_err(|_| Error::InvalidData("zpaq: header allocation failed"))?;
        z.header.resize(hsize + 300, 0);
        z.header[0] = (hsize & 0xff) as u8;
        z.header[1] = (hsize >> 8) as u8;
        z.header[4] = ph;
        z.header[5] = pm;
        z.cend = 8;
        z.hbegin = z.cend + HEADER_GAP;
        z.hend = z.hbegin + program.len();
        z.header[z.hbegin..z.hend].copy_from_slice(program);
        Ok(z)
    }

    /// Number of predictor components (`n` field).
    pub(crate) fn component_count(&self) -> usize {
        self.header[6] as usize
    }

    /// COMP section view (component records, `n` entries, `0`-terminated
    /// at `cend - 1`). Excludes the size field and the trailing 0.
    pub(crate) fn comp(&self) -> &[u8] {
        &self.header[7..self.cend.saturating_sub(1)]
    }

    /// hmap-independent view of the hash array for the predictor.
    pub(crate) fn hash_at(&self, i: usize) -> u32 {
        self.h[i]
    }

    /// Initialize VM state for HCOMP (`hh`, `hm` fields).
    pub(crate) fn inith(&mut self) -> Result<(), Error> {
        self.init(self.header[2] as usize, self.header[3] as usize)
    }

    /// Initialize VM state for PCOMP (`ph`, `pm` fields).
    pub(crate) fn initp(&mut self) -> Result<(), Error> {
        self.init(self.header[4] as usize, self.header[5] as usize)
    }

    fn init(&mut self, hbits: usize, mbits: usize) -> Result<(), Error> {
        if hbits > 32 || mbits > 32 {
            return Err(Error::InvalidData("zpaq: memory size too big"));
        }
        let hsize = 1usize << hbits;
        let msize = 1usize << mbits;
        self.h
            .try_reserve(hsize)
            .map_err(|_| Error::InvalidData("zpaq: memory allocation failed"))?;
        self.m
            .try_reserve(msize)
            .map_err(|_| Error::InvalidData("zpaq: memory allocation failed"))?;
        self.h.clear();
        self.h.resize(hsize, 0);
        self.m.clear();
        self.m.resize(msize, 0);
        self.r = [0; 256];
        self.a = 0;
        self.b = 0;
        self.c = 0;
        self.d = 0;
        self.f = false;
        self.pc = 0;
        self.out.clear();
        Ok(())
    }

    /// Run the program at `hbegin` with `input` in register `a` until
    /// HALT. `input` wraps to `u32` (PCOMP receives `0xFFFF_FFFF` at
    /// end of segment).
    pub(crate) fn run(&mut self, input: u32) -> Result<(), Error> {
        self.pc = self.hbegin;
        self.a = input;
        let mut cycles = MAX_CYCLES;
        loop {
            cycles -= 1;
            if cycles == 0 {
                return Err(Error::InvalidData("zpaq: hcomp execution limit exceeded"));
            }
            if !self.execute()? {
                return Ok(());
            }
        }
    }

    /// Drain bytes emitted by `OUT` since the last call.
    pub(crate) fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    #[inline]
    fn read_m(&self, i: u32) -> u8 {
        self.m[(i as usize) & (self.m.len() - 1)]
    }

    #[inline]
    fn write_m(&mut self, i: u32, v: u8) {
        let idx = (i as usize) & (self.m.len() - 1);
        self.m[idx] = v;
    }

    #[inline]
    fn read_h(&self, i: u32) -> u32 {
        self.h[(i as usize) & (self.h.len() - 1)]
    }

    #[inline]
    fn write_h(&mut self, i: u32, v: u32) {
        let idx = (i as usize) & (self.h.len() - 1);
        self.h[idx] = v;
    }

    /// Execute one instruction; returns `Ok(false)` on HALT.
    fn execute(&mut self) -> Result<bool, Error> {
        let op = *self
            .header
            .get(self.pc)
            .ok_or(Error::InvalidData("zpaq: ZPAQL execution out of bounds"))?;
        self.pc += 1;
        match op {
            0 => return Err(Error::InvalidData("zpaq: ZPAQL execution error")),
            1 => self.a = self.a.wrapping_add(1),
            2 => self.a = self.a.wrapping_sub(1),
            3 => self.a = !self.a,
            4 => self.a = 0,
            7 => self.a = self.r[self.next_operand()? as usize],
            8 => core::mem::swap(&mut self.a, &mut self.b),
            9 => self.b = self.b.wrapping_add(1),
            10 => self.b = self.b.wrapping_sub(1),
            11 => self.b = !self.b,
            12 => self.b = 0,
            15 => self.b = self.r[self.next_operand()? as usize],
            16 => core::mem::swap(&mut self.a, &mut self.c),
            17 => self.c = self.c.wrapping_add(1),
            18 => self.c = self.c.wrapping_sub(1),
            19 => self.c = !self.c,
            20 => self.c = 0,
            23 => self.c = self.r[self.next_operand()? as usize],
            24 => core::mem::swap(&mut self.a, &mut self.d),
            25 => self.d = self.d.wrapping_add(1),
            26 => self.d = self.d.wrapping_sub(1),
            27 => self.d = !self.d,
            28 => self.d = 0,
            31 => self.d = self.r[self.next_operand()? as usize],
            32 => self.swap_m(self.b),
            33 => self.write_m(self.b, self.read_m(self.b).wrapping_add(1)),
            34 => self.write_m(self.b, self.read_m(self.b).wrapping_sub(1)),
            35 => self.write_m(self.b, !self.read_m(self.b)),
            36 => self.write_m(self.b, 0),
            39 => {
                // JT N: jump N - 127 bytes forward from the operand
                // address if F is true, else skip the operand.
                let n = self.next_operand()?;
                if self.f {
                    self.pc = self.rel_jump(self.pc - 1, n)?;
                }
            }
            40 => self.swap_m(self.c),
            41 => self.write_m(self.c, self.read_m(self.c).wrapping_add(1)),
            42 => self.write_m(self.c, self.read_m(self.c).wrapping_sub(1)),
            43 => self.write_m(self.c, !self.read_m(self.c)),
            44 => self.write_m(self.c, 0),
            47 => {
                // JF N
                let n = self.next_operand()?;
                if !self.f {
                    self.pc = self.rel_jump(self.pc - 1, n)?;
                }
            }
            48 => {
                let di = self.d_index();
                core::mem::swap(&mut self.a, &mut self.h[di]);
            }
            49 => {
                let v = self.read_h(self.d).wrapping_add(1);
                self.write_h(self.d, v);
            }
            50 => {
                let v = self.read_h(self.d).wrapping_sub(1);
                self.write_h(self.d, v);
            }
            51 => {
                let v = !self.read_h(self.d);
                self.write_h(self.d, v);
            }
            52 => self.write_h(self.d, 0),
            55 => {
                let n = self.next_operand()? as usize;
                self.r[n] = self.a;
            }
            56 => return Ok(false),                     // HALT
            57 => self.out.push((self.a & 0xff) as u8), // OUT
            59 => {
                self.a = self
                    .a
                    .wrapping_add(self.read_m(self.b) as u32)
                    .wrapping_add(512)
                    .wrapping_mul(773);
            }
            60 => {
                let v = self
                    .read_h(self.d)
                    .wrapping_add(self.a)
                    .wrapping_add(512)
                    .wrapping_mul(773);
                self.write_h(self.d, v);
            }
            63 => {
                // JMP N
                let n = self.next_operand()?;
                self.pc = self.rel_jump(self.pc - 1, n)?;
            }
            64..=119 => {
                let dest = (op - 64) / 8;
                let source = (op - 64) % 8;
                let value = self.resolve_source(source)?;
                self.assign_dest(dest, value);
            }
            128..=239 => {
                let group = (op - 128) / 8;
                let source = (op - 128) % 8;
                let rhs = self.resolve_source(source)?;
                match group {
                    0 => self.a = self.a.wrapping_add(rhs),
                    1 => self.a = self.a.wrapping_sub(rhs),
                    2 => self.a = self.a.wrapping_mul(rhs),
                    3 => self.a = self.a.checked_div(rhs).unwrap_or(0),
                    4 => self.a = self.a.checked_rem(rhs).unwrap_or(0),
                    5 => self.a &= rhs,
                    6 => self.a &= !rhs,
                    7 => self.a |= rhs,
                    8 => self.a ^= rhs,
                    9 => self.a <<= rhs & 31,
                    10 => self.a >>= rhs & 31,
                    11 => self.f = self.a == rhs,
                    12 => self.f = self.a < rhs,
                    13 => self.f = self.a > rhs,
                    _ => unreachable!(),
                }
            }
            255 => {
                // LJ: long jump to `hbegin + N`, where N is a 16-bit
                // operand. It is an error if the target is outside the
                // program region.
                let lo = self.next_operand()? as usize;
                let hi = self.next_operand()? as usize;
                let target = self.hbegin + lo + (hi << 8);
                if target >= self.hend {
                    return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
                }
                self.pc = target;
            }
            _ => return Err(Error::InvalidData("zpaq: ZPAQL execution error")),
        }
        Ok(true)
    }

    /// Swap the low byte of `a` with `m[index]`, preserving the high
    /// bits of `a` (upstream `swap(U8&)`).
    fn swap_m(&mut self, index: u32) {
        let x = self.read_m(index);
        self.write_m(index, (self.a & 0xff) as u8);
        self.a = (self.a & !0xff) | x as u32;
    }

    fn d_index(&self) -> usize {
        (self.d as usize) & (self.h.len() - 1)
    }

    fn next_operand(&mut self) -> Result<u8, Error> {
        let v = *self
            .header
            .get(self.pc)
            .ok_or(Error::InvalidData("zpaq: ZPAQL execution out of bounds"))?;
        self.pc += 1;
        Ok(v)
    }

    /// Relative jump: `target = operand_pos + ((n + 128) & 255) - 127`.
    fn rel_jump(&self, operand_pos: usize, n: u8) -> Result<usize, Error> {
        let delta = ((n as i32 + 128) & 255) - 127;
        let target = operand_pos as i64 + delta as i64;
        if target < 0 || target as usize >= self.header.len() {
            return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
        }
        Ok(target as usize)
    }

    fn resolve_source(&mut self, source: u8) -> Result<u32, Error> {
        Ok(match source {
            0 => self.a,
            1 => self.b,
            2 => self.c,
            3 => self.d,
            4 => self.read_m(self.b) as u32,
            5 => self.read_m(self.c) as u32,
            6 => self.read_h(self.d),
            7 => self.next_operand()? as u32,
            _ => unreachable!(),
        })
    }

    fn assign_dest(&mut self, dest: u8, value: u32) {
        match dest {
            0 => self.a = value,
            1 => self.b = value,
            2 => self.c = value,
            3 => self.d = value,
            4 => self.write_m(self.b, value as u8),
            5 => self.write_m(self.c, value as u8),
            6 => self.write_h(self.d, value),
            _ => unreachable!(),
        }
    }
}

impl Default for Zpaql {
    fn default() -> Self {
        Self::new()
    }
}
