//! ZPAQL virtual machine for context hash computation.
//!
//! The VM has 4 registers (a, b, c, d: u32), a flag (f: bool),
//! 256 general-purpose registers (r[256]: u32), byte memory (m[]),
//! and hash memory (h[]).  It executes HCOMP bytecode once per
//! input byte to update the context hashes in h[].

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// ZPAQL virtual machine state.
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct ZPAQL {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub f: bool,
    pub r: [u32; 256],
    pub m: Vec<u8>,
    pub h: Vec<u32>,
    pub hcomp: Vec<u8>,
    m_mask: u32,
    h_mask: u32,
    legacy_builtin: bool,
}

impl ZPAQL {
    pub(crate) fn validate_hcomp(hcomp: &[u8]) -> Result<(), Error> {
        if Self::is_legacy_builtin_hcomp(hcomp) {
            return Ok(());
        }

        let mut pc = 0usize;

        while pc < hcomp.len() {
            let op = hcomp[pc];
            if op == 56 {
                break;
            }

            let instruction_len = Self::upstream_instruction_len(op)?;
            if pc + instruction_len > hcomp.len() {
                return Err(Error::InvalidData("zpaq: truncated hcomp instruction"));
            }

            match op {
                39 | 47 | 63 => {
                    let target = Self::relative_jump_target(pc + 1, hcomp[pc + 1]);
                    if target >= hcomp.len() {
                        return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
                    }
                }
                255 => {
                    let target = hcomp[pc + 1] as usize | ((hcomp[pc + 2] as usize) << 8);
                    if target >= hcomp.len() {
                        return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
                    }
                }
                _ => {}
            }

            pc += instruction_len;
        }

        Ok(())
    }

    /// Create a new VM with the given memory sizes (as log2) and bytecode.
    pub fn new(hh: usize, hm: usize, hcomp: Vec<u8>) -> Self {
        let m_size = if hm > 0 { 1usize << hm } else { 0 };
        let h_size = if hh > 0 { 1usize << hh } else { 0 };
        let legacy_builtin = Self::is_legacy_builtin_hcomp(&hcomp);
        Self {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            f: false,
            r: [0; 256],
            m: vec![0u8; m_size],
            h: vec![0u32; h_size],
            hcomp,
            m_mask: if m_size > 0 { (m_size - 1) as u32 } else { 0 },
            h_mask: if h_size > 0 { (h_size - 1) as u32 } else { 0 },
            legacy_builtin,
        }
    }

    /// Run upstream HCOMP bytecode, returning an error if execution does not
    /// halt before the VM cycle limit is exhausted.
    pub fn try_run(&mut self, input_byte: u32) -> Result<(), Error> {
        if self.legacy_builtin {
            return self.try_run_legacy(input_byte);
        }

        self.try_run_upstream(input_byte)
    }

    fn is_legacy_builtin_hcomp(hcomp: &[u8]) -> bool {
        (1..=3).any(|level| crate::compress::zpaq::models::model_config(level).hcomp == hcomp)
    }

    const fn upstream_instruction_len(op: u8) -> Result<usize, Error> {
        match op {
            1..=4
            | 8..=12
            | 16..=20
            | 24..=28
            | 32..=36
            | 40..=44
            | 48..=52
            | 56
            | 59
            | 60
            | 64..=70
            | 72..=78
            | 80..=86
            | 88..=94
            | 96..=102
            | 104..=110
            | 112..=118 => Ok(1),
            7
            | 15
            | 23
            | 31
            | 39
            | 47
            | 55
            | 63
            | 71
            | 79
            | 87
            | 95
            | 103
            | 111
            | 119
            | 128..=239 => Ok(2),
            255 => Ok(3),
            _ => Err(Error::InvalidData("zpaq: unsupported hcomp opcode")),
        }
    }

    fn try_run_upstream(&mut self, input_byte: u32) -> Result<(), Error> {
        self.a = input_byte;
        let mut pc = 0usize;
        let code = self.hcomp.clone();
        let len = code.len();
        let mut cycle_limit = 65536u32;

        while pc < len {
            cycle_limit -= 1;
            if cycle_limit == 0 {
                return Err(Error::InvalidData("zpaq: hcomp execution limit exceeded"));
            }

            let op = code[pc];
            pc += 1;

            match op {
                1 => self.a = self.a.wrapping_add(1),
                2 => self.a = self.a.wrapping_sub(1),
                3 => self.a = !self.a,
                4 => self.a = 0,
                7 => {
                    let n = Self::read_u8(&code, &mut pc)? as usize;
                    self.a = self.r[n];
                }
                8 => core::mem::swap(&mut self.a, &mut self.b),
                9 => self.b = self.b.wrapping_add(1),
                10 => self.b = self.b.wrapping_sub(1),
                11 => self.b = !self.b,
                12 => self.b = 0,
                15 => {
                    let n = Self::read_u8(&code, &mut pc)? as usize;
                    self.b = self.r[n];
                }
                16 => core::mem::swap(&mut self.a, &mut self.c),
                17 => self.c = self.c.wrapping_add(1),
                18 => self.c = self.c.wrapping_sub(1),
                19 => self.c = !self.c,
                20 => self.c = 0,
                23 => {
                    let n = Self::read_u8(&code, &mut pc)? as usize;
                    self.c = self.r[n];
                }
                24 => core::mem::swap(&mut self.a, &mut self.d),
                25 => self.d = self.d.wrapping_add(1),
                26 => self.d = self.d.wrapping_sub(1),
                27 => self.d = !self.d,
                28 => self.d = 0,
                31 => {
                    let n = Self::read_u8(&code, &mut pc)? as usize;
                    self.d = self.r[n];
                }
                32 => {
                    let value = self.read_m(self.b) as u32;
                    self.write_m(self.b, self.a as u8);
                    self.a = value;
                }
                33 => self.write_m(self.b, self.read_m(self.b).wrapping_add(1)),
                34 => self.write_m(self.b, self.read_m(self.b).wrapping_sub(1)),
                35 => self.write_m(self.b, !self.read_m(self.b)),
                36 => self.write_m(self.b, 0),
                39 => {
                    let offset = Self::read_u8(&code, &mut pc)?;
                    if self.f {
                        pc = Self::checked_relative_jump(len, pc - 1, offset)?;
                    }
                }
                40 => {
                    let value = self.read_m(self.c) as u32;
                    self.write_m(self.c, self.a as u8);
                    self.a = value;
                }
                41 => self.write_m(self.c, self.read_m(self.c).wrapping_add(1)),
                42 => self.write_m(self.c, self.read_m(self.c).wrapping_sub(1)),
                43 => self.write_m(self.c, !self.read_m(self.c)),
                44 => self.write_m(self.c, 0),
                47 => {
                    let offset = Self::read_u8(&code, &mut pc)?;
                    if !self.f {
                        pc = Self::checked_relative_jump(len, pc - 1, offset)?;
                    }
                }
                48 => {
                    let value = self.read_h(self.d);
                    self.write_h(self.d, self.a);
                    self.a = value;
                }
                49 => self.write_h(self.d, self.read_h(self.d).wrapping_add(1)),
                50 => self.write_h(self.d, self.read_h(self.d).wrapping_sub(1)),
                51 => self.write_h(self.d, !self.read_h(self.d)),
                52 => self.write_h(self.d, 0),
                55 => {
                    let n = Self::read_u8(&code, &mut pc)? as usize;
                    self.r[n] = self.a;
                }
                56 => break,
                59 => {
                    self.a = self
                        .a
                        .wrapping_add(self.read_m(self.b) as u32)
                        .wrapping_add(512)
                        .wrapping_mul(773);
                }
                60 => {
                    self.write_h(
                        self.d,
                        self.read_h(self.d)
                            .wrapping_add(self.a)
                            .wrapping_add(512)
                            .wrapping_mul(773),
                    );
                }
                63 => {
                    let offset = Self::read_u8(&code, &mut pc)?;
                    pc = Self::checked_relative_jump(len, pc - 1, offset)?;
                }
                64..=119 => {
                    let dest = (op - 64) / 8;
                    let source = (op - 64) % 8;
                    let value = self.resolve_upstream_source(source, &code, &mut pc)?;
                    self.assign_upstream_dest(dest, value);
                }
                128..=239 => {
                    let group = (op - 128) / 8;
                    let source = (op - 128) % 8;
                    let rhs = self.resolve_upstream_source(source, &code, &mut pc)?;
                    match group {
                        0 => self.a = self.a.wrapping_add(rhs),
                        1 => self.a = self.a.wrapping_sub(rhs),
                        2 => self.a = self.a.wrapping_mul(rhs),
                        3 => self.a = if rhs != 0 { self.a / rhs } else { 0 },
                        4 => self.a = if rhs != 0 { self.a % rhs } else { 0 },
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
                    let low = Self::read_u8(&code, &mut pc)? as usize;
                    let high = Self::read_u8(&code, &mut pc)? as usize;
                    let target = low | (high << 8);
                    if target >= len {
                        return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
                    }
                    pc = target;
                }
                _ => return Err(Error::InvalidData("zpaq: unsupported hcomp opcode")),
            }
        }

        Ok(())
    }

    fn try_run_legacy(&mut self, input_byte: u32) -> Result<(), Error> {
        self.a = input_byte;
        let mut pc = 0usize;
        let code = &self.hcomp;
        let len = code.len();
        let mut cycle_limit = 65536u32;

        while pc < len {
            cycle_limit -= 1;
            if cycle_limit == 0 {
                return Err(Error::InvalidData("zpaq: hcomp execution limit exceeded"));
            }

            let op = code[pc];
            pc += 1;

            match op {
                0 => break,
                1 => self.a = self.a.wrapping_add(1),
                2 => self.a = self.a.wrapping_sub(1),
                3 => self.a = !self.a,
                4 => self.a = 0,
                7 => {
                    let idx = (self.b & self.m_mask) as usize;
                    let val = if idx < self.m.len() { self.m[idx] } else { 0 };
                    self.a = (self.a << 8) | val as u32;
                }
                8 => {
                    let idx = (self.b & self.m_mask) as usize;
                    self.a = if idx < self.m.len() {
                        self.m[idx] as u32
                    } else {
                        0
                    };
                }
                9 => {
                    let idx = (self.b & self.m_mask) as usize;
                    if idx < self.m.len() {
                        self.m[idx] = self.a as u8;
                    }
                }
                10 => {
                    let idx = (self.c & self.m_mask) as usize;
                    self.a = if idx < self.m.len() {
                        self.m[idx] as u32
                    } else {
                        0
                    };
                }
                11 => {
                    let idx = (self.c & self.m_mask) as usize;
                    if idx < self.m.len() {
                        self.m[idx] = self.a as u8;
                    }
                }
                12 => {
                    let idx = (self.d & self.h_mask) as usize;
                    self.a = if idx < self.h.len() { self.h[idx] } else { 0 };
                }
                13 => {
                    let idx = (self.d & self.h_mask) as usize;
                    if idx < self.h.len() {
                        self.h[idx] = self.a;
                    }
                }
                14 => {
                    let idx = (self.b & self.m_mask) as usize;
                    self.d = if idx < self.m.len() {
                        self.m[idx] as u32
                    } else {
                        0
                    };
                }
                15 => {
                    let idx = (self.c & self.m_mask) as usize;
                    self.d = if idx < self.m.len() {
                        self.m[idx] as u32
                    } else {
                        0
                    };
                }
                16 => {
                    let idx = (self.b & self.m_mask) as usize;
                    let val = if idx < self.m.len() {
                        self.m[idx] as u32
                    } else {
                        0
                    };
                    self.a = self.a.wrapping_add(val).wrapping_add(512).wrapping_mul(773);
                }
                17 => {
                    let idx = (self.d & self.h_mask) as usize;
                    if idx < self.h.len() {
                        self.h[idx] = self.h[idx]
                            .wrapping_add(self.a)
                            .wrapping_add(512)
                            .wrapping_mul(773);
                    }
                }
                24 => core::mem::swap(&mut self.a, &mut self.b),
                25 => core::mem::swap(&mut self.a, &mut self.c),
                26 => core::mem::swap(&mut self.a, &mut self.d),
                27 => self.a = self.b,
                28 => self.a = self.c,
                29 => self.a = self.d,
                30 => self.b = self.a,
                31 => self.c = self.a,
                32 => self.d = self.a,
                33 => self.b = self.c,
                34 => self.b = self.d,
                35 => self.a = self.a.wrapping_add(self.b),
                36 => self.a = self.a.wrapping_sub(self.b),
                37 => self.a = self.a.wrapping_mul(self.b),
                38 => self.a = if self.b != 0 { self.a / self.b } else { 0 },
                39 => self.a = if self.b != 0 { self.a % self.b } else { 0 },
                40 => self.a &= self.b,
                41 => self.a &= !self.b,
                42 => self.a |= self.b,
                43 => self.a ^= self.b,
                44 => self.a = if self.b < 32 { self.a << self.b } else { 0 },
                45 => self.a = if self.b < 32 { self.a >> self.b } else { 0 },
                46 => self.f = self.a == self.b,
                47 => self.f = self.a < self.b,
                48 => self.f = self.a > self.b,
                56..=63 => {
                    if pc < len {
                        let offset = code[pc];
                        pc += 1;
                        if self.f {
                            pc = self.compute_jump_legacy(pc, offset, op - 56);
                        }
                    }
                }
                64..=71 => {
                    if pc < len {
                        let offset = code[pc];
                        pc += 1;
                        if !self.f {
                            pc = self.compute_jump_legacy(pc, offset, op - 64);
                        }
                    }
                }
                72..=79 => {
                    if pc < len {
                        let offset = code[pc];
                        pc += 1;
                        pc = self.compute_jump_legacy(pc, offset, op - 72);
                    }
                }
                128..=255 => {
                    let real_op = op - 128;
                    let n = if pc < len {
                        let v = code[pc] as u32;
                        pc += 1;
                        v
                    } else {
                        0
                    };

                    match real_op {
                        0 => self.a = n,
                        1 => self.a = self.a.wrapping_add(n),
                        2 => self.a = self.a.wrapping_sub(n),
                        3 => self.a = self.a.wrapping_mul(n),
                        4 => self.a = if n != 0 { self.a / n } else { 0 },
                        5 => self.a = if n != 0 { self.a % n } else { 0 },
                        6 => self.a &= n,
                        7 => self.a |= n,
                        8 => self.a ^= n,
                        9 => self.a = if n < 32 { self.a << n } else { 0 },
                        10 => self.a = if n < 32 { self.a >> n } else { 0 },
                        11 => self.f = self.a == n,
                        12 => self.f = self.a < n,
                        13 => self.f = self.a > n,
                        14 => self.b = n,
                        15 => self.c = n,
                        16 => self.d = n,
                        17 => self.b = self.b.wrapping_add(n),
                        18 => self.b = self.b.wrapping_sub(n),
                        19 => self.c = self.c.wrapping_add(n),
                        20 => self.c = self.c.wrapping_sub(n),
                        21 => {
                            let idx = n as usize;
                            if idx < 256 {
                                self.r[idx] = self.a;
                            }
                        }
                        22 => {
                            let idx = n as usize;
                            self.a = if idx < 256 { self.r[idx] } else { 0 };
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn read_u8(code: &[u8], pc: &mut usize) -> Result<u8, Error> {
        let byte = *code
            .get(*pc)
            .ok_or(Error::InvalidData("zpaq: truncated hcomp instruction"))?;
        *pc += 1;
        Ok(byte)
    }

    const fn relative_jump_target(operand_pc: usize, offset: u8) -> usize {
        let delta = (((offset as i16 + 128) & 255) - 127) as isize;
        operand_pc.wrapping_add_signed(delta)
    }

    const fn checked_relative_jump(
        len: usize,
        operand_pc: usize,
        offset: u8,
    ) -> Result<usize, Error> {
        let target = Self::relative_jump_target(operand_pc, offset);
        if target >= len {
            return Err(Error::InvalidData("zpaq: invalid hcomp jump target"));
        }
        Ok(target)
    }

    fn read_m(&self, index: u32) -> u8 {
        let idx = (index & self.m_mask) as usize;
        self.m.get(idx).copied().unwrap_or(0)
    }

    fn write_m(&mut self, index: u32, value: u8) {
        let idx = (index & self.m_mask) as usize;
        if let Some(slot) = self.m.get_mut(idx) {
            *slot = value;
        }
    }

    fn read_h(&self, index: u32) -> u32 {
        let idx = (index & self.h_mask) as usize;
        self.h.get(idx).copied().unwrap_or(0)
    }

    fn write_h(&mut self, index: u32, value: u32) {
        let idx = (index & self.h_mask) as usize;
        if let Some(slot) = self.h.get_mut(idx) {
            *slot = value;
        }
    }

    fn resolve_upstream_source(
        &self,
        source: u8,
        code: &[u8],
        pc: &mut usize,
    ) -> Result<u32, Error> {
        Ok(match source {
            0 => self.a,
            1 => self.b,
            2 => self.c,
            3 => self.d,
            4 => self.read_m(self.b) as u32,
            5 => self.read_m(self.c) as u32,
            6 => self.read_h(self.d),
            7 => Self::read_u8(code, pc)? as u32,
            _ => unreachable!(),
        })
    }

    fn assign_upstream_dest(&mut self, dest: u8, value: u32) {
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

    const fn compute_jump_legacy(&self, pc: usize, offset: u8, mode: u8) -> usize {
        // mode 0..7: forward/backward jumps with different scales
        // Simple: offset is relative jump from current pc
        // Forward: mode bit 0 = 0 -> forward, 1 -> backward
        if mode & 1 == 0 {
            pc.wrapping_add(offset as usize)
        } else {
            pc.wrapping_sub(offset as usize + 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hcomp_accepts_builtin_models() {
        for level in 1..=3 {
            let model = crate::compress::zpaq::models::model_config(level);
            assert!(ZPAQL::validate_hcomp(&model.hcomp).is_ok());
        }
    }

    #[test]
    fn test_validate_hcomp_rejects_unsupported_single_byte_opcode() {
        assert!(matches!(
            ZPAQL::validate_hcomp(&[5]),
            Err(Error::InvalidData("zpaq: unsupported hcomp opcode"))
        ));
    }

    #[test]
    fn test_validate_hcomp_rejects_unsupported_two_byte_opcode() {
        assert!(matches!(
            ZPAQL::validate_hcomp(&[240, 0]),
            Err(Error::InvalidData("zpaq: unsupported hcomp opcode"))
        ));
    }

    #[test]
    fn test_validate_hcomp_rejects_truncated_instruction() {
        assert!(matches!(
            ZPAQL::validate_hcomp(&[7]),
            Err(Error::InvalidData("zpaq: truncated hcomp instruction"))
        ));
        assert!(matches!(
            ZPAQL::validate_hcomp(&[255, 0]),
            Err(Error::InvalidData("zpaq: truncated hcomp instruction"))
        ));
    }

    #[test]
    fn test_validate_hcomp_stops_at_halt() {
        assert!(ZPAQL::validate_hcomp(&[56, 5]).is_ok());
    }

    #[test]
    fn test_validate_hcomp_accepts_supported_upstream_arithmetic_opcode() {
        assert!(ZPAQL::validate_hcomp(&[239, 7, 56]).is_ok());
    }

    #[test]
    fn test_try_run_supports_upstream_c_register_opcodes() {
        let mut vm = ZPAQL::new(0, 0, vec![20, 23, 3, 56]);
        vm.c = 99;
        vm.r[3] = 42;
        vm.try_run(7).unwrap();
        assert_eq!(vm.c, 42);
    }

    #[test]
    fn test_try_run_supports_upstream_conditional_jump() {
        let mut vm = ZPAQL::new(0, 0, vec![223, 7, 39, 1, 4, 56]);
        vm.try_run(7).unwrap();
        assert_eq!(vm.a, 7);
        assert!(vm.f);
    }

    #[test]
    fn test_try_run_supports_upstream_memory_and_hash_writes() {
        let mut vm = ZPAQL::new(2, 2, vec![87, 1, 71, 0xAB, 104, 95, 2, 71, 0x34, 112, 56]);
        vm.try_run(0).unwrap();
        assert_eq!(vm.m[1], 0xAB);
        assert_eq!(vm.h[2], 0x34);
    }

    #[test]
    fn test_try_run_supports_upstream_register_file_roundtrip() {
        let mut vm = ZPAQL::new(0, 0, vec![55, 4, 4, 7, 4, 56]);
        vm.try_run(0x33).unwrap();
        assert_eq!(vm.r[4], 0x33);
        assert_eq!(vm.a, 0x33);
    }

    #[test]
    fn test_try_run_supports_upstream_div_mod_operations() {
        let mut vm = ZPAQL::new(0, 0, vec![71, 20, 159, 7, 167, 4, 56]);
        vm.try_run(20).unwrap();
        assert_eq!(vm.a, 2);
    }

    #[test]
    fn test_try_run_supports_upstream_memory_increment_decrement() {
        let mut vm = ZPAQL::new(0, 2, vec![79, 1, 32, 33, 34, 32, 87, 1, 40, 41, 42, 40, 56]);
        vm.try_run(0x10).unwrap();
        assert_eq!(vm.m[1], 0);
        assert_eq!(vm.a, 0x10);
    }

    #[test]
    fn test_try_run_supports_upstream_mul_overflow_and_shift_masking() {
        let mut vm = ZPAQL::new(0, 0, vec![4, 3, 151, 2, 71, 1, 207, 40, 56]);
        vm.try_run(0).unwrap();
        assert_eq!(vm.a, 256);
    }

    #[test]
    fn test_try_run_supports_upstream_logical_ops_with_memory_source() {
        let mut vm = ZPAQL::new(0, 2, vec![79, 1, 71, 0x0F, 96, 71, 0xF3, 172, 56]);
        vm.try_run(0).unwrap();
        assert_eq!(vm.a, 0x03);
        assert_eq!(vm.m[1], 0x0F);
    }

    #[test]
    fn test_try_run_wraps_memory_and_hash_indices() {
        let mut vm = ZPAQL::new(2, 2, vec![79, 5, 71, 0xAA, 96, 95, 6, 71, 0x55, 112, 56]);
        vm.try_run(0).unwrap();
        assert_eq!(vm.m[1], 0xAA);
        assert_eq!(vm.h[2], 0x55);
    }

    #[test]
    fn test_try_run_supports_mixed_memory_hash_arithmetic_sequence() {
        let mut vm = ZPAQL::new(
            2,
            2,
            vec![79, 1, 87, 2, 95, 3, 71, 0x10, 32, 1, 40, 59, 48, 55, 4, 56],
        );
        vm.try_run(0).unwrap();
        assert_eq!(vm.m[1], 0x10);
        assert_eq!(vm.m[2], 1);
        assert_eq!(vm.h[3], 408_144);
        assert_eq!(vm.r[4], 0);
        assert_eq!(vm.a, 0);
    }

    #[test]
    fn test_try_run_supports_nested_conditional_branch_shape() {
        let mut vm = ZPAQL::new(
            0,
            0,
            vec![223, 7, 39, 1, 4, 71, 9, 223, 8, 47, 2, 71, 3, 56],
        );
        vm.try_run(7).unwrap();
        assert_eq!(vm.a, 9);
        assert!(!vm.f);
    }

    #[test]
    fn test_try_run_rejects_invalid_absolute_jump_target() {
        let mut vm = ZPAQL::new(0, 0, vec![255, 0xFF, 0xFF]);
        assert!(matches!(
            vm.try_run(0),
            Err(Error::InvalidData("zpaq: invalid hcomp jump target"))
        ));
    }

    #[test]
    fn test_try_run_rejects_cycle_limit_exhaustion() {
        let mut vm = ZPAQL::new(0, 0, vec![255, 0, 0]);
        assert!(matches!(
            vm.try_run(0),
            Err(Error::InvalidData("zpaq: hcomp execution limit exceeded"))
        ));
    }
}
