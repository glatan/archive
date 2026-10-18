//! Branch/Call/Jump conversion filters.
//!
//! The current shared implementation exposes x86, PowerPC, IA64, SPARC, ARM,
//! ARM-Thumb, ARM64, and RISC-V BCJ filters that are used by XZ / 7z style
//! filter chains.
//!
//! Ported from the public-domain liblzma `simple/` filters. See
//! `THIRD_PARTY_NOTICES` section 2.

use alloc::vec::Vec;

mod pattern;

const MASK_TO_BIT_NUMBER: [u32; 5] = [0, 1, 2, 2, 3];

#[inline]
fn read32le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

#[inline]
fn read32be(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

#[inline]
fn write32le(data: &mut [u8], value: u32) {
    data[..4].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn write32be(data: &mut [u8], value: u32) {
    data[..4].copy_from_slice(&value.to_be_bytes());
}

#[inline]
const fn not_auipc_pair(auipc: u32, inst2: u32) -> bool {
    ((((auipc) << 8) ^ (inst2.wrapping_sub(3))) & 0xF8003) != 0
}

#[inline]
const fn not_special_auipc(auipc: u32, inst2_rs1: u32) -> bool {
    ((auipc.wrapping_sub(0x3117)) << 18) >= (inst2_rs1 & 0x1D)
}

/// Stateful x86 BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X86Filter {
    pos: u32,
    prev_mask: u32,
    prev_pos: u32,
}

impl X86Filter {
    /// Create a new x86 BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self {
            pos: start_offset,
            prev_mask: 0,
            prev_pos: u32::MAX - 4,
        }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        self.code_from(buffer, is_encoder, false)
    }

    fn code_from(&mut self, buffer: &mut [u8], is_encoder: bool, scalar_scan: bool) -> usize {
        if buffer.len() < 5 {
            self.pos = self.pos.wrapping_add(buffer.len() as u32);
            return 0;
        }

        let now_pos = self.pos;
        let mut prev_mask = self.prev_mask;
        let mut prev_pos = self.prev_pos;

        if now_pos.wrapping_sub(prev_pos) > 5 {
            prev_pos = now_pos.wrapping_sub(5);
        }

        let limit = buffer.len() - 5;
        let mut buffer_pos = 0usize;

        while buffer_pos <= limit {
            let found = if scalar_scan {
                crate::compress::scan::find_byte_scalar(buffer, buffer_pos, limit, 0xE8, Some(0xE9))
            } else {
                crate::compress::scan::find_byte(buffer, buffer_pos, limit, 0xE8, Some(0xE9))
            };
            let Some(at) = found else {
                buffer_pos = limit + 1;
                break;
            };
            buffer_pos = at;
            buffer_pos += apply_x86(
                buffer,
                buffer_pos,
                now_pos,
                &mut prev_mask,
                &mut prev_pos,
                is_encoder,
            );
        }

        self.prev_mask = prev_mask;
        self.prev_pos = prev_pos;
        self.pos = self.pos.wrapping_add(buffer_pos as u32);
        buffer_pos
    }
}

fn apply_x86(
    buffer: &mut [u8],
    buffer_pos: usize,
    now_pos: u32,
    prev_mask: &mut u32,
    prev_pos: &mut u32,
    is_encoder: bool,
) -> usize {
    let offset = now_pos
        .wrapping_add(buffer_pos as u32)
        .wrapping_sub(*prev_pos);
    *prev_pos = now_pos.wrapping_add(buffer_pos as u32);

    if offset > 5 {
        *prev_mask = 0;
    } else {
        for _ in 0..offset {
            *prev_mask &= 0x77;
            *prev_mask <<= 1;
        }
    }

    let mut b = buffer[buffer_pos + 4];

    if test_86_ms_byte(b) && (*prev_mask >> 1) <= 4 && (*prev_mask >> 1) != 3 {
        let mut src = ((b as u32) << 24)
            | ((buffer[buffer_pos + 3] as u32) << 16)
            | ((buffer[buffer_pos + 2] as u32) << 8)
            | (buffer[buffer_pos + 1] as u32);

        let dest = loop {
            let dest = if is_encoder {
                src.wrapping_add(now_pos.wrapping_add(buffer_pos as u32).wrapping_add(5))
            } else {
                src.wrapping_sub(now_pos.wrapping_add(buffer_pos as u32).wrapping_add(5))
            };

            if *prev_mask == 0 {
                break dest;
            }

            let i = MASK_TO_BIT_NUMBER[(*prev_mask >> 1) as usize];
            b = (dest >> (24 - i * 8)) as u8;
            if !test_86_ms_byte(b) {
                break dest;
            }

            src = dest ^ ((1u32 << (32 - i * 8)) - 1);
        };

        buffer[buffer_pos + 4] = !((((dest >> 24) & 1) as u8).wrapping_sub(1));
        buffer[buffer_pos + 3] = (dest >> 16) as u8;
        buffer[buffer_pos + 2] = (dest >> 8) as u8;
        buffer[buffer_pos + 1] = dest as u8;
        *prev_mask = 0;
        5
    } else {
        *prev_mask |= 1;
        if test_86_ms_byte(b) {
            *prev_mask |= 0x10;
        }
        1
    }
}

/// Encode x86 machine code using the BCJ filter.
pub fn x86_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = X86Filter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode x86 machine code using the BCJ filter.
pub fn x86_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = X86Filter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful PowerPC BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerPcFilter {
    pos: u32,
}

impl PowerPcFilter {
    /// Create a new PowerPC BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self { pos: start_offset }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        let size = buffer.len() & !3;
        let now_pos = self.pos;
        let mut i = 0usize;
        while i + 16 <= size {
            let hits = ppc_group_hits(&buffer[i..i + 16]);
            let mut k = 0;
            while k < 4 {
                if hits & (1 << k) != 0 {
                    let at = i + k * 4;
                    ppc_apply(
                        &mut buffer[at..at + 4],
                        now_pos.wrapping_add(at as u32),
                        is_encoder,
                    );
                }
                k += 1;
            }
            i += 16;
        }
        while i < size {
            if ppc_match(&buffer[i..]) {
                ppc_apply(
                    &mut buffer[i..i + 4],
                    now_pos.wrapping_add(i as u32),
                    is_encoder,
                );
            }
            i += 4;
        }
        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

fn ppc_match(buf: &[u8]) -> bool {
    (buf[0] >> 2) == 0x12 && (buf[3] & 0x03) == 0x01
}

fn ppc_apply(buf: &mut [u8], now_pos: u32, is_encoder: bool) {
    let src = (((buf[0] as u32) & 0x03) << 24)
        | ((buf[1] as u32) << 16)
        | ((buf[2] as u32) << 8)
        | ((buf[3] as u32) & !0x03);
    let dest = if is_encoder {
        now_pos.wrapping_add(src)
    } else {
        src.wrapping_sub(now_pos)
    };
    buf[0] = 0x48 | ((dest >> 24) & 0x03) as u8;
    buf[1] = (dest >> 16) as u8;
    buf[2] = (dest >> 8) as u8;
    buf[3] = (buf[3] & 0x03) | dest as u8;
}

fn ppc_group_hits(chunk: &[u8]) -> u32 {
    const MASK: [u8; 16] = [
        0xFC, 0x00, 0x00, 0x03, 0xFC, 0x00, 0x00, 0x03, 0xFC, 0x00, 0x00, 0x03, 0xFC, 0x00, 0x00,
        0x03,
    ];
    const EXPECT: [u8; 16] = [
        0x48, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00,
        0x01,
    ];
    pattern::groups_of_four(pattern::pattern_bits(chunk, &MASK, &EXPECT))
}

/// Encode PowerPC machine code using the BCJ filter.
pub fn powerpc_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = PowerPcFilter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode PowerPC machine code using the BCJ filter.
pub fn powerpc_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = PowerPcFilter::new(start_offset).decode_in_place(&mut output);
    output
}

const IA64_BRANCH_TABLE: [u32; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
];

/// Stateful IA64 BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ia64Filter {
    pos: u32,
}

impl Ia64Filter {
    /// Create a new IA64 BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self { pos: start_offset }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        let size = buffer.len() & !15;
        let now_pos = self.pos;

        let mut i = 0usize;
        while i < size {
            let instr_template = (buffer[i] & 0x1F) as usize;
            let mask = IA64_BRANCH_TABLE[instr_template];
            let mut bit_pos = 5u32;

            for slot in 0..3 {
                if ((mask >> slot) & 1) == 0 {
                    bit_pos += 41;
                    continue;
                }

                let byte_pos = (bit_pos >> 3) as usize;
                let bit_res = bit_pos & 0x7;
                let mut instruction = 0u64;
                for j in 0..6 {
                    instruction |= (buffer[i + j + byte_pos] as u64) << (8 * j);
                }

                let mut inst_norm = instruction >> bit_res;
                if ((inst_norm >> 37) & 0xF) == 0x5 && ((inst_norm >> 9) & 0x7) == 0 {
                    let mut src = ((inst_norm >> 13) & 0xFFFFF) as u32;
                    src |= (((inst_norm >> 36) & 1) as u32) << 20;
                    src <<= 4;

                    let mut dest = if is_encoder {
                        now_pos.wrapping_add(i as u32).wrapping_add(src)
                    } else {
                        src.wrapping_sub(now_pos.wrapping_add(i as u32))
                    };

                    dest >>= 4;
                    inst_norm &= !((0x8FFFFFu64) << 13);
                    inst_norm |= ((dest & 0xFFFFF) as u64) << 13;
                    inst_norm |= ((dest & 0x100000) as u64) << (36 - 20);

                    instruction &= (1u64 << bit_res) - 1;
                    instruction |= inst_norm << bit_res;

                    for j in 0..6 {
                        buffer[i + j + byte_pos] = (instruction >> (8 * j)) as u8;
                    }
                }

                bit_pos += 41;
            }

            i += 16;
        }

        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

/// Encode IA64 machine code using the BCJ filter.
pub fn ia64_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = Ia64Filter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode IA64 machine code using the BCJ filter.
pub fn ia64_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = Ia64Filter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful SPARC BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparcFilter {
    pos: u32,
}

impl SparcFilter {
    /// Create a new SPARC BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self { pos: start_offset }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        let size = buffer.len() & !3;
        let now_pos = self.pos;
        let mut i = 0usize;
        while i + 16 <= size {
            let hits = sparc_group_hits(&buffer[i..i + 16]);
            let mut k = 0;
            while k < 4 {
                if hits & (1 << k) != 0 {
                    let at = i + k * 4;
                    sparc_apply(
                        &mut buffer[at..at + 4],
                        now_pos.wrapping_add(at as u32),
                        is_encoder,
                    );
                }
                k += 1;
            }
            i += 16;
        }
        while i < size {
            if sparc_match(&buffer[i..]) {
                sparc_apply(
                    &mut buffer[i..i + 4],
                    now_pos.wrapping_add(i as u32),
                    is_encoder,
                );
            }
            i += 4;
        }
        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

fn sparc_match(buf: &[u8]) -> bool {
    (buf[0] == 0x40 && (buf[1] & 0xC0) == 0x00) || (buf[0] == 0x7F && (buf[1] & 0xC0) == 0xC0)
}

fn sparc_apply(buf: &mut [u8], now_pos: u32, is_encoder: bool) {
    let mut src =
        ((buf[0] as u32) << 24) | ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
    src <<= 2;
    let mut dest = if is_encoder {
        now_pos.wrapping_add(src)
    } else {
        src.wrapping_sub(now_pos)
    };
    dest >>= 2;
    dest = (((0u32.wrapping_sub((dest >> 22) & 1)) << 22) & 0x3FFF_FFFF)
        | (dest & 0x003F_FFFF)
        | 0x4000_0000;
    buf[0] = (dest >> 24) as u8;
    buf[1] = (dest >> 16) as u8;
    buf[2] = (dest >> 8) as u8;
    buf[3] = dest as u8;
}

fn sparc_group_hits(chunk: &[u8]) -> u32 {
    const MASK: [u8; 16] = [
        0xFF, 0xC0, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x00, 0xFF, 0xC0, 0x00,
        0x00,
    ];
    const CALL: [u8; 16] = [
        0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
        0x00,
    ];
    const JUMP: [u8; 16] = [
        0x7F, 0xC0, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x7F, 0xC0, 0x00,
        0x00,
    ];
    pattern::groups_of_four(pattern::pattern_bits(chunk, &MASK, &CALL))
        | pattern::groups_of_four(pattern::pattern_bits(chunk, &MASK, &JUMP))
}

/// Encode SPARC machine code using the BCJ filter.
pub fn sparc_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = SparcFilter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode SPARC machine code using the BCJ filter.
pub fn sparc_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = SparcFilter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful ARM BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmFilter {
    pos: u32,
}

impl ArmFilter {
    /// Create a new ARM BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self { pos: start_offset }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        let size = buffer.len() & !3;
        let now_pos = self.pos;

        // Branch bytes sit at index 3 of each aligned instruction. The
        // shared scanner finds `0xEB`; only those aligned hits are rewritten.
        let mut probe = 3usize;
        while probe < size {
            let Some(at) = crate::compress::scan::find_byte(buffer, probe, size - 1, 0xEB, None)
            else {
                break;
            };
            if at % 4 != 3 {
                let rem = at % 4;
                probe = at + (3 - rem);
                continue;
            }
            let i = at - 3;
            let mut src =
                ((buffer[i + 2] as u32) << 16) | ((buffer[i + 1] as u32) << 8) | buffer[i] as u32;
            src <<= 2;

            let mut dest = if is_encoder {
                now_pos
                    .wrapping_add(i as u32)
                    .wrapping_add(8)
                    .wrapping_add(src)
            } else {
                src.wrapping_sub(now_pos.wrapping_add(i as u32).wrapping_add(8))
            };

            dest >>= 2;
            buffer[i + 2] = (dest >> 16) as u8;
            buffer[i + 1] = (dest >> 8) as u8;
            buffer[i] = dest as u8;
            probe = at + 4;
        }

        self.pos = self.pos.wrapping_add(size as u32);
        size
    }
}

/// Encode ARM machine code using the BCJ filter.
pub fn arm_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = ArmFilter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode ARM machine code using the BCJ filter.
pub fn arm_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = ArmFilter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful ARM-Thumb BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmThumbFilter {
    pos: u32,
}

impl ArmThumbFilter {
    /// Create a new ARM-Thumb BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self { pos: start_offset }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        if buffer.len() < 4 {
            return 0;
        }

        let size = buffer.len() - 4;
        let now_pos = self.pos;
        let mut i = 0usize;

        while i <= size {
            let Some(at) = thumb_next(buffer, i, size) else {
                i = even_finish(i, size);
                break;
            };
            i = at;
            let mut src = (((buffer[i + 1] as u32) & 0x07) << 19)
                | ((buffer[i] as u32) << 11)
                | (((buffer[i + 3] as u32) & 0x07) << 8)
                | (buffer[i + 2] as u32);
            src <<= 1;

            let mut dest = if is_encoder {
                now_pos
                    .wrapping_add(i as u32)
                    .wrapping_add(4)
                    .wrapping_add(src)
            } else {
                src.wrapping_sub(now_pos.wrapping_add(i as u32).wrapping_add(4))
            };

            dest >>= 1;
            buffer[i + 1] = 0xF0 | ((dest >> 19) & 0x07) as u8;
            buffer[i] = (dest >> 11) as u8;
            buffer[i + 3] = 0xF8 | ((dest >> 8) & 0x07) as u8;
            buffer[i + 2] = dest as u8;
            i += 4;
        }

        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

/// Encode ARM-Thumb machine code using the BCJ filter.
pub fn armthumb_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = ArmThumbFilter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode ARM-Thumb machine code using the BCJ filter.
pub fn armthumb_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = ArmThumbFilter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful ARM64 BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64Filter {
    pos: u32,
}

impl Arm64Filter {
    /// Create a new ARM64 BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self {
            pos: start_offset & !3,
        }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, true)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.code(buffer, false)
    }

    fn code(&mut self, buffer: &mut [u8], is_encoder: bool) -> usize {
        let size = buffer.len() & !3;
        let now_pos = self.pos;

        let mut i = 0usize;
        while i + 16 <= size {
            let hits = arm64_group_hits(&buffer[i..i + 16]);
            let mut k = 0;
            while k < 4 {
                if hits & (1 << k) != 0 {
                    let at = i + k * 4;
                    arm64_apply(
                        &mut buffer[at..at + 4],
                        now_pos.wrapping_add(at as u32),
                        is_encoder,
                    );
                }
                k += 1;
            }
            i += 16;
        }
        while i < size {
            arm64_apply(
                &mut buffer[i..i + 4],
                now_pos.wrapping_add(i as u32),
                is_encoder,
            );
            i += 4;
        }

        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

fn arm64_apply(buf: &mut [u8], mut pc: u32, is_encoder: bool) {
    let mut instr = read32le(buf);
    if (instr >> 26) == 0x25 {
        let src = instr;
        instr = 0x9400_0000;
        pc >>= 2;
        if !is_encoder {
            pc = 0u32.wrapping_sub(pc);
        }
        instr |= src.wrapping_add(pc) & 0x03FF_FFFF;
        write32le(buf, instr);
    } else if (instr & 0x9F00_0000) == 0x9000_0000 {
        let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
        if ((src + 0x0002_0000) & 0x001C_0000) != 0 {
            return;
        }
        instr &= 0x9000_001F;
        pc >>= 12;
        if !is_encoder {
            pc = 0u32.wrapping_sub(pc);
        }
        let dest = src.wrapping_add(pc);
        instr |= (dest & 3) << 29;
        instr |= (dest & 0x0003_FFFC) << 3;
        instr |= (0u32.wrapping_sub(dest & 0x0002_0000)) & 0x00E0_0000;
        write32le(buf, instr);
    }
}

fn arm64_group_hits(chunk: &[u8]) -> u32 {
    const BL_MASK: [u8; 16] = [
        0x00, 0x00, 0x00, 0xFC, 0x00, 0x00, 0x00, 0xFC, 0x00, 0x00, 0x00, 0xFC, 0x00, 0x00, 0x00,
        0xFC,
    ];
    const BL: [u8; 16] = [
        0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00,
        0x94,
    ];
    const ADRP_MASK: [u8; 16] = [
        0x00, 0x00, 0x00, 0x9F, 0x00, 0x00, 0x00, 0x9F, 0x00, 0x00, 0x00, 0x9F, 0x00, 0x00, 0x00,
        0x9F,
    ];
    const ADRP: [u8; 16] = [
        0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00,
        0x90,
    ];
    pattern::groups_of_four(pattern::pattern_bits(chunk, &BL_MASK, &BL))
        | pattern::groups_of_four(pattern::pattern_bits(chunk, &ADRP_MASK, &ADRP))
}

/// Encode ARM64 machine code using the BCJ filter.
pub fn arm64_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = Arm64Filter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode ARM64 machine code using the BCJ filter.
pub fn arm64_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = Arm64Filter::new(start_offset).decode_in_place(&mut output);
    output
}

/// Stateful RISC-V BCJ converter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiscVFilter {
    pos: u32,
}

impl RiscVFilter {
    /// Create a new RISC-V BCJ filter with the given start offset.
    pub const fn new(start_offset: u32) -> Self {
        Self {
            pos: start_offset & !1,
        }
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.encode(buffer)
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) -> usize {
        self.decode(buffer)
    }

    fn encode(&mut self, buffer: &mut [u8]) -> usize {
        if buffer.len() < 8 {
            return 0;
        }

        let size = buffer.len() - 8;
        let now_pos = self.pos;
        let mut i = 0usize;

        while i <= size {
            if !riscv_candidate(buffer[i]) {
                let Some(at) = riscv_next(buffer, i, size) else {
                    i = even_finish(i, size);
                    break;
                };
                i = at;
            }
            let mut inst = buffer[i] as u32;

            if inst == 0xEF {
                let b1 = buffer[i + 1] as u32;
                if (b1 & 0x0D) != 0 {
                    i += 2;
                    continue;
                }

                let b2 = buffer[i + 2] as u32;
                let b3 = buffer[i + 3] as u32;
                let pc = now_pos.wrapping_add(i as u32);

                let addr = ((b1 & 0xF0) << 8)
                    | ((b2 & 0x0F) << 16)
                    | ((b2 & 0x10) << 7)
                    | ((b2 & 0xE0) >> 4)
                    | ((b3 & 0x7F) << 4)
                    | ((b3 & 0x80) << 13);
                let addr = addr.wrapping_add(pc);

                buffer[i + 1] = ((b1 & 0x0F) | ((addr >> 13) & 0xF0)) as u8;
                buffer[i + 2] = (addr >> 9) as u8;
                buffer[i + 3] = (addr >> 1) as u8;
                i += 4;
                continue;
            } else if (inst & 0x7F) == 0x17 {
                inst |= (buffer[i + 1] as u32) << 8;
                inst |= (buffer[i + 2] as u32) << 16;
                inst |= (buffer[i + 3] as u32) << 24;

                if (inst & 0xE80) != 0 {
                    let inst2 = read32le(&buffer[i + 4..]);
                    if not_auipc_pair(inst, inst2) {
                        i += 6;
                        continue;
                    }

                    let mut addr = inst & 0xFFFF_F000;
                    addr = addr
                        .wrapping_add(inst2 >> 20)
                        .wrapping_sub((inst2 >> 19) & 0x1000)
                        .wrapping_add(now_pos.wrapping_add(i as u32));

                    inst = 0x17 | (2 << 7) | (inst2 << 12);
                    write32le(&mut buffer[i..], inst);
                    write32be(&mut buffer[i + 4..], addr);
                } else {
                    let fake_rs1 = inst >> 27;
                    if not_special_auipc(inst, fake_rs1) {
                        i += 4;
                        continue;
                    }

                    let fake_addr = read32le(&buffer[i + 4..]);
                    let fake_inst2 = (inst >> 12) | (fake_addr << 20);
                    inst = 0x17 | (fake_rs1 << 7) | (fake_addr & 0xFFFF_F000);
                    write32le(&mut buffer[i..], inst);
                    write32le(&mut buffer[i + 4..], fake_inst2);
                }

                i += 8;
                continue;
            }

            i += 2;
        }

        self.pos = self.pos.wrapping_add(i as u32);
        i
    }

    fn decode(&mut self, buffer: &mut [u8]) -> usize {
        if buffer.len() < 8 {
            return 0;
        }

        let size = buffer.len() - 8;
        let now_pos = self.pos;
        let mut i = 0usize;

        while i <= size {
            if !riscv_candidate(buffer[i]) {
                let Some(at) = riscv_next(buffer, i, size) else {
                    i = even_finish(i, size);
                    break;
                };
                i = at;
            }
            let mut inst = buffer[i] as u32;

            if inst == 0xEF {
                let b1 = buffer[i + 1] as u32;
                if (b1 & 0x0D) != 0 {
                    i += 2;
                    continue;
                }

                let b2 = buffer[i + 2] as u32;
                let b3 = buffer[i + 3] as u32;
                let pc = now_pos.wrapping_add(i as u32);

                let addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
                let addr = addr.wrapping_sub(pc);

                buffer[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
                buffer[i + 2] =
                    (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
                buffer[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
                i += 4;
                continue;
            } else if (inst & 0x7F) == 0x17 {
                inst |= (buffer[i + 1] as u32) << 8;
                inst |= (buffer[i + 2] as u32) << 16;
                inst |= (buffer[i + 3] as u32) << 24;

                let inst2;
                let new_inst;
                if (inst & 0xE80) != 0 {
                    let inst2_candidate = read32le(&buffer[i + 4..]);
                    if not_auipc_pair(inst, inst2_candidate) {
                        i += 6;
                        continue;
                    }

                    let addr = (inst & 0xFFFF_F000).wrapping_add(inst2_candidate >> 20);
                    new_inst = 0x17 | (2 << 7) | (inst2_candidate << 12);
                    inst2 = addr;
                } else {
                    let inst2_rs1 = inst >> 27;
                    if not_special_auipc(inst, inst2_rs1) {
                        i += 4;
                        continue;
                    }

                    let addr =
                        read32be(&buffer[i + 4..]).wrapping_sub(now_pos.wrapping_add(i as u32));
                    inst2 = (inst >> 12) | (addr << 20);
                    new_inst = 0x17 | (inst2_rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
                }

                write32le(&mut buffer[i..], new_inst);
                write32le(&mut buffer[i + 4..], inst2);
                i += 8;
                continue;
            }

            i += 2;
        }

        self.pos = self.pos.wrapping_add(i as u32);
        i
    }
}

/// Encode RISC-V machine code using the BCJ filter.
pub fn riscv_encode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = RiscVFilter::new(start_offset).encode_in_place(&mut output);
    output
}

/// Decode RISC-V machine code using the BCJ filter.
pub fn riscv_decode(input: &[u8], start_offset: u32) -> Vec<u8> {
    let mut output = input.to_vec();
    let _ = RiscVFilter::new(start_offset).decode_in_place(&mut output);
    output
}

const fn test_86_ms_byte(byte: u8) -> bool {
    byte == 0 || byte == 0xFF
}
fn even_finish(i: usize, size: usize) -> usize {
    if i > size {
        i
    } else {
        i + ((size - i) / 2 + 1) * 2
    }
}

fn thumb_match(buf: &[u8]) -> bool {
    (buf[1] & 0xF8) == 0xF0 && (buf[3] & 0xF8) == 0xF8
}

fn thumb_pair_hits(chunk: &[u8]) -> u32 {
    let mask = [0xF8u8; 16];
    let f0 = [0xF0u8; 16];
    let f8 = [0xF8u8; 16];
    let high = pattern::pattern_bits(chunk, &mask, &f0);
    let low = pattern::pattern_bits(chunk, &mask, &f8);
    let mut hits = 0u32;
    let mut k = 0;
    while k <= 12 {
        if ((high >> (k + 1)) & 1) == 1 && ((low >> (k + 3)) & 1) == 1 {
            hits |= 1 << k;
        }
        k += 2;
    }
    hits
}

fn thumb_next(buffer: &[u8], i: usize, size: usize) -> Option<usize> {
    let mut j = i;
    while j <= size {
        if j + 16 <= buffer.len() && j + 12 <= size {
            let hits = thumb_pair_hits(&buffer[j..j + 16]);
            if hits != 0 {
                let rel = hits.trailing_zeros() as usize;
                if j + rel <= size {
                    return Some(j + rel);
                }
            } else {
                j += 14;
                continue;
            }
        }
        if thumb_match(&buffer[j..]) {
            return Some(j);
        }
        j += 2;
    }
    None
}

fn riscv_candidate(byte: u8) -> bool {
    byte == 0xEF || (byte & 0x7F) == 0x17
}

fn riscv_hits(chunk: &[u8]) -> u32 {
    let ones = [0xFFu8; 16];
    let ef = [0xEFu8; 16];
    let op17 = [0x17u8; 16];
    let op97 = [0x97u8; 16];
    (pattern::pattern_bits(chunk, &ones, &ef)
        | pattern::pattern_bits(chunk, &ones, &op17)
        | pattern::pattern_bits(chunk, &ones, &op97))
        & 0x5555
}

fn riscv_next(buffer: &[u8], i: usize, size: usize) -> Option<usize> {
    let mut j = i;
    while j <= size {
        if j + 16 <= buffer.len() && j + 14 <= size {
            let hits = riscv_hits(&buffer[j..j + 16]);
            if hits != 0 {
                let rel = hits.trailing_zeros() as usize;
                if j + rel <= size {
                    return Some(j + rel);
                }
            } else {
                j += 16;
                continue;
            }
        }
        if riscv_candidate(buffer[j]) {
            return Some(j);
        }
        j += 2;
    }
    None
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_x86_known_vector_matches_liblzma() {
        let input = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0x00,
            0x00, 0x00, 0x00, 0x90, 0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90,
        ];
        let expected = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xFC, 0xFF, 0xFF, 0xFF, 0xE8, 0x11,
            0x00, 0x00, 0x00, 0x90, 0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90,
        ];
        assert_eq!(x86_encode(&input, 0), expected);
        assert_eq!(x86_decode(&expected, 0), input);
    }

    #[test]
    fn test_x86_processed_bytes_leaves_last_four_bytes() {
        let mut input = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0x00,
            0x00, 0x00, 0x00, 0x90, 0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90,
        ];
        let processed = X86Filter::new(0).encode_in_place(&mut input);
        assert_eq!(processed, 21);
        assert_eq!(&input[21..], &[0x22, 0x33, 0x44, 0x90]);
    }

    #[test]
    fn test_x86_scan_matches_scalar_bytes() {
        let mut samples: Vec<Vec<u8>> = vec![
            vec![0u8; 64],
            vec![0xE8; 80],
            vec![0xE9; 48],
            (0..200u32).map(|i| i as u8).collect(),
        ];
        let mut dense = vec![0x90u8; 120];
        for i in (0..120).step_by(3) {
            dense[i] = if i % 2 == 0 { 0xE8 } else { 0xE9 };
        }
        samples.push(dense);
        for sample in samples {
            for offset in [0u32, 1, 5, 13] {
                let mut scalar_filter = X86Filter::new(offset);
                let mut vector_filter = X86Filter::new(offset);
                let mut scalar = sample.clone();
                let mut vector = sample.clone();
                let n_scalar = scalar_filter.code_from(&mut scalar, true, true);
                let n_vector = vector_filter.encode_in_place(&mut vector);
                assert_eq!(n_scalar, n_vector, "offset {offset}");
                assert_eq!(scalar, vector, "offset {offset}");
                assert_eq!(scalar_filter, vector_filter);
                assert_eq!(x86_decode(&vector, offset), sample);
            }
        }
    }

    #[test]
    fn test_x86_streaming_matches_one_shot() {
        let input = vec![
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0x00,
            0x00, 0x00, 0x00, 0x90, 0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90,
        ];
        let one_shot = x86_encode(&input, 0);
        let mut streaming = input;
        let mut filter = X86Filter::new(0);
        let first = filter.encode_in_place(&mut streaming[..13]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(first, 12);
        assert_eq!(second, 9);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn test_powerpc_roundtrip() {
        let input = [
            0x48, 0x12, 0x34, 0x01, 0x60, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x01,
        ];
        let encoded = powerpc_encode(&input, 0);
        assert_eq!(powerpc_decode(&encoded, 0), input);
    }

    #[test]
    fn test_powerpc_streaming_matches_one_shot() {
        let input = vec![
            0x48, 0x12, 0x34, 0x01, 0x60, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x01,
        ];
        let one_shot = powerpc_encode(&input, 0);
        let mut streaming = input;
        let mut filter = PowerPcFilter::new(0);
        let first = filter.encode_in_place(&mut streaming[..8]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(first, 8);
        assert_eq!(second, 4);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn test_sparc_roundtrip() {
        let input = [0x40, 0x00, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00];
        let encoded = sparc_encode(&input, 0);
        assert_eq!(sparc_decode(&encoded, 0), input);
    }

    #[test]
    fn test_ia64_roundtrip() {
        let input = [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0xA0,
        ];
        let encoded = ia64_encode(&input, 0x1000);
        assert_eq!(ia64_decode(&encoded, 0x1000), input);
    }

    #[test]
    fn test_ia64_streaming_matches_one_shot() {
        let input = vec![
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0xA0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00, 0x00, 0xA0,
        ];
        let one_shot = ia64_encode(&input, 0x1000);
        let mut streaming = input;
        let mut filter = Ia64Filter::new(0x1000);
        let first = filter.encode_in_place(&mut streaming[..16]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(first, 16);
        assert_eq!(second, 16);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn test_aligned_group_matches_stride() {
        let patterns = [
            vec![0u8; 80],
            (0..200u32).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
            [0x48u8, 0, 0, 1].repeat(20),
            [0x40u8, 0, 0, 0].repeat(20),
            [0x7Fu8, 0xC0, 0, 0].repeat(16),
            {
                let mut arm64 = vec![0u8; 64];
                for i in (0..64).step_by(8) {
                    arm64[i + 3] = 0x94;
                    arm64[i + 7] = 0x90;
                }
                arm64
            },
            [0xF0u8, 0xF0, 0x00, 0xF8].repeat(20),
        ];
        for input in patterns {
            let mut ppc_stride = input.clone();
            let size = ppc_stride.len() & !3;
            let mut i = 0;
            while i < size {
                if ppc_match(&ppc_stride[i..]) {
                    ppc_apply(&mut ppc_stride[i..i + 4], i as u32, true);
                }
                i += 4;
            }
            assert_eq!(powerpc_encode(&input, 0), ppc_stride);

            let mut sparc_stride = input.clone();
            i = 0;
            while i < size {
                if sparc_match(&sparc_stride[i..]) {
                    sparc_apply(&mut sparc_stride[i..i + 4], i as u32, true);
                }
                i += 4;
            }
            assert_eq!(sparc_encode(&input, 0), sparc_stride);

            let mut arm64_stride = input.clone();
            i = 0;
            while i < size {
                arm64_apply(&mut arm64_stride[i..i + 4], i as u32, true);
                i += 4;
            }
            assert_eq!(arm64_encode(&input, 0), arm64_stride);
        }

        let thumb_input = [0x11u8, 0xF0, 0x22, 0xF8].repeat(30);
        let encoded = armthumb_encode(&thumb_input, 4);
        let mut stride = thumb_input.clone();
        let size = stride.len() - 4;
        let mut i = 0usize;
        while i <= size {
            if thumb_match(&stride[i..]) {
                let mut src = (((stride[i + 1] as u32) & 0x07) << 19)
                    | ((stride[i] as u32) << 11)
                    | (((stride[i + 3] as u32) & 0x07) << 8)
                    | (stride[i + 2] as u32);
                src <<= 1;
                let mut dest = 4u32
                    .wrapping_add(i as u32)
                    .wrapping_add(4)
                    .wrapping_add(src);
                dest >>= 1;
                stride[i + 1] = 0xF0 | ((dest >> 19) & 0x07) as u8;
                stride[i] = (dest >> 11) as u8;
                stride[i + 3] = 0xF8 | ((dest >> 8) & 0x07) as u8;
                stride[i + 2] = dest as u8;
                i += 2;
            }
            i += 2;
        }
        assert_eq!(encoded, stride);

        let mut quiet = vec![0u8; 40];
        assert_eq!(RiscVFilter::new(0).encode_in_place(&mut quiet), 34);
        let mut thumb_quiet = vec![0u8; 20];
        assert_eq!(ArmThumbFilter::new(0).encode_in_place(&mut thumb_quiet), 18);
        let riscv = {
            let mut data = vec![0u8; 64];
            data[0] = 0xEF;
            data[8] = 0x17;
            data[20] = 0x97;
            data
        };
        let size = riscv.len() - 8;
        let mut seen = Vec::new();
        let mut j = 0usize;
        while j <= size {
            match riscv_next(&riscv, j, size) {
                Some(at) => {
                    seen.push(at);
                    j = at + 2;
                }
                None => break,
            }
        }
        let mut expect = Vec::new();
        j = 0;
        while j <= size {
            if riscv_candidate(riscv[j]) {
                expect.push(j);
            }
            j += 2;
        }
        assert_eq!(seen, expect);
    }

    #[test]
    fn test_arm_scan_matches_stride_loop() {
        fn scalar(input: &[u8], start: u32) -> Vec<u8> {
            let mut buffer = input.to_vec();
            let size = buffer.len() & !3;
            let mut i = 0usize;
            while i < size {
                if buffer[i + 3] == 0xEB {
                    let mut src = ((buffer[i + 2] as u32) << 16)
                        | ((buffer[i + 1] as u32) << 8)
                        | buffer[i] as u32;
                    src <<= 2;
                    let mut dest = start
                        .wrapping_add(i as u32)
                        .wrapping_add(8)
                        .wrapping_add(src);
                    dest >>= 2;
                    buffer[i + 2] = (dest >> 16) as u8;
                    buffer[i + 1] = (dest >> 8) as u8;
                    buffer[i] = dest as u8;
                }
                i += 4;
            }
            buffer
        }

        let mut samples = vec![vec![0u8; 64], vec![0xEB; 80]];
        let mut mixed = (0..200u32).map(|i| i as u8).collect::<Vec<_>>();
        for i in (3..mixed.len()).step_by(4) {
            mixed[i] = 0xEB;
        }
        mixed[1] = 0xEB;
        mixed[2] = 0xEB;
        samples.push(mixed);
        for sample in samples {
            assert_eq!(arm_encode(&sample, 0), scalar(&sample, 0));
            assert_eq!(arm_encode(&sample, 8), scalar(&sample, 8));
        }
    }

    #[test]
    fn test_arm_roundtrip() {
        let input = [0x01, 0x02, 0x03, 0xEB, 0x00, 0x00, 0x00, 0x00];
        let encoded = arm_encode(&input, 0);
        assert_eq!(arm_decode(&encoded, 0), input);
    }

    #[test]
    fn test_arm_streaming_matches_one_shot() {
        let input = vec![
            0x01, 0x02, 0x03, 0xEB, 0x00, 0x00, 0x00, 0x00, 0x04, 0x05, 0x06, 0xEB,
        ];
        let one_shot = arm_encode(&input, 0);
        let mut streaming = input;
        let mut filter = ArmFilter::new(0);
        let first = filter.encode_in_place(&mut streaming[..8]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(first, 8);
        assert_eq!(second, 4);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn test_armthumb_roundtrip() {
        let input = [0x00, 0xF0, 0x00, 0xF8, 0xFF, 0xFF];
        let encoded = armthumb_encode(&input, 0);
        assert_eq!(armthumb_decode(&encoded, 0), input);
    }

    #[test]
    fn test_armthumb_streaming_matches_one_shot() {
        let input = vec![0x00, 0xF0, 0x00, 0xF8, 0x11, 0x22, 0x00, 0xF0, 0x00, 0xF8];
        let one_shot = armthumb_encode(&input, 0);
        let mut streaming = input;
        let mut filter = ArmThumbFilter::new(0);
        let first = filter.encode_in_place(&mut streaming[..6]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(streaming, one_shot);
        assert_eq!(
            armthumb_decode(&streaming, 0),
            vec![0x00, 0xF0, 0x00, 0xF8, 0x11, 0x22, 0x00, 0xF0, 0x00, 0xF8]
        );
        assert!(first <= 6);
        assert!(second <= 6);
    }

    #[test]
    fn test_arm64_roundtrip() {
        let input = [0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90];
        let encoded = arm64_encode(&input, 0x1000);
        assert_eq!(arm64_decode(&encoded, 0x1000), input);
    }

    #[test]
    fn test_arm64_streaming_matches_one_shot() {
        let input = vec![
            0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x94, 0x00, 0x00,
            0x00, 0x90,
        ];
        let one_shot = arm64_encode(&input, 0x1000);
        let mut streaming = input;
        let mut filter = Arm64Filter::new(0x1000);
        let first = filter.encode_in_place(&mut streaming[..8]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(first, 8);
        assert_eq!(second, 8);
        assert_eq!(streaming, one_shot);
    }

    #[test]
    fn test_riscv_roundtrip() {
        let input = [0xEF, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
        let encoded = riscv_encode(&input, 0x1000);
        assert_eq!(riscv_decode(&encoded, 0x1000), input);
    }

    #[test]
    fn test_riscv_auipc_non_pair_roundtrip() {
        // Regression (fuzz run-1791310276): `not_auipc_pair` must treat
        // any non-zero masked result as "not a pair". Here the mask
        // yields 3, which the buggy `!= 3` check misread as a real pair
        // and the encoder rewrote the bytes into an undecodable form.
        let input = [0x17, 0x15, 0x4C, 0xA3, 0x5A, 0x69, 0xD5, 0xD8];
        let encoded = riscv_encode(&input, 0);
        assert_eq!(riscv_decode(&encoded, 0), input);
    }

    #[test]
    fn test_riscv_special_auipc_roundtrip() {
        // Same regression on the decode side: this input already looks
        // like the encoded rd=x2 special form, so the decoder converts
        // it and the encoder must restore it exactly.
        let input = [0x17, 0x71, 0xC6, 0x31, 0x62, 0x9B, 0x2D, 0x4E];
        let encoded = riscv_encode(&input, 0);
        assert_eq!(riscv_decode(&encoded, 0), input);
    }

    #[test]
    fn test_riscv_special_auipc_reads_be_absolute_address() {
        // Regression (fuzz run-1791310276): the encoded special format
        // stores the absolute address big endian (encoder `write32be`),
        // so the decoder must use `read32be`. Expected output matches
        // liblzma `lzma_bcj_riscv_decode` at start_offset 0x7884.
        let encoded = [0x17, 0x31, 0xD9, 0x70, 0x83, 0xD1, 0x7C, 0xE6];
        let decoded = [0x17, 0x07, 0xD1, 0x83, 0x93, 0x0D, 0x27, 0x46];
        assert_eq!(riscv_decode(&encoded, 0x7884), decoded);
        assert_eq!(riscv_encode(&decoded, 0x7884), encoded);
    }

    #[test]
    fn test_riscv_streaming_matches_one_shot() {
        let input = vec![
            0xEF, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0xEF, 0x00, 0x00, 0x00, 0x13, 0x00,
            0x00, 0x00,
        ];
        let one_shot = riscv_encode(&input, 0x1000);
        let mut streaming = input;
        let mut filter = RiscVFilter::new(0x1000);
        let first = filter.encode_in_place(&mut streaming[..8]);
        let second = filter.encode_in_place(&mut streaming[first..]);
        assert_eq!(streaming, one_shot);
        assert!(first <= 8);
        assert!(second <= 8);
    }
}
