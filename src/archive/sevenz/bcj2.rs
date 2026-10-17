//! BCJ2 filter for 7z x86 executables.
//!
//! The filter splits an x86 byte stream into a control stream plus
//! three data streams (`main`, `call`, `jump`); the control stream is
//! range-coded, and the relative targets of E8/E9 call/jump (and 0F 8x
//! jcc) instructions are converted so that they compress better.
//!
//! Ported from the public-domain LZMA SDK `Bcj2.c` (Igor Pavlov); see
//! `THIRD_PARTY_NOTICES` for provenance.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

const TOP_VALUE: u32 = 1 << 24;
const NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_TOTAL_BITS;
const NUM_MOVE_BITS: u32 = 5;

#[inline]
const fn is_jcc(prev: u8, current: u8) -> bool {
    prev == 0x0F && (current & 0xF0) == 0x80
}

#[inline]
const fn is_j(prev: u8, current: u8) -> bool {
    (current & 0xFE) == 0xE8 || is_jcc(prev, current)
}

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::UnexpectedEof);
        }
        let mut code = 0u32;
        for &byte in &data[..5] {
            code = (code << 8) | u32::from(byte);
        }
        if code == u32::MAX {
            return Err(Error::InvalidData("7z: invalid BCJ2 range coder state"));
        }
        Ok(Self {
            data,
            pos: 5,
            range: u32::MAX,
            code,
        })
    }

    fn normalize(&mut self) -> Result<(), Error> {
        if self.range < TOP_VALUE {
            let byte = *self.data.get(self.pos).ok_or(Error::UnexpectedEof)?;
            self.pos += 1;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(byte);
        }
        Ok(())
    }

    fn decode_bit(&mut self, prob: &mut u16) -> Result<bool, Error> {
        self.normalize()?;
        let bound = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * u32::from(*prob);
        if self.code < bound {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - u32::from(*prob)) >> NUM_MOVE_BITS) as u16;
            Ok(false)
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= (u32::from(*prob) >> NUM_MOVE_BITS) as u16;
            Ok(true)
        }
    }
}

/// Encoded BCJ2 output with four separate streams.
pub(super) struct Bcj2Encoded {
    /// Main stream (non-branch bytes + branch opcodes when selected).
    pub main: Vec<u8>,
    /// Call target stream (relative addresses for CALL instructions).
    pub call: Vec<u8>,
    /// Jump target stream (relative addresses for JMP/Jcc instructions).
    pub jump: Vec<u8>,
    /// Range coder stream (probability decisions).
    pub rc: Vec<u8>,
}

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u32,
    output: Vec<u8>,
}

impl RangeEncoder {
    const fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            cache: 0,
            cache_size: 1,
            output: Vec::new(),
        }
    }

    fn shift_low(&mut self) {
        if (self.low >> 32) != 0 || self.low < 0xFF00_0000 {
            let carry = (self.low >> 32) as u8;
            self.output.push(self.cache.wrapping_add(carry));
            for _ in 1..self.cache_size {
                self.output.push(0xFF_u8.wrapping_add(carry));
            }
            self.cache_size = 0;
            self.cache = ((self.low >> 24) & 0xFF) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    fn encode_bit(&mut self, prob: &mut u16, bit: bool) {
        let bound = (self.range >> NUM_BIT_MODEL_TOTAL_BITS) * u32::from(*prob);
        if !bit {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL - u32::from(*prob)) >> NUM_MOVE_BITS) as u16;
        } else {
            self.low += u64::from(bound);
            self.range -= bound;
            *prob -= (u32::from(*prob) >> NUM_MOVE_BITS) as u16;
        }
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.output
    }
}

/// Encode an input buffer into BCJ2 four-stream representation.
pub(super) fn encode(input: &[u8]) -> Bcj2Encoded {
    let mut main = Vec::new();
    let mut call = Vec::new();
    let mut jump = Vec::new();
    let mut rc_enc = RangeEncoder::new();
    let mut probs = vec![(BIT_MODEL_TOTAL >> 1) as u16; 258];
    let mut prev = 0u8;
    let mut pos = 0usize;

    while pos < input.len() {
        let byte = input[pos];
        main.push(byte);
        pos += 1;

        if !is_j(prev, byte) {
            prev = byte;
            continue;
        }

        let opcode = byte;
        let prob_index = if opcode == 0xE8 {
            usize::from(prev)
        } else if opcode == 0xE9 {
            256
        } else {
            257
        };

        if pos + 4 > input.len() {
            // Not enough bytes for a branch target, emit as non-branch
            rc_enc.encode_bit(&mut probs[prob_index], false);
            prev = opcode;
            continue;
        }

        // Always encode as a branch (bit = true)
        rc_enc.encode_bit(&mut probs[prob_index], true);

        // Read the 4-byte LE relative address from input
        let rel_addr =
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        pos += 4;

        // Convert to absolute address (add current position including the 4 bytes)
        let abs_addr = rel_addr.wrapping_add(pos as u32);
        let be_bytes = abs_addr.to_be_bytes();

        if opcode == 0xE8 {
            call.extend_from_slice(&be_bytes);
        } else {
            jump.extend_from_slice(&be_bytes);
        }

        prev = input[pos - 1]; // last byte of the address that was consumed
    }

    let rc = rc_enc.finish();

    Bcj2Encoded {
        main,
        call,
        jump,
        rc,
    }
}

pub(super) fn decode(
    main: &[u8],
    call: &[u8],
    jump: &[u8],
    rc: &[u8],
    expected_size: usize,
) -> Result<Vec<u8>, Error> {
    if expected_size > crate::util::bounded::DECLARED_OUTPUT_LIMIT {
        return Err(Error::OutputLimitExceeded {
            limit: crate::util::bounded::DECLARED_OUTPUT_LIMIT,
        });
    }
    let mut rc = RangeDecoder::new(rc)?;
    let mut probs = [((BIT_MODEL_TOTAL >> 1) as u16); 258];
    let mut out = Vec::with_capacity(expected_size.min(1 << 24));
    let mut prev = 0u8;
    let mut main_pos = 0usize;
    let mut call_pos = 0usize;
    let mut jump_pos = 0usize;

    while out.len() < expected_size {
        while main_pos < main.len() && out.len() < expected_size {
            let byte = main[main_pos];
            out.push(byte);
            if is_j(prev, byte) {
                break;
            }
            main_pos += 1;
            prev = byte;
        }

        // A J-opcode byte pushed to `out` still has its opcode pending
        // in `main` plus a decision bit in `rc` (the encoder emits the
        // bit even when fewer than 4 bytes remain). Only stop early
        // when `main` is drained, or when `out` is full and the pending
        // byte is not a branch opcode.
        if main_pos == main.len() || (out.len() == expected_size && !is_j(prev, main[main_pos])) {
            break;
        }

        let opcode = main[main_pos];
        main_pos += 1;
        let prob_index = if opcode == 0xE8 {
            usize::from(prev)
        } else if opcode == 0xE9 {
            256
        } else {
            257
        };

        if !rc.decode_bit(&mut probs[prob_index])? {
            prev = opcode;
            continue;
        }

        let source = if opcode == 0xE8 {
            let bytes = call
                .get(call_pos..call_pos + 4)
                .ok_or(Error::UnexpectedEof)?;
            call_pos += 4;
            bytes
        } else {
            let bytes = jump
                .get(jump_pos..jump_pos + 4)
                .ok_or(Error::UnexpectedEof)?;
            jump_pos += 4;
            bytes
        };

        let dest = u32::from_be_bytes([source[0], source[1], source[2], source[3]])
            .wrapping_sub((out.len() as u32).wrapping_add(4));
        let bytes = dest.to_le_bytes();
        if out.len() + bytes.len() > expected_size {
            return Err(Error::InvalidData("7z: BCJ2 output truncated mid-branch"));
        }
        out.extend_from_slice(&bytes);
        prev = bytes[3];
    }

    if out.len() != expected_size {
        return Err(Error::SizeMismatch {
            expected: expected_size as u32,
            actual: out.len() as u32,
        });
    }
    if main_pos != main.len() {
        return Err(Error::InvalidData(
            "7z: BCJ2 main stream not fully consumed",
        ));
    }
    if call_pos != call.len() {
        return Err(Error::InvalidData(
            "7z: BCJ2 call stream not fully consumed",
        ));
    }
    if jump_pos != jump.len() {
        return Err(Error::InvalidData(
            "7z: BCJ2 jump stream not fully consumed",
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_passthrough_without_branches() {
        let main = b"plain bcj2 payload";
        let decoded = decode(main, &[], &[], &[0, 0, 0, 0, 0], main.len()).unwrap();
        assert_eq!(decoded, main);
    }

    #[test]
    fn test_encode_decode_passthrough_without_branches() {
        let input = b"plain bcj2 payload";
        let encoded = encode(input);
        let decoded = decode(
            &encoded.main,
            &encoded.call,
            &encoded.jump,
            &encoded.rc,
            input.len(),
        )
        .unwrap();
        assert_eq!(decoded, input);
    }

    /// Regression (fuzz run-1791677246): an input ending in a J-opcode
    /// with fewer than 4 bytes left encodes a non-branch decision bit
    /// for that opcode. The decoder must still consume the opcode and
    /// its decision bit when `out` is already full.
    #[test]
    fn test_roundtrip_trailing_branch_opcode() {
        for input in [
            &[0xE9][..],
            &[0xE8][..],
            &[0x0F, 0x8F][..],
            &[0x90, 0xE9][..],
            &[0x90, 0x0F, 0x80][..],
        ] {
            let encoded = encode(input);
            let decoded = decode(
                &encoded.main,
                &encoded.call,
                &encoded.jump,
                &encoded.rc,
                input.len(),
            )
            .unwrap_or_else(|e| panic!("decode of {input:02x?} failed: {e}"));
            assert_eq!(decoded, input);
        }
    }

    /// A trailing J-opcode whose decision bit selects a real branch
    /// cannot append its 4-byte target once `out` is full.
    #[test]
    fn test_decode_trailing_branch_opcode_truncated_mid_branch() {
        let encoded = encode(&[0xE9, 0x01, 0x02, 0x03, 0x04]);
        let err = decode(&encoded.main, &encoded.call, &encoded.jump, &encoded.rc, 1).unwrap_err();
        assert!(matches!(err, Error::InvalidData(_)));
    }

    #[test]
    fn test_encode_decode_roundtrip_with_branches() {
        // Simple x86-like data with CALL and JMP instructions
        let mut input = Vec::new();
        input.push(0x90); // NOP
        input.push(0xE8); // CALL
        input.extend_from_slice(&0x00001234u32.to_le_bytes()); // relative address
        input.push(0x90); // NOP
        input.push(0xE9); // JMP
        input.extend_from_slice(&0xFFFFFF00u32.to_le_bytes()); // relative address
        input.push(0x90); // NOP

        let encoded = encode(&input);
        let decoded = decode(
            &encoded.main,
            &encoded.call,
            &encoded.jump,
            &encoded.rc,
            input.len(),
        )
        .unwrap();
        assert_eq!(decoded, input);
    }
}
