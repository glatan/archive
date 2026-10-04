// Ported from ppmd-rust (CC0-1.0 OR MIT-0); see the `compress::ppmd`
// module docs and THIRD_PARTY_NOTICES section 3.

use alloc::vec::Vec;

use crate::error::Error;

use super::K_TOP_VALUE;

pub(crate) struct RangeDecoder<'a> {
    pub(crate) range: u32,
    pub(crate) code: u32,
    input: &'a [u8],
    pos: usize,
}

impl<'a> RangeDecoder<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < 5 {
            return Err(Error::UnexpectedEof);
        }
        let mut decoder = Self {
            range: 0xFFFF_FFFF,
            code: 0,
            input,
            pos: 0,
        };
        if decoder.read_byte()? != 0 {
            return Err(Error::InvalidData(
                "ppmd: range decoder stream must start with 0x00",
            ));
        }
        for _ in 0..4 {
            decoder.code = (decoder.code << 8) | decoder.read_byte()?;
        }
        if decoder.code == 0xFFFF_FFFF {
            return Err(Error::InvalidData(
                "ppmd: invalid initial range decoder code",
            ));
        }
        Ok(decoder)
    }

    #[inline(always)]
    pub(crate) const fn get_threshold(&mut self, total: u32) -> u32 {
        self.range /= total;
        self.code / self.range
    }

    #[inline(always)]
    pub(crate) fn read_byte(&mut self) -> Result<u32, Error> {
        let Some(&byte) = self.input.get(self.pos) else {
            return Err(Error::UnexpectedEof);
        };
        self.pos += 1;
        Ok(byte as u32)
    }

    #[inline(always)]
    pub(crate) fn decode_bit_0(&mut self, size: u32) -> Result<(), Error> {
        self.range = size;
        self.normalize_1()?;
        Ok(())
    }

    #[inline(always)]
    pub(crate) const fn decode_bit_1(&mut self, size: u32) {
        self.code -= size;
        self.range -= size;
    }

    #[inline(always)]
    pub(crate) const fn decode(&mut self, start: u32, size: u32) {
        self.code -= start * self.range;
        self.range *= size;
    }

    #[inline(always)]
    pub(crate) fn decode_final(&mut self, start: u32, freq: u32) -> Result<(), Error> {
        self.decode(start, freq);
        self.normalize_remote()?;
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn normalize_remote(&mut self) -> Result<(), Error> {
        if self.range < (1 << 24) {
            self.code = (self.code << 8) | self.read_byte()?;
            self.range <<= 8;
            if self.range < (1 << 24) {
                self.code = (self.code << 8) | self.read_byte()?;
                self.range <<= 8;
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn normalize_1(&mut self) -> Result<(), Error> {
        if self.range < (1 << 24) {
            self.code = (self.code << 8) | self.read_byte()?;
            self.range <<= 8;
        }
        Ok(())
    }
}

pub(crate) struct RangeEncoder {
    pub(crate) range: u32,
    pub(crate) cache: u8,
    pub(crate) low: u64,
    pub(crate) cache_size: u64,
    output: Vec<u8>,
}

impl RangeEncoder {
    pub(crate) const fn new() -> Self {
        Self {
            range: 0xFFFF_FFFF,
            cache: 0,
            low: 0,
            cache_size: 1,
            output: Vec::new(),
        }
    }

    pub(crate) fn shift_low(&mut self) {
        if self.low < 0xFF00_0000 || (self.low >> 32) != 0 {
            let mut temp = self.cache;
            loop {
                let byte = (temp as u16 + (self.low >> 32) as u8 as u16) as u8;
                self.output.push(byte);
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low as u32 >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = ((self.low as u32) << 8) as u64;
    }

    #[inline(always)]
    pub(crate) fn encode_bit_0(&mut self, bound: u32) {
        self.range = bound;
        self.normalize_1();
    }

    #[inline(always)]
    pub(crate) const fn encode_bit_1(&mut self, bound: u32) {
        self.low += bound as u64;
        self.range -= bound;
    }

    #[inline(always)]
    pub(crate) const fn encode(&mut self, start: u32, size: u32) {
        self.low += (start * self.range) as u64;
        self.range *= size;
    }

    #[inline(always)]
    pub(crate) fn encode_final(&mut self, start: u32, freq: u32) {
        self.encode(start, freq);
        self.normalize_remote();
    }

    #[inline(always)]
    pub(crate) fn normalize_remote(&mut self) {
        if self.range < K_TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
            if self.range < K_TOP_VALUE {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    #[inline(always)]
    pub(crate) fn normalize_1(&mut self) {
        if self.range < (1 << 24) {
            self.range <<= 8;
            self.shift_low();
        }
    }

    pub(crate) fn flush(&mut self) {
        for _ in 0..5 {
            self.shift_low();
        }
    }

    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.output
    }
}
