//! Arithmetic encoder and decoder for ZPAQ.
//!
//! Uses a 32-bit range coder with carry propagation.  The probability
//! `p` is in the range 0..65536 where 0 means the bit is certainly 0
//! and 65535 means the bit is almost certainly 1.

use alloc::vec::Vec;

/// Arithmetic encoder.
pub(crate) struct ArithEncoder {
    x1: u32,
    x2: u32,
    output: Vec<u8>,
}

impl ArithEncoder {
    pub const fn new() -> Self {
        Self {
            x1: 0,
            x2: 0xFFFFFFFF,
            output: Vec::new(),
        }
    }

    /// Encode a single bit with the given probability (0..65536) that
    /// the bit is 1.
    pub fn encode(&mut self, bit: u8, prob: u32) {
        let xmid = self.x1
            + ((self.x2 - self.x1) >> 16) * prob
            + ((((self.x2 - self.x1) & 0xFFFF) * prob) >> 16);
        if bit != 0 {
            self.x2 = xmid;
        } else {
            self.x1 = xmid + 1;
        }
        self.normalize();
    }

    fn normalize(&mut self) {
        while ((self.x1 ^ self.x2) & 0xFF000000) == 0 {
            self.output.push((self.x2 >> 24) as u8);
            self.x1 <<= 8;
            self.x2 = (self.x2 << 8) | 0xFF;
        }
    }

    /// Flush remaining bytes and return the compressed output.
    pub fn finish(mut self) -> Vec<u8> {
        self.output.push((self.x1 >> 24) as u8);
        self.output.push((self.x1 >> 16) as u8);
        self.output.push((self.x1 >> 8) as u8);
        self.output.push(self.x1 as u8);
        self.output
    }
}

/// Arithmetic decoder.
pub(crate) struct ArithDecoder<'a> {
    x1: u32,
    x2: u32,
    x: u32,
    data: &'a [u8],
    pos: usize,
}

impl<'a> ArithDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let mut dec = Self {
            x1: 0,
            x2: 0xFFFFFFFF,
            x: 0,
            data,
            pos: 0,
        };
        // Read initial 4 bytes into x
        for _ in 0..4 {
            dec.x = (dec.x << 8) | dec.read_byte() as u32;
        }
        dec
    }

    fn read_byte(&mut self) -> u8 {
        if self.pos < self.data.len() {
            let b = self.data[self.pos];
            self.pos += 1;
            b
        } else {
            0
        }
    }

    /// Decode a single bit given probability (0..65536) that the bit is 1.
    pub fn decode(&mut self, prob: u32) -> u8 {
        let xmid = self.x1
            + ((self.x2 - self.x1) >> 16) * prob
            + ((((self.x2 - self.x1) & 0xFFFF) * prob) >> 16);
        let bit = if self.x <= xmid { 1u8 } else { 0u8 };
        if bit != 0 {
            self.x2 = xmid;
        } else {
            self.x1 = xmid + 1;
        }
        self.normalize();
        bit
    }

    fn normalize(&mut self) {
        while ((self.x1 ^ self.x2) & 0xFF000000) == 0 {
            self.x1 <<= 8;
            self.x2 = (self.x2 << 8) | 0xFF;
            self.x = (self.x << 8) | self.read_byte() as u32;
        }
    }
}
