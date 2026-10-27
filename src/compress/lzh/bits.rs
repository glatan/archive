//! MSB-first bit reader/writer for the LZH Huffman streams.
//!
//! LHA reads bits most-significant-first. The classic `getbits`/
//! `fillbuf` scheme (as observed in Okumura's `ar002` and lhasa) keeps
//! a 16-bit left-aligned window and zero-pads past the end of input;
//! this reader mirrors the zero-pad behaviour while tracking the real
//! end so callers can decide whether running out of bits is an error.

use alloc::vec::Vec;

/// MSB-first bit cursor over a byte slice.
pub(crate) struct MsbReader<'a> {
    data: &'a [u8],
    /// Bits consumed so far (may exceed `data.len() * 8` via padding).
    pos: u64,
}

impl<'a> MsbReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        MsbReader { data, pos: 0 }
    }

    /// Peek the next `n` bits (n <= 32) MSB-first, zero-padded past
    /// end of input, without consuming.
    pub(crate) fn peek(&self, n: u32) -> u32 {
        let mut v = 0u32;
        for i in 0..n {
            let bit = (self.pos + u64::from(i)) as usize;
            let b = if bit / 8 < self.data.len() {
                u32::from((self.data[bit / 8] >> (7 - bit % 8)) & 1)
            } else {
                0
            };
            v = (v << 1) | b;
        }
        v
    }

    /// Consume `n` bits (n <= 32) MSB-first, zero-padded past end.
    pub(crate) fn get(&mut self, n: u32) -> u32 {
        let v = self.peek(n);
        self.pos += u64::from(n);
        v
    }

    /// Number of real (non-padding) bits consumed past the end, if any.
    pub(crate) fn overran(&self) -> bool {
        self.pos > self.data.len() as u64 * 8
    }
}

/// MSB-first bit writer (encoders and test mirror encoders).
pub(crate) struct MsbWriter {
    bytes: Vec<u8>,
    /// Pending bits; wider than `u32` so `put` can accept `n` up to 32
    /// while up to 7 bits are still buffered.
    acc: u64,
    nbits: u32,
}

impl MsbWriter {
    pub(crate) fn new() -> Self {
        MsbWriter {
            bytes: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    /// Emit the low `n` bits of `v` (n <= 32), MSB of the field first.
    pub(crate) fn put(&mut self, v: u32, n: u32) {
        debug_assert!(n <= 32);
        self.acc = (self.acc << n) | (u64::from(v) & ((1u64 << n) - 1));
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.bytes.push((self.acc >> self.nbits) as u8);
        }
        self.acc &= (1u64 << self.nbits) - 1;
    }

    /// Flush, zero-padding the tail byte; returns the byte stream.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.bytes.push((self.acc << (8 - self.nbits)) as u8);
        }
        debug_assert!(self.nbits < 8);
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_reads_msb_first_and_zero_pads() {
        let mut reader = MsbReader::new(&[0b1010_0110, 0xFF]);
        assert_eq!(reader.peek(4), 0b1010);
        assert_eq!(reader.get(4), 0b1010);
        assert_eq!(reader.get(4), 0b0110);
        assert!(!reader.overran());
        assert_eq!(reader.get(2), 0b11);
        assert_eq!(reader.get(8), 0xFC);
        assert!(reader.overran());
    }

    #[test]
    fn writer_roundtrips_mixed_widths() {
        let mut writer = MsbWriter::new();
        writer.put(0b101, 3);
        writer.put(0x3F, 6);
        writer.put(0x1234, 16);
        writer.put(0, 7);
        let bytes = writer.finish();

        let mut reader = MsbReader::new(&bytes);
        assert_eq!(reader.get(3), 0b101);
        assert_eq!(reader.get(6), 0x3F);
        assert_eq!(reader.get(16), 0x1234);
        assert_eq!(reader.get(7), 0);
        assert!(!reader.overran());
    }
}
