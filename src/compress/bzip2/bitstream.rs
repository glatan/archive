//! MSB-first bit reader and writer for bzip2 streams.
//!
//! bzip2 uses big-endian (MSB-first) bit ordering, unlike DEFLATE/zstd
//! which use LSB-first.

use crate::error::Error;
use alloc::vec::Vec;

/// MSB-first bit reader.
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_count: u8,
}

impl<'a> BitReader<'a> {
    /// Create a new bit reader over the given byte slice.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn fill(&mut self) {
        while self.bit_count <= 56 && self.pos < self.data.len() {
            self.bit_buf |= (self.data[self.pos] as u64) << (56 - self.bit_count);
            self.bit_count += 8;
            self.pos += 1;
        }
    }

    /// Read `n` bits (1..=32) as a u32, MSB-first.
    pub(crate) fn read_bits(&mut self, n: u8) -> Result<u32, Error> {
        debug_assert!(n <= 32 && n > 0);
        self.fill();
        if self.bit_count < n {
            return Err(Error::UnexpectedEof);
        }
        let value = (self.bit_buf >> (64 - n)) as u32;
        self.bit_buf <<= n;
        self.bit_count -= n;
        Ok(value)
    }

    /// Read a single bit.
    pub(crate) fn read_bool(&mut self) -> Result<bool, Error> {
        Ok(self.read_bits(1)? != 0)
    }

    /// Read `n` bits (1..=48) as a u64, MSB-first. Used for 48-bit magic numbers.
    pub(crate) fn read_bits_u64(&mut self, n: u8) -> Result<u64, Error> {
        debug_assert!(n <= 48 && n > 0);
        if n <= 32 {
            return Ok(self.read_bits(n)? as u64);
        }
        let hi = self.read_bits(n - 32)? as u64;
        let lo = self.read_bits(32)? as u64;
        Ok((hi << 32) | lo)
    }

    /// Read a byte (8 bits).
    pub(crate) fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.read_bits(8)? as u8)
    }

    /// Read a 32-bit unsigned integer.
    pub(crate) fn read_u32(&mut self) -> Result<u32, Error> {
        self.read_bits(32)
    }

    /// Discard any partial byte in the bit buffer and return the remaining
    /// unconsumed bytes from the underlying data slice.
    pub(crate) fn into_remaining(self) -> Vec<u8> {
        // Any bits currently in bit_buf were read-ahead from data[pos-N..pos].
        // We need to figure out how many whole bytes remain unconsumed.
        // The reader eagerly fills: it has consumed self.pos bytes from data,
        // but self.bit_count bits are buffered and not yet consumed by the caller.
        // The number of unconsumed whole bytes is bit_count / 8 (discard partial).
        let unconsumed_whole_bytes = (self.bit_count / 8) as usize;
        // These bytes came from data[pos - unconsumed_whole_bytes .. pos],
        // but we also have the rest of data[pos..].
        let start = self.pos - unconsumed_whole_bytes;
        self.data[start..].to_vec()
    }
}

/// MSB-first bit writer.
pub(crate) struct BitWriter {
    data: Vec<u8>,
    bit_buf: u64,
    bit_count: u8,
}

impl BitWriter {
    /// Create a new empty bit writer.
    pub(crate) const fn new() -> Self {
        Self {
            data: Vec::new(),
            bit_buf: 0,
            bit_count: 0,
        }
    }

    /// Write `n` bits (1..=32) from the low bits of `value`, MSB-first.
    pub(crate) fn write_bits(&mut self, value: u32, n: u8) {
        debug_assert!(n <= 32 && n > 0);
        let masked = if n == 32 {
            value as u64
        } else {
            (value as u64) & ((1u64 << n) - 1)
        };
        self.bit_buf |= masked << (64 - self.bit_count - n);
        self.bit_count += n;
        self.flush_bytes();
    }

    /// Write `n` bits (1..=48) from a u64, MSB-first.
    pub(crate) fn write_bits_u64(&mut self, value: u64, n: u8) {
        debug_assert!(n <= 48 && n > 0);
        if n <= 32 {
            self.write_bits(value as u32, n);
            return;
        }
        self.write_bits((value >> 32) as u32, n - 32);
        self.write_bits(value as u32, 32);
    }

    /// Write a single bit.
    pub(crate) fn write_bool(&mut self, bit: bool) {
        self.write_bits(bit as u32, 1);
    }

    /// Write a byte.
    pub(crate) fn write_u8(&mut self, value: u8) {
        self.write_bits(value as u32, 8);
    }

    /// Write a 32-bit unsigned integer.
    pub(crate) fn write_u32(&mut self, value: u32) {
        self.write_bits(value, 32);
    }

    fn flush_bytes(&mut self) {
        while self.bit_count >= 8 {
            self.data.push((self.bit_buf >> 56) as u8);
            self.bit_buf <<= 8;
            self.bit_count -= 8;
        }
    }

    /// Finish writing, padding the last byte with zeros.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.bit_count > 0 {
            self.data.push((self.bit_buf >> 56) as u8);
        }
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_bits() {
        let mut w = BitWriter::new();
        w.write_bits(0b101, 3);
        w.write_bits(0b11110000, 8);
        w.write_bits(0b1, 1);
        let data = w.finish();

        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(3).unwrap(), 0b101);
        assert_eq!(r.read_bits(8).unwrap(), 0b11110000);
        assert_eq!(r.read_bits(1).unwrap(), 1);
    }

    #[test]
    fn test_read_bool() {
        let data = [0b10110000];
        let mut r = BitReader::new(&data);
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
        assert!(r.read_bool().unwrap());
        assert!(r.read_bool().unwrap());
    }

    #[test]
    fn test_48bit_magic() {
        let mut w = BitWriter::new();
        w.write_bits_u64(0x314159265359, 48);
        let data = w.finish();

        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits_u64(48).unwrap(), 0x314159265359);
    }

    #[test]
    fn test_read_eof() {
        let data = [0xFF];
        let mut r = BitReader::new(&data);
        r.read_bits(8).unwrap();
        assert!(r.read_bits(1).is_err());
    }

    #[test]
    fn test_write_u32() {
        let mut w = BitWriter::new();
        w.write_u32(0xDEADBEEF);
        let data = w.finish();
        assert_eq!(data, [0xDE, 0xAD, 0xBE, 0xEF]);

        let mut r = BitReader::new(&data);
        assert_eq!(r.read_u32().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_bitwriter_finish_partial_bytes() {
        // Verify that finish() correctly pads partial bytes (1-7 bits)
        // with zero bits in the low positions.
        for num_bits in 1u8..=7 {
            let mut w = BitWriter::new();
            // Write `num_bits` ones
            let value = (1u32 << num_bits) - 1;
            w.write_bits(value, num_bits);
            let data = w.finish();

            // Should produce exactly one byte
            assert_eq!(data.len(), 1, "num_bits={num_bits}");

            // The written bits should be in the MSB positions, remaining
            // bits zero-padded. E.g. 3 bits of 0b111 → 0b1110_0000.
            let expected = value << (8 - num_bits);
            assert_eq!(
                data[0], expected as u8,
                "num_bits={num_bits}: expected {expected:#010b}, got {:#010b}",
                data[0]
            );

            // Reading back those bits through BitReader must recover the
            // original value.
            let mut r = BitReader::new(&data);
            assert_eq!(
                r.read_bits(num_bits).unwrap(),
                value,
                "num_bits={num_bits}: read-back mismatch"
            );
        }
    }
}
