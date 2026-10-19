//! LSB-first bit reader for DEFLATE and Brotli streams.

use crate::error::Error;

/// LSB-first bit reader for DEFLATE and Brotli streams.
///
/// Reads bits from a byte slice, consuming bits from the least significant
/// bit of each byte first. No method on this type panics (debug assertions
/// exist for `n <= 57` in debug builds only).
///
/// # Examples
///
/// ```ignore
/// use archive::util::bitreader::BitReader;
///
/// let data = [0b1010_0011u8, 0xFF];
/// let mut reader = BitReader::new(&data);
/// assert_eq!(reader.read_bits(4).unwrap(), 0b0011); // low nibble first
/// assert_eq!(reader.read_bits(4).unwrap(), 0b1010);
/// ```
#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_count: u8,
}

impl<'a> BitReader<'a> {
    /// Create a new bit reader over the given byte slice.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let reader = BitReader::new(&[0x00, 0xFF]);
    /// assert_eq!(reader.remaining_bytes(), 2);
    /// ```
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    /// Ensure at least `n` bits are available in the bit buffer.
    fn fill(&mut self, n: u8) -> Result<(), Error> {
        while self.bit_count < n {
            if self.pos >= self.data.len() {
                return Err(Error::UnexpectedEof);
            }
            self.bit_buf |= (self.data[self.pos] as u64) << self.bit_count;
            self.pos += 1;
            self.bit_count += 8;
        }
        Ok(())
    }

    /// Fill the bit buffer with as many bits as available (no EOF error).
    /// Used by peek_bits to allow Huffman table lookups at end of stream.
    fn fill_available(&mut self) {
        while self.bit_count < 57 && self.pos < self.data.len() {
            self.bit_buf |= (self.data[self.pos] as u64) << self.bit_count;
            self.pos += 1;
            self.bit_count += 8;
        }
    }

    /// Read `n` bits (0..=57) from the stream, LSB first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `n` bits remain.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0b1101_0110]);
    /// assert_eq!(r.read_bits(3).unwrap(), 0b110);
    /// assert_eq!(r.read_bits(5).unwrap(), 0b11010);
    /// ```
    pub fn read_bits(&mut self, n: u8) -> Result<u32, Error> {
        debug_assert!(n <= 57);
        if n == 0 {
            return Ok(0);
        }
        self.fill(n)?;
        let mask = (1u64 << n) - 1;
        let value = (self.bit_buf & mask) as u32;
        self.bit_buf >>= n;
        self.bit_count -= n;
        Ok(value)
    }

    /// Peek at the next `n` bits without consuming them.
    ///
    /// At end of stream, if fewer than `n` bits remain, the missing
    /// high bits are implicitly zero. This is safe for Huffman table lookups
    /// where the actual symbol may be shorter than `max_bits`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] only if zero bits are available.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0xAB]);
    /// let bits = r.peek_bits(8).unwrap();
    /// assert_eq!(bits, 0xAB);
    /// // peek does not consume
    /// assert_eq!(r.remaining_bytes(), 1);
    /// ```
    pub fn peek_bits(&mut self, n: u8) -> Result<u32, Error> {
        debug_assert!(n <= 57);
        if n == 0 {
            return Ok(0);
        }
        if self.bit_count < n {
            self.fill_available();
            if self.bit_count == 0 {
                return Err(Error::UnexpectedEof);
            }
        }
        let mask = (1u64 << n) - 1;
        Ok((self.bit_buf & mask) as u32)
    }

    /// Consume `n` bits that were previously peeked.
    ///
    /// If `n` exceeds `bit_count` (possible after a zero-padded peek at end
    /// of stream), all remaining bits are consumed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0xFF]);
    /// r.peek_bits(4).unwrap();
    /// r.consume(4);
    /// assert_eq!(r.read_bits(4).unwrap(), 0xF);
    /// ```
    pub const fn consume(&mut self, n: u8) {
        if n >= self.bit_count {
            self.bit_buf = 0;
            self.bit_count = 0;
        } else {
            self.bit_buf >>= n;
            self.bit_count -= n;
        }
    }

    /// Discard remaining bits in the current byte, aligning to the next byte boundary.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0xFF, 0x42]);
    /// r.read_bits(3).unwrap();
    /// r.align_to_byte();
    /// assert_eq!(r.read_bits(8).unwrap(), 0x42);
    /// ```
    pub const fn align_to_byte(&mut self) {
        let discard = self.bit_count % 8;
        if discard > 0 {
            self.bit_buf >>= discard;
            self.bit_count -= discard;
        }
    }

    /// Discard bits up to the next byte boundary, requiring them to be zero.
    #[cfg_attr(not(any(test, feature = "brotli")), allow(dead_code))]
    pub const fn align_to_byte_if_zero(&mut self) -> Result<(), Error> {
        let discard = self.bit_count % 8;
        if discard > 0 {
            let mask = (1u64 << discard) - 1;
            if self.bit_buf & mask != 0 {
                return Err(Error::InvalidData("non-zero padding bits"));
            }
            self.bit_buf >>= discard;
            self.bit_count -= discard;
        }
        Ok(())
    }

    /// Read `n` whole bytes from the stream (must be byte-aligned).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `n` bytes remain.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0x01, 0x02, 0x03]);
    /// let bytes = r.read_bytes(2).unwrap();
    /// assert_eq!(bytes, &[0x01, 0x02]);
    /// ```
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        self.align_to_byte();
        // Drain any buffered complete bytes back
        let buffered_bytes = (self.bit_count / 8) as usize;
        if buffered_bytes >= n {
            // All requested bytes are in the bit buffer
            let result_pos = self.pos - buffered_bytes;
            let result = &self.data[result_pos..result_pos + n];
            // Consume n bytes from the bit buffer
            self.bit_buf >>= (n as u8) * 8;
            self.bit_count -= (n as u8) * 8;
            return Ok(result);
        }
        // Put buffered bytes back into the stream
        self.pos -= buffered_bytes;
        self.bit_buf = 0;
        self.bit_count = 0;

        if self.pos + n > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let result = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(result)
    }

    /// Read a little-endian `u16` from the stream (must be byte-aligned).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than 2 bytes remain.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0x34, 0x12]);
    /// assert_eq!(r.read_u16_le().unwrap(), 0x1234);
    /// ```
    #[cfg_attr(not(feature = "deflate"), allow(dead_code))]
    pub fn read_u16_le(&mut self) -> Result<u16, Error> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the number of unconsumed bytes remaining.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0x00; 4]);
    /// assert_eq!(r.remaining_bytes(), 4);
    /// r.read_bytes(2).unwrap();
    /// assert_eq!(r.remaining_bytes(), 2);
    /// ```
    #[allow(dead_code)]
    pub(crate) const fn remaining_bytes(&self) -> usize {
        self.data.len() - self.pos + (self.bit_count / 8) as usize
    }

    /// Return the current byte position in the underlying data.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[0x00; 4]);
    /// assert_eq!(r.byte_position(), 0);
    /// r.read_bytes(3).unwrap();
    /// assert_eq!(r.byte_position(), 3);
    /// ```
    #[cfg_attr(not(any(feature = "gzip", feature = "zlib")), allow(dead_code))]
    pub const fn byte_position(&self) -> usize {
        self.pos - (self.bit_count / 8) as usize
    }

    /// Consume all remaining bytes and return them as a slice.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::bitreader::BitReader;
    /// let mut r = BitReader::new(&[1, 2, 3, 4]);
    /// r.read_bytes(2).unwrap();
    /// let rest = r.remaining_data();
    /// assert_eq!(rest, &[3, 4]);
    /// ```
    #[allow(dead_code)]
    pub(crate) fn remaining_data(&mut self) -> &'a [u8] {
        self.align_to_byte();
        let buffered = (self.bit_count / 8) as usize;
        let start = self.pos - buffered;
        self.bit_buf = 0;
        self.bit_count = 0;
        self.pos = self.data.len();
        &self.data[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bits() {
        // 0xAB = 0b1010_1011 (LSB first: bits 1,1,0,1,0,1,0,1)
        let data = [0xAB, 0xCD];
        let mut reader = BitReader::new(&data);

        // Read 4 bits: should get low nibble of 0xAB = 0xB = 0b1011
        assert_eq!(reader.read_bits(4).unwrap(), 0xB); // LSB nibble
        // Read next 4 bits: should get high nibble = 0xA = 0b1010
        assert_eq!(reader.read_bits(4).unwrap(), 0xA);
        // Read 8 bits: should get 0xCD
        assert_eq!(reader.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn test_read_bits_zero() {
        let data = [0xFF];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(0).unwrap(), 0);
    }

    #[test]
    fn test_read_bits_crosses_byte_boundary_direct() {
        let data = [0xAB, 0xCD];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(12).unwrap(), 0xDAB);
        assert_eq!(reader.read_bits(4).unwrap(), 0xC);
    }

    #[test]
    fn test_peek_and_consume() {
        let data = [0xAB, 0xCD];
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.peek_bits(4).unwrap(), 0xB); // LSB nibble
        // peek should not consume
        assert_eq!(reader.peek_bits(4).unwrap(), 0xB);
        reader.consume(4);
        assert_eq!(reader.read_bits(4).unwrap(), 0xA);
    }

    #[test]
    fn test_align_to_byte() {
        let data = [0xFF, 0x42];
        let mut reader = BitReader::new(&data);
        reader.read_bits(3).unwrap(); // read 3 bits
        reader.align_to_byte(); // skip remaining 5 bits
        assert_eq!(reader.read_bits(8).unwrap(), 0x42);
    }

    #[test]
    fn test_align_to_byte_if_zero_ok() {
        let data = [0x00, 0x42];
        let mut reader = BitReader::new(&data);
        reader.read_bits(3).unwrap();
        reader.align_to_byte_if_zero().unwrap();
        assert_eq!(reader.read_bits(8).unwrap(), 0x42);
    }

    #[test]
    fn test_align_to_byte_if_zero_rejects_non_zero_padding() {
        let data = [0x1F, 0x42];
        let mut reader = BitReader::new(&data);
        reader.read_bits(3).unwrap();
        assert!(matches!(
            reader.align_to_byte_if_zero(),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_read_bytes() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut reader = BitReader::new(&data);
        let bytes = reader.read_bytes(2).unwrap();
        assert_eq!(bytes, &[0x01, 0x02]);
        let bytes = reader.read_bytes(2).unwrap();
        assert_eq!(bytes, &[0x03, 0x04]);
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_u16_le().unwrap(), 0x1234);
    }

    #[test]
    fn test_unexpected_eof() {
        let data = [0xFF];
        let mut reader = BitReader::new(&data);
        reader.read_bits(8).unwrap();
        assert!(reader.read_bits(1).is_err());
    }

    #[test]
    fn test_read_bytes_eof() {
        let data = [0x01];
        let mut reader = BitReader::new(&data);
        assert!(reader.read_bytes(2).is_err());
    }

    #[test]
    fn test_read_u16_le_eof() {
        let data = [0x01];
        let mut reader = BitReader::new(&data);
        assert!(reader.read_u16_le().is_err());
    }

    #[test]
    fn test_remaining_bytes() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.remaining_bytes(), 4);
        reader.read_bytes(1).unwrap();
        // After reading 1 byte, 3 remain
        assert_eq!(reader.remaining_bytes(), 3);
        reader.read_bytes(2).unwrap();
        assert_eq!(reader.remaining_bytes(), 1);
    }

    #[test]
    fn test_byte_position() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.byte_position(), 0);
        reader.read_bytes(1).unwrap();
        // After reading 1 byte
        assert_eq!(reader.byte_position(), 1);
        reader.read_bytes(2).unwrap();
        assert_eq!(reader.byte_position(), 3);
    }

    #[test]
    fn test_remaining_bytes_after_partial_bits() {
        // Verify remaining_bytes and byte_position are consistent after
        // reading partial bits (not aligned to byte boundary).
        let data = [0xFF, 0xAA, 0x55];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.remaining_bytes(), 3);
        assert_eq!(reader.byte_position(), 0);

        // Read 4 bits — bit_count should be 4 (from fill: read 1 byte, bit_count=8, then consume 4 → 4)
        reader.read_bits(4).unwrap();
        // After fill(4): pos=1, bit_count=8. After consume 4: bit_count=4.
        // remaining_bytes = 3 - 1 + 4/8 = 2. byte_position = 1 - 4/8 = 1.
        // But fill reads full bytes: pos=1, bit_count=4.
        // remaining_bytes = len(3) - pos(1) + bit_count/8(0) = 2
        assert_eq!(reader.remaining_bytes(), 2);
        assert_eq!(reader.byte_position(), 1);

        // Read 4 more bits (completes first byte)
        reader.read_bits(4).unwrap();
        assert_eq!(reader.remaining_bytes(), 2);
        assert_eq!(reader.byte_position(), 1);
    }

    #[test]
    fn test_remaining_data() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut reader = BitReader::new(&data);
        reader.read_bytes(2).unwrap();
        let rest = reader.remaining_data();
        assert_eq!(rest, &[0x03, 0x04]);
        // After remaining_data, reader should be at end
        assert_eq!(reader.remaining_bytes(), 0);
    }

    #[test]
    fn test_read_bits_max_57() {
        // 8 bytes of data, read 57 bits at once (the maximum allowed)
        let data = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let mut reader = BitReader::new(&data);
        let val = reader.read_bits(57).unwrap();
        // bit_buf after loading 8 bytes (LE): 0x8877665544332211
        // 57-bit mask: 0x01FFFFFFFFFFFFFF
        // masked value: 0x0077665544332211, truncated to u32: 0x44332211
        assert_eq!(val, 0x4433_2211);
    }

    #[test]
    fn test_read_bytes_zero() {
        let data = [0x01, 0x02, 0x03];
        let mut reader = BitReader::new(&data);
        let bytes = reader.read_bytes(0).unwrap();
        assert!(bytes.is_empty());
        // Reader position should be unchanged
        assert_eq!(reader.remaining_bytes(), 3);
    }

    #[test]
    fn test_peek_bits_zero_padded_at_eof() {
        let data = [0b1111_0000];
        let mut reader = BitReader::new(&data);

        assert_eq!(reader.read_bits(4).unwrap(), 0);
        assert_eq!(reader.peek_bits(8).unwrap(), 0x0F);
        reader.consume(8);
        assert!(matches!(reader.read_bits(1), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_read_bytes_served_from_bit_buffer() {
        // peek_bits buffers bytes without consuming them; read_bytes
        // must return those buffered bytes and keep the rest readable.
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.peek_bits(32).unwrap(), 0x0403_0201);
        assert_eq!(reader.read_bytes(3).unwrap(), &[0x01, 0x02, 0x03]);
        for expected in [0x04u32, 0x05, 0x06, 0x07, 0x08] {
            assert_eq!(reader.read_bits(8).unwrap(), expected);
        }
        assert_eq!(reader.remaining_bytes(), 0);
    }

    #[test]
    fn test_read_bytes_put_back_past_buffered() {
        // peek_bits fills the bit buffer (8 bytes on a 10-byte input);
        // read_bytes(9) exceeds the buffered 8 bytes, so they are put
        // back and the bytes are re-read from the stream.
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A];
        let mut reader = BitReader::new(&data);
        reader.peek_bits(8).unwrap();
        assert_eq!(reader.read_bytes(9).unwrap(), &data[..9]);
        assert_eq!(reader.byte_position(), 9);
        assert_eq!(reader.read_bits(8).unwrap(), 0x0Au32);
    }

    #[test]
    fn test_peek_bits_at_empty_stream() {
        let data: [u8; 0] = [];
        let mut reader = BitReader::new(&data);
        // peek_bits(0) succeeds even on an empty stream.
        assert_eq!(reader.peek_bits(0).unwrap(), 0);
        // A non-empty peek on a fully drained stream errors.
        assert!(matches!(reader.peek_bits(1), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_consume_more_than_buffered() {
        let data = [0xAB];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.peek_bits(8).unwrap(), 0xAB);
        // Consuming more bits than buffered drains the whole buffer.
        reader.consume(57);
        assert!(matches!(reader.read_bits(1), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_read_bits_past_end() {
        let data = [0xFF];
        let mut reader = BitReader::new(&data);
        // Reading more bits than the stream holds fails during fill.
        assert!(matches!(reader.read_bits(9), Err(Error::UnexpectedEof)));
        // The failed read leaves the buffered byte intact.
        assert_eq!(reader.read_bits(8).unwrap(), 0xFF);
    }

    #[test]
    fn test_remaining_data_unaligned() {
        // remaining_data discards partial bits and returns whole bytes
        // from the next byte boundary onward.
        let data = [0xFF, 0xAA, 0xBB];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(4).unwrap(), 0xF);
        assert_eq!(reader.remaining_data(), &[0xAA, 0xBB]);
        assert_eq!(reader.remaining_bytes(), 0);
    }
}
