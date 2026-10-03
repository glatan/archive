//! Shared range coder (arithmetic coding).
//!
//! Shared range coder used by LZMA-style entropy coding. It encodes/decodes
//! binary decisions with adaptive probability models (11-bit precision).
//! The carry-less design (constants and the `cache`/`cache_size`
//! `shift_low` structure) follows the public-domain LZMA SDK range
//! coder (Subbotin scheme); see `THIRD_PARTY_NOTICES`.

use alloc::vec::Vec;

use crate::error::Error;

/// Number of bits in probability model.
const NUM_BIT_MODEL_BITS: u32 = 11;

/// Total probability range (2^11 = 2048).
const BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_BITS;

/// Shift amount for probability adaptation.
const NUM_MOVE_BITS: u32 = 5;

/// Normalization threshold for the range.
const TOP_VALUE: u32 = 1 << 24;

/// Initial probability value (50/50).
pub(crate) const PROB_INIT: u16 = (BIT_MODEL_TOTAL / 2) as u16;

// ── Decoder ──────────────────────────────────────────────────────────────

/// Shared range decoder.
pub(crate) struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    /// Create a new range decoder.
    ///
    /// Reads the initial 5-byte header: the first byte must be 0x00,
    /// and the next 4 bytes form the initial `code` (big-endian).
    pub(crate) fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::UnexpectedEof);
        }
        if data[0] != 0x00 {
            return Err(Error::InvalidData(
                "range coder: stream must start with 0x00",
            ));
        }
        let code = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        // The initial code must be strictly less than the initial range (0xFFFFFFFF).
        // A code of 0xFFFFFFFF would indicate a corrupted or invalid stream.
        if code == 0xFFFF_FFFF {
            return Err(Error::InvalidData("range coder: invalid initial code"));
        }
        Ok(Self {
            data,
            pos: 5,
            range: 0xFFFF_FFFF,
            code,
        })
    }

    /// Normalize the range coder state by reading a byte when range is small.
    #[inline]
    fn normalize(&mut self) -> Result<(), Error> {
        if self.range < TOP_VALUE {
            if self.pos >= self.data.len() {
                return Err(Error::UnexpectedEof);
            }
            self.range <<= 8;
            self.code = (self.code << 8) | self.data[self.pos] as u32;
            self.pos += 1;
        }
        Ok(())
    }

    /// Decode a single bit using an adaptive probability model.
    #[inline]
    pub(crate) fn decode_bit(&mut self, prob: &mut u16) -> Result<u32, Error> {
        self.normalize()?;
        let bound = (self.range >> NUM_BIT_MODEL_BITS) * (*prob as u32);
        if self.code < bound {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL as u16) - *prob) >> NUM_MOVE_BITS;
            Ok(0)
        } else {
            self.range -= bound;
            self.code -= bound;
            *prob -= *prob >> NUM_MOVE_BITS;
            Ok(1)
        }
    }

    /// Decode `count` direct (fixed 50/50 probability) bits.
    pub(crate) fn decode_direct_bits(&mut self, count: u32) -> Result<u32, Error> {
        let mut result = 0u32;
        for _ in 0..count {
            self.normalize()?;
            self.range >>= 1;
            let t = (self.code.wrapping_sub(self.range)) >> 31;
            self.code -= self.range & (t.wrapping_sub(1));
            result = (result << 1) | (1 - t);
        }
        Ok(result)
    }

    /// Decode a bit-tree of `num_bits` bits (MSB-first context model).
    ///
    /// `probs` must have at least `1 << num_bits` entries.
    pub(crate) fn decode_bit_tree(
        &mut self,
        probs: &mut [u16],
        num_bits: u32,
    ) -> Result<u32, Error> {
        let mut m = 1u32;
        for _ in 0..num_bits {
            let bit = self.decode_bit(&mut probs[m as usize])?;
            m = (m << 1) | bit;
        }
        Ok(m - (1 << num_bits))
    }

    /// Decode a reversed bit-tree (LSB-first context model).
    pub(crate) fn decode_reverse_bit_tree(
        &mut self,
        probs: &mut [u16],
        num_bits: u32,
    ) -> Result<u32, Error> {
        let mut m = 1u32;
        let mut result = 0u32;
        for i in 0..num_bits {
            let bit = self.decode_bit(&mut probs[m as usize])?;
            m = (m << 1) | bit;
            result |= bit << i;
        }
        Ok(result)
    }

    /// Return the current byte position in the input stream.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Check if the range coder has finished cleanly.
    pub(crate) const fn is_finished(&self) -> bool {
        self.code == 0
    }
}

// ── Encoder ──────────────────────────────────────────────────────────────

/// Shared range encoder.
pub(crate) struct RangeEncoder {
    output: Vec<u8>,
    range: u32,
    low: u64,
    cache: u8,
    cache_size: u32,
    first_byte: bool,
}

impl RangeEncoder {
    /// Create a new range encoder that writes to an internal buffer.
    pub(crate) const fn new() -> Self {
        Self {
            output: Vec::new(),
            range: 0xFFFF_FFFF,
            low: 0,
            cache: 0,
            cache_size: 1,
            first_byte: true,
        }
    }

    fn shift_low(&mut self) {
        let low_hi = (self.low >> 32) as u8;
        if self.low < 0xFF00_0000 || low_hi != 0 {
            if self.first_byte {
                self.first_byte = false;
            } else {
                self.output.push(self.cache.wrapping_add(low_hi));
            }
            for _ in 1..self.cache_size {
                self.output.push(0xFF_u8.wrapping_add(low_hi));
            }
            self.cache = (self.low >> 24) as u8;
            self.cache_size = 1;
        } else {
            self.cache_size += 1;
        }
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    /// Encode a single bit with an adaptive probability model.
    #[inline]
    pub(crate) fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let bound = (self.range >> NUM_BIT_MODEL_BITS) * (*prob as u32);
        if bit == 0 {
            self.range = bound;
            *prob += ((BIT_MODEL_TOTAL as u16) - *prob) >> NUM_MOVE_BITS;
        } else {
            self.low += bound as u64;
            self.range -= bound;
            *prob -= *prob >> NUM_MOVE_BITS;
        }
        self.normalize();
    }

    /// Encode `count` direct (fixed 50/50 probability) bits.
    pub(crate) fn encode_direct_bits(&mut self, value: u32, count: u32) {
        for i in (0..count).rev() {
            self.range >>= 1;
            if (value >> i) & 1 != 0 {
                self.low += self.range as u64;
            }
            self.normalize();
        }
    }

    /// Encode a bit-tree of `num_bits` bits (MSB-first context model).
    pub(crate) fn encode_bit_tree(&mut self, probs: &mut [u16], num_bits: u32, value: u32) {
        let mut m = 1u32;
        for i in (0..num_bits).rev() {
            let bit = (value >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    /// Encode a reversed bit-tree (LSB-first context model).
    pub(crate) fn encode_reverse_bit_tree(&mut self, probs: &mut [u16], num_bits: u32, value: u32) {
        let mut m = 1u32;
        for i in 0..num_bits {
            let bit = (value >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    /// Flush the encoder and return the compressed data.
    ///
    /// The output does NOT include the leading 0x00 byte that LZMA-style wrappers require
    /// before the range coder data; the caller must prepend it.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn init_probs(n: usize) -> Vec<u16> {
        vec![PROB_INIT; n]
    }

    #[test]
    fn test_range_coder_roundtrip_bits() {
        // Encode a sequence of bits with adaptive probabilities
        let bits = [0u32, 1, 1, 0, 1, 0, 0, 0, 1, 1];
        let mut probs = init_probs(1);

        let mut enc = RangeEncoder::new();
        for &b in &bits {
            enc.encode_bit(&mut probs[0], b);
        }
        let data = enc.finish();

        // Prepend the 0x00 byte for the decoder
        let mut stream = vec![0x00];
        stream.extend_from_slice(&data);

        let mut dec = RangeDecoder::new(&stream).unwrap();
        let mut probs = init_probs(1);
        for &expected in &bits {
            assert_eq!(dec.decode_bit(&mut probs[0]).unwrap(), expected);
        }
    }

    #[test]
    fn test_range_coder_roundtrip_direct_bits() {
        let value = 0xABCD_u32;

        let mut enc = RangeEncoder::new();
        enc.encode_direct_bits(value, 16);
        let data = enc.finish();

        let mut stream = vec![0x00];
        stream.extend_from_slice(&data);

        let mut dec = RangeDecoder::new(&stream).unwrap();
        assert_eq!(dec.decode_direct_bits(16).unwrap(), value);
    }

    #[test]
    fn test_range_coder_roundtrip_bit_tree() {
        let values = [3u32, 7, 0, 5, 2];
        let num_bits = 3;

        let mut probs = init_probs(1 << num_bits);
        let mut enc = RangeEncoder::new();
        for &v in &values {
            enc.encode_bit_tree(&mut probs, num_bits, v);
        }
        let data = enc.finish();

        let mut stream = vec![0x00];
        stream.extend_from_slice(&data);

        let mut probs = init_probs(1 << num_bits);
        let mut dec = RangeDecoder::new(&stream).unwrap();
        for &expected in &values {
            assert_eq!(dec.decode_bit_tree(&mut probs, num_bits).unwrap(), expected);
        }
    }

    #[test]
    fn test_range_coder_roundtrip_reverse_bit_tree() {
        let values = [5u32, 2, 7, 0];
        let num_bits = 3;

        let mut probs = init_probs(1 << num_bits);
        let mut enc = RangeEncoder::new();
        for &v in &values {
            enc.encode_reverse_bit_tree(&mut probs, num_bits, v);
        }
        let data = enc.finish();

        let mut stream = vec![0x00];
        stream.extend_from_slice(&data);

        let mut probs = init_probs(1 << num_bits);
        let mut dec = RangeDecoder::new(&stream).unwrap();
        for &expected in &values {
            assert_eq!(
                dec.decode_reverse_bit_tree(&mut probs, num_bits).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn test_encoder_normalizes_after_bit_operations() {
        let mut enc = RangeEncoder::new();
        enc.range = TOP_VALUE - 1;
        enc.low = 0x0012_3456;
        enc.normalize();

        assert_eq!(enc.range, (TOP_VALUE - 1) << 8);
        assert_eq!(enc.low, 0x1234_5600);
        assert!(!enc.first_byte);
    }

    #[test]
    fn test_decoder_normalizes_before_bit_operations() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x01, 0xAB];
        let mut dec = RangeDecoder::new(&data).unwrap();
        dec.range = TOP_VALUE - 1;
        dec.code = 1;
        dec.normalize().unwrap();

        assert_eq!(dec.range, (TOP_VALUE - 1) << 8);
        assert_eq!(dec.code, 0x01AB);
        assert_eq!(dec.pos, 6);
    }

    #[test]
    fn test_decoder_initial_code_max_rejected() {
        // Initial code of 0xFFFFFFFF should be rejected
        let data = [0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            RangeDecoder::new(&data),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_decoder_initial_code_valid() {
        // 0xFFFFFFFE should be accepted
        let data = [0x00, 0xFF, 0xFF, 0xFF, 0xFE, 0x00]; // extra byte for normalization
        assert!(RangeDecoder::new(&data).is_ok());

        // 0x00000000 should be accepted
        let data2 = [0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(RangeDecoder::new(&data2).is_ok());
    }

    #[test]
    fn test_decoder_bad_first_byte() {
        let data = [0x01, 0, 0, 0, 0];
        assert!(RangeDecoder::new(&data).is_err());
    }

    #[test]
    fn test_decoder_too_short() {
        let data = [0x00, 0, 0];
        assert!(RangeDecoder::new(&data).is_err());
    }
}
