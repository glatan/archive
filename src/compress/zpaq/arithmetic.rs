//! Arithmetic encoder and decoder for ZPAQ.
//!
//! Port of the inclusive-range coder in upstream libzpaq
//! (`Encoder::encode`/`Decoder::decode`).  The range is the closed
//! interval `low..=high` initialized to `1..=0xFFFFFFFF`.  `p` is the
//! 16-bit probability that the next bit is 1; the split point is
//! `mid = low + ((high - low) * p >> 16)` computed with a 64-bit
//! product.  Bit 1 selects `low..=mid`, bit 0 selects `mid+1..=high`.
//!
//! Normalization emits/discards identical leading bytes while
//! `(high ^ low) < 0x01000000`, shifting in `0xFF` on `high` and `0`
//! on `low`, with `low` incremented when it wraps to 0 so the encoder
//! never emits four consecutive zero bytes inside the coded stream.
//!
//! For unmodeled (`n == 0`) streams the same objects are used in
//! "stored" mode: the encoder buffers up to 64 KiB and writes
//! `len(4, big-endian) || payload` blocks, and the decoder reads the
//! counts directly.

use alloc::vec::Vec;

use crate::error::Error;

/// Arithmetic encoder writing to an internal buffer.
pub(crate) struct ArithEncoder {
    /// Low end of the range (modeled) or buffered byte count (stored).
    low: u32,
    /// High end of the range (inclusive).
    high: u32,
    /// Compressed output bytes.
    output: Vec<u8>,
    /// Stored-mode buffer (unmodeled streams only), 64 KiB.
    buf: Vec<u8>,
}

impl ArithEncoder {
    /// Create an encoder in modeled mode (`low=1`, `high=0xFFFFFFFF`).
    pub fn new() -> Self {
        Self {
            low: 1,
            high: 0xFFFFFFFF,
            output: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Switch to stored mode for unmodeled streams (`low` becomes the
    /// buffered byte count).
    pub fn init_stored(&mut self) {
        self.low = 0;
        self.buf = alloc::vec![0; 1 << 16];
    }

    /// Encode bit `y` (0/1) with 16-bit probability `p` of a 1.
    pub fn encode(&mut self, y: u32, p: u32) {
        debug_assert!(y <= 1 && p < 65536);
        debug_assert!(self.high > self.low && self.low > 0);
        let mid = self
            .low
            .wrapping_add(((u64::from(self.high - self.low) * u64::from(p)) >> 16) as u32);
        if y != 0 {
            self.high = mid;
        } else {
            self.low = mid.wrapping_add(1);
        }
        while (self.high ^ self.low) < 0x0100_0000 {
            self.output.push((self.high >> 24) as u8);
            self.high = (self.high << 8) | 0xFF;
            self.low <<= 8;
            self.low += u32::from(self.low == 0);
        }
    }

    /// Stored mode: append a byte (`c` 0..=255) or flush on `None`.
    /// A full 64 KiB buffer is flushed automatically.
    pub fn store(&mut self, c: Option<u8>) {
        if self.low != 0 && (c.is_none() || self.low as usize == self.buf.len()) {
            let n = self.low;
            self.output.extend_from_slice(&n.to_be_bytes());
            let n = n as usize;
            self.output.extend_from_slice(&self.buf[..n]);
            self.low = 0;
        }
        if let Some(b) = c {
            self.buf[self.low as usize] = b;
            self.low += 1;
        }
    }

    /// Take the accumulated output bytes.
    pub fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.output)
    }
}

/// Arithmetic decoder reading from a byte slice.
pub(crate) struct ArithDecoder<'a> {
    /// Low end of the range (modeled), or a 32-bit down-counter of
    /// bytes remaining in the current stored block.
    pub(crate) low: u32,
    /// High end of the inclusive range.
    pub(crate) high: u32,
    /// Current 4-byte window of coded input (modeled), or stored-mode
    /// block counter as upstream reuses `curr`.
    pub(crate) curr: u32,
    input: &'a [u8],
    pos: usize,
}

impl<'a> ArithDecoder<'a> {
    /// Create a decoder over `input` in modeled mode.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            low: 1,
            high: 0xFFFFFFFF,
            curr: 0,
            input,
            pos: 0,
        }
    }

    /// Initialize for a segment: modeled streams reset the range;
    /// unmodeled streams zero all state (upstream `Decoder::init`).
    pub fn init(&mut self, modeled: bool) {
        if modeled {
            self.low = 1;
            self.high = 0xFFFFFFFF;
            self.curr = 0;
        } else {
            self.low = 0;
            self.high = 0;
            self.curr = 0;
        }
    }

    /// Current read offset within `input`.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Read one raw byte, or -1 at end of input (upstream `get()`).
    pub fn get(&mut self) -> i32 {
        if self.pos < self.input.len() {
            let b = self.input[self.pos];
            self.pos += 1;
            i32::from(b)
        } else {
            -1
        }
    }

    /// Decode one bit with 16-bit probability `p` of a 1.
    pub fn decode(&mut self, p: u32) -> Result<u32, Error> {
        debug_assert!(p < 65536);
        if self.curr < self.low || self.curr > self.high {
            return Err(Error::InvalidData("zpaq: arithmetic state out of range"));
        }
        let mid = self
            .low
            .wrapping_add(((u64::from(self.high - self.low) * u64::from(p)) >> 16) as u32);
        let y;
        if self.curr <= mid {
            y = 1;
            self.high = mid;
        } else {
            y = 0;
            self.low = mid.wrapping_add(1);
        }
        while (self.high ^ self.low) < 0x0100_0000 {
            self.high = (self.high << 8) | 0xFF;
            self.low <<= 8;
            self.low += u32::from(self.low == 0);
            let c = self.get();
            if c < 0 {
                return Err(Error::InvalidData("zpaq: unexpected end of coded input"));
            }
            self.curr = (self.curr << 8) | (c as u32);
        }
        Ok(y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_mode_emits_length_prefixed_blocks() {
        let mut encoder = ArithEncoder::new();
        encoder.init_stored();
        encoder.store(Some(b'h'));
        encoder.store(Some(b'i'));
        encoder.store(None);
        let out = encoder.take();
        assert_eq!(&out[..4], &2u32.to_be_bytes());
        assert_eq!(&out[4..], b"hi");
    }

    #[test]
    fn decoder_get_reads_raw_bytes_and_eof() {
        let mut decoder = ArithDecoder::new(b"ab");
        decoder.init(false);
        assert_eq!(decoder.get(), i32::from(b'a'));
        assert_eq!(decoder.get(), i32::from(b'b'));
        assert_eq!(decoder.get(), -1);
    }
}
