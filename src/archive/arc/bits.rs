//! Bit readers/writers shared by the ARC compression methods.

use alloc::vec::Vec;

/// LSB-first bit cursor over a byte slice.
pub(crate) struct LsbBits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> LsbBits<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        LsbBits { data, pos: 0 }
    }

    /// Read `n` bits (1..=24) LSB-first, or `None` when fewer than `n`
    /// bits remain.
    pub(crate) fn read(&mut self, n: u8) -> Option<u32> {
        if self.data.len() * 8 - self.pos < usize::from(n) {
            return None;
        }
        let mut v = 0u32;
        for i in 0..n {
            let byte = self.data[self.pos / 8];
            v |= u32::from((byte >> (self.pos % 8)) & 1) << i;
            self.pos += 1;
        }
        Some(v)
    }
}

/// LSB-first bit writer (mirror of [`LsbBits`]).
pub(crate) struct LsbWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl LsbWriter {
    pub(crate) fn new() -> Self {
        LsbWriter {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    /// Emit the low `n` bits of `v`, least significant bit first.
    pub(crate) fn put(&mut self, v: u32, n: u32) {
        self.acc |= (v & ((1 << n) - 1)) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    /// Flush, zero-padding the tail byte; returns the byte stream.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// MSB-first bit cursor over a byte slice.
pub(crate) struct MsbBits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsbBits<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        MsbBits { data, pos: 0 }
    }

    /// Read `n` bits (1..=16) MSB-first, or `None` when fewer than `n`
    /// bits remain (trailing padding is ignored).
    pub(crate) fn read(&mut self, n: u8) -> Option<u32> {
        if self.data.len() * 8 - self.pos < usize::from(n) {
            return None;
        }
        let mut v = 0u32;
        for _ in 0..n {
            let byte = self.data[self.pos / 8];
            v = (v << 1) | u32::from((byte >> (7 - self.pos % 8)) & 1);
            self.pos += 1;
        }
        Some(v)
    }
}

/// MSB-first bit writer (mirror of [`MsbBits`]).
pub(crate) struct MsbWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl MsbWriter {
    pub(crate) fn new() -> Self {
        MsbWriter {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    /// Emit the low `n` bits of `v`, most significant bit first.
    pub(crate) fn put(&mut self, v: u32, n: u32) {
        self.acc = (self.acc << n) | (v & ((1 << n) - 1));
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.out.push((self.acc >> self.nbits) as u8);
        }
        self.acc &= (1 << self.nbits) - 1;
    }

    /// Flush, zero-padding the tail byte; returns the byte stream.
    pub(crate) fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.out
    }
}
