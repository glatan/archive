//! Bit readers shared by the ARC compression methods.

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
