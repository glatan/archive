//! bzip2-style CRC-32 (big-endian / non-reflected).
//!
//! bzip2 uses the normal (non-reflected) CRC-32 polynomial 0x04C11DB7,
//! which is different from the reflected polynomial 0xEDB88320 used by gzip.

const fn make_bz2_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i << 24;
        let mut j = 0;
        while j < 8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

const BZ2_CRC32_TABLE: [u32; 256] = make_bz2_crc32_table();

/// Incremental bzip2 CRC-32 calculator (big-endian / non-reflected).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bz2Crc32 {
    value: u32,
}

impl Bz2Crc32 {
    /// Create a new CRC-32 calculator initialized to the start value.
    pub(crate) const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    /// Feed data into the CRC-32 calculation.
    pub(crate) fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.value >> 24) ^ byte as u32) as usize;
            self.value = (self.value << 8) ^ BZ2_CRC32_TABLE[index];
        }
    }

    /// Return the current CRC-32 value.
    pub(crate) const fn finish(&self) -> u32 {
        self.value ^ 0xFFFF_FFFF
    }

    /// Reset to the initial state for reuse.
    #[allow(dead_code)]
    pub(crate) const fn reset(&mut self) {
        self.value = 0xFFFF_FFFF;
    }
}

/// Compute bzip2-style CRC-32 of a byte slice.
#[allow(dead_code)]
pub(crate) fn bz2_crc32(data: &[u8]) -> u32 {
    let mut state = Bz2Crc32::new();
    state.update(data);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bz2_crc32_single_x() {
        // bzip2 CRC-32 of "x" should be 0x774BB014
        assert_eq!(bz2_crc32(b"x"), 0x774B_B014);
    }

    #[test]
    fn test_bz2_crc32_empty() {
        assert_eq!(bz2_crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_bz2_crc32_incremental() {
        let mut state = Bz2Crc32::new();
        state.update(b"Hel");
        state.update(b"lo");
        let full = bz2_crc32(b"Hello");
        assert_eq!(state.finish(), full);
    }
}
