//! CRC32C (Castagnoli) implementation for Snappy framing.

const fn make_crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
}

const CRC32C_TABLE: [u32; 256] = make_crc32c_table();

pub fn crc32c(data: &[u8]) -> u32 {
    let mut state = Crc32c::new();
    state.update(data);
    state.finish()
}

#[cfg_attr(not(feature = "snappy"), allow(dead_code))]
pub const fn mask_crc32c(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(0xA282_EAD8)
}

#[cfg_attr(not(feature = "snappy"), allow(dead_code))]
pub const fn unmask_crc32c(masked: u32) -> u32 {
    masked.wrapping_sub(0xA282_EAD8).rotate_left(15)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32c {
    value: u32,
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    pub const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.value ^ byte as u32) & 0xFF) as usize;
            self.value = CRC32C_TABLE[index] ^ (self.value >> 8);
        }
    }

    pub const fn finish(&self) -> u32 {
        self.value ^ 0xFFFF_FFFF
    }

    #[cfg(test)]
    pub(crate) const fn reset(&mut self) {
        self.value = 0xFFFF_FFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32c_known_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn test_crc32c_incremental() {
        let mut crc = Crc32c::new();
        crc.update(b"1234");
        crc.update(b"56789");
        assert_eq!(crc.finish(), 0xE306_9283);
        crc.reset();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0xE306_9283);
    }

    #[test]
    fn test_crc32c_mask_roundtrip() {
        let crc = crc32c(b"snappy");
        assert_eq!(unmask_crc32c(mask_crc32c(crc)), crc);
    }
}
