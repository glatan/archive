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

const fn step_zero(crc: u32) -> u32 {
    let index = (crc >> 24) as usize;
    (crc << 8) ^ BZ2_CRC32_TABLE[index]
}

/// Eight tables for an 8-byte step of the non-reflected CRC.
///
/// `SLICING[k][b]` is `k` zero-byte steps applied to the one-byte table
/// entry `b`. The register's four bytes are xored with the first four data
/// bytes and indexed at shifts 7..4. The next four data bytes use shifts 3..0.
const fn make_slicing_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut byte = 0usize;
    while byte < 256 {
        tables[0][byte] = BZ2_CRC32_TABLE[byte];
        let mut shift = 1usize;
        while shift < 8 {
            tables[shift][byte] = step_zero(tables[shift - 1][byte]);
            shift += 1;
        }
        byte += 1;
    }
    tables
}

const SLICING: [[u32; 256]; 8] = make_slicing_tables();

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
        let mut crc = self.value;
        let mut offset = 0;
        while offset + 8 <= data.len() {
            let mixed = crc
                ^ (u32::from(data[offset]) << 24)
                ^ (u32::from(data[offset + 1]) << 16)
                ^ (u32::from(data[offset + 2]) << 8)
                ^ u32::from(data[offset + 3]);
            crc = SLICING[7][(mixed >> 24) as usize]
                ^ SLICING[6][((mixed >> 16) & 0xff) as usize]
                ^ SLICING[5][((mixed >> 8) & 0xff) as usize]
                ^ SLICING[4][(mixed & 0xff) as usize]
                ^ SLICING[3][data[offset + 4] as usize]
                ^ SLICING[2][data[offset + 5] as usize]
                ^ SLICING[1][data[offset + 6] as usize]
                ^ SLICING[0][data[offset + 7] as usize];
            offset += 8;
        }
        while offset < data.len() {
            let index = ((crc >> 24) ^ u32::from(data[offset])) as usize;
            crc = (crc << 8) ^ BZ2_CRC32_TABLE[index];
            offset += 1;
        }
        self.value = crc;
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

    /// One-byte recurrence, independent of `Bz2Crc32::update`.
    fn scalar_crc(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFF;
        for &byte in data {
            let index = ((crc >> 24) ^ u32::from(byte)) as usize;
            crc = (crc << 8) ^ BZ2_CRC32_TABLE[index];
        }
        crc ^ 0xFFFF_FFFF
    }

    #[test]
    fn test_bz2_crc32_slicing_matches_byte_step() {
        let mut lcg = 0x1234_5678u32;
        let mut data = [0u8; 64];
        for byte in &mut data {
            lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (lcg >> 24) as u8;
        }
        for len in 0..=data.len() {
            assert_eq!(bz2_crc32(&data[..len]), scalar_crc(&data[..len]));
        }
        let mut split = Bz2Crc32::new();
        split.update(&data[..5]);
        split.update(&data[5..13]);
        split.update(&data[13..]);
        assert_eq!(split.finish(), scalar_crc(&data));
    }
}
