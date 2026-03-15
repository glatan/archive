//! CRC-64/XZ implementation using table-driven algorithm.
//!
//! Provides both one-shot and incremental interfaces.
//! Polynomial: 0xC96C5795D7870F42 (reflected representation of 0x42F0E1EBA9EA3693).

const fn make_crc64_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xC96C_5795_D787_0F42;
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

const CRC64_TABLE: [u64; 256] = make_crc64_table();

/// Compute CRC-64/XZ of a byte slice.
///
/// # Examples
///
/// ```ignore
/// use archive::util::crc64::crc64;
///
/// assert_eq!(crc64(b"123456789"), 0x995DC9BBDF1939FA);
/// assert_eq!(crc64(b""), 0x0000000000000000);
/// ```
pub fn crc64(data: &[u8]) -> u64 {
    let mut state = Crc64::new();
    state.update(data);
    state.finish()
}

/// Incremental CRC-64 calculator.
///
/// # Examples
///
/// ```ignore
/// use archive::util::crc64::Crc64;
///
/// let mut crc = Crc64::new();
/// crc.update(b"1234");
/// crc.update(b"56789");
/// assert_eq!(crc.finish(), 0x995DC9BBDF1939FA);
///
/// crc.reset();
/// crc.update(b"123456789");
/// assert_eq!(crc.finish(), 0x995DC9BBDF1939FA);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc64 {
    value: u64,
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    /// Create a new CRC-64 calculator.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc64::Crc64;
    /// let crc = Crc64::new();
    /// assert_eq!(crc.finish(), 0x0000000000000000);
    /// ```
    pub const fn new() -> Self {
        Self {
            value: 0xFFFF_FFFF_FFFF_FFFF,
        }
    }

    /// Feed data into the CRC-64 calculation.
    ///
    /// Can be called multiple times to incrementally compute the checksum.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc64::Crc64;
    /// let mut crc = Crc64::new();
    /// crc.update(b"12345");
    /// crc.update(b"6789");
    /// assert_eq!(crc.finish(), 0x995DC9BBDF1939FA);
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.value ^ byte as u64) & 0xFF) as usize;
            self.value = CRC64_TABLE[index] ^ (self.value >> 8);
        }
    }

    /// Return the current CRC-64 value. Can be called multiple times without
    /// affecting state.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc64::Crc64;
    /// let mut crc = Crc64::new();
    /// crc.update(b"123456789");
    /// let v1 = crc.finish();
    /// let v2 = crc.finish();
    /// assert_eq!(v1, v2);
    /// ```
    pub const fn finish(&self) -> u64 {
        self.value ^ 0xFFFF_FFFF_FFFF_FFFF
    }

    /// Reset to the initial state for reuse.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc64::Crc64;
    /// let mut crc = Crc64::new();
    /// crc.update(b"data");
    /// crc.reset();
    /// assert_eq!(crc.finish(), 0x0000000000000000);
    /// ```
    #[allow(dead_code)]
    pub(crate) const fn reset(&mut self) {
        self.value = 0xFFFF_FFFF_FFFF_FFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc64_empty() {
        assert_eq!(crc64(b""), 0x0000_0000_0000_0000);
    }

    #[test]
    fn test_crc64_known_vector() {
        // CRC-64/XZ "123456789" = 0x995DC9BBDF1939FA
        assert_eq!(crc64(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    #[test]
    fn test_crc64_incremental() {
        let mut state = Crc64::new();
        state.update(b"1234");
        state.update(b"56789");
        assert_eq!(state.finish(), crc64(b"123456789"));
    }

    #[test]
    fn test_crc64_null_bytes() {
        assert_eq!(crc64(b"\x00\x00\x00\x00"), 0xF4A5_8635_1E1B_9F4B);
    }

    #[test]
    fn test_crc64_reset() {
        let mut state = Crc64::new();
        state.update(b"hello");
        state.reset();
        state.update(b"123456789");
        assert_eq!(state.finish(), 0x995D_C9BB_DF19_39FA);
    }
}
