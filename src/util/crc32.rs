//! CRC32 (IEEE / ITU-T V.42) implementation using table-driven algorithm.
//!
//! Provides both one-shot and incremental interfaces.
//! Polynomial: 0xEDB88320 (reflected representation of 0x04C11DB7).
#![cfg_attr(
    not(any(
        feature = "gzip",
        feature = "lzip",
        feature = "lzo",
        feature = "lrzip",
        feature = "xz",
        feature = "zip",
        feature = "sevenz",
        feature = "rzip",
    )),
    allow(dead_code)
)]

const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
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

const CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Compute CRC32 of a byte slice.
///
/// This function does not panic.
///
/// # Examples
///
/// ```ignore
/// use archive::util::crc32::crc32;
///
/// assert_eq!(crc32(b"123456789"), 0xCBF43926);
/// assert_eq!(crc32(b""), 0x00000000);
/// ```
#[cfg_attr(
    not(any(
        feature = "gzip",
        feature = "lzip",
        feature = "lzo",
        feature = "xz",
        feature = "zip",
        feature = "sevenz",
    )),
    allow(dead_code)
)]
pub fn crc32(data: &[u8]) -> u32 {
    let mut state = Crc32::new();
    state.update(data);
    state.finish()
}

/// Incremental CRC32 calculator.
///
/// No method on this type panics.
///
/// # Examples
///
/// ```ignore
/// use archive::util::crc32::Crc32;
///
/// let mut crc = Crc32::new();
/// crc.update(b"1234");
/// crc.update(b"56789");
/// assert_eq!(crc.finish(), 0xCBF43926);
///
/// crc.reset();
/// crc.update(b"123456789");
/// assert_eq!(crc.finish(), 0xCBF43926);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crc32 {
    value: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Create a new CRC32 calculator.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc32::Crc32;
    /// let crc = Crc32::new();
    /// assert_eq!(crc.finish(), 0x00000000);
    /// ```
    pub const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    /// Create a CRC32 calculator from a raw internal state.
    #[cfg_attr(not(any(feature = "lrzip", feature = "rzip")), allow(dead_code))]
    pub(crate) const fn from_raw(value: u32) -> Self {
        Self { value }
    }

    /// Feed data into the CRC32 calculation.
    ///
    /// Can be called multiple times to incrementally compute the checksum.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc32::Crc32;
    /// let mut crc = Crc32::new();
    /// crc.update(b"12345");
    /// crc.update(b"6789");
    /// assert_eq!(crc.finish(), 0xCBF43926);
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.value ^ byte as u32) & 0xFF) as usize;
            self.value = CRC32_TABLE[index] ^ (self.value >> 8);
        }
    }

    /// Return the current CRC32 value. Can be called multiple times without
    /// affecting state.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc32::Crc32;
    /// let mut crc = Crc32::new();
    /// crc.update(b"123456789");
    /// let v1 = crc.finish();
    /// let v2 = crc.finish();
    /// assert_eq!(v1, v2);
    /// ```
    #[cfg_attr(
        not(any(
            feature = "gzip",
            feature = "lzip",
            feature = "lzo",
            feature = "xz",
            feature = "zip",
            feature = "sevenz",
        )),
        allow(dead_code)
    )]
    pub const fn finish(&self) -> u32 {
        self.value ^ 0xFFFF_FFFF
    }

    #[cfg_attr(not(any(feature = "lrzip", feature = "rzip")), allow(dead_code))]
    pub(crate) const fn finish_raw(&self) -> u32 {
        self.value
    }

    /// Reset to the initial state for reuse.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::crc32::Crc32;
    /// let mut crc = Crc32::new();
    /// crc.update(b"data");
    /// crc.reset();
    /// assert_eq!(crc.finish(), 0x00000000);
    /// ```
    #[allow(dead_code)]
    pub(crate) const fn reset(&mut self) {
        self.value = 0xFFFF_FFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32_known_vectors() {
        // "123456789" -> 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_incremental() {
        let mut state = Crc32::new();
        state.update(b"1234");
        state.update(b"56789");
        assert_eq!(state.finish(), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_single_byte() {
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn test_crc32_reset() {
        let mut state = Crc32::new();
        // First, compute CRC of some arbitrary data
        state.update(b"hello world");
        let _ = state.finish();
        // Reset and compute the well-known test vector
        state.reset();
        state.update(b"123456789");
        assert_eq!(state.finish(), 0xCBF4_3926);
    }

    #[test]
    fn test_crc32_empty_update_and_repeated_finish() {
        let mut state = Crc32::new();
        state.update(b"");
        assert_eq!(state.finish(), crc32(b""));

        state.reset();
        state.update(b"abc");
        state.update(b"");
        state.update(b"def");
        let expected = crc32(b"abcdef");
        assert_eq!(state.finish(), expected);
        // finish() called again should return the same value
        assert_eq!(state.finish(), expected);
    }

    #[test]
    fn test_crc32_null_bytes() {
        assert_eq!(crc32(b"\x00\x00\x00\x00"), 0x2144_DF1C);
    }

    // C-5 #36: Default impl equivalence
    #[test]
    fn test_default_equals_new() {
        let from_new = Crc32::new();
        let from_default = Crc32::default();
        assert_eq!(from_new.finish(), from_default.finish());
    }
}
