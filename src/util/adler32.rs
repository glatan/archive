//! Adler-32 checksum ([RFC 1950]).
//!
//! Used by the lzop and zlib formats for data integrity checking.
//!
//! [RFC 1950]: https://datatracker.ietf.org/doc/html/rfc1950

/// Adler-32 modulus.
const MOD_ADLER: u32 = 65521;

/// Maximum bytes to process before reducing modulo (prevents u32 overflow).
/// With s2 accumulating at most 65520 * 255 per byte, we can safely
/// process up to 5552 bytes before overflow of a u32.
const NMAX: usize = 5552;

/// Compute Adler-32 checksum of data.
///
/// # Examples
///
/// ```ignore
/// use archive::util::adler32::adler32;
///
/// assert_eq!(adler32(b""), 1);
/// assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
/// ```
pub fn adler32(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;

    for chunk in data.chunks(NMAX) {
        for &byte in chunk {
            s1 += byte as u32;
            s2 += s1;
        }
        s1 %= MOD_ADLER;
        s2 %= MOD_ADLER;
    }

    (s2 << 16) | s1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adler32_empty() {
        assert_eq!(adler32(b""), 1);
    }

    #[test]
    fn test_adler32_wikipedia() {
        // Known test vector: "Wikipedia"
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    #[test]
    fn test_adler32_abc() {
        // Known test vector
        assert_eq!(adler32(b"abc"), 0x024d0127);
    }

    #[test]
    fn test_adler32_long() {
        // Verify NMAX chunking works for long inputs
        let data = [0x41u8; 10000]; // 10000 'A's
        let result = adler32(&data);
        // Verify it produces a valid non-zero result
        assert_ne!(result, 0);
        assert_ne!(result, 1);
    }

    #[test]
    fn test_adler32_nmax_boundary() {
        extern crate alloc;
        use alloc::vec;

        // NMAX = 5552: exactly one chunk, no overflow
        let data_nmax = vec![0xFFu8; NMAX];
        let result_nmax = adler32(&data_nmax);
        assert_ne!(result_nmax, 0);
        assert_ne!(result_nmax, 1);
        // s1 and s2 must fit in u32 before modulo; verify the result is valid
        let s1 = result_nmax & 0xFFFF;
        let s2 = result_nmax >> 16;
        assert!(s1 < MOD_ADLER, "s1 must be reduced mod 65521");
        assert!(s2 < MOD_ADLER, "s2 must be reduced mod 65521");

        // NMAX + 1 = 5553: crosses the chunk boundary
        let data_nmax_plus_1 = vec![0xFFu8; NMAX + 1];
        let result_nmax_plus_1 = adler32(&data_nmax_plus_1);
        assert_ne!(result_nmax_plus_1, 0);
        assert_ne!(result_nmax_plus_1, 1);
        let s1p = result_nmax_plus_1 & 0xFFFF;
        let s2p = result_nmax_plus_1 >> 16;
        assert!(s1p < MOD_ADLER, "s1 must be reduced mod 65521");
        assert!(s2p < MOD_ADLER, "s2 must be reduced mod 65521");

        // The two results should differ (different lengths)
        assert_ne!(result_nmax, result_nmax_plus_1);
    }
}
