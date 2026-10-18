//! Deflate64 length and distance tables.
//!
//! The values live next to the DEFLATE tables so the shared inflater can see
//! them without depending on the `zip` / `sevenz` features.

#[cfg(test)]
pub(crate) use crate::compress::deflate::tables::{
    DISTANCE_BASE_64, DISTANCE_EXTRA_64, LENGTH_BASE_64, LENGTH_EXTRA_64,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_tables_match_deflate_except_code_285() {
        use crate::compress::deflate::tables::{LENGTH_BASE, LENGTH_EXTRA};
        // Indices 0-27 (codes 257-284) must be identical.
        assert_eq!(&LENGTH_BASE_64[..28], &LENGTH_BASE[..28]);
        assert_eq!(&LENGTH_EXTRA_64[..28], &LENGTH_EXTRA[..28]);
        // Index 28 (code 285) differs.
        assert_eq!(LENGTH_BASE_64[28], 3);
        assert_eq!(LENGTH_EXTRA_64[28], 16);
    }

    #[test]
    fn test_distance_tables_extend_deflate() {
        use crate::compress::deflate::tables::{DISTANCE_BASE, DISTANCE_EXTRA};
        // First 30 entries must match DEFLATE.
        for i in 0..30 {
            assert_eq!(DISTANCE_BASE_64[i], DISTANCE_BASE[i] as u32);
            assert_eq!(DISTANCE_EXTRA_64[i], DISTANCE_EXTRA[i]);
        }
        // Codes 30-31: new Deflate64 entries.
        assert_eq!(DISTANCE_BASE_64[30], 32769);
        assert_eq!(DISTANCE_BASE_64[31], 49153);
        assert_eq!(DISTANCE_EXTRA_64[30], 14);
        assert_eq!(DISTANCE_EXTRA_64[31], 14);
    }

    #[test]
    fn test_max_distance() {
        // Code 31: base 49153 + (2^14 - 1) = 49153 + 16383 = 65536
        let max_dist = DISTANCE_BASE_64[31] as u64 + ((1u64 << DISTANCE_EXTRA_64[31]) - 1);
        assert_eq!(max_dist, 65536);
    }

    #[test]
    fn test_max_length() {
        // Code 285: base 3 + (2^16 - 1) = 3 + 65535 = 65538
        let max_len = LENGTH_BASE_64[28] as u64 + ((1u64 << LENGTH_EXTRA_64[28]) - 1);
        assert_eq!(max_len, 65538);
    }
}
