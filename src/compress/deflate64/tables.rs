/// Length code base values for codes 257-285 (Deflate64).
///
/// Identical to DEFLATE except index 28 (code 285): base = 3 instead of 258.
/// Combined with 16 extra bits this yields a maximum match length of 3 + 65535 = 65538.
pub(super) const LENGTH_BASE_64: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, // 257-264
    11, 13, 15, 17, // 265-268
    19, 23, 27, 31, // 269-272
    35, 43, 51, 59, // 273-276
    67, 83, 99, 115, // 277-280
    131, 163, 195, 227, // 281-284
    3,   // 285: base=3 (Deflate64 difference)
];

/// Length code extra bits for codes 257-285 (Deflate64).
///
/// Identical to DEFLATE except index 28 (code 285): 16 extra bits instead of 0.
pub(super) const LENGTH_EXTRA_64: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, // 257-264
    1, 1, 1, 1, // 265-268
    2, 2, 2, 2, // 269-272
    3, 3, 3, 3, // 273-276
    4, 4, 4, 4, // 277-280
    5, 5, 5, 5,  // 281-284
    16, // 285: 16 extra bits (Deflate64 difference)
];

/// Distance code base values for codes 0-31 (Deflate64).
///
/// Extends DEFLATE (codes 0-29) with two additional codes:
/// - Code 30: base = 32769
/// - Code 31: base = 49153
pub(super) const DISTANCE_BASE_64: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

/// Distance code extra bits for codes 0-31 (Deflate64).
///
/// Extends DEFLATE (codes 0-29) with two additional codes, each with 14 extra bits.
pub(super) const DISTANCE_EXTRA_64: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

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
