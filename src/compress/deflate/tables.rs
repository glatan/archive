/// Length code base values and extra bits for codes 257-285.
/// Index 0 corresponds to code 257.
pub(crate) const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, // 257-264
    11, 13, 15, 17, // 265-268
    19, 23, 27, 31, // 269-272
    35, 43, 51, 59, // 273-276
    67, 83, 99, 115, // 277-280
    131, 163, 195, 227, // 281-284
    258, // 285
];

pub(crate) const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, // 257-264
    1, 1, 1, 1, // 265-268
    2, 2, 2, 2, // 269-272
    3, 3, 3, 3, // 273-276
    4, 4, 4, 4, // 277-280
    5, 5, 5, 5, // 281-284
    0, // 285
];

/// Distance code base values and extra bits for codes 0-29.
pub(crate) const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

pub(crate) const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Deflate64 length bases. Index 28 (code 285) is 3, not 258.
pub(crate) const LENGTH_BASE_64: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, // 257-264
    11, 13, 15, 17, // 265-268
    19, 23, 27, 31, // 269-272
    35, 43, 51, 59, // 273-276
    67, 83, 99, 115, // 277-280
    131, 163, 195, 227, // 281-284
    3,   // 285
];

/// Deflate64 length extra bits. Index 28 (code 285) is 16.
pub(crate) const LENGTH_EXTRA_64: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, // 257-264
    1, 1, 1, 1, // 265-268
    2, 2, 2, 2, // 269-272
    3, 3, 3, 3, // 273-276
    4, 4, 4, 4, // 277-280
    5, 5, 5, 5,  // 281-284
    16, // 285
];

/// Deflate64 distance bases, including codes 30 and 31.
pub(crate) const DISTANCE_BASE_64: [u32; 32] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153,
];

/// Deflate64 distance extra bits. Codes 30 and 31 use 14.
pub(crate) const DISTANCE_EXTRA_64: [u8; 32] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14,
];

/// Order of code length alphabet codes for dynamic Huffman tables.
pub(crate) const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Reverse the low `num_bits` of `value`. Huffman codes are stored MSB-first
/// in the RFC and consumed LSB-first from the bitstream.
pub(crate) const fn reverse_bits(mut value: u32, mut num_bits: u8) -> u32 {
    let mut result = 0u32;
    while num_bits > 0 {
        result = (result << 1) | (value & 1);
        value >>= 1;
        num_bits -= 1;
    }
    result
}

/// Fixed literal/length code lengths (RFC 1951 section 3.2.6).
pub(crate) const fn fixed_literal_lengths() -> [u8; 288] {
    let mut lengths = [0u8; 288];
    let mut i = 0;
    while i <= 143 {
        lengths[i] = 8;
        i += 1;
    }
    while i <= 255 {
        lengths[i] = 9;
        i += 1;
    }
    while i <= 279 {
        lengths[i] = 7;
        i += 1;
    }
    while i <= 287 {
        lengths[i] = 8;
        i += 1;
    }
    lengths
}

/// Fixed distance code lengths: all 5 bits for codes 0-31.
///
/// RFC 1951 §3.2.6 defines 32 distance codes (0-31) with 5 bits each,
/// though only codes 0-29 are valid. Codes 30-31 are never generated
/// by a conforming compressor and are rejected by the decoder via
/// `DISTANCE_BASE` bounds checking.
pub(crate) const fn fixed_distance_lengths() -> [u8; 32] {
    [5u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Phase 2: Verify tables match RFC 1951 Section 3.2.5

    #[test]
    fn test_length_base_matches_rfc1951() {
        // RFC 1951 Table: length codes 257-285
        let expected: [u16; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, // 257-264
            11, 13, 15, 17, // 265-268
            19, 23, 27, 31, // 269-272
            35, 43, 51, 59, // 273-276
            67, 83, 99, 115, // 277-280
            131, 163, 195, 227, // 281-284
            258, // 285
        ];
        assert_eq!(LENGTH_BASE.len(), 29);
        assert_eq!(&LENGTH_BASE[..], &expected[..]);

        // Verify extra bits
        let expected_extra: [u8; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        assert_eq!(&LENGTH_EXTRA[..], &expected_extra[..]);
    }

    #[test]
    fn test_fixed_literal_lengths_exhaustive() {
        let lengths = fixed_literal_lengths();
        assert_eq!(lengths.len(), 288);
        assert!(lengths[..=143].iter().all(|&len| len == 8));
        assert!(lengths[144..=255].iter().all(|&len| len == 9));
        assert!(lengths[256..=279].iter().all(|&len| len == 7));
        assert!(lengths[280..=287].iter().all(|&len| len == 8));
    }

    #[test]
    fn test_fixed_distance_lengths_exhaustive() {
        let lengths = fixed_distance_lengths();
        assert_eq!(lengths.len(), 32);
        assert!(lengths.iter().all(|&len| len == 5));
    }

    #[test]
    fn test_distance_base_matches_rfc1951() {
        // RFC 1951 Table: distance codes 0-29
        let expected: [u16; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        assert_eq!(DISTANCE_BASE.len(), 30);
        assert_eq!(&DISTANCE_BASE[..], &expected[..]);

        // Verify extra bits
        let expected_extra: [u8; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        assert_eq!(&DISTANCE_EXTRA[..], &expected_extra[..]);
    }
}
