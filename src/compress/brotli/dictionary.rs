use alloc::vec::Vec;

use crate::error::Error;

const SIZE_BITS_BY_LENGTH: [u8; 32] = [
    0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5, 0, 0, 0, 0,
    0, 0, 0,
];

const OFFSETS_BY_LENGTH: [usize; 32] = [
    0, 0, 0, 0, 0, 4096, 9216, 21504, 35840, 44032, 53248, 63488, 74752, 87040, 93696, 100864,
    104704, 106752, 108928, 113536, 115968, 118528, 119872, 121280, 122016, 122784, 122784, 122784,
    122784, 122784, 122784, 122784,
];

const AFFIXES: [&[u8]; 50] = [
    b" ",
    b", ",
    b" of the ",
    b" of ",
    b"s ",
    b".",
    b" and ",
    b" in ",
    b"\"",
    b" to ",
    b"\">",
    b"\x0A",
    b". ",
    b"]",
    b" for ",
    b" a ",
    b" that ",
    b"'",
    b" with ",
    b" from ",
    b" by ",
    b"(",
    b". The ",
    b" on ",
    b" as ",
    b" is ",
    b"ing ",
    b"\x0A\x09",
    b":",
    b"ed ",
    b"=\"",
    b" at ",
    b"ly ",
    b",",
    b"='",
    b".com/",
    b". This ",
    b" not ",
    b"er ",
    b"al ",
    b"ful ",
    b"ive ",
    b"less ",
    b"est ",
    b"ize ",
    b"\xC2\xA0",
    b"ous ",
    b" the ",
    b"e ",
    b"",
];

const TRANSFORMS: &[u8] = &[
    49,
    IDENTITY,
    49,
    49,
    IDENTITY,
    0,
    0,
    IDENTITY,
    0,
    49,
    OMIT_FIRST_1,
    49,
    49,
    UPPERCASE_FIRST,
    0,
    49,
    IDENTITY,
    47,
    0,
    IDENTITY,
    49,
    4,
    IDENTITY,
    0,
    49,
    IDENTITY,
    3,
    49,
    UPPERCASE_FIRST,
    49,
    49,
    IDENTITY,
    6,
    49,
    13,
    49,
    49,
    1,
    49,
    1,
    IDENTITY,
    0,
    49,
    IDENTITY,
    1,
    0,
    UPPERCASE_FIRST,
    0,
    49,
    IDENTITY,
    7,
    49,
    IDENTITY,
    9,
    48,
    IDENTITY,
    0,
    49,
    IDENTITY,
    8,
    49,
    IDENTITY,
    5,
    49,
    IDENTITY,
    10,
    49,
    IDENTITY,
    11,
    49,
    3,
    49,
    49,
    IDENTITY,
    13,
    49,
    IDENTITY,
    14,
    49,
    14,
    49,
    49,
    2,
    49,
    49,
    IDENTITY,
    15,
    49,
    IDENTITY,
    16,
    0,
    UPPERCASE_FIRST,
    49,
    49,
    IDENTITY,
    12,
    5,
    IDENTITY,
    49,
    0,
    IDENTITY,
    1,
    49,
    15,
    49,
    49,
    IDENTITY,
    18,
    49,
    IDENTITY,
    17,
    49,
    IDENTITY,
    19,
    49,
    IDENTITY,
    20,
    49,
    16,
    49,
    49,
    17,
    49,
    47,
    IDENTITY,
    49,
    49,
    4,
    49,
    49,
    IDENTITY,
    22,
    49,
    UPPERCASE_ALL,
    49,
    49,
    IDENTITY,
    23,
    49,
    IDENTITY,
    24,
    49,
    IDENTITY,
    25,
    49,
    7,
    49,
    49,
    1,
    26,
    49,
    IDENTITY,
    27,
    49,
    IDENTITY,
    28,
    0,
    IDENTITY,
    12,
    49,
    IDENTITY,
    29,
    49,
    20,
    49,
    49,
    18,
    49,
    49,
    6,
    49,
    49,
    IDENTITY,
    21,
    49,
    UPPERCASE_FIRST,
    1,
    49,
    8,
    49,
    49,
    IDENTITY,
    31,
    49,
    IDENTITY,
    32,
    47,
    IDENTITY,
    3,
    49,
    5,
    49,
    49,
    9,
    49,
    0,
    UPPERCASE_FIRST,
    1,
    49,
    UPPERCASE_FIRST,
    8,
    5,
    IDENTITY,
    21,
    49,
    UPPERCASE_ALL,
    0,
    49,
    UPPERCASE_FIRST,
    10,
    49,
    IDENTITY,
    30,
    0,
    IDENTITY,
    5,
    35,
    IDENTITY,
    49,
    47,
    IDENTITY,
    2,
    49,
    UPPERCASE_FIRST,
    17,
    49,
    IDENTITY,
    36,
    49,
    IDENTITY,
    33,
    5,
    IDENTITY,
    0,
    49,
    UPPERCASE_FIRST,
    21,
    49,
    UPPERCASE_FIRST,
    5,
    49,
    IDENTITY,
    37,
    0,
    IDENTITY,
    30,
    49,
    IDENTITY,
    38,
    0,
    UPPERCASE_ALL,
    0,
    49,
    IDENTITY,
    39,
    0,
    UPPERCASE_ALL,
    49,
    49,
    IDENTITY,
    34,
    49,
    UPPERCASE_ALL,
    8,
    49,
    UPPERCASE_FIRST,
    12,
    0,
    IDENTITY,
    21,
    49,
    IDENTITY,
    40,
    0,
    UPPERCASE_FIRST,
    12,
    49,
    IDENTITY,
    41,
    49,
    IDENTITY,
    42,
    49,
    UPPERCASE_ALL,
    17,
    49,
    IDENTITY,
    43,
    0,
    UPPERCASE_FIRST,
    5,
    49,
    UPPERCASE_ALL,
    10,
    0,
    IDENTITY,
    34,
    49,
    UPPERCASE_FIRST,
    33,
    49,
    IDENTITY,
    44,
    49,
    UPPERCASE_ALL,
    5,
    45,
    IDENTITY,
    49,
    0,
    IDENTITY,
    33,
    49,
    UPPERCASE_FIRST,
    30,
    49,
    UPPERCASE_ALL,
    30,
    49,
    IDENTITY,
    46,
    49,
    UPPERCASE_ALL,
    1,
    49,
    UPPERCASE_FIRST,
    34,
    0,
    UPPERCASE_FIRST,
    33,
    0,
    UPPERCASE_ALL,
    30,
    0,
    UPPERCASE_ALL,
    1,
    49,
    UPPERCASE_ALL,
    33,
    49,
    UPPERCASE_ALL,
    21,
    49,
    UPPERCASE_ALL,
    12,
    0,
    UPPERCASE_ALL,
    5,
    49,
    UPPERCASE_ALL,
    34,
    0,
    UPPERCASE_ALL,
    12,
    0,
    UPPERCASE_FIRST,
    30,
    0,
    UPPERCASE_ALL,
    34,
    0,
    UPPERCASE_FIRST,
    34,
];

const IDENTITY: u8 = 0;
const OMIT_LAST_9: u8 = 9;
const UPPERCASE_FIRST: u8 = 10;
const UPPERCASE_ALL: u8 = 11;
const OMIT_FIRST_1: u8 = 12;
const OMIT_FIRST_9: u8 = 20;

const DICTIONARY_DATA: &[u8] = include_bytes!("dictionary.bin");

pub(super) fn copy_static_dictionary_word(
    output: &mut Vec<u8>,
    distance: usize,
    copy_len: usize,
    max_allowed_distance: usize,
    output_limit: Option<usize>,
) -> Result<usize, Error> {
    if !(4..=24).contains(&copy_len) {
        return Err(Error::InvalidData("brotli: invalid dictionary length"));
    }

    let shift = SIZE_BITS_BY_LENGTH[copy_len] as usize;
    if shift == 0 {
        return Err(Error::InvalidData("brotli: invalid dictionary length"));
    }

    let address = distance
        .checked_sub(max_allowed_distance + 1)
        .ok_or(Error::InvalidData("brotli: invalid dictionary distance"))?;
    let mask = (1usize << shift) - 1;
    let word_idx = address & mask;
    let transform_idx = address >> shift;
    let transform = transform_triplet(transform_idx)
        .ok_or(Error::InvalidData("brotli: invalid dictionary transform"))?;

    let offset = OFFSETS_BY_LENGTH[copy_len]
        .checked_add(
            word_idx
                .checked_mul(copy_len)
                .ok_or(Error::InvalidData("brotli: dictionary offset overflow"))?,
        )
        .ok_or(Error::InvalidData("brotli: dictionary offset overflow"))?;
    let word_end = offset
        .checked_add(copy_len)
        .ok_or(Error::InvalidData("brotli: dictionary offset overflow"))?;
    let word = DICTIONARY_DATA
        .get(offset..word_end)
        .ok_or(Error::InvalidData("brotli: invalid dictionary address"))?;

    let transform_type = transform[1];
    let trimmed = trim_word(word, transform_type)?;
    let prefix = AFFIXES
        .get(transform[0] as usize)
        .ok_or(Error::InvalidData("brotli: invalid dictionary affix"))?;
    let suffix = AFFIXES
        .get(transform[2] as usize)
        .ok_or(Error::InvalidData("brotli: invalid dictionary affix"))?;
    let add = prefix
        .len()
        .saturating_add(trimmed.len())
        .saturating_add(suffix.len());
    if let Some(max) = output_limit
        && output.len().saturating_add(add) > max
    {
        return Err(Error::OutputLimitExceeded { limit: max });
    }

    output.extend_from_slice(prefix);
    let transformed_start = output.len();
    output.extend_from_slice(trimmed);

    match transform_type {
        UPPERCASE_FIRST => {
            uppercase_first(&mut output[transformed_start..]);
        }
        UPPERCASE_ALL => {
            uppercase_all(&mut output[transformed_start..]);
        }
        21 | 22 => {
            return Err(Error::Unsupported("brotli: dictionary shift transform"));
        }
        _ => {}
    }

    output.extend_from_slice(suffix);
    Ok(output.len() - transformed_start)
}

fn transform_triplet(index: usize) -> Option<[u8; 3]> {
    let base = index.checked_mul(3)?;
    Some([
        *TRANSFORMS.get(base)?,
        *TRANSFORMS.get(base + 1)?,
        *TRANSFORMS.get(base + 2)?,
    ])
}

fn trim_word(word: &[u8], transform_type: u8) -> Result<&[u8], Error> {
    match transform_type {
        IDENTITY | UPPERCASE_FIRST | UPPERCASE_ALL => Ok(word),
        1..=OMIT_LAST_9 => word
            .get(..word.len().saturating_sub(transform_type as usize))
            .ok_or(Error::InvalidData("brotli: invalid dictionary transform")),
        OMIT_FIRST_1..=OMIT_FIRST_9 => {
            let skip = (transform_type - OMIT_FIRST_1 + 1) as usize;
            word.get(skip..)
                .ok_or(Error::InvalidData("brotli: invalid dictionary transform"))
        }
        _ => Err(Error::InvalidData("brotli: invalid dictionary transform")),
    }
}

fn uppercase_first(bytes: &mut [u8]) {
    let _ = uppercase_next(bytes);
}

fn uppercase_all(bytes: &mut [u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        let step = uppercase_next(&mut bytes[offset..]);
        if step == 0 {
            break;
        }
        offset += step;
    }
}

fn uppercase_next(bytes: &mut [u8]) -> usize {
    let Some(&first) = bytes.first() else {
        return 0;
    };
    if first < 0xC0 {
        if first.is_ascii_lowercase() {
            bytes[0] ^= 32;
        }
        return 1;
    }
    if first < 0xE0 {
        if bytes.len() >= 2 {
            bytes[1] ^= 32;
        }
        return 2.min(bytes.len());
    }
    if bytes.len() >= 3 {
        bytes[2] ^= 5;
    }
    3.min(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_static_dictionary_identity_word() {
        let mut output = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let written = copy_static_dictionary_word(&mut output, 1017, 8, 8, None).unwrap();
        assert_eq!(written, 8);
        assert_eq!(output, (0u8..16).collect::<Vec<_>>());
    }

    #[test]
    fn test_trim_word_omit_last_transform() {
        assert_eq!(trim_word(b"abcdef", 1).unwrap(), b"abcde");
        assert_eq!(trim_word(b"abcdef", 14).unwrap(), b"def");
    }

    #[test]
    fn test_copy_static_dictionary_rejects_out_of_range_copy_len() {
        // RFC 7932 section 8: dictionary copy lengths are 4..=24.
        let mut output = Vec::new();
        for copy_len in [3usize, 25] {
            let result = copy_static_dictionary_word(&mut output, 100, copy_len, 0, None);
            assert!(
                matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("dictionary length")),
                "copy_len {copy_len}: expected rejection, got {result:?}"
            );
        }
    }

    #[test]
    fn test_copy_static_dictionary_rejects_out_of_range_transform() {
        // RFC 7932 section 8: only transform ids 0..=120 exist.
        // copy_len 24 uses 5 size bits, so address 121 << 5 selects
        // transform 121, which is out of range.
        let mut output = Vec::new();
        let result = copy_static_dictionary_word(&mut output, 1 + (121usize << 5), 24, 0, None);
        assert!(
            matches!(&result, Err(Error::InvalidData(msg)) if msg.contains("dictionary transform")),
            "expected dictionary transform rejection, got {result:?}"
        );
        // Boundary check: transform 120 (the last valid one) is accepted.
        assert!(
            copy_static_dictionary_word(&mut Vec::new(), 1 + (120usize << 5), 24, 0, None).is_ok()
        );
    }

    #[test]
    fn test_transform_table_uses_default_transform_types_only() {
        for idx in 0..(TRANSFORMS.len() / 3) {
            let transform = transform_triplet(idx).unwrap();
            assert!(
                matches!(transform[1], IDENTITY | 1..=20),
                "unexpected transform type {} at index {}",
                transform[1],
                idx
            );
        }
    }
}
