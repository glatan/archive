use alloc::vec::Vec;

use crate::error::Error;

/// Literal length base values and extra bits.
pub(crate) const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];

/// Extra bits for each literal length symbol.
pub(crate) const LL_EXTRA: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// Match length base values and extra bits.
pub(crate) const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];

/// Extra bits for each match length symbol.
pub(crate) const ML_EXTRA: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// A decoded sequence (literal length, match offset, match length).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sequence {
    /// Number of literals to copy before the match.
    pub(crate) literal_length: u32,
    /// Match offset into the history window.
    pub(crate) offset: u32,
    /// Number of bytes to copy from the match.
    pub(crate) match_length: u32,
}

/// Decode the sequences section of a compressed block.
///
/// Returns (sequences, bytes_consumed).
pub(crate) fn decode_sequences_header(data: &[u8]) -> Result<(usize, usize), Error> {
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }

    let first_byte = data[0] as usize;
    let (num_sequences, pos) = if first_byte < 128 {
        (first_byte, 1)
    } else if first_byte < 255 {
        if data.len() < 2 {
            return Err(Error::UnexpectedEof);
        }
        let n = ((first_byte - 128) << 8) + data[1] as usize;
        (n, 2)
    } else {
        if data.len() < 3 {
            return Err(Error::UnexpectedEof);
        }
        let n = data[1] as usize + (data[2] as usize * 256) + 0x7F00;
        (n, 3)
    };

    Ok((num_sequences, pos))
}

/// Apply decoded sequences to produce output.
///
/// `literals` - the decoded literals for this block
/// `sequences` - the decoded sequences
/// `output` - output buffer (also serves as history window)
#[cfg(test)]
pub(crate) fn execute_sequences(
    literals: &[u8],
    sequences: &[Sequence],
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    execute_sequences_with_dict(literals, sequences, output, &[])
}

/// Execute sequences with optional dictionary content as prefix history.
///
/// When a dictionary is used, `dict_content` provides additional history
/// that sequences can reference via offsets beyond the current output.
pub(crate) fn execute_sequences_with_dict(
    literals: &[u8],
    sequences: &[Sequence],
    output: &mut Vec<u8>,
    dict_content: &[u8],
) -> Result<(), Error> {
    let mut lit_pos = 0;
    let dict_len = dict_content.len();

    for seq in sequences {
        // Copy literal_length bytes from literals
        let ll = seq.literal_length as usize;
        if lit_pos + ll > literals.len() {
            return Err(Error::InvalidData("literal overflow in sequence"));
        }
        output.extend_from_slice(&literals[lit_pos..lit_pos + ll]);
        lit_pos += ll;

        // Copy match from history (dict_content ++ output)
        let ml = seq.match_length as usize;
        let offset = seq.offset as usize;

        if offset == 0 {
            return Err(Error::InvalidData("zero offset in sequence"));
        }

        let total_history = dict_len + output.len();
        if offset > total_history {
            return Err(Error::InvalidData("offset beyond available history"));
        }

        // The virtual history is: [dict_content | output]
        // An offset of N means N bytes back from current end of output.
        let match_start_in_virtual = total_history - offset;

        for i in 0..ml {
            let vpos = match_start_in_virtual + i;
            let byte = if vpos < dict_len {
                dict_content[vpos]
            } else {
                output[vpos - dict_len]
            };
            output.push(byte);
        }
    }

    // Copy remaining literals
    if lit_pos < literals.len() {
        output.extend_from_slice(&literals[lit_pos..]);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn test_decode_sequences_header_small() {
        let data = [5];
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, 5);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_decode_sequences_header_medium() {
        // first_byte = 128, so n = (128-128) << 8 + data[1]
        let data = [128, 10];
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, 10);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_execute_simple() {
        let literals = b"hello world";
        let sequences = vec![Sequence {
            literal_length: 11,
            offset: 6,
            match_length: 5,
        }];
        let mut output = Vec::new();
        execute_sequences(literals, &sequences, &mut output).unwrap();
        // After 11 literals: "hello world". Offset=6 means copy from pos 11-6=5: " worl"
        assert_eq!(&output, b"hello world worl");
    }

    // Phase 1: Error detection

    #[test]
    fn test_execute_zero_offset() {
        let literals = b"abc";
        let sequences = vec![Sequence {
            literal_length: 3,
            offset: 0,
            match_length: 1,
        }];
        let mut output = Vec::new();
        let result = execute_sequences(literals, &sequences, &mut output);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_execute_offset_beyond_history() {
        let literals = b"ab";
        let sequences = vec![Sequence {
            literal_length: 2,
            offset: 10, // only 2 bytes in output
            match_length: 1,
        }];
        let mut output = Vec::new();
        let result = execute_sequences(literals, &sequences, &mut output);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_execute_literal_overflow() {
        let literals = b"ab"; // only 2 bytes
        let sequences = vec![Sequence {
            literal_length: 5, // requesting 5 literals but only 2 available
            offset: 1,
            match_length: 1,
        }];
        let mut output = Vec::new();
        let result = execute_sequences(literals, &sequences, &mut output);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_sequences_header_large() {
        // byte0=255 triggers the 3-byte encoding: n = data[1] + data[2]*256 + 0x7F00
        let data = [255, 0x10, 0x01]; // n = 0x10 + 0x01*256 + 0x7F00 = 16 + 256 + 32512 = 32784
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, 0x10 + 0x0100 + 0x7F00);
        assert_eq!(pos, 3);
    }

    // Phase 2: Spec value verification

    #[test]
    fn test_ll_base_matches_spec() {
        // RFC 8878 Table 13: Literal_Length values
        let expected: [u32; 36] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40,
            48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
        ];
        assert_eq!(LL_BASE.len(), 36);
        assert_eq!(&LL_BASE[..], &expected[..]);
    }

    #[test]
    fn test_ll_extra_matches_spec() {
        let expected: [u8; 36] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9,
            10, 11, 12, 13, 14, 15, 16,
        ];
        assert_eq!(LL_EXTRA.len(), 36);
        assert_eq!(&LL_EXTRA[..], &expected[..]);
    }

    #[test]
    fn test_ml_base_matches_spec() {
        // RFC 8878 Table 14: Match_Length values
        let expected: [u32; 53] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131,
            259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
        ];
        assert_eq!(ML_BASE.len(), 53);
        assert_eq!(&ML_BASE[..], &expected[..]);
    }

    #[test]
    fn test_ml_extra_matches_spec() {
        let expected: [u8; 53] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ];
        assert_eq!(ML_EXTRA.len(), 53);
        assert_eq!(&ML_EXTRA[..], &expected[..]);
    }

    // Phase 3: Boundary values

    #[test]
    fn test_sequences_header_boundary_127() {
        // byte0=127 → 1-byte encoding, n=127
        let data = [127];
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, 127);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_sequences_header_boundary_128() {
        // byte0=128, byte1=0 → 2-byte encoding, n = (128-128)<<8 + 0 = 0
        let data = [128, 0];
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, 0);
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_sequences_header_boundary_254() {
        // byte0=254 → 2-byte encoding, n = (254-128)<<8 + data[1]
        // With data[1]=255: n = 126*256 + 255 = 32256 + 255 = 32511
        let data = [254, 255];
        let (n, pos) = decode_sequences_header(&data).unwrap();
        assert_eq!(n, (254 - 128) * 256 + 255);
        assert_eq!(pos, 2);
    }
}
