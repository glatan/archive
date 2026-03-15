//! ZIP Method 1 (UnShrinking) decompression.
//!
//! Implements the LZW variant described in APPNOTE §5.1.
//! Code width starts at 9 bits and can grow up to 13 bits.
//! Code 256 is a special control code: followed by 1 it increases code width,
//! followed by 2 it performs a partial clear (frees leaf dictionary entries).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Maximum code width for UnShrink (APPNOTE §5.1).
const MAX_BITS: u32 = 13;
/// Initial code width.
const INIT_BITS: u32 = 9;
/// Special control code.
const CONTROL_CODE: u16 = 256;
/// First available dictionary slot (codes 0-255 are literals, 256 is control).
const FIRST_CODE: u16 = 257;
/// Maximum number of dictionary entries (2^13 = 8192).
const DICT_SIZE: usize = 1 << MAX_BITS;

/// Marker for "no prefix" (entry is a single-byte literal).
const NO_PREFIX: u16 = u16::MAX;

/// Decompress data compressed with ZIP Method 1 (Shrinking).
///
/// The input must be the raw compressed payload (no ZIP local file header).
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the bitstream is malformed or a code
/// references an invalid dictionary entry.
pub(super) fn unshrink(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut prefix = vec![NO_PREFIX; DICT_SIZE];
    let mut suffix = vec![0u8; DICT_SIZE];
    // Track which codes are in use (not freed by partial clear).
    let mut in_use = vec![false; DICT_SIZE];

    // Initialise single-byte entries (codes 0-255).
    for i in 0u16..256 {
        prefix[i as usize] = NO_PREFIX;
        suffix[i as usize] = i as u8;
        in_use[i as usize] = true;
    }
    // Code 256 is the control code (always "in use" conceptually).
    in_use[CONTROL_CODE as usize] = true;

    let mut next_code: u16 = FIRST_CODE;
    let mut code_bits: u32 = INIT_BITS;
    let mut bit_pos: usize = 0;

    let mut output = Vec::new();
    let mut decode_stack = Vec::with_capacity(DICT_SIZE);

    // Read the first code — must be a literal (< 256).
    let prev_code = match read_code(input, &mut bit_pos, code_bits) {
        Some(c) if c < 256 => c as u16,
        Some(_) => return Err(Error::InvalidData("unshrink: first code must be a literal")),
        None => return Ok(output),
    };
    output.push(prev_code as u8);
    let mut prev_code = prev_code;

    while let Some(raw) = read_code(input, &mut bit_pos, code_bits) {
        let code = raw as u16;

        // Handle special control code (256).
        if code == CONTROL_CODE {
            let sub = match read_code(input, &mut bit_pos, code_bits) {
                Some(s) => s as u16,
                None => break, // end of stream after control code
            };
            match sub {
                1 => {
                    // Increase code width (up to MAX_BITS).
                    if code_bits < MAX_BITS {
                        code_bits += 1;
                    }
                }
                2 => {
                    // Partial clear: free leaf entries.
                    partial_clear(&prefix, &mut in_use, next_code);
                }
                _ => {
                    return Err(Error::InvalidData(
                        "unshrink: invalid sub-code after control code 256",
                    ));
                }
            }
            continue;
        }

        // Decode the string for this code.
        let first_byte;
        let expected_slot = find_free_slot(next_code, &in_use);
        if code < DICT_SIZE as u16 && in_use[code as usize] {
            first_byte = decode_chain(&prefix, &suffix, &in_use, code, &mut decode_stack)?;
        } else if expected_slot == Some(code) {
            // KwKwK case: code references the slot about to be added.
            first_byte = decode_chain(&prefix, &suffix, &in_use, prev_code, &mut decode_stack)?;
            decode_stack.insert(0, first_byte);
        } else {
            return Err(Error::InvalidData("unshrink: code out of range"));
        }

        // Output the decoded string (stack is in reverse order).
        for &b in decode_stack.iter().rev() {
            output.push(b);
        }

        // Add a new dictionary entry: prev_code + first_byte.
        // Find the next available slot.
        let slot = find_free_slot(next_code, &in_use);
        if let Some(s) = slot {
            prefix[s as usize] = prev_code;
            suffix[s as usize] = first_byte;
            in_use[s as usize] = true;
            if s >= next_code {
                next_code = s + 1;
            }
        }

        prev_code = code;
    }

    Ok(output)
}

/// Find the next free dictionary slot starting from `start`.
fn find_free_slot(start: u16, in_use: &[bool]) -> Option<u16> {
    (start..(DICT_SIZE as u16)).find(|&i| !in_use[i as usize])
}

/// Partial clear: mark leaf entries as free.
///
/// A leaf entry is one that is not referenced as a prefix by any other
/// in-use entry. We mark all such entries (from FIRST_CODE onward) as free.
fn partial_clear(prefix: &[u16], in_use: &mut [bool], next_code: u16) {
    // First, determine which codes are referenced as a prefix by some other in-use code.
    let mut is_parent = vec![false; DICT_SIZE];
    let limit = core::cmp::min(next_code as usize, DICT_SIZE);
    for i in FIRST_CODE as usize..limit {
        if in_use[i] && prefix[i] != NO_PREFIX {
            let p = prefix[i] as usize;
            if p < DICT_SIZE {
                is_parent[p] = true;
            }
        }
    }
    // Free non-parent entries from FIRST_CODE onward.
    for i in FIRST_CODE as usize..limit {
        if in_use[i] && !is_parent[i] {
            in_use[i] = false;
        }
    }
}

/// Decode a dictionary chain into `stack` (reversed order).
/// Returns the first byte of the string.
fn decode_chain(
    prefix: &[u16],
    suffix: &[u8],
    in_use: &[bool],
    mut code: u16,
    stack: &mut Vec<u8>,
) -> Result<u8, Error> {
    stack.clear();
    let limit = DICT_SIZE;
    let mut count = 0;
    loop {
        if count >= limit {
            return Err(Error::InvalidData("unshrink: dictionary chain too long"));
        }
        let idx = code as usize;
        if idx >= DICT_SIZE || (!in_use[idx] && code >= FIRST_CODE) {
            return Err(Error::InvalidData("unshrink: invalid dictionary entry"));
        }
        stack.push(suffix[idx]);
        if prefix[idx] == NO_PREFIX {
            break;
        }
        code = prefix[idx];
        count += 1;
    }
    stack
        .last()
        .copied()
        .ok_or(Error::InvalidData("unshrink: empty dictionary chain"))
}

/// Read a variable-width code from the bitstream (LSB-first).
fn read_code(data: &[u8], bit_pos: &mut usize, code_bits: u32) -> Option<u32> {
    let bits_needed = code_bits as usize;
    if *bit_pos + bits_needed > data.len() * 8 {
        return None;
    }
    let mut code = 0u32;
    for i in 0..bits_needed {
        let byte_idx = (*bit_pos + i) / 8;
        let bit_idx = (*bit_pos + i) % 8;
        if (data[byte_idx] >> bit_idx) & 1 != 0 {
            code |= 1 << i;
        }
    }
    *bit_pos += bits_needed;
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    /// Helper: write a variable-width code into a bit buffer (LSB-first).
    fn write_code(buf: &mut Vec<u8>, bit_pos: &mut usize, code: u32, bits: u32) {
        let needed_bytes = (*bit_pos + bits as usize).div_ceil(8);
        while buf.len() < needed_bytes {
            buf.push(0);
        }
        for i in 0..bits as usize {
            if (code >> i) & 1 != 0 {
                let byte_idx = (*bit_pos + i) / 8;
                let bit_idx = (*bit_pos + i) % 8;
                if byte_idx >= buf.len() {
                    buf.push(0);
                }
                buf[byte_idx] |= 1 << bit_idx;
            }
        }
        *bit_pos += bits as usize;
    }

    /// Pad buf to contain at least enough bytes for all written bits.
    fn flush(buf: &mut Vec<u8>, bit_pos: usize) {
        let needed = bit_pos.div_ceil(8);
        while buf.len() < needed {
            buf.push(0);
        }
    }

    #[test]
    fn test_unshrink_literals_only() {
        // Stream of just literal codes: 'H' 'i' should produce "Hi".
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, b'H' as u32, 9);
        write_code(&mut buf, &mut bp, b'i' as u32, 9);
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"Hi");
    }

    #[test]
    fn test_unshrink_simple_with_dict() {
        // Encode "ABABAB" manually using unshrink-style LZW:
        //
        // Initial: codes 0-255 = literals, 256 = control, next_code = 257
        // Codes at 9 bits.
        //
        // Step 1: prev='A'(65), emit 65. Output: A
        // Step 2: code='B'(66), emit 66. Add dict[257]=(65,'B')="AB". prev=66. Output: AB
        // Step 3: code='A'(65), emit 65. Add dict[258]=(66,'A')="BA". prev=65. Output: ABA
        // Step 4: code='B'(66), emit 66. Add dict[259]=(65,'B')="AB" (dup, but still added). prev=66. Output: ABAB
        // Step 5: code=65, emit 65. Add dict[260]=(66,'A')="BA". prev=65. Output: ABABA
        // Step 6: code=66, emit 66. Add dict[261]=(65,'B')="AB". Output: ABABAB
        //
        // But actually with LZW the encoder would use dictionary codes. Let's just
        // test with literals to ensure basic operation.
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, b'A' as u32, 9);
        write_code(&mut buf, &mut bp, b'B' as u32, 9);
        write_code(&mut buf, &mut bp, b'A' as u32, 9);
        write_code(&mut buf, &mut bp, b'B' as u32, 9);
        write_code(&mut buf, &mut bp, b'A' as u32, 9);
        write_code(&mut buf, &mut bp, b'B' as u32, 9);
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"ABABAB");
    }

    #[test]
    fn test_unshrink_dictionary_reference() {
        // Encode "ABA" using dictionary code:
        // Step 1: emit 'A'(65). Output: A
        // Step 2: emit 'B'(66). dict[257]=(65,'B'). Output: AB
        // Step 3: emit 257. dict[258]=(66,'A')="BA" (prev=66 + first byte of chain(257)='A').
        //         chain(257) = suffix[257]='B' -> prefix[257]=65 -> suffix[65]='A'. So "AB".
        //         Wait, we're decoding code 257 *after* it was added? No.
        //         After step 2, next_code=258 (we added 257 in step 2).
        //         Wait: after first code (65), prev=65. Then code=66: we add entry (prev=65, first_byte='B')
        //         as dict[257]. next_code=258. Then code=257: valid (257 < 258). chain(257)= suffix='B',
        //         prefix=65 -> suffix='A'. So "AB". Add dict[258]=(66, 'A'). Output = A B A B.
        //
        // So codes: [65, 66, 257] produces "ABAB".
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 65, 9); // 'A'
        write_code(&mut buf, &mut bp, 66, 9); // 'B'
        write_code(&mut buf, &mut bp, 257, 9); // dict entry "AB"
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"ABAB");
    }

    #[test]
    fn test_unshrink_kwkwk() {
        // KwKwK case: "AAA"
        // Step 1: emit 'A'(65). prev=65. Output: A
        // Step 2: code='A'(65). emit 'A'. dict[257]=(65,'A')="AA". prev=65. Output: AA
        // Step 3: code=257. chain(257)='A','A'. dict[258]=(65,'A')="AA". Output: AAAA
        // Step 4: code=258. chain(258)='A','A'. dict[259]=(257,'A'). Output: AAAAAA
        //
        // For KwKwK specifically:
        // codes: [65, 65, 257] produces "AAAA"
        // where code 257 = "AA" is built from prev=65, first_byte='A'
        // (but 257 is only added when we process the *second* 65)
        //
        // Wait, let's trace more carefully:
        //   read first code: 65 ('A'). emit 'A'. prev=65.
        //   read code: 65 ('A'). Known. chain = ['A']. first_byte = 'A'.
        //     Output 'A'. Now output = "AA".
        //     Add dict[257] = (prev=65, first_byte='A'). next_code=258. prev=65.
        //   read code: 257. Known. chain(257) = suffix='A', prefix=65, suffix='A'.
        //     chain = "AA". first_byte='A'. Output "AA". Now output = "AAAA".
        //     Add dict[258] = (prev=65, first_byte='A'). next_code=259. prev=257.
        //
        // Now for actual KwKwK:
        //   codes: [65, 65, 258]
        //   After reading 65,65: dict[257]=(65,'A'), next_code=258, prev=65.
        //   Read code 258: code == next_code! KwKwK case.
        //     chain(prev=65) = "A", first='A'. prepend first -> "AA".
        //     Add dict[258]=(65,'A'). Output "AA". Total: "AAAA".
        //     Hmm, same result. Let me use a clearer KwKwK example.
        //
        // Classic KwKwK: codes [65, 257] where 257 == next_code (not yet added).
        //   After first code 65, prev=65, next_code=257.
        //   Read code 257 == next_code. KwKwK!
        //   chain(prev=65) = "A", first='A'. prepend -> "AA".
        //   Add dict[257]=(65,'A'). Output "AA". Total: "AAA".
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 65, 9); // 'A'
        write_code(&mut buf, &mut bp, 257, 9); // KwKwK: not yet in dict
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"AAA");
    }

    #[test]
    fn test_unshrink_code_width_increase() {
        // Test the control code 256 + sub-code 1 (increase code width).
        // Build a stream at 9 bits, issue control+1, then codes at 10 bits.
        let mut buf = Vec::new();
        let mut bp = 0;
        // First code: literal 'X' at 9 bits
        write_code(&mut buf, &mut bp, b'X' as u32, 9);
        // Control code 256 at 9 bits
        write_code(&mut buf, &mut bp, 256, 9);
        // Sub-code 1 (increase width) at 9 bits
        write_code(&mut buf, &mut bp, 1, 9);
        // Next code: literal 'Y' at 10 bits (width increased)
        write_code(&mut buf, &mut bp, b'Y' as u32, 10);
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"XY");
    }

    #[test]
    fn test_unshrink_empty_input() {
        let result = unshrink(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_unshrink_first_code_not_literal() {
        // First code must be < 256.
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 257, 9);
        flush(&mut buf, bp);

        let result = unshrink(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_unshrink_code_out_of_range() {
        // After only one literal, next_code = 257. Code 500 should be invalid.
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 65, 9); // 'A'
        write_code(&mut buf, &mut bp, 500, 9); // out of range (only 257 is next)
        flush(&mut buf, bp);

        let result = unshrink(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_unshrink_partial_clear() {
        // Build a dictionary, then issue partial clear (256 + 2).
        // After partial clear, leaf entries should be freed, and new entries
        // should be able to reuse those slots.
        let mut buf = Vec::new();
        let mut bp = 0;

        // Emit some literals to build dictionary entries.
        // 'A' 'B' 'C' 'D' builds entries 257=(A,B), 258=(B,C), 259=(C,D).
        write_code(&mut buf, &mut bp, b'A' as u32, 9);
        write_code(&mut buf, &mut bp, b'B' as u32, 9);
        write_code(&mut buf, &mut bp, b'C' as u32, 9);
        write_code(&mut buf, &mut bp, b'D' as u32, 9);

        // Issue partial clear: control(256) + sub-code(2).
        write_code(&mut buf, &mut bp, 256, 9);
        write_code(&mut buf, &mut bp, 2, 9);

        // After partial clear, leaf entries (those not used as prefix by others)
        // are freed. Entries: 257=(A prefix->literal), 258=(B prefix->literal),
        // 259=(C prefix->literal). None of these are parents of each other,
        // so all three are leaves and should be freed.

        // Continue with more literals. New entries should reuse freed slots.
        write_code(&mut buf, &mut bp, b'E' as u32, 9);
        write_code(&mut buf, &mut bp, b'F' as u32, 9);
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"ABCDEF");
    }

    #[test]
    fn test_unshrink_invalid_sub_code() {
        // Control code 256 followed by invalid sub-code 3.
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, b'A' as u32, 9);
        write_code(&mut buf, &mut bp, 256, 9);
        write_code(&mut buf, &mut bp, 3, 9); // invalid
        flush(&mut buf, bp);

        let result = unshrink(&buf);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("invalid sub-code")));
    }

    #[test]
    fn test_unshrink_roundtrip() {
        // Verify that unshrink can decode a hand-encoded LZW stream with
        // mixed literals and dictionary references, confirming that all
        // decoded bytes match the expected original data.
        //
        // Encode "XYZXYZ" using codes:
        //   Step 1: emit 'X'(88). prev=88. Output: X
        //   Step 2: code 'Y'(89). emit 'Y'. dict[257]=(88,'Y'). prev=89. Output: XY
        //   Step 3: code 'Z'(90). emit 'Z'. dict[258]=(89,'Z'). prev=90. Output: XYZ
        //   Step 4: code 'X'(88). emit 'X'. dict[259]=(90,'X'). prev=88. Output: XYZX
        //   Step 5: code 258. chain(258): suffix='Z', prefix=89 -> suffix='Y'.
        //           Stack=['Z','Y']. first_byte='Y'. Output reversed: "YZ".
        //           dict[260]=(88,'Y'). prev=258. Output: XYZXYZ
        //
        // Codes: [88, 89, 90, 88, 258]
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 88, 9); // 'X'
        write_code(&mut buf, &mut bp, 89, 9); // 'Y'
        write_code(&mut buf, &mut bp, 90, 9); // 'Z'
        write_code(&mut buf, &mut bp, 88, 9); // 'X'
        write_code(&mut buf, &mut bp, 258, 9); // "YZ"
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"XYZXYZ");
    }

    #[test]
    fn test_unshrink_repeated_pattern() {
        // Encode "ABCABC" - the second "ABC" could use dictionary codes.
        // After "ABC": dict[257]=(A,B), dict[258]=(B,C). next_code=259.
        // For 'A': dict[259]=(C,A). prev=A. For code 257: chain="AB", dict[260]=(A,B).
        // Total: A B C A AB = ABCAAB. That's not right.
        //
        // Let me trace properly for "ABCABC":
        //   Emit 'A'(65). prev=65. Output: A
        //   Code 'B'(66). emit 'B'. dict[257]=(65,'B'). prev=66. Output: AB
        //   Code 'C'(67). emit 'C'. dict[258]=(66,'C'). prev=67. Output: ABC
        //   Code 'A'(65). emit 'A'. dict[259]=(67,'A'). prev=65. Output: ABCA
        //   Code 258. chain(258)='C',prefix=66,'B'. So "BC". emit "BC". dict[260]=(65,'B'). Output: ABCABC
        //
        // Codes: [65, 66, 67, 65, 258]
        let mut buf = Vec::new();
        let mut bp = 0;
        write_code(&mut buf, &mut bp, 65, 9); // A
        write_code(&mut buf, &mut bp, 66, 9); // B
        write_code(&mut buf, &mut bp, 67, 9); // C
        write_code(&mut buf, &mut bp, 65, 9); // A
        write_code(&mut buf, &mut bp, 258, 9); // "BC"
        flush(&mut buf, bp);

        let result = unshrink(&buf).unwrap();
        assert_eq!(result, b"ABCABC");
    }
}
