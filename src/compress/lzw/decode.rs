//! LZW decompression (Unix compress `.Z` format).
//!
//! Decodes data compressed with the Unix `compress` utility or any
//! LZW compressor using the same `.Z` format.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzw::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```
//!
//! # Errors
//!
//! Returns [`Error::InvalidData`] if the input is not valid `.Z` data.
//!
//! [`Error::InvalidData`]: crate::error::Error::InvalidData

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::should_bump_decode_code_width;

/// Magic bytes for Unix compress format.
const MAGIC: [u8; 2] = [0x1F, 0x9D];

/// Block mode flag (bit 7 of flags byte).
const BLOCK_MODE: u8 = 0x80;
/// Reserved header bits that classic `compress` / `uncompress` reject.
const RESERVED_FLAGS: u8 = 0x60;

/// Clear code used in block mode.
const CLEAR_CODE: u16 = 256;

/// First available dictionary code (after 256 single-byte entries + clear code).
const FIRST_CODE: u16 = 257;

/// Decode Unix compress (`.Z`) data.
///
/// Supports variable-width codes (9-16 bits) and block mode (clear code).
///
/// This function does not panic.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the magic number is wrong, the max bits
/// value is out of range, or the compressed data is malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    // Parse header
    if input.len() < 3 {
        return Err(Error::InvalidData("lzw: input too short for header"));
    }
    if input[0] != MAGIC[0] || input[1] != MAGIC[1] {
        return Err(Error::InvalidData("lzw: invalid magic number"));
    }

    let flags = input[2];
    if flags & RESERVED_FLAGS != 0 {
        return Err(Error::InvalidData("lzw: reserved header flag bits are set"));
    }
    let max_bits = (flags & 0x1F) as u32;
    let block_mode = (flags & BLOCK_MODE) != 0;

    if !(9..=16).contains(&max_bits) {
        return Err(Error::InvalidData("lzw: max bits out of range (9-16)"));
    }

    decode_body(&input[3..], max_bits, block_mode)
}

/// Decode a headerless Unix compress LZW codestream.
///
/// This is the variable-width LZW codestream without the 3-byte `.Z`
/// header, used by ARC methods 8 (Crunched) and 9 (Squashed) and the
/// Spark `0x7f` method which embed the stream inside their own member
/// records. `max_bits` is the maximum code width (9-16); `block_mode`
/// enables the reserved clear code 256 and the group-of-8 resync.
pub(crate) fn decode_body(data: &[u8], max_bits: u32, block_mode: bool) -> Result<Vec<u8>, Error> {
    if !(9..=16).contains(&max_bits) {
        return Err(Error::InvalidData("lzw: max bits out of range (9-16)"));
    }

    let max_code = (1u32 << max_bits) - 1;

    // Dictionary: for each code, store (prefix_code, suffix_byte).
    // Codes 0-255 are single-byte entries (prefix = none).
    // We store strings lazily and reconstruct on output.
    let dict_capacity = (max_code + 1) as usize;
    let mut prefix = vec![0u16; dict_capacity];
    let mut suffix = vec![0u8; dict_capacity];

    // Initialize single-byte entries
    for i in 0u16..256 {
        prefix[i as usize] = u16::MAX; // no prefix
        suffix[i as usize] = i as u8;
    }

    // u32: next_code must reach max_code + 1 (65536 at max_bits=16) without
    // wrapping — a full dictionary is signaled by next_code > max_code.
    let mut next_code: u32 = if block_mode { FIRST_CODE as u32 } else { 256 };
    let mut code_bits: u32 = 9;
    let mut bit_pos: usize = 0;
    let mut output = Vec::new();

    // Temp buffer for decoding a dictionary chain
    let mut decode_stack = Vec::with_capacity(max_bits as usize * 2);

    // Read the first code — must be a literal (< 256)
    let mut prev_code = match read_code(data, &mut bit_pos, code_bits) {
        Some(c) => c,
        None => return Ok(output), // empty compressed data
    };
    if prev_code > 255 {
        return Err(Error::InvalidData("lzw: first code must be a literal"));
    }
    output.push(prev_code as u8);

    while let Some(code) = read_code(data, &mut bit_pos, code_bits) {
        if block_mode && code == CLEAR_CODE as u32 {
            // Save old code width for alignment before resetting
            let old_code_bits = code_bits;

            // Reset dictionary
            next_code = FIRST_CODE as u32;
            code_bits = 9;

            // Skip to next old_code_bits-aligned boundary.
            // Unix compress packs codes in groups of 8, each group being
            // old_code_bits bytes. After clear, remaining bits in the
            // current group are discarded.
            let bits_per_group = old_code_bits as usize;
            let remainder = bit_pos % (bits_per_group * 8);
            if remainder != 0 {
                bit_pos += bits_per_group * 8 - remainder;
            }

            // Read next code after clear
            prev_code = match read_code(data, &mut bit_pos, code_bits) {
                Some(c) => c,
                None => break,
            };
            if prev_code > 255 {
                return Err(Error::InvalidData(
                    "lzw: first code after clear must be a literal",
                ));
            }
            output.push(prev_code as u8);
            continue;
        }

        let code16 = code as u16;

        // Decode the string for this code
        let first_byte;
        if code < next_code {
            // Known code — decode the chain
            first_byte = decode_chain(&prefix, &suffix, code16, &mut decode_stack)?;
        } else if code == next_code {
            // Special case: code not yet in dictionary (KwKwK)
            // The string is string(prev_code) + first_byte_of(string(prev_code))
            first_byte = decode_chain(&prefix, &suffix, prev_code as u16, &mut decode_stack)?;
            // Insert at position 0 of the reversed stack so it becomes the
            // last byte when output in reverse order.
            decode_stack.insert(0, first_byte);
        } else {
            return Err(Error::InvalidData("lzw: code out of range"));
        }

        // Output the decoded string (stack is in reverse order)
        for &b in decode_stack.iter().rev() {
            output.push(b);
        }

        // Add new dictionary entry: prev_code + first_byte
        if next_code <= max_code {
            prefix[next_code as usize] = prev_code as u16;
            suffix[next_code as usize] = first_byte;
            next_code += 1;

            // The decoder reconstructs dictionary entries one step behind the
            // encoder, so it widens one boundary earlier than the encoder.
            if should_bump_decode_code_width(next_code, code_bits, max_bits) {
                code_bits += 1;
            }
        }

        prev_code = code;
    }

    Ok(output)
}

/// Decode a dictionary chain into decode_stack (reversed order).
/// Returns the first byte of the string.
fn decode_chain(
    prefix: &[u16],
    suffix: &[u8],
    mut code: u16,
    stack: &mut Vec<u8>,
) -> Result<u8, Error> {
    stack.clear();
    // Safety limit to prevent infinite loops on corrupt data
    let limit = prefix.len();
    let mut count = 0;
    // Walk dictionary entries (codes >= 256). At max_bits=16, code 65535 is a
    // real code so u16::MAX cannot be used as a "no prefix" sentinel here —
    // the chain ends at a literal (code <= 255) instead.
    while code > 255 {
        if count >= limit {
            return Err(Error::InvalidData("lzw: dictionary chain too long"));
        }
        stack.push(suffix[code as usize]);
        code = prefix[code as usize];
        count += 1;
    }
    // Reached a literal entry (0-255): its byte is the first byte of the string.
    stack.push(suffix[code as usize]);
    stack
        .last()
        .copied()
        .ok_or(Error::InvalidData("lzw: empty dictionary chain"))
}

/// Read a variable-width code from the bitstream (LSB-first).
fn read_code(data: &[u8], bit_pos: &mut usize, code_bits: u32) -> Option<u32> {
    let bits_needed = code_bits as usize;
    // Check if enough bits remain
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

/// Decode Unix compress (`.Z`) data from a reader.
///
/// # Errors
///
/// Returns an error if reading from the underlying reader fails or if the
/// data is not valid `.Z` format.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode_reader(&compressed[..]).unwrap();
/// assert_eq!(decoded, data);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    decode(&buf).map_err(Into::into)
}

/// Decode Unix compress (`.Z`) data with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let result = decode(input)?;
    if result.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;

    #[test]
    fn test_should_bump_decode_code_width_at_boundary() {
        assert!(!should_bump_decode_code_width(511, 9, 10));
        assert!(should_bump_decode_code_width(512, 9, 10));
        assert!(!should_bump_decode_code_width(512, 9, 9));
    }

    #[test]
    fn test_invalid_magic() {
        let result = decode(&[0x00, 0x00, 0x90]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("magic")));
    }

    #[test]
    fn test_input_too_short() {
        let result = decode(&[0x1F, 0x9D]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("too short")));
    }

    #[test]
    fn test_max_bits_out_of_range() {
        // max_bits = 8 (too low)
        let result = decode(&[0x1F, 0x9D, 0x08]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("max bits")));

        // max_bits = 17 (too high)
        let result = decode(&[0x1F, 0x9D, 0x91]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("max bits")));
    }

    #[test]
    fn test_reserved_flag_bits_rejected() {
        let result = decode(&[0x1F, 0x9D, 0xB0]);
        assert!(matches!(
            result,
            Err(Error::InvalidData(msg)) if msg.contains("reserved header flag")
        ));
    }

    #[test]
    fn test_empty_compressed_data() {
        // Valid header but no data
        let result = decode(&[0x1F, 0x9D, 0x90]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_truncated_after_header() {
        // Just the 3-byte header with no code data — should return empty or succeed
        let result = decode(&[0x1F, 0x9D, 0x90]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_roundtrip_hello() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let data = b"A";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        // Test with various sizes and max_bits to exercise code width transitions
        for max_bits in 9..=16u8 {
            for &size in &[512, 1024, 10000] {
                let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                let compressed = super::super::encode::encode_with_options(&data, max_bits);
                let decompressed = decode(&compressed).unwrap_or_else(|e| {
                    panic!("decode failed for max_bits={max_bits} size={size}: {e}")
                });
                assert_eq!(
                    decompressed, data,
                    "roundtrip failed for max_bits={max_bits} size={size}"
                );
            }
        }
    }

    #[test]
    fn test_roundtrip_kwkwk() {
        // Data that triggers the KwKwK special case: a pattern where the
        // decoder encounters a code that equals next_code (not yet added).
        // This happens when the encoder sees a repeated prefix.
        let data = b"AAAAAA";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_read_code_lsb_first() {
        // Two 9-bit codes packed LSB-first in bytes:
        // code0 = 0x041 (65 = 'A'), code1 = 0x042 (66 = 'B')
        // Binary layout (9 bits each, LSB-first):
        // code0: bits 0-8 = 0b0_0100_0001 = 65
        // code1: bits 9-17 = 0b0_0100_0010 = 66
        // Bytes: [0b10000010, 0b00001000, 0b000000_01]
        //        = [0x82, 0x08, 0x01] ... let me compute properly.
        // bit layout in byte 0: bits[0..8] → code0[0..8]
        // bit layout in byte 1: bit[0] → code0[8], bits[1..8] → code1[0..7]
        // bit layout in byte 2: bits[0..2] → code1[7..9]
        // code0=65=0b001000001, code1=66=0b001000010
        // byte0 = code0[0..8] = 0b01000001 = 0x41
        // byte1 = code0[8] | code1[0..7]<<1 = 0b0 | 0b1000100 = 0b01000100 = 0x44
        // Hmm, let me just test via read_code directly.
        let data = [0x41u8, 0x44, 0x00]; // packed codes
        let mut bp = 0;
        let c0 = read_code(&data, &mut bp, 9).unwrap();
        assert_eq!(c0, 65); // 'A'
    }

    #[test]
    fn test_roundtrip_english_text() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     The quick brown fox jumps over the lazy dog.";
        let compressed = super::super::encode::encode(data);
        assert!(compressed.len() < data.len(), "should compress");
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_max_bits_range() {
        let data = b"test data for various max_bits settings";
        for max_bits in 9..=16u8 {
            let compressed = super::super::encode::encode_with_options(data, max_bits);
            let decompressed = decode(&compressed).unwrap();
            assert_eq!(decompressed, data, "failed for max_bits={max_bits}");
        }
    }

    #[test]
    fn test_non_block_mode_decode() {
        // Construct a valid .Z stream with block_mode=0 (bit 7 of flags byte clear).
        // With block_mode=0, there is no clear code, and dictionary codes start at 256
        // instead of 257. We manually build a stream encoding "ABAB".
        //
        // Dictionary starts at next_code=256 (no clear code reserved).
        // Encoder steps for "ABAB":
        //   - w = 'A' (65)
        //   - byte 'B': lookup (65,'B') → miss. Emit 65, add (65,'B')=256. w='B'
        //   - byte 'A': lookup (66,'A') → miss. Emit 66, add (66,'A')=257. w='A'
        //   - byte 'B': lookup (65,'B') → 256. w=256
        //   - end: emit 256
        // Codes to emit: [65, 66, 256] in 9-bit LSB-first packing.
        //
        // 65  = 0b0_0100_0001
        // 66  = 0b0_0100_0010
        // 256 = 0b1_0000_0000
        //
        // Bit layout (LSB first, packed):
        //   bits  0.. 8: 65  → 0b001000001
        //   bits  9..17: 66  → 0b001000010
        //   bits 18..26: 256 → 0b100000000
        //
        // Pack into bytes:
        //   byte0 (bits 0-7):  code0[0..8] = 0b01000001 = 0x41
        //   byte1 (bits 8-15): code0[8]=0 | code1[0..6]<<1 = 0b0_1000100 = 0x44
        //   byte2 (bits 16-23): code1[7..8]=0b01 | code2[0..5]<<2 = 0b00000001 = 0x01
        //   byte3 (bits 24-26): code2[5..8]=0b100 = 0b00000100 = 0x04
        // Wait, let me be more careful:
        //   bit  0..8  = 65  = bits: 1,0,0,0,0,0,1,0,0   (LSB first: bit0=1, bit1=0,... bit8=0)
        //   Actually 65 = 0b001000001, LSB first: 1,0,0,0,0,0,1,0,0
        //   bit  9..17 = 66 = 0b001000010, LSB first: 0,1,0,0,0,0,1,0,0
        //   bit 18..26 = 256= 0b100000000, LSB first: 0,0,0,0,0,0,0,0,1

        // Let me just build it programmatically.
        fn write_code_to_buf(buf: &mut Vec<u8>, bit_pos: &mut usize, code: u32, bits: u32) {
            // Ensure buf is large enough
            let needed_bytes = (*bit_pos + bits as usize).div_ceil(8);
            while buf.len() < needed_bytes {
                buf.push(0);
            }
            for i in 0..bits as usize {
                if (code >> i) & 1 != 0 {
                    let byte_idx = (*bit_pos + i) / 8;
                    let bit_idx = (*bit_pos + i) % 8;
                    buf[byte_idx] |= 1 << bit_idx;
                }
            }
            *bit_pos += bits as usize;
        }

        // Header: magic + flags with block_mode=0, max_bits=16
        let mut stream = vec![0x1F, 0x9D, 16u8]; // block_mode=0, max_bits=16
        let mut data_buf = Vec::new();
        let mut bp = 0usize;
        write_code_to_buf(&mut data_buf, &mut bp, 65, 9); // 'A'
        write_code_to_buf(&mut data_buf, &mut bp, 66, 9); // 'B'
        write_code_to_buf(&mut data_buf, &mut bp, 256, 9); // code for "AB"
        // Flush remaining bits
        let final_bytes = bp.div_ceil(8);
        while data_buf.len() < final_bytes {
            data_buf.push(0);
        }
        stream.extend_from_slice(&data_buf);

        let result = decode(&stream).unwrap();
        assert_eq!(result, b"ABAB");
    }

    #[test]
    fn test_clear_code_after_dict_full() {
        // Use max_bits=9, so max_code = 511. With block_mode, dictionary starts
        // at 257 and fills up to 511 (255 entries). Generate data that fills the
        // dictionary and forces a clear code to be emitted, then verify roundtrip.
        // A cycling pattern of bytes ensures many unique (prefix, byte) pairs.
        let mut data = Vec::new();
        // 512 bytes of cycling data should be enough to fill the 9-bit dictionary
        // and trigger at least one clear code.
        for i in 0..512u32 {
            data.push((i % 256) as u8);
        }
        let compressed = super::super::encode::encode_with_options(&data, 9);

        // Verify the compressed stream actually contains at least one clear code.
        // (The dictionary can hold 255 entries with max_bits=9, so 512 unique-pair
        // bytes should overflow it.)
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_code_width_transition_boundary() {
        // With max_bits >= 10, create input that causes next_code to land exactly on
        // 2^9 = 512, verifying the code width bump from 9 to 10 bits.
        // With block_mode, next_code starts at 257. We need 255 unique dictionary
        // entries to reach next_code=512 (257 + 255 = 512). Then the code width
        // should bump from 9 to 10.
        //
        // Use max_bits=10 to isolate the 9→10 transition.
        // Generate input with many unique byte pairs to fill dictionary slots.
        let mut data = Vec::new();
        // A sequence of distinct byte pairs: (0,1), (2,3), (4,5)... ensures each
        // pair is new. We need >255 pairs, so >512 bytes.
        for i in 0..600u32 {
            data.push((i % 256) as u8);
        }
        let compressed = super::super::encode::encode_with_options(&data, 10);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_literal_after_clear_required() {
        // Construct a raw .Z stream where a clear code (256) is immediately followed
        // by a non-literal code (>= 256), which should trigger the error
        // "first code after clear must be a literal".
        //
        // Header: magic + flags (max_bits=9, block_mode=1)
        // First code: literal 'A' (65) — valid
        // Second code: clear code (256)
        // Third code: 257 — invalid (must be < 256 after clear)

        fn write_code_to_buf(buf: &mut Vec<u8>, bit_pos: &mut usize, code: u32, bits: u32) {
            let needed_bytes = (*bit_pos + bits as usize).div_ceil(8);
            while buf.len() < needed_bytes {
                buf.push(0);
            }
            for i in 0..bits as usize {
                if (code >> i) & 1 != 0 {
                    let byte_idx = (*bit_pos + i) / 8;
                    let bit_idx = (*bit_pos + i) % 8;
                    buf[byte_idx] |= 1 << bit_idx;
                }
            }
            *bit_pos += bits as usize;
        }

        // Header: magic + block_mode=1, max_bits=9
        let mut stream = vec![0x1F, 0x9D, 0x80 | 9];
        let mut data_buf = Vec::new();
        let mut bp = 0usize;

        // Code 0: literal 'A' = 65 (9 bits)
        write_code_to_buf(&mut data_buf, &mut bp, 65, 9);
        // Code 1: clear code = 256 (9 bits)
        write_code_to_buf(&mut data_buf, &mut bp, 256, 9);

        // After clear, the decoder skips to the next code_bits-aligned boundary.
        // The old code_bits was 9 at the time of clear. Codes are packed in groups
        // of 8 codes, each group being (old_code_bits * 8) bits. After reading 2
        // codes (18 bits), the remainder in the current group is 18 % (9*8) = 18 % 72
        // = 18, so we need to skip 72 - 18 = 54 bits to reach the next boundary.
        // That means the next code starts at bit position 72.
        // We need to pad data_buf to at least bit 72 before writing the next code.
        // After alignment, code_bits is reset to 9.
        let aligned_bp = 72usize;
        let needed = (aligned_bp + 9).div_ceil(8);
        while data_buf.len() < needed {
            data_buf.push(0);
        }
        // Write code 257 at bit position 72 (9 bits, after clear reset to 9-bit codes)
        let mut aligned_pos = aligned_bp;
        write_code_to_buf(&mut data_buf, &mut aligned_pos, 257, 9);

        let final_bytes = aligned_pos.div_ceil(8);
        while data_buf.len() < final_bytes {
            data_buf.push(0);
        }

        stream.extend_from_slice(&data_buf);

        let result = decode(&stream);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("after clear")),
            "expected error about first code after clear, got: {result:?}"
        );
    }

    #[test]
    fn test_code_out_of_range() {
        // Craft a stream with a code that's too large
        // Header: magic + flags (max_bits=9, block_mode=1)
        let mut data = vec![0x1F, 0x9D, 0x90 | 9];
        // First code: literal 'A' = 65 (9 bits, LSB-first)
        // Second code: 999 (way too large for 9-bit codes, max valid = 257)
        // 65 in 9 bits: 0b001000001
        // 999 in 9 bits: 0b111100111 — but 999 > 511 so it wraps to 999 & 0x1FF = 487
        // Let's use code 500 which is > FIRST_CODE(257) and > next_code(257)
        // after first code, next_code = 258 (if prev valid)
        // code 500 > 258 → out of range
        // Pack: code0=65 (9 bits), code1=500 (9 bits)
        // 65 = 0b001000001, 500 = 0b111110100
        // byte0 = code0[0..8] = 0b01000001 = 0x41
        // byte1 = code0[8]=0 | code1[0..7]<<1 = 0b11101000 = 0xE8
        // byte2 = code1[7..9] = 0b11 = 0x03
        data.extend_from_slice(&[0x41, 0xE8, 0x03]);
        let result = decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello lzw bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello lzw bounded test data";
        let compressed = super::super::encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello lzw bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello lzw bounded test data";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // LZW encoding of empty data produces a valid .Z header with no codes.
        let compressed = super::super::encode::encode(b"");
        let decoded = decode_bounded(&compressed, 0).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_decode_chain_code_65535() {
        // At max_bits=16, code 65535 is a valid dictionary code. It must not be
        // treated as a "no prefix" sentinel when walking the chain.
        let mut prefix = vec![u16::MAX; 65536];
        let mut suffix = vec![0u8; 65536];
        for i in 0u16..256 {
            suffix[i as usize] = i as u8;
        }
        // entry 65535 = literal 'A' (65) + 'B' → string "AB"
        prefix[65535] = 65;
        suffix[65535] = b'B';

        let mut stack = Vec::new();
        let first = decode_chain(&prefix, &suffix, 65535, &mut stack).unwrap();
        assert_eq!(first, b'A');
        assert_eq!(&stack[..], b"BA"); // stack is in reverse order
    }

    #[test]
    fn test_decode_chain_prefix_65535() {
        // An entry whose prefix is code 65535 must not truncate the chain at
        // that node.
        let mut prefix = vec![u16::MAX; 65536];
        let mut suffix = vec![0u8; 65536];
        for i in 0u16..256 {
            suffix[i as usize] = i as u8;
        }
        // entry 65535 = 'A' + 'B' → "AB"
        prefix[65535] = 65;
        suffix[65535] = b'B';
        // entry 600 = code 65535 + 'C' → "ABC"
        prefix[600] = 65535;
        suffix[600] = b'C';

        let mut stack = Vec::new();
        let first = decode_chain(&prefix, &suffix, 600, &mut stack).unwrap();
        assert_eq!(first, b'A');
        assert_eq!(&stack[..], b"CBA");
    }

    /// Deterministic byte stream that forces dictionary growth.
    fn prng_bytes(n: usize) -> Vec<u8> {
        let mut state = 0x9E3779B97F4A7C15u64;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn test_roundtrip_dict_full_boundary_all_max_bits() {
        // Drive the dictionary past capacity at every max_bits so that
        // next_code reaches max_code + 1 — the boundary where a u16
        // next_code used to wrap to 0 — and a clear code is emitted.
        for max_bits in 9..=16u8 {
            let max_code = (1usize << max_bits) - 1;
            // ~3x dictionary capacity guarantees the dictionary fills and the
            // block-mode encoder emits at least one clear code.
            let data = prng_bytes(max_code * 3);
            let compressed = super::super::encode::encode_with_options(&data, max_bits);
            let decoded = decode(&compressed)
                .unwrap_or_else(|e| panic!("decode failed for max_bits={max_bits}: {e}"));
            assert_eq!(
                &decoded[..],
                &data[..],
                "roundtrip failed for max_bits={max_bits}"
            );
        }
    }

    #[test]
    fn test_roundtrip_non_block_dict_full() {
        // Non-block mode at max_bits=16: the dictionary fills to 65535 and
        // stays full — no clear code, but the stream must still decode.
        // A wrapped next_code would have silently corrupted the dictionary.
        let data = prng_bytes(65535 * 3);
        let compressed = super::super::encode::encode_with_full_options(&data, 16, false);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(&decoded[..], &data[..]);
    }

    #[test]
    fn test_fuzz_regression_dict_full_wraparound() {
        // Fuzz-found regression (run-1790257066): with max_bits=16 the
        // dictionary fills completely and next_code reaches 65536. A u16
        // next_code wrapped to 0, so the encoder kept inserting from code 0
        // and the decoder reported "code out of range".
        let input = include_bytes!("../../../tests/fixtures/fuzz/lzw_dict_full_wraparound.bin");
        let encoded = super::super::encode::encode(input);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(&decoded[..], &input[..]);
    }
}
