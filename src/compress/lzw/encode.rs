//! LZW compression (Unix compress `.Z` format).
//!
//! Compresses data using the LZW algorithm, producing output compatible
//! with the Unix `compress` utility.
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

use alloc::vec;
use alloc::vec::Vec;

use super::should_bump_encode_code_width;

/// Magic bytes for Unix compress format.
const MAGIC: [u8; 2] = [0x1F, 0x9D];

/// Block mode flag (bit 7 of flags byte).
const BLOCK_MODE: u8 = 0x80;

/// Clear code used in block mode.
const CLEAR_CODE: u16 = 256;

/// First available dictionary code.
const FIRST_CODE: u16 = 257;

/// Default maximum code bits.
const DEFAULT_MAX_BITS: u8 = 16;

/// Compress data using LZW (Unix compress `.Z` format).
///
/// Uses 16-bit maximum code size with block mode enabled.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_options(input, DEFAULT_MAX_BITS)
}

/// Compress data using LZW with a specified maximum code size (9-16 bits).
///
/// Lower values use less memory but may compress less effectively.
/// Block mode (clear code) is always enabled.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode_with_options(data, 12);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with_options(input: &[u8], max_bits: u8) -> Vec<u8> {
    let max_bits = max_bits.clamp(9, 16);
    let max_code = (1u32 << max_bits) - 1;

    let flags = BLOCK_MODE | max_bits;
    let mut output = Vec::new();
    output.push(MAGIC[0]);
    output.push(MAGIC[1]);
    output.push(flags);

    if input.is_empty() {
        return output;
    }

    // Dictionary: hash table mapping (prefix_code, byte) → code
    // Use a simple hash table with open addressing.
    let table_size = 1 << (max_bits + 1); // power of 2 for fast modulo
    // u32 + u32::MAX sentinel: at max_bits=16 the prefix 65535 is a real code
    // and must not collide with the empty-slot marker.
    let mut hash_prefix = vec![u32::MAX; table_size as usize];
    let mut hash_suffix = vec![0u8; table_size as usize];
    let mut hash_code = vec![0u16; table_size as usize];

    // u32: next_code must reach max_code + 1 (65536 at max_bits=16) without
    // wrapping — a full dictionary is signaled by next_code > max_code.
    let mut next_code: u32 = FIRST_CODE as u32;
    let mut code_bits: u32 = 9;
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    // Helper: flush bits to output
    let flush_bits = |bit_buf: &mut u64, bit_count: &mut u32, output: &mut Vec<u8>| {
        while *bit_count >= 8 {
            output.push(*bit_buf as u8);
            *bit_buf >>= 8;
            *bit_count -= 8;
        }
    };

    // Helper: write a code
    let write_code = |code: u32,
                      code_bits: u32,
                      bit_buf: &mut u64,
                      bit_count: &mut u32,
                      output: &mut Vec<u8>| {
        *bit_buf |= (code as u64) << *bit_count;
        *bit_count += code_bits;
        flush_bits(bit_buf, bit_count, output);
    };

    // Helper: clear the hash table
    let clear_table = |hash_prefix: &mut [u32]| {
        for p in hash_prefix.iter_mut() {
            *p = u32::MAX;
        }
    };

    // Helper: hash function
    let hash = |prefix: u16, byte: u8, table_size: usize| -> usize {
        let h = ((prefix as u32) << 8 | byte as u32).wrapping_mul(2654435761);
        (h as usize) & (table_size - 1)
    };

    // Helper: look up or insert into hash table
    let lookup = |prefix: u16,
                  byte: u8,
                  hash_prefix: &[u32],
                  hash_suffix: &[u8],
                  hash_code: &[u16],
                  table_size: usize|
     -> Option<u16> {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                return None; // empty slot
            }
            if hash_prefix[idx] == prefix as u32 && hash_suffix[idx] == byte {
                return Some(hash_code[idx]);
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    let insert = |prefix: u16,
                  byte: u8,
                  code: u16,
                  hash_prefix: &mut [u32],
                  hash_suffix: &mut [u8],
                  hash_code: &mut [u16],
                  table_size: usize| {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                hash_prefix[idx] = prefix as u32;
                hash_suffix[idx] = byte;
                hash_code[idx] = code;
                return;
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    let table_sz = table_size as usize;

    // Start with first byte as the current prefix (not output yet)
    let mut w = input[0] as u16;

    for &byte in &input[1..] {
        if let Some(code) = lookup(w, byte, &hash_prefix, &hash_suffix, &hash_code, table_sz) {
            // String w+byte is in dictionary
            w = code;
        } else {
            // Output code for w
            write_code(
                w as u32,
                code_bits,
                &mut bit_buf,
                &mut bit_count,
                &mut output,
            );

            // Add w+byte to dictionary
            if next_code <= max_code {
                insert(
                    w,
                    byte,
                    next_code as u16,
                    &mut hash_prefix,
                    &mut hash_suffix,
                    &mut hash_code,
                    table_sz,
                );
                next_code += 1;

                // The encoder widens after the newly allocated code would no
                // longer fit in the current width.
                if should_bump_encode_code_width(next_code, code_bits, max_bits as u32) {
                    code_bits += 1;
                }
            } else {
                // Dictionary full — emit clear code and reset
                write_code(
                    CLEAR_CODE as u32,
                    code_bits,
                    &mut bit_buf,
                    &mut bit_count,
                    &mut output,
                );

                // Pad to code_bits-aligned boundary (Unix compress behavior):
                // Codes are packed in groups of 8 into code_bits bytes.
                // After clear, remaining bits in the group are discarded.
                // Flush remaining bits first.
                if bit_count > 0 {
                    output.push(bit_buf as u8);
                    bit_buf = 0;
                    bit_count = 0;
                }
                // Pad output to code_bits-byte alignment
                let group_bytes = code_bits as usize;
                let data_bytes = output.len() - 3; // exclude header
                let remainder = data_bytes % group_bytes;
                if remainder != 0 {
                    let pad = group_bytes - remainder;
                    output.resize(output.len() + pad, 0);
                }

                // Reset dictionary
                clear_table(&mut hash_prefix);
                next_code = FIRST_CODE as u32;
                code_bits = 9;
            }

            w = byte as u16;
        }
    }

    // Output the last code
    write_code(
        w as u32,
        code_bits,
        &mut bit_buf,
        &mut bit_count,
        &mut output,
    );

    // Flush remaining bits
    if bit_count > 0 {
        output.push(bit_buf as u8);
    }

    output
}

/// Compress data using LZW with full control over max bits and block mode.
///
/// When `block_mode` is `true`, code 256 is reserved as a clear code and
/// the dictionary resets when full (same as [`encode_with_options`]).
///
/// When `block_mode` is `false`, no clear code is reserved, dictionary
/// codes start at 256, and once the dictionary is full new entries are
/// simply not inserted.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::{decode, encode};
///
/// let data = b"Hello, LZW!";
/// let compressed = encode::encode_with_full_options(data, 16, false);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with_full_options(input: &[u8], max_bits: u8, block_mode: bool) -> Vec<u8> {
    if block_mode {
        return encode_with_options(input, max_bits);
    }

    let max_bits = max_bits.clamp(9, 16);
    let max_code = (1u32 << max_bits) - 1;

    // Non-block mode: bit 7 is clear, just max_bits
    let flags = max_bits;
    let mut output = Vec::new();
    output.push(MAGIC[0]);
    output.push(MAGIC[1]);
    output.push(flags);

    if input.is_empty() {
        return output;
    }

    // Dictionary: hash table mapping (prefix_code, byte) → code
    let table_size = 1 << (max_bits + 1);
    // u32 + u32::MAX sentinel: at max_bits=16 the prefix 65535 is a real code
    // and must not collide with the empty-slot marker.
    let mut hash_prefix = vec![u32::MAX; table_size as usize];
    let mut hash_suffix = vec![0u8; table_size as usize];
    let mut hash_code = vec![0u16; table_size as usize];

    // No clear code in non-block mode; codes start at 256.
    // u32: next_code must reach max_code + 1 without wrapping.
    let mut next_code: u32 = 256;
    let mut code_bits: u32 = 9;
    let mut bit_buf: u64 = 0;
    let mut bit_count: u32 = 0;

    let flush_bits = |bit_buf: &mut u64, bit_count: &mut u32, output: &mut Vec<u8>| {
        while *bit_count >= 8 {
            output.push(*bit_buf as u8);
            *bit_buf >>= 8;
            *bit_count -= 8;
        }
    };

    let write_code = |code: u32,
                      code_bits: u32,
                      bit_buf: &mut u64,
                      bit_count: &mut u32,
                      output: &mut Vec<u8>| {
        *bit_buf |= (code as u64) << *bit_count;
        *bit_count += code_bits;
        flush_bits(bit_buf, bit_count, output);
    };

    let hash = |prefix: u16, byte: u8, table_size: usize| -> usize {
        let h = ((prefix as u32) << 8 | byte as u32).wrapping_mul(2654435761);
        (h as usize) & (table_size - 1)
    };

    let lookup = |prefix: u16,
                  byte: u8,
                  hash_prefix: &[u32],
                  hash_suffix: &[u8],
                  hash_code: &[u16],
                  table_size: usize|
     -> Option<u16> {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                return None;
            }
            if hash_prefix[idx] == prefix as u32 && hash_suffix[idx] == byte {
                return Some(hash_code[idx]);
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    let insert = |prefix: u16,
                  byte: u8,
                  code: u16,
                  hash_prefix: &mut [u32],
                  hash_suffix: &mut [u8],
                  hash_code: &mut [u16],
                  table_size: usize| {
        let mut idx = hash(prefix, byte, table_size);
        loop {
            if hash_prefix[idx] == u32::MAX {
                hash_prefix[idx] = prefix as u32;
                hash_suffix[idx] = byte;
                hash_code[idx] = code;
                return;
            }
            idx = (idx + 1) & (table_size - 1);
        }
    };

    let table_sz = table_size as usize;

    let mut w = input[0] as u16;

    for &byte in &input[1..] {
        if let Some(code) = lookup(w, byte, &hash_prefix, &hash_suffix, &hash_code, table_sz) {
            w = code;
        } else {
            write_code(
                w as u32,
                code_bits,
                &mut bit_buf,
                &mut bit_count,
                &mut output,
            );

            // Add to dictionary only if not full
            if next_code <= max_code {
                insert(
                    w,
                    byte,
                    next_code as u16,
                    &mut hash_prefix,
                    &mut hash_suffix,
                    &mut hash_code,
                    table_sz,
                );
                next_code += 1;

                if should_bump_encode_code_width(next_code, code_bits, max_bits as u32) {
                    code_bits += 1;
                }
            }
            // When dict full, just stop inserting (no clear code)

            w = byte as u16;
        }
    }

    // Output the last code
    write_code(
        w as u32,
        code_bits,
        &mut bit_buf,
        &mut bit_count,
        &mut output,
    );

    // Flush remaining bits
    if bit_count > 0 {
        output.push(bit_buf as u8);
    }

    output
}

/// Compress data using LZW and write to a writer.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::lzw::encode;
///
/// let data = b"Hello, writer!";
/// let mut output = Vec::new();
/// let size = encode::encode_writer(data, &mut output).unwrap();
/// assert!(size > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(input: &[u8], mut writer: W) -> std::io::Result<usize> {
    let encoded = encode(input);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_bump_encode_code_width_at_boundary() {
        assert!(!should_bump_encode_code_width(511, 9, 10));
        assert!(!should_bump_encode_code_width(512, 9, 10));
        assert!(should_bump_encode_code_width(513, 9, 10));
        assert!(!should_bump_encode_code_width(513, 9, 9));
    }

    #[test]
    fn test_header_format() {
        let compressed = encode(b"A");
        assert_eq!(compressed[0], 0x1F);
        assert_eq!(compressed[1], 0x9D);
        assert_eq!(compressed[2] & 0x1F, 16); // default max_bits
        assert_ne!(compressed[2] & BLOCK_MODE, 0); // block mode on
    }

    #[test]
    fn test_empty_input() {
        let compressed = encode(b"");
        assert_eq!(compressed.len(), 3); // header only
        assert_eq!(compressed[0], 0x1F);
        assert_eq!(compressed[1], 0x9D);
    }

    #[test]
    fn test_max_bits_clamping() {
        // Too low → clamps to 9
        let c1 = encode_with_options(b"test", 5);
        assert_eq!(c1[2] & 0x1F, 9);

        // Too high → clamps to 16
        let c2 = encode_with_options(b"test", 20);
        assert_eq!(c2[2] & 0x1F, 16);
    }

    #[test]
    fn test_compression_ratio() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = encode(data);
        // LZW should compress repetitive data
        assert!(
            compressed.len() < data.len(),
            "compressed {} >= original {}",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn test_encode_with_options_max_bits_9() {
        let data = b"Hello, World!";
        let compressed = encode_with_options(data, 9);
        assert_eq!(compressed[2] & 0x1F, 9);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_clear_code_emitted_when_dict_full() {
        // With max_bits=9, dictionary can hold codes 257..=511 (255 entries).
        // Feed enough unique byte pairs to fill the dictionary and force a
        // clear code. Verify the encoder produces a stream that round-trips.
        let data: Vec<u8> = (0..512u32).map(|i| (i % 256) as u8).collect();
        let compressed = encode_with_options(&data, 9);
        // The compressed data should be valid and decodable.
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_non_block_mode() {
        let data = b"Hello, non-block mode LZW! ABABABABABABAB";
        let compressed = encode_with_full_options(data, 16, false);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_non_block_mode_header_flag() {
        let compressed = encode_with_full_options(b"test", 12, false);
        // Header byte 2: block_mode bit (0x80) should be clear
        assert_eq!(
            compressed[2] & BLOCK_MODE,
            0,
            "block mode bit should be clear"
        );
        // max_bits should be 12
        assert_eq!(compressed[2] & 0x1F, 12);
    }

    #[test]
    fn test_code_width_grows_at_boundary() {
        // With max_bits=10, verify that the encoder correctly bumps code width
        // from 9 to 10 bits when next_code exceeds 2^9 = 512. Use enough
        // unique byte pairs to push next_code past 512. Verify roundtrip.
        let data: Vec<u8> = (0..600u32).map(|i| (i % 256) as u8).collect();
        let compressed = encode_with_options(&data, 10);
        assert_eq!(compressed[2] & 0x1F, 10);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
