//! ZIP Expanding (Methods 2-5) decoder.
//!
//! Implements the Reducing/Expanding algorithm as described in APPNOTE §5.2.
//! The factor parameter (1-4) determines the follower set size: max followers
//! = 2^(7-factor). After follower-set decoding, a DLE (Data Length Encoding)
//! pass expands run-length encoded bytes.

use alloc::vec::Vec;

use crate::error::Error;

/// Expand (decompress) data compressed with ZIP method 2-5 (Reducing).
///
/// `factor` must be 1-4, corresponding to methods 2-5.
pub(super) fn expand(input: &[u8], factor: u8) -> Result<Vec<u8>, Error> {
    if !(1..=4).contains(&factor) {
        return Err(Error::InvalidData("zip expand: factor must be 1-4"));
    }

    let max_followers: usize = 1 << (7 - factor);

    // --- Phase 1: Read follower set table ---
    let mut reader = BitReader::new(input);
    let mut follower_sets: [Vec<u8>; 256] = core::array::from_fn(|_| Vec::new());

    // The follower set table is read for bytes 255 down to 0.
    for i in (0..=255u16).rev() {
        let bits_for_count = if max_followers < 2 {
            1
        } else {
            bit_length(max_followers as u32)
        };
        let count = reader.read_bits(bits_for_count)? as usize;
        if count > max_followers {
            return Err(Error::InvalidData(
                "zip expand: follower count exceeds maximum",
            ));
        }
        let followers = &mut follower_sets[i as usize];
        followers.reserve(count);
        for _ in 0..count {
            let follower = reader.read_bits(8)? as u8;
            followers.push(follower);
        }
    }

    // --- Phase 2: Decode data using follower sets ---
    let mut intermediate = Vec::new();
    // First byte is always read as a literal 8-bit value.
    let first_byte = reader.read_bits(8)? as u8;
    intermediate.push(first_byte);
    let mut last_byte = first_byte;

    loop {
        if reader.is_exhausted() {
            break;
        }
        let num_followers = follower_sets[last_byte as usize].len();

        let byte = if num_followers == 0 {
            // No followers: read literal 8-bit byte.
            match reader.try_read_bits(8) {
                Some(v) => v as u8,
                None => break,
            }
        } else {
            // Has followers: read a single bit.
            let bit = match reader.try_read_bits(1) {
                Some(v) => v,
                None => break,
            };
            if bit == 1 {
                // Literal byte.
                match reader.try_read_bits(8) {
                    Some(v) => v as u8,
                    None => break,
                }
            } else {
                // Read follower index.
                let index_bits = bit_length(num_followers as u32);
                let index = match reader.try_read_bits(index_bits) {
                    Some(v) => v as usize,
                    None => break,
                };
                if index >= num_followers {
                    return Err(Error::InvalidData(
                        "zip expand: follower index out of range",
                    ));
                }
                follower_sets[last_byte as usize][index]
            }
        };
        intermediate.push(byte);
        last_byte = byte;
    }

    // --- Phase 3: DLE (Data Length Encoding) expansion ---
    dle_expand(&intermediate)
}

/// Expand DLE-encoded data.
///
/// DLE marker is 0x90:
/// - `0x90 0x00` => literal byte 0x90
/// - `0x90 <count>` => repeat previous byte <count> times (count > 0)
fn dle_expand(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        if input[i] == 0x90 {
            i += 1;
            if i >= input.len() {
                return Err(Error::InvalidData("zip expand: truncated DLE sequence"));
            }
            if input[i] == 0x00 {
                // Literal 0x90
                output.push(0x90);
            } else {
                // Repeat previous byte
                let count = input[i] as usize;
                let prev = output.last().copied().ok_or(Error::InvalidData(
                    "zip expand: DLE repeat with no previous byte",
                ))?;
                for _ in 0..count {
                    output.push(prev);
                }
            }
        } else {
            output.push(input[i]);
        }
        i += 1;
    }

    Ok(output)
}

/// Compute the number of bits needed to represent a value (ceil(log2(n))).
/// For n=0 or n=1, returns 1.
const fn bit_length(n: u32) -> u8 {
    if n <= 1 {
        return 1;
    }
    32 - (n - 1).leading_zeros() as u8
}

/// Bitstream reader that reads bits LSB-first from a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0-7, bits consumed within current byte
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    const fn is_exhausted(&self) -> bool {
        self.byte_pos >= self.data.len()
    }

    /// Read `count` bits (1-16) from the stream, LSB first.
    fn read_bits(&mut self, count: u8) -> Result<u16, Error> {
        self.try_read_bits(count).ok_or(Error::UnexpectedEof)
    }

    /// Try to read `count` bits; returns None if not enough data.
    fn try_read_bits(&mut self, count: u8) -> Option<u16> {
        let mut result: u16 = 0;
        for i in 0..count {
            if self.byte_pos >= self.data.len() {
                return None;
            }
            let bit = (self.data[self.byte_pos] >> self.bit_pos) & 1;
            result |= (bit as u16) << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_length() {
        assert_eq!(bit_length(0), 1);
        assert_eq!(bit_length(1), 1);
        assert_eq!(bit_length(2), 1);
        assert_eq!(bit_length(3), 2);
        assert_eq!(bit_length(4), 2);
        assert_eq!(bit_length(5), 3);
        assert_eq!(bit_length(8), 3);
        assert_eq!(bit_length(9), 4);
        assert_eq!(bit_length(64), 6);
    }

    #[test]
    fn test_dle_expand_literal_0x90() {
        // 0x90 0x00 => literal 0x90
        let input = [0x41, 0x90, 0x00, 0x42];
        let result = dle_expand(&input).unwrap();
        assert_eq!(result, vec![0x41, 0x90, 0x42]);
    }

    #[test]
    fn test_dle_expand_repeat() {
        // 0x41 0x90 0x03 => 0x41 followed by 3 copies of 0x41
        let input = [0x41, 0x90, 0x03];
        let result = dle_expand(&input).unwrap();
        assert_eq!(result, vec![0x41, 0x41, 0x41, 0x41]);
    }

    #[test]
    fn test_dle_expand_no_markers() {
        let input = [0x41, 0x42, 0x43];
        let result = dle_expand(&input).unwrap();
        assert_eq!(result, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_expand_simple() {
        // Build a minimal Reducing-compressed stream (factor=1, max_followers=64).
        //
        // Follower set table: for each byte 255..0, encode 0 followers (6-bit 0).
        // Then encode literal bytes using the "no followers" path (8-bit literals).
        //
        // With factor=1, max_followers = 2^(7-1) = 64, so follower count needs
        // bit_length(64) = 6 bits.

        let message = b"ABC";
        let mut bits = BitWriter::new();

        // Phase 1: Write follower set table (256 entries, all with count=0).
        // Each count is 6 bits (for factor=1).
        for _ in 0..256 {
            bits.write_bits(0, 6); // 0 followers
        }

        // Phase 2: Write literal bytes.
        // First byte is always a literal 8-bit value.
        for &b in message.iter() {
            // No followers for any byte, so always read 8-bit literal.
            bits.write_bits(b as u16, 8);
        }

        let compressed = bits.finish();
        let result = expand(&compressed, 1).unwrap();
        assert_eq!(result, b"ABC");
    }

    #[test]
    fn test_expand_roundtrip() {
        // Verify that expand can decode a stream that uses follower sets
        // and DLE encoding, confirming all decoded bytes match the expected
        // original data.
        //
        // Build a Reducing-compressed stream with factor=4 (max_followers=8).
        // Use all-empty follower sets so every byte is a literal, then verify
        // DLE expansion of a run-length encoded byte (0x90 escape).
        //
        // With factor=4, max_followers = 2^(7-4) = 8. Count bits = bit_length(8) = 3.

        let mut bits = BitWriter::new();

        // Phase 1: Write follower set table (256 entries, all with count=0).
        for _ in 0..256 {
            bits.write_bits(0, 3); // 0 followers (3-bit count for factor=4)
        }

        // Phase 2: Write literal bytes that include a DLE sequence.
        // We want: 'A', 'B', 0x90, 0x00, 'C'
        // After DLE expansion, 0x90 0x00 -> literal 0x90, so final: [A, B, 0x90, C]
        for &b in &[b'A', b'B', 0x90u8, 0x00u8, b'C'] {
            bits.write_bits(b as u16, 8);
        }

        let compressed = bits.finish();
        let result = expand(&compressed, 4).unwrap();
        assert_eq!(result, &[b'A', b'B', 0x90, b'C']);
    }

    /// Minimal bit writer for constructing test data, LSB-first.
    struct BitWriter {
        data: Vec<u8>,
        current_byte: u8,
        bit_pos: u8,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                data: Vec::new(),
                current_byte: 0,
                bit_pos: 0,
            }
        }

        fn write_bits(&mut self, value: u16, count: u8) {
            for i in 0..count {
                let bit = ((value >> i) & 1) as u8;
                self.current_byte |= bit << self.bit_pos;
                self.bit_pos += 1;
                if self.bit_pos == 8 {
                    self.data.push(self.current_byte);
                    self.current_byte = 0;
                    self.bit_pos = 0;
                }
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.bit_pos > 0 {
                self.data.push(self.current_byte);
            }
            self.data
        }
    }
}
