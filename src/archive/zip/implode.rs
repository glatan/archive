//! ZIP Imploding (Method 6) decoder.
//!
//! Implements the Imploding decompression algorithm as described in APPNOTE §5.3.
//! Uses Shannon-Fano trees and a sliding dictionary for LZ77-style matches.
//!
//! General purpose bit flag controls:
//! - Bit 1: 8K sliding dictionary (set) or 4K (clear)
//! - Bit 2: 3 Shannon-Fano trees (set) or 2 trees (clear)

use alloc::vec::Vec;

use crate::error::Error;

/// Implode (decompress) data compressed with ZIP method 6.
///
/// `flags` is the general purpose bit flag from the ZIP entry header.
/// Bits 1-2 control the dictionary size and number of trees.
///
/// `expected_size` is the uncompressed size from the ZIP entry header, used
/// to know when decompression is complete (the bitstream may have padding bits
/// in the final byte that must not be decoded as additional tokens).
pub(super) fn implode(input: &[u8], flags: u16, expected_size: usize) -> Result<Vec<u8>, Error> {
    let large_dict = (flags & 0x0002) != 0; // bit 1: 8K dict
    let has_literal_tree = (flags & 0x0004) != 0; // bit 2: 3 trees

    let dict_bits: u8 = if large_dict { 7 } else { 6 }; // extra distance bits: 7 for 8K, 6 for 4K
    let min_match_length: usize = if has_literal_tree { 3 } else { 2 };

    let mut reader = BitReader::new(input);

    // Read Shannon-Fano trees.
    let literal_tree = if has_literal_tree {
        Some(read_shannon_fano_tree(&mut reader)?)
    } else {
        None
    };
    let length_tree = read_shannon_fano_tree(&mut reader)?;
    let distance_tree = read_shannon_fano_tree(&mut reader)?;

    let mut output = Vec::with_capacity(expected_size);

    loop {
        if output.len() >= expected_size || reader.is_exhausted() {
            break;
        }

        // Read one bit to decide literal vs match.
        let bit = match reader.try_read_bits(1) {
            Some(v) => v,
            None => break,
        };

        if has_literal_tree && bit == 0 {
            // Literal byte: decode from literal tree.
            let byte = match decode_symbol(&mut reader, literal_tree.as_ref().unwrap()) {
                Ok(v) => v,
                Err(_) => break,
            };
            output.push(byte as u8);
        } else if !has_literal_tree && bit == 0 {
            // Literal byte: read 8 bits directly.
            let byte = match reader.try_read_bits(8) {
                Some(v) => v,
                None => break,
            };
            output.push(byte as u8);
        } else {
            // Length/distance match.
            // Read low distance bits (dict_bits bits).
            let low_dist = match reader.try_read_bits(dict_bits) {
                Some(v) => v as usize,
                None => break,
            };

            // Read high distance bits from distance tree.
            let high_dist = match decode_symbol(&mut reader, &distance_tree) {
                Ok(v) => v as usize,
                Err(_) => break,
            };

            let distance = (high_dist << dict_bits) | low_dist;
            // distance is 0-based offset back from current position.
            let distance = distance + 1; // convert to 1-based

            // Read length from length tree.
            let length_code = match decode_symbol(&mut reader, &length_tree) {
                Ok(v) => v as usize,
                Err(_) => break,
            };

            let length = length_code + min_match_length;

            // If length_code == 63, read an additional 8-bit value and add it.
            let length = if length_code == 63 {
                let extra = match reader.try_read_bits(8) {
                    Some(v) => v as usize,
                    None => break,
                };
                length + extra
            } else {
                length
            };

            if distance > output.len() {
                return Err(Error::InvalidData(
                    "zip implode: back-reference distance exceeds output",
                ));
            }

            // Copy from sliding window.
            let start = output.len() - distance;
            for i in 0..length {
                let byte = output[start + (i % distance)];
                output.push(byte);
            }
        }
    }

    Ok(output)
}

/// A Shannon-Fano decoding tree node.
#[derive(Debug, Clone)]
enum SfNode {
    Leaf(u16),
    Internal {
        left: Box<SfNode>,  // bit 0
        right: Box<SfNode>, // bit 1
    },
}

/// Read a Shannon-Fano tree from the bitstream.
///
/// Format (APPNOTE §5.3):
/// - 1 byte: number of values minus 1 (so 0 means 1 value, 255 means 256)
/// - For each value: 1 byte = (value << 4) | (bit_length - 1)
///   Actually the format per the original PKZIP source is:
///   - low 4 bits: bit length minus 1
///   - high 4 bits are NOT the value; values are ordered
///
/// The actual format per APPNOTE/PKZIP implementation:
/// - First byte: number of code length entries - 1
/// - Each entry: 1 byte where low 4 bits = bit_length-1, high 4 bits = (not used for value)
///
/// However, the standard format from the actual PKZIP implementation is:
/// - Read number of entries - 1
/// - For each entry: read bit_length (low 4 bits + 1), the values are 0..n_entries-1
///   arranged by code length using Shannon-Fano assignment.
fn read_shannon_fano_tree(reader: &mut BitReader<'_>) -> Result<SfNode, Error> {
    let n_entries = reader.read_bits(8)? as usize + 1;

    // Read code lengths for each value.
    let mut entries: Vec<(u16, u8)> = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let byte = reader.read_bits(8)? as u8;
        let code_len = (byte & 0x0F) + 1; // low 4 bits + 1
        entries.push((i as u16, code_len));
    }

    // Build Shannon-Fano tree: sort by code length, then assign codes.
    // Sort by code length (stable sort preserves value order within same length).
    entries.sort_by_key(|&(_, len)| len);

    if entries.is_empty() {
        return Err(Error::InvalidData("zip implode: empty Shannon-Fano tree"));
    }

    // Assign canonical codes (similar to canonical Huffman).
    let mut code: u32 = 0;
    let mut prev_len: u8 = entries[0].1;

    let mut code_assignments: Vec<(u16, u8, u32)> = Vec::with_capacity(entries.len());

    for &(value, len) in &entries {
        if len > prev_len {
            code <<= len - prev_len;
        }
        code_assignments.push((value, len, code));
        code += 1;
        prev_len = len;
    }

    // Build tree from the code assignments.
    let max_len = entries
        .last()
        .ok_or(Error::InvalidData("implode: empty code table"))?
        .1;
    build_tree_from_codes(&code_assignments, max_len)
}

/// Build a binary tree from (value, bit_length, code) triples.
fn build_tree_from_codes(codes: &[(u16, u8, u32)], max_len: u8) -> Result<SfNode, Error> {
    // Build tree by inserting each code.
    // Even single-entry trees must have the proper depth so that
    // decode_symbol consumes the correct number of bits.
    let mut root = build_empty_tree(max_len);

    for &(value, len, code) in codes {
        insert_code(&mut root, value, len, code)?;
    }

    Ok(root)
}

/// Build an empty tree of the given maximum depth.
fn build_empty_tree(depth: u8) -> SfNode {
    if depth == 0 {
        SfNode::Leaf(u16::MAX) // placeholder
    } else {
        SfNode::Internal {
            left: Box::new(build_empty_tree(depth - 1)),
            right: Box::new(build_empty_tree(depth - 1)),
        }
    }
}

/// Insert a code into the tree.
fn insert_code(node: &mut SfNode, value: u16, len: u8, code: u32) -> Result<(), Error> {
    if len == 0 {
        *node = SfNode::Leaf(value);
        return Ok(());
    }

    match node {
        SfNode::Leaf(_) => {
            // Need to convert to internal node.
            *node = SfNode::Internal {
                left: Box::new(SfNode::Leaf(u16::MAX)),
                right: Box::new(SfNode::Leaf(u16::MAX)),
            };
            insert_code(node, value, len, code)
        }
        SfNode::Internal { left, right } => {
            // Shannon-Fano codes are read MSB first from the bitstream.
            // The bit we check is the (len-1)th bit of the code.
            let bit = (code >> (len - 1)) & 1;
            if bit == 0 {
                insert_code(left, value, len - 1, code)
            } else {
                insert_code(right, value, len - 1, code)
            }
        }
    }
}

/// Decode a symbol from the bitstream using the given Shannon-Fano tree.
///
/// Bits are read one at a time: 0 goes left, 1 goes right.
fn decode_symbol(reader: &mut BitReader<'_>, tree: &SfNode) -> Result<u16, Error> {
    let mut node = tree;
    loop {
        match node {
            SfNode::Leaf(value) => {
                if *value == u16::MAX {
                    return Err(Error::InvalidData(
                        "zip implode: invalid code in Shannon-Fano tree",
                    ));
                }
                return Ok(*value);
            }
            SfNode::Internal { left, right } => {
                let bit = reader.read_bits(1)?;
                node = if bit == 0 {
                    left.as_ref()
                } else {
                    right.as_ref()
                };
            }
        }
    }
}

/// Bitstream reader that reads bits LSB-first from a byte slice.
struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
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

    fn read_bits(&mut self, count: u8) -> Result<u16, Error> {
        self.try_read_bits(count).ok_or(Error::UnexpectedEof)
    }

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

    #[test]
    fn test_implode_roundtrip() {
        // Verify that implode can decode a stream containing both literals
        // and a back-reference, confirming the decompressed data matches
        // the expected original.
        //
        // Encode "ABCABC" as: literals 'A','B','C' + match(dist=3, len=3).
        // flags = 0x0000 (4K dict, 2 trees).
        // dict_bits = 6, min_match_length = 2.

        let flags: u16 = 0x0000;

        let mut bits = BitWriter::new();

        // Length tree: 2 entries. Value 0 (len=0+2=2), value 1 (len=1+2=3).
        bits.write_bits(1, 8); // n_entries - 1 = 1
        bits.write_bits(0, 8); // entry 0: code_len=1
        bits.write_bits(0, 8); // entry 1: code_len=1

        // Distance tree: 1 entry.
        bits.write_bits(0, 8); // n_entries - 1 = 0
        bits.write_bits(0, 8); // entry: code_len=1

        // Literal 'A' (0x41)
        bits.write_bits(0, 1); // literal flag
        bits.write_bits(0x41, 8);

        // Literal 'B' (0x42)
        bits.write_bits(0, 1);
        bits.write_bits(0x42, 8);

        // Literal 'C' (0x43)
        bits.write_bits(0, 1);
        bits.write_bits(0x43, 8);

        // Match: bit=1 (match flag), distance=3 (back 3 bytes to 'A'), length=3.
        bits.write_bits(1, 1);
        // Low distance bits (6 bits): distance-1=2, low 6 bits = 2.
        bits.write_bits(2, 6);
        // High distance from distance tree: value 0, code = 0 (1 bit).
        bits.write_bits(0, 1);
        // Length from length tree: want length_code=1 (length = 1 + 2 = 3).
        bits.write_bits(1, 1); // code 1 => value 1 => length = 3

        let compressed = bits.finish();
        let result = implode(&compressed, flags, 6).unwrap();
        assert_eq!(result, b"ABCABC");
    }

    #[test]
    fn test_implode_simple() {
        // Build a minimal Imploding-compressed stream.
        // Use: no literal tree (2 trees), 4K dictionary (bit 1 clear, bit 2 clear).
        // flags = 0x0000.
        // dict_bits = 6, min_match_length = 2.
        //
        // We will encode 3 literal bytes: 'H', 'i', '!'
        // Each literal: bit 0 (literal marker) + 8-bit value.

        let flags: u16 = 0x0000; // 4K dict, 2 trees

        let mut bits = BitWriter::new();

        // Write length tree (must have at least 1 entry).
        // We encode 1 entry (n_entries - 1 = 0), value 0, code length 1.
        bits.write_bits(0, 8); // n_entries - 1 = 0
        bits.write_bits(0, 8); // entry: code_len-1=0, high bits=0 => code_len=1

        // Write distance tree (1 entry).
        bits.write_bits(0, 8); // n_entries - 1 = 0
        bits.write_bits(0, 8); // entry: code_len=1

        // Encode literals: bit=0 means literal, then 8-bit value.
        for &byte in b"Hi!" {
            bits.write_bits(0, 1); // literal flag
            bits.write_bits(byte as u16, 8); // byte value
        }

        let compressed = bits.finish();
        let result = implode(&compressed, flags, 3).unwrap();
        assert_eq!(result, b"Hi!");
    }

    #[test]
    fn test_implode_with_literal_tree() {
        // Use 3 trees (bit 2 set), 4K dictionary (bit 1 clear).
        // flags = 0x0004.
        // dict_bits = 6, min_match_length = 3.
        //
        // We will use a trivial literal tree with 1 entry (value 0, code len 1).
        // But that means we can only decode value 0 as the literal.
        // Let's instead encode a single literal NUL byte.

        let flags: u16 = 0x0004; // 4K dict, 3 trees

        let mut bits = BitWriter::new();

        // Write literal tree: 1 entry (value 0, code_len=1).
        bits.write_bits(0, 8); // n_entries - 1 = 0
        bits.write_bits(0, 8); // code_len=1

        // Write length tree: 1 entry.
        bits.write_bits(0, 8);
        bits.write_bits(0, 8);

        // Write distance tree: 1 entry.
        bits.write_bits(0, 8);
        bits.write_bits(0, 8);

        // Encode literal: bit=0 means literal (from literal tree).
        // Literal tree has only value 0 with code 0 (length 1).
        bits.write_bits(0, 1); // literal flag
        bits.write_bits(0, 1); // code 0 from literal tree => value 0

        let compressed = bits.finish();
        let result = implode(&compressed, flags, 1).unwrap();
        assert_eq!(result, vec![0u8]);
    }

    #[test]
    fn test_implode_back_reference() {
        // Test a back-reference. Encode "AAAA" as literal 'A' + match(dist=1, len=3).
        // flags = 0x0000 (4K dict, 2 trees).
        // dict_bits = 6, min_match_length = 2.

        let flags: u16 = 0x0000;

        let mut bits = BitWriter::new();

        // Length tree: 2 entries. Value 0 (len=2), value 1 (len=3).
        // Both get code_len=1.
        bits.write_bits(1, 8); // n_entries - 1 = 1
        bits.write_bits(0, 8); // entry 0: code_len=1
        bits.write_bits(0, 8); // entry 1: code_len=1

        // Distance tree: 1 entry.
        bits.write_bits(0, 8); // n_entries - 1 = 0
        bits.write_bits(0, 8); // entry: code_len=1

        // Literal 'A' (0x41).
        bits.write_bits(0, 1); // literal flag
        bits.write_bits(0x41, 8);

        // Match: bit=1 (match flag).
        bits.write_bits(1, 1);
        // Low distance bits (6 bits for 4K dict): distance-1 = 0, so low 6 bits = 0.
        bits.write_bits(0, 6);
        // High distance from distance tree: value 0, code = 0 (1 bit).
        bits.write_bits(0, 1);
        // Length from length tree: we want length_code=1 (which gives length=1+2=3).
        // Tree: value 0 has code 0 (len 1), value 1 has code 1 (len 1).
        bits.write_bits(1, 1); // code 1 => value 1 => length = 1 + 2 = 3

        let compressed = bits.finish();
        let result = implode(&compressed, flags, 4).unwrap();
        // 'A' + match(dist=1, len=3) = "AAAA"
        assert_eq!(result, b"AAAA");
    }
}
