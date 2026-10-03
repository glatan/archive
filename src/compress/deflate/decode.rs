//! DEFLATE decompression (inflate) per [RFC 1951].
//!
//! [RFC 1951]: https://datatracker.ietf.org/doc/html/rfc1951

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::bitreader::BitReader;

use super::tables::*;

const MAX_BITS: u8 = 15;

/// Huffman lookup table entry: (symbol, code_length).
/// Built with reversed bit codes for direct LSB-first lookup.
#[derive(Debug, Clone)]
struct HuffmanTable {
    entries: Vec<(u16, u8)>,
    max_bits: u8,
}

impl HuffmanTable {
    /// Build a Huffman lookup table from code lengths.
    ///
    /// `code_lengths[i]` is the code length for symbol `i`. A length of 0 means
    /// the symbol is not used.
    fn from_lengths(code_lengths: &[u8]) -> Result<Self, Error> {
        let max_bits = *code_lengths.iter().max().unwrap_or(&0);
        if max_bits == 0 {
            return Ok(Self {
                entries: Vec::new(),
                max_bits: 0,
            });
        }
        if max_bits > MAX_BITS {
            return Err(Error::InvalidData("Huffman code length exceeds 15"));
        }

        // Step 1: Count codes of each length
        let mut bl_count = [0u32; (MAX_BITS + 1) as usize];
        for &len in code_lengths {
            bl_count[len as usize] += 1;
        }
        bl_count[0] = 0;

        // Step 2: Reject over-subscribed trees (RFC 1951 section 3.2.2).
        // The remaining code space starts at 1, doubles for each bit
        // depth, and shrinks by the number of codes assigned at that
        // depth. A negative value means the lengths violate the Kraft
        // inequality (sum of 2^-len > 1), i.e. the tree is over-subscribed
        // and cannot be decoded unambiguously.
        //
        // Incomplete trees (positive code space left over) are
        // intentionally still accepted here: a single-code or empty
        // distance tree is legal per RFC 1951 section 3.2.7, and unused
        // code space is reported as an "invalid Huffman code" error only
        // if the stream actually references it.
        let mut left: i32 = 1;
        for bits in 1..=max_bits {
            left <<= 1;
            left -= bl_count[bits as usize] as i32;
            if left < 0 {
                return Err(Error::InvalidData("over-subscribed Huffman code"));
            }
        }

        // Step 3: Find the numerical value of the smallest code for each code length
        let mut next_code = [0u32; (MAX_BITS + 1) as usize];
        let mut code = 0u32;
        for bits in 1..=max_bits {
            code = (code + bl_count[(bits - 1) as usize]) << 1;
            next_code[bits as usize] = code;
        }

        // Step 4: Assign numerical values to all codes, then build lookup table
        let table_size = 1usize << max_bits;
        let mut entries = vec![(0u16, 0u8); table_size];

        for (symbol, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;

            // Reverse the bits for LSB-first lookup
            let reversed = reverse_bits(code, len);

            // Fill all table entries where the lower `len` bits match `reversed`
            let step = 1usize << len;
            let mut idx = reversed as usize;
            while idx < table_size {
                entries[idx] = (symbol as u16, len);
                idx += step;
            }
        }

        Ok(Self { entries, max_bits })
    }

    /// Decode one symbol from the bit stream.
    fn decode(&self, reader: &mut BitReader) -> Result<u16, Error> {
        if self.entries.is_empty() {
            return Err(Error::InvalidData("empty Huffman table"));
        }
        let bits = reader.peek_bits(self.max_bits)? as usize;
        let (symbol, len) = self.entries[bits];
        if len == 0 {
            return Err(Error::InvalidData("invalid Huffman code"));
        }
        reader.consume(len);
        Ok(symbol)
    }
}

/// Reverse `num_bits` bits of `value`.
fn reverse_bits(value: u32, num_bits: u8) -> u32 {
    let mut result = 0;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    result
}

/// Decode a DEFLATE compressed stream.
///
/// Takes raw DEFLATE data (no gzip/zlib header) and returns the decompressed bytes.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::deflate::{encode, decode};
///
/// let compressed = encode::encode(b"Hello!", encode::Level::Fast);
/// let data = decode::decode(&compressed).unwrap();
/// assert_eq!(data, b"Hello!");
/// ```
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] if the input is truncated, [`Error::InvalidData`]
/// if the stream is malformed.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = BitReader::new(input);
    let mut output = Vec::new();
    decode_stream(&mut reader, &mut output)?;
    Ok(output)
}

/// Decode DEFLATE blocks from `reader` until a BFINAL block completes,
/// appending to `output`.
///
/// Used by container formats that embed a self-terminating DEFLATE
/// stream (e.g. git pack objects): the caller can read the true
/// consumed byte count afterwards via `reader.byte_position()`.
pub(crate) fn decode_stream(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), Error> {
    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0b00 => decode_uncompressed(reader, output)?,
            0b01 => decode_fixed_huffman(reader, output)?,
            0b10 => decode_dynamic_huffman(reader, output)?,
            _ => return Err(Error::InvalidData("invalid DEFLATE block type 11")),
        }

        if bfinal == 1 {
            break;
        }
    }
    Ok(())
}

/// Decode DEFLATE data with a preset dictionary.
///
/// The dictionary is pre-seeded into the output buffer so that back-references
/// can reach into it. The dictionary bytes are stripped from the returned result.
pub(crate) fn decode_with_dict(input: &[u8], dict: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = BitReader::new(input);
    let mut output = Vec::from(dict);

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0b00 => decode_uncompressed(&mut reader, &mut output)?,
            0b01 => decode_fixed_huffman(&mut reader, &mut output)?,
            0b10 => decode_dynamic_huffman(&mut reader, &mut output)?,
            _ => return Err(Error::InvalidData("invalid DEFLATE block type 11")),
        }

        if bfinal == 1 {
            break;
        }
    }

    // Strip the pre-seeded dictionary from the beginning
    Ok(output[dict.len()..].to_vec())
}

/// Decode a non-compressed block (BTYPE=00).
fn decode_uncompressed(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), Error> {
    reader.align_to_byte();
    let len = reader.read_u16_le()?;
    let nlen = reader.read_u16_le()?;
    if len != !nlen {
        return Err(Error::InvalidData("stored block LEN/NLEN mismatch"));
    }
    let data = reader.read_bytes(len as usize)?;
    output.extend_from_slice(data);
    Ok(())
}

/// Decode a block with fixed Huffman codes (BTYPE=01).
fn decode_fixed_huffman(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), Error> {
    let lit_table = HuffmanTable::from_lengths(&fixed_literal_lengths())?;
    let dist_table = HuffmanTable::from_lengths(&fixed_distance_lengths())?;
    decode_huffman_block(reader, &lit_table, &dist_table, output)
}

/// Decode a block with dynamic Huffman codes (BTYPE=10).
fn decode_dynamic_huffman(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), Error> {
    let hlit = reader.read_bits(5)? as usize + 257;
    let hdist = reader.read_bits(5)? as usize + 1;
    let hclen = reader.read_bits(4)? as usize + 4;

    if hlit > 286 {
        return Err(Error::InvalidData("HLIT exceeds maximum (286)"));
    }
    if hdist > 30 {
        return Err(Error::InvalidData("HDIST exceeds maximum (30)"));
    }

    // Read code length alphabet code lengths
    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CODE_LENGTH_ORDER[i]] = reader.read_bits(3)? as u8;
    }

    let cl_table = HuffmanTable::from_lengths(&cl_lengths)?;

    // Decode literal/length and distance code lengths
    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = cl_table.decode(reader)?;
        match sym {
            0..=15 => {
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                // Repeat previous length 3-6 times
                if i == 0 {
                    return Err(Error::InvalidData("code length repeat with no previous"));
                }
                let repeat = reader.read_bits(2)? as usize + 3;
                let prev = lengths[i - 1];
                for _ in 0..repeat {
                    if i >= total {
                        return Err(Error::InvalidData("code length repeat overflow"));
                    }
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                // Repeat 0 for 3-10 times
                let repeat = reader.read_bits(3)? as usize + 3;
                i += repeat;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            18 => {
                // Repeat 0 for 11-138 times
                let repeat = reader.read_bits(7)? as usize + 11;
                i += repeat;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            _ => return Err(Error::InvalidData("invalid code length symbol")),
        }
    }

    // RFC 1951 §3.2.7: The literal/length alphabet must include the end-of-block symbol (256).
    // Since hlit >= 257, symbol 256 is always within the lit/len range.
    if lengths[256] == 0 {
        return Err(Error::InvalidData(
            "dynamic Huffman: missing end-of-block symbol (256)",
        ));
    }

    let lit_table = HuffmanTable::from_lengths(&lengths[..hlit])?;
    let dist_table = HuffmanTable::from_lengths(&lengths[hlit..hlit + hdist])?;
    decode_huffman_block(reader, &lit_table, &dist_table, output)
}

/// Core Huffman block decode loop (shared by fixed and dynamic).
fn decode_huffman_block(
    reader: &mut BitReader,
    lit_table: &HuffmanTable,
    dist_table: &HuffmanTable,
    output: &mut Vec<u8>,
) -> Result<(), Error> {
    loop {
        let symbol = lit_table.decode(reader)?;
        match symbol {
            0..=255 => {
                // Literal byte
                output.push(symbol as u8);
            }
            256 => {
                // End of block
                return Ok(());
            }
            257..=285 => {
                // Length/distance pair
                let len_idx = (symbol - 257) as usize;
                if len_idx >= LENGTH_BASE.len() {
                    return Err(Error::InvalidData("invalid length code"));
                }
                let length = LENGTH_BASE[len_idx] as usize
                    + reader.read_bits(LENGTH_EXTRA[len_idx])? as usize;

                let dist_sym = dist_table.decode(reader)? as usize;
                if dist_sym >= DISTANCE_BASE.len() {
                    return Err(Error::InvalidData("invalid distance code"));
                }
                let distance = DISTANCE_BASE[dist_sym] as usize
                    + reader.read_bits(DISTANCE_EXTRA[dist_sym])? as usize;

                if distance > output.len() {
                    return Err(Error::InvalidData("distance too far back"));
                }

                // Copy from sliding window - byte-by-byte to handle overlapping copies
                let start = output.len() - distance;
                for i in 0..length {
                    let byte = output[start + i];
                    output.push(byte);
                }
            }
            _ => return Err(Error::InvalidData("invalid literal/length symbol")),
        }
    }
}

/// Decode DEFLATE compressed data from a [`std::io::Read`] source.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if reading from the source fails, or if the data is malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::deflate::{encode, decode};
///
/// let compressed = encode::encode(b"data", encode::Level::Fast);
/// let data = decode::decode_reader(compressed.as_slice()).unwrap();
/// assert_eq!(data, b"data");
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> Result<Vec<u8>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

/// Decode with a maximum output size limit.
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

    #[test]
    fn test_decode_uncompressed() {
        // BFINAL=1, BTYPE=00 (uncompressed), LEN=5, NLEN=!5, "hello"
        let mut data = Vec::new();
        data.push(0b0000_0001); // BFINAL=1, BTYPE=00
        data.extend_from_slice(&5u16.to_le_bytes()); // LEN
        data.extend_from_slice(&(!5u16).to_le_bytes()); // NLEN
        data.extend_from_slice(b"hello");

        let result = decode(&data).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_huffman_table_build() {
        // Simple table: symbol 0 = length 1, symbol 1 = length 1
        let table = HuffmanTable::from_lengths(&[1, 1]).unwrap();
        assert_eq!(table.max_bits, 1);
    }

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0b110, 3), 0b011);
        assert_eq!(reverse_bits(0b1010, 4), 0b0101);
        assert_eq!(reverse_bits(0b1, 1), 0b1);
    }

    #[test]
    fn test_fixed_huffman_lengths() {
        let lengths = fixed_literal_lengths();
        assert_eq!(lengths[0], 8);
        assert_eq!(lengths[143], 8);
        assert_eq!(lengths[144], 9);
        assert_eq!(lengths[255], 9);
        assert_eq!(lengths[256], 7);
        assert_eq!(lengths[279], 7);
        assert_eq!(lengths[280], 8);
        assert_eq!(lengths[287], 8);
    }

    // Phase 1: Error detection tests

    #[test]
    fn test_empty_input() {
        let result = decode(&[]);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_invalid_btype_11() {
        // BFINAL=1, BTYPE=11 (reserved/invalid)
        // bits LSB-first: BFINAL=1, BTYPE=11 → value 0b111 = 0x07
        let data = [0x07];
        let result = decode(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_stored_len_nlen_mismatch() {
        let mut data = Vec::new();
        data.push(0b0000_0001); // BFINAL=1, BTYPE=00
        data.extend_from_slice(&5u16.to_le_bytes()); // LEN=5
        data.extend_from_slice(&(!6u16).to_le_bytes()); // NLEN=!6 (mismatch with LEN=5)
        data.extend_from_slice(b"hello");
        let result = decode(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_distance_too_far_back() {
        // Manually constructed fixed Huffman block:
        // BFINAL=1, BTYPE=01 (fixed), literal 'a', length=3 (code 257), distance=10 (code 6 + extra=1)
        // After only 1 byte in output, distance=10 > 1 → error
        //
        // Byte construction verified by tracing through BitWriter and BitReader operations:
        // byte 0: 0x4B = BFINAL(1) + BTYPE(01) + literal 'a' (first 5 bits)
        // byte 1: 0x04 = literal 'a' (remaining 3 bits) + length 257 (first 5 bits)
        // byte 2: 0xB2 = length 257 (remaining 2 bits) + dist code 6 (5 bits) + extra (1 bit)
        // byte 3: 0x00 = extra (remaining 1 bit) + padding
        let data = [0x4B, 0x04, 0xB2, 0x00];
        let result = decode(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_fixed_huffman_direct() {
        // Minimal fixed-Huffman block that decodes to "A".
        //
        // RFC 1951 §3.2.6 fixed literal/length codes:
        //   symbol 65 ('A')  -> 8-bit code 0b01110001
        //   symbol 256 (EOB) -> 7-bit code 0b0000000
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01 (fixed Huffman)
        w.write_huffman(0b0111_0001, 8); // literal 'A'
        w.write_huffman(0b000_0000, 7); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_fixed_huffman_overlap_copy_direct() {
        // Minimal fixed-Huffman block that emits one literal and then an
        // overlapping back-reference (distance=1, length=4).
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01 (fixed Huffman)
        w.write_huffman(0b0111_0001, 8); // literal 'A' (symbol 65)
        w.write_huffman(0b000_0010, 7); // length symbol 258 => len 4
        w.write_huffman(0b00000, 5); // distance symbol 0 => dist 1
        w.write_huffman(0b000_0000, 7); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"AAAAA");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_cross_block_back_reference_direct() {
        let mut data = Vec::new();

        // Block 1: stored, non-final, emits "AB".
        data.push(0x00);
        let len1 = 2u16;
        data.extend_from_slice(&len1.to_le_bytes());
        data.extend_from_slice(&(!len1).to_le_bytes());
        data.extend_from_slice(b"AB");

        // Block 2: fixed Huffman, final, emits len=4 dist=2 referencing across blocks.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01
        w.write_huffman(0b000_0010, 7); // length symbol 258 => len 4
        w.write_huffman(0b00001, 5); // distance symbol 1 => dist 2
        w.write_huffman(0b000_0000, 7); // EOB
        data.extend_from_slice(&w.finish());

        let result = decode(&data).unwrap();
        assert_eq!(result, b"ABABAB");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader() {
        use crate::compress::deflate::encode;
        let input = b"Hello, deflate!";
        let encoded = encode::encode(input, encode::Level::Fast);
        let cursor = std::io::Cursor::new(&encoded);
        let decoded = decode_reader(cursor).unwrap();
        assert_eq!(decoded, input);
    }

    // Phase 2: Spec value tests

    /// Helper: LSB-first bit writer for constructing test streams.
    struct TestBitWriter {
        data: Vec<u8>,
        bit_buf: u32,
        bit_count: u8,
    }

    impl TestBitWriter {
        fn new() -> Self {
            Self {
                data: Vec::new(),
                bit_buf: 0,
                bit_count: 0,
            }
        }

        /// Write `n` bits, value given LSB-first (lowest bit written first).
        fn write_bits(&mut self, value: u32, n: u8) {
            self.bit_buf |= value << self.bit_count;
            self.bit_count += n;
            while self.bit_count >= 8 {
                self.data.push(self.bit_buf as u8);
                self.bit_buf >>= 8;
                self.bit_count -= 8;
            }
        }

        /// Write `n` bits of a Huffman code (MSB-first in spec → reverse for LSB-first packing).
        fn write_huffman(&mut self, code: u32, n: u8) {
            let reversed = super::reverse_bits(code, n);
            self.write_bits(reversed, n);
        }

        fn finish(mut self) -> Vec<u8> {
            if self.bit_count > 0 {
                self.data.push(self.bit_buf as u8);
            }
            self.data
        }
    }

    #[test]
    fn test_dynamic_huffman_direct() {
        // Construct a minimal DEFLATE stream with BTYPE=10 (dynamic Huffman)
        // that encodes the string "A".
        //
        // Lit/len alphabet: symbol 65 ('A') = code length 1, symbol 256 (EOB) = code length 1.
        // Distance alphabet: distance code 0 = code length 1 (required but unused).
        //
        // Code length alphabet uses 3 symbols:
        //   code 17 (repeat 0 for 3-10): Huffman length 1 → MSB code "0"
        //   code 18 (repeat 0 for 11-138): Huffman length 2 → MSB code "10"
        //   code  1 (literal code length): Huffman length 2 → MSB code "11"

        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes (symbols 0..=256)
        w.write_bits(0, 5);
        // HDIST = 0 → 1 distance code
        w.write_bits(0, 5);
        // HCLEN = 14 → 18 code length codes
        w.write_bits(14, 4);

        // Code length code lengths, 3 bits each, in CODE_LENGTH_ORDER:
        // [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        // We set:
        //   index 1 (code 17) = 1
        //   index 2 (code 18) = 2
        //   index 17 (code 1) = 2
        //   all others = 0
        // HCLEN=14 means we write 18 entries (indices 0..17).
        let cl_code_lengths: [u8; 18] = [
            0, // index 0: code 16
            1, // index 1: code 17
            2, // index 2: code 18
            0, // index 3: code 0
            0, // index 4: code 8
            0, // index 5: code 7
            0, // index 6: code 9
            0, // index 7: code 6
            0, // index 8: code 10
            0, // index 9: code 5
            0, // index 10: code 11
            0, // index 11: code 4
            0, // index 12: code 12
            0, // index 13: code 3
            0, // index 14: code 13
            0, // index 15: code 2
            0, // index 16: code 14
            2, // index 17: code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Canonical Huffman codes for the code length alphabet:
        //   code 17: length 1 → canonical MSB code 0b0
        //   code 18: length 2 → canonical MSB code 0b10
        //   code  1: length 2 → canonical MSB code 0b11
        //
        // Verification: sorted by (length, symbol):
        //   (1, 17) → code 0 (1 bit)
        //   (2, 1)  → code 10 (2 bits)
        //   (2, 18) → code 11 (2 bits)

        // Now encode lit/len code lengths (257 symbols, 0..=256):
        // symbols 0-64: 65 zeros
        //   → code 18 (repeat 0 for 11-138), count=65, extra = 65-11 = 54 (7 bits)
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra bits for count 65

        // symbol 65 ('A'): code length 1
        //   → code length code 1 (literal value 1)
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 66-255: 190 zeros
        //   → code 18 (count=138, extra=127) + code 18 (count=52, extra=41)
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra for count 138

        w.write_huffman(0b11, 2); // code 18
        w.write_bits(41, 7); // extra for count 52

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // Now encode distance code lengths (1 code):
        // distance code 0: code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // Lit/len Huffman tree (canonical, 2 symbols both length 1):
        //   symbol 65 ('A'): MSB code "0" → 1-bit code 0
        //   symbol 256 (EOB): MSB code "1" → 1-bit code 1
        //
        // Compressed data: 'A' then EOB
        w.write_huffman(0b0, 1); // 'A'
        w.write_huffman(0b1, 1); // EOB

        let deflate_stream = w.finish();

        // Decode and verify
        let result = decode(&deflate_stream).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_dynamic_huffman_direct_uses_repeat17() {
        // Same target payload as test_dynamic_huffman_direct, but the leading
        // zero run is split so code 17 (repeat zero for 3-10) is exercised.
        let mut w = TestBitWriter::new();

        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10
        w.write_bits(0, 5); // HLIT = 0 -> 257 lit/len codes
        w.write_bits(0, 5); // HDIST = 0 -> 1 distance code
        w.write_bits(14, 4); // HCLEN = 14 -> 18 code length codes

        let cl_code_lengths: [u8; 18] = [
            0, // code 16
            1, // code 17
            2, // code 18
            0, // code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // symbols 0-9: 10 zeros via code 17
        w.write_huffman(0b0, 1); // code 17
        w.write_bits(7, 3); // 10 - 3 = 7

        // symbols 10-64: 55 zeros via code 18
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(44, 7); // 55 - 11 = 44

        // symbol 65 ('A'): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 66-255: 190 zeros = 138 + 52
        w.write_huffman(0b11, 2);
        w.write_bits(127, 7);
        w.write_huffman(0b11, 2);
        w.write_bits(41, 7);

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b10, 2);

        // distance code 0: code length 1
        w.write_huffman(0b10, 2);

        w.write_huffman(0b0, 1); // 'A'
        w.write_huffman(0b1, 1); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_dynamic_huffman_direct_uses_repeat16() {
        // Build a valid dynamic tree where code 16 repeats the previous
        // non-zero code length three times.
        let mut w = TestBitWriter::new();

        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10
        w.write_bits(0, 5); // HLIT = 0 -> 257 lit/len codes
        w.write_bits(0, 5); // HDIST = 0 -> 1 distance code
        w.write_bits(14, 4); // HCLEN = 14 -> 18 code length codes

        let cl_code_lengths: [u8; 18] = [
            2, // code 16
            0, // code 17
            2, // code 18
            0, // code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // code 3
            0, 0, 0, 2, // code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Canonical codes among {1,3,16,18} all at length 2:
        // code1=00, code3=01, code16=10, code18=11.

        // symbols 0-64: 65 zeros
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // 65 - 11 = 54

        // symbol 65: code length 3
        w.write_huffman(0b01, 2); // CL code for "3"

        // symbols 66-68: repeat previous code length 3 times via code 16
        w.write_huffman(0b10, 2); // code 16
        w.write_bits(0, 2); // 3 repeats

        // symbols 69-255: 187 zeros = 138 + 49
        w.write_huffman(0b11, 2);
        w.write_bits(127, 7);
        w.write_huffman(0b11, 2);
        w.write_bits(38, 7); // 49 - 11 = 38

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b00, 2); // CL code for "1"

        // distance code 0: code length 1
        w.write_huffman(0b00, 2);

        // Lit/len codes: symbol 256 has len 1 => code 0. Symbols 65..68 have len 3.
        w.write_huffman(0b100, 3); // 'A' (symbol 65)
        w.write_huffman(0b0, 1); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_dynamic_huffman_all_literals_empty_dist_tree() {
        // RFC 1951 §3.2.7: a dynamic Huffman block whose distance code lengths
        // are all zero (empty distance tree) must be accepted as an
        // all-literals stream, as long as no length/distance pair is used.
        //
        // Same lit/len alphabet as test_dynamic_huffman_direct
        // ('A' = length 1, EOB = length 1), but HDIST=2 (3 distance codes)
        // with every distance code length set to 0 via code 17.
        //
        // Code length alphabet (same as test_dynamic_huffman_direct):
        //   code 17 (repeat 0 for 3-10):  Huffman length 1 → MSB code "0"
        //   code 18 (repeat 0 for 11-138): Huffman length 2 → MSB code "11"
        //   code  1 (literal code length): Huffman length 2 → MSB code "10"
        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes (symbols 0..=256)
        w.write_bits(0, 5);
        // HDIST = 2 → 3 distance codes
        w.write_bits(2, 5);
        // HCLEN = 14 → 18 code length codes
        w.write_bits(14, 4);

        // Code length code lengths, 3 bits each, in CODE_LENGTH_ORDER:
        // [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        let cl_code_lengths: [u8; 18] = [
            0, // index 0: code 16
            1, // index 1: code 17
            2, // index 2: code 18
            0, // index 3: code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // indices 4..16
            2, // index 17: code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Lit/len code lengths (257 symbols, 0..=256):
        // symbols 0-64: 65 zeros via code 18
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra: 65 - 11 = 54

        // symbol 65 ('A'): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 66-255: 190 zeros = 138 + 52
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra: 138 - 11 = 127
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(41, 7); // extra: 52 - 11 = 41

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // Distance code lengths (3 codes): all zero via code 17
        // (repeat 0 for 3 times, extra = 3 - 3 = 0). This produces an empty
        // distance Huffman table, which is legal per RFC 1951 §3.2.7 when the
        // stream contains no length/distance pairs.
        w.write_huffman(0b0, 1); // code 17
        w.write_bits(0, 3); // extra: 3 - 3 = 0

        // Lit/len Huffman tree (canonical, 2 symbols both length 1):
        //   symbol 65 ('A'): code "0";  symbol 256 (EOB): code "1"
        w.write_huffman(0b0, 1); // 'A'
        w.write_huffman(0b1, 1); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_dynamic_huffman_empty_dist_tree_rejects_match() {
        // Companion to test_dynamic_huffman_all_literals_empty_dist_tree:
        // an empty distance tree is only legal while unused. A stream that
        // emits a length/distance pair must be rejected.
        //
        // Lit/len alphabet: 'A' = length 2, EOB = length 1, sym 257 = length 2.
        // Distance codes (3): all lengths zero → empty distance table.
        //
        // Code length alphabet: symbols {1, 2, 17, 18} all Huffman length 2.
        // Canonical MSB codes: 1 → "00", 2 → "01", 17 → "10", 18 → "11".
        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 1 → 258 lit/len codes (symbols 0..=257)
        w.write_bits(1, 5);
        // HDIST = 2 → 3 distance codes
        w.write_bits(2, 5);
        // HCLEN = 14 → 18 code length codes
        w.write_bits(14, 4);

        // Code length code lengths in CODE_LENGTH_ORDER
        // [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]:
        //   code 17 = 2, code 18 = 2, code 2 = 2, code 1 = 2; all others 0.
        let cl_code_lengths: [u8; 18] = [
            0, // index 0: code 16
            2, // index 1: code 17
            2, // index 2: code 18
            0, // index 3: code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // indices 4..14
            2, // index 15: code 2
            0, // index 16: code 14
            2, // index 17: code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Lit/len code lengths (258 symbols, 0..=257):
        // symbols 0-64: 65 zeros via code 18
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra: 65 - 11 = 54

        // symbol 65 ('A'): code length 2
        w.write_huffman(0b01, 2); // CL code for "2"

        // symbols 66-255: 190 zeros = 138 + 52
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra: 138 - 11 = 127
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(41, 7); // extra: 52 - 11 = 41

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b00, 2); // CL code for "1"

        // symbol 257 (length 3): code length 2
        w.write_huffman(0b01, 2); // CL code for "2"

        // Distance code lengths (3 codes): all zero via code 17
        w.write_huffman(0b10, 2); // code 17
        w.write_bits(0, 3); // extra: 3 - 3 = 0

        // Lit/len canonical codes: EOB (len 1) → "0"; 'A' (len 2) → "10";
        // symbol 257 (len 2) → "11".
        w.write_huffman(0b10, 2); // literal 'A'
        w.write_huffman(0b11, 2); // length symbol 257 (len 3, 0 extra bits)
        // Decoder now attempts dist_table.decode() on the empty table.

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("empty Huffman table")),
            "expected InvalidData about empty Huffman table, got: {:?}",
            result
        );
    }

    #[test]
    fn test_huffman_rfc1951_example() {
        // RFC 1951 §3.2.2 example: bit lengths [3,3,3,3,3,2,4,4]
        // Expected codes (MSB-first): A=010, B=011, C=100, D=101, E=110, F=00, G=1110, H=1111
        let code_lengths: [u8; 8] = [3, 3, 3, 3, 3, 2, 4, 4];
        let table = HuffmanTable::from_lengths(&code_lengths).unwrap();
        assert_eq!(table.max_bits, 4);

        // Verify by encoding known codes and checking table lookup
        // Symbol F (5) has code 00 (2 bits), reversed = 00
        // In 4-bit table: entries at 0b0000, 0b0100, 0b1000, 0b1100 should all decode to (5, 2)
        assert_eq!(table.entries[0b0000], (5, 2));
        assert_eq!(table.entries[0b0100], (5, 2));
        assert_eq!(table.entries[0b1000], (5, 2));
        assert_eq!(table.entries[0b1100], (5, 2));

        // Symbol A (0) has code 010 (3 bits), reversed = 010
        // In 4-bit table: entries at 0b0010, 0b1010 should decode to (0, 3)
        assert_eq!(table.entries[0b0010], (0, 3));
        assert_eq!(table.entries[0b1010], (0, 3));

        // Symbol G (6) has code 1110 (4 bits), reversed = 0111
        assert_eq!(table.entries[0b0111], (6, 4));

        // Symbol H (7) has code 1111 (4 bits), reversed = 1111
        assert_eq!(table.entries[0b1111], (7, 4));
    }

    #[test]
    fn test_distance_one_self_copy() {
        // A run of repeated bytes will use distance=1 matches
        let input = vec![b'A'; 100];
        let encoded = crate::compress::deflate::encode::encode(
            &input,
            crate::compress::deflate::encode::Level::Fast,
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_code_length_repeat_exact_boundary() {
        // Test that code length repeat codes (16, 17, 18) work correctly
        // when they fill exactly to the total count.
        // We test this via a full encode→decode roundtrip with data that
        // naturally exercises the dynamic Huffman path.
        let mut input = Vec::new();
        // Create data with enough variety to trigger dynamic Huffman in real encoders
        // but for our fixed-Huffman encoder, this just tests roundtrip
        for i in 0..256u16 {
            input.push(i as u8);
        }
        let encoded = crate::compress::deflate::encode::encode(
            &input,
            crate::compress::deflate::encode::Level::Default,
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_hlit_exceeds_max() {
        // Construct BTYPE=10 block with HLIT=30 (5-bit field) → 30+257=287 > 286
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(30, 5); // HLIT = 30 → 287 lit/len codes (exceeds 286)
        w.write_bits(0, 5); // HDIST = 0
        w.write_bits(0, 4); // HCLEN = 0
        // Pad to make enough bytes
        w.write_bits(0, 8);
        let data = w.finish();
        let result = decode(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_hdist_exceeds_max() {
        // Construct BTYPE=10 block with HDIST=31 (5-bit field) → 31+1=32 > 30
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(0, 5); // HLIT = 0 (valid)
        w.write_bits(31, 5); // HDIST = 31 → 32 distance codes (exceeds 30)
        w.write_bits(0, 4); // HCLEN = 0
        w.write_bits(0, 8);
        let data = w.finish();
        let result = decode(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_dynamic_huffman_missing_eob() {
        // Construct a BTYPE=10 block where symbol 256 has code_length=0 (missing EOB).
        // HLIT=0 (257 codes), HDIST=0 (1 code), with symbol 65 ('A') = length 1,
        // symbol 256 = 0 (missing), distance code 0 = length 1.
        //
        // Code length alphabet:
        //   code 17 (repeat 0 for 3-10): Huffman length 1 → MSB code "0"
        //   code 18 (repeat 0 for 11-138): Huffman length 2 → MSB code "10"
        //   code  1 (literal code length): Huffman length 2 → MSB code "11"

        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes (symbols 0..=256)
        w.write_bits(0, 5);
        // HDIST = 0 → 1 distance code
        w.write_bits(0, 5);
        // HCLEN = 14 → 18 code length codes
        w.write_bits(14, 4);

        // Code length code lengths (same as test_dynamic_huffman_direct):
        let cl_code_lengths: [u8; 18] = [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Encode lit/len code lengths (257 symbols):
        // symbols 0-64: 65 zeros → code 18 (repeat 0 for 65)
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra: 65 - 11 = 54

        // symbol 65 ('A'): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 66-256: 191 zeros (including symbol 256 = 0, i.e. missing EOB)
        // 138 + 53 = 191
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra: 138 - 11 = 127

        w.write_huffman(0b11, 2); // code 18
        w.write_bits(42, 7); // extra: 53 - 11 = 42

        // Distance code lengths (1 code):
        // distance code 0: code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("end-of-block")),
            "expected InvalidData about missing end-of-block, got: {:?}",
            result
        );
    }

    #[test]
    fn test_huffman_table_oversubscribed() {
        // RFC 1951 section 3.2.2: code lengths whose Kraft sum exceeds 1
        // (over-subscribed) must be rejected at table construction.
        // Three 1-bit codes need 3/2 > 1 of the code space.
        assert!(matches!(
            HuffmanTable::from_lengths(&[1, 1, 1]),
            Err(Error::InvalidData(_))
        ));
        // Five 2-bit codes need 5/4 > 1.
        assert!(matches!(
            HuffmanTable::from_lengths(&[2, 2, 2, 2, 2]),
            Err(Error::InvalidData(_))
        ));
        // A single 3-bit code is incomplete but NOT over-subscribed:
        // still accepted (a single-code distance tree is legal).
        assert!(HuffmanTable::from_lengths(&[3]).is_ok());
        // Two 1-bit codes form a complete tree.
        assert!(HuffmanTable::from_lengths(&[1, 1]).is_ok());
        // An all-zero (empty) table stays legal (empty distance tree).
        assert!(HuffmanTable::from_lengths(&[0, 0, 0]).is_ok());
    }

    #[test]
    fn test_oversubscribed_huffman_rejected() {
        // Same dynamic-Huffman framing as test_dynamic_huffman_direct, but
        // the lit/len alphabet assigns THREE symbols ('A', 'B', EOB) a
        // 1-bit code each. The Kraft sum is 3/2 > 1, so the tree is
        // over-subscribed and must be rejected (RFC 1951 section 3.2.2).
        let mut w = TestBitWriter::new();

        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(0, 5); // HLIT = 0 -> 257 lit/len codes
        w.write_bits(0, 5); // HDIST = 0 -> 1 distance code
        w.write_bits(14, 4); // HCLEN = 14 -> 18 code length codes

        // Code length alphabet (same as test_dynamic_huffman_direct):
        //   code 17 -> length 1 (MSB code "0")
        //   code 18 -> length 2 (MSB code "11")
        //   code  1 -> length 2 (MSB code "10")
        let cl_code_lengths: [u8; 18] = [
            0, // code 16
            1, // code 17
            2, // code 18
            0, // code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Lit/len code lengths (257 symbols, 0..=256):
        // symbols 0-64: 65 zeros via code 18
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra: 65 - 11 = 54

        // symbol 65 ('A'): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"
        // symbol 66 ('B'): code length 1 (third 1-bit code overall)
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 67-255: 189 zeros = 138 + 51
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra: 138 - 11 = 127
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(40, 7); // extra: 51 - 11 = 40

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // Distance code 0: code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("over-subscribed")),
            "expected InvalidData about over-subscribed Huffman code, got: {:?}",
            result
        );
    }

    #[test]
    fn test_oversubscribed_dist_tree_rejected() {
        // Valid lit/len tree ('A' = 1 bit, EOB = 1 bit), but the distance
        // alphabet assigns THREE distance codes a 1-bit code each
        // (Kraft sum 3/2 > 1) -> over-subscribed, must be rejected.
        let mut w = TestBitWriter::new();

        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(0, 5); // HLIT = 0 -> 257 lit/len codes
        w.write_bits(2, 5); // HDIST = 2 -> 3 distance codes
        w.write_bits(14, 4); // HCLEN = 14 -> 18 code length codes

        // Same code length alphabet as test_dynamic_huffman_direct.
        let cl_code_lengths: [u8; 18] = [
            0, // code 16
            1, // code 17
            2, // code 18
            0, // code 0
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, // code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Lit/len code lengths (257 symbols, 0..=256):
        // symbols 0-64: 65 zeros via code 18
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(54, 7); // extra: 65 - 11 = 54

        // symbol 65 ('A'): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // symbols 66-255: 190 zeros = 138 + 52
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(127, 7); // extra: 138 - 11 = 127
        w.write_huffman(0b11, 2); // code 18
        w.write_bits(41, 7); // extra: 52 - 11 = 41

        // symbol 256 (EOB): code length 1
        w.write_huffman(0b10, 2); // CL code for "1"

        // Distance code lengths (3 codes): all length 1 -> over-subscribed
        w.write_huffman(0b10, 2); // CL code for "1"
        w.write_huffman(0b10, 2); // CL code for "1"
        w.write_huffman(0b10, 2); // CL code for "1"

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("over-subscribed")),
            "expected InvalidData about over-subscribed Huffman code, got: {:?}",
            result
        );
    }

    #[test]
    fn test_oversubscribed_code_length_code_rejected() {
        // The code-length alphabet itself is over-subscribed: three
        // symbols get a 1-bit code each (Kraft sum 3/2 > 1). The stream
        // must be rejected before any lit/len lengths are decoded.
        let mut w = TestBitWriter::new();

        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(0, 5); // HLIT = 0 -> 257 lit/len codes
        w.write_bits(0, 5); // HDIST = 0 -> 1 distance code
        w.write_bits(0, 4); // HCLEN = 0 -> 4 code length codes

        // CODE_LENGTH_ORDER[0..4] = [16, 17, 18, 0]: three 1-bit codes.
        w.write_bits(1, 3); // code 16: length 1
        w.write_bits(1, 3); // code 17: length 1
        w.write_bits(1, 3); // code 18: length 1
        w.write_bits(0, 3); // code 0:  length 0

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("over-subscribed")),
            "expected InvalidData about over-subscribed Huffman code, got: {:?}",
            result
        );
    }

    #[test]
    fn test_distance_max_32768() {
        // Create input: 'a', then 32768 'b's, then 'a' again.
        // The encoder should produce a match at distance exactly 32768 for the final 'a'.
        let mut input = Vec::with_capacity(32770);
        input.push(b'a');
        input.extend(core::iter::repeat_n(b'b', 32768));
        input.push(b'a');

        let encoded = crate::compress::deflate::encode::encode(
            &input,
            crate::compress::deflate::encode::Level::Default,
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_overlap_copy_distance_2() {
        // "ab" repeated 50 times = 100 bytes with distance=2 overlapping pattern
        let input: Vec<u8> = b"ab".iter().copied().cycle().take(100).collect();
        let encoded = crate::compress::deflate::encode::encode(
            &input,
            crate::compress::deflate::encode::Level::Default,
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_code_length_repeat16_no_previous() {
        // Construct a DEFLATE dynamic Huffman block where code length symbol 16
        // (repeat previous) appears as the very first code length symbol (i==0).
        // This must return InvalidData because there is no previous length to repeat.
        //
        // Code length alphabet: only symbol 16 has a Huffman code (length 1, MSB code "0").
        // HCLEN=4 → we define codes [16, 17, 18, 0] in CODE_LENGTH_ORDER.
        // Set code 16 = length 1, all others = 0.
        //
        // When decoding lit/len+dist code lengths, the first decoded symbol
        // is 16, which triggers the "no previous" error.

        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes
        w.write_bits(0, 5);
        // HDIST = 0 → 1 distance code
        w.write_bits(0, 5);
        // HCLEN = 0 → 4 code length codes (indices 0..3 of CODE_LENGTH_ORDER = [16, 17, 18, 0])
        w.write_bits(0, 4);

        // Code length code lengths (3 bits each):
        // index 0 → code 16: length 1
        w.write_bits(1, 3);
        // index 1 → code 17: length 0
        w.write_bits(0, 3);
        // index 2 → code 18: length 0
        w.write_bits(0, 3);
        // index 3 → code 0: length 0
        w.write_bits(0, 3);

        // Now the decoder will try to read code lengths for 258 symbols.
        // The first bit (0) decodes to CL symbol 16 at i==0 → error.
        // We write a 0 bit to ensure symbol 16 is decoded.
        w.write_bits(0, 1);
        // Extra bits for symbol 16 (2 bits for repeat count) - won't be read due to error
        w.write_bits(0, 2);
        // Pad to ensure enough data
        w.write_bits(0, 8);

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("no previous")),
            "expected InvalidData about no previous length, got: {:?}",
            result
        );
    }

    #[test]
    fn test_code_length_repeat_overflow() {
        // Construct a DEFLATE dynamic Huffman block where code length symbol 18
        // (repeat 0 for 11-138 times) is used twice with maximum repeat count,
        // causing the total count to exceed HLIT + HDIST (257 + 1 = 258).
        //
        // Code length alphabet:
        //   code 18: Huffman length 1 → MSB code "0"
        //   code  1: Huffman length 2 → MSB code "10"  (needed but won't be reached)
        //
        // First code 18: extra=127 → repeat 138 zeros → i=138
        // Second code 18: extra=127 → repeat 138 zeros → i=276 > 258 → error

        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes
        w.write_bits(0, 5);
        // HDIST = 0 → 1 distance code
        w.write_bits(0, 5);
        // HCLEN = 14 → 18 code length codes (indices 0..17 of CODE_LENGTH_ORDER)
        w.write_bits(14, 4);

        // Code length code lengths, 3 bits each, in CODE_LENGTH_ORDER:
        // [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        // We set:
        //   index 2 (code 18) = 1   → Huffman length 1 → MSB code "0"
        //   index 17 (code 1) = 2   → Huffman length 2 → MSB code "10"
        //   all others = 0
        let cl_code_lengths: [u8; 18] = [
            0, // index 0: code 16
            0, // index 1: code 17
            1, // index 2: code 18
            0, // index 3: code 0
            0, // index 4: code 8
            0, // index 5: code 7
            0, // index 6: code 9
            0, // index 7: code 6
            0, // index 8: code 10
            0, // index 9: code 5
            0, // index 10: code 11
            0, // index 11: code 4
            0, // index 12: code 12
            0, // index 13: code 3
            0, // index 14: code 13
            0, // index 15: code 2
            0, // index 16: code 14
            2, // index 17: code 1
        ];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // Canonical Huffman codes for the code length alphabet:
        //   code 18: length 1 → canonical MSB code 0b0
        //   code  1: length 2 → canonical MSB code 0b10

        // First code 18: repeat 0 for 138 times (extra = 127)
        w.write_huffman(0b0, 1); // code 18
        w.write_bits(127, 7); // extra bits: 138 - 11 = 127

        // Second code 18: repeat 0 for 138 times → total = 276 > 258 → overflow
        w.write_huffman(0b0, 1); // code 18
        w.write_bits(127, 7); // extra bits: 138 - 11 = 127

        // Pad to ensure enough data
        w.write_bits(0, 8);

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("overflow")),
            "expected InvalidData about repeat overflow, got: {:?}",
            result
        );
    }

    #[test]
    fn test_corrupted_huffman_table() {
        // Construct a DEFLATE dynamic Huffman block where all code length code
        // lengths are 0, producing an empty code length Huffman table.
        // When the decoder tries to decode the first lit/len code length symbol,
        // it will fail with "empty Huffman table".
        //
        // HCLEN = 0 → 4 entries, all set to 0.

        let mut w = TestBitWriter::new();

        // Block header
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)

        // HLIT = 0 → 257 lit/len codes
        w.write_bits(0, 5);
        // HDIST = 0 → 1 distance code
        w.write_bits(0, 5);
        // HCLEN = 0 → 4 code length codes
        w.write_bits(0, 4);

        // All 4 code length code lengths = 0
        w.write_bits(0, 3);
        w.write_bits(0, 3);
        w.write_bits(0, 3);
        w.write_bits(0, 3);

        // Pad with some data (will never be decoded)
        w.write_bits(0, 16);

        let data = w.finish();
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(_))),
            "expected InvalidData for corrupted Huffman table, got: {:?}",
            result
        );
    }

    #[test]
    fn test_truncated_single_byte_input() {
        // BFINAL=1, BTYPE=00 (stored) — truncated before LEN/NLEN
        let result = decode(&[0x01]);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_blocks() {
        // Two stored blocks: BFINAL=0 + "Hello", then BFINAL=1 + " World"
        let mut data = Vec::new();
        // Block 1: BFINAL=0, BTYPE=00
        data.push(0x00);
        let len1 = 5u16;
        data.extend_from_slice(&len1.to_le_bytes());
        data.extend_from_slice(&(!len1).to_le_bytes());
        data.extend_from_slice(b"Hello");
        // Block 2: BFINAL=1, BTYPE=00
        data.push(0x01);
        let len2 = 6u16;
        data.extend_from_slice(&len2.to_le_bytes());
        data.extend_from_slice(&(!len2).to_le_bytes());
        data.extend_from_slice(b" World");

        let result = decode(&data).unwrap();
        assert_eq!(result, b"Hello World");
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, super::super::encode::Level::Default);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, super::super::encode::Level::Default);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, super::super::encode::Level::Default);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data, super::super::encode::Level::Default);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }
}
