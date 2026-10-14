//! Deflate64 (Enhanced Deflating) decompression. APPNOTE.TXT registers
//! method 9 only; the bit-level structure follows the de facto definition
//! embodied in Info-ZIP `unzip`/`inflate.c` (see THIRD_PARTY_NOTICES).
//!
//! Differences from DEFLATE (RFC 1951):
//! - 64KB sliding window (vs 32KB)
//! - Distance codes 30-31 are valid (base 32769/49153, 14 extra bits each)
//! - Length code 285: base 3, 16 extra bits (max length 65538 vs 258)
//! - HDIST can be up to 32 (vs 30)

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::bitreader::BitReader;

use crate::compress::deflate::tables::{
    CODE_LENGTH_ORDER, fixed_distance_lengths, fixed_literal_lengths,
};

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

        let mut bl_count = [0u32; (MAX_BITS + 1) as usize];
        for &len in code_lengths {
            bl_count[len as usize] += 1;
        }
        bl_count[0] = 0;

        let mut next_code = [0u32; (MAX_BITS + 1) as usize];
        let mut code = 0u32;
        for bits in 1..=max_bits {
            code = (code + bl_count[(bits - 1) as usize]) << 1;
            next_code[bits as usize] = code;
        }

        let table_size = 1usize << max_bits;
        let mut entries = vec![(0u16, 0u8); table_size];

        for (symbol, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = next_code[len as usize];
            next_code[len as usize] += 1;
            let reversed = reverse_bits(code, len);
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

fn reverse_bits(value: u32, num_bits: u8) -> u32 {
    let mut result = 0;
    let mut v = value;
    for _ in 0..num_bits {
        result = (result << 1) | (v & 1);
        v >>= 1;
    }
    result
}

/// Decode a Deflate64 compressed stream.
///
/// Takes raw Deflate64 data (no ZIP framing) and returns the decompressed bytes.
/// Used for ZIP compression method 9.
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] if the input is truncated, [`Error::InvalidData`]
/// if the stream is malformed.
pub(crate) fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut reader = BitReader::new(input);
    let mut output = Vec::new();

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0b00 => decode_uncompressed(&mut reader, &mut output)?,
            0b01 => decode_fixed_huffman(&mut reader, &mut output)?,
            0b10 => decode_dynamic_huffman(&mut reader, &mut output)?,
            _ => return Err(Error::InvalidData("invalid Deflate64 block type 11")),
        }

        if bfinal == 1 {
            break;
        }
    }

    Ok(output)
}

/// Decode a non-compressed block (BTYPE=00). Identical to DEFLATE.
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
///
/// Deflate64 allows HDIST up to 32 (vs DEFLATE's 30).
fn decode_dynamic_huffman(reader: &mut BitReader, output: &mut Vec<u8>) -> Result<(), Error> {
    let hlit = reader.read_bits(5)? as usize + 257;
    let hdist = reader.read_bits(5)? as usize + 1;
    let hclen = reader.read_bits(4)? as usize + 4;

    if hlit > 286 {
        return Err(Error::InvalidData("HLIT exceeds maximum (286)"));
    }
    // Deflate64: HDIST can be up to 32 (distance codes 0-31).
    if hdist > 32 {
        return Err(Error::InvalidData("HDIST exceeds maximum (32)"));
    }

    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CODE_LENGTH_ORDER[i]] = reader.read_bits(3)? as u8;
    }

    let cl_table = HuffmanTable::from_lengths(&cl_lengths)?;

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
                let repeat = reader.read_bits(3)? as usize + 3;
                i += repeat;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            18 => {
                let repeat = reader.read_bits(7)? as usize + 11;
                i += repeat;
                if i > total {
                    return Err(Error::InvalidData("code length repeat overflow"));
                }
            }
            _ => return Err(Error::InvalidData("invalid code length symbol")),
        }
    }

    if lengths[256] == 0 {
        return Err(Error::InvalidData(
            "dynamic Huffman: missing end-of-block symbol (256)",
        ));
    }

    let lit_table = HuffmanTable::from_lengths(&lengths[..hlit])?;
    let dist_table = HuffmanTable::from_lengths(&lengths[hlit..hlit + hdist])?;
    decode_huffman_block(reader, &lit_table, &dist_table, output)
}

/// Core Huffman block decode loop.
///
/// Uses Deflate64-specific tables:
/// - LENGTH_BASE_64 / LENGTH_EXTRA_64 (code 285 = base 3, 16 extra bits)
/// - DISTANCE_BASE_64 / DISTANCE_EXTRA_64 (32 entries, codes 30-31 valid)
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
                output.push(symbol as u8);
            }
            256 => {
                return Ok(());
            }
            257..=285 => {
                let len_idx = (symbol - 257) as usize;
                let length = LENGTH_BASE_64[len_idx] as usize
                    + reader.read_bits(LENGTH_EXTRA_64[len_idx])? as usize;

                let dist_sym = dist_table.decode(reader)? as usize;
                if dist_sym >= DISTANCE_BASE_64.len() {
                    return Err(Error::InvalidData("invalid distance code"));
                }
                let distance = DISTANCE_BASE_64[dist_sym] as usize
                    + reader.read_bits(DISTANCE_EXTRA_64[dist_sym])? as usize;

                if distance > output.len() {
                    return Err(Error::InvalidData("distance too far back"));
                }

                // Copy from sliding window - byte-by-byte to handle overlapping copies.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// LSB-first bit writer for constructing test streams.
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

        /// Write `n` bits of a Huffman code (MSB-first in spec -> reverse for LSB-first packing).
        fn write_huffman(&mut self, code: u32, n: u8) {
            let reversed = reverse_bits(code, n);
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
    fn test_deflate64_decode_stored_block() {
        // BFINAL=1, BTYPE=00 (stored), LEN=5, NLEN=!5, "hello"
        let mut data = Vec::new();
        data.push(0b0000_0001); // BFINAL=1, BTYPE=00
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&(!5u16).to_le_bytes());
        data.extend_from_slice(b"hello");

        let result = decode(&data).unwrap();
        assert_eq!(result, b"hello");
    }

    #[test]
    fn test_deflate64_decode_fixed_huffman() {
        // Minimal fixed-Huffman block that decodes to "A".
        // Fixed codes: symbol 65 ('A') = 8-bit 0b01110001, symbol 256 (EOB) = 7-bit 0b0000000.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01 (fixed Huffman)
        w.write_huffman(0b0111_0001, 8); // literal 'A'
        w.write_huffman(0b000_0000, 7); // EOB

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_deflate64_decode_distance_code_30() {
        // Test distance > 32768 using distance code 30.
        //
        // Strategy: emit 32769 literal bytes via stored blocks, then in a
        // fixed-Huffman block emit a length/distance pair with dist=32769 (code 30, 0 extra).
        // The first byte should be copied from position 0.
        //
        // We use multiple stored blocks to emit the initial data, then a final
        // fixed-Huffman block for the back-reference.

        let prefix_len: usize = 32769;
        let mut stream = Vec::new();

        // Emit prefix via stored blocks (max 65535 bytes each, we only need 32769).
        // Block 1: non-final stored block with 32769 bytes.
        stream.push(0b0000_0000); // BFINAL=0, BTYPE=00
        let len1 = prefix_len as u16;
        stream.extend_from_slice(&len1.to_le_bytes());
        stream.extend_from_slice(&(!len1).to_le_bytes());
        // Fill with 'X' for the first byte, then 'Y' for the rest.
        stream.push(b'X');
        stream.extend(core::iter::repeat_n(b'Y', prefix_len - 1));

        // Block 2: final fixed-Huffman block with length=3, distance=32769.
        // distance code 30 = base 32769, 14 extra bits = 0 -> distance = 32769.
        // length code 257 = base 3, 0 extra bits -> length = 3.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01 (fixed Huffman)

        // Length symbol 257 (code length 7 in fixed table): MSB code 0b0000001
        w.write_huffman(0b000_0001, 7); // length 3
        // Distance symbol 30: 5 bits (fixed distance), MSB code for symbol 30 = 0b11110
        w.write_huffman(0b11110, 5);
        // 14 extra bits for distance code 30, value = 0 (distance = 32769 + 0)
        w.write_bits(0, 14);

        // EOB (symbol 256): 7-bit code 0b0000000
        w.write_huffman(0b000_0000, 7);

        stream.extend_from_slice(&w.finish());

        let result = decode(&stream).unwrap();
        assert_eq!(result.len(), prefix_len + 3);
        // The back-reference at distance 32769 copies from position 0:
        // output[0] = 'X', output[1] = 'Y', output[2] = 'Y'
        assert_eq!(result[prefix_len], b'X');
        assert_eq!(result[prefix_len + 1], b'Y');
        assert_eq!(result[prefix_len + 2], b'Y');
    }

    #[test]
    fn test_deflate64_decode_long_match() {
        // Test match length > 258 using code 285 with extra bits.
        //
        // Code 285 in Deflate64: base=3, extra=16 bits.
        // We'll use extra=0 -> length=3 (just to test the mechanism works).
        // Then also test with extra=1 -> length=4.

        // Emit one literal byte via stored block, then fixed Huffman with code 285.
        let mut stream = Vec::new();

        // Block 1: non-final stored block with 1 byte.
        stream.push(0b0000_0000); // BFINAL=0, BTYPE=00
        stream.extend_from_slice(&1u16.to_le_bytes());
        stream.extend_from_slice(&(!1u16).to_le_bytes());
        stream.push(b'Z');

        // Block 2: final fixed-Huffman block.
        // Length code 285 = symbol 285 = index 28 in fixed literal table.
        // Fixed code for 285: 8-bit code 0b11000101 (280-287 are 8 bits, code 280=0b11000000).
        // Symbol 285 - 280 = 5, so code = 0b11000000 + 5 = 0b11000101 = 0xC5.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01

        // Symbol 285 in fixed Huffman: 8-bit, MSB code = 0b11000101
        w.write_huffman(0b1100_0101, 8);
        // 16 extra bits for code 285: value = 2 -> length = 3 + 2 = 5
        w.write_bits(2, 16);
        // Distance symbol 0: 5-bit, dist=1
        w.write_huffman(0b00000, 5);
        // EOB
        w.write_huffman(0b000_0000, 7);

        stream.extend_from_slice(&w.finish());

        let result = decode(&stream).unwrap();
        // 1 literal 'Z' + 5 copies of 'Z' (length=5, dist=1) = 6 bytes
        assert_eq!(result, b"ZZZZZZ");
    }

    #[test]
    fn test_deflate64_decode_stored_len_nlen_mismatch() {
        let mut data = Vec::new();
        data.push(0b0000_0001);
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&(!6u16).to_le_bytes()); // mismatch
        data.extend_from_slice(b"hello");
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_deflate64_invalid_block_type() {
        let data = [0x07]; // BFINAL=1, BTYPE=11
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_deflate64_empty_input() {
        assert!(matches!(decode(&[]), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_deflate64_max_distance_65536() {
        // Distance code 31 with maximum extra bits → distance 65536:
        // the 64 KB window that gives Deflate64 its name.
        let prefix_len = 65536usize;
        let mut stream = Vec::new();

        // Emit 65536 prefix bytes via two stored blocks (max 65535 each).
        stream.push(0b0000_0000); // BFINAL=0, BTYPE=00
        stream.extend_from_slice(&65535u16.to_le_bytes());
        stream.extend_from_slice(&(!65535u16).to_le_bytes());
        stream.push(b'X'); // position 0 — the byte we will back-reference
        stream.extend(core::iter::repeat_n(b'Y', 65534));

        stream.push(0b0000_0000); // BFINAL=0, BTYPE=00
        stream.extend_from_slice(&1u16.to_le_bytes());
        stream.extend_from_slice(&(!1u16).to_le_bytes());
        stream.push(b'Y');

        // Final fixed-Huffman block: length 3 at distance 65536.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01
        w.write_huffman(0b000_0001, 7); // length symbol 257 → len 3
        w.write_huffman(0b11111, 5); // distance symbol 31
        w.write_bits(0x3FFF, 14); // extra: 49153 + 16383 = 65536
        w.write_huffman(0b000_0000, 7); // EOB
        stream.extend_from_slice(&w.finish());

        let result = decode(&stream).unwrap();
        assert_eq!(result.len(), prefix_len + 3);
        assert_eq!(&result[prefix_len..], b"XYY");
    }

    #[test]
    fn test_deflate64_max_match_length_65538() {
        // Length code 285 with maximum extra bits → 3 + 65535 = 65538.
        let mut stream = Vec::new();
        stream.push(0b0000_0000); // stored 'Z'
        stream.extend_from_slice(&1u16.to_le_bytes());
        stream.extend_from_slice(&(!1u16).to_le_bytes());
        stream.push(b'Z');

        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01
        w.write_huffman(0b1100_0101, 8); // length symbol 285
        w.write_bits(0xFFFF, 16); // extra: 3 + 65535 = 65538
        w.write_huffman(0b00000, 5); // distance symbol 0 → dist 1
        w.write_huffman(0b000_0000, 7); // EOB
        stream.extend_from_slice(&w.finish());

        let result = decode(&stream).unwrap();
        assert_eq!(result.len(), 1 + 65538);
        assert!(result.iter().all(|&b| b == b'Z'));
    }

    #[test]
    fn test_deflate64_distance_30_exceeds_output() {
        // Distance code 30 is valid in the Deflate64 table, but the
        // distance (32769) must still be ≤ bytes emitted so far.
        let mut stream = Vec::new();
        stream.push(0b0000_0000); // stored 100 bytes
        stream.extend_from_slice(&100u16.to_le_bytes());
        stream.extend_from_slice(&(!100u16).to_le_bytes());
        stream.extend(core::iter::repeat_n(b'Y', 100));

        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b01, 2); // BTYPE = 01
        w.write_huffman(0b000_0001, 7); // len 3
        w.write_huffman(0b11110, 5); // distance symbol 30 → 32769
        w.write_bits(0, 14);
        w.write_huffman(0b000_0000, 7); // EOB
        stream.extend_from_slice(&w.finish());

        assert!(matches!(decode(&stream), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_deflate64_dynamic_hdist_32_code31_accepted() {
        // Deflate64-specific: HDIST may reach 32 and distance code 31
        // may carry a non-zero code length (rejected in plain DEFLATE).
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10 (dynamic Huffman)
        w.write_bits(0, 5); // HLIT → 257 lit/len codes
        w.write_bits(31, 5); // HDIST → 32 distance codes
        w.write_bits(14, 4); // HCLEN → 18 code length codes

        // CL lengths in CODE_LENGTH_ORDER: CL17=1, CL18=2, CL1=2 →
        // canonical codes CL17='0', CL1='10', CL18='11'.
        let cl_code_lengths: [u8; 18] = [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // 289 entries: lit[65]=1, lit[256]=1, dist[31]=1, rest 0.
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(54, 7); // i=0..64 zeros
        w.write_huffman(0b10, 2); // CL1 → i=65 len 1
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(127, 7); // i=66..203 zeros
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(41, 7); // i=204..255 zeros
        w.write_huffman(0b10, 2); // CL1 → i=256 len 1 (EOB)
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(20, 7); // i=257..287 zeros (dist codes 0-30)
        w.write_huffman(0b10, 2); // CL1 → i=288 len 1 (dist code 31)

        // Emit 'A' (lit code '0') then EOB (lit code '1').
        w.write_huffman(0b0, 1);
        w.write_huffman(0b1, 1);

        let result = decode(&w.finish()).unwrap();
        assert_eq!(result, b"A");
    }

    #[test]
    fn test_deflate64_dynamic_missing_eob() {
        // lit/len symbol 256 with code length 0 → must be rejected.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10
        w.write_bits(0, 5); // HLIT → 257
        w.write_bits(0, 5); // HDIST → 1
        w.write_bits(14, 4); // HCLEN → 18

        let cl_code_lengths: [u8; 18] = [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        for &len in &cl_code_lengths {
            w.write_bits(len as u32, 3);
        }

        // lit[65]=1, lit[256]=0 (missing EOB), dist[0]=1.
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(54, 7); // i=0..64 zeros
        w.write_huffman(0b10, 2); // CL1 → i=65 len 1
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(127, 7); // i=66..203 zeros
        w.write_huffman(0b11, 2); // CL18
        w.write_bits(42, 7); // i=204..256 zeros (incl. EOB)
        w.write_huffman(0b10, 2); // CL1 → i=257 len 1 (dist)

        let result = decode(&w.finish());
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_deflate64_hlit_exceeds_max() {
        // HLIT field = 30 → 287 lit/len codes > 286 maximum.
        let mut w = TestBitWriter::new();
        w.write_bits(1, 1); // BFINAL = 1
        w.write_bits(0b10, 2); // BTYPE = 10
        w.write_bits(30, 5); // HLIT → 287
        w.write_bits(0, 5); // HDIST → 1
        w.write_bits(0, 4); // HCLEN → 4
        w.write_bits(0, 8); // padding
        assert!(matches!(decode(&w.finish()), Err(Error::InvalidData(_))));
    }
}
