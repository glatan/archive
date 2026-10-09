//! ZIP Method 10 (PKWARE DCL Implode) decoder.
//!
//! Implements the decompression algorithm used by PKWARE's Data Compression
//! Library.  This is distinct from ZIP Method 6 (Imploding / APPNOTE SS5.3).
//!
//! The reference implementation is Mark Adler's `blast.c` (zlib
//! license); this file is a modified reimplementation.  The format uses:
//! - A two-byte header: literal-tree flag (byte), dictionary-size parameter (byte)
//! - Three Huffman code tables: literal (256 symbols), length (16 symbols),
//!   distance (64 symbols)
//! - LZ77-coded data read from an LSB-first bitstream
//!
//! The Huffman codes are decoded with *inverted* bits (blast.c XORs each bit
//! with 1 before accumulating), so the canonical code assignment is reversed
//! compared to the usual convention.
//!
//! This file also provides a minimal *encoder* for the write path:
//! `dcl_implode_encode` emits a literal-only stream (header `lit=0` raw
//! literals, `dict=4`) carrying one 9-bit literal (tag 0 + raw byte) per input
//! byte followed by the end-of-stream marker (length symbol 15 + extra bits
//! 255 = length 519).  No back-references are emitted, so the output is a
//! valid but non-compressing method-10 stream.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

// ---------------------------------------------------------------------------
// Tables from blast.c
// ---------------------------------------------------------------------------

/// Length base values (blast.c `base[]`).
const LEN_BASE: [u16; 16] = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264];

/// Length extra bits (blast.c `extra[]`).
const LEN_EXTRA: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];

// ---------------------------------------------------------------------------
// Run-length encoded code-length tables (blast.c litlen[], lenlen[], distlen[])
//
// Each byte encodes: repeat = (byte >> 4) + 1,  length = byte & 0x0F
// ---------------------------------------------------------------------------

/// Compressed code lengths for the 256-symbol literal tree.
const LITLEN_REP: [u8; 98] = [
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8, 9, 7, 6, 7, 8, 7, 6, 55,
    8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5, 7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8,
    25, 11, 8, 11, 9, 12, 8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27, 44,
    253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45, 44, 173,
];

/// Compressed code lengths for the 16-symbol length tree.
const LENLEN_REP: [u8; 6] = [2, 35, 36, 53, 38, 23];

/// Compressed code lengths for the 64-symbol distance tree.
const DISTLEN_REP: [u8; 7] = [2, 20, 53, 230, 247, 151, 248];

/// Maximum Huffman code bit-length.
const MAXBITS: usize = 13;

// ---------------------------------------------------------------------------
// Expand a run-length encoded code-length table
// ---------------------------------------------------------------------------

/// Decode a run-length encoded array into per-symbol code lengths.
///
/// Each byte in `rep` encodes `(byte >> 4) + 1` repetitions of code-length
/// `byte & 0x0F`.  Returns a vector of `n` code lengths.
fn expand_rep(rep: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    let mut lengths = Vec::with_capacity(n);
    for &byte in rep {
        let count = (byte >> 4) as usize + 1;
        let len = byte & 0x0F;
        for _ in 0..count {
            lengths.push(len);
        }
    }
    if lengths.len() != n {
        return Err(Error::InvalidData(
            "zip dcl_implode: code-length table size mismatch",
        ));
    }
    Ok(lengths)
}

// ---------------------------------------------------------------------------
// Canonical Huffman table
// ---------------------------------------------------------------------------

/// A lookup-table Huffman decoder matching the blast.c `struct huffman`.
///
/// `count[len]` = number of symbols with code length `len`.
/// `symbols[]` = symbols in canonical order (sorted by length, then value).
struct HuffTable {
    count: [u16; MAXBITS + 1],
    symbols: Vec<u16>,
}

impl HuffTable {
    /// Build from per-symbol code lengths (matching blast.c `construct()`).
    fn build(lengths: &[u8]) -> Result<Self, Error> {
        let n = lengths.len();

        // Count codes of each length.
        let mut count = [0u16; MAXBITS + 1];
        for &len in lengths {
            count[len as usize] += 1;
        }

        // Check for an empty code (all lengths zero).
        if count[0] as usize == n {
            return Err(Error::InvalidData(
                "zip dcl_implode: degenerate Huffman code (all zero lengths)",
            ));
        }

        // Build offsets into symbol table for each length.
        let mut offs = [0u16; MAXBITS + 1];
        for len in 1..MAXBITS {
            offs[len + 1] = offs[len] + count[len];
        }

        // Fill in symbol table in canonical order.
        let total: usize = lengths.iter().filter(|&&l| l > 0).count();
        let mut symbols = vec![0u16; total];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let idx = offs[len as usize] as usize;
                symbols[idx] = sym as u16;
                offs[len as usize] += 1;
            }
        }

        Ok(Self { count, symbols })
    }

    /// Decode one symbol from the bitstream (matching blast.c `decode()`).
    ///
    /// blast.c inverts each bit (`(bitbuf & 1) ^ 1`) before accumulating
    /// into `code`.  We reproduce that here.
    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, Error> {
        let mut code: u32 = 0;
        let mut first: u32 = 0;
        let mut index: usize = 0;

        for len in 1..=MAXBITS {
            let bit = reader.read_bits(1)?;
            // Invert the bit, matching blast.c: `code |= (bitbuf & 1) ^ 1`
            code = (code << 1) | (bit ^ 1);
            let cnt = self.count[len] as u32;
            if code < first + cnt {
                return Ok(self.symbols[index + (code - first) as usize]);
            }
            index += cnt as usize;
            first = (first + cnt) << 1;
        }

        Err(Error::InvalidData(
            "zip dcl_implode: invalid Huffman code in bitstream",
        ))
    }
}

// ---------------------------------------------------------------------------
// Bitstream reader — LSB-first (matching blast.c `bits()`)
// ---------------------------------------------------------------------------

/// Reads bits from a byte slice in LSB-first order.
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

    /// Read `count` bits, returning them packed LSB-first.
    fn read_bits(&mut self, count: u8) -> Result<u32, Error> {
        let mut result: u32 = 0;
        for i in 0..count {
            if self.byte_pos >= self.data.len() {
                return Err(Error::UnexpectedEof);
            }
            let bit = ((self.data[self.byte_pos] >> self.bit_pos) & 1) as u32;
            result |= bit << i;
            self.bit_pos += 1;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Decompress data compressed with PKWARE DCL Implode (ZIP Method 10).
///
/// `data` is the raw compressed payload (excluding the ZIP local file header
/// and any encryption layer).
pub(super) fn dcl_implode_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::InvalidData(
            "zip dcl_implode: empty compressed payload",
        ));
    }

    let mut reader = BitReader::new(data);

    // --- Header (blast.c reads two full bytes) ------------------------------
    // lit: 0 = raw 8-bit literals, 1 = Huffman-coded literals
    let lit = reader.read_bits(8)?;
    if lit > 1 {
        return Err(Error::InvalidData(
            "zip dcl_implode: invalid literal flag (must be 0 or 1)",
        ));
    }
    let lit = lit == 1;

    // dict: number of extra low-order distance bits (blast.c expects 4, 5, or 6)
    let dict = reader.read_bits(8)?;
    if !(4..=6).contains(&dict) {
        return Err(Error::InvalidData(
            "zip dcl_implode: invalid dictionary parameter (must be 4-6)",
        ));
    }
    let dict = dict as u8;

    // --- Build Huffman tables from the fixed code-length descriptors ---------
    let lit_table = if lit {
        let lengths = expand_rep(&LITLEN_REP, 256)?;
        Some(HuffTable::build(&lengths)?)
    } else {
        None
    };

    let len_lengths = expand_rep(&LENLEN_REP, 16)?;
    let len_table = HuffTable::build(&len_lengths)?;

    let dist_lengths = expand_rep(&DISTLEN_REP, 64)?;
    let dist_table = HuffTable::build(&dist_lengths)?;

    // --- Decode loop (blast.c decomp()) -------------------------------------
    let mut output: Vec<u8> = Vec::new();

    loop {
        let tag = reader.read_bits(1)?;

        if tag == 0 {
            // --- Literal byte ---
            let sym = if lit {
                lit_table.as_ref().unwrap().decode(&mut reader)?
            } else {
                reader.read_bits(8)? as u16
            };
            output.push(sym as u8);
        } else {
            // --- Length / distance pair ---

            // Decode length from the length Huffman table.
            let len_sym = len_table.decode(&mut reader)? as usize;
            let length =
                LEN_BASE[len_sym] as usize + reader.read_bits(LEN_EXTRA[len_sym])? as usize;

            // End-of-stream marker: length == 519.
            if length == 519 {
                break;
            }

            // Decode distance.
            // blast.c: symbol = len == 2 ? 2 : dict
            let dist_shift = if length == 2 { 2 } else { dict };
            let dist_sym = dist_table.decode(&mut reader)? as u32;
            let dist = (dist_sym << dist_shift) + reader.read_bits(dist_shift)? + 1;
            let dist = dist as usize;

            if dist > output.len() {
                return Err(Error::InvalidData(
                    "zip dcl_implode: back-reference distance exceeds output",
                ));
            }

            // Copy `length` bytes from the sliding window.
            let start = output.len() - dist;
            for i in 0..length {
                let byte = output[start + (i % dist)];
                output.push(byte);
            }
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Literal-only encoder (write path)
// ---------------------------------------------------------------------------

/// Minimal bit writer for the LSB-first DCL bitstream.
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

    /// Write `count` bits from `value`, LSB-first.
    fn write_bits(&mut self, value: u32, count: u8) {
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

/// Encode a Huffman symbol using the blast.c-style inverted-bit canonical
/// code.  The caller must provide the code length and canonical code
/// value (as produced by `HuffTable::build`).
///
/// blast.c `decode()` reads bits LSB-first and inverts each bit before
/// accumulating MSB-first into the code.  To *encode* we therefore need
/// to reverse that: take the canonical code, emit its bits MSB-first,
/// but invert each bit before writing to the LSB-first bitstream.
fn write_huffman_code(writer: &mut BitWriter, code: u32, len: u8) {
    // Emit MSB first, inverted.
    for i in (0..len).rev() {
        let bit = (code >> i) & 1;
        // Invert the bit to match decode's `^ 1`.
        writer.write_bits(bit ^ 1, 1);
    }
}

/// Encode a literal using the blast.c format (lit=0 header: raw 8-bit value).
fn encode_literal_raw(writer: &mut BitWriter, byte: u8) {
    // tag bit 0 = literal
    writer.write_bits(0, 1);
    // raw 8-bit literal
    writer.write_bits(byte as u32, 8);
}

/// Encode an end-of-stream marker.
/// Length 519 = base[15] + extra = 264 + 255.
/// Length code 15 has extra[15] = 8 extra bits.
fn encode_end_marker(writer: &mut BitWriter, len_codes: &[(u32, u8)]) {
    // tag bit 1 = length/distance
    writer.write_bits(1, 1);
    // length symbol 15
    write_huffman_code(writer, len_codes[15].0, len_codes[15].1);
    // extra bits: need 264 + x = 519, so x = 255
    writer.write_bits(255, 8);
}

/// Compute the canonical `(code, length)` pairs implied by a `HuffTable`.
fn compute_canonical_codes_from_table(table: &HuffTable, n_symbols: usize) -> Vec<(u32, u8)> {
    let mut codes = vec![(0u32, 0u8); n_symbols];
    let mut code: u32 = 0;
    let mut sym_idx = 0;

    for len in 1..=MAXBITS {
        let cnt = table.count[len] as usize;
        for i in 0..cnt {
            let sym = table.symbols[sym_idx + i] as usize;
            if sym < n_symbols {
                codes[sym] = (code, len as u8);
            }
            code += 1;
        }
        sym_idx += cnt;
        code <<= 1;
    }

    codes
}

/// Compress `data` into a literal-only PKWARE DCL Implode stream (ZIP
/// Method 10).
///
/// Emits the `lit=0` (raw literals) / `dict=4` header, then one 9-bit
/// literal (tag bit 0 + raw byte) per input byte, terminated by the
/// end-of-stream marker (length 519).  No length/distance pairs are
/// emitted, so the output is a valid but non-compressing stream.
pub(super) fn dcl_implode_encode(data: &[u8]) -> Vec<u8> {
    // The EOS marker needs the canonical code for length symbol 15; the
    // code-length descriptors are compile-time constants, so table
    // construction cannot fail.
    let len_lengths = expand_rep(&LENLEN_REP, 16).expect("static length table");
    let len_table = HuffTable::build(&len_lengths).expect("static length table");
    let len_codes = compute_canonical_codes_from_table(&len_table, 16);

    let mut writer = BitWriter::new();
    // Header: lit = 0 (raw 8-bit literals), dict = 4.
    writer.write_bits(0, 8);
    writer.write_bits(4, 8);

    for &byte in data {
        encode_literal_raw(&mut writer, byte);
    }
    encode_end_marker(&mut writer, &len_codes);
    writer.finish()
}

/// Helper used by tests: encode a length/distance pair.
#[cfg(test)]
fn encode_match(
    writer: &mut BitWriter,
    length: usize,
    distance: usize,
    dict: u8,
    len_codes: &[(u32, u8)],
    dist_codes: &[(u32, u8)],
) {
    // tag bit 1 = length/distance
    writer.write_bits(1, 1);

    // Find the length symbol.  LEN_BASE is not monotonically increasing
    // (index 0 = 3, index 1 = 2), so we check each symbol to find the one
    // whose base + extra-bits range covers `length`.
    let mut len_sym = 0;
    for i in 0..16 {
        let base = LEN_BASE[i] as usize;
        let max_extra = if LEN_EXTRA[i] > 0 {
            (1 << LEN_EXTRA[i]) - 1
        } else {
            0
        };
        if length >= base && length <= base + max_extra {
            len_sym = i;
            break;
        }
    }
    let len_extra_val = length - LEN_BASE[len_sym] as usize;

    write_huffman_code(writer, len_codes[len_sym].0, len_codes[len_sym].1);
    writer.write_bits(len_extra_val as u32, LEN_EXTRA[len_sym]);

    // Distance: blast.c uses `dist_shift = if length == 2 { 2 } else { dict }`
    let dist_shift = if length == 2 { 2 } else { dict };
    let dist_minus_1 = (distance - 1) as u32;
    let dist_sym = dist_minus_1 >> dist_shift;
    let dist_low = dist_minus_1 & ((1 << dist_shift) - 1);

    write_huffman_code(
        writer,
        dist_codes[dist_sym as usize].0,
        dist_codes[dist_sym as usize].1,
    );
    writer.write_bits(dist_low, dist_shift);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_rep_lenlen() {
        let lengths = expand_rep(&LENLEN_REP, 16).unwrap();
        assert_eq!(lengths.len(), 16);
        // First symbol has length 2
        assert_eq!(lengths[0], 2);
        // Next 3 symbols have length 3
        assert_eq!(lengths[1], 3);
        assert_eq!(lengths[2], 3);
        assert_eq!(lengths[3], 3);
    }

    #[test]
    fn test_expand_rep_distlen() {
        let lengths = expand_rep(&DISTLEN_REP, 64).unwrap();
        assert_eq!(lengths.len(), 64);
    }

    #[test]
    fn test_expand_rep_litlen() {
        let lengths = expand_rep(&LITLEN_REP, 256).unwrap();
        assert_eq!(lengths.len(), 256);
    }

    #[test]
    fn test_huff_table_build_and_decode() {
        // Build the length table and verify it can decode symbols.
        let lengths = expand_rep(&LENLEN_REP, 16).unwrap();
        let table = HuffTable::build(&lengths).unwrap();
        assert_eq!(table.symbols.len(), 16);
    }

    #[test]
    fn test_dcl_implode_literal_only() {
        // Construct a valid DCL Implode stream with only literal bytes and
        // an end-of-stream marker.  Use lit=0 (raw literals), dict=4.
        let len_lengths = expand_rep(&LENLEN_REP, 16).unwrap();
        let len_table = HuffTable::build(&len_lengths).unwrap();
        let len_codes = compute_canonical_codes_from_table(&len_table, 16);

        let dist_lengths = expand_rep(&DISTLEN_REP, 64).unwrap();
        let dist_table = HuffTable::build(&dist_lengths).unwrap();
        let _dist_codes = compute_canonical_codes_from_table(&dist_table, 64);

        let mut writer = BitWriter::new();

        // Header: lit=0, dict=4
        writer.write_bits(0, 8); // lit flag
        writer.write_bits(4, 8); // dict

        // Literals: "Hello"
        for &b in b"Hello" {
            encode_literal_raw(&mut writer, b);
        }

        // End marker
        encode_end_marker(&mut writer, &len_codes);

        let compressed = writer.finish();
        let result = dcl_implode_decode(&compressed).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_dcl_implode_back_reference() {
        // Encode "ABCABC" as: literals "ABC" + back-reference (dist=3, len=3).
        let len_lengths = expand_rep(&LENLEN_REP, 16).unwrap();
        let len_table = HuffTable::build(&len_lengths).unwrap();
        let len_codes = compute_canonical_codes_from_table(&len_table, 16);

        let dist_lengths = expand_rep(&DISTLEN_REP, 64).unwrap();
        let dist_table = HuffTable::build(&dist_lengths).unwrap();
        let dist_codes = compute_canonical_codes_from_table(&dist_table, 64);

        let mut writer = BitWriter::new();

        // Header: lit=0, dict=4
        writer.write_bits(0, 8);
        writer.write_bits(4, 8);

        // Literals: "ABC"
        for &b in b"ABC" {
            encode_literal_raw(&mut writer, b);
        }

        // Match: length=3, distance=3
        encode_match(&mut writer, 3, 3, 4, &len_codes, &dist_codes);

        // End marker
        encode_end_marker(&mut writer, &len_codes);

        let compressed = writer.finish();
        let result = dcl_implode_decode(&compressed).unwrap();
        assert_eq!(result, b"ABCABC");
    }

    #[test]
    fn test_dcl_implode_roundtrip_with_known_vector() {
        // Encode "AAAAAAAAAA" (10 A's) as: literal 'A' + match(dist=1, len=9).
        let len_lengths = expand_rep(&LENLEN_REP, 16).unwrap();
        let len_table = HuffTable::build(&len_lengths).unwrap();
        let len_codes = compute_canonical_codes_from_table(&len_table, 16);

        let dist_lengths = expand_rep(&DISTLEN_REP, 64).unwrap();
        let dist_table = HuffTable::build(&dist_lengths).unwrap();
        let dist_codes = compute_canonical_codes_from_table(&dist_table, 64);

        let mut writer = BitWriter::new();

        // Header: lit=0, dict=4
        writer.write_bits(0, 8);
        writer.write_bits(4, 8);

        // Literal 'A'
        encode_literal_raw(&mut writer, b'A');

        // Match: length=9, distance=1
        // length 9 => base[7]=9, extra[7]=0, extra_val=0
        encode_match(&mut writer, 9, 1, 4, &len_codes, &dist_codes);

        // End marker
        encode_end_marker(&mut writer, &len_codes);

        let compressed = writer.finish();
        let result = dcl_implode_decode(&compressed).unwrap();
        assert_eq!(result, b"AAAAAAAAAA");
    }

    #[test]
    fn test_dcl_implode_empty_payload() {
        let result = dcl_implode_decode(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcl_implode_invalid_lit_flag() {
        // lit flag = 2 (invalid)
        let result = dcl_implode_decode(&[2, 4, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcl_implode_invalid_dict() {
        // dict = 3 (invalid, must be 4-6)
        let result = dcl_implode_decode(&[0, 3, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcl_implode_encode_roundtrip() {
        // Literal-only encoder output decodes back to the input for empty,
        // small, and repetitive payloads.
        for data in [
            &b""[..],
            &b"a"[..],
            &b"Hello, world!"[..],
            &vec![0xAA; 1024][..],
        ] {
            let compressed = dcl_implode_encode(data);
            // Header: lit = 0 (raw literals), dict = 4.
            assert_eq!(compressed[0], 0);
            assert_eq!(compressed[1], 4);
            let decoded = dcl_implode_decode(&compressed).unwrap();
            assert_eq!(&decoded, data);
        }
    }

    #[test]
    fn test_dcl_implode_encode_random_roundtrip() {
        // Pseudo-random bytes (LCG) roundtrip through the literal-only
        // encoder.
        let mut data = vec![0u8; 997];
        let mut state = 0x1234_5678u32;
        for byte in &mut data {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let compressed = dcl_implode_encode(&data);
        assert_eq!(dcl_implode_decode(&compressed).unwrap(), data);
    }
}
