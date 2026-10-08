//! LZO1X-1 compression with lzop file format wrapper.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzo::{decode, encode};
//!
//! let data = b"Hello, LZO!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec;
use alloc::vec::Vec;

use crate::util::adler32::adler32;

// ── lzop constants ──────────────────────────────────────────────

/// lzop file magic number.
const LZOP_MAGIC: &[u8] = &[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A];

/// lzop version we claim to be.
const LZOP_VERSION: u16 = 0x1040;
/// Minimum version needed to extract.
const LZOP_VERSION_NEEDED: u16 = 0x0940;
/// LZO library version.
const LZO_VERSION: u16 = 0x2080;

/// Compression method: LZO1X-1.
const M_LZO1X_1: u8 = 1;
/// Compression level for LZO1X-1.
const LEVEL_LZO1X_1: u8 = 3;

/// Flag: Adler-32 of uncompressed data.
const F_ADLER32_D: u32 = 0x0001;

// ── LZO1X-1 constants ──────────────────────────────────────────

const HASH_BITS: usize = 14;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MIN_MATCH: usize = 4;
const LAST_LITERALS: usize = 5;
const MF_LIMIT: usize = MIN_MATCH + LAST_LITERALS;
/// Maximum back-reference distance for LZO1X.
const MAX_OFFSET: usize = 49151;
/// Maximum block size for lzop (256 KB).
const BLOCK_SIZE: usize = 256 * 1024;

/// Compress data using lzop format with LZO1X-1 compression.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzo::{decode, encode};
///
/// let data = b"Hello, LZO!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    // ── lzop header ─────────────────────────────────────────
    output.extend_from_slice(LZOP_MAGIC);
    write_u16_be(&mut output, LZOP_VERSION);
    write_u16_be(&mut output, LZO_VERSION);
    write_u16_be(&mut output, LZOP_VERSION_NEEDED);
    output.push(M_LZO1X_1);
    output.push(LEVEL_LZO1X_1);
    write_u32_be(&mut output, F_ADLER32_D);
    write_u32_be(&mut output, 0o100644); // mode
    write_u32_be(&mut output, 0); // mtime_low
    write_u32_be(&mut output, 0); // mtime_high
    output.push(0); // no filename

    // Header checksum (Adler-32 of header bytes after magic)
    let hc = adler32(&output[LZOP_MAGIC.len()..]);
    write_u32_be(&mut output, hc);

    // ── Compress blocks ─────────────────────────────────────
    for chunk in input.chunks(BLOCK_SIZE).chain(if input.is_empty() {
        Some(&[][..])
    } else {
        None
    }) {
        if chunk.is_empty() {
            break;
        }

        let compressed = compress_lzo1x(chunk);
        let uncompressed_adler = adler32(chunk);

        if compressed.len() >= chunk.len() {
            // Store uncompressed
            write_u32_be(&mut output, chunk.len() as u32);
            write_u32_be(&mut output, chunk.len() as u32);
            write_u32_be(&mut output, uncompressed_adler);
            output.extend_from_slice(chunk);
        } else {
            write_u32_be(&mut output, chunk.len() as u32);
            write_u32_be(&mut output, compressed.len() as u32);
            write_u32_be(&mut output, uncompressed_adler);
            output.extend_from_slice(&compressed);
        }
    }

    // End mark
    write_u32_be(&mut output, 0);

    output
}

/// Compress a single block using standard LZO1X-1 bytecode.
///
/// The output follows the standard LZO1X stream format as documented
/// in the Linux kernel (Documentation/staging/lzo.rst). All matches use S=0
/// (no embedded trailing literals).
pub(crate) fn compress_lzo1x(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    if input.len() < MF_LIMIT {
        // Input too small — emit as all literals + end marker.
        // For < 4 bytes, return something >= input.len() to trigger uncompressed storage.
        if input.len() < 4 {
            output.resize(input.len() + 3, 0); // always >= input
            return output;
        }
        emit_literal_run(&mut output, input.len());
        output.extend_from_slice(input);
        emit_end_marker(&mut output);
        return output;
    }

    let mut hash_table = vec![0u32; HASH_SIZE];
    let mut anchor = 0usize;
    let mut pos = 4usize; // first 4 bytes are always literals

    let limit = input.len() - MF_LIMIT;

    while pos < limit {
        let h = hash4_lzo(&input[pos..]) & (HASH_SIZE - 1);
        let candidate = hash_table[h] as usize;
        hash_table[h] = pos as u32;

        if candidate < pos
            && pos - candidate <= MAX_OFFSET
            && candidate + 3 < input.len()
            && input[candidate..candidate + 4] == input[pos..pos + 4]
        {
            let gap = pos - anchor;

            // Ensure gap between matches is 0 or >= 4 for state=0 literal encoding
            if gap > 0 && gap < 4 {
                pos += 1;
                continue;
            }

            // Emit literal run if gap >= 4
            if gap >= 4 {
                emit_literal_run(&mut output, gap);
                output.extend_from_slice(&input[anchor..pos]);
            }

            // Extend match forward
            let mut match_len = 4;
            let max_match = (input.len() - LAST_LITERALS).saturating_sub(pos);
            while match_len < max_match && input[candidate + match_len] == input[pos + match_len] {
                match_len += 1;
            }

            let offset = pos - candidate;
            emit_match_instruction(&mut output, offset, match_len);

            pos += match_len;
            anchor = pos;

            // Re-hash at new position
            if pos < limit {
                hash_table[hash4_lzo(&input[pos..]) & (HASH_SIZE - 1)] = pos as u32;
            }
        } else {
            pos += 1;
        }
    }

    // Trailing literals (>= LAST_LITERALS = 5 >= 4)
    let trailing = input.len() - anchor;
    if trailing > 0 {
        emit_literal_run(&mut output, trailing);
        output.extend_from_slice(&input[anchor..]);
    }

    emit_end_marker(&mut output);
    output
}

/// Emit a literal run instruction (state=0 encoding, byte < 16).
///
/// Standard LZO1X: byte 1-15 → count = byte + 3 (4-18 literals).
/// byte 0 → extended: count = 18 + (255*zeros + nonzero_byte).
fn emit_literal_run(output: &mut Vec<u8>, count: usize) {
    debug_assert!(count >= 4, "literal run count must be >= 4");
    if count <= 18 {
        output.push((count - 3) as u8);
    } else {
        output.push(0);
        write_vle(output, count - 18);
    }
}

/// Write VLE (variable-length encoding): emit a zero byte for each full
/// chunk of 255 beyond the first, then the remainder as a non-zero
/// terminator byte (1..=255). The terminator must never be 0x00, since the
/// decoder treats 0x00 as a continuation byte.
fn write_vle(output: &mut Vec<u8>, mut value: usize) {
    debug_assert!(value >= 1, "VLE terminator byte must be non-zero");
    while value > 255 {
        output.push(0);
        value -= 255;
    }
    output.push(value as u8);
}

/// Emit a match instruction in standard LZO1X format with S=0.
///
/// Uses M2 (2-byte) for short matches at short offsets,
/// M3 (3-byte) for medium matches, M4 (3-byte) for long offsets.
fn emit_match_instruction(output: &mut Vec<u8>, offset: usize, match_len: usize) {
    if match_len <= 8 && offset <= 2048 {
        // M2: LLLDDDSS + H
        // length = (LLL) + 1, where LLL = (byte >> 5) in range 2-7
        // offset = (H << 3) + DDD + 1
        let off_m1 = offset - 1;
        let byte0 = ((match_len - 1) << 5) | ((off_m1 & 7) << 2); // S=0
        output.push(byte0 as u8);
        output.push((off_m1 >> 3) as u8);
    } else if offset <= 16384 {
        // M3: 001LLLLL + LE16((offset-1)<<2 | S)
        emit_m3(output, offset, match_len);
    } else {
        // M4: 0001HLLL + LE16(base<<2 | S)
        emit_m4(output, offset, match_len);
    }
}

/// Emit an M3 match: offset 1-16384, length 3+.
fn emit_m3(output: &mut Vec<u8>, offset: usize, match_len: usize) {
    if match_len <= 33 {
        output.push((0x20 | (match_len - 2)) as u8);
    } else {
        output.push(0x20);
        write_vle(output, match_len - 33);
    }
    let v = ((offset - 1) << 2) as u16; // S=0
    output.extend_from_slice(&v.to_le_bytes());
}

/// Emit an M4 match: offset 16385-49151, length 3+.
fn emit_m4(output: &mut Vec<u8>, offset: usize, match_len: usize) {
    let adj = offset - 16384;
    let h = (adj >> 14) & 1;
    let base = adj & 0x3FFF;

    if match_len <= 9 {
        output.push((0x10 | (h << 3) | (match_len - 2)) as u8);
    } else {
        output.push((0x10 | (h << 3)) as u8);
        write_vle(output, match_len - 9);
    }
    let v = (base as u16) << 2; // S=0
    output.extend_from_slice(&v.to_le_bytes());
}

/// Emit end-of-stream marker: M4 instruction with distance == 16384.
fn emit_end_marker(output: &mut Vec<u8>) {
    output.push(0x11); // M4: H=0, LLL=1 → length=3
    output.push(0x00);
    output.push(0x00);
}

/// Hash 4 bytes for LZO match finding.
fn hash4_lzo(data: &[u8]) -> usize {
    let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    (v.wrapping_mul(0x1E35A7BD) >> 18) as usize
}

fn write_u16_be(output: &mut Vec<u8>, v: u16) {
    output.extend_from_slice(&v.to_be_bytes());
}

fn write_u32_be(output: &mut Vec<u8>, v: u32) {
    output.extend_from_slice(&v.to_be_bytes());
}

/// Compress data and write to a writer.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::lzo::encode;
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
    fn test_lzop_header() {
        let compressed = encode(b"test");
        assert_eq!(&compressed[..9], LZOP_MAGIC);
    }

    #[test]
    fn test_empty_input() {
        let compressed = encode(b"");
        let len = compressed.len();
        assert_eq!(&compressed[len - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_roundtrip_short() {
        let data = b"Hello, LZO!";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABABABABABABABABABABABABABABABABABABABABABABABABABAB";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_m4_max_offset_roundtrip() {
        // Exercise M4 match encoding at the maximum offset (49151 bytes).
        // M4 handles offsets 16385..=49151 (MAX_OFFSET).
        // We place a recognizable pattern at the start and repeat it near offset 49151
        // so the encoder must emit an M4 instruction at or near max distance.
        let total_size = 50_000usize;
        let mut data = Vec::with_capacity(total_size);

        // 8-byte marker pattern at the very start.
        let marker: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        data.extend_from_slice(&marker);

        // Fill the gap with pseudo-random bytes so the hash table does not find
        // spurious matches before we reach our target offset.
        let gap = total_size - marker.len() - marker.len();
        for i in 0..gap {
            // Simple PRNG-style fill that avoids accidentally reproducing the marker.
            data.push(((i.wrapping_mul(179) ^ (i >> 5)) & 0xFF) as u8);
        }

        // Repeat the marker at position (total_size - 8).
        // Offset from here back to position 0 = total_size - 8 = 49992 — but that
        // exceeds MAX_OFFSET (49151). Instead place it exactly at offset 49151.
        // Position of second marker = marker.len() + (49151 - marker.len()) = 49151?
        // Actually offset = current_pos - match_pos.  We want offset <= 49151.
        // So place second copy at position 49151 (offset back to position 0 = 49151).
        data.truncate(49151);
        data.extend_from_slice(&marker);

        // Pad to make the trailing-literals requirement happy.
        while data.len() < 49151 + marker.len() + 8 {
            data.push(0xFF);
        }

        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed.len(), data.len());
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_gap_below_four_is_skipped() {
        let data = b"ABCDxxxxABCDyyyABCDzzzzzz";
        let compressed = compress_lzo1x(data);
        let expected = [
            5, b'A', b'B', b'C', b'D', b'x', b'x', b'x', b'x', 0x7C, 0x00, 10, b'y', b'y', b'y',
            b'A', b'B', b'C', b'D', b'z', b'z', b'z', b'z', b'z', b'z', 0x11, 0x00, 0x00,
        ];

        assert_eq!(compressed, expected);

        let wrapped = encode(data);
        let decompressed = super::super::decode::decode(&wrapped).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_lzo_vle_255_boundary() {
        // Regression test: write_vle must terminate with a non-zero byte.
        // 297 identical bytes produce an M3 match with match_len = 288,
        // which calls write_vle(288 - 33 = 255). The buggy encoder emitted
        // two 0x00 bytes, which the decoder treated as a continuation byte
        // and desynchronized the stream.
        let data = [b'A'; 297];
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_write_vle_boundary_values() {
        // VLE encodes value as floor((value - 1) / 255) zero continuation
        // bytes followed by a non-zero terminator in 1..=255.
        let mut out = Vec::new();

        write_vle(&mut out, 1);
        assert_eq!(out, [0x01]);

        write_vle(&mut out, 254);
        assert_eq!(out, [0x01, 0xFE]);

        out.clear();
        write_vle(&mut out, 255);
        assert_eq!(out, [0xFF]);

        out.clear();
        write_vle(&mut out, 256);
        assert_eq!(out, [0x00, 0x01]);

        out.clear();
        write_vle(&mut out, 510);
        assert_eq!(out, [0x00, 0xFF]);

        out.clear();
        write_vle(&mut out, 511);
        assert_eq!(out, [0x00, 0x00, 0x01]);
    }
}
