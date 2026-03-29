//! lrzip compression.
//!
//! Produces `.lrz` streams that round-trip with this crate and have validated
//! interoperability with the system `lrzip` tool across the supported backend
//! matrix.
//!
//! The format uses rzip-style long-range redundancy reduction with two streams
//! (metadata + literals), followed by a configurable backend compression.
//!
//! Current system-tool coverage confirms system `lrzip -d` consumption of the
//! crate's LZMA, bzip2, LZO, zlib/gzip, ZPAQ, and uncompressed backend outputs
//! on the exercised single-file payloads. The encoder writes lrzip's
//! variable-width match offset field (`chunk_bytes`) rather than reusing the
//! fixed-width `.rz` stream verbatim.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lrzip::{decode, encode};
//!
//! let data = b"Hello, lrzip!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::compress::lzma::LzmaProperties;
use crate::compress::rzip;

// ── lrzip format constants ──────────────────────────────────────────

/// lrzip file magic number: "LRZI".
const MAGIC: &[u8; 4] = b"LRZI";

/// Version.
const VERSION_MAJOR: u8 = 0;
const VERSION_MINOR: u8 = 6;

/// Number of streams (metadata + literals).
const NUM_STREAMS: usize = 2;

/// Compression type values matching real lrzip.
const CTYPE_NONE: u8 = 3;
const CTYPE_BZIP2: u8 = 4;
const CTYPE_LZO: u8 = 5;
const CTYPE_LZMA: u8 = 6;
const CTYPE_GZIP: u8 = 7;
const CTYPE_ZPAQ: u8 = 8;

/// LZMA properties: lc=3, lp=0, pb=2 → 3 + 0*9 + 2*45 = 93 = 0x5D.
const LZMA_PROPS_BYTE: u8 = LzmaProperties::LZIP.to_props_byte();

/// Default dictionary size for LZMA.
const LZMA_DICT_SIZE: u32 = 4096;

/// Chunk size limit (~100MB as in real lrzip).
const CHUNK_MULTIPLE: usize = 100 * 1024 * 1024;

/// Backend compression type for lrzip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    /// No backend compression (CTYPE_NONE = 3).
    None,
    /// bzip2 backend (CTYPE_BZIP2 = 4).
    Bzip2,
    /// LZO backend (CTYPE_LZO = 5).
    Lzo,
    /// LZMA backend (CTYPE_LZMA = 6).
    Lzma,
    /// zlib/gzip backend (CTYPE_GZIP = 7).
    Gzip,
    /// ZPAQ backend (CTYPE_ZPAQ = 8).
    Zpaq,
}

/// Compress data using lrzip format with LZMA backend (default).
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lrzip::{decode, encode};
///
/// let data = b"Hello, lrzip!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with(input, CompressionType::Lzma)
}

/// Compress data using lrzip format with the specified backend compression.
///
/// # Examples
///
/// ```
/// use archive::compress::lrzip::{decode, encode};
///
/// let data = b"Hello, lrzip bzip2!";
/// let compressed = encode::encode_with(data, encode::CompressionType::Bzip2);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode_with(input: &[u8], compression: CompressionType) -> Vec<u8> {
    let mut output = Vec::new();

    // ── File header (24 bytes) ──────────────────────────────────
    output.extend_from_slice(MAGIC); // 0-3
    output.push(VERSION_MAJOR); // 4
    output.push(VERSION_MINOR); // 5
    // File size (8 bytes LE) or 0 if empty
    output.extend_from_slice(&(input.len() as u64).to_le_bytes()); // 6-13
    output.extend_from_slice(&[0u8; 2]); // 14-15: unused
    // LZMA properties (5 bytes): props_byte + dict_size (4 LE)
    output.push(LZMA_PROPS_BYTE); // 16
    output.extend_from_slice(&LZMA_DICT_SIZE.to_le_bytes()); // 17-20
    output.push(0); // 21: no MD5
    output.push(0); // 22: no encryption
    output.push(0); // 23: unused
    debug_assert_eq!(output.len(), 24);

    if input.is_empty() {
        // Write a single empty chunk with eof=1
        write_empty_chunk(&mut output);
        return output;
    }

    // ── Process chunks ──────────────────────────────────────────
    let chunks: Vec<&[u8]> = input.chunks(CHUNK_MULTIPLE).collect();
    let num_chunks = chunks.len();

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == num_chunks - 1;
        write_chunk(&mut output, chunk, is_last, compression);
    }

    output
}

/// Write a chunk of data in lrzip format.
fn write_chunk(output: &mut Vec<u8>, chunk: &[u8], is_last: bool, compression: CompressionType) {
    let crc = rzip::legacy_crc32(chunk);
    let mut chunk_bytes = rzip::encode::compute_chunk_bytes(chunk.len() as u64) as usize;
    let (stream0, stream1, s0_compressed, s0_ctype, s1_compressed, s1_ctype) = loop {
        let (rzip_stream0, stream1) = rzip::encode::encode_chunk(chunk, crc);
        let stream0 = reencode_stream0_for_lrzip(&rzip_stream0, chunk_bytes).expect(
            "rzip::encode::encode_chunk emits a valid token stream that lrzip can re-encode",
        );
        let (s0_compressed, s0_ctype) = compress_stream(&stream0, compression);
        let (s1_compressed, s1_ctype) = compress_stream(&stream1, compression);

        let stream_header_size = 1 + 3 * chunk_bytes;
        let block_header_size = 1 + 3 * chunk_bytes;
        let data_start = NUM_STREAMS * stream_header_size;
        let s1_block_offset = data_start + block_header_size + s0_compressed.len();
        let max_encoded_offset = s1_block_offset;
        let required =
            rzip::encode::compute_chunk_bytes((chunk.len().max(max_encoded_offset)) as u64)
                as usize;

        if required == chunk_bytes {
            break (
                stream0,
                stream1,
                s0_compressed,
                s0_ctype,
                s1_compressed,
                s1_ctype,
            );
        }
        chunk_bytes = required;
    };

    // ── Chunk header ────────────────────────────────────────────
    output.push(chunk_bytes as u8);
    output.push(if is_last { 1 } else { 0 });
    rzip::encode::write_le_n(output, chunk.len() as u64, chunk_bytes);

    // ── Calculate file offsets for data blocks ──────────────────
    let cb = chunk_bytes;
    let stream_header_size = 1 + 3 * cb; // ctype + c_len + u_len + last_head
    let block_header_size = 1 + 3 * cb; // ctype + c_len + u_len + last_head

    let data_start = NUM_STREAMS * stream_header_size;
    let s0_block_offset = data_start;
    let s1_block_offset = data_start + block_header_size + s0_compressed.len();

    // ── Stream 0 header ─────────────────────────────────────────
    output.push(s0_ctype);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, s0_block_offset as u64, cb);

    // ── Stream 1 header ─────────────────────────────────────────
    output.push(s1_ctype);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, s1_block_offset as u64, cb);

    // ── Stream 0 data block ─────────────────────────────────────
    output.push(s0_ctype);
    rzip::encode::write_le_n(output, s0_compressed.len() as u64, cb);
    rzip::encode::write_le_n(output, stream0.len() as u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb); // last_head = 0 (no next block)
    output.extend_from_slice(&s0_compressed);

    // ── Stream 1 data block ─────────────────────────────────────
    output.push(s1_ctype);
    rzip::encode::write_le_n(output, s1_compressed.len() as u64, cb);
    rzip::encode::write_le_n(output, stream1.len() as u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb); // last_head = 0 (no next block)
    output.extend_from_slice(&s1_compressed);
}

fn reencode_stream0_for_lrzip(stream0: &[u8], chunk_bytes: usize) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(stream0.len());
    let mut pos = 0usize;

    while pos + 3 <= stream0.len() {
        let head = stream0[pos];
        let len = u16::from_le_bytes([stream0[pos + 1], stream0[pos + 2]]) as usize;
        pos += 3;

        output.push(head);
        output.extend_from_slice(&(len as u16).to_le_bytes());

        match head {
            0x00 if len == 0 => {
                if pos + 4 > stream0.len() {
                    return None;
                }
                output.extend_from_slice(&stream0[pos..pos + 4]);
                return Some(output);
            }
            0x00 => {}
            _ => {
                if pos + 4 > stream0.len() {
                    return None;
                }
                let offset = u32::from_le_bytes([
                    stream0[pos],
                    stream0[pos + 1],
                    stream0[pos + 2],
                    stream0[pos + 3],
                ]) as usize;
                pos += 4;
                let offset = u64::try_from(offset).ok()?;
                if chunk_bytes > 8 || (chunk_bytes < 8 && offset >= (1u64 << (chunk_bytes * 8))) {
                    return None;
                }
                output.extend_from_slice(&offset.to_le_bytes()[..chunk_bytes]);
            }
        }
    }

    None
}

/// Write an empty chunk (for empty input).
fn write_empty_chunk(output: &mut Vec<u8>) {
    let chunk_bytes: u8 = 1;
    let cb = chunk_bytes as usize;

    // Chunk header
    output.push(chunk_bytes);
    output.push(1); // eof = 1
    rzip::encode::write_le_n(output, 0u64, cb); // chunk_size = 0

    // CRC for empty data
    let crc = rzip::legacy_crc32(&[]);
    let mut stream0 = Vec::new();
    stream0.extend_from_slice(&crc.to_le_bytes());
    let stream_header_size = 1 + 3 * cb;
    let data_start = NUM_STREAMS * stream_header_size;

    let block_header_size = 1 + 3 * cb;
    let s0_block_offset = data_start;
    let s1_block_offset = data_start + block_header_size + stream0.len();

    // Stream 0 header
    output.push(CTYPE_NONE);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, s0_block_offset as u64, cb);

    // Stream 1 header
    output.push(CTYPE_NONE);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, s1_block_offset as u64, cb);

    // Stream 0 data block
    output.push(CTYPE_NONE);
    rzip::encode::write_le_n(output, stream0.len() as u64, cb);
    rzip::encode::write_le_n(output, stream0.len() as u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    output.extend_from_slice(&stream0);

    // Stream 1 data block (empty)
    output.push(CTYPE_NONE);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
    rzip::encode::write_le_n(output, 0u64, cb);
}

/// Compress a stream with the given backend; fall back to CTYPE_NONE if it doesn't shrink.
fn compress_stream(data: &[u8], compression: CompressionType) -> (Vec<u8>, u8) {
    if data.is_empty() {
        return (Vec::new(), CTYPE_NONE);
    }

    let (compressed, ctype) = match compression {
        CompressionType::None => {
            return (data.to_vec(), CTYPE_NONE);
        }
        CompressionType::Lzma => {
            let c = crate::compress::lzma::lzma_encode(data, LZMA_DICT_SIZE);
            (c, CTYPE_LZMA)
        }
        CompressionType::Bzip2 => {
            let c = crate::compress::bzip2::encode::encode(data);
            (c, CTYPE_BZIP2)
        }
        CompressionType::Lzo => {
            let c = crate::compress::lzo::encode::compress_lzo1x(data);
            (c, CTYPE_LZO)
        }
        CompressionType::Gzip => {
            let c = crate::compress::zlib::encode::encode(data);
            (c, CTYPE_GZIP)
        }
        CompressionType::Zpaq => {
            let c = crate::compress::zpaq::encode::encode(data, 2);
            (c, CTYPE_ZPAQ)
        }
    };

    if compressed.len() < data.len() {
        (compressed, ctype)
    } else {
        (data.to_vec(), CTYPE_NONE)
    }
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
/// use archive::compress::lrzip::encode;
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
    fn test_header_format() {
        let compressed = encode(b"A");
        assert_eq!(&compressed[..4], b"LRZI");
        assert_eq!(compressed[4], VERSION_MAJOR);
        assert_eq!(compressed[5], VERSION_MINOR);
        assert!(compressed.len() > 24); // header + chunk data
    }

    #[test]
    fn test_header_file_size() {
        let data = b"Hello, lrzip!";
        let compressed = encode(data);
        let stored_size = u64::from_le_bytes([
            compressed[6],
            compressed[7],
            compressed[8],
            compressed[9],
            compressed[10],
            compressed[11],
            compressed[12],
            compressed[13],
        ]);
        assert_eq!(stored_size, data.len() as u64);
    }

    #[test]
    fn test_lzma_properties() {
        let compressed = encode(b"test");
        // Byte 16: LZMA props byte (0x5D = lc=3, lp=0, pb=2)
        assert_eq!(compressed[16], 0x5D);
        // Bytes 17-20: dict_size LE
        let dict_size = u32::from_le_bytes([
            compressed[17],
            compressed[18],
            compressed[19],
            compressed[20],
        ]);
        assert_eq!(dict_size, LZMA_DICT_SIZE);
    }

    #[test]
    fn test_empty_input() {
        let compressed = encode(b"");
        assert!(compressed.len() > 24); // header + chunk data
        let stored_size = u64::from_le_bytes([
            compressed[6],
            compressed[7],
            compressed[8],
            compressed[9],
            compressed[10],
            compressed[11],
            compressed[12],
            compressed[13],
        ]);
        assert_eq!(stored_size, 0);
    }

    #[test]
    fn test_roundtrip_short() {
        let data = b"Hello, lrzip!";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABCDEFGH".repeat(1000);
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_large() {
        let data: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_stream_block_offsets_valid() {
        let data = b"Hello, lrzip block offsets!";
        let compressed = encode(data);
        let cb = compressed[24] as usize; // chunk_bytes
        let mut pos = 24 + 2 + cb;
        let chunk_base = pos;
        pos += 1; // ctype
        pos += cb; // c_len
        pos += cb; // u_len
        let s0_offset = read_le_n_test(&compressed, pos, cb);
        pos += cb;
        pos += 1; // ctype
        pos += cb; // c_len
        pos += cb; // u_len
        let s1_offset = read_le_n_test(&compressed, pos, cb);
        pos += cb;
        assert_eq!(chunk_base + s0_offset, pos);
        let s0_c_len = read_le_n_test(&compressed, chunk_base + s0_offset + 1, cb);
        let s0_block_data_end = chunk_base + s0_offset + 1 + 3 * cb + s0_c_len;
        assert_eq!(chunk_base + s1_offset, s0_block_data_end);
    }

    fn read_le_n_test(data: &[u8], pos: usize, n: usize) -> usize {
        let mut bytes = [0u8; 8];
        bytes[..n].copy_from_slice(&data[pos..pos + n]);
        u64::from_le_bytes(bytes) as usize
    }

    fn parse_chunk_headers(data: &[u8]) -> Vec<(usize, usize, bool)> {
        let mut pos = 24;
        let mut chunks = Vec::new();

        loop {
            let cb = data[pos] as usize;
            let eof = data[pos + 1] != 0;
            pos += 2;
            let chunk_size = read_le_n_test(data, pos, cb);
            pos += cb;

            for _ in 0..NUM_STREAMS {
                pos += 1;
                pos += cb;
                pos += cb;
                pos += cb;
            }

            for _ in 0..NUM_STREAMS {
                pos += 1;
                let c_len = read_le_n_test(data, pos, cb);
                pos += cb;
                pos += cb;
                pos += cb;
                pos += c_len;
            }

            chunks.push((cb, chunk_size, eof));
            if eof {
                break;
            }
        }

        chunks
    }

    #[test]
    fn test_compute_chunk_bytes() {
        assert_eq!(rzip::encode::compute_chunk_bytes(0), 1);
        assert_eq!(rzip::encode::compute_chunk_bytes(1), 1);
        assert_eq!(rzip::encode::compute_chunk_bytes(255), 1);
        assert_eq!(rzip::encode::compute_chunk_bytes(256), 2);
        assert_eq!(rzip::encode::compute_chunk_bytes(65535), 2);
        assert_eq!(rzip::encode::compute_chunk_bytes(65536), 3);
    }

    #[test]
    fn test_reencode_stream0_for_lrzip_reduces_match_offset_width() {
        let input = b"hello lrzip repeated ".repeat(64);
        let crc = rzip::legacy_crc32(&input);
        let (rzip_stream0, _) = rzip::encode::encode_chunk(&input, crc);
        let lrzip_stream0 = reencode_stream0_for_lrzip(&rzip_stream0, 2).unwrap();

        assert!(lrzip_stream0.len() < rzip_stream0.len());
        assert_eq!(&lrzip_stream0[..3], &[0x00, 0x15, 0x00]);
        assert_eq!(lrzip_stream0[3], 0x01);
        assert_eq!(&lrzip_stream0[6..8], &[0x15, 0x00]);
    }

    #[test]
    fn test_min_match_boundary() {
        let data: Vec<u8> = (0..31u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_below_min_match() {
        let data: Vec<u8> = (0..30u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_bzip2() {
        let data = b"Hello, lrzip bzip2!";
        let compressed = encode_with(data, CompressionType::Bzip2);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_lzo() {
        let data = b"Hello, lrzip LZO! ".repeat(10);
        let compressed = encode_with(&data, CompressionType::Lzo);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_gzip() {
        let data = b"Hello, lrzip gzip!";
        let compressed = encode_with(data, CompressionType::Gzip);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_zpaq() {
        let data = b"Hello, lrzip ZPAQ!";
        let compressed = encode_with(data, CompressionType::Zpaq);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_none() {
        let data = b"Hello, lrzip none!";
        let compressed = encode_with(data, CompressionType::None);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_chunk_multiple_boundary() {
        let data = vec![b'A'; CHUNK_MULTIPLE + 64];
        let compressed = encode_with(&data, CompressionType::None);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_chunk_multiple_boundary_splits_into_two_chunks() {
        let data = vec![b'A'; CHUNK_MULTIPLE + 64];
        let compressed = encode_with(&data, CompressionType::None);
        let chunks = parse_chunk_headers(&compressed);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (4, CHUNK_MULTIPLE, false));
        assert_eq!(chunks[1], (1, 64, true));
    }

    #[test]
    fn test_compress_stream_falls_back_for_tiny_backend_matrix() {
        let data: &[u8] = b"A";

        for backend in [
            CompressionType::Lzma,
            CompressionType::Bzip2,
            CompressionType::Lzo,
            CompressionType::Gzip,
            CompressionType::Zpaq,
        ] {
            let (compressed, ctype) = compress_stream(data, backend);
            assert_eq!(ctype, CTYPE_NONE, "backend {backend:?}");
            assert_eq!(compressed, data, "backend {backend:?}");
        }
    }

    #[test]
    fn test_compress_stream_keeps_lzma_backend_for_literal_heavy_input() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (compressed, ctype) = compress_stream(&data, CompressionType::Lzma);
        assert_eq!(ctype, CTYPE_LZMA);
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_roundtrip_long_rzip_match_length() {
        let data = vec![b'A'; (u16::MAX as usize) + 4096];
        let compressed = encode_with(&data, CompressionType::None);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_header_version_minor_updated() {
        let compressed = encode(b"version");
        assert_eq!(compressed[5], VERSION_MINOR);
    }
}
