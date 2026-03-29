//! rzip encoding.
//!
//! This module emits the upstream `.rz` container structure: a 24-byte
//! `RZIP` header followed by one or more chunks, each chunk storing two
//! logical streams (metadata and literals) in the multiplexed format used
//! by the original implementation.
//!
//! The token stream shape matches upstream rzip:
//! - stream 0: `head:u8`, `len:u16`, and `offset:u32` for match tokens
//! - stream 1: literal bytes

use alloc::vec;
use alloc::vec::Vec;

use super::legacy_crc32;
use crate::compress::bzip2;
#[cfg(feature = "lzo")]
use crate::compress::lzo;
#[cfg(feature = "zlib")]
use crate::compress::zlib;

/// rzip file magic.
const MAGIC: &[u8; 4] = b"RZIP";
/// Upstream rzip major version.
const VERSION_MAJOR: u8 = 2;
/// Upstream rzip minor version.
const VERSION_MINOR: u8 = 1;

const NUM_STREAMS: usize = 2;
const CHUNK_MULTIPLE: usize = 100 * 1024 * 1024;
const CTYPE_GZIP: u8 = 1;
const CTYPE_LZO: u8 = 2;
const CTYPE_NONE: u8 = 3;
const CTYPE_BZIP2: u8 = 4;
const DEFAULT_LEVEL: u8 = 6;

/// Compression backend for rzip stream blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// bzip2 compression (default, upstream rzip).
    Bzip2,
    /// zlib/gzip compression (CTYPE 1).
    #[cfg(feature = "zlib")]
    Gzip,
    /// LZO compression (CTYPE 2).
    #[cfg(feature = "lzo")]
    Lzo,
    /// No compression (raw).
    None,
}

/// Rolling hash window for rzip match finding.
const RZIP_HASH_WINDOW: usize = 31;
/// Minimum match length for rzip.
const RZIP_MIN_MATCH: usize = 31;
/// Maximum number of rzip hash table entries.
const RZIP_HASH_BITS: usize = 16;
const RZIP_HASH_SIZE: usize = 1 << RZIP_HASH_BITS;

/// Encode input into an upstream-style `.rz` container.
#[must_use]
pub fn encode(input: &[u8]) -> Vec<u8> {
    encode_with_level(input, DEFAULT_LEVEL)
}

/// Encode input into an upstream-style `.rz` container with rzip level `0..=9`.
#[must_use]
pub fn encode_with_level(input: &[u8], level: u8) -> Vec<u8> {
    let mut output = Vec::new();
    write_file_header(&mut output, input.len() as u64);

    let chunk_size = chunk_size_for_level(level);
    let bzip_level = bzip_level_for_level(level);

    for chunk in input.chunks(chunk_size) {
        let crc = legacy_crc32(chunk);
        let (stream0, stream1) = encode_chunk(chunk, crc);
        let packed = pack_streams(&stream0, &stream1, bzip_level);
        output.extend_from_slice(&packed);
    }

    output
}

/// Encode input into an upstream-style `.rz` container using the specified
/// compression backend.
#[must_use]
pub fn encode_with_backend(input: &[u8], backend: Backend) -> Vec<u8> {
    let mut output = Vec::new();
    write_file_header(&mut output, input.len() as u64);

    let chunk_size = chunk_size_for_level(DEFAULT_LEVEL);

    for chunk in input.chunks(chunk_size) {
        let crc = legacy_crc32(chunk);
        let (stream0, stream1) = encode_chunk(chunk, crc);
        let packed = pack_streams_with_backend(&stream0, &stream1, backend);
        output.extend_from_slice(&packed);
    }

    output
}

/// Encode a single chunk into the upstream rzip token streams.
pub(crate) fn encode_chunk(chunk: &[u8], crc: u32) -> (Vec<u8>, Vec<u8>) {
    let mut stream0 = Vec::new();
    let mut stream1 = Vec::new();

    if chunk.len() < RZIP_MIN_MATCH {
        emit_rzip_literal(&mut stream0, &mut stream1, chunk);
        emit_stream_terminator(&mut stream0, crc);
        return (stream0, stream1);
    }

    let mut hash_table = vec![u32::MAX; RZIP_HASH_SIZE];

    let mut anchor = 0usize;
    let mut pos = 0usize;
    let limit = chunk.len().saturating_sub(RZIP_MIN_MATCH);

    while pos < limit {
        if pos + RZIP_HASH_WINDOW > chunk.len() {
            break;
        }

        let h = rolling_hash(&chunk[pos..pos + RZIP_HASH_WINDOW]) & (RZIP_HASH_SIZE - 1);
        let candidate = hash_table[h] as usize;
        hash_table[h] = pos as u32;

        if candidate < pos
            && candidate != u32::MAX as usize
            && chunk[candidate..candidate + RZIP_MIN_MATCH] == chunk[pos..pos + RZIP_MIN_MATCH]
        {
            let mut match_len = RZIP_MIN_MATCH;
            let max_len = chunk.len() - pos;
            while match_len < max_len
                && candidate + match_len < chunk.len()
                && chunk[candidate + match_len] == chunk[pos + match_len]
            {
                match_len += 1;
            }

            if pos > anchor {
                emit_rzip_literal(&mut stream0, &mut stream1, &chunk[anchor..pos]);
            }

            let offset = pos - candidate;
            emit_rzip_match(&mut stream0, offset, match_len);

            pos += match_len;
            anchor = pos;
        } else {
            pos += 1;
        }
    }

    if anchor < chunk.len() {
        emit_rzip_literal(&mut stream0, &mut stream1, &chunk[anchor..]);
    }

    emit_stream_terminator(&mut stream0, crc);
    (stream0, stream1)
}

/// Pack two logical rzip streams into the upstream multiplexed chunk layout.
pub(crate) fn pack_streams(stream0: &[u8], stream1: &[u8], bzip_level: u8) -> Vec<u8> {
    let mut output = vec![0u8; NUM_STREAMS * 13];
    for stream_index in 0..NUM_STREAMS {
        output[stream_index * 13] = CTYPE_NONE;
    }
    let mut next_block_pos = output.len() as u32;

    for (stream_index, stream) in [stream0, stream1].iter().enumerate() {
        if stream.is_empty() {
            continue;
        }

        let (ctype, payload) = maybe_compress_stream(stream, bzip_level);
        let header_pos = stream_index * 13;
        write_u32_at(&mut output, header_pos + 9, next_block_pos);

        output.push(ctype);
        write_u32(&mut output, payload.len() as u32);
        write_u32(&mut output, stream.len() as u32);
        write_u32(&mut output, 0);
        output.extend_from_slice(&payload);
        next_block_pos = output.len() as u32;
    }

    output
}

/// Pack two logical rzip streams using the specified compression backend.
pub(crate) fn pack_streams_with_backend(
    stream0: &[u8],
    stream1: &[u8],
    backend: Backend,
) -> Vec<u8> {
    let mut output = vec![0u8; NUM_STREAMS * 13];
    for stream_index in 0..NUM_STREAMS {
        output[stream_index * 13] = CTYPE_NONE;
    }
    let mut next_block_pos = output.len() as u32;

    for (stream_index, stream) in [stream0, stream1].iter().enumerate() {
        if stream.is_empty() {
            continue;
        }

        let (ctype, payload) = maybe_compress_stream_with_backend(stream, backend);
        let header_pos = stream_index * 13;
        write_u32_at(&mut output, header_pos + 9, next_block_pos);

        output.push(ctype);
        write_u32(&mut output, payload.len() as u32);
        write_u32(&mut output, stream.len() as u32);
        write_u32(&mut output, 0);
        output.extend_from_slice(&payload);
        next_block_pos = output.len() as u32;
    }

    output
}

fn maybe_compress_stream_with_backend(stream: &[u8], backend: Backend) -> (u8, Vec<u8>) {
    if stream.is_empty() {
        return (CTYPE_NONE, stream.to_vec());
    }

    match backend {
        Backend::None => (CTYPE_NONE, stream.to_vec()),
        Backend::Bzip2 => {
            let compressed = bzip2::encode::encode_with_level(stream, 9);
            if compressed.len() < stream.len() {
                (CTYPE_BZIP2, compressed)
            } else {
                (CTYPE_NONE, stream.to_vec())
            }
        }
        #[cfg(feature = "zlib")]
        Backend::Gzip => {
            let compressed = zlib::encode::encode(stream);
            if compressed.len() < stream.len() {
                (CTYPE_GZIP, compressed)
            } else {
                (CTYPE_NONE, stream.to_vec())
            }
        }
        #[cfg(feature = "lzo")]
        Backend::Lzo => {
            let compressed = lzo::encode::compress_lzo1x(stream);
            if compressed.len() < stream.len() {
                (CTYPE_LZO, compressed)
            } else {
                (CTYPE_NONE, stream.to_vec())
            }
        }
    }
}

fn write_file_header(output: &mut Vec<u8>, expected_size: u64) {
    output.extend_from_slice(MAGIC);
    output.push(VERSION_MAJOR);
    output.push(VERSION_MINOR);
    output.extend_from_slice(&(expected_size as u32).to_be_bytes());
    output.extend_from_slice(&((expected_size >> 32) as u32).to_be_bytes());
    output.extend_from_slice(&[0u8; 10]);
}

const fn bzip_level_for_level(level: u8) -> u8 {
    match level {
        0 => 0,
        1 => 1,
        2 => 3,
        3 => 5,
        4 => 7,
        _ => 9,
    }
}

const fn chunk_size_for_level(level: u8) -> usize {
    if level == 0 {
        CHUNK_MULTIPLE
    } else {
        level as usize * CHUNK_MULTIPLE
    }
}

fn maybe_compress_stream(stream: &[u8], bzip_level: u8) -> (u8, Vec<u8>) {
    if bzip_level == 0 || stream.is_empty() {
        return (CTYPE_NONE, stream.to_vec());
    }

    let compressed = bzip2::encode::encode_with_level(stream, bzip_level);
    if compressed.len() < stream.len() {
        (CTYPE_BZIP2, compressed)
    } else {
        (CTYPE_NONE, stream.to_vec())
    }
}

fn emit_stream_terminator(stream0: &mut Vec<u8>, crc: u32) {
    stream0.push(0x00);
    stream0.extend_from_slice(&0u16.to_le_bytes());
    stream0.extend_from_slice(&crc.to_le_bytes());
}

/// Emit rzip literal tokens (head=0, length=u16LE, data in stream1).
fn emit_rzip_literal(stream0: &mut Vec<u8>, stream1: &mut Vec<u8>, data: &[u8]) {
    for chunk in data.chunks(u16::MAX as usize) {
        stream0.push(0x00);
        stream0.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        stream1.extend_from_slice(chunk);
    }
}

/// Emit rzip match tokens (head=1, length=u16LE, offset=u32LE).
fn emit_rzip_match(stream0: &mut Vec<u8>, offset: usize, mut length: usize) {
    while length > 0 {
        let chunk_len = length.min(u16::MAX as usize);
        stream0.push(0x01);
        stream0.extend_from_slice(&(chunk_len as u16).to_le_bytes());
        stream0.extend_from_slice(&(offset as u32).to_le_bytes());
        length -= chunk_len;
    }
}

/// Simple rolling hash for rzip match finding.
fn rolling_hash(data: &[u8]) -> usize {
    let mut h: u32 = 0;
    for &b in data {
        h = h.wrapping_mul(0x0808_8405).wrapping_add(b as u32);
    }
    h as usize
}

/// Compute minimum bytes needed to represent a value.
pub const fn compute_chunk_bytes(size: u64) -> u8 {
    if size == 0 {
        return 1;
    }
    let mut bytes = 0u8;
    let mut v = size;
    while v > 0 {
        bytes += 1;
        v >>= 8;
    }
    bytes
}

/// Write a value as `n` bytes little-endian.
pub fn write_le_n(output: &mut Vec<u8>, value: u64, n: usize) {
    let bytes = value.to_le_bytes();
    output.extend_from_slice(&bytes[..n]);
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn write_u32_at(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::rzip::decode;

    #[test]
    fn test_header_format() {
        let compressed = encode(b"hello");
        assert_eq!(&compressed[..4], b"RZIP");
        assert_eq!(compressed[4], VERSION_MAJOR);
        assert_eq!(compressed[5], VERSION_MINOR);
    }

    #[test]
    fn test_roundtrip_public_container() {
        let data = b"Hello, upstream rzip! Hello, upstream rzip!";
        let compressed = encode(data);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let compressed = encode(b"");
        let decoded = decode::decode(&compressed).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_long_match_is_split_into_u16_chunks() {
        let data = vec![b'A'; (u16::MAX as usize) + 1024];
        let (stream0, _) = encode_chunk(&data, legacy_crc32(&data));

        let mut pos = 0usize;
        let mut saw_split_match = false;
        while pos + 3 <= stream0.len() {
            let head = stream0[pos];
            let len = u16::from_le_bytes([stream0[pos + 1], stream0[pos + 2]]) as usize;
            pos += 3;
            if head == 0 && len == 0 {
                break;
            }
            match head {
                0x00 => {}
                0x01 => {
                    assert!(len <= u16::MAX as usize);
                    pos += 4;
                    if len == u16::MAX as usize {
                        saw_split_match = true;
                    }
                }
                _ => panic!("unexpected tag {head}"),
            }
        }

        assert!(saw_split_match, "expected a split u16-sized match token");
    }

    #[test]
    fn test_pack_streams_uses_upstream_raw_sentinels() {
        let packed = pack_streams(b"\x00\x01\x02", b"abc", 9);
        assert_eq!(packed[0], CTYPE_NONE);
        assert_eq!(packed[13], CTYPE_NONE);
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn test_encode_with_backend_gzip_roundtrip() {
        let data = b"gzip backend roundtrip in encoder tests";
        let compressed = encode_with_backend(data, Backend::Gzip);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[cfg(feature = "lzo")]
    #[test]
    fn test_encode_with_backend_lzo_roundtrip() {
        let data = b"lzo backend roundtrip in encoder tests";
        let compressed = encode_with_backend(data, Backend::Lzo);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_with_backend_none_roundtrip() {
        let data = b"no compression backend roundtrip";
        let compressed = encode_with_backend(data, Backend::None);
        let decoded = decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }
}
