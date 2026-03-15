//! rzip decoding.
//!
//! Decodes the upstream `.rz` container and the two-stream token format used
//! inside it.

use alloc::vec::Vec;

use super::legacy_crc32;
use crate::compress::bzip2;
#[cfg(feature = "lzo")]
use crate::compress::lzo;
#[cfg(feature = "zlib")]
use crate::compress::zlib;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"RZIP";
const VERSION_MAJOR: u8 = 2;
const VERSION_MINOR: u8 = 1;
const NUM_STREAMS: usize = 2;
const CTYPE_GZIP: u8 = 1;
const CTYPE_LZO: u8 = 2;
const CTYPE_NONE: u8 = 3;
const CTYPE_BZIP2: u8 = 4;

/// Decode an upstream-style `.rz` container.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() < 24 {
        return Err(Error::InvalidData("rzip: input too short"));
    }
    if &input[..4] != MAGIC {
        return Err(Error::InvalidData("rzip: invalid magic"));
    }
    if input[4] != VERSION_MAJOR || input[5] != VERSION_MINOR {
        return Err(Error::Unsupported("rzip: unsupported version"));
    }
    if input[14..24].iter().any(|&byte| byte != 0) {
        return Err(Error::InvalidData(
            "rzip: reserved header bytes must be zero",
        ));
    }

    let expected_size = u32::from_be_bytes([input[6], input[7], input[8], input[9]]) as u64
        | ((u32::from_be_bytes([input[10], input[11], input[12], input[13]]) as u64) << 32);

    let mut output = Vec::with_capacity(expected_size.min(4 * 1024 * 1024) as usize);
    let mut pos = 24usize;
    while (output.len() as u64) < expected_size {
        if pos >= input.len() {
            return Err(Error::UnexpectedEof);
        }
        let consumed = decode_chunk_container(&input[pos..], &mut output)?;
        pos += consumed;
    }

    if output.len() as u64 != expected_size {
        return Err(Error::InvalidData("rzip: output size mismatch"));
    }
    if pos != input.len() {
        return Err(Error::InvalidData("rzip: trailing data after final chunk"));
    }

    Ok(output)
}

fn decode_chunk_container(chunk: &[u8], dst: &mut Vec<u8>) -> Result<usize, Error> {
    if chunk.len() < NUM_STREAMS * 13 {
        return Err(Error::UnexpectedEof);
    }

    let stream0_head = read_u32_le(&chunk[9..13])?;
    let stream1_head = read_u32_le(&chunk[22..26])?;
    let mut consumed = NUM_STREAMS * 13;

    let stream0 = read_stream_chain(chunk, stream0_head, &mut consumed)?;
    let stream1 = read_stream_chain(chunk, stream1_head, &mut consumed)?;
    decode_streams(&stream0, &stream1, dst)?;
    Ok(consumed)
}

fn read_stream_chain(chunk: &[u8], mut head: u32, consumed: &mut usize) -> Result<Vec<u8>, Error> {
    let mut stream = Vec::new();

    while head != 0 {
        let pos = head as usize;
        if pos + 13 > chunk.len() {
            return Err(Error::UnexpectedEof);
        }
        let ctype = chunk[pos];
        let c_len = read_u32_le(&chunk[pos + 1..pos + 5])? as usize;
        let u_len = read_u32_le(&chunk[pos + 5..pos + 9])? as usize;
        let next = read_u32_le(&chunk[pos + 9..pos + 13])?;
        let data_start = pos + 13;
        let data_end = data_start + c_len;
        if data_end > chunk.len() {
            return Err(Error::UnexpectedEof);
        }

        let decoded = match ctype {
            CTYPE_NONE => {
                if c_len != u_len {
                    return Err(Error::InvalidData("rzip: raw stream length mismatch"));
                }
                chunk[data_start..data_end].to_vec()
            }
            #[cfg(feature = "zlib")]
            CTYPE_GZIP => {
                let decoded = zlib::decode::decode(&chunk[data_start..data_end])?;
                if decoded.len() != u_len {
                    return Err(Error::InvalidData(
                        "rzip: decompressed stream length mismatch",
                    ));
                }
                decoded
            }
            #[cfg(not(feature = "zlib"))]
            CTYPE_GZIP => {
                return Err(Error::Unsupported(
                    "rzip: gzip stream compression requires 'zlib' feature",
                ));
            }
            #[cfg(feature = "lzo")]
            CTYPE_LZO => {
                let decoded = lzo::decode::decompress_lzo1x(&chunk[data_start..data_end], u_len)?;
                if decoded.len() != u_len {
                    return Err(Error::InvalidData(
                        "rzip: decompressed stream length mismatch",
                    ));
                }
                decoded
            }
            #[cfg(not(feature = "lzo"))]
            CTYPE_LZO => {
                return Err(Error::Unsupported(
                    "rzip: lzo stream compression requires 'lzo' feature",
                ));
            }
            CTYPE_BZIP2 => {
                let decoded = bzip2::decode::decode(&chunk[data_start..data_end])?;
                if decoded.len() != u_len {
                    return Err(Error::InvalidData(
                        "rzip: decompressed stream length mismatch",
                    ));
                }
                decoded
            }
            _ => {
                return Err(Error::Unsupported(
                    "rzip: unsupported stream compression type",
                ));
            }
        };

        stream.extend_from_slice(&decoded);
        *consumed += 13 + c_len;
        head = next;
    }

    Ok(stream)
}

/// Decode upstream rzip token streams into `dst`.
pub(crate) fn decode_streams(
    stream0: &[u8],
    stream1: &[u8],
    dst: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut s0pos = 0usize;
    let mut s1pos = 0usize;
    let chunk_start = dst.len();

    while s0pos + 3 <= stream0.len() {
        let head = stream0[s0pos];
        let length = u16::from_le_bytes([stream0[s0pos + 1], stream0[s0pos + 2]]) as usize;
        s0pos += 3;

        match head {
            0x00 if length == 0 => {
                if s0pos + 4 > stream0.len() {
                    return Err(Error::InvalidData("rzip: missing CRC in stream"));
                }
                let expected_crc = u32::from_le_bytes([
                    stream0[s0pos],
                    stream0[s0pos + 1],
                    stream0[s0pos + 2],
                    stream0[s0pos + 3],
                ]);
                let actual_crc = legacy_crc32(&dst[chunk_start..]);
                if actual_crc != expected_crc {
                    return Err(Error::ChecksumMismatch {
                        expected: expected_crc,
                        actual: actual_crc,
                    });
                }
                return Ok(());
            }
            0x00 => {
                if s1pos + length > stream1.len() {
                    return Err(Error::UnexpectedEof);
                }
                dst.extend_from_slice(&stream1[s1pos..s1pos + length]);
                s1pos += length;
            }
            _ => {
                if s0pos + 4 > stream0.len() {
                    return Err(Error::UnexpectedEof);
                }
                let offset = read_u32_le(&stream0[s0pos..s0pos + 4])? as usize;
                s0pos += 4;

                let current_pos = dst.len() - chunk_start;
                if offset == 0 || offset > current_pos {
                    return Err(Error::InvalidData("rzip: match offset out of range"));
                }

                let match_start = dst.len() - offset;
                for i in 0..length {
                    let b = dst[match_start + i];
                    dst.push(b);
                }
            }
        }
    }

    Err(Error::InvalidData("rzip: unterminated chunk stream"))
}

fn read_u32_le(data: &[u8]) -> Result<u32, Error> {
    if data.len() < 4 {
        return Err(Error::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// Read `n` bytes as a little-endian u64, advancing `pos`.
pub fn read_le_n_at(data: &[u8], pos: &mut usize, n: usize) -> Result<u64, Error> {
    if *pos + n > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let mut bytes = [0u8; 8];
    bytes[..n].copy_from_slice(&data[*pos..*pos + n]);
    *pos += n;
    Ok(u64::from_le_bytes(bytes))
}

/// Decode an rzip (`.rz`) container with a maximum output size limit.
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
    use crate::compress::rzip::encode;

    #[test]
    fn test_decode_roundtrip_chunk_streams() {
        let data = b"hello hello hello hello";
        let (stream0, stream1) = encode::encode_chunk(data, legacy_crc32(data));
        let mut decoded = Vec::new();
        decode_streams(&stream0, &stream1, &mut decoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_public_container() {
        let data = b"container roundtrip";
        let compressed = encode::encode(data);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let mut compressed = encode::encode(b"version");
        compressed[5] = compressed[5].wrapping_add(1);
        assert!(matches!(decode(&compressed), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_nonzero_reserved_header_bytes_rejected() {
        let mut compressed = encode::encode(b"reserved");
        compressed[20] = 1;
        assert!(matches!(decode(&compressed), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_trailing_garbage_rejected() {
        let mut compressed = encode::encode(b"trailing");
        compressed.extend_from_slice(b"garbage");
        assert!(matches!(decode(&compressed), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_unsupported_stream_compression_type_rejected() {
        let mut compressed = encode::encode(b"ctype");
        compressed[24 + 26] = 9;
        assert!(matches!(decode(&compressed), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_rzip_match_offset_zero_rejected() {
        let mut decoded = Vec::new();
        let stream0 = [
            0x01, 0x04, 0x00, // match token, len=4
            0x00, 0x00, 0x00, 0x00, // offset=0
        ];
        let stream1 = [];
        assert!(matches!(
            decode_streams(&stream0, &stream1, &mut decoded),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_empty_input_rejected() {
        assert!(matches!(decode(&[]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_truncated_header_rejected() {
        // Only the 4-byte magic, header is 24 bytes total
        assert!(matches!(decode(b"RZIP"), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_chunk_crc_mismatch_rejected() {
        let data = b"crc";
        let (mut stream0, stream1) = encode::encode_chunk(data, legacy_crc32(data));
        let crc_pos = stream0.len() - 4;
        stream0[crc_pos] ^= 0xFF;
        let mut decoded = Vec::new();
        assert!(matches!(
            decode_streams(&stream0, &stream1, &mut decoded),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn test_roundtrip_container_gzip_backend() {
        let data = b"gzip backend roundtrip test data with repetition repetition";
        let compressed = encode::encode_with_backend(data, encode::Backend::Gzip);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[cfg(feature = "lzo")]
    #[test]
    fn test_roundtrip_container_lzo_backend() {
        let data = b"lzo backend roundtrip test data with repetition repetition";
        let compressed = encode::encode_with_backend(data, encode::Backend::Lzo);
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello rzip bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello rzip bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello rzip bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello rzip bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // Empty input is rejected by rzip decoder.
        let result = decode_bounded(b"", 1024);
        assert!(result.is_err());
    }
}
