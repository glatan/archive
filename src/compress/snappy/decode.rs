//! Snappy decoding (framed by default, raw helpers included).

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32c::{crc32c, unmask_crc32c};

const STREAM_IDENTIFIER_TYPE: u8 = 0xFF;
const COMPRESSED_DATA_TYPE: u8 = 0x00;
const UNCOMPRESSED_DATA_TYPE: u8 = 0x01;
const STREAM_IDENTIFIER: &[u8; 6] = b"sNaPpY";

/// Decode a Snappy framed stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(Error::InvalidData("snappy: missing stream identifier"));
    }

    let mut pos = 0;
    let mut output = Vec::new();
    let mut saw_identifier = false;

    while pos < input.len() {
        let chunk_type = read_byte(input, &mut pos)?;
        let chunk_len = read_u24_le(input, &mut pos)? as usize;
        if pos + chunk_len > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let chunk = &input[pos..pos + chunk_len];
        pos += chunk_len;

        match chunk_type {
            STREAM_IDENTIFIER_TYPE => {
                if saw_identifier || pos != 10 {
                    return Err(Error::InvalidData(
                        "snappy: stream identifier must be first and unique",
                    ));
                }
                if chunk != STREAM_IDENTIFIER {
                    return Err(Error::InvalidData("snappy: invalid stream identifier"));
                }
                saw_identifier = true;
            }
            COMPRESSED_DATA_TYPE => {
                if !saw_identifier {
                    return Err(Error::InvalidData("snappy: missing stream identifier"));
                }
                if chunk.len() < 4 {
                    return Err(Error::UnexpectedEof);
                }
                let expected_crc =
                    u32::from_le_bytes(chunk[..4].try_into().map_err(|_| Error::UnexpectedEof)?);
                let decoded = decode_raw(&chunk[4..])?;
                let actual_crc = crc32c(&decoded);
                if unmask_crc32c(expected_crc) != actual_crc {
                    return Err(Error::ChecksumMismatch {
                        expected: unmask_crc32c(expected_crc),
                        actual: actual_crc,
                    });
                }
                output.extend_from_slice(&decoded);
            }
            UNCOMPRESSED_DATA_TYPE => {
                if !saw_identifier {
                    return Err(Error::InvalidData("snappy: missing stream identifier"));
                }
                if chunk.len() < 4 {
                    return Err(Error::UnexpectedEof);
                }
                let expected_crc =
                    u32::from_le_bytes(chunk[..4].try_into().map_err(|_| Error::UnexpectedEof)?);
                let data = &chunk[4..];
                let actual_crc = crc32c(data);
                if unmask_crc32c(expected_crc) != actual_crc {
                    return Err(Error::ChecksumMismatch {
                        expected: unmask_crc32c(expected_crc),
                        actual: actual_crc,
                    });
                }
                output.extend_from_slice(data);
            }
            0x80..=0xFE => {
                if !saw_identifier {
                    return Err(Error::InvalidData(
                        "snappy: stream identifier must precede skippable chunks",
                    ));
                }
            }
            _ => return Err(Error::Unsupported("snappy: unskippable chunk type")),
        }
    }

    if !saw_identifier {
        return Err(Error::InvalidData("snappy: missing stream identifier"));
    }

    Ok(output)
}

/// Decode a raw Snappy block.
pub fn decode_raw(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut pos = 0;
    let expected_len = read_varint(input, &mut pos)?;
    // Preamble is a 32-bit uncompressed length; reject larger values
    // before trusting them as an allocation size.
    if expected_len > u32::MAX as u64 {
        return Err(Error::InvalidData("snappy: preamble length exceeds 2^32-1"));
    }
    let expected_len = expected_len as usize;
    let mut output = Vec::new();
    // A corrupt block can declare a multi-gigabyte length. `with_capacity`
    // aborts when that reservation is refused.
    output
        .try_reserve_exact(expected_len)
        .map_err(|_| Error::InvalidData("snappy: uncompressed size too large"))?;

    while output.len() < expected_len {
        let tag = read_byte(input, &mut pos)?;
        match tag & 0x03 {
            0x00 => {
                let len = read_literal_len(input, &mut pos, tag)?;
                if pos + len > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                output.extend_from_slice(&input[pos..pos + len]);
                pos += len;
            }
            0x01 => {
                let len = 4 + ((tag >> 2) & 0x07) as usize;
                let offset =
                    ((((tag as usize) >> 5) & 0x07) << 8) | read_byte(input, &mut pos)? as usize;
                copy_from_offset(&mut output, offset, len)?;
            }
            0x02 => {
                let len = 1 + ((tag >> 2) & 0x3F) as usize;
                let offset = read_u16_le(input, &mut pos)? as usize;
                copy_from_offset(&mut output, offset, len)?;
            }
            0x03 => {
                let len = 1 + ((tag >> 2) & 0x3F) as usize;
                let offset = read_u32_le(input, &mut pos)? as usize;
                copy_from_offset(&mut output, offset, len)?;
            }
            _ => unreachable!(),
        }
        if output.len() > expected_len {
            return Err(Error::InvalidData(
                "snappy: decoded length exceeds preamble",
            ));
        }
    }

    if output.len() != expected_len {
        return Err(Error::SizeMismatch {
            expected: expected_len as u32,
            actual: output.len() as u32,
        });
    }
    if pos != input.len() {
        return Err(Error::InvalidData("snappy: trailing bytes after raw block"));
    }

    Ok(output)
}

fn read_literal_len(input: &[u8], pos: &mut usize, tag: u8) -> Result<usize, Error> {
    let len_code = (tag >> 2) as usize;
    if len_code < 60 {
        return Ok(len_code + 1);
    }
    let extra = len_code - 59;
    if *pos + extra > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let mut len_minus_one = 0usize;
    for i in 0..extra {
        len_minus_one |= (input[*pos + i] as usize) << (8 * i);
    }
    *pos += extra;
    Ok(len_minus_one + 1)
}

fn copy_from_offset(output: &mut Vec<u8>, offset: usize, len: usize) -> Result<(), Error> {
    crate::compress::match_ops::copy_match(output, offset, len)
        .map_err(|_| Error::InvalidData("snappy: invalid copy offset"))
}

fn read_varint(input: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = read_byte(input, pos)?;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::InvalidData("snappy: varint too large"));
        }
    }
}

fn read_byte(input: &[u8], pos: &mut usize) -> Result<u8, Error> {
    if *pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    let value = input[*pos];
    *pos += 1;
    Ok(value)
}

fn read_u16_le(input: &[u8], pos: &mut usize) -> Result<u16, Error> {
    if *pos + 2 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let value = u16::from_le_bytes([input[*pos], input[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

fn read_u24_le(input: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 3 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let value =
        input[*pos] as u32 | ((input[*pos + 1] as u32) << 8) | ((input[*pos + 2] as u32) << 16);
    *pos += 3;
    Ok(value)
}

fn read_u32_le(input: &[u8], pos: &mut usize) -> Result<u32, Error> {
    if *pos + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let value = u32::from_le_bytes([
        input[*pos],
        input[*pos + 1],
        input[*pos + 2],
        input[*pos + 3],
    ]);
    *pos += 4;
    Ok(value)
}

/// Append the decompressed bytes of `input` to `output`.
///
/// `max_output` limits how many bytes are appended. An empty `output`
/// takes the decoder buffer by move. A non-empty `output` is extended.
pub fn decode_into(
    input: &[u8],
    output: &mut Vec<u8>,
    max_output: Option<usize>,
) -> Result<(), Error> {
    let produced = match max_output {
        Some(limit) => decode_bounded(input, limit)?,
        None => decode(input)?,
    };
    crate::compress::move_into(output, produced);
    Ok(())
}

/// Decode a Snappy framed stream with a maximum output size limit.
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
    use crate::compress::snappy::encode;
    use crate::util::crc32c::mask_crc32c;

    #[test]
    fn test_decode_raw_literal_only() {
        let encoded = [0x03, 0x08, b'a', b'b', b'c'];
        let decoded = decode_raw(&encoded).unwrap();
        assert_eq!(decoded, b"abc");
    }

    #[test]
    fn test_decode_raw_copy() {
        let encoded = [0x06, 0x04, b'a', b'b', 0x01, 0x02];
        let decoded = decode_raw(&encoded).unwrap();
        assert_eq!(decoded, b"ababab");
    }

    #[test]
    fn test_decode_raw_copy4() {
        let encoded = [
            0x08, 0x0c, b'a', b'b', b'c', b'd', 0x0f, 0x04, 0x00, 0x00, 0x00,
        ];
        let decoded = decode_raw(&encoded).unwrap();
        assert_eq!(decoded, b"abcdabcd");
    }

    #[test]
    fn test_decode_raw_invalid_offset() {
        let encoded = [0x04, 0x01, 0x00];
        assert!(matches!(decode_raw(&encoded), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_framed_uncompressed() {
        let payload = b"hello";
        let mut framed = Vec::new();
        framed.push(STREAM_IDENTIFIER_TYPE);
        framed.extend_from_slice(&6u32.to_le_bytes()[..3]);
        framed.extend_from_slice(STREAM_IDENTIFIER);
        framed.push(UNCOMPRESSED_DATA_TYPE);
        framed.extend_from_slice(&(payload.len() as u32 + 4).to_le_bytes()[..3]);
        framed.extend_from_slice(&mask_crc32c(crc32c(payload)).to_le_bytes());
        framed.extend_from_slice(payload);
        assert_eq!(decode(&framed).unwrap(), payload);
    }

    #[test]
    fn test_decode_framed_skippable_chunk() {
        let payload = b"hello";
        let mut framed = encode::encode(payload);
        let mut with_skippable = framed[..10].to_vec();
        with_skippable.push(0x80);
        with_skippable.extend_from_slice(&3u32.to_le_bytes()[..3]);
        with_skippable.extend_from_slice(b"pad");
        with_skippable.extend_from_slice(&framed[10..]);
        framed = with_skippable;
        assert_eq!(decode(&framed).unwrap(), payload);
    }

    #[test]
    fn test_decode_framed_bad_crc() {
        let mut encoded = encode::encode(b"hello");
        let idx = 14;
        encoded[idx] ^= 0xFF;
        assert!(matches!(
            decode(&encoded),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_framed_empty_rejected() {
        assert!(matches!(decode(b""), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_framed_duplicate_identifier_rejected() {
        let mut encoded = encode::encode(b"hello");
        encoded.extend_from_slice(&[
            STREAM_IDENTIFIER_TYPE,
            6,
            0,
            0,
            b's',
            b'N',
            b'a',
            b'P',
            b'p',
            b'Y',
        ]);
        assert!(matches!(decode(&encoded), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_framed_skippable_before_identifier_rejected() {
        let mut framed = Vec::new();
        framed.push(0x80);
        framed.extend_from_slice(&3u32.to_le_bytes()[..3]);
        framed.extend_from_slice(b"pad");
        framed.extend_from_slice(&encode::encode(b"hello"));
        assert!(matches!(decode(&framed), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"hello snappy bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"hello snappy bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"hello snappy bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"hello snappy bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // Empty input is rejected by snappy decoder (missing stream identifier).
        let result = decode_bounded(b"", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_preamble_over_u32_max_rejected() {
        // Varint preamble declaring 2^32 must be rejected before it is
        // trusted as an allocation size.
        let input = [0x80, 0x80, 0x80, 0x80, 0x10]; // varint 2^32
        assert!(matches!(decode_raw(&input), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_raw_literal_length_extension_boundaries() {
        // format_description.txt: literal length codes 60-63 store
        // (len-1) in 1/2/3/4 extra bytes. Exercise the 1- and 2-byte
        // boundaries: len=60 via 1-byte extension, len=300 via 2-byte.
        let mut raw = vec![60]; // varint preamble: 60
        raw.push(60 << 2); // literal tag, len code 60 -> 1 extra byte
        raw.push(59); // len - 1 = 59 -> len 60
        raw.extend_from_slice(&[b'a'; 60]);
        assert_eq!(decode_raw(&raw).unwrap(), vec![b'a'; 60]);

        let mut raw = Vec::new();
        raw.extend_from_slice(&[0xAC, 0x02]); // varint 300
        raw.push(61 << 2); // literal tag, len code 61 -> 2 extra bytes
        raw.extend_from_slice(&299u16.to_le_bytes()); // len - 1 = 299
        raw.extend_from_slice(&[b'b'; 300]);
        assert_eq!(decode_raw(&raw).unwrap(), vec![b'b'; 300]);
    }

    #[test]
    fn test_decode_framed_truncated_at_every_position() {
        // A stream containing only the 10-byte stream identifier is a
        // valid empty frame; every other proper prefix must fail —
        // chunk headers require 4 bytes and payloads must be complete.
        let data = b"snappy truncation sweep: five quacking zephyrs jolt my wax bed";
        let compressed = crate::compress::snappy::encode::encode(data);
        assert_eq!(&compressed[..10], b"\xff\x06\x00\x00sNaPpY");
        for cut in 1..compressed.len() {
            if cut == 10 {
                assert!(decode(&compressed[..cut]).unwrap().is_empty());
            } else {
                assert!(
                    decode(&compressed[..cut]).is_err(),
                    "cut={cut} must not decode"
                );
            }
        }
    }
}
