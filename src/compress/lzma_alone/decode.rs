//! LZMA-Alone `.lzma` decompression.
//!
//! Decodes `.lzma` files: a 13-byte header (properties byte, dictionary
//! size, uncompressed size) followed by a raw LZMA stream.
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzma_alone::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```
//!
//! # Errors
//!
//! Returns [`Error::InvalidData`] if the input is not valid `.lzma` data.
//!
//! [`Error::InvalidData`]: crate::error::Error::InvalidData

use alloc::vec::Vec;

use crate::compress::lzma::{
    LzmaProperties, lzma_decode_with_props, lzma_decode_with_props_and_size,
};
use crate::error::Error;

/// Header size: 1 (properties) + 4 (dict size) + 8 (unpacked size) = 13 bytes.
const HEADER_SIZE: usize = 13;

/// Uncompressed size field value meaning "size unknown"; an end-of-payload
/// marker is required in the LZMA stream.
const UNKNOWN_SIZE: u64 = u64::MAX;

/// The range decoder may leave the last 0-2 flush bytes of the LZMA stream
/// unread. Anything beyond this slack is treated as trailing data and
/// rejected.
const MAX_DECODER_SLACK: usize = 2;

/// Returns true when the unread input tail fits the range decoder slack.
const fn within_slack(consumed: usize, stream_len: usize) -> bool {
    stream_len - consumed <= MAX_DECODER_SLACK
}

/// Parsed `.lzma` header fields.
struct Header {
    props: LzmaProperties,
    dict_size: u32,
    unpacked_size: u64,
}

/// Parse and validate the 13-byte `.lzma` header.
fn parse_header(data: &[u8]) -> Result<Header, Error> {
    if data.len() < HEADER_SIZE {
        return Err(Error::UnexpectedEof);
    }
    let props = LzmaProperties::from_props_byte(data[0])
        .map_err(|_| Error::InvalidData("lzma: invalid properties byte"))?;
    let dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if dict_size == 0 {
        return Err(Error::InvalidData("lzma: dictionary size must be non-zero"));
    }
    let unpacked_size = u64::from_le_bytes([
        data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12],
    ]);
    Ok(Header {
        props,
        dict_size,
        unpacked_size,
    })
}

/// Decode a `.lzma` compressed byte stream.
///
/// Handles both streams terminated by an end-of-payload marker (used when
/// the header declares the uncompressed size as unknown) and streams that
/// end exactly at the stated uncompressed size without a marker.
///
/// Bytes after the end of the LZMA stream are rejected as trailing data,
/// matching the XZ Utils `.lzma` decoder behavior.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the input is not valid `.lzma` data.
/// Returns [`Error::UnexpectedEof`] if the input is truncated.
///
/// # Examples
///
/// ```
/// use archive::compress::lzma_alone::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    let header = parse_header(data)?;
    let stream = &data[HEADER_SIZE..];
    if stream.is_empty() {
        return Err(Error::UnexpectedEof);
    }

    if header.unpacked_size == UNKNOWN_SIZE {
        let (decoded, consumed) = lzma_decode_with_props(stream, header.dict_size, header.props)?;
        if !within_slack(consumed, stream.len()) {
            return Err(Error::InvalidData("lzma: trailing data after stream"));
        }
        return Ok(decoded);
    }

    let Ok(expected) = usize::try_from(header.unpacked_size) else {
        return Err(Error::InvalidData(
            "lzma: uncompressed size does not fit address space",
        ));
    };

    // Stream ends at the stated size without an end-of-payload marker.
    let (decoded, consumed) =
        lzma_decode_with_props_and_size(stream, header.dict_size, header.props, expected)?;
    if within_slack(consumed, stream.len()) {
        return Ok(decoded);
    }

    // The format also permits an end-of-payload marker after the stated size.
    // Re-decode in EOS mode so the marker bytes are consumed; anything else
    // after the declared stream end is rejected as trailing data.
    let Ok((decoded, consumed)) = lzma_decode_with_props(stream, header.dict_size, header.props)
    else {
        return Err(Error::InvalidData("lzma: trailing data after stream"));
    };
    if decoded.len() != expected || !within_slack(consumed, stream.len()) {
        return Err(Error::InvalidData("lzma: trailing data after stream"));
    }
    Ok(decoded)
}

/// Decode `.lzma` compressed data with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let result = decode(data)?;
    if result.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzma::lzma_encode_with_props;

    const DEFAULT_DICT_SIZE: u32 = 1 << 23;

    fn header_bytes(props_byte: u8, dict_size: u32, unpacked_size: u64) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.push(props_byte);
        header.extend_from_slice(&dict_size.to_le_bytes());
        header.extend_from_slice(&unpacked_size.to_le_bytes());
        header
    }

    fn stream_bytes(data: &[u8], dict_size: u32) -> Vec<u8> {
        lzma_encode_with_props(data, dict_size, LzmaProperties::LZIP)
    }

    fn file_bytes(data: &[u8], dict_size: u32, unpacked_size: u64) -> Vec<u8> {
        let mut file = header_bytes(0x5D, dict_size, unpacked_size);
        file.extend_from_slice(&stream_bytes(data, dict_size));
        file
    }

    #[test]
    fn test_decode_known_size_with_eos() {
        let data = b"known size plus end marker";
        let file = file_bytes(data, DEFAULT_DICT_SIZE, data.len() as u64);
        assert_eq!(decode(&file).unwrap(), data);
    }

    #[test]
    fn test_decode_unknown_size() {
        let data = b"unknown size requires end marker";
        let file = file_bytes(data, DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        assert_eq!(decode(&file).unwrap(), data);
    }

    #[test]
    fn test_decode_known_size_without_eos() {
        // Trim the stream so the range coder stops exactly at the stated
        // size: emit through the no-EOS helper instead.
        let data = b"no end marker stream";
        let props = LzmaProperties::LZIP;
        let mut file = header_bytes(props.to_props_byte(), DEFAULT_DICT_SIZE, data.len() as u64);
        let stream =
            crate::compress::lzma::lzma_encode_with_props_no_eos(data, DEFAULT_DICT_SIZE, props);
        file.extend_from_slice(&stream);
        assert_eq!(decode(&file).unwrap(), data);
    }

    #[test]
    fn test_decode_empty_payload_unknown_size() {
        let file = file_bytes(b"", DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        assert_eq!(decode(&file).unwrap(), b"");
    }

    #[test]
    fn test_decode_empty_payload_known_size() {
        let file = file_bytes(b"", DEFAULT_DICT_SIZE, 0);
        assert_eq!(decode(&file).unwrap(), b"");
    }

    #[test]
    fn test_decode_rejects_truncated_header() {
        for len in 0..HEADER_SIZE {
            assert!(decode(&vec![0x5Du8; len]).is_err(), "len={len}");
        }
    }

    #[test]
    fn test_decode_rejects_empty_stream() {
        let file = header_bytes(0x5D, DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        assert!(matches!(decode(&file), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_decode_rejects_invalid_props_byte() {
        // 0xE1 = 225 is the first invalid properties value.
        let data = b"props";
        let mut file = header_bytes(0xE1, DEFAULT_DICT_SIZE, data.len() as u64);
        file.extend_from_slice(&stream_bytes(data, DEFAULT_DICT_SIZE));
        assert!(matches!(decode(&file), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_rejects_unsupported_props_combo() {
        // lc+lp > 4 is a valid properties byte but outside the supported
        // literal-context range (XZ Utils rejects it the same way).
        let props = LzmaProperties {
            lc: 4,
            lp: 1,
            pb: 0,
        };
        let props_byte = props.to_props_byte();
        let mut file = header_bytes(props_byte, DEFAULT_DICT_SIZE, 0);
        file.extend_from_slice(&stream_bytes(b"", DEFAULT_DICT_SIZE));
        assert!(matches!(decode(&file), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_rejects_zero_dict_size() {
        let data = b"dict";
        let mut file = header_bytes(0x5D, 0, data.len() as u64);
        file.extend_from_slice(&stream_bytes(data, DEFAULT_DICT_SIZE));
        assert!(matches!(decode(&file), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_rejects_truncated_stream() {
        let data = b"truncated stream payload with some length";
        let file = file_bytes(data, DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        let truncated = &file[..file.len() - 3];
        assert!(decode(truncated).is_err());
    }

    #[test]
    fn test_decode_rejects_trailing_data_known_size() {
        let data = b"trailing check";
        let mut file = file_bytes(data, DEFAULT_DICT_SIZE, data.len() as u64);
        file.extend_from_slice(b"garbage");
        assert!(matches!(decode(&file), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_rejects_trailing_data_unknown_size() {
        let data = b"trailing check";
        let mut file = file_bytes(data, DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        file.extend_from_slice(b"garbage");
        assert!(matches!(decode(&file), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_rejects_size_mismatch() {
        let data = b"size mismatch payload";
        // Claim a larger unpacked size than the stream actually produces.
        let file = file_bytes(data, DEFAULT_DICT_SIZE, data.len() as u64 + 1);
        assert!(decode(&file).is_err());
    }

    #[test]
    fn test_decode_nondefault_props() {
        // lc=0, lp=2, pb=2 (props byte = 0x73 + lc = wait compute)
        let props = LzmaProperties {
            lc: 0,
            lp: 2,
            pb: 2,
        };
        let data = b"custom properties payload custom properties payload";
        let mut file = header_bytes(props.to_props_byte(), DEFAULT_DICT_SIZE, UNKNOWN_SIZE);
        file.extend_from_slice(&lzma_encode_with_props(data, DEFAULT_DICT_SIZE, props));
        assert_eq!(decode(&file).unwrap(), data);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        use super::super::encode;
        let data = b"bounded lzma-alone payload";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        use super::super::encode;
        let data = b"bounded lzma-alone payload";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }
}
