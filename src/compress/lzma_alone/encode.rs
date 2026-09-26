//! LZMA-Alone `.lzma` compression.
//!
//! Encodes data as a `.lzma` file: a 13-byte header (properties byte,
//! dictionary size, uncompressed size) followed by an end-of-payload
//! marker-terminated LZMA stream.
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

use alloc::vec::Vec;

use crate::compress::lzma::{LzmaProperties, lzma_encode_with_props};
use crate::error::Error;

/// Header size: 1 (properties) + 4 (dict size) + 8 (unpacked size) = 13 bytes.
const HEADER_SIZE: usize = 13;

/// Default dictionary size (8 MiB), matching the `xz -6` default.
const DEFAULT_DICT_SIZE: u32 = 1 << 23;

/// Encode data as a `.lzma` stream with the default dictionary size (8 MiB)
/// and the default `lc=3, lp=0, pb=2` property tuple.
///
/// The header records the uncompressed size and the LZMA stream is
/// terminated with an end-of-payload marker, matching what `xz --format=lzma`
/// produces.
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
pub fn encode(data: &[u8]) -> Vec<u8> {
    encode_with_dict_size(data, DEFAULT_DICT_SIZE).expect("default dictionary size is non-zero")
}

/// Encode data as a `.lzma` stream with an explicit dictionary size.
///
/// `dict_size` must be non-zero and is stored verbatim in the 4-byte header
/// field; it also bounds the LZMA match distance the encoder may emit.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if `dict_size` is zero.
///
/// [`Error::InvalidData`]: crate::error::Error::InvalidData
pub fn encode_with_dict_size(data: &[u8], dict_size: u32) -> Result<Vec<u8>, Error> {
    if dict_size == 0 {
        return Err(Error::InvalidData("lzma: dictionary size must be non-zero"));
    }
    let props = LzmaProperties::LZIP;
    let mut output = Vec::with_capacity(HEADER_SIZE + data.len() / 2 + 32);
    output.push(props.to_props_byte());
    output.extend_from_slice(&dict_size.to_le_bytes());
    output.extend_from_slice(&(data.len() as u64).to_le_bytes());
    output.extend_from_slice(&lzma_encode_with_props(data, dict_size, props));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_header_format() {
        let data = b"header check";
        let encoded = encode(data);
        assert_eq!(encoded[0], 0x5D); // lc=3, lp=0, pb=2 -> 93
        assert_eq!(
            u32::from_le_bytes(encoded[1..5].try_into().unwrap()),
            DEFAULT_DICT_SIZE
        );
        assert_eq!(
            u64::from_le_bytes(encoded[5..13].try_into().unwrap()),
            data.len() as u64
        );
        assert!(encoded.len() > HEADER_SIZE);
    }

    #[test]
    fn test_encode_roundtrip_empty() {
        let encoded = encode(b"");
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_encode_roundtrip_hello() {
        let data = b"Hello, World!";
        let encoded = encode(data);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_roundtrip_repeated() {
        let data = b"abcabcabcabcabcabcabcabcabcabc";
        let encoded = encode(data);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_roundtrip_all_bytes() {
        let data: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let encoded = encode(&data);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_roundtrip_1kb() {
        let data: Vec<u8> = (0..1024u32).map(|i| (i % 97) as u8).collect();
        let encoded = encode(&data);
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_with_dict_size() {
        let data = b"small dictionary roundtrip payload small dictionary roundtrip";
        let encoded = encode_with_dict_size(data, 1 << 12).unwrap();
        assert_eq!(
            u32::from_le_bytes(encoded[1..5].try_into().unwrap()),
            1 << 12
        );
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_rejects_zero_dict_size() {
        assert!(matches!(
            encode_with_dict_size(b"data", 0),
            Err(Error::InvalidData(_))
        ));
    }
}
