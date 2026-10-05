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

/// Returns true when `dict_size` has one of the portable forms (2^n or
/// 2^n + 2^(n-1)) recommended by lzma-file-format.txt §1.1.2 — the only
/// forms XZ Utils generates and decompresses.
fn is_portable_dict_size(dict_size: u32) -> bool {
    dict_size.is_power_of_two()
        || (dict_size.is_multiple_of(3) && (dict_size / 3).is_power_of_two())
}

/// Encode data as a `.lzma` stream with the default dictionary size (8 MiB)
/// and the default `lc=3, lp=0, pb=2` property tuple.
///
/// The header marks the uncompressed size as unknown (`0xFFFF_FFFF_FFFF_FFFF`)
/// and the LZMA stream is terminated with an end-of-payload marker, matching
/// what `xz --format=lzma` produces. Writing the known size is legal per the
/// format spec, but liblzma-based decoders (including `xz`) can reject such
/// streams when the end-of-payload marker is split across their internal
/// input-buffer boundary, so this encoder avoids the known-size form.
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
/// `dict_size` is stored verbatim in the 4-byte header field and also bounds
/// the LZMA match distance the encoder may emit. It must be non-zero and have
/// a portable form (2^n or 2^n + 2^(n-1), per lzma-file-format.txt §1.1.2);
/// unlike XZ Utils, non-portable values are rejected rather than silently
/// rounded up in the stored field.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if `dict_size` is zero or does not have a
/// portable form.
///
/// [`Error::InvalidData`]: crate::error::Error::InvalidData
pub fn encode_with_dict_size(data: &[u8], dict_size: u32) -> Result<Vec<u8>, Error> {
    if dict_size == 0 {
        return Err(Error::InvalidData("lzma: dictionary size must be non-zero"));
    }
    if !is_portable_dict_size(dict_size) {
        return Err(Error::InvalidData(
            "lzma: dictionary size must be 2^n or 2^n + 2^(n-1)",
        ));
    }
    let props = LzmaProperties::LZIP;
    let mut output = Vec::with_capacity(HEADER_SIZE + data.len() / 2 + 32);
    output.push(props.to_props_byte());
    output.extend_from_slice(&dict_size.to_le_bytes());
    output.extend_from_slice(&u64::MAX.to_le_bytes());
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
            u64::MAX // uncompressed size unknown; stream ends with EoPM
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

    #[test]
    fn test_encode_accepts_portable_dict_size() {
        let data = b"portable dictionary size roundtrip payload";
        // 2^n and 2^n + 2^(n-1) forms (lzma-file-format.txt §1.1.2).
        for dict_size in [1u32 << 20, 3 << 19, 1 << 31, 3 << 30] {
            let encoded = encode_with_dict_size(data, dict_size).unwrap();
            assert_eq!(
                u32::from_le_bytes(encoded[1..5].try_into().unwrap()),
                dict_size
            );
            let decoded = super::super::decode::decode(&encoded).unwrap();
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn test_encode_rejects_nonportable_dict_size() {
        for dict_size in [5u32, 4097, 5 << 10, u32::MAX] {
            assert!(
                matches!(
                    encode_with_dict_size(b"data", dict_size),
                    Err(Error::InvalidData(_))
                ),
                "dict_size={dict_size}"
            );
        }
    }

    #[test]
    fn test_is_portable_dict_size() {
        // 2^n and 2^n + 2^(n-1) boundary forms are portable.
        for dict_size in [1u32, 2, 3, 1 << 25, 3 << 24, 1 << 31, 3 << 30] {
            assert!(is_portable_dict_size(dict_size), "dict_size={dict_size}");
        }
        for dict_size in [0u32, 5, 7, 4097, u32::MAX] {
            assert!(!is_portable_dict_size(dict_size), "dict_size={dict_size}");
        }
    }
}
