//! lzip compression.
//!
//! Compresses data into the lzip format (single member).
//!
//! # Examples
//!
//! ```
//! use archive::compress::lzip::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32;

use crate::compress::lzma::lzma_encode;

use super::{MAX_DATA_SIZE, MAX_MEMBER_SIZE};

/// lzip magic number: "LZIP" (4 bytes).
const MAGIC: [u8; 4] = [0x4C, 0x5A, 0x49, 0x50];

/// lzip version 1.
const VERSION: u8 = 1;

/// Header size: 6 bytes.
const HEADER_SIZE: usize = 6;

/// Trailer size: 20 bytes.
const TRAILER_SIZE: usize = 20;

/// Default dictionary size byte: 0x0C = 4 KiB (minimum, for simplicity).
const DEFAULT_DICT_SIZE_BYTE: u8 = 0x0C;

/// Default dictionary size value: 4096.
const DEFAULT_DICT_SIZE: u32 = 4096;

/// Minimum dictionary size (4 KiB).
const MIN_DICT_SIZE: u32 = 1 << 12;

/// Maximum dictionary size (512 MiB).
const MAX_DICT_SIZE: u32 = 1 << 29;

const fn decode_dict_size(dict_size_byte: u8) -> u32 {
    let base = 1u32 << (dict_size_byte & 0x1F);
    base - (base >> 4).wrapping_mul(((dict_size_byte >> 5) & 7) as u32)
}

fn validate_dict_size(dict_size_byte: u8, dict_size: u32) -> Result<(), Error> {
    if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size) {
        return Err(Error::InvalidData("lzip: dictionary size out of range"));
    }

    let decoded = decode_dict_size(dict_size_byte);
    if decoded != dict_size {
        return Err(Error::InvalidData(
            "lzip: dictionary size byte does not match dictionary size",
        ));
    }

    Ok(())
}

/// Encode the dictionary size to a byte per lzip spec.
///
/// Test helper for the pure power-of-two subset of lzip dictionary size bytes.
#[cfg(test)]
fn encode_dict_size_byte(dict_size: u32) -> u8 {
    let bits = 31 - dict_size.leading_zeros();
    bits as u8
}

/// Compress data into lzip format.
///
/// Uses default dictionary size (4 KiB). For most inputs this provides
/// reasonable compression; larger dictionary sizes improve compression
/// of larger inputs but use more memory.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzip::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(data: &[u8]) -> Vec<u8> {
    encode_with_dict_size(data, DEFAULT_DICT_SIZE_BYTE, DEFAULT_DICT_SIZE)
        .expect("default lzip dictionary parameters must remain valid")
}

/// Compress data into lzip format with a specified dictionary size.
///
/// `dict_size_byte` is the raw byte to encode in the header.
/// `dict_size` is the actual dictionary size value for LZMA.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::lzip::{decode, encode};
///
/// let compressed = encode::encode_with_dict_size(b"data", 0x0C, 4096).unwrap();
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, b"data");
/// ```
pub fn encode_with_dict_size(
    data: &[u8],
    dict_size_byte: u8,
    dict_size: u32,
) -> Result<Vec<u8>, Error> {
    validate_dict_size(dict_size_byte, dict_size)?;

    // Lzip manual ch.5: a member encodes at most 16 EiB - 1 bytes of
    // uncompressed data. Unreachable where usize fits in u64.
    if data.len() as u128 > u128::from(MAX_DATA_SIZE) {
        return Err(Error::InvalidData("lzip: data size exceeds limit"));
    }

    // Encode the LZMA stream
    let lzma_data = lzma_encode(data, dict_size);

    // Compute CRC-32 of the original data
    let crc = crc32::crc32(data);

    // Build the member
    let data_size = data.len() as u64;
    let member_size = (HEADER_SIZE + lzma_data.len() + TRAILER_SIZE) as u64;

    // Lzip manual ch.5: member size is limited to 2 PiB.
    if member_size > MAX_MEMBER_SIZE {
        return Err(Error::InvalidData("lzip: member size exceeds limit"));
    }

    let mut output = Vec::with_capacity(member_size as usize);

    // Header: magic (4) + version (1) + dict_size_byte (1)
    output.extend_from_slice(&MAGIC);
    output.push(VERSION);
    output.push(dict_size_byte);

    // LZMA data
    output.extend_from_slice(&lzma_data);

    // Trailer: CRC-32 (4) + data size (8) + member size (8)
    output.extend_from_slice(&crc.to_le_bytes());
    output.extend_from_slice(&data_size.to_le_bytes());
    output.extend_from_slice(&member_size.to_le_bytes());

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_header_format() {
        let compressed = encode(b"test");
        assert_eq!(&compressed[0..4], &MAGIC);
        assert_eq!(compressed[4], VERSION);
        assert_eq!(compressed[5], DEFAULT_DICT_SIZE_BYTE);
    }

    #[test]
    fn test_encode_roundtrip_empty() {
        let data = b"";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_roundtrip_hello() {
        let data = b"Hello, World!";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_roundtrip_repeated() {
        let data = b"abcabcabcabcabcabcabcabc";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_roundtrip_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_roundtrip_1kb() {
        let data: Vec<u8> = (0..1024).map(|i| (i * 37 % 256) as u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_dict_size_byte() {
        assert_eq!(encode_dict_size_byte(4096), 12);
        assert_eq!(encode_dict_size_byte(65536), 16);
        assert_eq!(encode_dict_size_byte(1 << 29), 29);
    }

    #[test]
    fn test_multi_member_roundtrip() {
        // Create two separate lzip members and concatenate them
        let data1 = b"first member";
        let data2 = b"second member";
        let mut combined = encode(data1);
        combined.extend_from_slice(&encode(data2));

        let decompressed = super::super::decode::decode(&combined).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        assert_eq!(decompressed, expected);
    }

    #[test]
    fn test_encode_with_larger_dict() {
        let data = b"test with larger dictionary";
        // dict_size_byte = 0x10 → dict_size = 1 << 16 = 65536
        let compressed = encode_with_dict_size(data, 0x10, 65536).unwrap();
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_with_65536_dict() {
        // Encode with dict_size=65536 and verify roundtrip.
        let data: Vec<u8> = (0..2048).map(|i| (i * 53 % 256) as u8).collect();
        let compressed = encode_with_dict_size(&data, 0x10, 65536).unwrap();
        // Verify header has the correct dict_size_byte
        assert_eq!(compressed[5], 0x10);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_encode_with_invalid_dict_size_rejected() {
        assert!(matches!(
            encode_with_dict_size(b"data", 0x0C, 8192),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_encode_with_out_of_range_dict_size_rejected() {
        assert!(matches!(
            encode_with_dict_size(b"data", 0x0B, 2048),
            Err(Error::InvalidData(_))
        ));
    }
}
