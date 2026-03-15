//! zlib compression (RFC 1950).
//!
//! Produces a zlib wrapper around a raw DEFLATE stream:
//! - 2-byte header (CMF + FLG)
//! - Raw DEFLATE compressed data
//! - 4-byte Adler-32 checksum (big-endian)

use alloc::vec::Vec;

use crate::compress::deflate;
use crate::util::adler32;

/// Compress data in zlib format.
///
/// Uses DEFLATE default compression level.
///
/// # Examples
///
/// ```
/// use archive::compress::zlib::{decode, encode};
///
/// let data = b"Hello, zlib!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(input: &[u8]) -> Vec<u8> {
    let deflated = deflate::encode::encode(input, deflate::encode::Level::Default);

    let mut output = Vec::with_capacity(2 + deflated.len() + 4);

    // CMF byte: CM=8 (deflate), CINFO=7 (window size 32K)
    let cmf: u8 = 0x78;
    // FLG byte: FCHECK so that (CMF*256 + FLG) % 31 == 0, FLEVEL=2 (default)
    // FLEVEL=2 -> bits 6-7 = 0b10 -> FLG base = 0x80
    // FCHECK = (31 - (cmf as u16 * 256 + 0x80) % 31) % 31
    let flg_base: u16 = 0x80;
    let fcheck = (31 - ((cmf as u16) * 256 + flg_base) % 31) % 31;
    let flg = (flg_base + fcheck) as u8;

    output.push(cmf);
    output.push(flg);
    output.extend_from_slice(&deflated);
    output.extend_from_slice(&adler32::adler32(input).to_be_bytes());

    output
}

/// Compress data in zlib format with a preset dictionary (FDICT=1).
///
/// Produces a zlib stream with:
/// - 2-byte header (CMF + FLG with FDICT=1)
/// - 4-byte DICTID (Adler-32 of the dictionary, big-endian)
/// - Raw DEFLATE compressed data (using the dictionary for better compression)
/// - 4-byte Adler-32 checksum of the uncompressed data (big-endian)
pub fn encode_with_dict(input: &[u8], dict: &[u8]) -> Vec<u8> {
    let deflated = deflate::encode::encode_with_dict(input, dict);

    // CMF byte: CM=8 (deflate), CINFO=7 (window size 32K)
    let cmf: u8 = 0x78;
    // FLG byte: FDICT=1 (bit 5), FLEVEL=2 (bits 6-7 = 0b10)
    // FLG base = 0x80 (FLEVEL) | 0x20 (FDICT) = 0xA0
    let flg_base: u16 = 0xA0;
    let fcheck = (31 - ((cmf as u16) * 256 + flg_base) % 31) % 31;
    let flg = (flg_base + fcheck) as u8;

    let dictid = adler32::adler32(dict);

    let mut output = Vec::with_capacity(2 + 4 + deflated.len() + 4);
    output.push(cmf);
    output.push(flg);
    output.extend_from_slice(&dictid.to_be_bytes());
    output.extend_from_slice(&deflated);
    output.extend_from_slice(&adler32::adler32(input).to_be_bytes());

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_valid() {
        let compressed = encode(b"test");
        let cmf = compressed[0] as u16;
        let flg = compressed[1] as u16;
        assert_eq!((cmf * 256 + flg) % 31, 0);
        assert_eq!(cmf & 0x0F, 8); // CM = deflate
    }

    #[test]
    fn test_roundtrip() {
        let data = b"Hello, zlib!";
        let compressed = encode(data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let compressed = encode(b"");
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn test_roundtrip_large() {
        let data = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        let compressed = encode(&data);
        let decompressed = super::super::decode::decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
