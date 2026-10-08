//! lzip decompression with CRC-32 and size verification.
//!
//! Decodes lzip compressed data (single or multi-member streams).
//! Each member has a 6-byte header, an LZMA stream, and a 20-byte trailer.
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
//!
//! # Errors
//!
//! Returns [`Error::InvalidData`] if the input is not valid lzip data.
//! Returns [`Error::ChecksumMismatch`] if a CRC-32 check fails.
//!
//! [`Error::InvalidData`]: crate::error::Error::InvalidData
//! [`Error::ChecksumMismatch`]: crate::error::Error::ChecksumMismatch

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32;

use crate::compress::lzma::lzma_decode;

use super::MAX_MEMBER_SIZE;

/// lzip magic number: "LZIP" (4 bytes).
const MAGIC: [u8; 4] = [0x4C, 0x5A, 0x49, 0x50];

/// Supported lzip version.
const VERSION: u8 = 1;

/// Header size: 4 (magic) + 1 (version) + 1 (dict size) = 6 bytes.
const HEADER_SIZE: usize = 6;

/// Trailer size: 4 (CRC-32) + 8 (data size) + 8 (member size) = 20 bytes.
const TRAILER_SIZE: usize = 20;

/// Minimum dictionary size (4 KiB).
const MIN_DICT_SIZE: u32 = 1 << 12;

/// Maximum dictionary size (512 MiB).
const MAX_DICT_SIZE: u32 = 1 << 29;

/// Decode the dictionary size byte per lzip spec.
///
/// `base = 1 << (ds & 0x1F)`, `dict_size = base - (base >> 4) * ((ds >> 5) & 7)`.
const fn decode_dict_size(ds: u8) -> u32 {
    let base = 1u32 << (ds & 0x1F);
    base - (base >> 4).wrapping_mul(((ds >> 5) & 7) as u32)
}

/// Decode a lzip compressed byte stream.
///
/// Supports multi-member lzip files (concatenated members).
/// Returns the decompressed data.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the input is not valid lzip data.
/// Returns [`Error::ChecksumMismatch`] if a CRC-32 check fails.
/// Returns [`Error::SizeMismatch`] if the decompressed size does not match
/// the trailer.
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
pub fn decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut pos = 0;

    if data.is_empty() {
        return Err(Error::InvalidData("lzip: empty input"));
    }

    // Decode each member
    let mut member_count = 0usize;
    loop {
        if pos >= data.len() {
            break;
        }

        // Parse header
        if pos + HEADER_SIZE > data.len() {
            if pos == 0 {
                return Err(Error::UnexpectedEof);
            }
            break;
        }

        if data[pos..pos + 4] != MAGIC {
            if pos == 0 {
                return Err(Error::InvalidData("lzip: invalid magic number"));
            }
            break;
        }

        let version = data[pos + 4];
        if version != VERSION {
            return Err(Error::Unsupported("lzip: unsupported version"));
        }

        let dict_size = decode_dict_size(data[pos + 5]);
        if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size) {
            return Err(Error::InvalidData("lzip: dictionary size out of range"));
        }

        pos += HEADER_SIZE;

        // Minimum remaining: range coder header (5) + trailer (20) = 25 bytes
        if pos + 25 > data.len() {
            return Err(Error::InvalidData("lzip: member too short"));
        }

        // Decode LZMA stream
        let member_start = pos - HEADER_SIZE;
        let (decoded, lzma_consumed) = lzma_decode(&data[pos..], dict_size)?;
        pos += lzma_consumed;

        // The range decoder may not consume the last few bytes of the LZMA
        // stream (the encoder flushes a 5-byte cache; up to that many bytes
        // can be left unread). Scan candidate positions using the data_size
        // field, preferring one that fully verifies.
        let mut trailer_pos = None;
        let mut first_size_match = None;
        for padding in 0..=5usize {
            let tpos = pos + padding;
            if tpos + TRAILER_SIZE > data.len() {
                break;
            }
            let ds = u64::from_le_bytes([
                data[tpos + 4],
                data[tpos + 5],
                data[tpos + 6],
                data[tpos + 7],
                data[tpos + 8],
                data[tpos + 9],
                data[tpos + 10],
                data[tpos + 11],
            ]);
            if ds != decoded.len() as u64 {
                continue;
            }
            if first_size_match.is_none() {
                first_size_match = Some(tpos);
            }
            let crc_ok =
                u32::from_le_bytes([data[tpos], data[tpos + 1], data[tpos + 2], data[tpos + 3]])
                    == crc32::crc32(&decoded);
            let ms = u64::from_le_bytes([
                data[tpos + 12],
                data[tpos + 13],
                data[tpos + 14],
                data[tpos + 15],
                data[tpos + 16],
                data[tpos + 17],
                data[tpos + 18],
                data[tpos + 19],
            ]);
            let ms_ok = ms == (tpos + TRAILER_SIZE - member_start) as u64 && ms <= MAX_MEMBER_SIZE;
            if crc_ok && ms_ok {
                trailer_pos = Some(tpos);
                break;
            }
        }
        let tpos = trailer_pos
            .or(first_size_match)
            .ok_or(Error::InvalidData("lzip: cannot find trailer"))?;

        let expected_crc =
            u32::from_le_bytes([data[tpos], data[tpos + 1], data[tpos + 2], data[tpos + 3]]);
        let expected_data_size = u64::from_le_bytes([
            data[tpos + 4],
            data[tpos + 5],
            data[tpos + 6],
            data[tpos + 7],
            data[tpos + 8],
            data[tpos + 9],
            data[tpos + 10],
            data[tpos + 11],
        ]);
        let expected_member_size = u64::from_le_bytes([
            data[tpos + 12],
            data[tpos + 13],
            data[tpos + 14],
            data[tpos + 15],
            data[tpos + 16],
            data[tpos + 17],
            data[tpos + 18],
            data[tpos + 19],
        ]);

        pos = tpos + TRAILER_SIZE;

        // Verify CRC-32
        let actual_crc = crc32::crc32(&decoded);
        if actual_crc != expected_crc {
            return Err(Error::ChecksumMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        // Verify data size
        if decoded.len() as u64 != expected_data_size {
            return Err(Error::InvalidData("lzip: data size mismatch"));
        }

        // Lzip manual ch.5: member size is limited to 2 PiB. The data
        // size field spans the full u64 range (16 EiB - 1) and needs
        // no limit check.
        if expected_member_size > MAX_MEMBER_SIZE {
            return Err(Error::InvalidData("lzip: member size exceeds limit"));
        }

        // Verify member size (from member_start to pos)
        let actual_member_size = (pos - member_start) as u64;
        if actual_member_size != expected_member_size {
            return Err(Error::InvalidData("lzip: member size mismatch"));
        }

        // Lzip manual ch.5: a multimember file cannot contain empty
        // members (a member whose data size is zero). Trailing data that
        // does not form another member (e.g. zero padding, ch.9) is allowed
        // after a single-member file, even an empty one.
        member_count += 1;
        if decoded.is_empty() && (member_count > 1 || data[pos..].starts_with(&MAGIC)) {
            return Err(Error::InvalidData("lzip: empty member in multimember file"));
        }

        output.extend_from_slice(&decoded);
    }

    if output.is_empty() && pos == 0 {
        return Err(Error::InvalidData("lzip: no members found"));
    }

    Ok(output)
}

/// Decode lzip compressed data with a maximum output size limit.
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

    #[test]
    fn test_decode_dict_size_basic() {
        // ds = 12 (0x0C): base = 1 << 12 = 4096, sub = 0 → 4096
        assert_eq!(decode_dict_size(0x0C), 4096);
    }

    #[test]
    fn test_decode_dict_size_with_fraction() {
        // ds = 0x2C: low5 = 12, high3 = 1
        // base = 4096, sub = (4096 >> 4) * 1 = 256 → 3840
        assert_eq!(decode_dict_size(0x2C), 3840);
    }

    #[test]
    fn test_decode_dict_size_system_lzip_header_byte() {
        // `lzip -c` commonly emits 0xB1 for ~88 KiB dictionaries.
        assert_eq!(decode_dict_size(0xB1), 88 * 1024);
    }

    #[test]
    fn test_decode_dict_size_max() {
        // ds = 29 (0x1D): base = 1 << 29 = 512MiB, sub = 0
        assert_eq!(decode_dict_size(0x1D), 1 << 29);
    }

    #[test]
    fn test_decode_dict_size_valid_header_range() {
        let mut saw_min = false;
        let mut saw_max = false;

        for exp in 12u8..=29 {
            for frac in 0u8..=7 {
                let ds = exp | (frac << 5);
                let dict_size = decode_dict_size(ds);
                if !(MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size) {
                    continue;
                }
                saw_min |= dict_size == MIN_DICT_SIZE;
                saw_max |= dict_size == MAX_DICT_SIZE;
                assert!(
                    (MIN_DICT_SIZE..=MAX_DICT_SIZE).contains(&dict_size),
                    "ds=0x{ds:02X} produced out-of-range size {dict_size}"
                );
            }
        }

        assert!(saw_min, "minimum dictionary size should be reachable");
        assert!(saw_max, "maximum dictionary size should be reachable");
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0x00, 0x00, 0x00, 0x00, 0x01, 0x0C];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_unsupported_version() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(2); // version 2
        data.push(0x0C); // dict size
        assert!(matches!(decode(&data), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_empty_input() {
        assert!(decode(b"").is_err());
    }

    #[test]
    fn test_truncated_header() {
        let data = [0x4C, 0x5A, 0x49]; // Only 3 bytes of magic
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_roundtrip_via_encode() {
        use super::super::encode;
        let data = b"Hello, lzip!";
        let compressed = encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_crc_mismatch() {
        use super::super::encode;
        let data = b"test data";
        let mut compressed = encode::encode(data);
        // Corrupt the CRC in the trailer (last 20 bytes, first 4 are CRC)
        let trailer_start = compressed.len() - TRAILER_SIZE;
        compressed[trailer_start] ^= 0xFF;
        assert!(matches!(
            decode(&compressed),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_data_size_mismatch() {
        use super::super::encode;
        let data = b"test data";
        let mut compressed = encode::encode(data);
        // Corrupt the data size field (bytes 4-11 of trailer)
        let trailer_start = compressed.len() - TRAILER_SIZE;
        compressed[trailer_start + 4] ^= 0xFF;
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn test_minimum_member_size() {
        // Valid header but truncated before LZMA stream can start
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(1); // version
        data.push(0x0C); // dict size byte
        // Only a few bytes after header — not enough for range coder + trailer
        data.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_member_size_mismatch() {
        use super::super::encode;
        let data = b"test data";
        let mut compressed = encode::encode(data);
        // Corrupt the member size field (bytes 12-19 of trailer)
        let trailer_start = compressed.len() - TRAILER_SIZE;
        compressed[trailer_start + 12] ^= 0xFF;
        assert!(decode(&compressed).is_err());
    }

    /// Lzip manual ch.5: member size is limited to 2 PiB.
    #[test]
    fn test_decode_rejects_oversized_member() {
        use super::super::encode;
        let mut compressed = encode::encode(b"oversized member test data");
        let trailer_start = compressed.len() - TRAILER_SIZE;
        compressed[trailer_start + 12..trailer_start + TRAILER_SIZE]
            .copy_from_slice(&(MAX_MEMBER_SIZE + 1).to_le_bytes());
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("lzip: member size exceeds limit"))
        ));

        // Exactly at the limit passes the bound check and fails only
        // on the member size mismatch.
        compressed[trailer_start + 12..trailer_start + TRAILER_SIZE]
            .copy_from_slice(&MAX_MEMBER_SIZE.to_le_bytes());
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("lzip: member size mismatch"))
        ));
    }

    #[test]
    fn test_dict_size_boundary_min() {
        use super::super::encode;
        // Encode with dict_size = 4096 (minimum), decode and verify roundtrip.
        let data = b"minimum dictionary size test data with some repetition: test data";
        let compressed = encode::encode_with_dict_size(data, 0x0C, 4096).unwrap();
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_multi_member_different_dict_sizes() {
        use super::super::encode;
        // Create two lzip members with different dictionary sizes and concatenate.
        let data1 = b"first member with small dict";
        let data2 = b"second member with larger dict";
        let member1 = encode::encode_with_dict_size(data1, 0x0C, 4096).unwrap();
        let member2 = encode::encode_with_dict_size(data2, 0x10, 65536).unwrap();
        let mut combined = member1;
        combined.extend_from_slice(&member2);

        let decompressed = decode(&combined).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        assert_eq!(decompressed, expected);
    }

    /// Lzip manual ch.5: a multimember file cannot contain empty
    /// members. An empty member before or after a non-empty member is
    /// rejected; a file consisting of a single empty member is accepted.
    #[test]
    fn test_empty_member_in_multimember_rejected() {
        use super::super::encode;
        let empty_member = encode::encode(b"");
        let member = encode::encode(b"non-empty member");

        // Single-member file containing only an empty member is fine.
        assert!(decode(&empty_member).unwrap().is_empty());

        for combined in [
            {
                let mut c = empty_member.clone();
                c.extend_from_slice(&member);
                c
            },
            {
                let mut c = member.clone();
                c.extend_from_slice(&empty_member);
                c
            },
        ] {
            assert!(matches!(decode(&combined), Err(Error::InvalidData(_))));
        }
    }

    #[test]
    fn test_invalid_dict_size_byte_too_large() {
        // Construct a lzip header with dict_size_byte = 41 (> 40, which is invalid).
        // decode_dict_size(41) = 1 << (41 & 0x1F) = 1 << 9 = 512, which is < MIN_DICT_SIZE (4096).
        // So decode should reject it as "dictionary size out of range".
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.push(VERSION);
        data.push(41); // dict_size_byte > 40
        // Add enough trailing bytes so we don't get "member too short" before the dict check
        data.extend_from_slice(&[0u8; 30]);
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_member_with_range_coder_padding_patterns() {
        use super::super::encode;

        let original = encode::encode(b"lzip padding regression payload");
        let trailer_start = original.len() - TRAILER_SIZE;

        for padding_len in 0..=5usize {
            let mut padded = original[..trailer_start].to_vec();
            padded.extend(core::iter::repeat_n(0u8, padding_len));
            padded.extend_from_slice(&original[trailer_start..]);

            let member_size_offset = padded.len() - 8;
            let member_size = u64::from_le_bytes(
                padded[member_size_offset..member_size_offset + 8]
                    .try_into()
                    .unwrap(),
            ) + padding_len as u64;
            padded[member_size_offset..member_size_offset + 8]
                .copy_from_slice(&member_size.to_le_bytes());

            let decoded = decode(&padded).unwrap();
            assert_eq!(decoded, b"lzip padding regression payload");
        }
    }

    #[test]
    fn test_trailing_data_after_valid_member_ignored() {
        use super::super::encode;

        let mut compressed = encode::encode(b"lzip trailing data policy");
        compressed.extend_from_slice(b"garbage after member");

        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"lzip trailing data policy");
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        use super::super::encode;
        let data = b"hello lzip bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, 1024).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        use super::super::encode;
        let data = b"hello lzip bounded test data";
        let compressed = encode::encode(data);
        let decoded = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        use super::super::encode;
        let data = b"hello lzip bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, data.len() - 1);
        assert!(matches!(result, Err(Error::OutputLimitExceeded { .. })));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        use super::super::encode;
        let data = b"hello lzip bounded test data";
        let compressed = encode::encode(data);
        let result = decode_bounded(&compressed, 0);
        assert!(matches!(
            result,
            Err(Error::OutputLimitExceeded { limit: 0 })
        ));
    }

    #[test]
    fn test_decode_bounded_empty() {
        // Empty input is rejected by lzip decoder.
        let result = decode_bounded(b"", 1024);
        assert!(result.is_err());
    }

    /// Lzip manual ch.9: trailing zero padding may be appended to a
    /// single-member file, even when the member is empty.
    #[test]
    fn test_empty_member_with_trailing_padding() {
        use super::super::encode;
        let mut compressed = encode::encode(b"");
        compressed.extend_from_slice(&[0u8; 16]);
        assert!(decode(&compressed).unwrap().is_empty());
    }

    /// Trailing garbage that does not form another member header is
    /// ignored after a single-member file, even when it is empty.
    #[test]
    fn test_empty_member_with_trailing_garbage() {
        use super::super::encode;
        let mut compressed = encode::encode(b"");
        compressed.extend_from_slice(b"garbage after member");
        assert!(decode(&compressed).unwrap().is_empty());
    }
}
