//! zlib decompression (RFC 1950).
//!
//! Parses the zlib header, decompresses the DEFLATE payload, and
//! verifies the trailing Adler-32 checksum.

use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::adler32;
use crate::util::bitreader::BitReader;

/// Informational fields parsed from the zlib header (RFC 1950 §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZlibInfo {
    /// Compression level hint (FLEVEL, FLG bits 6–7).
    ///
    /// - 0: fastest
    /// - 1: fast
    /// - 2: default
    /// - 3: slowest (maximum compression)
    ///
    /// This field is informational only and does not affect decompression.
    pub flevel: u8,
}

/// Validate the two-byte zlib header and return `(flevel, has_fdict)`.
///
/// Checks FCHECK, CM, and CINFO per RFC 1950 §2.2.
const fn parse_header(cmf: u8, flg: u8) -> Result<(u8, bool), Error> {
    // Verify FCHECK: (CMF*256 + FLG) must be a multiple of 31
    let check = (cmf as u16) * 256 + (flg as u16);
    if !check.is_multiple_of(31) {
        return Err(Error::InvalidData("zlib: FCHECK failed"));
    }

    // CM must be 8 (deflate)
    let cm = cmf & 0x0F;
    if cm != 8 {
        return Err(Error::InvalidData("zlib: unsupported compression method"));
    }

    // CINFO must be <= 7 when CM=8 (RFC 1950 §2.2)
    let cinfo = cmf >> 4;
    if cinfo > 7 {
        return Err(Error::InvalidData("zlib: CINFO must be <= 7"));
    }

    // FLEVEL: bits 6-7 of FLG
    let flevel = (flg >> 6) & 0x03;

    // FDICT: bit 5 of FLG
    let has_fdict = flg & 0x20 != 0;

    Ok((flevel, has_fdict))
}

/// Decode a DEFLATE payload from the front of `input`, returning the
/// decompressed data and the byte offset where the DEFLATE stream ends
/// (rounded up to the next byte boundary).
///
/// The DEFLATE stream is self-terminating (BFINAL block), so the exact end
/// offset is recovered from the bit reader instead of assuming the payload
/// extends to the end of `input`. This lets the caller locate the Adler-32
/// trailer and ignore any trailing data after it (RFC 1950 §2.2).
///
/// When `dict` is `Some`, the dictionary is pre-seeded into the output
/// buffer so back-references can reach into it, then stripped from the
/// returned data (same scheme as `deflate::decode_with_dict`).
fn decode_deflate_payload(input: &[u8], dict: Option<&[u8]>) -> Result<(Vec<u8>, usize), Error> {
    let mut reader = BitReader::new(input);
    let mut output = match dict {
        Some(d) => Vec::from(d),
        None => Vec::new(),
    };
    deflate::decode::decode_stream(&mut reader, &mut output)?;
    reader.align_to_byte();
    let deflate_end = reader.byte_position();

    let decompressed = match dict {
        Some(d) => output.split_off(d.len()),
        None => output,
    };
    Ok((decompressed, deflate_end))
}

/// Verify the 4-byte big-endian Adler-32 trailer at `trailer_start`.
///
/// Bytes after the trailer are ignored: per RFC 1950 §2.2 the zlib stream
/// ends at ADLER32 and trailing data is not part of the stream.
fn verify_adler32(input: &[u8], trailer_start: usize, decompressed: &[u8]) -> Result<(), Error> {
    let trailer = input
        .get(trailer_start..trailer_start + 4)
        .ok_or(Error::UnexpectedEof)?;
    let expected_adler = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let actual_adler = adler32::adler32(decompressed);
    if actual_adler != expected_adler {
        return Err(Error::ChecksumMismatch {
            expected: expected_adler,
            actual: actual_adler,
        });
    }
    Ok(())
}

/// Decompress zlib format data.
///
/// Bytes after the 4-byte Adler-32 trailer are ignored: the zlib stream
/// ends at ADLER32 (RFC 1950 §2.2).
///
/// # Errors
///
/// Returns an error if the header is invalid, the DEFLATE data is
/// corrupt, or the Adler-32 checksum does not match.
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
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() < 6 {
        return Err(Error::InvalidData("zlib: input too short"));
    }

    let (_, has_fdict) = parse_header(input[0], input[1])?;

    // FDICT must be 0 (no preset dictionary)
    if has_fdict {
        return Err(Error::Unsupported("zlib: preset dictionary not supported"));
    }

    // Decompress DEFLATE payload; the trailer follows the exact stream end.
    let (decompressed, deflate_end) = decode_deflate_payload(&input[2..], None)?;

    // Verify Adler-32 checksum (big-endian); trailing data is ignored.
    verify_adler32(input, 2 + deflate_end, &decompressed)?;

    Ok(decompressed)
}

/// Decompress zlib format data, returning the decompressed payload and
/// informational header fields.
///
/// Identical to [`decode`] except it also returns a [`ZlibInfo`] containing
/// the FLEVEL compression-level hint from the zlib header (RFC 1950 §2.2).
/// FLEVEL is purely informational and does not affect decompression.
/// Like [`decode`], bytes after the Adler-32 trailer are ignored.
///
/// # Errors
///
/// Returns an error if the header is invalid, the DEFLATE data is
/// corrupt, or the Adler-32 checksum does not match.
///
/// # Examples
///
/// ```
/// use archive::compress::zlib::{decode, encode};
///
/// let data = b"Hello, zlib!";
/// let compressed = encode::encode(data);
/// let (decompressed, info) = decode::decode_with_info(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// assert_eq!(info.flevel, 2); // default compression level
/// ```
pub fn decode_with_info(input: &[u8]) -> Result<(Vec<u8>, ZlibInfo), Error> {
    if input.len() < 6 {
        return Err(Error::InvalidData("zlib: input too short"));
    }

    let (flevel, has_fdict) = parse_header(input[0], input[1])?;

    // FDICT must be 0 (no preset dictionary)
    if has_fdict {
        return Err(Error::Unsupported("zlib: preset dictionary not supported"));
    }

    // Decompress DEFLATE payload; the trailer follows the exact stream end.
    let (decompressed, deflate_end) = decode_deflate_payload(&input[2..], None)?;

    // Verify Adler-32 checksum (big-endian); trailing data is ignored.
    verify_adler32(input, 2 + deflate_end, &decompressed)?;

    Ok((decompressed, ZlibInfo { flevel }))
}

/// Decompress zlib format data that uses a preset dictionary (FDICT=1).
///
/// When the zlib header has the FDICT flag set, the stream includes a 4-byte
/// DICTID (Adler-32 of the dictionary). This function verifies DICTID matches
/// the supplied dictionary, then decompresses using the dictionary as initial
/// history for back-references. Like [`decode`], bytes after the Adler-32
/// trailer are ignored.
///
/// # Errors
///
/// Returns an error if the header is invalid, FDICT is not set, DICTID does
/// not match the dictionary, the DEFLATE data is corrupt, or the Adler-32
/// checksum does not match.
pub fn decode_with_dict(input: &[u8], dict: &[u8]) -> Result<Vec<u8>, Error> {
    // Minimum: 2 (header) + 4 (DICTID) + 0 (payload) + 4 (checksum) = 10
    if input.len() < 10 {
        return Err(Error::InvalidData("zlib: input too short"));
    }

    let (_, has_fdict) = parse_header(input[0], input[1])?;

    // FDICT must be set
    if !has_fdict {
        return Err(Error::InvalidData(
            "zlib: FDICT not set but decode_with_dict called",
        ));
    }

    // Read and verify DICTID (Adler-32 of the dictionary, big-endian)
    let dictid = u32::from_be_bytes([input[2], input[3], input[4], input[5]]);
    let expected_dictid = adler32::adler32(dict);
    if dictid != expected_dictid {
        return Err(Error::ChecksumMismatch {
            expected: dictid,
            actual: expected_dictid,
        });
    }

    // Decompress DEFLATE payload with dict (after header + DICTID);
    // the trailer follows the exact stream end.
    let (decompressed, deflate_end) = decode_deflate_payload(&input[6..], Some(dict))?;

    // Verify Adler-32 checksum of decompressed data (big-endian);
    // trailing data is ignored.
    verify_adler32(input, 6 + deflate_end, &decompressed)?;

    Ok(decompressed)
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

/// Decode with a maximum output size limit.
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

    #[test]
    fn test_too_short() {
        assert!(matches!(
            decode(&[0x78, 0x9C, 0x00]),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_bad_fcheck() {
        // Valid zlib header is 0x78 0x9C; corrupt FLG
        assert!(matches!(
            decode(&[0x78, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(Error::InvalidData(msg)) if msg.contains("FCHECK")
        ));
    }

    #[test]
    fn test_bad_cm() {
        // CM = 0 (not deflate), compute valid FCHECK
        let cmf: u8 = 0x70; // CM=0, CINFO=7
        let flg_base: u16 = 0x00;
        let fcheck = (31 - ((cmf as u16) * 256 + flg_base) % 31) % 31;
        let flg = (flg_base + fcheck) as u8;
        assert!(matches!(
            decode(&[cmf, flg, 0x00, 0x00, 0x00, 0x00]),
            Err(Error::InvalidData(msg)) if msg.contains("compression method")
        ));
    }

    #[test]
    fn test_roundtrip() {
        let data = b"Hello, zlib!";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_empty_input_rejected() {
        assert!(matches!(decode(&[]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_truncated_zlib_header() {
        // Only 1 byte of the 2-byte header
        assert!(matches!(decode(&[0x78]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_cinfo_above_7_rejected() {
        // CMF byte with CINFO=8 (upper nibble > 7): CM=8, CINFO=8 → CMF=0x88
        // Calculate valid FLG so FCHECK passes: (0x88 * 256 + FLG) % 31 == 0
        // 0x88 * 256 = 34816; 34816 % 31 = 34816 - 1123*31 = 34816 - 34813 = 3
        // FLG = 31 - 3 = 28
        let cmf: u8 = 0x88;
        let flg: u8 = 28;
        // Verify our FCHECK calculation: (0x88 * 256 + 28) = 34844; 34844 / 31 = 1124 exactly
        debug_assert_eq!((cmf as u16 * 256 + flg as u16) % 31, 0);
        let result = decode(&[cmf, flg, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(
            result,
            Err(Error::InvalidData(msg)) if msg.contains("CINFO")
        ));
    }

    #[test]
    fn test_adler32_mismatch() {
        let mut compressed = super::super::encode::encode(b"test");
        let len = compressed.len();
        compressed[len - 1] ^= 0xFF;
        assert!(matches!(
            decode(&compressed),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_decode_with_dict_roundtrip() {
        let dict = b"the quick brown fox jumps over the lazy dog";
        let data = b"the quick brown fox is fast";
        let compressed = super::super::encode::encode_with_dict(data, dict);
        let decompressed = decode_with_dict(&compressed, dict).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decode_with_dict_wrong_dict_rejected() {
        let dict = b"the quick brown fox jumps over the lazy dog";
        let wrong_dict = b"a completely different dictionary";
        let data = b"the quick brown fox is fast";
        let compressed = super::super::encode::encode_with_dict(data, dict);
        let result = decode_with_dict(&compressed, wrong_dict);
        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_decode_with_info_flevel() {
        // encode uses FLEVEL=2 (default compression level)
        let data = b"Hello, zlib!";
        let compressed = super::super::encode::encode(data);
        let (decompressed, info) = decode_with_info(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(info.flevel, 2);
    }

    #[test]
    fn test_decode_with_info_flevel_variants() {
        // Construct zlib headers for all four FLEVEL values (0..=3) and verify
        // decode_with_info extracts the correct value.
        // CMF = 0x78 (CM=8, CINFO=7); FLG bits 6-7 hold FLEVEL.
        let data = b"test";
        let original = super::super::encode::encode(data);
        // The DEFLATE payload and Adler-32 trailer are the same regardless of
        // FLEVEL, so we only need to swap the header bytes.
        let trailer_start = original.len() - 4;
        let deflate_payload = &original[2..trailer_start];
        let adler_bytes = &original[trailer_start..];

        for flevel in 0u8..=3 {
            let cmf: u8 = 0x78;
            let flg_base: u16 = (flevel as u16) << 6;
            let fcheck = (31 - ((cmf as u16) * 256 + flg_base) % 31) % 31;
            let flg = (flg_base + fcheck) as u8;

            let mut stream = alloc::vec![cmf, flg];
            stream.extend_from_slice(deflate_payload);
            stream.extend_from_slice(adler_bytes);

            let (decompressed, info) = decode_with_info(&stream).unwrap();
            assert_eq!(decompressed, data, "flevel={flevel}");
            assert_eq!(info.flevel, flevel, "flevel={flevel}");
        }
    }

    #[test]
    fn test_decode_with_info_too_short() {
        assert!(matches!(
            decode_with_info(&[0x78, 0x9C, 0x00]),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_decode_with_info_fdict_rejected() {
        // FDICT streams should be rejected by decode_with_info
        let dict = b"dict";
        let data = b"data";
        let compressed = super::super::encode::encode_with_dict(data, dict);
        assert!(matches!(
            decode_with_info(&compressed),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_trailing_data_ignored() {
        // RFC 1950 §2.2: the zlib stream ends at the ADLER32 field; bytes
        // after it are not part of the stream and must be ignored.
        let data = b"Hello, zlib trailing data!";
        let mut compressed = super::super::encode::encode(data);
        compressed.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);

        // decode_with_info follows the same rule.
        let (decompressed, info) = decode_with_info(&compressed).unwrap();
        assert_eq!(decompressed, data);
        assert_eq!(info.flevel, 2);
    }

    #[test]
    fn test_decode_with_dict_trailing_data() {
        let dict = b"the quick brown fox jumps over the lazy dog";
        let data = b"the quick brown fox is fast";
        let mut compressed = super::super::encode::encode_with_dict(data, dict);
        compressed.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let decompressed = decode_with_dict(&compressed, dict).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decode_fdict_rejected() {
        // decode() must reject FDICT=1 streams; only decode_with_dict
        // handles preset dictionaries (RFC 1950 §2.3).
        let dict = b"the quick brown fox";
        let data = b"the quick brown fox is fast";
        let compressed = super::super::encode::encode_with_dict(data, dict);
        assert!(matches!(decode(&compressed), Err(Error::Unsupported(_))));
    }

    #[test]
    fn test_decode_with_dict_fdict_not_set_rejected() {
        // decode_with_dict on an FDICT=0 stream must be rejected.
        let compressed = super::super::encode::encode(b"hello");
        assert!(matches!(
            decode_with_dict(&compressed, b"dict"),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_cinfo_minimum_zero_accepted() {
        // CINFO=0 (256-byte window hint) is the smallest legal value and
        // must still decode; the window hint does not constrain decoding.
        // CMF = 0x08 (CINFO=0, CM=8); compute FLG for FCHECK.
        let data = b"test data";
        let original = super::super::encode::encode(data);
        let trailer_start = original.len() - 4;
        let deflate_payload = &original[2..trailer_start];
        let adler_bytes = &original[trailer_start..];

        let cmf: u8 = 0x08;
        let fcheck = (31 - (cmf as u16) * 256 % 31) % 31;
        let flg = fcheck as u8;
        debug_assert_eq!((cmf as u16 * 256 + flg as u16) % 31, 0);

        let mut stream = alloc::vec![cmf, flg];
        stream.extend_from_slice(deflate_payload);
        stream.extend_from_slice(adler_bytes);

        assert_eq!(decode(&stream).unwrap(), data);
    }

    #[test]
    fn test_truncated_at_every_position() {
        // Every proper prefix of a valid zlib stream must fail.
        let data = b"zlib truncation boundary test payload";
        let compressed = super::super::encode::encode(data);
        for cut in 1..compressed.len() {
            assert!(
                decode(&compressed[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }

    #[test]
    fn test_decode_truncated_adler_still_rejected() {
        // Fewer than 4 bytes after the DEFLATE stream end is a truncated
        // ADLER32 trailer and must still be rejected.
        let data = b"Hello, zlib!";
        let compressed = super::super::encode::encode(data);
        for cut in 1..=4 {
            let truncated = &compressed[..compressed.len() - cut];
            assert!(
                matches!(decode(truncated), Err(Error::UnexpectedEof)),
                "cut={cut} should be rejected as truncated trailer"
            );
        }
    }
}
