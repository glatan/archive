//! gzip header parsing ([RFC 1952] §2.3).
//!
//! [RFC 1952]: https://datatracker.ietf.org/doc/html/rfc1952

use crate::error::Error;
use crate::util::crc32;

/// Gzip magic number bytes.
pub(crate) const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// Compression method: DEFLATE.
pub(crate) const CM_DEFLATE: u8 = 8;

// Header flag bits
const _FTEXT: u8 = 1 << 0;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

/// Parsed gzip header.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::{encode, header::GzipHeader};
/// use archive::compress::deflate::encode::Level;
///
/// let gz = encode::encode(b"data", Level::Fast);
/// let header = GzipHeader::parse(&gz).unwrap();
/// assert_eq!(header.method, 8); // DEFLATE
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipHeader {
    /// Compression method (should be 8 for DEFLATE).
    pub method: u8,
    /// Flags byte.
    pub flags: u8,
    /// Modification time (Unix timestamp).
    pub mtime: u32,
    /// Extra flags (compression level hint).
    pub xfl: u8,
    /// Operating system.
    pub os: u8,
    /// Total header size in bytes (for finding start of compressed data).
    pub header_size: usize,
}

impl GzipHeader {
    /// Parse a gzip header from the beginning of `data`.
    ///
    /// This method does not panic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if data is shorter than 10 bytes,
    /// [`Error::InvalidData`] for bad magic numbers or reserved flags,
    /// [`Error::Unsupported`] if the compression method is not DEFLATE.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::compress::gzip::{encode, header::GzipHeader};
    /// use archive::compress::deflate::encode::Level;
    ///
    /// let gz = encode::encode(b"data", Level::Fast);
    /// let header = GzipHeader::parse(&gz).unwrap();
    /// assert_eq!(header.method, 8);
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 10 {
            return Err(Error::UnexpectedEof);
        }
        if data[0] != GZIP_MAGIC[0] || data[1] != GZIP_MAGIC[1] {
            return Err(Error::InvalidData("invalid gzip magic number"));
        }
        let method = data[2];
        if method != CM_DEFLATE {
            return Err(Error::Unsupported("only DEFLATE compression is supported"));
        }
        let flags = data[3];
        // RFC 1952 §2.3.1 Compliance: reserved flag bits must cause an error.
        if flags & 0xE0 != 0 {
            return Err(Error::Unsupported("gzip: reserved header flag bits set"));
        }
        let mtime = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let xfl = data[8];
        let os = data[9];

        let mut pos = 10;

        // FEXTRA
        if flags & FEXTRA != 0 {
            if pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            let extra_start = pos + 2;
            let extra_end = extra_start + xlen;
            if extra_end > data.len() {
                return Err(Error::UnexpectedEof);
            }
            validate_extra_field(&data[extra_start..extra_end])?;
            pos = extra_end;
        }

        // FNAME (null-terminated)
        if flags & FNAME != 0 {
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            if pos >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += 1; // skip null terminator
        }

        // FCOMMENT (null-terminated)
        if flags & FCOMMENT != 0 {
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            if pos >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += 1;
        }

        // FHCRC (2-byte CRC16 of header)
        if flags & FHCRC != 0 {
            if pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let computed_crc32 = crc32::crc32(&data[0..pos]);
            let stored_crc16 = u16::from_le_bytes([data[pos], data[pos + 1]]);
            let computed_crc16 = (computed_crc32 & 0xFFFF) as u16;
            if computed_crc16 != stored_crc16 {
                return Err(Error::ChecksumMismatch {
                    expected: stored_crc16 as u32,
                    actual: computed_crc16 as u32,
                });
            }
            pos += 2;
        }

        Ok(GzipHeader {
            method,
            flags,
            mtime,
            xfl,
            os,
            header_size: pos,
        })
    }
}

pub(crate) fn validate_extra_field(extra: &[u8]) -> Result<(), Error> {
    let mut pos = 0usize;
    while pos < extra.len() {
        if extra.len() - pos < 4 {
            return Err(Error::InvalidData("gzip: malformed FEXTRA subfield header"));
        }
        let data_len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if extra.len() - pos < data_len {
            return Err(Error::InvalidData("gzip: malformed FEXTRA subfield data"));
        }
        pos += data_len;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_header() {
        let data = vec![
            0x1F, 0x8B, // magic
            0x08, // method: DEFLATE
            0x00, // flags: none
            0x00, 0x00, 0x00, 0x00, // mtime
            0x00, // xfl
            0xFF, // os: unknown
        ];
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.method, CM_DEFLATE);
        assert_eq!(header.flags, 0);
        assert_eq!(header.header_size, 10);
    }

    #[test]
    fn test_invalid_magic() {
        let data = [0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(GzipHeader::parse(&data).is_err());
    }

    #[test]
    fn test_too_short() {
        let data = [0x1F, 0x8B];
        assert_eq!(GzipHeader::parse(&data), Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_header_length_boundary() {
        // Exactly 9 bytes is below the 10-byte minimum → UnexpectedEof;
        // exactly 10 bytes with a valid minimal header must parse.
        let mut nine = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0];
        assert_eq!(GzipHeader::parse(&nine), Err(Error::UnexpectedEof));

        nine.push(0xFF);
        let header = GzipHeader::parse(&nine).unwrap();
        assert_eq!(header.header_size, 10);
        assert_eq!(header.os, 0xFF);
    }

    #[test]
    fn test_xfl_arbitrary_values_accepted() {
        // XFL is informational (RFC 1952 §2.3.1): any byte value parses.
        for xfl in [0x00u8, 0x01, 0x03, 0x05, 0xFF] {
            let data = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, xfl, 0xFF];
            let header = GzipHeader::parse(&data).unwrap();
            assert_eq!(header.xfl, xfl, "xfl={xfl:#04x}");
        }
    }

    // Phase 1: Error detection

    #[test]
    fn test_invalid_compression_method() {
        let data = [
            0x1F, 0x8B, // magic
            0x09, // method: NOT DEFLATE (9 instead of 8)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        assert!(matches!(
            GzipHeader::parse(&data),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn test_reserved_flag_bits_rejected() {
        // RFC 1952 §2.3.1 Compliance: reserved flag bits must cause an error.

        // Bit 5 (0x20)
        let data = [
            0x1F, 0x8B, 0x08, 0x20, // flags: reserved bit 5 set
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        assert!(matches!(
            GzipHeader::parse(&data),
            Err(Error::Unsupported(_))
        ));

        // Bit 6 (0x40)
        let data2 = [0x1F, 0x8B, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        assert!(matches!(
            GzipHeader::parse(&data2),
            Err(Error::Unsupported(_))
        ));

        // Bit 7 (0x80)
        let data3 = [0x1F, 0x8B, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        assert!(matches!(
            GzipHeader::parse(&data3),
            Err(Error::Unsupported(_))
        ));

        // All reserved bits set along with valid flags
        let data4 = [0x1F, 0x8B, 0x08, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        assert!(matches!(
            GzipHeader::parse(&data4),
            Err(Error::Unsupported(_))
        ));
    }

    // Phase 3: Flag combination tests

    #[test]
    fn test_parse_header_fextra() {
        let mut data = vec![
            0x1F, 0x8B, 0x08, FEXTRA, // flags: FEXTRA
            0x00, 0x00, 0x00, 0x00, // mtime
            0x00, 0xFF, // xfl, os
        ];
        // XLEN = 6, then SI1 SI2 LEN DATA
        data.extend_from_slice(&6u16.to_le_bytes());
        data.extend_from_slice(&[b'A', b'B', 0x02, 0x00, 0xCC, 0xDD]);
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.flags, FEXTRA);
        assert_eq!(header.header_size, 10 + 2 + 6); // base + xlen field + xlen data
    }

    #[test]
    fn test_parse_header_fname() {
        let mut data = vec![
            0x1F, 0x8B, 0x08, FNAME, // flags: FNAME
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        data.extend_from_slice(b"test.txt\0");
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.flags, FNAME);
        assert_eq!(header.header_size, 10 + 9); // base + "test.txt\0"
    }

    #[test]
    fn test_parse_header_fcomment() {
        let mut data = vec![
            0x1F, 0x8B, 0x08, FCOMMENT, // flags: FCOMMENT
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        data.extend_from_slice(b"a comment\0");
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.flags, FCOMMENT);
        assert_eq!(header.header_size, 10 + 10);
    }

    #[test]
    fn test_parse_header_fhcrc() {
        let header_bytes = vec![
            0x1F, 0x8B, 0x08, FHCRC, // flags: FHCRC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        let crc = crc32::crc32(&header_bytes);
        let crc16 = (crc & 0xFFFF) as u16;
        let mut data = header_bytes;
        data.extend_from_slice(&crc16.to_le_bytes());
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.flags, FHCRC);
        assert_eq!(header.header_size, 10 + 2);
    }

    #[test]
    fn test_parse_header_all_flags() {
        let mut data = vec![
            0x1F,
            0x8B,
            0x08,
            FEXTRA | FNAME | FCOMMENT | FHCRC, // all flags
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xFF,
        ];
        // FEXTRA: xlen=4 + zero-length subfield
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[b'X', b'Y', 0x00, 0x00]);
        // FNAME: null-terminated
        data.extend_from_slice(b"f.gz\0");
        // FCOMMENT: null-terminated
        data.extend_from_slice(b"comment\0");
        // FHCRC: compute correct CRC16
        let crc = crc32::crc32(&data);
        let crc16 = (crc & 0xFFFF) as u16;
        data.extend_from_slice(&crc16.to_le_bytes());
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 10 + (2 + 4) + 5 + 8 + 2);
    }

    #[test]
    fn test_fextra_valid_multiple_subfields() {
        let extra = [b'A', b'B', 0x01, 0x00, 0x11, b'C', b'D', 0x00, 0x00];
        assert_eq!(validate_extra_field(&extra), Ok(()));
    }

    #[test]
    fn test_fextra_zero_length_subfield() {
        let extra = [b'A', b'B', 0x00, 0x00];
        assert_eq!(validate_extra_field(&extra), Ok(()));
    }

    #[test]
    fn test_fextra_truncated_subfield_header() {
        let extra = [b'A', b'B', 0x01];
        assert_eq!(
            validate_extra_field(&extra),
            Err(Error::InvalidData("gzip: malformed FEXTRA subfield header"))
        );
    }

    #[test]
    fn test_fextra_truncated_subfield_data() {
        let extra = [b'A', b'B', 0x02, 0x00, 0x11];
        assert_eq!(
            validate_extra_field(&extra),
            Err(Error::InvalidData("gzip: malformed FEXTRA subfield data"))
        );
    }

    #[test]
    fn test_parse_header_invalid_fextra_subfield_rejected() {
        let mut data = vec![0x1F, 0x8B, 0x08, FEXTRA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&[b'A', b'B', 0x02, 0x00, 0x11]);
        assert_eq!(
            GzipHeader::parse(&data),
            Err(Error::InvalidData("gzip: malformed FEXTRA subfield data"))
        );
    }

    #[test]
    fn test_mtime_xfl_os_fields() {
        let data = [
            0x1F, 0x8B, // magic
            0x08, // method: DEFLATE
            0x00, // flags: none
            0x78, 0x56, 0x34, 0x12, // mtime: 0x12345678
            0x02, // xfl: maximum compression
            0x03, // os: Unix
        ];
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.mtime, 0x12345678);
        assert_eq!(header.xfl, 0x02);
        assert_eq!(header.os, 0x03);
    }

    #[test]
    fn test_xfl_fast_compression() {
        let data = [
            0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, // xfl: fastest compression
            0xFF, // os: unknown
        ];
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.xfl, 0x04);
        assert_eq!(header.os, 0xFF);
    }

    #[test]
    fn test_fextra_xlen_zero() {
        let mut data = vec![0x1F, 0x8B, 0x08, FEXTRA, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        data.extend_from_slice(&0u16.to_le_bytes()); // XLEN = 0
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 10 + 2); // base + xlen field only
    }

    #[test]
    fn test_fname_empty() {
        let mut data = vec![0x1F, 0x8B, 0x08, FNAME, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        data.push(0x00); // just null terminator
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 10 + 1);
    }

    #[test]
    fn test_fcomment_empty() {
        let mut data = vec![
            0x1F, 0x8B, 0x08, FCOMMENT, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        data.push(0x00); // just null terminator
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 10 + 1);
    }

    #[test]
    fn test_fname_unterminated() {
        // FNAME set but no null terminator before EOF
        let data = vec![
            0x1F, 0x8B, 0x08, 0x08, // flags: FNAME
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, b'f', b'o', b'o', // no null terminator
        ];
        assert!(matches!(
            GzipHeader::parse(&data),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn test_fcomment_unterminated() {
        let data = vec![
            0x1F, 0x8B, 0x08, 0x10, // flags: FCOMMENT
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, b'h', b'i', // no null terminator
        ];
        assert!(matches!(
            GzipHeader::parse(&data),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn test_fextra_truncated() {
        // FEXTRA set, XLEN=100 but only 2 bytes of extra data
        let mut data = vec![
            0x1F, 0x8B, 0x08, 0x04, // flags: FEXTRA
            0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ];
        data.extend_from_slice(&100u16.to_le_bytes()); // XLEN=100
        data.extend_from_slice(&[0x01, 0x02]); // only 2 bytes
        assert!(matches!(
            GzipHeader::parse(&data),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn test_invalid_compression_method_various() {
        // CM=0, CM=7, CM=255 should all be rejected (only CM=8 DEFLATE is valid)
        for cm in [0u8, 7, 255] {
            let data = [
                0x1F, 0x8B, // magic
                cm,   // invalid compression method
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
            ];
            let result = GzipHeader::parse(&data);
            assert!(
                matches!(result, Err(Error::Unsupported(_))),
                "CM={cm} should be rejected as unsupported"
            );
        }
    }

    #[test]
    fn test_fhcrc_with_fname_fextra_corrupted() {
        // Build a valid header with FHCRC + FNAME + FEXTRA all set
        let flags = FHCRC | FNAME | FEXTRA;
        let mut data = vec![
            0x1F, 0x8B, 0x08, flags, // magic + method + flags
            0x00, 0x00, 0x00, 0x00, // mtime
            0x00, 0xFF, // xfl, os
        ];
        // FEXTRA: xlen=4, then a zero-length subfield
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&[b'X', b'Y', 0x00, 0x00]);
        // FNAME: null-terminated string
        data.extend_from_slice(b"myfile.txt\0");
        // FHCRC: compute correct CRC16 of everything so far, then corrupt it
        let crc = crc32::crc32(&data);
        let crc16 = (crc & 0xFFFF) as u16;
        let corrupted_crc16 = crc16 ^ 0xFFFF; // flip all bits
        data.extend_from_slice(&corrupted_crc16.to_le_bytes());

        let result = GzipHeader::parse(&data);
        assert!(
            matches!(result, Err(Error::ChecksumMismatch { .. })),
            "corrupted FHCRC should produce ChecksumMismatch error"
        );
    }

    #[test]
    fn test_fhcrc_validation() {
        // Build a header with FHCRC set and correct CRC16
        let header_bytes = vec![0x1F, 0x8B, 0x08, FHCRC, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        let crc = crc32::crc32(&header_bytes);
        let crc16 = (crc & 0xFFFF) as u16;
        let mut data = header_bytes;
        data.extend_from_slice(&crc16.to_le_bytes());

        // Correct CRC16 should parse successfully
        let header = GzipHeader::parse(&data).unwrap();
        assert_eq!(header.header_size, 12);

        // Corrupt the CRC16 and verify it fails
        let crc_offset = 10;
        data[crc_offset] ^= 0xFF;
        let result = GzipHeader::parse(&data);
        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
    }
}
