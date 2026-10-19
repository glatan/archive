//! gzip compression per [RFC 1952].
//!
//! [RFC 1952]: https://datatracker.ietf.org/doc/html/rfc1952

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::crc32;

use super::header::validate_extra_field;

// Header flag bits
const FTEXT: u8 = 1 << 0;
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

/// Options for gzip encoding.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::encode::GzipEncodeOptions;
///
/// let opts = GzipEncodeOptions {
///     filename: Some("hello.txt"),
///     comment: Some("a comment"),
///     ..Default::default()
/// };
/// ```
pub struct GzipEncodeOptions<'a> {
    /// Original filename (FNAME flag). Must not contain zero bytes.
    pub filename: Option<&'a str>,
    /// Comment (FCOMMENT flag). Must not contain zero bytes.
    pub comment: Option<&'a str>,
    /// Extra field data (FEXTRA flag).
    pub extra: Option<&'a [u8]>,
    /// Include header CRC16 (FHCRC flag).
    pub header_crc: bool,
    /// Hint that the data is probably ASCII text (FTEXT flag).
    ///
    /// This is an informational flag per RFC 1952 §2.3.1.1;
    /// decoders may ignore it.
    pub ftext: bool,
    /// Modification time as Unix timestamp.
    pub mtime: u32,
    /// Operating system (0=FAT, 3=Unix, 7=Macintosh, 11=NTFS, 0xFF=unknown).
    pub os: u8,
}

impl Default for GzipEncodeOptions<'_> {
    fn default() -> Self {
        Self {
            filename: None,
            comment: None,
            extra: None,
            header_crc: false,
            ftext: false,
            mtime: 0,
            os: 0xFF,
        }
    }
}

/// Encode data as a gzip stream with custom header options.
///
/// Uses the given DEFLATE compression level and applies the specified
/// header options per RFC 1952.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::{encode, decode};
/// use archive::compress::gzip::encode::GzipEncodeOptions;
/// use archive::compress::deflate::encode::Level;
///
/// let opts = GzipEncodeOptions {
///     filename: Some("hello.txt"),
///     ..Default::default()
/// };
/// let gz = encode::encode_with_options(b"Hello!", Level::Fast, &opts).unwrap();
/// let data = decode::decode(&gz).unwrap();
/// assert_eq!(data, b"Hello!");
/// ```
pub fn encode_with_options(
    input: &[u8],
    level: deflate::encode::Level,
    options: &GzipEncodeOptions<'_>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();

    // Compute flags
    let mut flags: u8 = 0x00;
    if options.ftext {
        flags |= FTEXT;
    }
    if options.extra.is_some() {
        flags |= FEXTRA;
    }
    if options.filename.is_some() {
        flags |= FNAME;
    }
    if options.comment.is_some() {
        flags |= FCOMMENT;
    }
    if options.header_crc {
        flags |= FHCRC;
    }

    // Gzip header (10 bytes)
    output.push(0x1F); // magic
    output.push(0x8B); // magic
    output.push(0x08); // method: DEFLATE
    output.push(flags);
    output.extend_from_slice(&options.mtime.to_le_bytes());
    // Extra flags (compression level hint)
    let xfl = match level {
        deflate::encode::Level::NoCompression => 0x00,
        deflate::encode::Level::Fast => 0x04,
        deflate::encode::Level::Default => 0x02,
    };
    output.push(xfl);
    output.push(options.os);

    // FEXTRA: 2-byte LE length + data
    if let Some(extra) = options.extra {
        validate_extra_field(extra)?;
        let xlen = u16::try_from(extra.len())
            .map_err(|_| Error::InvalidData("gzip: extra field exceeds 65535 bytes"))?;
        output.extend_from_slice(&xlen.to_le_bytes());
        output.extend_from_slice(extra);
    }

    // FNAME: NUL-terminated (RFC 1952 §2.3.1: must not contain zero bytes)
    if let Some(filename) = options.filename {
        let bytes = encode_latin1_field(filename, "gzip: filename must be Latin-1 without NUL")?;
        output.extend_from_slice(&bytes);
        output.push(0x00);
    }

    // FCOMMENT: NUL-terminated (RFC 1952 §2.3.1: must not contain zero bytes)
    if let Some(comment) = options.comment {
        let bytes = encode_latin1_field(comment, "gzip: comment must be Latin-1 without NUL")?;
        output.extend_from_slice(&bytes);
        output.push(0x00);
    }

    // FHCRC: CRC16 of header bytes so far (lower 16 bits of CRC32)
    if options.header_crc {
        let header_crc32 = crc32::crc32(&output);
        let crc16 = (header_crc32 & 0xFFFF) as u16;
        output.extend_from_slice(&crc16.to_le_bytes());
    }

    // DEFLATE compressed data
    let compressed = deflate::encode::encode(input, level);
    output.extend_from_slice(&compressed);

    // Trailer: CRC32 + ISIZE
    let checksum = crc32::crc32(input);
    output.extend_from_slice(&checksum.to_le_bytes());
    let isize = input.len() as u32;
    output.extend_from_slice(&isize.to_le_bytes());

    Ok(output)
}

fn encode_latin1_field(input: &str, error: &'static str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len());
    for ch in input.chars() {
        let value = ch as u32;
        if value == 0 || value > 0xFF {
            return Err(Error::InvalidData(error));
        }
        out.push(value as u8);
    }
    Ok(out)
}

/// Encode data as a gzip stream with custom header options using a writer.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::encode::{encode_writer_with_options, GzipEncodeOptions};
/// use archive::compress::deflate::encode::Level;
///
/// let opts = GzipEncodeOptions { filename: Some("test.txt"), ..Default::default() };
/// let mut buf = Vec::new();
/// encode_writer_with_options(b"data", Level::Fast, &opts, &mut buf).unwrap();
/// assert!(!buf.is_empty());
/// ```
#[cfg(feature = "std")]
pub fn encode_writer_with_options<W: std::io::Write>(
    input: &[u8],
    level: deflate::encode::Level,
    options: &GzipEncodeOptions<'_>,
    mut writer: W,
) -> std::io::Result<usize> {
    let encoded = encode_with_options(input, level, options).map_err(std::io::Error::from)?;
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

/// Encode data as a gzip stream.
///
/// Uses the given DEFLATE compression level with default header options
/// (no filename, no comment, OS=unknown).
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::{encode, decode};
/// use archive::compress::deflate::encode::Level;
///
/// let gz = encode::encode(b"Hello!", Level::Default);
/// let data = decode::decode(&gz).unwrap();
/// assert_eq!(data, b"Hello!");
/// ```
pub fn encode(input: &[u8], level: deflate::encode::Level) -> Vec<u8> {
    let mut output = Vec::new();
    encode_into(input, &mut output, level);
    output
}

/// Append one gzip member to `output`.
pub fn encode_into(input: &[u8], output: &mut Vec<u8>, level: deflate::encode::Level) {
    crate::compress::move_into(output, encode_member(input, level));
}

fn encode_member(input: &[u8], level: deflate::encode::Level) -> Vec<u8> {
    let mut output = vec![
        0x1F, // magic
        0x8B, // magic
        0x08, // method: DEFLATE
        0x00, // flags: none
    ];

    // Gzip header (10 bytes)
    output.extend_from_slice(&[0, 0, 0, 0]); // mtime: 0
    // Extra flags (compression level hint)
    let xfl = match level {
        deflate::encode::Level::NoCompression => 0x00,
        deflate::encode::Level::Fast => 0x04,
        deflate::encode::Level::Default => 0x02,
    };
    output.push(xfl);
    output.push(0xFF); // OS: unknown

    // DEFLATE compressed data
    let compressed = deflate::encode::encode(input, level);
    output.extend_from_slice(&compressed);

    // Trailer: CRC32 + ISIZE
    let checksum = crc32::crc32(input);
    output.extend_from_slice(&checksum.to_le_bytes());
    let isize = input.len() as u32;
    output.extend_from_slice(&isize.to_le_bytes());

    output
}

/// Encode data as a gzip stream and write to a [`std::io::Write`] sink.
///
/// Returns the number of bytes written.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if writing to the underlying writer fails.
///
/// # Examples
///
/// ```
/// use archive::compress::gzip::encode::encode_writer;
/// use archive::compress::deflate::encode::Level;
///
/// let mut buf = Vec::new();
/// let len = encode_writer(b"Hello!", Level::Fast, &mut buf).unwrap();
/// assert!(len > 0);
/// ```
#[cfg(feature = "std")]
pub fn encode_writer<W: std::io::Write>(
    input: &[u8],
    level: deflate::encode::Level,
    mut writer: W,
) -> std::io::Result<usize> {
    let encoded = encode(input, level);
    writer.write_all(&encoded)?;
    Ok(encoded.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::gzip::decode;

    #[test]
    fn test_roundtrip_empty() {
        let encoded = encode(b"", deflate::encode::Level::NoCompression);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn test_roundtrip_hello() {
        let input = b"Hello, gzip!";
        let encoded = encode(input, deflate::encode::Level::Fast);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_writer() {
        let input = b"Hello, gzip!";
        let mut output = Vec::new();
        let len = encode_writer(input, deflate::encode::Level::Fast, &mut output).unwrap();
        assert_eq!(len, output.len());
        let decoded = decode::decode(&output).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_xfl_values() {
        let fast = encode(b"test", deflate::encode::Level::Fast);
        assert_eq!(fast[8], 0x04); // XFL: fastest
        let default = encode(b"test", deflate::encode::Level::Default);
        assert_eq!(default[8], 0x02); // XFL: maximum compression
        let none = encode(b"test", deflate::encode::Level::NoCompression);
        assert_eq!(none[8], 0x00); // XFL: no compression
    }

    #[test]
    fn test_roundtrip_compressed() {
        let input = "The quick brown fox. ".repeat(50);
        let encoded = encode(input.as_bytes(), deflate::encode::Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input.as_bytes());
        assert!(encoded.len() < input.len());
    }

    #[test]
    fn test_all_compression_levels_roundtrip() {
        let input = "Hello, gzip compression levels!".repeat(20);
        let input = input.as_bytes();

        for level in [
            deflate::encode::Level::NoCompression,
            deflate::encode::Level::Fast,
            deflate::encode::Level::Default,
        ] {
            let encoded = encode(input, level);
            let decoded = decode::decode(&encoded).unwrap();
            assert_eq!(decoded, input, "roundtrip failed for level {:?}", level);
        }
    }

    #[test]
    fn test_gzip_header_structure() {
        let encoded = encode(b"test", deflate::encode::Level::Fast);
        // Magic bytes
        assert_eq!(encoded[0], 0x1F);
        assert_eq!(encoded[1], 0x8B);
        // Compression method (8 = DEFLATE)
        assert_eq!(encoded[2], 0x08);
        // Flags (0 = none)
        assert_eq!(encoded[3], 0x00);
        // OS (0xFF = unknown)
        assert_eq!(encoded[9], 0xFF);
    }

    #[test]
    fn test_gzip_trailer_crc_and_isize() {
        let input = b"Hello, World!";
        let encoded = encode(input, deflate::encode::Level::Fast);
        let len = encoded.len();
        // Last 8 bytes: CRC32 (4 bytes LE) + ISIZE (4 bytes LE)
        let crc = u32::from_le_bytes([
            encoded[len - 8],
            encoded[len - 7],
            encoded[len - 6],
            encoded[len - 5],
        ]);
        let isize = u32::from_le_bytes([
            encoded[len - 4],
            encoded[len - 3],
            encoded[len - 2],
            encoded[len - 1],
        ]);
        assert_eq!(crc, crate::util::crc32::crc32(input));
        assert_eq!(isize, input.len() as u32);
    }

    #[test]
    fn test_default_compresses_better_than_fast() {
        let input = "abcdefghijklmnopqrstuvwxyz ".repeat(100);
        let fast = encode(input.as_bytes(), deflate::encode::Level::Fast);
        let default = encode(input.as_bytes(), deflate::encode::Level::Default);
        // Default should compress at least as well as Fast
        assert!(default.len() <= fast.len());
    }

    #[test]
    fn test_incompressible_data() {
        // Pseudo-random data should still roundtrip
        let input: Vec<u8> = (0..256).map(|i| i as u8).cycle().take(500).collect();
        let encoded = encode(&input, deflate::encode::Level::Default);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    // Tests for encode_with_options

    #[test]
    fn test_encode_with_options_default_matches_encode() {
        let input = b"Hello, gzip!";
        let level = deflate::encode::Level::Fast;
        let encoded_plain = encode(input, level);
        let encoded_opts =
            encode_with_options(input, level, &GzipEncodeOptions::default()).unwrap();
        assert_eq!(encoded_plain, encoded_opts);
    }

    #[test]
    fn test_encode_with_fname() {
        let input = b"Hello, gzip!";
        let options = GzipEncodeOptions {
            filename: Some("hello.txt"),
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify FNAME flag is set
        assert_eq!(encoded[3] & FNAME, FNAME);

        // Verify the filename is in the header (NUL-terminated after 10-byte header)
        assert_eq!(&encoded[10..19], b"hello.txt");
        assert_eq!(encoded[19], 0x00); // NUL terminator

        // Verify data roundtrips through decode
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_fcomment() {
        let input = b"Hello, gzip!";
        let options = GzipEncodeOptions {
            comment: Some("a test comment"),
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify FCOMMENT flag is set
        assert_eq!(encoded[3] & FCOMMENT, FCOMMENT);

        // Verify the comment is in the header (NUL-terminated after 10-byte header)
        assert_eq!(&encoded[10..24], b"a test comment");
        assert_eq!(encoded[24], 0x00);

        // Verify data roundtrips
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_all_options() {
        let input = b"Hello with all options!";
        let extra_data = &[b'A', b'B', 0x01, 0x00, 0xCC];
        let options = GzipEncodeOptions {
            filename: Some("test.txt"),
            comment: Some("my comment"),
            extra: Some(extra_data),
            header_crc: false,
            ftext: false,
            mtime: 1234567890,
            os: 0x03, // Unix
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify all flags are set
        assert_eq!(
            encoded[3] & (FEXTRA | FNAME | FCOMMENT),
            FEXTRA | FNAME | FCOMMENT
        );

        // Verify mtime
        let mtime = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(mtime, 1234567890);

        // Verify OS
        assert_eq!(encoded[9], 0x03);

        // Verify FEXTRA: 2-byte LE length + data at offset 10
        let xlen = u16::from_le_bytes([encoded[10], encoded[11]]);
        assert_eq!(xlen, 5);
        assert_eq!(&encoded[12..17], extra_data);

        // Verify FNAME follows FEXTRA (at offset 17)
        assert_eq!(&encoded[17..25], b"test.txt");
        assert_eq!(encoded[25], 0x00);

        // Verify FCOMMENT follows FNAME (at offset 26)
        assert_eq!(&encoded[26..36], b"my comment");
        assert_eq!(encoded[36], 0x00);

        // Verify data roundtrips
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_mtime() {
        let input = b"mtime test";
        let options = GzipEncodeOptions {
            mtime: 0xDEADBEEF,
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify the 4-byte mtime field (bytes 4-7, little-endian)
        let mtime = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(mtime, 0xDEADBEEF);

        // Flags should be 0 (no optional fields)
        assert_eq!(encoded[3], 0x00);

        // Verify data roundtrips
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_writer_with_options() {
        let input = b"writer options test";
        let options = GzipEncodeOptions {
            filename: Some("writer.txt"),
            mtime: 42,
            ..GzipEncodeOptions::default()
        };
        let mut output = Vec::new();
        let len =
            encode_writer_with_options(input, deflate::encode::Level::Fast, &options, &mut output)
                .unwrap();
        assert_eq!(len, output.len());
        let decoded = decode::decode(&output).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_empty_options() {
        let input = b"edge case options";
        let options = GzipEncodeOptions {
            filename: Some(""),
            comment: Some(""),
            extra: Some(&[]),
            header_crc: false,
            ftext: false,
            mtime: u32::MAX,
            os: 0xFF,
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // All flags should be set (even for empty values)
        assert_eq!(
            encoded[3] & (FEXTRA | FNAME | FCOMMENT),
            FEXTRA | FNAME | FCOMMENT
        );

        // mtime = u32::MAX
        let mtime = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(mtime, u32::MAX);

        // Roundtrip
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fhcrc_roundtrip() {
        let input = b"Hello, FHCRC roundtrip!";
        let options = GzipEncodeOptions {
            filename: Some("hcrc.txt"),
            comment: Some("with header crc"),
            header_crc: true,
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fhcrc_header_parse() {
        use crate::compress::gzip::header::GzipHeader;

        let input = b"Hello, FHCRC header parse!";
        let options = GzipEncodeOptions {
            filename: Some("hcrc.txt"),
            header_crc: true,
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify FHCRC flag is set
        assert_eq!(encoded[3] & FHCRC, FHCRC);

        // Parse the header — this validates the CRC16 internally
        let header = GzipHeader::parse(&encoded).unwrap();
        assert_eq!(header.flags & FHCRC, FHCRC);

        // Verify the CRC16 value manually: it should be the lower 16 bits of CRC32
        // of all header bytes before the CRC16 field
        let crc16_offset = header.header_size - 2;
        let stored_crc16 = u16::from_le_bytes([encoded[crc16_offset], encoded[crc16_offset + 1]]);
        let computed_crc32 = crate::util::crc32::crc32(&encoded[..crc16_offset]);
        let expected_crc16 = (computed_crc32 & 0xFFFF) as u16;
        assert_eq!(stored_crc16, expected_crc16);
    }

    #[test]
    fn test_ftext_flag_roundtrip() {
        let input = b"Hello, text!";
        let options = GzipEncodeOptions {
            ftext: true,
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Verify FTEXT flag is set (bit 0)
        assert_eq!(encoded[3] & FTEXT, FTEXT);

        // Roundtrip should succeed (decoder ignores FTEXT)
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fname_with_embedded_nul() {
        let input = b"test data";
        let options = GzipEncodeOptions {
            filename: Some("hello\0world.txt"),
            ..GzipEncodeOptions::default()
        };
        assert_eq!(
            encode_with_options(input, deflate::encode::Level::Fast, &options),
            Err(Error::InvalidData(
                "gzip: filename must be Latin-1 without NUL"
            ))
        );
    }

    #[test]
    fn test_fname_fcomment_empty_string_nul() {
        use crate::compress::gzip::header::GzipHeader;

        let input = b"payload";
        let options = GzipEncodeOptions {
            filename: Some(""),
            comment: Some(""),
            ..GzipEncodeOptions::default()
        };
        let encoded = encode_with_options(input, deflate::encode::Level::Fast, &options).unwrap();

        // Both FNAME and FCOMMENT flags must be set even for empty strings
        assert_eq!(encoded[3] & FNAME, FNAME);
        assert_eq!(encoded[3] & FCOMMENT, FCOMMENT);

        // After the 10-byte header, FNAME should be a single NUL byte (empty name)
        assert_eq!(
            encoded[10], 0x00,
            "FNAME NUL terminator expected at offset 10"
        );

        // FCOMMENT should follow immediately: another single NUL byte
        assert_eq!(
            encoded[11], 0x00,
            "FCOMMENT NUL terminator expected at offset 11"
        );

        // Header parser must accept this
        let header = GzipHeader::parse(&encoded).unwrap();
        assert_eq!(header.header_size, 12); // 10 base + 1 (FNAME NUL) + 1 (FCOMMENT NUL)

        // Roundtrip must succeed
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_fcomment_with_embedded_nul() {
        let input = b"test data";
        let options = GzipEncodeOptions {
            comment: Some("good\0bad comment"),
            ..GzipEncodeOptions::default()
        };
        assert_eq!(
            encode_with_options(input, deflate::encode::Level::Fast, &options),
            Err(Error::InvalidData(
                "gzip: comment must be Latin-1 without NUL"
            ))
        );
    }

    #[test]
    fn test_fname_latin1_encoded() {
        let options = GzipEncodeOptions {
            filename: Some("café.txt"),
            ..GzipEncodeOptions::default()
        };
        let encoded =
            encode_with_options(b"latin1 name", deflate::encode::Level::Fast, &options).unwrap();
        assert_eq!(&encoded[10..18], b"caf\xe9.txt");
        assert_eq!(encoded[18], 0x00);
    }

    #[test]
    fn test_fname_non_latin1_rejected() {
        let options = GzipEncodeOptions {
            filename: Some("snowman-\u{2603}.txt"),
            ..GzipEncodeOptions::default()
        };
        assert_eq!(
            encode_with_options(b"data", deflate::encode::Level::Fast, &options),
            Err(Error::InvalidData(
                "gzip: filename must be Latin-1 without NUL"
            ))
        );
    }

    #[test]
    fn test_fcomment_latin1_encoded() {
        let options = GzipEncodeOptions {
            comment: Some("piñata"),
            ..GzipEncodeOptions::default()
        };
        let encoded =
            encode_with_options(b"latin1 comment", deflate::encode::Level::Fast, &options).unwrap();
        assert_eq!(&encoded[10..16], b"pi\xf1ata");
        assert_eq!(encoded[16], 0x00);
    }

    #[test]
    fn test_fcomment_non_latin1_rejected() {
        let options = GzipEncodeOptions {
            comment: Some("emoji-\u{1F600}"),
            ..GzipEncodeOptions::default()
        };
        assert_eq!(
            encode_with_options(b"data", deflate::encode::Level::Fast, &options),
            Err(Error::InvalidData(
                "gzip: comment must be Latin-1 without NUL"
            ))
        );
    }

    #[test]
    fn test_invalid_extra_rejected() {
        let options = GzipEncodeOptions {
            extra: Some(&[b'A', b'B', 0x02, 0x00, 0x11]),
            ..GzipEncodeOptions::default()
        };
        assert_eq!(
            encode_with_options(b"data", deflate::encode::Level::Fast, &options),
            Err(Error::InvalidData("gzip: malformed FEXTRA subfield data"))
        );
    }

    #[test]
    fn rejects_oversized_extra_field() {
        // XLEN is u16; >65535 bytes of FEXTRA must be rejected, not
        // silently truncated to a non-conformant header.
        let extra = vec![0u8; 65540];
        let opts = GzipEncodeOptions {
            extra: Some(&extra),
            ..Default::default()
        };
        assert!(matches!(
            encode_with_options(b"x", deflate::encode::Level::Default, &opts),
            Err(Error::InvalidData(_))
        ));
    }
}
