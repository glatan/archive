//! xz stream encoder.
//!
//! Produces a single-stream, single-block xz file with LZMA2 compression,
//! optional standard BCJ / Delta prefilters, and CRC-32 integrity check.
//!
//! # Format overview
//!
//! ```text
//! Stream Header (12 bytes)
//!   ├─ Magic: FD 37 7A 58 5A 00
//!   ├─ Stream Flags (2 bytes): check type
//!   └─ CRC-32 of Stream Flags (4 bytes)
//! Block
//!   ├─ Block Header
//!   │   ├─ Header Size (1 byte, encoded as (real_size / 4) - 1)
//!   │   ├─ Block Flags (1 byte)
//!   │   ├─ Compressed Size (VLI, optional)
//!   │   ├─ Uncompressed Size (VLI, optional)
//!   │   ├─ Filter: LZMA2 (filter ID = 0x21) + dict size byte
//!   │   ├─ Padding to 4-byte boundary
//!   │   └─ CRC-32 of header (excluding size byte and CRC)
//!   └─ Compressed Data + Padding to 4-byte boundary
//! Index
//!   ├─ Index Indicator (1 byte: 0x00)
//!   ├─ Number of Records (VLI)
//!   ├─ Record: Unpadded Size (VLI) + Uncompressed Size (VLI)
//!   ├─ Padding to 4-byte boundary
//!   └─ CRC-32
//! Stream Footer (12 bytes)
//!   ├─ CRC-32 of footer fields
//!   ├─ Backward Size (4 bytes LE)
//!   ├─ Stream Flags (2 bytes, same as header)
//!   └─ Magic: YZ
//! ```
//!
//! # Examples
//!
//! ```
//! use archive::compress::xz::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32;

use super::filters::{
    FILTER_ARM, FILTER_ARM64, FILTER_ARMTHUMB, FILTER_DELTA, FILTER_IA64, FILTER_LZMA2,
    FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86, Filter, apply_encoder_filters,
};
use super::registry::FilterRegistry;

/// xz stream magic bytes.
const STREAM_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

/// Check type: CRC-32.
const CHECK_CRC32: u8 = 0x01;

/// Dictionary size for LZMA2 encoding: 4096 bytes.
/// Encoded as dictionary size byte 0x00 → 2^(byte/2 + 12) = 2^12 = 4096.
const DICT_SIZE: u32 = 4096;
const DICT_SIZE_BYTE: u8 = 0x00;

/// Encode data as an xz stream.
///
/// Produces a single-block xz stream with LZMA2 compression and CRC-32
/// integrity checking.
///
/// # Examples
///
/// ```
/// use archive::compress::xz::{decode, encode};
///
/// let data = b"Hello, World!";
/// let compressed = encode::encode(data);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn encode(data: &[u8]) -> Vec<u8> {
    match encode_with_filters(data, &[]) {
        Ok(output) => output,
        Err(_) => unreachable!("default xz filter chain is valid"),
    }
}

/// Encode data as an xz stream with optional pre-LZMA2 block filters.
///
/// The provided `filters` are applied in order before LZMA2 compression, and
/// are emitted into the xz block header in the same order.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if a filter configuration is invalid or
/// [`Error::Unsupported`] if more than three pre-LZMA2 filters are requested.
pub fn encode_with_filters(data: &[u8], filters: &[Filter]) -> Result<Vec<u8>, Error> {
    encode_with_filters_and_registry(data, filters, None)
}

/// Encode data as an xz stream with explicit filters and a custom filter
/// registry.
///
/// Behaves like [`encode_with_filters`] but consults the provided
/// [`FilterRegistry`] for filter IDs that are not built-in. Pass `None` if
/// no custom filters are needed.
pub fn encode_with_filters_and_registry(
    data: &[u8],
    filters: &[Filter],
    registry: Option<&FilterRegistry>,
) -> Result<Vec<u8>, Error> {
    if filters.len() + 1 > 4 {
        return Err(Error::Unsupported(
            "xz: at most three pre-LZMA2 filters are supported",
        ));
    }

    let filtered_data = apply_encoder_filters(data, filters, registry)?;
    let mut output = Vec::new();

    // ── Stream Header (12 bytes) ────────────────────────────────────
    output.extend_from_slice(&STREAM_MAGIC);
    let stream_flags = [0x00, CHECK_CRC32];
    let sf_crc = crc32::crc32(&stream_flags);
    output.extend_from_slice(&stream_flags);
    output.extend_from_slice(&sf_crc.to_le_bytes());

    // ── Block ───────────────────────────────────────────────────────
    let lzma2_data = crate::compress::lzma2::lzma2_encode(&filtered_data, DICT_SIZE);

    // Build block header content (everything between size byte and CRC)
    let mut block_hdr = vec![(filters.len() as u8) & 0x03];
    for filter in filters {
        append_filter_header(&mut block_hdr, filter, registry)?;
    }
    encode_vli(&mut block_hdr, FILTER_LZMA2);
    encode_vli(&mut block_hdr, 1);
    block_hdr.push(DICT_SIZE_BYTE);

    // Pad block header to multiple of 4 bytes (header = 1 (size byte) + content + padding + 4 (CRC))
    // Total (excluding size byte and CRC) must be: (real_header_size - 1) including size byte
    // real_header_size = 1 (size_byte) + block_hdr.len() + padding + 4 (CRC)
    // real_header_size must be multiple of 4
    let content_len = block_hdr.len();
    // header_bytes_before_crc = 1 + content_len + padding
    // header_bytes_before_crc + 4 must be multiple of 4
    // so header_bytes_before_crc must be multiple of 4
    let before_crc = 1 + content_len;
    let padding = (4 - (before_crc % 4)) % 4;
    block_hdr.resize(block_hdr.len() + padding, 0x00);

    let real_header_size = 1 + block_hdr.len() + 4; // size_byte + content+padding + CRC
    let header_size_byte = ((real_header_size / 4) - 1) as u8;

    // CRC-32 covers everything in the block header except the CRC field itself
    // (i.e., includes the size byte)
    let mut crc_input = Vec::with_capacity(1 + block_hdr.len());
    crc_input.push(header_size_byte);
    crc_input.extend_from_slice(&block_hdr);
    let block_hdr_crc = crc32::crc32(&crc_input);

    output.push(header_size_byte);
    output.extend_from_slice(&block_hdr);
    output.extend_from_slice(&block_hdr_crc.to_le_bytes());

    // Compressed data
    output.extend_from_slice(&lzma2_data);

    // Pad compressed data to 4-byte boundary
    let comp_padding = (4 - (lzma2_data.len() % 4)) % 4;
    output.resize(output.len() + comp_padding, 0x00);

    // Block check: CRC-32 of uncompressed data
    let check = crc32::crc32(data);
    output.extend_from_slice(&check.to_le_bytes());

    // ── Index ───────────────────────────────────────────────────────
    let index_start = output.len();

    let mut index_body = vec![0x00]; // Index Indicator

    // Number of records = 1
    encode_vli(&mut index_body, 1);

    // Record: Unpadded Size, Uncompressed Size
    // Unpadded Size = Block Header + Compressed Data (no padding) + Check
    let unpadded_size = real_header_size + lzma2_data.len() + 4;
    encode_vli(&mut index_body, unpadded_size as u64);
    encode_vli(&mut index_body, data.len() as u64);

    // Pad index to 4-byte boundary (after indicator, before CRC)
    let index_content_len = index_body.len();
    let index_padding = (4 - (index_content_len % 4)) % 4;
    index_body.resize(index_body.len() + index_padding, 0x00);

    let index_crc = crc32::crc32(&index_body);
    output.extend_from_slice(&index_body);
    output.extend_from_slice(&index_crc.to_le_bytes());

    let index_end = output.len();
    let index_size = index_end - index_start;

    // ── Stream Footer (12 bytes) ────────────────────────────────────
    // Backward Size = (index_size / 4) - 1
    let backward_size = ((index_size / 4) - 1) as u32;
    let mut footer_fields = Vec::new();
    footer_fields.extend_from_slice(&backward_size.to_le_bytes());
    footer_fields.extend_from_slice(&stream_flags);
    let footer_crc = crc32::crc32(&footer_fields);

    output.extend_from_slice(&footer_crc.to_le_bytes());
    output.extend_from_slice(&footer_fields);
    output.push(b'Y');
    output.push(b'Z');

    Ok(output)
}

/// Encode a variable-length integer (VLI) per xz spec.
///
/// xz VLI uses 7 data bits per byte with bit 7 as continuation flag.
fn encode_vli(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            output.push(byte);
            break;
        }
        output.push(byte | 0x80);
    }
}

fn append_filter_header(
    output: &mut Vec<u8>,
    filter: &Filter,
    registry: Option<&FilterRegistry>,
) -> Result<(), Error> {
    filter.validate()?;

    match filter {
        Filter::X86 { start_offset } => {
            append_start_offset_filter(output, FILTER_X86, *start_offset);
        }
        Filter::PowerPc { start_offset } => {
            append_start_offset_filter(output, FILTER_POWERPC, *start_offset);
        }
        Filter::Ia64 { start_offset } => {
            append_start_offset_filter(output, FILTER_IA64, *start_offset);
        }
        Filter::Sparc { start_offset } => {
            append_start_offset_filter(output, FILTER_SPARC, *start_offset);
        }
        Filter::Arm { start_offset } => {
            append_start_offset_filter(output, FILTER_ARM, *start_offset);
        }
        Filter::ArmThumb { start_offset } => {
            append_start_offset_filter(output, FILTER_ARMTHUMB, *start_offset);
        }
        Filter::Arm64 { start_offset } => {
            append_start_offset_filter(output, FILTER_ARM64, *start_offset);
        }
        Filter::RiscV { start_offset } => {
            append_start_offset_filter(output, FILTER_RISCV, *start_offset);
        }
        Filter::Delta { distance } => {
            encode_vli(output, FILTER_DELTA);
            encode_vli(output, 1);
            output.push((*distance - 1) as u8);
        }
        Filter::Unknown { id, properties } => {
            if registry.and_then(|registry| registry.get(*id)).is_none() {
                return Err(Error::Unsupported("xz: unsupported custom/unknown filter"));
            }
            encode_vli(output, *id);
            encode_vli(output, properties.len() as u64);
            output.extend_from_slice(properties);
        }
    }

    Ok(())
}

fn append_start_offset_filter(output: &mut Vec<u8>, filter_id: u64, start_offset: u32) {
    encode_vli(output, filter_id);
    if start_offset == 0 {
        encode_vli(output, 0);
    } else {
        encode_vli(output, 4);
        output.extend_from_slice(&start_offset.to_le_bytes());
    }
}

/// Encode data as an xz stream from a reader.
///
/// # Errors
///
/// Returns an error if reading from the reader fails.
///
/// # Examples
///
/// ```
/// use archive::compress::xz::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode_reader(&data[..]).unwrap();
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
#[cfg(feature = "std")]
pub fn encode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    encode_reader_with_filters_and_registry(&mut reader, &[], None)
}

/// Encode all data from a reader as an xz stream with optional pre-LZMA2 block
/// filters.
#[cfg(feature = "std")]
pub fn encode_reader_with_filters<R: std::io::Read>(
    mut reader: R,
    filters: &[Filter],
) -> std::io::Result<Vec<u8>> {
    encode_reader_with_filters_and_registry(&mut reader, filters, None)
}

/// Encode all data from a reader as an xz stream with optional filters and a
/// registry for custom/unknown filters.
#[cfg(feature = "std")]
pub fn encode_reader_with_filters_and_registry<R: std::io::Read>(
    mut reader: R,
    filters: &[Filter],
    registry: Option<&FilterRegistry>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    encode_with_filters_and_registry(&buf, filters, registry).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::*;
    use crate::compress::xz::registry::FilterRegistry;

    struct XorCodec;

    struct WrongIdCodec;

    impl crate::compress::xz::registry::FilterCodec for XorCodec {
        fn filter_id(&self) -> u64 {
            0x1234
        }

        fn encode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error> {
            let key = properties.first().copied().unwrap_or(0);
            Ok(input.iter().map(|byte| byte ^ key).collect())
        }

        fn decode(&self, input: &[u8], properties: &[u8]) -> Result<Vec<u8>, Error> {
            self.encode(input, properties)
        }
    }

    impl crate::compress::xz::registry::FilterCodec for WrongIdCodec {
        fn filter_id(&self) -> u64 {
            0x9999
        }

        fn encode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(input.to_vec())
        }

        fn decode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(input.to_vec())
        }
    }

    #[test]
    fn test_encode_starts_with_magic() {
        let encoded = encode(b"test");
        assert_eq!(&encoded[..6], &STREAM_MAGIC);
    }

    #[test]
    fn test_encode_ends_with_yz() {
        let encoded = encode(b"test");
        let len = encoded.len();
        assert_eq!(&encoded[len - 2..], b"YZ");
    }

    #[test]
    fn test_encode_stream_flags_crc() {
        let encoded = encode(b"test");
        let sf = &encoded[6..8];
        let crc_bytes = &encoded[8..12];
        let expected_crc = crc32::crc32(sf);
        let actual_crc =
            u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
        assert_eq!(actual_crc, expected_crc);
    }

    #[test]
    fn test_vli_encoding() {
        let mut buf = Vec::new();
        encode_vli(&mut buf, 0);
        assert_eq!(buf, [0x00]);

        buf.clear();
        encode_vli(&mut buf, 127);
        assert_eq!(buf, [0x7F]);

        buf.clear();
        encode_vli(&mut buf, 128);
        assert_eq!(buf, [0x80, 0x01]);

        buf.clear();
        encode_vli(&mut buf, 16384);
        assert_eq!(buf, [0x80, 0x80, 0x01]);
    }

    #[test]
    fn test_encode_empty() {
        let encoded = encode(b"");
        assert_eq!(&encoded[..6], &STREAM_MAGIC);
        let len = encoded.len();
        assert_eq!(&encoded[len - 2..], b"YZ");
    }

    #[test]
    fn test_encode_with_x86_filter_roundtrip() {
        let input = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF,
        ];
        let encoded = encode_with_filters(&input, &[Filter::X86 { start_offset: 0 }]).unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_delta_filter_roundtrip() {
        let input = (0u8..=63).cycle().take(512).collect::<Vec<_>>();
        let encoded = encode_with_filters(&input, &[Filter::Delta { distance: 4 }]).unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_arm_filter_roundtrip() {
        let input = [0x01, 0x02, 0x03, 0xEB, 0x00, 0x00, 0x00, 0x00];
        let encoded = encode_with_filters(&input, &[Filter::Arm { start_offset: 0 }]).unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_ia64_filter_roundtrip() {
        let input = [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0xA0,
        ];
        let encoded = encode_with_filters(
            &input,
            &[Filter::Ia64 {
                start_offset: 0x1000,
            }],
        )
        .unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_arm64_filter_roundtrip() {
        let input = [0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90];
        let encoded = encode_with_filters(
            &input,
            &[Filter::Arm64 {
                start_offset: 0x1000,
            }],
        )
        .unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_riscv_filter_roundtrip() {
        let input = [0xEF, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
        let encoded = encode_with_filters(
            &input,
            &[Filter::RiscV {
                start_offset: 0x1000,
            }],
        )
        .unwrap();
        let decoded = super::super::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_with_invalid_delta_distance_rejected() {
        let result = encode_with_filters(b"hello", &[Filter::Delta { distance: 0 }]);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("xz: delta distance must be 1..=256"))
            ),
            "expected invalid delta distance error, got {result:?}"
        );
    }

    #[test]
    fn test_encode_with_unknown_filter_rejected() {
        let result = encode_with_filters(
            b"hello",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![1, 2, 3],
            }],
        );
        assert!(matches!(
            result,
            Err(Error::Unsupported("xz: unsupported custom/unknown filter"))
        ));
    }

    #[test]
    fn test_encode_with_empty_registry_matches_encode_with_filters() {
        let filters = [Filter::X86 { start_offset: 0 }];
        let registry = FilterRegistry::new();
        assert_eq!(
            encode_with_filters(b"registry design", &filters).unwrap(),
            encode_with_filters_and_registry(b"registry design", &filters, Some(&registry))
                .unwrap()
        );
    }

    #[test]
    fn test_custom_filter_registry_roundtrip() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom registry roundtrip",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        let decoded =
            super::super::decode::decode_with_registry(&encoded, Some(&registry)).unwrap();
        assert_eq!(decoded, b"custom registry roundtrip");
    }

    #[test]
    fn test_custom_filter_registry_decode_requires_registration() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom registry roundtrip",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        assert!(matches!(
            super::super::decode::decode(&encoded),
            Err(Error::Unsupported("xz: unsupported custom/unknown filter"))
        ));
    }

    #[test]
    fn test_custom_filter_registry_roundtrip_with_standard_filter_chain() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom registry chain",
            &[
                Filter::Delta { distance: 1 },
                Filter::Unknown {
                    id: 0x1234,
                    properties: vec![0x55],
                },
            ],
            Some(&registry),
        )
        .unwrap();
        let decoded =
            super::super::decode::decode_with_registry(&encoded, Some(&registry)).unwrap();
        assert_eq!(decoded, b"custom registry chain");
    }

    #[test]
    fn test_custom_filter_passthrough_registry_roundtrip() {
        let mut registry = FilterRegistry::new();
        registry.register_passthrough(0x1234).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom passthrough registry",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0xAA, 0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        let decoded =
            super::super::decode::decode_with_registry(&encoded, Some(&registry)).unwrap();
        assert_eq!(decoded, b"custom passthrough registry");
    }

    #[test]
    fn test_custom_filter_passthrough_registry_roundtrip_with_standard_filter_chain() {
        let mut registry = FilterRegistry::new();
        registry.register_passthrough(0x1234).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom passthrough chain",
            &[
                Filter::Delta { distance: 1 },
                Filter::Unknown {
                    id: 0x1234,
                    properties: vec![0x01],
                },
            ],
            Some(&registry),
        )
        .unwrap();
        let decoded =
            super::super::decode::decode_with_registry(&encoded, Some(&registry)).unwrap();
        assert_eq!(decoded, b"custom passthrough chain");
    }

    #[test]
    fn test_custom_filter_registry_decode_with_wrong_codec_id_rejected() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = encode_with_filters_and_registry(
            b"custom registry roundtrip",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();

        let mut wrong_registry = FilterRegistry::new();
        wrong_registry.register(Box::new(WrongIdCodec)).unwrap();
        assert!(matches!(
            super::super::decode::decode_with_registry(&encoded, Some(&wrong_registry)),
            Err(Error::Unsupported("xz: unsupported custom/unknown filter"))
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_reader_with_filters_and_registry_roundtrip() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = encode_reader_with_filters_and_registry(
            &b"reader registry roundtrip"[..],
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
            Some(&registry),
        )
        .unwrap();
        let decoded =
            super::super::decode::decode_with_registry(&encoded, Some(&registry)).unwrap();
        assert_eq!(decoded, b"reader registry roundtrip");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_encode_reader_with_filters_without_registry_rejects_custom_filter() {
        let err = encode_reader_with_filters(
            &b"reader registry roundtrip"[..],
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x55],
            }],
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("unsupported custom/unknown filter")
        );
    }
}
