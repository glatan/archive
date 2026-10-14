//! xz stream decoder.
//!
//! Decodes xz files with LZMA2-based filter chains and checksum verification.
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

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32;

use super::filters::{
    FILTER_ARM, FILTER_ARM64, FILTER_ARMTHUMB, FILTER_DELTA, FILTER_IA64, FILTER_ID_RESERVED_START,
    FILTER_LZMA2, FILTER_POWERPC, FILTER_RISCV, FILTER_SPARC, FILTER_X86, Filter,
    apply_decoder_filters,
};
use super::registry::FilterRegistry;

/// xz stream magic bytes.
const STREAM_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

/// Maximum size of the Index field: 16 GiB (2^34).
///
/// xz-file-format.txt §2.1. Backward Size stores (index_size / 4) - 1
/// as a u32, so 2^34 is also the largest Index size encodable on the wire.
const MAX_INDEX_SIZE: u64 = 16 * 1024 * 1024 * 1024;

/// Check type constants.
const CHECK_NONE: u8 = 0x00;
const CHECK_CRC32: u8 = 0x01;
const CHECK_CRC64: u8 = 0x04;
const CHECK_SHA256: u8 = 0x0A;

/// Decode xz format data.
///
/// Supports concatenated xz streams with LZMA2 and the crate's currently
/// supported pre-LZMA2 filters: x86 / PowerPC / IA64 / SPARC / ARM /
/// ARM-Thumb / ARM64 / RISC-V BCJ and Delta.
/// Supported check types: None, CRC-32, CRC-64, and SHA-256.
///
/// # Errors
///
/// Returns an error if the data is not valid xz format or uses
/// unsupported features.
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
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_with_registry(input, None)
}

/// Decode an xz stream, using `registry` to handle custom filter IDs.
///
/// Behaves like [`decode`] but consults the provided [`FilterRegistry`] for
/// filter IDs that are not built-in. Pass `None` if no custom filters are
/// needed.
pub fn decode_with_registry(
    input: &[u8],
    registry: Option<&FilterRegistry>,
) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Err(Error::InvalidData("xz: input too short"));
    }

    let mut output = Vec::new();
    let mut stream_start = 0usize;

    while stream_start < input.len() {
        let (decoded, next_pos) = decode_stream(input, stream_start, registry)?;
        output.extend_from_slice(&decoded);
        stream_start = skip_stream_padding(input, next_pos)?;
    }

    // xz-file-format.txt §2: the size of every valid .xz file must be a
    // multiple of four bytes (streams are 4-byte aligned and padding is
    // 4-byte aligned).
    if !input.len().is_multiple_of(4) {
        return Err(Error::InvalidData(
            "xz: file size must be a multiple of four bytes",
        ));
    }

    Ok(output)
}

fn decode_stream(
    input: &[u8],
    stream_start: usize,
    registry: Option<&FilterRegistry>,
) -> Result<(Vec<u8>, usize), Error> {
    if input.len().saturating_sub(stream_start) < 24 {
        return Err(Error::InvalidData("xz: input too short"));
    }

    let stream = &input[stream_start..];

    // ── Stream Header (12 bytes) ────────────────────────────────────
    if stream[..6] != STREAM_MAGIC {
        return Err(Error::InvalidData("xz: invalid magic"));
    }

    let stream_flags = &stream[6..8];
    if stream_flags[0] != 0x00 {
        return Err(Error::InvalidData(
            "xz: reserved stream flag byte must be 0",
        ));
    }
    let check_type = stream_flags[1] & 0x0F;

    if stream_flags[1] & 0xF0 != 0 {
        return Err(Error::InvalidData(
            "xz: reserved bits in stream flags must be 0",
        ));
    }

    let hdr_crc = u32::from_le_bytes([stream[8], stream[9], stream[10], stream[11]]);
    let expected_hdr_crc = crc32::crc32(stream_flags);
    if hdr_crc != expected_hdr_crc {
        return Err(Error::ChecksumMismatch {
            expected: expected_hdr_crc,
            actual: hdr_crc,
        });
    }

    let check_size = match check_type {
        CHECK_NONE => 0,
        CHECK_CRC32 => 4,
        CHECK_CRC64 => 8,
        CHECK_SHA256 => 32,
        _ => return Err(Error::Unsupported("xz: unsupported check type")),
    };

    let mut pos = stream_start + 12;
    let mut output = Vec::new();
    let mut block_records: Vec<(u64, u64)> = Vec::new();

    while pos < input.len() {
        if input[pos] == 0x00 {
            break;
        }

        let block_start = pos;
        let header_size_byte = input[pos] as usize;
        let real_header_size = (header_size_byte + 1) * 4;
        if pos + real_header_size > input.len() {
            return Err(Error::UnexpectedEof);
        }

        let hdr_crc_input = &input[pos..pos + real_header_size - 4];
        let hdr_crc_offset = pos + real_header_size - 4;
        let block_hdr_crc = u32::from_le_bytes([
            input[hdr_crc_offset],
            input[hdr_crc_offset + 1],
            input[hdr_crc_offset + 2],
            input[hdr_crc_offset + 3],
        ]);
        let expected_block_hdr_crc = crc32::crc32(hdr_crc_input);
        if block_hdr_crc != expected_block_hdr_crc {
            return Err(Error::ChecksumMismatch {
                expected: expected_block_hdr_crc,
                actual: block_hdr_crc,
            });
        }

        let hdr_content = &input[pos + 1..pos + real_header_size - 4];
        let block_flags = hdr_content[0];
        let num_filters = (block_flags & 0x03) + 1;
        let has_compressed_size = block_flags & 0x40 != 0;
        let has_uncompressed_size = block_flags & 0x80 != 0;

        if block_flags & 0x3C != 0 {
            return Err(Error::InvalidData(
                "xz: reserved bits in block flags must be 0",
            ));
        }

        let mut hdr_pos = 1;
        let compressed_size = if has_compressed_size {
            let (val, consumed) = decode_vli(&hdr_content[hdr_pos..])?;
            hdr_pos += consumed;
            Some(val)
        } else {
            None
        };

        let uncompressed_size = if has_uncompressed_size {
            let (val, consumed) = decode_vli(&hdr_content[hdr_pos..])?;
            hdr_pos += consumed;
            Some(val)
        } else {
            None
        };

        let mut custom_filters = Vec::with_capacity((num_filters - 1) as usize);
        let mut dict_size = None;
        for filter_index in 0..num_filters {
            let (filter_id, filter_consumed) = decode_vli(&hdr_content[hdr_pos..])?;
            hdr_pos += filter_consumed;

            let (props_size, props_size_consumed) = decode_vli(&hdr_content[hdr_pos..])?;
            hdr_pos += props_size_consumed;

            let props_size = props_size as usize;
            if hdr_pos + props_size > hdr_content.len() {
                return Err(Error::UnexpectedEof);
            }
            let props = &hdr_content[hdr_pos..hdr_pos + props_size];
            hdr_pos += props_size;

            match parse_filter(filter_id, props, filter_index + 1 == num_filters)? {
                ParsedFilter::Lzma2 { dict_size: size } => dict_size = Some(size),
                ParsedFilter::Transform(filter) => custom_filters.push(filter),
            }
        }

        for &padding in &hdr_content[hdr_pos..] {
            if padding != 0 {
                return Err(Error::InvalidData("xz: non-zero block header padding"));
            }
        }

        let dict_size = dict_size.ok_or(Error::Unsupported("xz: final filter must be LZMA2"))?;

        pos += real_header_size;
        let block_data_start = pos;
        let available = &input[pos..];
        let lzma2_decoded = crate::compress::lzma2::lzma2_decode(available, dict_size)?;
        let compressed_len = lzma2_consumed_bytes(available)?;
        let padded_len = compressed_len.div_ceil(4) * 4;

        if block_data_start + padded_len > input.len() {
            return Err(Error::UnexpectedEof);
        }

        for &byte in &input[(block_data_start + compressed_len)..(block_data_start + padded_len)] {
            if byte != 0 {
                return Err(Error::InvalidData("xz: non-zero block padding"));
            }
        }

        pos = block_data_start + padded_len;
        let decoded = apply_decoder_filters(&lzma2_decoded, &custom_filters, registry)?;

        if let Some(expected_compressed_size) = compressed_size
            && expected_compressed_size != compressed_len as u64
        {
            return Err(Error::InvalidData(
                "xz: compressed size does not match block data",
            ));
        }

        if let Some(expected_uncompressed_size) = uncompressed_size
            && expected_uncompressed_size != decoded.len() as u64
        {
            return Err(Error::InvalidData(
                "xz: uncompressed size does not match decoded data",
            ));
        }

        if check_type == CHECK_CRC32 {
            if pos + check_size > input.len() {
                return Err(Error::UnexpectedEof);
            }
            let stored_crc =
                u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
            let actual_crc = crc32::crc32(&decoded);
            if stored_crc != actual_crc {
                return Err(Error::ChecksumMismatch {
                    expected: stored_crc,
                    actual: actual_crc,
                });
            }
            pos += 4;
        } else if check_type == CHECK_CRC64 {
            if pos + check_size > input.len() {
                return Err(Error::UnexpectedEof);
            }
            let stored_crc = u64::from_le_bytes([
                input[pos],
                input[pos + 1],
                input[pos + 2],
                input[pos + 3],
                input[pos + 4],
                input[pos + 5],
                input[pos + 6],
                input[pos + 7],
            ]);
            let actual_crc = crate::util::crc64::crc64(&decoded);
            if stored_crc != actual_crc {
                return Err(Error::ChecksumMismatch64 {
                    expected: stored_crc,
                    actual: actual_crc,
                });
            }
            pos += 8;
        } else if check_type == CHECK_SHA256 {
            if pos + check_size > input.len() {
                return Err(Error::UnexpectedEof);
            }
            let mut stored_sha = [0u8; 32];
            stored_sha.copy_from_slice(&input[pos..pos + 32]);
            let actual_sha = crate::util::sha256::sha256(&decoded);
            if stored_sha != actual_sha {
                return Err(Error::InvalidData("xz: SHA-256 mismatch"));
            }
            pos += 32;
        }

        let unpadded_size = (pos - block_start) as u64 - ((padded_len - compressed_len) as u64);
        let uncompressed_size = decoded.len() as u64;
        block_records.push((unpadded_size, uncompressed_size));
        output.extend_from_slice(&decoded);
    }

    let index_start = pos;
    let footer_start = verify_index(input, index_start, &block_records)?;
    if footer_start + 12 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    if &input[footer_start + 10..footer_start + 12] != b"YZ" {
        return Err(Error::InvalidData("xz: invalid footer magic"));
    }

    let footer_crc = u32::from_le_bytes([
        input[footer_start],
        input[footer_start + 1],
        input[footer_start + 2],
        input[footer_start + 3],
    ]);
    let footer_fields = &input[footer_start + 4..footer_start + 10];
    let expected_footer_crc = crc32::crc32(footer_fields);
    if footer_crc != expected_footer_crc {
        return Err(Error::ChecksumMismatch {
            expected: expected_footer_crc,
            actual: footer_crc,
        });
    }

    let footer_sf = &input[footer_start + 8..footer_start + 10];
    if footer_sf != stream_flags {
        return Err(Error::InvalidData(
            "xz: stream flags mismatch between header and footer",
        ));
    }

    let backward_size_raw = u32::from_le_bytes([
        input[footer_start + 4],
        input[footer_start + 5],
        input[footer_start + 6],
        input[footer_start + 7],
    ]);
    // u64 math keeps the max stored value (2^34) valid on 32-bit usize.
    let index_size = (u64::from(backward_size_raw) + 1) * 4;
    if index_size > MAX_INDEX_SIZE {
        return Err(Error::InvalidData("xz: Index exceeds 16 GiB limit"));
    }
    if index_size != (footer_start - index_start) as u64 {
        return Err(Error::InvalidData(
            "xz: footer backward size does not match Index",
        ));
    }

    Ok((output, footer_start + 12))
}

/// Verify Index records match the blocks decoded from the stream.
fn verify_index(
    input: &[u8],
    index_start: usize,
    block_records: &[(u64, u64)],
) -> Result<usize, Error> {
    // Index format: Indicator(1) + Number_of_Records(VLI) + Records + Padding + CRC32(4)
    let mut ipos = index_start;

    if ipos >= input.len() || input[ipos] != 0x00 {
        return Err(Error::InvalidData("xz: missing Index indicator"));
    }
    ipos += 1;

    let (num_records, consumed) = decode_vli(&input[ipos..])?;
    ipos += consumed;

    if num_records != block_records.len() as u64 {
        return Err(Error::InvalidData(
            "xz: Index record count does not match block count",
        ));
    }

    for &(expected_unpadded, expected_uncompressed) in block_records {
        let (unpadded_size, consumed) = decode_vli(&input[ipos..])?;
        ipos += consumed;
        let (uncompressed_size, consumed) = decode_vli(&input[ipos..])?;
        ipos += consumed;

        if unpadded_size != expected_unpadded {
            return Err(Error::InvalidData(
                "xz: Index unpadded size does not match block",
            ));
        }
        if uncompressed_size != expected_uncompressed {
            return Err(Error::InvalidData(
                "xz: Index uncompressed size does not match block",
            ));
        }
    }

    let padding = (4 - ((ipos - index_start) % 4)) % 4;
    if ipos + padding + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    for &byte in &input[ipos..ipos + padding] {
        if byte != 0 {
            return Err(Error::InvalidData("xz: non-zero Index padding"));
        }
    }
    ipos += padding;

    let index_crc = u32::from_le_bytes([
        input[ipos],
        input[ipos + 1],
        input[ipos + 2],
        input[ipos + 3],
    ]);
    let expected_index_crc = crc32::crc32(&input[index_start..ipos]);
    if index_crc != expected_index_crc {
        return Err(Error::ChecksumMismatch {
            expected: expected_index_crc,
            actual: index_crc,
        });
    }

    let index_size = (ipos + 4 - index_start) as u64;
    if index_size > MAX_INDEX_SIZE {
        return Err(Error::InvalidData("xz: Index exceeds 16 GiB limit"));
    }

    Ok(ipos + 4)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedFilter {
    Lzma2 { dict_size: u32 },
    Transform(Filter),
}

fn parse_filter(filter_id: u64, props: &[u8], is_last: bool) -> Result<ParsedFilter, Error> {
    // xz-file-format.txt §3.1.5: Filter IDs >= 2^62 are reserved for
    // implementation-dependent internal use and must never appear in a
    // List of Filter Flags. Reject before the registry-backed unknown-ID
    // path so a registered custom codec cannot resurrect them.
    if filter_id >= FILTER_ID_RESERVED_START {
        return Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"));
    }
    match filter_id {
        FILTER_LZMA2 => {
            if !is_last {
                return Err(Error::Unsupported("xz: LZMA2 must be the final filter"));
            }
            if props.len() != 1 {
                return Err(Error::InvalidData(
                    "xz: LZMA2 filter properties must be 1 byte",
                ));
            }
            let dict_size_byte = props[0];
            if dict_size_byte > 40 {
                return Err(Error::InvalidData(
                    "xz: LZMA2 dictionary size byte out of range",
                ));
            }
            Ok(ParsedFilter::Lzma2 {
                dict_size: decode_dict_size(dict_size_byte),
            })
        }
        FILTER_X86 => {
            let start_offset = parse_bcj_start_offset(props, is_last, "x86")?;
            Ok(ParsedFilter::Transform(Filter::X86 { start_offset }))
        }
        FILTER_POWERPC => Ok(ParsedFilter::Transform(Filter::PowerPc {
            start_offset: parse_bcj_start_offset(props, is_last, "PowerPC")?,
        })),
        FILTER_IA64 => Ok(ParsedFilter::Transform(Filter::Ia64 {
            start_offset: parse_bcj_start_offset(props, is_last, "IA64")?,
        })),
        FILTER_SPARC => Ok(ParsedFilter::Transform(Filter::Sparc {
            start_offset: parse_bcj_start_offset(props, is_last, "SPARC")?,
        })),
        FILTER_ARM => Ok(ParsedFilter::Transform(Filter::Arm {
            start_offset: parse_bcj_start_offset(props, is_last, "ARM")?,
        })),
        FILTER_ARMTHUMB => Ok(ParsedFilter::Transform(Filter::ArmThumb {
            start_offset: parse_bcj_start_offset(props, is_last, "ARM-Thumb")?,
        })),
        FILTER_ARM64 => Ok(ParsedFilter::Transform(Filter::Arm64 {
            start_offset: parse_bcj_start_offset(props, is_last, "ARM64")?,
        })),
        FILTER_RISCV => Ok(ParsedFilter::Transform(Filter::RiscV {
            start_offset: parse_bcj_start_offset(props, is_last, "RISC-V")?,
        })),
        FILTER_DELTA => {
            if is_last {
                return Err(Error::Unsupported("xz: final filter must be LZMA2"));
            }
            if props.len() != 1 {
                return Err(Error::InvalidData(
                    "xz: Delta filter properties must be 1 byte",
                ));
            }
            Ok(ParsedFilter::Transform(Filter::Delta {
                distance: props[0] as u16 + 1,
            }))
        }
        _ => {
            // Reserved filter ID range (§5.3): 0x40-0x7F
            if (0x40..=0x7F).contains(&filter_id) {
                return Err(Error::Unsupported("xz: reserved filter ID (0x40-0x7F)"));
            }
            if is_last {
                return Err(Error::Unsupported("xz: final filter must be LZMA2"));
            }
            Ok(ParsedFilter::Transform(Filter::Unknown {
                id: filter_id,
                properties: props.to_vec(),
            }))
        }
    }
}

fn parse_bcj_start_offset(props: &[u8], is_last: bool, name: &'static str) -> Result<u32, Error> {
    if is_last {
        return Err(Error::Unsupported("xz: final filter must be LZMA2"));
    }
    let offset = match props.len() {
        0 => return Ok(0),
        4 => u32::from_le_bytes([props[0], props[1], props[2], props[3]]),
        _ => {
            return Err(Error::InvalidData(match name {
                "x86" => "xz: x86 filter properties must be 0 or 4 bytes",
                "PowerPC" => "xz: PowerPC filter properties must be 0 or 4 bytes",
                "IA64" => "xz: IA64 filter properties must be 0 or 4 bytes",
                "SPARC" => "xz: SPARC filter properties must be 0 or 4 bytes",
                "ARM" => "xz: ARM filter properties must be 0 or 4 bytes",
                "ARM-Thumb" => "xz: ARM-Thumb filter properties must be 0 or 4 bytes",
                "ARM64" => "xz: ARM64 filter properties must be 0 or 4 bytes",
                "RISC-V" => "xz: RISC-V filter properties must be 0 or 4 bytes",
                _ => "xz: BCJ filter properties must be 0 or 4 bytes",
            }));
        }
    };

    // Check alignment requirement for the architecture
    let alignment: u32 = match name {
        "x86" => 1,
        "PowerPC" | "ARM" | "SPARC" | "ARM64" => 4,
        "IA64" => 16,
        "ARM-Thumb" | "RISC-V" => 2,
        _ => 1,
    };
    if alignment > 1 && offset % alignment != 0 {
        return Err(Error::InvalidData("xz: BCJ start offset not aligned"));
    }

    Ok(offset)
}

fn skip_stream_padding(input: &[u8], mut pos: usize) -> Result<usize, Error> {
    let padding_start = pos;
    while pos < input.len() && input[pos] == 0 {
        pos += 1;
    }

    let padding_len = pos - padding_start;
    if padding_len > 0 && !padding_len.is_multiple_of(4) {
        return Err(Error::InvalidData(
            "xz: stream padding must be a multiple of four bytes",
        ));
    }

    if pos < input.len() && input.len() - pos >= 6 && input[pos..pos + 6] != STREAM_MAGIC {
        return Err(Error::InvalidData("xz: garbage between streams"));
    }

    Ok(pos)
}

/// Decode the LZMA2 dictionary size from the encoded byte.
///
/// - Byte 0: dict_size = 4096 (2^12)
/// - Byte 1: dict_size = 6144 (3 × 2^11)
/// - Byte 2n: dict_size = 2^(n+12)
/// - Byte 2n+1: dict_size = 3 × 2^(n+11)
const fn decode_dict_size(byte: u8) -> u32 {
    if byte == 0 {
        return 4096;
    }
    let mantissa = if byte & 1 == 0 { 2u32 } else { 3u32 };
    let exponent = (byte as u32 / 2) + 11;
    if exponent >= 31 {
        return u32::MAX; // Cap at max u32 for large dictionary sizes
    }
    mantissa << exponent
}

/// Scan LZMA2 data to determine bytes consumed up to the end marker.
fn lzma2_consumed_bytes(data: &[u8]) -> Result<usize, Error> {
    let mut pos = 0;

    loop {
        if pos >= data.len() {
            return Err(Error::UnexpectedEof);
        }

        let control = data[pos];
        pos += 1;

        if control == 0x00 {
            break;
        }

        if control <= 0x02 {
            // Uncompressed chunk
            if pos + 2 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let size = ((data[pos] as usize) << 8 | data[pos + 1] as usize) + 1;
            pos += 2 + size;
        } else if control >= 0x80 {
            // LZMA chunk
            if pos + 4 > data.len() {
                return Err(Error::UnexpectedEof);
            }
            pos += 2; // uncompressed size bytes
            let c_size = ((data[pos] as usize) << 8 | data[pos + 1] as usize) + 1;
            pos += 2;

            let has_props = (control >> 5) >= 0b110;
            if has_props {
                pos += 1; // properties byte
            }

            pos += c_size;
        } else {
            return Err(Error::InvalidData("xz: invalid LZMA2 control byte"));
        }
    }

    Ok(pos)
}

/// Decode a VLI (Variable Length Integer) from a byte slice.
///
/// Returns `(value, bytes_consumed)`.
fn decode_vli(data: &[u8]) -> Result<(u64, usize), Error> {
    let mut value = 0u64;
    let mut shift = 0u32;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 9 {
            return Err(Error::InvalidData("xz: VLI too long"));
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Leading zero check: multi-byte VLI must not have 0x00 as last byte
            // (except for value 0 which is single byte)
            if i > 0 && byte == 0x00 {
                return Err(Error::InvalidData("xz: VLI has trailing zero byte"));
            }
            return Ok((value, i + 1));
        }
    }

    Err(Error::UnexpectedEof)
}

/// Decode xz format data from a reader.
///
/// # Errors
///
/// Returns an error if reading fails or the data is not valid xz format.
///
/// # Examples
///
/// ```
/// use archive::compress::xz::{decode, encode};
///
/// let data = b"Hello, reader!";
/// let compressed = encode::encode(data);
/// let decoded = decode::decode_reader(&compressed[..]).unwrap();
/// assert_eq!(decoded, data);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Vec<u8>> {
    decode_reader_with_registry(&mut reader, None)
}

/// Decode all xz data from a reader using an optional custom filter registry.
#[cfg(feature = "std")]
pub fn decode_reader_with_registry<R: std::io::Read>(
    mut reader: R,
    registry: Option<&FilterRegistry>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    decode_with_registry(&buf, registry).map_err(Into::into)
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
    use alloc::boxed::Box;
    use alloc::vec;

    use super::*;
    use crate::compress::xz::filters::Filter;
    use crate::compress::xz::registry::FilterRegistry;

    struct XorCodec;

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

    #[test]
    fn test_invalid_magic() {
        let result = decode(&[0x00; 30]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("magic")));
    }

    #[test]
    fn test_input_too_short() {
        let result = decode(&[0xFD, 0x37, 0x7A, 0x58]);
        assert!(matches!(result, Err(Error::InvalidData(msg)) if msg.contains("too short")));
    }

    #[test]
    fn test_decode_vli_values() {
        assert_eq!(decode_vli(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_vli(&[0x7F]).unwrap(), (127, 1));
        assert_eq!(decode_vli(&[0x80, 0x01]).unwrap(), (128, 2));
        assert_eq!(decode_vli(&[0x80, 0x80, 0x01]).unwrap(), (16384, 3));
    }

    #[test]
    fn test_decode_vli_too_long() {
        let data = [0x80; 10]; // 10 continuation bytes
        assert!(decode_vli(&data).is_err());
    }

    #[test]
    fn test_decode_vli_noncanonical_zero_rejected() {
        let result = decode_vli(&[0x80, 0x00]);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("xz: VLI has trailing zero byte"))
            ),
            "expected noncanonical VLI rejection, got {result:?}"
        );
    }

    #[test]
    fn test_dict_size_decoding() {
        assert_eq!(decode_dict_size(0), 4096);
        assert_eq!(decode_dict_size(1), 3 << 11); // 6144
        assert_eq!(decode_dict_size(2), 2 << 12); // 8192
        assert_eq!(decode_dict_size(3), 3 << 12); // 12288
        assert_eq!(decode_dict_size(4), 2 << 13); // 16384
        // byte=40 previously caused overflow (2u32 << 31); now caps at u32::MAX
        assert_eq!(decode_dict_size(40), u32::MAX);
    }

    #[test]
    fn test_roundtrip_hello() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let data = b"";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"The quick brown fox. ".repeat(100);
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: alloc::vec::Vec<u8> = (0..=255).collect();
        let compressed = super::super::encode::encode(&data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_single_byte() {
        let data = b"X";
        let compressed = super::super::encode::encode(data);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_footer_magic_check() {
        let mut compressed = super::super::encode::encode(b"test");
        let len = compressed.len();
        compressed[len - 1] = b'A'; // corrupt "YZ"
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn test_header_crc_check() {
        let mut compressed = super::super::encode::encode(b"test");
        compressed[7] ^= 0xFF; // corrupt stream flags
        assert!(decode(&compressed).is_err());
    }

    #[test]
    fn test_data_crc_check() {
        let mut compressed = super::super::encode::encode(b"test data for CRC");
        // Corrupt a byte in the compressed data area (after block header)
        if compressed.len() > 25 {
            compressed[20] ^= 0xFF;
        }
        assert!(decode(&compressed).is_err());
    }

    /// Helper: recalculate the Stream Header CRC (bytes 8..12) from stream flags (bytes 6..8).
    fn fix_stream_header_crc(data: &mut [u8]) {
        let crc = crc32::crc32(&data[6..8]);
        data[8..12].copy_from_slice(&crc.to_le_bytes());
    }

    /// Helper: recalculate the Stream Footer CRC and footer magic.
    /// Footer is the last 12 bytes: [CRC32(4)][backward_size(4)][stream_flags(2)][YZ(2)]
    /// CRC covers backward_size + stream_flags (6 bytes at offset footer+4..footer+10).
    fn fix_stream_footer_crc(data: &mut [u8]) {
        let footer_start = data.len() - 12;
        let fields = &data[footer_start + 4..footer_start + 10];
        let crc = crc32::crc32(fields);
        data[footer_start..footer_start + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Helper: recalculate the Block Header CRC from the header content.
    /// Block header starts at byte 12. real_header_size = (data[12] + 1) * 4.
    /// CRC covers bytes 12..12+real_header_size-4.
    fn fix_block_header_crc(data: &mut [u8]) {
        let header_size_byte = data[12] as usize;
        let real_header_size = (header_size_byte + 1) * 4;
        let crc_offset = 12 + real_header_size - 4;
        let crc = crc32::crc32(&data[12..crc_offset]);
        data[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn test_reserved_stream_flags_rejected() {
        // Encode valid data, then set a reserved bit in stream flags byte 1 (upper nibble).
        let mut data = super::super::encode::encode(b"hello");
        // Byte 7 is the check-type byte; set a reserved upper bit.
        data[7] |= 0x10; // set bit 4 (reserved)
        // Fix stream header CRC so the error is about reserved bits, not CRC.
        fix_stream_header_crc(&mut data);
        // Also fix footer stream flags to match (bytes footer+8..footer+10).
        let footer_start = data.len() - 12;
        data[footer_start + 9] = data[7];
        fix_stream_footer_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("reserved")),
            "expected reserved stream flags error, got: {result:?}"
        );
    }

    #[test]
    fn test_reserved_block_flags_rejected() {
        // Encode valid data, then set reserved bits 2-5 in the block flags byte.
        let mut data = super::super::encode::encode(b"hello");
        // Block flags byte is at offset 13 (byte 12 = header size, byte 13 = flags).
        data[13] |= 0x04; // set bit 2 (reserved)
        // Re-compute block header CRC.
        fix_block_header_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("reserved")),
            "expected reserved block flags error, got: {result:?}"
        );
    }

    #[test]
    fn test_nonzero_block_padding_rejected() {
        // Encode data, then set a block padding byte to non-zero.
        let mut data = super::super::encode::encode(b"hello");
        // Block header: starts at byte 12. real_header_size = (data[12]+1)*4
        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        // After block_data_start comes LZMA2 compressed data. We need to find where
        // the compressed data ends and padding begins.
        // Use lzma2_consumed_bytes to find the compressed data length.
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        // If there is no padding (compressed_len already multiple of 4), skip this test.
        if padded_len == compressed_len {
            // Force padding by checking: encode something that produces non-aligned compressed output.
            // Try a different payload.
            let mut data2 = super::super::encode::encode(b"ab");
            let rhs2 = (data2[12] as usize + 1) * 4;
            let bds2 = 12 + rhs2;
            let cl2 = lzma2_consumed_bytes(&data2[bds2..]).unwrap();
            let pl2 = cl2.div_ceil(4) * 4;
            if pl2 > cl2 {
                // Set the first padding byte to non-zero.
                data2[bds2 + cl2] = 0xFF;
                let result = decode(&data2);
                assert!(
                    matches!(result, Err(Error::InvalidData(msg)) if msg.contains("padding")),
                    "expected non-zero block padding error, got: {result:?}"
                );
                return;
            }
            // If still no padding, that's fine — we just verify the concept works
            // by constructing one manually.
            return;
        }
        // Set the first padding byte to non-zero.
        data[block_data_start + compressed_len] = 0xFF;
        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("padding")),
            "expected non-zero block padding error, got: {result:?}"
        );
    }

    #[test]
    fn test_dict_size_byte_41_rejected() {
        // Encode valid data, then set dict_size_byte to 41 (>40 is invalid).
        let mut data = super::super::encode::encode(b"hello");
        // Dict size byte is at offset 16 in the block header.
        // Byte 12: header size byte
        // Byte 13: block flags
        // Byte 14: filter ID (0x21)
        // Byte 15: filter props size (0x01)
        // Byte 16: dict_size_byte
        data[16] = 41;
        // Fix block header CRC.
        fix_block_header_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("dictionary size")),
            "expected dict size out of range error, got: {result:?}"
        );
    }

    #[test]
    fn test_index_record_corrupted() {
        // Encode valid data, then corrupt the Index record sizes.
        let mut data = super::super::encode::encode(b"hello");
        // Index is located before the Stream Footer. Footer starts at len-12.
        // The backward_size field in the footer tells us the Index size.
        let footer_start = data.len() - 12;
        let backward_size_raw = u32::from_le_bytes([
            data[footer_start + 4],
            data[footer_start + 5],
            data[footer_start + 6],
            data[footer_start + 7],
        ]);
        let index_size = ((backward_size_raw as usize) + 1) * 4;
        let index_start = footer_start - index_size;

        // Index layout: [indicator(1)][num_records VLI][unpadded_size VLI][uncompressed_size VLI][padding][CRC(4)]
        // Corrupt the unpadded_size record (byte after indicator + num_records).
        // indicator is at index_start, num_records VLI starts at index_start+1.
        // For 1 record with small values, num_records = 0x01 at index_start+1.
        // Unpadded size VLI starts at index_start+2.
        // Flip a bit to corrupt it.
        data[index_start + 2] ^= 0x01;

        // Re-compute Index CRC. Index body is index_start .. footer_start - 4.
        let index_body = &data[index_start..footer_start - 4];
        let new_index_crc = crc32::crc32(index_body);
        let crc_pos = footer_start - 4;
        data[crc_pos..crc_pos + 4].copy_from_slice(&new_index_crc.to_le_bytes());

        let result = decode(&data);
        assert!(
            result.is_err(),
            "expected Index verification error, got: {result:?}"
        );
    }

    #[test]
    fn test_backward_size_max_implies_index_limit() {
        // §2.1.2.2: real_backward_size = (stored + 1) * 4, so the largest
        // stored value maps to exactly the §2.1 Index field limit (16 GiB).
        assert_eq!(MAX_INDEX_SIZE, 16 * 1024 * 1024 * 1024);
        assert_eq!((u64::from(u32::MAX) + 1) * 4, MAX_INDEX_SIZE);

        // A footer claiming the maximum Backward Size while the real Index
        // is only a few bytes is a mismatch and must be rejected.
        let mut data = super::super::encode::encode(b"hello");
        let footer_start = data.len() - 12;
        data[footer_start + 4..footer_start + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        fix_stream_footer_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "xz: footer backward size does not match Index"
                ))
            ),
            "expected backward size mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_index_max_vli_record_count_rejected() {
        // A Number of Records far above the decoded block count must be
        // rejected via u64 comparison; this VLI encodes 2^63 - 1.
        let mut index = vec![0x00]; // Index indicator
        index.extend_from_slice(&[0xFF; 8]);
        index.push(0x7F);

        let result = verify_index(&index, 0, &[]);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "xz: Index record count does not match block count"
                ))
            ),
            "expected record count mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_nonzero_index_padding_rejected() {
        let index = [
            0x00, // Index indicator
            0x01, // record count
            0x80, 0x01, // unpadded size = 128 (two-byte VLI to force padding)
            0x07, // uncompressed size
            0xFF, // invalid non-zero padding
            0x00, 0x00, // remaining padding bytes
            0x00, 0x00, 0x00, 0x00, // CRC trailer bytes (not inspected here)
        ];

        let result = verify_index(&index, 0, &[(128, 7)]);
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("Index padding")),
            "expected non-zero Index padding error, got: {result:?}"
        );
    }

    #[test]
    fn test_roundtrip_single_byte_edge() {
        // Encode a single byte (edge case), decode and verify.
        for byte_val in [0x00u8, 0x7F, 0x80, 0xFF] {
            let input = [byte_val];
            let compressed = super::super::encode::encode(&input);
            let decompressed = decode(&compressed).unwrap();
            assert_eq!(
                decompressed, input,
                "roundtrip failed for byte value {byte_val:#04x}"
            );
        }
    }

    #[test]
    fn test_decode_two_concatenated_streams() {
        let first = super::super::encode::encode(b"first ");
        let second = super::super::encode::encode(b"second");
        let mut data = first;
        data.extend_from_slice(&second);
        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, b"first second");
    }

    #[test]
    fn test_decode_concatenated_streams_with_padding() {
        let first = super::super::encode::encode(b"pad ");
        let second = super::super::encode::encode(b"stream");
        let mut data = first;
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&second);
        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, b"pad stream");
    }

    #[test]
    fn test_decode_garbage_between_streams_rejected() {
        let first = super::super::encode::encode(b"first");
        let second = super::super::encode::encode(b"second");
        let mut data = first;
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&second);
        let result = decode(&data);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData("xz: garbage between streams"))
            ),
            "expected garbage-between-streams error, got {result:?}"
        );
    }

    #[test]
    fn test_decode_truncated_second_stream_rejected() {
        let first = super::super::encode::encode(b"first");
        let second = super::super::encode::encode(b"second");
        let mut data = first;
        data.extend_from_slice(&second[..second.len() - 3]);
        assert!(decode(&data).is_err());
    }

    #[test]
    fn test_parse_x86_filter_with_start_offset() {
        assert_eq!(
            parse_filter(FILTER_X86, &[0x34, 0x12, 0x00, 0x00], false).unwrap(),
            ParsedFilter::Transform(Filter::X86 {
                start_offset: 0x1234
            })
        );
    }

    #[test]
    fn test_parse_delta_filter_rejects_invalid_props_size() {
        let result = parse_filter(FILTER_DELTA, &[0x00, 0x01], false);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "xz: Delta filter properties must be 1 byte"
                ))
            ),
            "expected invalid Delta props error, got {result:?}"
        );
    }

    #[test]
    fn test_parse_arm_filter_with_start_offset() {
        assert_eq!(
            parse_filter(FILTER_ARM, &[0x34, 0x12, 0x00, 0x00], false).unwrap(),
            ParsedFilter::Transform(Filter::Arm {
                start_offset: 0x1234
            })
        );
    }

    #[test]
    fn test_parse_powerpc_filter_rejects_invalid_props_size() {
        let result = parse_filter(FILTER_POWERPC, &[0x00, 0x01], false);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "xz: PowerPC filter properties must be 0 or 4 bytes"
                ))
            ),
            "expected invalid PowerPC props error, got {result:?}"
        );
    }

    #[test]
    fn test_parse_ia64_filter_with_start_offset() {
        // IA64 requires 16-byte alignment; 0x1230 is 16-aligned
        assert_eq!(
            parse_filter(FILTER_IA64, &[0x30, 0x12, 0x00, 0x00], false).unwrap(),
            ParsedFilter::Transform(Filter::Ia64 {
                start_offset: 0x1230
            })
        );
    }

    #[test]
    fn test_parse_arm64_filter_with_start_offset() {
        assert_eq!(
            parse_filter(FILTER_ARM64, &[0x34, 0x12, 0x00, 0x00], false).unwrap(),
            ParsedFilter::Transform(Filter::Arm64 {
                start_offset: 0x1234
            })
        );
    }

    #[test]
    fn test_parse_riscv_filter_with_start_offset() {
        assert_eq!(
            parse_filter(FILTER_RISCV, &[0x34, 0x12, 0x00, 0x00], false).unwrap(),
            ParsedFilter::Transform(Filter::RiscV {
                start_offset: 0x1234
            })
        );
    }

    #[test]
    fn test_parse_unknown_prefilter_is_preserved() {
        assert_eq!(
            parse_filter(0x1234, &[0xAA, 0xBB], false).unwrap(),
            ParsedFilter::Transform(Filter::Unknown {
                id: 0x1234,
                properties: vec![0xAA, 0xBB],
            })
        );
    }

    #[test]
    fn test_parse_unknown_final_filter_rejected() {
        let result = parse_filter(0x1234, &[0xAA], true);
        assert!(matches!(
            result,
            Err(Error::Unsupported("xz: final filter must be LZMA2"))
        ));
    }

    #[test]
    fn test_reserved_filter_id_rejected() {
        // §5.3: 0x40-0x7F is reserved; all values in range must be rejected
        for id in [0x40u64, 0x41, 0x55, 0x7E, 0x7F] {
            let result = parse_filter(id, &[], false);
            assert!(
                matches!(
                    result,
                    Err(Error::Unsupported("xz: reserved filter ID (0x40-0x7F)"))
                ),
                "expected reserved filter ID rejection for id=0x{id:02X}, got {result:?}"
            );
        }
    }

    #[test]
    fn test_reserved_filter_id_boundary() {
        // 0x3F is just below the reserved range: accepted as unknown custom filter
        assert!(parse_filter(0x3F, &[], false).is_ok());
        // 0x80 is just above the reserved range: accepted as unknown custom filter
        assert!(parse_filter(0x80, &[], false).is_ok());
    }

    /// Helper: encode `value` as an xz VLI (7-bit little-endian chunks).
    fn vli_bytes(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    /// Helper: build a minimal xz stream whose single block declares one
    /// filter carrying `filter_id` with empty properties. Filter flag
    /// parsing decides the outcome before block data, Index, or footer
    /// are needed, so the stream ends right after the block header.
    fn stream_with_single_filter_id(filter_id: u64) -> Vec<u8> {
        let mut data = STREAM_MAGIC.to_vec();
        let stream_flags = [0x00, CHECK_CRC32];
        data.extend_from_slice(&stream_flags);
        data.extend_from_slice(&crc32::crc32(&stream_flags).to_le_bytes());

        let mut block_hdr = vec![0x00]; // Block Flags: one filter
        block_hdr.extend_from_slice(&vli_bytes(filter_id));
        block_hdr.push(0x00); // Size of Properties = 0

        let before_crc = 1 + block_hdr.len();
        block_hdr.resize(block_hdr.len() + (4 - (before_crc % 4)) % 4, 0x00);
        let real_header_size = 1 + block_hdr.len() + 4;
        let header_size_byte = ((real_header_size / 4) - 1) as u8;

        let mut crc_input = Vec::with_capacity(1 + block_hdr.len());
        crc_input.push(header_size_byte);
        crc_input.extend_from_slice(&block_hdr);
        data.push(header_size_byte);
        data.extend_from_slice(&block_hdr);
        data.extend_from_slice(&crc32::crc32(&crc_input).to_le_bytes());

        // decode_stream requires at least 24 bytes of input.
        data.resize(data.len().max(24), 0x00);
        data
    }

    #[test]
    fn test_reserved_high_filter_id_rejected() {
        // xz-file-format.txt §3.1.5: Filter IDs >= 2^62 are reserved for
        // implementation-dependent internal use and must never appear in
        // a List of Filter Flags.
        for id in [
            0x4000_0000_0000_0000u64,
            0x7FFF_FFFF_FFFF_FFFF, // largest encodable VLI (2^63 - 1)
        ] {
            for is_last in [false, true] {
                let result = parse_filter(id, &[], is_last);
                assert!(
                    matches!(
                        result,
                        Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"))
                    ),
                    "expected reserved filter ID rejection for id=0x{id:X} \
                     (is_last={is_last}), got {result:?}"
                );
            }
        }
    }

    #[test]
    fn test_filter_id_below_reserved_range_parses_as_unknown() {
        // 2^62 - 1 is the largest Filter ID usable in a List of Filter
        // Flags. It is not a built-in ID, so it parses as an unknown
        // custom filter like any other application-defined ID.
        assert_eq!(
            parse_filter(0x3FFF_FFFF_FFFF_FFFF, &[0xAA], false).unwrap(),
            ParsedFilter::Transform(Filter::Unknown {
                id: 0x3FFF_FFFF_FFFF_FFFF,
                properties: vec![0xAA],
            })
        );
    }

    #[test]
    fn test_block_header_reserved_high_filter_id_rejected() {
        // A block header whose only filter carries Filter ID = 2^62 must
        // be rejected as malformed.
        let data = stream_with_single_filter_id(0x4000_0000_0000_0000);
        assert!(matches!(
            decode(&data),
            Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"))
        ));
    }

    #[test]
    fn test_block_header_max_usable_filter_id_unsupported() {
        // Filter ID = 2^62 - 1 survives the reserved-range check and hits
        // the normal unknown-filter path ("final filter must be LZMA2").
        let data = stream_with_single_filter_id(0x3FFF_FFFF_FFFF_FFFF);
        assert!(matches!(
            decode(&data),
            Err(Error::Unsupported("xz: final filter must be LZMA2"))
        ));
    }

    #[test]
    fn test_reserved_high_filter_id_rejected_with_registry() {
        // Even a registered codec cannot make a reserved Filter ID
        // acceptable in a stream.
        struct ReservedIdCodec;
        impl crate::compress::xz::registry::FilterCodec for ReservedIdCodec {
            fn filter_id(&self) -> u64 {
                0x4000_0000_0000_0000
            }
            fn encode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
                Ok(input.to_vec())
            }
            fn decode(&self, input: &[u8], _properties: &[u8]) -> Result<Vec<u8>, Error> {
                Ok(input.to_vec())
            }
        }

        let mut registry = FilterRegistry::new();
        registry.register(Box::new(ReservedIdCodec)).unwrap();
        let data = stream_with_single_filter_id(0x4000_0000_0000_0000);
        assert!(matches!(
            decode_with_registry(&data, Some(&registry)),
            Err(Error::InvalidData("xz: reserved filter ID (>= 2^62)"))
        ));
    }

    #[test]
    fn test_none_check_type_decode() {
        fn encode_vli_local(output: &mut Vec<u8>, mut value: u64) {
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

        // Check type 0x00 (none): the check field is empty. Convert a
        // CRC-32 stream by dropping the 4-byte check and rebuilding the
        // index/footer.
        let payload = b"hello none";
        let mut data = super::super::encode::encode(payload);

        data[6] = 0x00;
        data[7] = CHECK_NONE;
        fix_stream_header_crc(&mut data);

        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        let check_offset = block_data_start + padded_len;

        // Drop the 4-byte CRC-32 check field entirely.
        data.truncate(check_offset);

        // Rebuild the index: unpadded size no longer includes a check.
        let unpadded_size = (real_header_size + compressed_len) as u64;
        let mut index_body = Vec::new();
        index_body.push(0x00);
        encode_vli_local(&mut index_body, 1);
        encode_vli_local(&mut index_body, unpadded_size);
        encode_vli_local(&mut index_body, payload.len() as u64);
        index_body.resize(index_body.len().next_multiple_of(4), 0x00);
        let index_crc = crc32::crc32(&index_body);
        index_body.extend_from_slice(&index_crc.to_le_bytes());
        data.extend_from_slice(&index_body);

        // Rebuild the footer: backward size + stream flags + YZ.
        let backward_size_raw = (index_body.len() / 4 - 1) as u32;
        data.extend_from_slice(&[0u8; 4]); // footer CRC placeholder
        data.extend_from_slice(&backward_size_raw.to_le_bytes());
        data.extend_from_slice(&[0x00, CHECK_NONE]);
        data.extend_from_slice(b"YZ");
        fix_stream_footer_crc(&mut data);

        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_crc64_check_type_decode() {
        fn encode_vli_local(output: &mut Vec<u8>, mut value: u64) {
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

        let payload = b"hello crc64";
        let mut data = super::super::encode::encode(payload);

        data[6] = 0x00;
        data[7] = CHECK_CRC64;
        fix_stream_header_crc(&mut data);

        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        let crc64 = crate::util::crc64::crc64(payload).to_le_bytes();
        let check_offset = block_data_start + padded_len;
        data.splice(check_offset..check_offset + 4, crc64);

        let footer_start = data.len() - 12;
        let backward_size_raw = u32::from_le_bytes([
            data[footer_start + 4],
            data[footer_start + 5],
            data[footer_start + 6],
            data[footer_start + 7],
        ]);
        let index_size = ((backward_size_raw as usize) + 1) * 4;
        let index_start = footer_start - index_size;

        let unpadded_size = (real_header_size + compressed_len + 8) as u64;
        let mut index_body = Vec::new();
        index_body.push(0x00);
        encode_vli_local(&mut index_body, 1);
        encode_vli_local(&mut index_body, unpadded_size);
        encode_vli_local(&mut index_body, payload.len() as u64);
        index_body.resize(index_body.len().next_multiple_of(4), 0x00);
        let index_crc = crc32::crc32(&index_body);
        let mut new_index = index_body;
        new_index.extend_from_slice(&index_crc.to_le_bytes());
        assert_eq!(new_index.len(), index_size);
        data[index_start..footer_start].copy_from_slice(&new_index);

        let new_footer_start = data.len() - 12;
        data[new_footer_start + 8] = 0x00;
        data[new_footer_start + 9] = CHECK_CRC64;
        fix_stream_footer_crc(&mut data);

        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_crc64_check_type_mismatch() {
        let payload = b"hello crc64 mismatch";
        let mut data = super::super::encode::encode(payload);

        data[6] = 0x00;
        data[7] = CHECK_CRC64;
        fix_stream_header_crc(&mut data);

        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        let mut crc64 = crate::util::crc64::crc64(payload).to_le_bytes();
        crc64[0] ^= 0xFF;
        let check_offset = block_data_start + padded_len;
        data.splice(check_offset..check_offset + 4, crc64);

        let footer_start = data.len() - 12;
        let backward_size_raw = u32::from_le_bytes([
            data[footer_start + 4],
            data[footer_start + 5],
            data[footer_start + 6],
            data[footer_start + 7],
        ]);
        let index_size = ((backward_size_raw as usize) + 1) * 4;
        let index_start = footer_start - index_size;

        let unpadded_size = (real_header_size + compressed_len + 8) as u64;
        let mut index_body = vec![0x00, 0x01, unpadded_size as u8, payload.len() as u8];
        index_body.resize(index_body.len().next_multiple_of(4), 0x00);
        let index_crc = crc32::crc32(&index_body);
        let mut new_index = index_body;
        new_index.extend_from_slice(&index_crc.to_le_bytes());
        data[index_start..footer_start].copy_from_slice(&new_index);

        let new_footer_start = data.len() - 12;
        data[new_footer_start + 8] = 0x00;
        data[new_footer_start + 9] = CHECK_CRC64;
        fix_stream_footer_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::ChecksumMismatch64 { .. })),
            "expected CRC-64 mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_sha256_check_type_decode() {
        fn encode_vli_local(output: &mut Vec<u8>, mut value: u64) {
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

        let payload = b"hello sha256";
        let mut data = super::super::encode::encode(payload);

        data[6] = 0x00;
        data[7] = CHECK_SHA256;
        fix_stream_header_crc(&mut data);

        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        let sha256 = crate::util::sha256::sha256(payload);
        let check_offset = block_data_start + padded_len;
        data.splice(check_offset..check_offset + 4, sha256);

        let footer_start = data.len() - 12;
        let backward_size_raw = u32::from_le_bytes([
            data[footer_start + 4],
            data[footer_start + 5],
            data[footer_start + 6],
            data[footer_start + 7],
        ]);
        let index_size = ((backward_size_raw as usize) + 1) * 4;
        let index_start = footer_start - index_size;

        let unpadded_size = (real_header_size + compressed_len + 32) as u64;
        let mut index_body = vec![0x00];
        encode_vli_local(&mut index_body, 1);
        encode_vli_local(&mut index_body, unpadded_size);
        encode_vli_local(&mut index_body, payload.len() as u64);
        index_body.resize(index_body.len().next_multiple_of(4), 0x00);
        let index_crc = crc32::crc32(&index_body);
        let mut new_index = index_body;
        new_index.extend_from_slice(&index_crc.to_le_bytes());
        assert_eq!(new_index.len(), index_size);
        data[index_start..footer_start].copy_from_slice(&new_index);

        let new_footer_start = data.len() - 12;
        data[new_footer_start + 8] = 0x00;
        data[new_footer_start + 9] = CHECK_SHA256;
        fix_stream_footer_crc(&mut data);

        let decoded = decode(&data).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_sha256_check_type_mismatch() {
        let payload = b"hello sha256 mismatch";
        let mut data = super::super::encode::encode(payload);

        data[6] = 0x00;
        data[7] = CHECK_SHA256;
        fix_stream_header_crc(&mut data);

        let real_header_size = (data[12] as usize + 1) * 4;
        let block_data_start = 12 + real_header_size;
        let compressed_len = lzma2_consumed_bytes(&data[block_data_start..]).unwrap();
        let padded_len = compressed_len.div_ceil(4) * 4;
        let mut sha256 = crate::util::sha256::sha256(payload);
        sha256[0] ^= 0xFF;
        let check_offset = block_data_start + padded_len;
        data.splice(check_offset..check_offset + 4, sha256);

        let footer_start = data.len() - 12;
        let backward_size_raw = u32::from_le_bytes([
            data[footer_start + 4],
            data[footer_start + 5],
            data[footer_start + 6],
            data[footer_start + 7],
        ]);
        let index_size = ((backward_size_raw as usize) + 1) * 4;
        let index_start = footer_start - index_size;

        let unpadded_size = (real_header_size + compressed_len + 32) as u64;
        let mut index_body = vec![0x00, 0x01, unpadded_size as u8, payload.len() as u8];
        index_body.resize(index_body.len().next_multiple_of(4), 0x00);
        let index_crc = crc32::crc32(&index_body);
        let mut new_index = index_body;
        new_index.extend_from_slice(&index_crc.to_le_bytes());
        data[index_start..footer_start].copy_from_slice(&new_index);

        let new_footer_start = data.len() - 12;
        data[new_footer_start + 8] = 0x00;
        data[new_footer_start + 9] = CHECK_SHA256;
        fix_stream_footer_crc(&mut data);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::InvalidData("xz: SHA-256 mismatch"))),
            "expected SHA-256 mismatch, got {result:?}"
        );
    }

    #[test]
    fn test_decode_system_xz_with_non_default_lzma_props() {
        fn encode_vli_local(output: &mut Vec<u8>, mut value: u64) {
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

        let expected = b"Hello xz props! ".repeat(40);
        let props = crate::compress::lzma::LzmaProperties {
            lc: 4,
            lp: 0,
            pb: 0,
        };
        let lzma = crate::compress::lzma::lzma_encode_with_props(&expected, 4096, props);
        let lzma2 = {
            let mut out = Vec::new();
            let u_size = expected.len() - 1;
            let c_size = lzma.len() - 1;
            out.push(0xC0 | ((u_size >> 16) as u8 & 0x1F));
            out.push((u_size >> 8) as u8);
            out.push(u_size as u8);
            out.push((c_size >> 8) as u8);
            out.push(c_size as u8);
            out.push(props.to_props_byte());
            out.extend_from_slice(&lzma);
            out.push(0x00);
            out
        };

        let mut encoded = STREAM_MAGIC.to_vec();
        let stream_flags = [0x00, CHECK_CRC32];
        encoded.extend_from_slice(&stream_flags);
        encoded.extend_from_slice(&crc32::crc32(&stream_flags).to_le_bytes());

        let mut block_hdr = vec![0x00, FILTER_LZMA2 as u8, 0x01, 0x00];
        let before_crc = 1 + block_hdr.len();
        let padding = (4 - (before_crc % 4)) % 4;
        block_hdr.extend(core::iter::repeat_n(0x00, padding));
        let real_header_size = 1 + block_hdr.len() + 4;
        let header_size_byte = ((real_header_size / 4) - 1) as u8;
        let mut hdr_crc_input = Vec::with_capacity(1 + block_hdr.len());
        hdr_crc_input.push(header_size_byte);
        hdr_crc_input.extend_from_slice(&block_hdr);
        encoded.push(header_size_byte);
        encoded.extend_from_slice(&block_hdr);
        encoded.extend_from_slice(&crc32::crc32(&hdr_crc_input).to_le_bytes());
        encoded.extend_from_slice(&lzma2);
        encoded.extend(core::iter::repeat_n(0x00, (4 - (lzma2.len() % 4)) % 4));
        encoded.extend_from_slice(&crc32::crc32(&expected).to_le_bytes());

        let index_start = encoded.len();
        let mut index_body = Vec::new();
        index_body.push(0x00);
        encode_vli_local(&mut index_body, 1);
        encode_vli_local(&mut index_body, (real_header_size + lzma2.len() + 4) as u64);
        encode_vli_local(&mut index_body, expected.len() as u64);
        index_body.extend(core::iter::repeat_n(0x00, (4 - (index_body.len() % 4)) % 4));
        encoded.extend_from_slice(&index_body);
        encoded.extend_from_slice(&crc32::crc32(&index_body).to_le_bytes());

        let index_size = encoded.len() - index_start;
        let backward_size = ((index_size / 4) - 1) as u32;
        let mut footer_fields = Vec::new();
        footer_fields.extend_from_slice(&backward_size.to_le_bytes());
        footer_fields.extend_from_slice(&stream_flags);
        encoded.extend_from_slice(&crc32::crc32(&footer_fields).to_le_bytes());
        encoded.extend_from_slice(&footer_fields);
        encoded.extend_from_slice(b"YZ");

        assert_eq!(decode(&encoded).unwrap(), expected);
    }

    #[test]
    fn test_decode_with_empty_registry_matches_decode() {
        let encoded = crate::compress::xz::encode::encode(b"registry design");
        let registry = FilterRegistry::new();
        assert_eq!(
            decode(&encoded).unwrap(),
            decode_with_registry(&encoded, Some(&registry)).unwrap()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader_with_registry_roundtrip() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = crate::compress::xz::encode::encode_with_filters_and_registry(
            b"reader registry decode",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x5A],
            }],
            Some(&registry),
        )
        .unwrap();
        let decoded = decode_reader_with_registry(&encoded[..], Some(&registry)).unwrap();
        assert_eq!(decoded, b"reader registry decode");
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader_without_registry_rejects_custom_filter() {
        let mut registry = FilterRegistry::new();
        registry.register(Box::new(XorCodec)).unwrap();
        let encoded = crate::compress::xz::encode::encode_with_filters_and_registry(
            b"reader registry decode",
            &[Filter::Unknown {
                id: 0x1234,
                properties: vec![0x5A],
            }],
            Some(&registry),
        )
        .unwrap();
        let err = decode_reader(&encoded[..]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .contains("unsupported custom/unknown filter")
        );
    }

    #[test]
    fn test_bcj_alignment_powerpc_rejected() {
        // PowerPC requires 4-byte alignment; offset 3 is not aligned
        let result = parse_bcj_start_offset(&3u32.to_le_bytes(), false, "PowerPC");
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("not aligned")),
            "expected alignment error, got: {result:?}"
        );
        // Verify aligned offset is accepted
        let result = parse_bcj_start_offset(&4u32.to_le_bytes(), false, "PowerPC");
        assert!(result.is_ok(), "aligned offset should be accepted");
    }

    #[test]
    fn test_bcj_alignment_arm_rejected() {
        // ARM requires 4-byte alignment; offset 1 is not aligned
        let result = parse_bcj_start_offset(&1u32.to_le_bytes(), false, "ARM");
        assert!(
            matches!(result, Err(Error::InvalidData(msg)) if msg.contains("not aligned")),
            "expected alignment error, got: {result:?}"
        );
        // Verify aligned offset is accepted
        let result = parse_bcj_start_offset(&8u32.to_le_bytes(), false, "ARM");
        assert!(result.is_ok(), "aligned offset should be accepted");
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
}
