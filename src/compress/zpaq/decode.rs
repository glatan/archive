//! ZPAQ decoding (public API).
//!
//! Decodes a single-payload ZPAQ block for any upstream level byte whose
//! header/model configuration is otherwise valid. Malformed truncated
//! configurations for known component types and unsupported/truncated HCOMP
//! instructions are rejected before payload decode.
//!
//! # Examples
//!
//! ```
//! use archive::compress::zpaq::{decode, encode};
//!
//! let data = b"Hello, ZPAQ!";
//! let compressed = encode::encode(data, 1);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

use alloc::vec::Vec;

use crate::error::Error;

use super::arithmetic::ArithDecoder;
use super::arithmetic::ArithEncoder;
use super::predictor::Predictor;
use super::zpaql::ZPAQL;

const HEADER_METADATA_SIZE: usize = 4;
const LEGACY_HEADER_METADATA_SIZE: usize = 6;

pub(crate) struct ParsedBlockHeader {
    pub hh: usize,
    pub hm: usize,
    pub comp_config: Vec<u8>,
    pub hcomp: Vec<u8>,
    pub next_pos: usize,
}

pub(crate) struct DecodedSegment {
    pub filename: Vec<u8>,
    pub comment: Vec<u8>,
    pub data: Vec<u8>,
    pub next_pos: usize,
}

fn encode_payload_with_header(header: &ParsedBlockHeader, input: &[u8]) -> Result<Vec<u8>, Error> {
    let z = ZPAQL::new(header.hh, header.hm, header.hcomp.clone());
    let mut pred = Predictor::try_new(z, &header.comp_config)?;
    let mut enc = ArithEncoder::new();

    for &byte in input {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            let prob = pred.predict();
            enc.encode(bit, prob);
            pred.try_update(bit)?;
        }
    }

    Ok(enc.finish())
}

fn read_terminated_bytes(input: &[u8], pos: &mut usize) -> Result<Vec<u8>, Error> {
    let start = *pos;
    while *pos < input.len() && input[*pos] != 0 {
        *pos += 1;
    }
    if *pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    let value = input[start..*pos].to_vec();
    *pos += 1;
    Ok(value)
}

pub(crate) fn parse_block_header(input: &[u8]) -> Result<ParsedBlockHeader, Error> {
    if input.len() < 7 {
        return Err(Error::InvalidData("zpaq: input too short"));
    }

    let mut pos = 0;

    if &input[pos..pos + 3] != b"zPQ" {
        return Err(Error::InvalidData("zpaq: invalid magic number"));
    }
    pos += 3;

    let _level = input[pos];
    pos += 1;

    if pos + 2 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let hsize = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
    pos += 2;
    let header_start = pos;

    if pos + 2 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let hh = input[pos] as usize;
    let hm = input[pos + 1] as usize;
    pos += 2;

    if pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    let n_comp = input[pos] as usize;
    pos += 1;

    let mut comp_config = Vec::new();
    comp_config.push(n_comp as u8);

    for _ in 0..n_comp {
        if pos >= input.len() {
            return Err(Error::UnexpectedEof);
        }
        let ctype = input[pos];
        comp_config.push(ctype);
        pos += 1;

        let param_count = match ctype {
            0 => 1,
            1 => 2,
            2 => 1,
            3 => 1,
            4 => 3,
            5 => 4,
            6 => {
                if pos + 1 >= input.len() {
                    return Err(Error::UnexpectedEof);
                }
                let size = input[pos];
                let m = input[pos + 1];
                comp_config.push(size);
                comp_config.push(m);
                pos += 2;
                for _ in 0..(m as usize + 1) {
                    if pos >= input.len() {
                        return Err(Error::UnexpectedEof);
                    }
                    comp_config.push(input[pos]);
                    pos += 1;
                }
                continue;
            }
            7 => 2,
            8 => 4,
            _ => return Err(Error::InvalidData("zpaq: unknown component type")),
        };

        for _ in 0..param_count {
            if pos >= input.len() {
                return Err(Error::UnexpectedEof);
            }
            comp_config.push(input[pos]);
            pos += 1;
        }
    }

    if pos + 2 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let hcomp_len = u16::from_le_bytes([input[pos], input[pos + 1]]) as usize;
    pos += 2;

    if pos + hcomp_len > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let hcomp = input[pos..pos + hcomp_len].to_vec();
    ZPAQL::validate_hcomp(&hcomp)?;
    pos += hcomp_len;

    let actual_hsize = pos - header_start;
    let legacy_hsize = actual_hsize + (LEGACY_HEADER_METADATA_SIZE - HEADER_METADATA_SIZE);
    if hsize != actual_hsize && hsize != legacy_hsize {
        return Err(Error::InvalidData("zpaq: invalid header size"));
    }

    Ok(ParsedBlockHeader {
        hh,
        hm,
        comp_config,
        hcomp,
        next_pos: pos,
    })
}

pub(crate) fn decode_segment_at(
    input: &[u8],
    start: usize,
    header: &ParsedBlockHeader,
) -> Result<Option<DecodedSegment>, Error> {
    let mut pos = start;
    if pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    if input[pos] == 0xFF {
        return Ok(None);
    }

    let filename = read_terminated_bytes(input, &mut pos)?;
    let comment = read_terminated_bytes(input, &mut pos)?;

    if pos + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let compressed_len =
        u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]) as usize;
    pos += 4;

    if pos + compressed_len > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let compressed_data = &input[pos..pos + compressed_len];
    pos += compressed_len;

    if pos + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let original_len =
        u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]) as usize;
    pos += 4;

    let z = ZPAQL::new(header.hh, header.hm, header.hcomp.clone());
    let mut pred = Predictor::try_new(z, &header.comp_config)?;
    let mut dec = ArithDecoder::new(compressed_data);
    let mut output = Vec::with_capacity(original_len);

    for _ in 0..original_len {
        let mut byte = 0u8;
        for bit_pos in (0..8).rev() {
            let prob = pred.predict();
            let bit = dec.decode(prob);
            pred.try_update(bit)?;
            byte |= bit << bit_pos;
        }
        output.push(byte);
    }

    if encode_payload_with_header(header, &output)? != compressed_data {
        return Err(Error::InvalidData("zpaq: corrupted arithmetic payload"));
    }

    if pos >= input.len() {
        return Err(Error::UnexpectedEof);
    }
    if input[pos] != 0xFF {
        return Err(Error::InvalidData("zpaq: missing segment terminator"));
    }
    pos += 1;

    Ok(Some(DecodedSegment {
        filename,
        comment,
        data: output,
        next_pos: pos,
    }))
}

/// Decompress ZPAQ format data.
///
/// # Errors
///
/// Returns an error if the data is not valid ZPAQ format.
///
/// # Examples
///
/// ```
/// use archive::compress::zpaq::{decode, encode};
///
/// let data = b"Hello, ZPAQ!";
/// let compressed = encode::encode(data, 1);
/// let decompressed = decode::decode(&compressed).unwrap();
/// assert_eq!(decompressed, data);
/// ```
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let header = parse_block_header(input)?;
    let mut pos = header.next_pos;
    let mut output = Vec::new();

    while let Some(segment) = decode_segment_at(input, pos, &header)? {
        output.extend_from_slice(&segment.data);
        pos = segment.next_pos;
    }

    Ok(output)
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
    use crate::archive::zpaq;

    fn build_block_with_header(header: &ParsedBlockHeader, input: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"zPQ");
        encoded.push(7);
        let hsize = header.comp_config.len() + header.hcomp.len() + HEADER_METADATA_SIZE;
        encoded.extend_from_slice(&(hsize as u16).to_le_bytes());
        encoded.push(header.hh as u8);
        encoded.push(header.hm as u8);
        encoded.push(header.comp_config[0]);
        encoded.extend_from_slice(&header.comp_config[1..]);
        encoded.extend_from_slice(&(header.hcomp.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&header.hcomp);
        encoded.push(0);
        encoded.push(0);
        let compressed = encode_payload_with_header(header, input).unwrap();
        encoded.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&compressed);
        encoded.extend_from_slice(&(input.len() as u32).to_le_bytes());
        encoded.push(0xFF);
        encoded.push(0xFF);
        encoded
    }

    fn build_archive_with_header_segments(
        header: &ParsedBlockHeader,
        segments: &[(&[u8], &[u8], &[u8])],
    ) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"zPQ");
        encoded.push(7);
        let hsize = header.comp_config.len() + header.hcomp.len() + HEADER_METADATA_SIZE;
        encoded.extend_from_slice(&(hsize as u16).to_le_bytes());
        encoded.push(header.hh as u8);
        encoded.push(header.hm as u8);
        encoded.push(header.comp_config[0]);
        encoded.extend_from_slice(&header.comp_config[1..]);
        encoded.extend_from_slice(&(header.hcomp.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&header.hcomp);
        for (filename, comment, input) in segments {
            encoded.extend_from_slice(filename);
            encoded.push(0);
            encoded.extend_from_slice(comment);
            encoded.push(0);
            let compressed = encode_payload_with_header(header, input).unwrap();
            encoded.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            encoded.extend_from_slice(&compressed);
            encoded.extend_from_slice(&(input.len() as u32).to_le_bytes());
            encoded.push(0xFF);
        }
        encoded.push(0xFF);
        encoded
    }

    fn hcomp_range(encoded: &[u8]) -> core::ops::Range<usize> {
        let header = parse_block_header(encoded).unwrap();
        let hcomp_end = header.next_pos;
        let hcomp_start = hcomp_end - header.hcomp.len();
        hcomp_start..hcomp_end
    }

    fn corrupt_first_payload_byte(encoded: &mut [u8]) {
        let header = parse_block_header(encoded).unwrap();
        let mut pos = header.next_pos;
        while encoded[pos] != 0 {
            pos += 1;
        }
        pos += 1;
        while encoded[pos] != 0 {
            pos += 1;
        }
        pos += 1;
        let payload_pos = pos + 4;
        encoded[payload_pos] ^= 0x01;
    }

    #[test]
    fn test_too_short() {
        assert!(matches!(decode(&[0; 5]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_bad_magic() {
        assert!(matches!(
            decode(&[b'z', b'P', b'X', 1, 0, 0, 0, 0, 0, 0]),
            Err(Error::InvalidData(msg)) if msg.contains("magic")
        ));
    }

    #[test]
    fn test_roundtrip_level1() {
        let data = b"Hello, ZPAQ!";
        let compressed = super::super::encode::encode(data, 1);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_level2() {
        let data = b"Hello, ZPAQ level 2!";
        let compressed = super::super::encode::encode(data, 2);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_level3() {
        let data = b"Hello, ZPAQ level 3!";
        let compressed = super::super::encode::encode(data, 3);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_empty() {
        let compressed = super::super::encode::encode(b"", 1);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, b"");
    }

    #[test]
    fn test_roundtrip_repeated() {
        let data = b"ABCDEFGH".repeat(100);
        let compressed = super::super::encode::encode(&data, 1);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let data: alloc::vec::Vec<u8> = (0..=255).collect();
        let compressed = super::super::encode::encode(&data, 1);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_noncanonical_level_byte_is_accepted_when_model_is_valid() {
        let mut compressed = super::super::encode::encode(b"hello", 1);
        compressed[3] = 7;
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_invalid_hsize_rejected() {
        let mut compressed = super::super::encode::encode(b"hello", 1);
        let hsize = u16::from_le_bytes([compressed[4], compressed[5]]);
        compressed[4..6].copy_from_slice(&(hsize + 1).to_le_bytes());
        let err = decode(&compressed).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidData("zpaq: invalid header size")
        ));
    }

    #[test]
    fn test_legacy_hsize_accepted() {
        let mut compressed = super::super::encode::encode(b"hello", 1);
        let hsize = u16::from_le_bytes([compressed[4], compressed[5]]);
        compressed[4..6].copy_from_slice(&(hsize + 2).to_le_bytes());
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, b"hello");
    }

    #[test]
    fn test_unsupported_hcomp_opcode_rejected() {
        let mut compressed = super::super::encode::encode(b"hello", 1);
        let hcomp = hcomp_range(&compressed);
        compressed[hcomp.start] = 5;
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: unsupported hcomp opcode"))
        ));
    }

    #[test]
    fn test_truncated_hcomp_instruction_rejected() {
        let compressed = [b'z', b'P', b'Q', 7, 10, 0, 8, 0, 1, 1, 8, 4, 2, 0, 255, 0];
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: truncated hcomp instruction"))
        ));
    }

    #[test]
    fn test_unknown_component_type_rejected() {
        let mut compressed = super::super::encode::encode(b"hello", 1);
        compressed[9] = 99;
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: unknown component type"))
        ));
    }

    #[test]
    fn test_hcomp_cycle_limit_exhaustion_rejected() {
        let header = ParsedBlockHeader {
            hh: 8,
            hm: 0,
            comp_config: vec![1, 1, 8, 4],
            hcomp: vec![95, 0, 112, 56],
            next_pos: 0,
        };
        let mut compressed = build_block_with_header(&header, b"x");
        let hcomp = hcomp_range(&compressed);
        compressed[hcomp.start] = 255;
        compressed[hcomp.start + 1] = 0;
        compressed[hcomp.start + 2] = 0;
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: hcomp execution limit exceeded"))
        ));
    }

    #[test]
    fn test_decode_accepts_upstream_style_hcomp_fixture() {
        let header = ParsedBlockHeader {
            hh: 8,
            hm: 0,
            comp_config: vec![1, 1, 8, 4],
            hcomp: vec![95, 0, 112, 56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"upstream hcomp");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"upstream hcomp");
    }

    #[test]
    fn test_decode_accepts_upstream_style_avg_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![3, 0, 128, 0, 64, 4, 0, 1, 32],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"avg fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"avg fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_cons_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 0, 128],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"cons fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"cons fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_icm_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 2, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"icm fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"icm fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_isse_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![2, 0, 128, 7, 4, 0],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"isse fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"isse fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_mix2_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![3, 0, 128, 0, 64, 5, 0, 0, 1, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"mix2 fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"mix2 fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_match_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 3, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"match fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"match fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_mix_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![4, 0, 128, 0, 64, 0, 96, 6, 0, 3, 0, 1, 2, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"mix fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"mix fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_sse_component_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![2, 1, 0, 4, 8, 0, 0, 0, 255],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"sse fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"sse fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_deep_mix2_sse_chain_fixture() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![5, 0, 128, 1, 4, 4, 2, 4, 5, 4, 1, 2, 4, 8, 4, 3, 0, 255],
            hcomp: vec![56],
            next_pos: 0,
        };
        let compressed = build_block_with_header(&header, b"deep mix2/sse fixture");
        let decoded = decode(&compressed).unwrap();
        assert_eq!(decoded, b"deep mix2/sse fixture");
    }

    #[test]
    fn test_decode_accepts_upstream_style_multiple_segments_with_deep_chain() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![5, 0, 128, 0, 160, 4, 0, 1, 64, 7, 4, 2, 6, 4, 2, 2, 3, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let encoded = build_archive_with_header_segments(
            &header,
            &[
                (
                    b"deep-one.bin".as_slice(),
                    b"alpha".as_slice(),
                    b"abc".as_slice(),
                ),
                (
                    b"deep-two.bin".as_slice(),
                    b"beta".as_slice(),
                    b"def".as_slice(),
                ),
            ],
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"abcdef");
    }

    #[test]
    fn test_decode_segment_at_preserves_upstream_filename_and_comment() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 3, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let encoded = build_archive_with_header_segments(
            &header,
            &[(
                b"named.bin".as_slice(),
                b"commentary".as_slice(),
                b"payload".as_slice(),
            )],
        );
        let parsed = parse_block_header(&encoded).unwrap();
        let segment = decode_segment_at(&encoded, parsed.next_pos, &parsed)
            .unwrap()
            .unwrap();
        assert_eq!(segment.filename, b"named.bin");
        assert_eq!(segment.comment, b"commentary");
        assert_eq!(segment.data, b"payload");
    }

    #[test]
    fn test_decode_accepts_upstream_style_multiple_named_segments() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![4, 0, 128, 0, 64, 0, 96, 6, 0, 3, 0, 1, 2, 4],
            hcomp: vec![56],
            next_pos: 0,
        };
        let encoded = build_archive_with_header_segments(
            &header,
            &[
                (
                    b"one.bin".as_slice(),
                    b"alpha".as_slice(),
                    b"abc".as_slice(),
                ),
                (b"two.bin".as_slice(), b"beta".as_slice(), b"def".as_slice()),
            ],
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"abcdef");
    }

    #[test]
    fn test_decode_rejects_missing_archive_terminator() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 0, 128],
            hcomp: vec![56],
            next_pos: 0,
        };
        let mut encoded = build_archive_with_header_segments(
            &header,
            &[(b"a".as_slice(), b"".as_slice(), b"x".as_slice())],
        );
        encoded.pop();
        assert!(matches!(decode(&encoded), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_decode_rejects_truncated_compressed_length_field() {
        let header = ParsedBlockHeader {
            hh: 0,
            hm: 0,
            comp_config: vec![1, 0, 128],
            hcomp: vec![56],
            next_pos: 0,
        };
        let encoded = build_archive_with_header_segments(
            &header,
            &[(b"a".as_slice(), b"b".as_slice(), b"x".as_slice())],
        );
        let parsed = parse_block_header(&encoded).unwrap();
        let segment_start = parsed.next_pos;
        let truncated_len = segment_start + 1 + 1 + 1 + 1 + 2;
        let truncated = encoded[..truncated_len].to_vec();
        assert!(matches!(decode(&truncated), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_invalid_hcomp_jump_target_rejected() {
        let compressed = [
            b'z', b'P', b'Q', 7, 11, 0, 8, 0, 1, 1, 8, 4, 3, 0, 0xFF, 0xFF, 0xFF,
        ];
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: invalid hcomp jump target"))
        ));
    }

    #[test]
    fn test_decode_concatenates_multiple_segments() {
        let mut compressed = Vec::new();
        let config = super::super::encode::write_block_header(&mut compressed, 2);
        super::super::encode::encode_segment(&mut compressed, &config, b"one", b"", b"abc");
        super::super::encode::encode_segment(&mut compressed, &config, b"two", b"", b"def");
        compressed.push(0xFF);
        let decompressed = decode(&compressed).unwrap();
        assert_eq!(decompressed, b"abcdef");
    }

    #[test]
    fn test_corrupted_arithmetic_payload_rejected() {
        let mut compressed = super::super::encode::encode(b"Hello, ZPAQ!", 1);
        corrupt_first_payload_byte(&mut compressed);
        assert!(matches!(
            decode(&compressed),
            Err(Error::InvalidData("zpaq: corrupted arithmetic payload"))
        ));
    }

    #[test]
    fn test_archive_corrupted_arithmetic_payload_rejected() {
        let mut enc = zpaq::encode::ZpaqEncoder::new(2);
        enc.add_file("hello.txt", b"hello from zpaq archive");
        let mut archive = enc.finish().unwrap();
        corrupt_first_payload_byte(&mut archive);
        assert!(matches!(
            zpaq::decode::decode(&archive),
            Err(Error::InvalidData("zpaq: corrupted arithmetic payload"))
        ));
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, 1);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, 1);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data, 1);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data, 1);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }
}
