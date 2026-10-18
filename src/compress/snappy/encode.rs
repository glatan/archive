//! Snappy encoding (framed by default, raw helpers included).

use alloc::vec;
use alloc::vec::Vec;

use crate::util::crc32c::{crc32c, mask_crc32c};

const STREAM_IDENTIFIER_TYPE: u8 = 0xFF;
const COMPRESSED_DATA_TYPE: u8 = 0x00;
const UNCOMPRESSED_DATA_TYPE: u8 = 0x01;
const STREAM_IDENTIFIER: &[u8; 6] = b"sNaPpY";
const MAX_CHUNK_SIZE: usize = 65_536;
const HASH_TABLE_SIZE: usize = 1 << 14;

/// Encode a framed Snappy stream.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    write_chunk(&mut output, STREAM_IDENTIFIER_TYPE, STREAM_IDENTIFIER);

    if input.is_empty() {
        return output;
    }

    for chunk in input.chunks(MAX_CHUNK_SIZE) {
        let raw = encode_raw(chunk);
        let crc = mask_crc32c(crc32c(chunk));
        if raw.len() < chunk.len() {
            let mut payload = Vec::with_capacity(raw.len() + 4);
            payload.extend_from_slice(&crc.to_le_bytes());
            payload.extend_from_slice(&raw);
            write_chunk(&mut output, COMPRESSED_DATA_TYPE, &payload);
        } else {
            let mut payload = Vec::with_capacity(chunk.len() + 4);
            payload.extend_from_slice(&crc.to_le_bytes());
            payload.extend_from_slice(chunk);
            write_chunk(&mut output, UNCOMPRESSED_DATA_TYPE, &payload);
        }
    }

    output
}

/// Encode a raw Snappy block.
pub fn encode_raw(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint(&mut output, input.len() as u64);
    if input.len() < 4 {
        emit_literal(&mut output, input);
        return output;
    }

    let mut table = vec![usize::MAX; HASH_TABLE_SIZE];
    let mut anchor = 0usize;
    let mut pos = 0usize;

    while pos + 4 <= input.len() {
        let hash = hash4(&input[pos..]) & (HASH_TABLE_SIZE - 1);
        let candidate = table[hash];
        table[hash] = pos;

        let matched = candidate != usize::MAX
            && pos > candidate
            && pos - candidate <= 65_535
            && candidate + 4 <= input.len()
            && input[candidate..candidate + 4] == input[pos..pos + 4];

        if !matched {
            pos += 1;
            continue;
        }

        emit_literal(&mut output, &input[anchor..pos]);

        let offset = pos - candidate;
        let max_extra = (input.len() - pos).min(input.len() - candidate) - 4;
        let match_len = 4 + crate::compress::match_ops::match_len(
            &input[candidate + 4..],
            &input[pos + 4..],
            max_extra,
        );
        emit_copy(&mut output, offset, match_len);

        let end = pos + match_len;
        let update_end = end.saturating_sub(3);
        let mut update_pos = pos + 1;
        while update_pos < update_end {
            let h = hash4(&input[update_pos..]) & (HASH_TABLE_SIZE - 1);
            table[h] = update_pos;
            update_pos += 1;
        }

        pos = end;
        anchor = pos;
    }

    emit_literal(&mut output, &input[anchor..]);
    output
}

fn emit_literal(output: &mut Vec<u8>, literal: &[u8]) {
    if literal.is_empty() {
        return;
    }
    let mut pos = 0;
    while pos < literal.len() {
        let remaining = literal.len() - pos;
        let chunk_len = remaining.min(1 << 20);
        write_literal_tag(output, chunk_len);
        output.extend_from_slice(&literal[pos..pos + chunk_len]);
        pos += chunk_len;
    }
}

fn write_literal_tag(output: &mut Vec<u8>, len: usize) {
    let len_minus_one = len - 1;
    if len < 60 {
        output.push((len_minus_one as u8) << 2);
        return;
    }

    let bytes = if len_minus_one <= 0xFF {
        1
    } else if len_minus_one <= 0xFFFF {
        2
    } else if len_minus_one <= 0xFF_FFFF {
        3
    } else {
        4
    };
    output.push(((59 + bytes) as u8) << 2);
    for i in 0..bytes {
        output.push(((len_minus_one >> (8 * i)) & 0xFF) as u8);
    }
}

fn emit_copy(output: &mut Vec<u8>, offset: usize, mut len: usize) {
    while len > 0 {
        if offset < 2048 && len >= 4 {
            let chunk = len.min(11);
            let tag = 0x01 | (((chunk - 4) as u8) << 2) | ((((offset >> 8) as u8) & 0x07) << 5);
            output.push(tag);
            output.push((offset & 0xFF) as u8);
            len -= chunk;
        } else {
            let chunk = len.min(64);
            let tag = 0x02 | (((chunk - 1) as u8) << 2);
            output.push(tag);
            output.extend_from_slice(&(offset as u16).to_le_bytes());
            len -= chunk;
        }
    }
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn write_chunk(output: &mut Vec<u8>, chunk_type: u8, payload: &[u8]) {
    output.push(chunk_type);
    let len = payload.len() as u32;
    output.push((len & 0xFF) as u8);
    output.push(((len >> 8) & 0xFF) as u8);
    output.push(((len >> 16) & 0xFF) as u8);
    output.extend_from_slice(payload);
}

fn hash4(input: &[u8]) -> usize {
    let word = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    (word.wrapping_mul(0x1E35_A7BD) >> 18) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::snappy::decode;

    #[test]
    fn test_encode_raw_literal_only() {
        let encoded = encode_raw(b"abc");
        assert_eq!(encoded, vec![0x03, 0x08, b'a', b'b', b'c']);
    }

    #[test]
    fn test_roundtrip_raw_repeated() {
        let input = b"abcabcabcabcabcabc";
        let encoded = encode_raw(input);
        let decoded = decode::decode_raw(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_roundtrip_framed_empty() {
        let encoded = encode(b"");
        let decoded = decode::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_roundtrip_framed_large() {
        let input = b"The quick brown fox jumps over the lazy dog. ".repeat(4000);
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_emit_copy_long_match() {
        let mut out = Vec::new();
        emit_copy(&mut out, 32, 100);
        assert!(out.len() >= 6);
    }

    #[test]
    fn test_framed_large_chunk_split() {
        // 100 KB payload forces multiple 65536-byte chunk splits in framed encoding.
        let input = vec![b'X'; 100 * 1024];
        let encoded = encode(&input);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_encode_incompressible_data() {
        // Pseudo-random data that resists compression; roundtrip must still succeed.
        let mut state = 0xDEAD_BEEFu32;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 16) as u8
            })
            .collect();
        let encoded = encode(&data);
        let decoded = decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
