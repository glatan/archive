//! LZRW1 compression (Ross Williams, public domain format, DCC'91).
//!
//! The stream begins with a 4-byte copy flag: if the flag byte is 1 the
//! remainder of the stream is the data verbatim (used by the encoder when
//! compression would not shrink the input). If the flag is 0 the stream is
//! a sequence of groups, each carrying a 16-bit control word (LSB first,
//! bit i describing item i: 0 = literal byte, 1 = copy item) followed by up
//! to sixteen items. The final group may be partial.
//!
//! A copy item is two bytes `C1 C2`: length = `(C1 & 0x0f) + 1` (1..=16)
//! and offset = `(C1 >> 4) << 8 | C2` (1..=4095, zero never used), copying
//! from `output_len - offset`. This differs from LZRW1-A only in the
//! length bias (1 vs 3) and the resulting length range (1-16 vs 3-18).

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzrw;
use crate::error::Error;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 16;
const MAX_OFFSET: usize = 4095;
const HASH_BITS: usize = 12;

const FLAG_ERRS: lzrw::FlagErrs = lzrw::FlagErrs {
    truncated_flag: "lzrw1: truncated copy flag",
    unknown_flag: "lzrw1: unknown copy flag",
};

/// Decode an LZRW1 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZRW1 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    match lzrw::head(input, FLAG_ERRS)? {
        lzrw::Head::Verbatim => {
            let data = &input[lzrw::FLAG_BYTES..];
            if data.len() > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            return Ok(data.to_vec());
        }
        lzrw::Head::Compressed => {}
    }

    let mut out: Vec<u8> = Vec::new();
    // LZRW1's copy-item length field carries `len - 1` (range 1..=16).
    let mut items = lzrw::Items::new(input, 1, "lzrw1: truncated copy item");
    while let Some(item) = items.next()? {
        match item {
            lzrw::Item::Literal(b) => {
                if out.len() == max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                out.push(b);
            }
            lzrw::Item::Copy { len, index: offset } => {
                if offset == 0 || offset > out.len() {
                    return Err(Error::InvalidData("lzrw1: bad copy offset"));
                }
                if out.len() + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                let start = out.len() - offset;
                lzrw::copy_from_output(&mut out, start, len);
            }
        }
    }
    Ok(out)
}

/// Encode data as an LZRW1 stream.
///
/// If compression does not reduce the size, the verbatim-copy form
/// (copy flag = 1) is emitted, matching the reference encoder.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = lzrw::GroupEncoder::new();

    let mut head = vec![-1i32; 1 << HASH_BITS];
    let hash = |b: &[u8]| -> usize {
        (((b[0] as usize) << 8) ^ ((b[1] as usize) << 4) ^ b[2] as usize).wrapping_mul(40543)
            >> (32 - HASH_BITS - 2)
            & ((1 << HASH_BITS) - 1)
    };

    let mut pos = 0usize;
    while pos < input.len() {
        let mut match_len = 0usize;
        let mut match_off = 0usize;
        if pos + MIN_MATCH <= input.len() {
            let h = hash(&input[pos..]);
            let cand = head[h];
            head[h] = pos as i32;
            if cand >= 0 {
                let c = cand as usize;
                let dist = pos - c;
                if dist <= MAX_OFFSET && input[c..c + MIN_MATCH] == input[pos..pos + MIN_MATCH] {
                    let mut len = MIN_MATCH;
                    while len < MAX_MATCH
                        && pos + len < input.len()
                        && input[c + len] == input[pos + len]
                    {
                        len += 1;
                    }
                    match_len = len;
                    match_off = dist;
                }
            }
        }
        if match_len >= MIN_MATCH {
            enc.copy(match_len - 1, match_off);
            pos += match_len;
        } else {
            enc.literal(input[pos]);
            pos += 1;
        }
    }

    let out = enc.finish();
    if out.len() >= lzrw::FLAG_BYTES + input.len() {
        return lzrw::verbatim(input);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    #[test]
    fn decode_copy_flag() {
        let input = [1, 0, 0, 0, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(decode(&input).unwrap(), b"hello");
    }

    #[test]
    fn decode_flag_remainder_bytes_ignored() {
        // Only flag byte 0 is evaluated; bytes 1-3 are ignored even when
        // non-zero (matching the reference decoder, which leaves them
        // uninitialized in its output).
        let input = [1, 0xAA, 0xBB, 0xCC, b'h', b'i'];
        assert_eq!(decode(&input).unwrap(), b"hi");
    }

    #[test]
    fn decode_verbatim_empty() {
        // FLAG_COPY with an empty remainder decodes to empty output.
        let input = [1, 0, 0, 0];
        assert_eq!(decode(&input).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_trailing_orphan_byte() {
        // After a complete 16-item group, a single dangling byte cannot
        // start a new control word and is ignored (the reference decoder
        // would read past the buffer; this implementation is lenient).
        let mut input = vec![0u8, 0, 0, 0, 0x00, 0x00];
        input.extend_from_slice(b"abcdefghijklmnop");
        input.push(0xFF); // orphan byte, < 2 bytes for a control word
        assert_eq!(decode(&input).unwrap(), b"abcdefghijklmnop");
    }

    #[test]
    fn decode_group_boundary_16_items() {
        // A group holds at most 16 items; item 17 must start a new group
        // with a fresh control word.
        let mut input = vec![0u8, 0, 0, 0];
        input.extend_from_slice(&[0x00, 0x00]); // group 1: all literals
        input.extend_from_slice(b"abcdefghijklmnop"); // 16 literals
        input.extend_from_slice(&[0x00, 0x00]); // group 2
        input.push(b'Z');
        let mut expected = b"abcdefghijklmnop".to_vec();
        expected.push(b'Z');
        assert_eq!(decode(&input).unwrap(), expected);
    }

    #[test]
    fn decode_max_offset_copy() {
        // offset 4095 (12-bit field maximum) copies from output position 0.
        let mut input = vec![0u8, 0, 0, 0];
        // 255 full literal groups -> 4080 bytes; first byte 'A', rest 'z'.
        for g in 0..255 {
            input.extend_from_slice(&[0x00, 0x00]);
            for i in 0..16 {
                input.push(if g == 0 && i == 0 { b'A' } else { b'z' });
            }
        }
        // Final group: 15 literals ('z') then a copy item (bit 15).
        input.extend_from_slice(&[0x00, 0x80]); // control: bit 15 = copy
        input.extend_from_slice(&[b'z'; 15]);
        input.extend_from_slice(&[0xF0, 0xFF]); // len 1, offset 4095
        let mut expected = vec![b'z'; 4096];
        expected[0] = b'A';
        expected[4095] = b'A';
        assert_eq!(decode(&input).unwrap(), expected);
    }

    #[test]
    fn decode_literal_group() {
        // control word 0x0000 + 3 literal bytes (partial group).
        let input = [0, 0, 0, 0, 0, 0, b'a', b'b', b'c'];
        assert_eq!(decode(&input).unwrap(), b"abc");
    }

    #[test]
    fn decode_copy_item() {
        // "abc" literals (items 0-2), then copy item len 6 offset 3
        // (bit 3 set). Control = 0x0008. LZRW1 length field = len - 1.
        let input = [0, 0, 0, 0, 0x08, 0x00, b'a', b'b', b'c', 0x05, 0x03];
        assert_eq!(decode(&input).unwrap(), b"abcabcabc");
    }

    #[test]
    fn decode_short_copy() {
        // LZRW1 can express copies of 1-2 bytes (field 0-1), which the
        // reference encoder never emits but the decoder must accept.
        // items 0-2 literals "abc", item 3 copy len 1 offset 2, item 4
        // copy len 2 offset 4. Control = 0b11000 = 0x0018.
        let input = [
            0, 0, 0, 0, 0x18, 0x00, b'a', b'b', b'c', 0x00, 0x02, 0x01, 0x04,
        ];
        assert_eq!(decode(&input).unwrap(), b"abcbab");
    }

    #[test]
    fn decode_max_len_copy() {
        // len 16 (field 15) offset 1: 16 bytes of 'a' after one literal.
        // item0 literal (bit0=0), item1 copy (bit1=1) -> control 0x0002.
        let input = [0, 0, 0, 0, 0x02, 0x00, b'a', 0x0f, 0x01];
        assert_eq!(decode(&input).unwrap(), vec![b'a'; 17]);
    }

    #[test]
    fn decode_control_bit_order() {
        // Second control byte covers items 8-15. Item 8 is bit 0 of byte 1.
        let mut input = vec![0u8, 0, 0, 0, 0x00, 0x01];
        input.extend_from_slice(b"abcdefgh");
        input.extend_from_slice(&[0x02, 0x08]); // copy len 3 offset 8
        // items 0-7 literals "abcdefgh", item 8 copy len 3 off 8 -> "abc"
        assert_eq!(decode(&input).unwrap(), b"abcdefghabc");
    }

    #[test]
    fn rejects_truncated_flag() {
        assert!(decode(&[0, 0]).is_err());
    }

    #[test]
    fn rejects_bad_flag() {
        assert!(decode(&[7, 0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_bad_offset() {
        // copy item with offset 0.
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x00, 0x00];
        assert!(decode(&input).is_err());
        // offset beyond output.
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x00, 0x05];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_truncated_copy_item() {
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x00];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'z'; 500];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&enc, 500).unwrap(), data);
        // copy-flag path respects the limit too.
        let raw = [1, 0, 0, 0, 9, 9, 9];
        assert!(decode_bounded(&raw, 2).is_err());
    }

    #[test]
    fn empty_input() {
        let enc = encode(b"");
        assert_eq!(decode(&enc).unwrap(), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_various() {
        rt(b"a");
        rt(b"ab");
        rt(b"abcabcabcabc");
        rt(b"hello world hello world hello world");
        rt(&[0u8; 2000]);
        rt(&[7u8; 20]);
        let mut text = Vec::new();
        for _ in 0..200 {
            text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&text);
        let mut binary = Vec::new();
        for i in 0..4000u32 {
            binary.extend_from_slice(&i.to_le_bytes());
        }
        rt(&binary);
        // Incompressible data exercises the verbatim copy flag.
        let mut noise = Vec::with_capacity(1024);
        let mut x = 0x9e3779b9u32;
        for _ in 0..1024 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            noise.push((x >> 24) as u8);
        }
        rt(&noise);
    }
}
