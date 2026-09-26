//! LZRW1-A compression (Ross Williams, public domain format).
//!
//! The stream begins with a 4-byte copy flag: if the flag byte is 1 the
//! remainder of the stream is the data verbatim (used by the encoder when
//! compression would not shrink the input). If the flag is 0 the stream is
//! a sequence of groups, each carrying a 16-bit control word (LSB first,
//! bit i describing item i: 0 = literal byte, 1 = copy item) followed by up
//! to sixteen items. The final group may be partial.
//!
//! A copy item is two bytes `C1 C2`: length = `(C1 & 0x0f) + 3` (3..=18)
//! and offset = `(C1 >> 4) << 8 | C2` (1..=4095, zero never used), copying
//! from `output_len - offset`.

use alloc::vec::Vec;

use crate::error::Error;

const FLAG_BYTES: usize = 4;
const FLAG_COMPRESS: u8 = 0;
const FLAG_COPY: u8 = 1;
const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 18;
const MAX_OFFSET: usize = 4095;
const HASH_BITS: usize = 12;

/// Decode an LZRW1-A stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZRW1-A stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() < FLAG_BYTES {
        return Err(Error::InvalidData("lzrw1a: truncated copy flag"));
    }
    if input[0] == FLAG_COPY {
        let data = &input[FLAG_BYTES..];
        if data.len() > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        return Ok(data.to_vec());
    }
    if input[0] != FLAG_COMPRESS {
        return Err(Error::InvalidData("lzrw1a: unknown copy flag"));
    }

    let mut out: Vec<u8> = Vec::new();
    let mut pos = FLAG_BYTES;
    while pos + 2 <= input.len() {
        let control = u16::from_le_bytes([input[pos], input[pos + 1]]);
        pos += 2;
        let mut mask = 1u16;
        while mask != 0 {
            if pos >= input.len() {
                break;
            }
            if control & mask == 0 {
                let b = input[pos];
                pos += 1;
                if out.len() == max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                out.push(b);
            } else {
                if pos + 2 > input.len() {
                    return Err(Error::InvalidData("lzrw1a: truncated copy item"));
                }
                let c1 = input[pos] as usize;
                let c2 = input[pos + 1] as usize;
                pos += 2;
                let len = (c1 & 0x0f) + 3;
                let offset = (c1 >> 4) * 256 + c2;
                if offset == 0 || offset > out.len() {
                    return Err(Error::InvalidData("lzrw1a: bad copy offset"));
                }
                if out.len() + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                let start = out.len() - offset;
                for i in 0..len {
                    let b = out[start + i];
                    out.push(b);
                }
            }
            mask = mask.wrapping_shl(1);
        }
    }
    Ok(out)
}

/// Encode data as an LZRW1-A stream.
///
/// If compression does not reduce the size, the verbatim-copy form
/// (copy flag = 1) is emitted, matching the reference encoder.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FLAG_BYTES + input.len() + input.len() / 16 + 4);
    out.resize(FLAG_BYTES, 0);
    out[0] = FLAG_COMPRESS;

    let mut head = vec![-1i32; 1 << HASH_BITS];
    let hash = |b: &[u8]| -> usize {
        (((b[0] as usize) << 8) ^ ((b[1] as usize) << 4) ^ b[2] as usize).wrapping_mul(40543)
            >> (32 - HASH_BITS - 2)
            & ((1 << HASH_BITS) - 1)
    };

    let mut pos = 0usize;
    while pos < input.len() {
        // Reserve space for the group's control word.
        let ctrl_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let mut control = 0u16;
        let mut items = 0usize;
        while items < 16 && pos < input.len() {
            let mut match_len = 0usize;
            let mut match_off = 0usize;
            if pos + MIN_MATCH <= input.len() {
                let h = hash(&input[pos..]);
                let cand = head[h];
                head[h] = pos as i32;
                if cand >= 0 {
                    let c = cand as usize;
                    let dist = pos - c;
                    if dist <= MAX_OFFSET && input[c..c + MIN_MATCH] == input[pos..pos + MIN_MATCH]
                    {
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
                control |= 1 << items;
                let c1 = (((match_off >> 8) & 0x0f) << 4) | (match_len - 3);
                out.push(c1 as u8);
                out.push((match_off & 0xff) as u8);
                pos += match_len;
            } else {
                out.push(input[pos]);
                pos += 1;
            }
            items += 1;
        }
        out[ctrl_pos] = (control & 0xff) as u8;
        out[ctrl_pos + 1] = (control >> 8) as u8;
    }

    if out.len() >= FLAG_BYTES + input.len() {
        // Verbatim copy form.
        let mut copy = Vec::with_capacity(FLAG_BYTES + input.len());
        copy.extend_from_slice(&[FLAG_COPY, 0, 0, 0]);
        copy.extend_from_slice(input);
        return copy;
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
    fn decode_literal_group() {
        // control word 0x0000 + 3 literal bytes (partial group).
        let input = [0, 0, 0, 0, 0, 0, b'a', b'b', b'c'];
        assert_eq!(decode(&input).unwrap(), b"abc");
    }

    #[test]
    fn decode_copy_item() {
        // "abc" literals (items 0-2), then copy item len 6 offset 3
        // (bit 3 set). Control = 0x0008.
        let input = [0, 0, 0, 0, 0x08, 0x00, b'a', b'b', b'c', 0x03, 0x03];
        assert_eq!(decode(&input).unwrap(), b"abcabcabc");
    }

    #[test]
    fn decode_control_bit_order() {
        // Second control byte covers items 8-15. Item 8 is bit 0 of byte 1.
        let mut input = vec![0u8, 0, 0, 0, 0x00, 0x01];
        input.extend_from_slice(b"abcdefgh");
        input.extend_from_slice(&[0x00, 0x08]); // copy len 3 offset 8
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
