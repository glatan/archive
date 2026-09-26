//! LZF compression (liblzf format).
//!
//! Raw codec stream of control-byte segments (no container header):
//!
//! - `ctrl < 32`: literal run — `ctrl + 1` bytes (1..=32) copied verbatim.
//! - `ctrl >= 32`: back-reference — the high three bits select the encoded
//!   length and the low five bits are the high bits of the offset:
//!   - `ctrl >> 5` in `1..=6`: 2-byte match, length `n + 2` (3..=8).
//!   - `ctrl >> 5` == `7`: 3-byte match; a length extension byte follows,
//!     length `ext + 9` (9..=264).
//!   - offset = `((ctrl & 0x1f) << 8) | next_byte`, distance `offset + 1`
//!     (1..=8192).
//!
//! The stream ends when the input is exhausted. This format is documented
//! in the liblzf sources (`lzfP.h`, BSD license) and the LZFFormat
//! description used by the Java LZF implementation.

use alloc::vec::Vec;

use crate::error::Error;

const MAX_LITERAL_RUN: usize = 32;
const MIN_MATCH: usize = 3;
const MAX_MATCH_LEN: usize = 264;
const MAX_OFFSET: usize = 1 << 13;

/// Decode an LZF stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZF stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;

    while pos < input.len() {
        let ctrl = input[pos] as usize;
        pos += 1;
        if ctrl < 32 {
            let len = ctrl + 1;
            if pos + len > input.len() {
                return Err(Error::InvalidData("lzf: truncated literal run"));
            }
            if out.len() + len > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            out.extend_from_slice(&input[pos..pos + len]);
            pos += len;
        } else {
            let mut len = ctrl >> 5;
            if len == 7 {
                let ext = *input
                    .get(pos)
                    .ok_or(Error::InvalidData("lzf: truncated length extension"))?;
                pos += 1;
                len = ext as usize + 9;
            } else {
                len += 2;
            }
            let low = *input
                .get(pos)
                .ok_or(Error::InvalidData("lzf: truncated match offset"))?;
            pos += 1;
            let offset = (((ctrl & 0x1f) << 8) | low as usize) + 1;
            if offset > out.len() {
                return Err(Error::InvalidData("lzf: match offset before start"));
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
    }
    Ok(out)
}

/// Encode data as an LZF stream.
///
/// Greedy single-candidate hash parse over 3-byte prefixes; any
/// spec-conforming parse is valid.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() + input.len() / 32 + 4);
    let mut head = vec![-1i32; 1 << 14];
    let mut lit_start = 0usize;
    let mut lit_len = 0usize;
    let mut pos = 0usize;

    // Flush a pending literal run: control bytes encode runs of <=32.
    macro_rules! flush_literals {
        () => {
            while lit_len > 0 {
                let run = lit_len.min(MAX_LITERAL_RUN);
                out.push((run - 1) as u8);
                out.extend_from_slice(&input[lit_start..lit_start + run]);
                lit_start += run;
                lit_len -= run;
            }
        };
    }

    while pos + MIN_MATCH <= input.len() {
        let h = ((input[pos] as usize) << 8
            ^ (input[pos + 1] as usize) << 4
            ^ (input[pos + 2] as usize))
            & ((1 << 14) - 1);
        let cand = head[h];
        head[h] = pos as i32;
        let mut matched = false;
        if cand >= 0 {
            let c = cand as usize;
            if pos - c <= MAX_OFFSET && input[c..c + MIN_MATCH] == input[pos..pos + MIN_MATCH] {
                let mut len = MIN_MATCH;
                while pos + len < input.len() && input[c + len] == input[pos + len] {
                    len += 1;
                }
                len = len.min(MAX_MATCH_LEN);

                flush_literals!();

                let offset = pos - c - 1;
                if len <= 8 {
                    out.push((((len - 2) << 5) | ((offset >> 8) & 0x1f)) as u8);
                    out.push((offset & 0xff) as u8);
                } else {
                    out.push((0xe0 | ((offset >> 8) & 0x1f)) as u8);
                    out.push((len - 9) as u8);
                    out.push((offset & 0xff) as u8);
                }
                lit_start = pos + len;
                lit_len = 0;
                pos += len;
                matched = true;
            }
        }
        if !matched {
            if lit_len == 0 {
                lit_start = pos;
            }
            lit_len += 1;
            pos += 1;
        }
    }
    // Remaining tail (< MIN_MATCH bytes) becomes literals.
    if lit_len == 0 {
        lit_start = pos;
    }
    lit_len += input.len() - pos;
    flush_literals!();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        assert_eq!(decode(&encode(data)).unwrap(), data);
    }

    #[test]
    fn decode_literal_run() {
        // ctrl=2 -> 3 literal bytes.
        assert_eq!(decode(&[2, b'a', b'b', b'c']).unwrap(), b"abc");
    }

    #[test]
    fn decode_short_match() {
        // literals "abc" + match len 3 dist 3: len-2=1 <<5 | off-hi 0,
        // off-lo 2 -> ctrl 0x20, low 0x02.
        let input = [2, b'a', b'b', b'c', 0x20, 0x02];
        assert_eq!(decode(&input).unwrap(), b"abcabc");
    }

    #[test]
    fn decode_long_match() {
        // literals "abc" + long match: ctrl 0xe0, ext len (6-9=253 -> 262),
        // offset low 2 -> copies 262 bytes at distance 3.
        let input = [2, b'a', b'b', b'c', 0xe0, 0xfd, 0x02];
        let dec = decode(&input).unwrap();
        assert_eq!(dec.len(), 265);
        let expected: Vec<u8> = b"abc".iter().cycle().take(265).copied().collect();
        assert_eq!(dec, expected);
    }

    #[test]
    fn decode_offset_high_bits() {
        // 32 literal zeros then a match at distance 30: exercises the
        // offset high bits in the control byte.
        let mut input = vec![31u8];
        input.extend_from_slice(&[0u8; 32]);
        // distance 30 -> offset 29 = 0x001d: ctrl 0x20 (len 3), low 0x1d.
        input.extend_from_slice(&[0x20, 0x1d]);
        let dec = decode(&input).unwrap();
        assert_eq!(dec.len(), 35);
        // distance with nonzero high bits: offset 299 -> 0x012b needs
        // >= 300 output bytes; build 300 literal zeros first.
        let mut input = Vec::new();
        for _ in 0..10 {
            input.push(31u8);
            input.extend_from_slice(&[0u8; 32]);
        }
        input.push(0x21);
        input.push(0x2b);
        let dec = decode(&input).unwrap();
        assert_eq!(dec.len(), 323);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[5, b'a']).is_err()); // literal run cut short
        assert!(decode(&[0xe0]).is_err()); // missing length ext + offset
        assert!(decode(&[0xe0, 0x00]).is_err()); // missing offset byte
        assert!(decode(&[0x20]).is_err()); // missing offset byte
    }

    #[test]
    fn rejects_offset_before_start() {
        let input = [0x20, 0x00]; // match at distance 1 with empty output
        assert!(decode(&input).is_err());
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'q'; 500];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&enc, 500).unwrap(), data);
    }

    #[test]
    fn roundtrip_various() {
        rt(b"");
        rt(b"a");
        rt(b"ab");
        rt(b"abc");
        rt(b"hello world hello world hello world");
        rt(&[0u8; 1000]);
        rt(&[7u8; 40]); // short-run boundary
        let mut big = Vec::new();
        for i in 0..5000u32 {
            big.extend_from_slice(&i.to_le_bytes());
        }
        rt(&big);
        // long runs force 32-byte literal splitting and long matches
        let mut rep = Vec::new();
        for _ in 0..200 {
            rep.extend_from_slice(b"the quick brown fox. ");
        }
        rt(&rep);
    }
}
