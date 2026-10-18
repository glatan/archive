//! FastLZ compression (Ariya Hidayat's FastLZ format).
//!
//! Raw codec stream of control-byte segments (no container header). The
//! stream variant ("level") is signalled by bit 5 of the first byte:
//! level 2 encoders set it as a marker; the decoder masks it out.
//!
//! - `ctrl < 32`: literal run — `ctrl + 1` bytes (1..=32) copied verbatim.
//! - `ctrl >= 32`: match — `ctrl >> 5` encodes the length field and
//!   `ctrl & 0x1f` the high offset bits:
//!   - field 1..=6: length = field + 2 (3..=8), then one offset-low byte;
//!     distance = `(ctrl & 0x1f) << 8 | low` + 1.
//!   - field 7: one (level 1) or a chain of (level 2) 0xff-terminated
//!     extension bytes follow; length = 9 + sum(ext). Then the offset-low
//!     byte.
//!   - level 2 only: when `ctrl & 0x1f == 31` and the offset-low byte is
//!     `0xff`, a further 16-bit distance extension follows;
//!     distance = `ext16 + 8192` (8192..=73727).
//!
//! The stream ends when input is exhausted (level 1 tolerates one trailing
//! byte as in the reference decoder).

use alloc::vec::Vec;

use crate::error::Error;

const MAX_LITERAL_RUN: usize = 32;
const MIN_MATCH: usize = 3;
/// Maximum distance encodable in level-1 streams (13 offset bits).
const MAX_L1_DISTANCE: usize = 8192;
/// Maximum distance encodable in level-2 short form.
const MAX_L2_NEAR: usize = 8191;
/// Maximum distance encodable in level-2 far form.
const MAX_L2_DISTANCE: usize = 73727;

/// Decode a FastLZ stream (level auto-detected from the first byte).
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a FastLZ stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let level = (input[0] >> 5) + 1;
    match level {
        1 => decode_level(input, max_output, Level::One),
        2 => decode_level(input, max_output, Level::Two),
        _ => Err(Error::InvalidData("fastlz: unsupported level marker")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    One,
    Two,
}

fn decode_level(input: &[u8], max_output: usize, level: Level) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 1usize;
    // The first control byte carries the level marker in bit 5.
    let mut ctrl = (input[0] & 31) as usize;

    loop {
        if ctrl >= 32 {
            let mut len = (ctrl >> 5) - 1;
            let ofs_hi = (ctrl & 31) << 8;
            if len == 6 {
                match level {
                    Level::One => {
                        let ext = *input
                            .get(pos)
                            .ok_or(Error::InvalidData("fastlz: truncated length extension"))?;
                        pos += 1;
                        len += ext as usize;
                    }
                    Level::Two => loop {
                        let ext = *input
                            .get(pos)
                            .ok_or(Error::InvalidData("fastlz: truncated length extension"))?;
                        pos += 1;
                        len += ext as usize;
                        if ext != 255 {
                            break;
                        }
                    },
                }
            }
            len += 3;
            let low = *input
                .get(pos)
                .ok_or(Error::InvalidData("fastlz: truncated match offset"))?;
            pos += 1;
            let mut distance = (ofs_hi | low as usize) + 1;
            if level == Level::Two && low == 255 && ofs_hi == 31 << 8 {
                // Level-2 far match: 16-bit distance extension.
                if pos + 2 > input.len() {
                    return Err(Error::InvalidData("fastlz: truncated far distance"));
                }
                let ext = u16::from_be_bytes(input[pos..pos + 2].try_into().unwrap());
                pos += 2;
                distance = ext as usize + 8192;
            }
            if distance > out.len() {
                return Err(Error::InvalidData("fastlz: match offset before start"));
            }
            if out.len() + len > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            crate::compress::match_ops::copy_match(&mut out, distance, len)
                .map_err(|_| Error::InvalidData("fastlz: match offset before start"))?;
        } else {
            let n = ctrl + 1;
            if pos + n > input.len() {
                return Err(Error::InvalidData("fastlz: truncated literal run"));
            }
            if out.len() + n > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            out.extend_from_slice(&input[pos..pos + n]);
            pos += n;
        }
        // Level 1 stops when fewer than 2 bytes remain; level 2 continues
        // while any byte remains (matches the reference loop conditions).
        let done = match level {
            Level::One => pos + 2 > input.len(),
            Level::Two => pos >= input.len(),
        };
        if done {
            break;
        }
        ctrl = input[pos] as usize;
        pos += 1;
    }
    Ok(out)
}

/// Encode data as a FastLZ stream.
///
/// Like the reference `fastlz_compress`, level 1 is used for inputs below
/// 64 KiB and level 2 for larger inputs.
pub fn encode(input: &[u8]) -> Vec<u8> {
    if input.len() < 65536 {
        encode_level1(input)
    } else {
        encode_level2(input)
    }
}

/// Encode data as a level-1 FastLZ stream (max distance 8192).
pub fn encode_level1(input: &[u8]) -> Vec<u8> {
    encode_inner(input, MAX_L1_DISTANCE, false)
}

/// Encode data as a level-2 FastLZ stream (near distance 8191, far 73727).
///
/// Distances >= 8192 use the far-match form. Length extensions use the
/// level-2 0xff-terminated chain.
pub fn encode_level2(input: &[u8]) -> Vec<u8> {
    let mut out = encode_inner(input, MAX_L2_DISTANCE, true);
    // Level marker: the first emitted byte is always a literal-run ctrl
    // (or empty); setting bit 5 marks the stream as level 2.
    if let Some(first) = out.first_mut() {
        *first |= 1 << 5;
    }
    out
}

fn encode_inner(input: &[u8], max_distance: usize, level2: bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() + input.len() / 32 + 4);
    let mut head = vec![-1i32; 1 << 15];
    let mut lit_start = 0usize;
    let mut lit_len = 0usize;
    let mut pos = 0usize;

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

    macro_rules! emit_match {
        ($len:expr, $dist:expr) => {{
            let len = $len;
            let dist = $dist;
            if level2 && dist > MAX_L2_NEAR {
                // Far match: ctrl keeps len field, offset high bits 0x1f,
                // then length extension, 0xff, and 16-bit distance minus 8192.
                let d16 = dist - 8192;
                if len <= 8 {
                    out.push((((len - 2) << 5) | 31) as u8);
                } else {
                    out.push((7 << 5 | 31) as u8);
                    let mut rest = len - 9;
                    while rest >= 255 {
                        out.push(255);
                        rest -= 255;
                    }
                    out.push(rest as u8);
                }
                out.push(255);
                out.extend_from_slice(&(d16 as u16).to_be_bytes());
            } else {
                let d = dist - 1;
                if len <= 8 {
                    out.push((((len - 2) << 5) | ((d >> 8) & 0x1f)) as u8);
                    out.push((d & 0xff) as u8);
                } else if level2 {
                    out.push((0xe0 | ((d >> 8) & 0x1f)) as u8);
                    let mut rest = len - 9;
                    while rest >= 255 {
                        out.push(255);
                        rest -= 255;
                    }
                    out.push(rest as u8);
                    out.push((d & 0xff) as u8);
                } else {
                    // Level 1: single extension byte; longer matches are
                    // split into <=264-byte chunks. Each emitted piece must
                    // leave a remainder of either 0 or >= MIN_MATCH so the
                    // continuation can itself be encoded as a match.
                    let mut remaining = len;
                    while remaining > 0 {
                        let mut t = remaining.min(264);
                        let leftover = remaining - t;
                        if leftover == 1 || leftover == 2 {
                            t -= 3 - leftover;
                        }
                        if t <= 8 {
                            out.push((((t - 2) << 5) | ((d >> 8) & 0x1f)) as u8);
                            out.push((d & 0xff) as u8);
                        } else {
                            out.push((0xe0 | ((d >> 8) & 0x1f)) as u8);
                            out.push((t - 9) as u8);
                            out.push((d & 0xff) as u8);
                        }
                        remaining -= t;
                    }
                }
            }
        }};
    }

    while pos + MIN_MATCH <= input.len() {
        let h = ((input[pos] as usize) << 8
            ^ (input[pos + 1] as usize) << 4
            ^ (input[pos + 2] as usize))
            & ((1 << 15) - 1);
        let cand = head[h];
        head[h] = pos as i32;
        let mut matched = false;
        if cand >= 0 {
            let c = cand as usize;
            if pos - c <= max_distance && input[c..c + MIN_MATCH] == input[pos..pos + MIN_MATCH] {
                let len = MIN_MATCH
                    + crate::compress::match_ops::match_len(
                        &input[c + MIN_MATCH..],
                        &input[pos + MIN_MATCH..],
                        input.len() - (pos + MIN_MATCH),
                    );
                flush_literals!();
                emit_match!(len, pos - c);
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
        assert_eq!(decode(&encode_level1(data)).unwrap(), data);
        assert_eq!(decode(&encode_level2(data)).unwrap(), data);
    }

    #[test]
    fn decode_literal_run() {
        assert_eq!(decode(&[2, b'a', b'b', b'c']).unwrap(), b"abc");
    }

    #[test]
    fn decode_short_match() {
        // "abc" + match len 3 dist 3: field = 1 <<5 | hi 0, low 2.
        let input = [2, b'a', b'b', b'c', 0x20, 0x02];
        assert_eq!(decode(&input).unwrap(), b"abcabc");
    }

    #[test]
    fn decode_l1_long_match() {
        // "abc" + long match len 9+0 dist 3.
        let input = [2, b'a', b'b', b'c', 0xe0, 0x00, 0x02];
        assert_eq!(decode(&input).unwrap(), b"abcabcabcabc");
    }

    #[test]
    fn decode_l2_ext_chain() {
        // Level-2 stream: literal ctrl with marker bit, "aa", then a long
        // match with a 0xff extension chain: len = 9 + 255 + 29 = 293 at
        // distance 2. (Real fastlz output for 300-byte input.)
        let input = [
            0x21, 0x61, 0x61, 0xe0, 0xff, 0x1d, 0x01, 0x04, 0x61, 0x61, 0x61, 0x61, 0x00,
        ];
        let dec = decode(&input).unwrap();
        assert_eq!(dec.len(), 300);
        assert_eq!(&dec[..296], &[0x61u8; 296]);
    }

    #[test]
    fn decode_l2_far_match() {
        // Hand-built level-2 far match: 'a'*3 literal, then far match at
        // distance 8192+0 = 8192? -- need >= 8192 output first, so use a
        // smaller gap: distance = ext16 + 8192; emit 9000 literals is too
        // long for one run; use matches: 'x'*9000 via L2 then far ref.
        let mut input = vec![0x21, b'x', b'x']; // marker + 2 literals
        // long match len 9+255+13 = 277 at dist 2 -> 279 x's so far... build
        // enough output with repeated long matches at dist 1.
        // Simpler: emit literals in chunks to reach 8200 output.
        input.clear();
        input.push(0x20); // level-2 marker, literal run 1 byte
        input.push(b'x');
        // 8200 total 'x' bytes via repeated matches dist 1 len 264:
        // ctrl 0xe0, ext 255 (len 264)... encode: len 264 -> field7, ext chain 255? no:
        // len 264 -> rest = 264-9 = 255 -> chain [255, 0]? while rest>=255 push 255, rest-=255
        // -> [255, 0]? rest 255 >=255 push 255 rest=0 push 0. len = 9+255+0=264. ok.
        for _ in 0..31 {
            input.push(0xe0);
            input.push(0xff);
            input.push(0x00);
            input.push(0x00); // offset low 0 -> dist 1
        }
        // now out = 1 + 31*264 = 8185 'x'. Add literal run 8 -> 8193.
        input.push(0x07);
        input.extend_from_slice(&[b'x'; 8]);
        // far match: ctrl field1|31 = 0x3f (len 3), low 0xff, ext16 = 1 -> dist 8193.
        input.extend_from_slice(&[0x3f, 0xff]);
        input.extend_from_slice(&1u16.to_be_bytes());
        let dec = decode(&input).unwrap();
        assert_eq!(dec.len(), 8196);
        assert!(dec.iter().all(|&b| b == b'x'));
    }

    #[test]
    fn rejects_bad_level() {
        assert!(decode(&[0x60, 0, 0]).is_err()); // level 3 marker
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[5, b'a']).is_err());
        assert!(decode(&[0xe0]).is_err());
        assert!(decode(&[0xe0, 0x00]).is_err());
        // level-2 far match missing the distance extension
        let far = [0x21, b'a', b'a', 0x3f, 0xff];
        assert!(decode(&far).is_err());
    }

    #[test]
    fn rejects_offset_before_start() {
        // "abc" literals then a match at distance 6 (> output 3).
        let input = [2, b'a', b'b', b'c', 0x20, 0x05];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'z'; 1000];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&enc, 1000).unwrap(), data);
    }

    #[test]
    fn empty_input() {
        assert_eq!(encode(b""), Vec::<u8>::new());
        assert_eq!(decode(&[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn roundtrip_various() {
        rt(b"a");
        rt(b"ab");
        rt(b"abc");
        rt(b"hello world hello world hello world");
        rt(&[0u8; 1000]);
        rt(&[7u8; 40]);
        rt(&[9u8; 70000]); // forces level-2 path and far/long matches
        let mut big = Vec::new();
        for i in 0..20000u32 {
            big.extend_from_slice(&i.to_le_bytes());
        }
        rt(&big); // 80000 bytes -> level 2
        let mut rep = Vec::new();
        for _ in 0..300 {
            rep.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        rt(&rep);
    }
}
