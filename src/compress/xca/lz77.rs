//! Plain LZ77 ("Xpress") compression — MS-XCA §2.3/§2.4.
//!
//! Stream layout: a sequence of 32-bit little-endian flag words, each
//! describing the following 32 elements MSB-first. A clear flag bit means a
//! literal byte; a set bit means a 16-bit match word whose high 13 bits are
//! the match offset minus one and whose low 3 bits are the length minus
//! three. A length field of 7 selects extended length coding: a 4-bit nibble
//! (two consecutive long matches share one byte), then a byte, a u16, or a
//! u32 escape for longer lengths.
//!
//! The encoder pads the final flag word with one bits; the decoder treats a
//! match flag observed with no input remaining as normal termination.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// Maximum match distance (2^13).
const MAX_OFFSET: usize = 1 << 13;
const MIN_MATCH: usize = 3;

/// Decode a Plain LZ77 stream.
///
/// The stream ends when the input is exhausted while a match flag is
/// pending (the encoder pads the trailing flag word with one bits) or when
/// a new flag word would be read past the end.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a Plain LZ77 stream with an output size limit.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    decode_internal(input, max_output, None)
}

/// Decode a Plain LZ77 stream with a known decompressed size.
///
/// Per MS-XCA the decoder is driven by the caller-provided output buffer
/// size; decoding stops once  bytes have been produced. This
/// also accepts streams that carry undecodable trailing flag bits (for
/// example, literal flags with no element data).
pub fn decode_with_size(input: &[u8], output_size: usize) -> Result<Vec<u8>, Error> {
    decode_internal(input, usize::MAX, Some(output_size))
}

fn decode_internal(
    input: &[u8],
    max_output: usize,
    expected: Option<usize>,
) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    let mut last_half = 0usize; // 1-based position of a pending length nibble byte

    loop {
        if flag_count == 0 {
            if pos >= input.len() {
                break;
            }
            if pos + 4 > input.len() {
                return Err(Error::InvalidData("xpress: truncated flag word"));
            }
            flags = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap());
            pos += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        // A flag word consumed with no element data remaining marks the end
        // of the stream; the unused flag bits are don't-care padding.
        if pos >= input.len() {
            break;
        }
        if flags & (1 << flag_count) == 0 {
            out.push(input[pos]);
            pos += 1;
        } else {
            if pos + 2 > input.len() {
                return Err(Error::InvalidData("xpress: truncated match word"));
            }
            let word = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;
            let mut len = word % 8;
            let offset = word / 8 + 1;
            if len == 7 {
                if last_half == 0 {
                    let b = *input
                        .get(pos)
                        .ok_or(Error::InvalidData("xpress: truncated length nibble"))?;
                    len = (b % 16) as usize;
                    last_half = pos + 1;
                    pos += 1;
                } else {
                    len = (input[last_half - 1] / 16) as usize;
                    last_half = 0;
                }
                if len == 15 {
                    len = *input
                        .get(pos)
                        .ok_or(Error::InvalidData("xpress: truncated length byte"))?
                        as usize;
                    pos += 1;
                    if len == 255 {
                        if pos + 2 > input.len() {
                            return Err(Error::InvalidData("xpress: truncated length u16"));
                        }
                        len = u16::from_le_bytes(input[pos..pos + 2].try_into().unwrap()) as usize;
                        pos += 2;
                        if len == 0 {
                            if pos + 4 > input.len() {
                                return Err(Error::InvalidData("xpress: truncated length u32"));
                            }
                            len = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap())
                                as usize;
                            pos += 4;
                        }
                        if len < 15 + 7 {
                            return Err(Error::InvalidData("xpress: invalid length escape"));
                        }
                        len -= 15 + 7;
                    }
                    len += 15;
                }
                len += 7;
            }
            len += 3;
            if offset > out.len() {
                return Err(Error::InvalidData("xpress: match offset before start"));
            }
            if out.len() + len > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            crate::compress::match_ops::copy_match(&mut out, offset, len)
                .map_err(|_| Error::InvalidData("xpress: match offset before start"))?;
        }
        if out.len() > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        if expected.is_some_and(|n| out.len() >= n) {
            break;
        }
    }
    Ok(out)
}

/// Encode data as a Plain LZ77 stream.
pub fn encode(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        // One flag word of padding bits; the decoder ends immediately.
        return u32::MAX.to_le_bytes().to_vec();
    }

    let mut table = MatchTable::new(input);
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 2 + 8);
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    let mut flag_pos = 0usize;
    out.extend_from_slice(&[0; 4]); // first flag word slot
    let mut last_half = 0usize; // 1-based position of a pending nibble byte
    let mut pos = 0usize;

    while pos < input.len() {
        let m = if pos + MIN_MATCH <= input.len() {
            table.find(input, pos, MAX_OFFSET)
        } else {
            None
        };
        match m {
            Some((offset, len)) => {
                let mut ml = len - 3;
                let word = (((offset - 1) << 3) | ml.min(7)) as u16;
                out.extend_from_slice(&word.to_le_bytes());
                if ml >= 7 {
                    ml -= 7;
                    let mut need_extra = false;
                    if last_half == 0 {
                        if ml < 15 {
                            last_half = out.len() + 1;
                            out.push(ml as u8);
                        } else {
                            last_half = out.len() + 1;
                            out.push(15);
                            need_extra = true;
                        }
                    } else {
                        if ml < 15 {
                            out[last_half - 1] |= (ml as u8) << 4;
                        } else {
                            out[last_half - 1] |= 15 << 4;
                            need_extra = true;
                        }
                        last_half = 0;
                    }
                    if need_extra {
                        ml -= 15;
                        if ml < 255 {
                            out.push(ml as u8);
                        } else {
                            out.push(255);
                            let full = len - 3;
                            if full < (1 << 16) {
                                out.extend_from_slice(&(full as u16).to_le_bytes());
                            } else {
                                out.extend_from_slice(&0u16.to_le_bytes());
                                out.extend_from_slice(&(full as u32).to_le_bytes());
                            }
                        }
                    }
                }
                flags = (flags << 1) | 1;
                pos += len;
            }
            None => {
                out.push(input[pos]);
                flags <<= 1;
                pos += 1;
            }
        }
        flag_count += 1;
        if flag_count == 32 {
            let slot = flag_pos;
            out[slot..slot + 4].copy_from_slice(&flags.to_le_bytes());
            flag_count = 0;
            flag_pos = out.len();
            out.extend_from_slice(&[0; 4]);
        }
    }

    // Pad the remaining flag bits with ones and store the last flag word.
    if flag_count == 0 {
        let slot = flag_pos;
        out[slot..slot + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    } else {
        flags <<= 32 - flag_count;
        flags |= (1u32 << (32 - flag_count)) - 1;
        let slot = flag_pos;
        out[slot..slot + 4].copy_from_slice(&flags.to_le_bytes());
    }
    out
}

/// Shared greedy match finder for the XCA codecs.
///
/// Single-candidate hash table over 3-byte prefixes: keeps the most recent
/// position for each hash and extends matches greedily. This is a fast,
/// spec-compliant strategy — the formats place no requirement on parse
/// optimality.
pub(crate) struct MatchTable {
    head: Vec<i32>,
}

impl MatchTable {
    /// `window` is unused here; distance bounds are enforced in `find`.
    pub(crate) fn new(_input: &[u8]) -> Self {
        Self {
            head: vec![-1; 1 << 15],
        }
    }

    fn hash(data: &[u8], pos: usize) -> usize {
        let v = (data[pos] as u32) | ((data[pos + 1] as u32) << 8) | ((data[pos + 2] as u32) << 16);
        (v.wrapping_mul(0x9E37_79B1) >> 17) as usize & ((1 << 15) - 1)
    }

    /// Find a match at `pos` with `1 <= offset <= max_offset`. Returns the
    /// longest match from the single most recent candidate, or `None`.
    /// The result length may exceed `u16` limits; callers cap as needed.
    pub(crate) fn find(
        &mut self,
        data: &[u8],
        pos: usize,
        max_offset: usize,
    ) -> Option<(usize, usize)> {
        if pos + MIN_MATCH > data.len() {
            return None;
        }
        let h = Self::hash(data, pos);
        let cand = self.head[h];
        self.head[h] = pos as i32;
        if cand < 0 {
            return None;
        }
        let c = cand as usize;
        if pos - c > max_offset || data[c..c + 3] != data[pos..pos + 3] {
            return None;
        }
        let len = MIN_MATCH
            + crate::compress::match_ops::match_len(
                &data[c + MIN_MATCH..],
                &data[pos + MIN_MATCH..],
                data.len() - (pos + MIN_MATCH),
            );
        Some((pos - c, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn spec_example_literals() {
        // MS-XCA §3.1: 26 literals -> flags then bytes.
        let enc = encode(b"abcdefghijklmnopqrstuvwxyz");
        assert_eq!(&enc[..4], &[0x3f, 0x00, 0x00, 0x00]);
        let dec = decode(&enc).unwrap();
        assert_eq!(dec, b"abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn spec_example_match() {
        // MS-XCA §3.1: "abc" * 100 -> abc + match (distance 3, length 297).
        let data: Vec<u8> = b"abc".iter().cycle().take(300).cloned().collect();
        let dec = decode(&encode(&data)).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn roundtrip_various() {
        rt(b"");
        rt(b"a");
        rt(b"ab");
        rt(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        rt(&[7u8; 100_000]); // exercises u16 length escape
        let mut big = Vec::new();
        for i in 0..5000u32 {
            big.extend_from_slice(&i.to_le_bytes());
        }
        rt(&big);
    }

    #[test]
    fn long_match_u16_escape() {
        // >255+22 encoded length uses the u16 escape path.
        let data = vec![b'x'; 1000];
        let dec = decode(&encode(&data)).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn rejects_truncated() {
        let enc = encode(b"hello hello hello hello");
        for cut in [enc.len() - 1, 4] {
            if cut > 0 {
                let _ = decode(&enc[..cut]); // may end cleanly or error, no panic
            }
        }
        assert!(decode(&[0xff]).is_err() || decode(&[0xff]).unwrap().is_empty());
    }

    #[test]
    fn offset_bounds() {
        // Flag=1 match at position 0 -> offset before start must error.
        let input = [0x00, 0x00, 0x00, 0x80, 0x00, 0x00];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn trailing_flag_word_without_data() {
        // Stream produced by an older Windows encoder (via Samba's
        // test_lzxpress): 4 trailing zero bytes occupy the remaining
        // literal flag positions, so the decompressed size is required to
        // recover exactly the original 38 bytes.
        let input = [
            0x00, 0x20, 0x00, 0x04, 0x74, 0x68, 0x69, 0x73, 0x20, 0x10, 0x00, 0x61, 0x20, 0x74,
            0x65, 0x73, 0x74, 0x2E, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x9F, 0x00, 0x04, 0x20, 0x74,
            0x6F, 0x6F, 0x00, 0x00, 0x00, 0x00,
        ];
        let dec = decode_with_size(&input, 38).unwrap();
        assert_eq!(dec, b"this is a test. and this is a test too");
    }

    #[test]
    fn bounded_decode() {
        let data = vec![b'y'; 5000];
        let enc = encode(&data);
        assert!(matches!(
            decode_bounded(&enc, 100),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(decode_bounded(&enc, 5000).unwrap().len(), 5000);
    }
}
