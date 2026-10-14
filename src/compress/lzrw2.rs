//! LZRW2 compression (Ross Williams, public domain format).
//!
//! LZRW2 shares the LZRW1-A container (4-byte copy flag + 16-item groups)
//! but a copy item carries a *phrase table index* instead of a byte offset.
//! The phrase table is a 4096-entry circular table maintained by both the
//! compressor and the decompressor: after every item, the position where
//! that item's decoded bytes start overwrites the next cyclic entry.
//! A copy item `C1 C2` decodes as length = `(C1 & 0x0f) + 3` (3..=18) and
//! index = `(C1 >> 4) * 256 + C2` (0..=4095); the index selects the phrase
//! table entry whose recorded output position is the copy source.
//!
//! Phrase table entry 0 is pre-initialized (by convention) to an 18-byte
//! constant string so the compressor's all-zero hash table state refers to
//! defined text; every other entry may only be referenced after it has
//! been written by a preceding item.

use alloc::vec::Vec;

use crate::compress::lzrw;
use crate::error::Error;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 18;
const PHRASE_TABLE_LEN: usize = 4096;
const HASH_TABLE_LEN: usize = 4096;

const FLAG_ERRS: lzrw::FlagErrs = lzrw::FlagErrs {
    truncated_flag: "lzrw2: truncated copy flag",
    unknown_flag: "lzrw2: unknown copy flag",
};

/// Decode an LZRW2 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZRW2 stream with an output size limit.
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
    // phrase[i] = output position where the i-th item's bytes started.
    // Entry 0 conceptually holds the constant start string until it is
    // overwritten by the first item.
    let mut phrase = [0usize; PHRASE_TABLE_LEN];
    let mut next = 0usize; // next cyclic entry to overwrite
    let mut decoded = 0usize; // number of items decoded so far

    let mut items = lzrw::Items::new(input, MIN_MATCH, "lzrw2: truncated copy item");
    while let Some(item) = items.next()? {
        match item {
            lzrw::Item::Literal(b) => {
                phrase[next] = out.len();
                next = (next + 1) & (PHRASE_TABLE_LEN - 1);
                decoded += 1;
                if out.len() == max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                out.push(b);
            }
            lzrw::Item::Copy { len, index } => {
                // Resolve the copy source BEFORE updating the table: the
                // reference reads the entry first, then writes phrase[next].
                let source = if index == 0 && decoded == 0 {
                    None // constant start string
                } else if index < decoded.min(PHRASE_TABLE_LEN) {
                    Some(phrase[index])
                } else {
                    return Err(Error::InvalidData("lzrw2: phrase index out of range"));
                };
                phrase[next] = out.len();
                next = (next + 1) & (PHRASE_TABLE_LEN - 1);
                decoded += 1;
                if out.len() + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                match source {
                    Some(pos) => lzrw::copy_from_output(&mut out, pos, len),
                    None => out.extend_from_slice(&lzrw::START_STRING_18[..len]),
                }
            }
        }
    }
    Ok(out)
}

/// Encode data as an LZRW2 stream.
///
/// If compression does not reduce the size, the verbatim-copy form
/// (copy flag = 1) is emitted, matching the reference encoder.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = lzrw::GroupEncoder::new();

    // hash[h] = phrase-table index of the most recent phrase whose 3-byte
    // prefix hashed to h; all entries start at 0 (the constant-string
    // entry) exactly like the reference compressor.
    let mut hash_idx = [0u16; HASH_TABLE_LEN];
    // phrase[i] = input position where the i-th emitted item started.
    let mut phrase = [0usize; PHRASE_TABLE_LEN];
    let mut next = 0usize;
    let mut emitted = 0usize;

    let mut pos = 0usize;
    while pos < input.len() {
        if pos + MIN_MATCH <= input.len() {
            let h = lzrw::hash3(&input[pos..], 0xFFF);
            let index = hash_idx[h] as usize;
            // Resolve the candidate BEFORE this item's phrase-table write:
            // after a full 4096-item cycle `index` can equal `next`, and
            // the decompressor also reads the entry before overwriting it.
            let cand_pos = phrase[index];
            let cand_is_start = index == 0 && emitted == 0;
            hash_idx[h] = next as u16;
            phrase[next] = pos;
            next = (next + 1) & (PHRASE_TABLE_LEN - 1);
            emitted += 1;

            // Entry 0 is the constant start string only until the first
            // item writes it.
            let len = if cand_is_start {
                match_prefix(&input[pos..], lzrw::START_STRING_18)
            } else {
                match_prefix(&input[pos..], &input[cand_pos..])
            };
            if len >= MIN_MATCH {
                enc.copy(len - MIN_MATCH, index);
                pos += len;
            } else {
                enc.literal(input[pos]);
                pos += 1;
            }
        } else {
            // Fewer than three bytes remain: no hash can be taken.
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

/// Longest common prefix of `a` (the lookahead text) and `b` (a candidate
/// source), capped at [`MAX_MATCH`].
fn match_prefix(a: &[u8], b: &[u8]) -> usize {
    let mut len = 0;
    while len < MAX_MATCH && len < a.len() && len < b.len() && a[len] == b[len] {
        len += 1;
    }
    len
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
        // non-zero (matching the reference decoder).
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
    fn decode_literal_group() {
        // control word 0x0000 + 3 literal bytes (partial group).
        let input = [0, 0, 0, 0, 0, 0, b'a', b'b', b'c'];
        assert_eq!(decode(&input).unwrap(), b"abc");
    }

    #[test]
    fn decode_copy_item() {
        // "abc" literals (items 0-2), then copy item len 6 referencing
        // phrase table entry 0 (start of item 0 = position 0). Control
        // = 0x0008; copy item: len-3=3, index 0 -> [0x03, 0x00].
        let input = [0, 0, 0, 0, 0x08, 0x00, b'a', b'b', b'c', 0x03, 0x00];
        assert_eq!(decode(&input).unwrap(), b"abcabcabc");
    }

    #[test]
    fn decode_phrase_index_semantics() {
        // items 0-2 literals "abc" (phrase entries 0,1,2 -> pos 0,1,2),
        // item 3 copy len 3 index 2 -> copies 3 bytes from pos 2 with
        // overlap: 'c','c','c'.
        let input = [0, 0, 0, 0, 0x08, 0x00, b'a', b'b', b'c', 0x00, 0x02];
        assert_eq!(decode(&input).unwrap(), b"abcccc");
    }

    #[test]
    fn decode_start_string_reference() {
        // A copy item with index 0 as the very first item copies from the
        // 18-byte constant start string "123456789012345678".
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x02, 0x00]; // len 5 index 0
        assert_eq!(decode(&input).unwrap(), b"12345");
    }

    #[test]
    fn rejects_unwritten_phrase_index() {
        // First item is a copy with index 5: entry 5 has never been
        // written and is not the start-string entry.
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x02, 0x05];
        assert!(decode(&input).is_err());
    }

    #[test]
    fn decode_overlapping_copy() {
        // items 0-3 literals "abca"; item 4 copy len 18 index 0 (pos 0).
        // len 18 from pos 0 overlaps the phrase being produced.
        let input = [0, 0, 0, 0, 0x10, 0x00, b'a', b'b', b'c', b'a', 0x0f, 0x00];
        let mut expected = b"abca".to_vec();
        expected.extend_from_slice(b"abcaabcaabcaabcaab");
        assert_eq!(decode(&input).unwrap(), expected);
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
        rt(b"123456789012345678 and 123456789012345678");
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
        // `binary` above exceeds 4096 phrases and exercises the cyclic
        // wrap of the phrase table; `long` adds a longer compressible run.
        let mut long = Vec::new();
        for i in 0..6000u32 {
            long.extend_from_slice(&(i % 251).to_le_bytes());
            long.push(b'x');
        }
        rt(&long);
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
