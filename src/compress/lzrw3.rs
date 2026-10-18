//! LZRW3 compression (Ross Williams, public domain format).
//!
//! LZRW3 shares the LZRW1-A container (4-byte copy flag + 16-item groups)
//! but a copy item carries a *hash table index* instead of a byte offset.
//! Both the compressor and the decompressor maintain an identical 4096-entry
//! hash table mapping 3-byte prefixes to output positions. A copy item
//! `C1 C2` decodes as length = `(C1 & 0x0f) + 3` (3..=18) and
//! index = `(C1 >> 4) * 256 + C2` (0..=4095); the entry at `index` holds
//! the copy source position, and is then overwritten with the position of
//! the item just decoded.
//!
//! Because a literal item does not provide three bytes to hash until more
//! input has been decoded, table updates for literal-only positions are
//! deferred: the oldest pending literal is hashed once three consecutive
//! literal bytes are available, and remaining pending literals are flushed
//! when the next copy item supplies the missing context. All table entries
//! initially point at an 18-byte constant string, so every index is always
//! meaningful.

use alloc::vec::Vec;

use crate::compress::lzrw;
use crate::error::Error;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 18;
const HASH_TABLE_LEN: usize = 4096;

const FLAG_ERRS: lzrw::FlagErrs = lzrw::FlagErrs {
    truncated_flag: "lzrw3: truncated copy flag",
    unknown_flag: "lzrw3: unknown copy flag",
};

/// Decode an LZRW3 stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZRW3 stream with an output size limit.
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
    // hash[h] = output position of the most recent phrase whose 3-byte
    // prefix hashed to h. `None` marks the initial constant-string entry.
    let mut hash: [Option<usize>; HASH_TABLE_LEN] = [None; HASH_TABLE_LEN];
    // Output positions of up to two literal items not yet hashable
    // (their three-byte context is not fully decoded yet).
    let mut pending: Vec<usize> = Vec::with_capacity(3);

    let mut items = lzrw::Items::new(input, MIN_MATCH, "lzrw3: truncated copy item");
    while let Some(item) = items.next()? {
        match item {
            lzrw::Item::Literal(b) => {
                if out.len() == max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                pending.push(out.len());
                out.push(b);
                if pending.len() == 3 {
                    // Three consecutive literals: hash the oldest one.
                    let r = pending.remove(0);
                    hash[lzrw::hash3(&out[r..r + 3], 0xFFF)] = Some(r);
                }
            }
            lzrw::Item::Copy { len, index } => {
                let ziv = out.len();
                // Read the source BEFORE any table update, exactly like the
                // reference decompressor.
                let source = hash[index];
                if ziv + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                match source {
                    Some(pos) => lzrw::copy_from_output(&mut out, pos, len),
                    None => out.extend_from_slice(&lzrw::START_STRING_18[..len]),
                }
                // The copy just supplied >= 3 bytes: flush pending literals
                // (oldest first), then record this phrase's position in the
                // entry the sender transmitted.
                for r in pending.drain(..) {
                    hash[lzrw::hash3(&out[r..r + 3], 0xFFF)] = Some(r);
                }
                hash[index] = Some(ziv);
            }
        }
    }
    Ok(out)
}

/// Encode data as an LZRW3 stream.
///
/// The encoder replicates the decompressor's table-update discipline so
/// every transmitted index resolves to the same source on both sides.
/// If compression does not reduce the size, the verbatim-copy form
/// (copy flag = 1) is emitted, matching the reference encoder.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = lzrw::GroupEncoder::new();

    let mut hash: [Option<usize>; HASH_TABLE_LEN] = [None; HASH_TABLE_LEN];
    let mut pending: Vec<usize> = Vec::with_capacity(3);

    let mut pos = 0usize;
    while pos < input.len() {
        if pos + MIN_MATCH <= input.len() {
            let h = lzrw::hash3(&input[pos..], 0xFFF);
            let len = match hash[h] {
                None => match_prefix(&input[pos..], lzrw::START_STRING_18),
                Some(c) => match_prefix(&input[pos..], &input[c..]),
            };
            if len >= MIN_MATCH {
                enc.copy(len - MIN_MATCH, h);
                for r in pending.drain(..) {
                    hash[lzrw::hash3(&input[r..], 0xFFF)] = Some(r);
                }
                hash[h] = Some(pos);
                pos += len;
            } else {
                enc.literal(input[pos]);
                pending.push(pos);
                pos += 1;
                if pending.len() == 3 {
                    let r = pending.remove(0);
                    hash[lzrw::hash3(&input[r..], 0xFFF)] = Some(r);
                }
            }
        } else {
            // Fewer than three bytes remain: literals only.
            enc.literal(input[pos]);
            pending.push(pos);
            pos += 1;
            if pending.len() == 3 {
                let r = pending.remove(0);
                hash[lzrw::hash3(&input[r..], 0xFFF)] = Some(r);
            }
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
    crate::compress::match_ops::match_len(a, b, MAX_MATCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(data: &[u8]) {
        let enc = encode(data);
        assert_eq!(decode(&enc).unwrap(), data);
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
    fn decode_start_string_reference() {
        // Any hash index is initially mapped to the constant string
        // "123456789012345678". A copy item as first item copies from it.
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x05, 0x9f]; // len 8 index 0x89f
        assert_eq!(decode(&input).unwrap(), b"12345678");
    }

    #[test]
    fn decode_copy_after_literals() {
        // items 0-2 literals "abc": on the third literal the position 0
        // is hashed under hash3("abc"). item 3 copy len 3 must use that
        // index. index for "abc" per hash3(&[b'a',b'b',b'c'],0xFFF).
        let idx = lzrw::hash3(b"abc", 0xFFF);
        let input = [
            0,
            0,
            0,
            0,
            0x08,
            0x00,
            b'a',
            b'b',
            b'c',
            (((idx >> 8) & 0x0f) << 4) as u8,
            (idx & 0xff) as u8,
        ];
        assert_eq!(decode(&input).unwrap(), b"abcabc");
    }

    #[test]
    fn decode_deferred_literal_hash() {
        // items 0-3 literals "abcd": after item 2, position 0 ("abc") is
        // hashed; after item 3, position 1 ("bcd") is hashed and
        // positions 2,3 stay pending. Item 4 copy len 3 under hash3("abc")
        // then resolves to position 0 and flushes the pending literals.
        let h_abc = lzrw::hash3(b"abc", 0xFFF);
        let input = [
            0,
            0,
            0,
            0,
            0x10,
            0x00,
            b'a',
            b'b',
            b'c',
            b'd',
            (((h_abc >> 8) & 0x0f) << 4) as u8,
            (h_abc & 0xff) as u8,
        ];
        assert_eq!(decode(&input).unwrap(), b"abcdabc");
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
        // Long literal runs followed by copies exercise the deferred
        // literal hashing in both directions.
        rt(b"0123456789abcdefg abcabcabc 0123456789abcdefg");
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
