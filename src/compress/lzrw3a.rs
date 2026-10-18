//! LZRW3-A compression (Ross Williams, public domain format).
//!
//! LZRW3-A is LZRW3 with a "deep" hash table: instead of 4096 single
//! entries, the table holds 512 partitions of 8 entries each (the
//! canonical LZRW3-A depth). A copy item `C1 C2` still carries
//! length = `(C1 & 0x0f) + 3` (3..=18) and an absolute table index
//! `(C1 >> 4) * 256 + C2` (0..=4095) naming one entry inside one
//! partition.
//!
//! Updates within a partition are steered by a single `cycle` counter
//! shared by all partitions and maintained in lockstep by compressor and
//! decompressor: each table update writes `partition_base + cycle` and
//! advances `cycle` modulo the depth. Literal positions are hashed lazily
//! exactly as in LZRW3 (the oldest pending literal is hashed once three
//! consecutive literal bytes exist; remaining pending literals flush on
//! the next copy item). All entries initially point at an 18-byte
//! constant string.

use alloc::vec::Vec;

use crate::compress::lzrw;
use crate::error::Error;

const MIN_MATCH: usize = 3;
const MAX_MATCH: usize = 18;
const HASH_TABLE_LEN: usize = 4096;
const DEPTH_BITS: usize = 3;
const DEPTH: usize = 1 << DEPTH_BITS;
const PARTITION_MASK: u32 = (1 << (12 - DEPTH_BITS)) - 1; // 0x1FF

const FLAG_ERRS: lzrw::FlagErrs = lzrw::FlagErrs {
    truncated_flag: "lzrw3a: truncated copy flag",
    unknown_flag: "lzrw3a: unknown copy flag",
};

/// Base index of the partition selected for the three bytes at `b`.
fn partition(b: &[u8]) -> usize {
    lzrw::hash3(b, PARTITION_MASK) << DEPTH_BITS
}

/// Decode an LZRW3-A stream.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode an LZRW3-A stream with an output size limit.
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
    // hash[i] = output position recorded in table entry i (`None` marks
    // the initial constant-string entries).
    let mut hash: [Option<usize>; HASH_TABLE_LEN] = [None; HASH_TABLE_LEN];
    let mut cycle = 0usize;
    let mut pending: Vec<usize> = Vec::with_capacity(3);

    let update =
        |hash: &mut [Option<usize>; HASH_TABLE_LEN], cycle: &mut usize, base: usize, pos: usize| {
            hash[base + *cycle] = Some(pos);
            *cycle = (*cycle + 1) & (DEPTH - 1);
        };

    let mut items = lzrw::Items::new(input, MIN_MATCH, "lzrw3a: truncated copy item");
    while let Some(item) = items.next()? {
        match item {
            lzrw::Item::Literal(b) => {
                if out.len() == max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                pending.push(out.len());
                out.push(b);
                if pending.len() == 3 {
                    let r = pending.remove(0);
                    update(&mut hash, &mut cycle, partition(&out[r..r + 3]), r);
                }
            }
            lzrw::Item::Copy { len, index } => {
                let ziv = out.len();
                let source = hash[index];
                if ziv + len > max_output {
                    return Err(Error::OutputLimitExceeded { limit: max_output });
                }
                match source {
                    Some(pos) => lzrw::copy_from_output(&mut out, pos, len),
                    None => out.extend_from_slice(&lzrw::START_STRING_18[..len]),
                }
                for r in pending.drain(..) {
                    let base = partition(&out[r..r + 3]);
                    update(&mut hash, &mut cycle, base, r);
                }
                update(&mut hash, &mut cycle, index & !(DEPTH - 1), ziv);
            }
        }
    }
    Ok(out)
}

/// Encode data as an LZRW3-A stream.
///
/// The encoder searches all eight entries of the target partition and
/// transmits the absolute index of the best match; table updates then
/// replicate the decompressor's discipline (including the shared `cycle`
/// counter) so both sides stay in lockstep. If compression does not
/// reduce the size, the verbatim-copy form (copy flag = 1) is emitted.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut enc = lzrw::GroupEncoder::new();

    let mut hash: [Option<usize>; HASH_TABLE_LEN] = [None; HASH_TABLE_LEN];
    let mut cycle = 0usize;
    let mut pending: Vec<usize> = Vec::with_capacity(3);

    macro_rules! update {
        ($base:expr, $pos:expr) => {{
            hash[$base + cycle] = Some($pos);
            cycle = (cycle + 1) & (DEPTH - 1);
        }};
    }

    let mut pos = 0usize;
    while pos < input.len() {
        if pos + MIN_MATCH <= input.len() {
            let base = partition(&input[pos..]);
            let mut best_len = 0usize;
            let mut best_slot = 0usize;
            for slot in 0..DEPTH {
                let len = match hash[base + slot] {
                    None => match_prefix(&input[pos..], lzrw::START_STRING_18),
                    Some(c) => match_prefix(&input[pos..], &input[c..]),
                };
                if len > best_len {
                    best_len = len;
                    best_slot = slot;
                }
            }
            if best_len >= MIN_MATCH {
                let index = base + best_slot;
                enc.copy(best_len - MIN_MATCH, index);
                for r in pending.drain(..) {
                    update!(partition(&input[r..]), r);
                }
                update!(index & !(DEPTH - 1), pos);
                pos += best_len;
            } else {
                enc.literal(input[pos]);
                pending.push(pos);
                pos += 1;
                if pending.len() == 3 {
                    let r = pending.remove(0);
                    update!(partition(&input[r..]), r);
                }
            }
        } else {
            enc.literal(input[pos]);
            pending.push(pos);
            pos += 1;
            if pending.len() == 3 {
                let r = pending.remove(0);
                update!(partition(&input[r..]), r);
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
        // Any absolute index initially maps to the constant string
        // "123456789012345678".
        let input = [0, 0, 0, 0, 0x01, 0x00, 0x05, 0x9f]; // len 8 index 0x89f
        assert_eq!(decode(&input).unwrap(), b"12345678");
    }

    #[test]
    fn decode_copy_after_literals() {
        // items 0-2 literals "abc": after the third literal, position 0
        // is written into partition hash3("abc") at slot `cycle` (=0).
        // The copy must therefore use index = partition*8 + 0.
        let base = partition(b"abc");
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
            (((base >> 8) & 0x0f) << 4) as u8,
            (base & 0xff) as u8,
        ];
        assert_eq!(decode(&input).unwrap(), b"abcabc");
    }

    #[test]
    fn decode_cycle_advances() {
        // items 0-5 literals "abcdef": literal updates land in slots
        // cycle 0 and 1 of partitions hash3("abc") and hash3("bcd").
        // item 6 copy uses base of "abc" partition, slot 0 -> pos 0.
        let base = partition(b"abc");
        let input = [
            0,
            0,
            0,
            0,
            0x40,
            0x00,
            b'a',
            b'b',
            b'c',
            b'd',
            b'e',
            b'f',
            (((base >> 8) & 0x0f) << 4) as u8,
            (base & 0xff) as u8,
        ];
        assert_eq!(decode(&input).unwrap(), b"abcdefabc");
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
