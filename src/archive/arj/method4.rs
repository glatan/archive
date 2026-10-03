//! ARJ method 4 ("fastest") codec: an LZSS sliding window over a
//! 32 KiB (0x8000) ring, fed by an MSB-first bit stream of
//! literal/match tokens. There is no end marker — decoding stops once
//! the expected byte count has been produced.
//!
//! Token format: a length/literal prefix of up to 7 leading one-bits
//! (each contributes 1 << k) followed by that many suffix bits; a
//! value of 0 selects a literal (next 8 bits). Otherwise a match
//! follows: an offset prefix of up to 4 leading one-bits over an
//! exponent base of 9 (each contributes 1 << (9 + k)) plus
//! 9 + k suffix bits; distance = offset + 1, length = value + 2.
//!
//! The encoder is a greedy hash-chain matcher: it produces valid
//! streams but does not attempt optimal parsing.
//!
//! Decoder ported from the newtua_dos transliteration of XADMaster's
//! XADARJFastestHandle (LGPL-3.0-or-later).
//!
//! Licensing: incorporated under LGPL-3.0 section 2 (GPL-3.0) and
//! combined with this AGPL-3.0 work via AGPL-3.0 section 13.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzh::bits::{MsbReader, MsbWriter};
use crate::error::Error;

/// Decode a method-4 payload to the expected byte count.
pub(crate) fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 0x8000;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    if expected == 0 {
        return Ok(out);
    }
    let mut ring = vec![b' '; N];
    let mut w = 0usize;
    let mut r = MsbReader::new(input);

    while out.len() < expected {
        // Length/literal prefix: up to 7 one-bits, then pow suffix bits.
        let mut val = 0u32;
        let mut pow = 0u32;
        while pow < 7 && r.get(1) != 0 {
            val += 1 << pow;
            pow += 1;
        }
        if pow > 0 {
            val += r.get(pow);
        }
        if r.overran() {
            return Err(Error::InvalidData("arj: truncated method 4 stream"));
        }

        if val == 0 {
            let b = r.get(8) as u8;
            if r.overran() {
                return Err(Error::InvalidData("arj: truncated method 4 stream"));
            }
            out.push(b);
            ring[w] = b;
            w = (w + 1) & (N - 1);
        } else {
            // Offset prefix: up to 4 one-bits over an exponent base of 9.
            let mut offs = 0u32;
            let mut pow = 9u32;
            while pow < 13 && r.get(1) != 0 {
                offs += 1 << pow;
                pow += 1;
            }
            offs += r.get(pow);
            if r.overran() {
                return Err(Error::InvalidData("arj: truncated method 4 stream"));
            }
            let dist = (offs + 1) as usize;
            let len = (val + 2) as usize;
            if dist > N {
                return Err(Error::InvalidData("arj: method 4 distance out of window"));
            }
            let mut src = (w + N - dist) & (N - 1);
            for _ in 0..len {
                if out.len() >= expected {
                    break;
                }
                let v = ring[src];
                out.push(v);
                ring[w] = v;
                w = (w + 1) & (N - 1);
                src = (src + 1) & (N - 1);
            }
        }
    }
    Ok(out)
}

/// Smallest match length (a zero length value encodes a literal).
const MIN_MATCH: usize = 3;
/// Longest match: the length value caps at 127 + 127, plus 2.
const MAX_MATCH: usize = 256;
/// Longest encodable distance: (512 * 15) + 8191, plus 1.
const MAX_DIST: usize = 15872;
/// Hash-chain probes per position before taking the best match found.
const CHAIN_LIMIT: usize = 64;
/// Hash table width over 3-byte sequences.
const HASH_BITS: u32 = 15;

/// Emit a literal token: a zero bit plus the raw byte.
fn put_lit(b: u8, w: &mut MsbWriter) {
    w.put(0, 1);
    w.put(u32::from(b), 8);
}

/// Emit a match token: the exponent-coded length prefix (value
/// len - 2) and offset prefix (value dist - 1), mirroring the
/// decoder's prefix loops.
fn put_match(len: usize, dist: usize, w: &mut MsbWriter) {
    debug_assert!((MIN_MATCH..=MAX_MATCH).contains(&len));
    debug_assert!((1..=MAX_DIST).contains(&dist));
    let val = (len - 2) as u32;
    let mut k = 0u32;
    while k < 7 && (1u32 << (k + 1)) - 1 <= val {
        k += 1;
    }
    for _ in 0..k {
        w.put(1, 1);
    }
    if k < 7 {
        w.put(0, 1);
    }
    if k > 0 {
        w.put(val - ((1u32 << k) - 1), k);
    }
    let v = (dist - 1) as u32;
    let mut m = 0u32;
    while m < 4 && v >= 512 * ((1u32 << (m + 1)) - 1) {
        m += 1;
    }
    for _ in 0..m {
        w.put(1, 1);
    }
    if m < 4 {
        w.put(0, 1);
    }
    w.put(v - 512 * ((1u32 << m) - 1), 9 + m);
}

/// Multiplicative hash of the next three bytes.
fn hash3(b: &[u8]) -> usize {
    let v = u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16;
    (v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

/// Shared prefix length of data[a..] and data[b..], capped at max.
fn match_len(data: &[u8], a: usize, b: usize, max: usize) -> usize {
    let mut l = 0;
    while l < max && data[a + l] == data[b + l] {
        l += 1;
    }
    l
}

/// Compress the input into a method-4 stream.
///
/// Greedy hash-chain matcher over a 15-bit hash of 3-byte sequences,
/// probing up to CHAIN_LIMIT candidates per position. The output is a
/// valid stream the decoder round-trips, but is not size-optimal.
pub(crate) fn encode(data: &[u8]) -> Vec<u8> {
    let mut head = vec![usize::MAX; 1 << HASH_BITS];
    let mut prev = vec![usize::MAX; data.len()];
    let mut w = MsbWriter::new();
    let mut i = 0usize;
    while i < data.len() {
        let max_len = MAX_MATCH.min(data.len() - i);
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if max_len >= MIN_MATCH {
            let mut cand = head[hash3(&data[i..i + MIN_MATCH])];
            let mut budget = CHAIN_LIMIT;
            while cand != usize::MAX && budget > 0 {
                budget -= 1;
                let dist = i - cand;
                if dist > MAX_DIST {
                    break;
                }
                let l = match_len(data, cand, i, max_len);
                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if l == max_len {
                        break;
                    }
                }
                cand = prev[cand];
            }
        }
        let next = if best_len >= MIN_MATCH {
            put_match(best_len, best_dist, &mut w);
            i + best_len
        } else {
            put_lit(data[i], &mut w);
            i + 1
        };
        while i < next {
            if i + MIN_MATCH <= data.len() {
                let h = hash3(&data[i..i + MIN_MATCH]);
                prev[i] = head[h];
                head[h] = i;
            }
            i += 1;
        }
    }
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_only() {
        let mut w = MsbWriter::new();
        for &b in b"arj!" {
            put_lit(b, &mut w);
        }
        assert_eq!(decode(&w.finish(), 4).unwrap(), b"arj!");
    }

    #[test]
    fn match_copies() {
        let mut w = MsbWriter::new();
        for &b in b"abcd" {
            put_lit(b, &mut w);
        }
        put_match(5, 4, &mut w); // copy "abcda"
        put_match(3, 1, &mut w); // overlapping run
        let out = decode(&w.finish(), 12).unwrap();
        assert_eq!(&out[..4], b"abcd");
        assert_eq!(&out[4..9], b"abcda");
        assert_eq!(&out[9..12], b"aaa");
    }

    #[test]
    fn rejects_truncated() {
        let mut w = MsbWriter::new();
        put_lit(b'x', &mut w);
        let payload = w.finish();
        assert!(decode(&payload[..1], 4).is_err());
        assert!(decode(&[], 1).is_err());
    }

    #[test]
    fn encode_roundtrip() {
        // Compressible mix of literals and matches.
        let mut data = Vec::new();
        for i in 0..300u32 {
            data.extend_from_slice(b"the quick brown fox jumps over ");
            data.extend_from_slice(&i.to_le_bytes());
        }
        let packed = encode(&data);
        assert!(packed.len() < data.len());
        assert_eq!(decode(&packed, data.len()).unwrap(), data);
    }

    #[test]
    fn encode_edge_cases() {
        assert!(encode(b"").is_empty());
        assert_eq!(decode(&encode(b"ab"), 2).unwrap(), b"ab");
        assert_eq!(decode(&encode(b"aaa"), 3).unwrap(), b"aaa");
        // A long run exercises maximum-length matches.
        let run = vec![0x55u8; 10_000];
        assert_eq!(decode(&encode(&run), run.len()).unwrap(), run);
        // A far match exercises the widest offset prefix.
        let mut far: Vec<u8> = (0u32..12_000)
            .map(|i| (i.wrapping_mul(0x9E37_79B1) >> 16) as u8)
            .collect();
        let copy = far[..200].to_vec();
        far.extend_from_slice(&copy);
        assert_eq!(decode(&encode(&far), far.len()).unwrap(), far);
    }
}
