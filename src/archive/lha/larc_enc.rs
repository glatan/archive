//! LArc `-lzs-` and `-lz5-` encoders — the encode mirror of `larc`.
//!
//! Both wirings copy from *absolute* decoder-ring positions, so the
//! encoder maps a match source at input index `src` to ring slot
//! `(w0 + src) % ring` where `w0` is the decoder's initial write
//! head. The parse is a greedy hash-chain search over at most `ring`
//! bytes of history; the decoder's initial ring fill (spaces / the
//! `-lz5-` pattern) is never referenced.
//!
//! `-lzs-` emits a MSB-first bit stream: a 1 bit + 8-bit literal, or
//! a 0 bit + 11-bit ring position + 4-bit length (+2, so 2..=17; only
//! lengths >= 3 are emitted). `-lz5-` is byte oriented: a control
//! byte whose set bits mark literal bytes and whose clear bits mark
//! 2-byte copy commands holding a 12-bit ring position and a 4-bit
//! length (+3, so 3..=18).

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzh::bits::MsbWriter;

/// Shortest match worth emitting (a copy command costs more than two
/// literals on both wirings).
const MIN_MATCH: usize = 3;
/// Hash table size for the 3-byte prefix index.
const HASH_SIZE: usize = 1 << 15;
/// Chain links followed per position.
const MAX_CHAIN: usize = 32;
/// Chain-list terminator.
const NIL: u32 = u32::MAX;

/// One LZ command: a literal byte, or a copy of `len` bytes read from
/// the decoder ring slot `ring_pos`.
enum Cmd {
    Lit(u8),
    Copy { len: usize, ring_pos: usize },
}

fn hash(b: &[u8]) -> usize {
    (b[0] as usize * 251 + b[1] as usize * 11 + b[2] as usize) & (HASH_SIZE - 1)
}

/// Greedy parse of `input` into literal/copy commands. `ring` is the
/// decoder ring size, `w0` the decoder's initial write head, and
/// `max_len` the longest encodable copy. Distances are capped at
/// `ring` so the named slot still holds the source byte when the copy
/// runs (at distance == `ring` the decoder reads the slot just before
/// overwriting it in the same copy step).
fn parse(input: &[u8], ring: usize, w0: usize, max_len: usize) -> Vec<Cmd> {
    let n = input.len();
    let mut head = vec![NIL; HASH_SIZE];
    let mut prev = vec![NIL; n];
    let mut cmds = Vec::new();
    let mut i = 0usize;
    while i < n {
        let max = (n - i).min(max_len);
        let mut best_len = 0usize;
        let mut best_src = 0usize;
        if max >= MIN_MATCH {
            let h = hash(&input[i..]);
            let mut cand = head[h];
            let mut links = 0;
            while cand != NIL && links < MAX_CHAIN {
                let c = cand as usize;
                // The chain is position-ordered: once a candidate is
                // out of range every later one is too.
                if i - c > ring {
                    break;
                }
                let mut l = 0usize;
                while l < max && input[c + l] == input[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_src = c;
                    if l >= max {
                        break;
                    }
                }
                cand = prev[c];
                links += 1;
            }
            prev[i] = head[h];
            head[h] = i as u32;
        }
        if best_len >= MIN_MATCH {
            cmds.push(Cmd::Copy {
                len: best_len,
                ring_pos: (w0 + best_src) % ring,
            });
            // Index the skipped positions so later matches can reach
            // them.
            let end = (i + best_len).min(n);
            for p in i + 1..end {
                if p + MIN_MATCH <= n {
                    let h = hash(&input[p..]);
                    prev[p] = head[h];
                    head[h] = p as u32;
                }
            }
            i += best_len;
        } else {
            cmds.push(Cmd::Lit(input[i]));
            i += 1;
        }
    }
    cmds
}

/// Encode `input` as a `-lzs-` stream (bit oriented, 2 KiB ring).
pub(crate) fn encode_lzs(input: &[u8]) -> Vec<u8> {
    const RING: usize = 2048;
    const W0: usize = RING - 17; // decoder starts 17 before the end
    const MAX_LEN: usize = 17; // 4-bit length field, +2
    let cmds = parse(input, RING, W0, MAX_LEN);
    let mut w = MsbWriter::new();
    for cmd in cmds {
        match cmd {
            Cmd::Lit(b) => {
                w.put(1, 1);
                w.put(u32::from(b), 8);
            }
            Cmd::Copy { len, ring_pos } => {
                w.put(0, 1);
                w.put(ring_pos as u32, 11);
                w.put((len - 2) as u32, 4);
            }
        }
    }
    w.finish()
}

/// Encode `input` as a `-lz5-` stream (control byte + data bytes,
/// 4 KiB ring).
pub(crate) fn encode_lz5(input: &[u8]) -> Vec<u8> {
    const RING: usize = 4096;
    const W0: usize = RING - 18; // decoder starts 18 before the end
    const MAX_LEN: usize = 18; // 4-bit length field, +3
    let cmds = parse(input, RING, W0, MAX_LEN);
    let mut out = Vec::new();
    for chunk in cmds.chunks(8) {
        let mut bitmap = 0u8;
        let mut body = Vec::with_capacity(16);
        for (bit, cmd) in chunk.iter().enumerate() {
            match cmd {
                Cmd::Lit(b) => {
                    bitmap |= 1 << bit;
                    body.push(*b);
                }
                Cmd::Copy { len, ring_pos } => {
                    // c[0] = position low byte; c[1] high nibble =
                    // position bits 8..11, low nibble = len - 3.
                    body.push((ring_pos & 0xff) as u8);
                    body.push((((ring_pos >> 8) << 4) | (len - 3)) as u8);
                }
            }
        }
        out.push(bitmap);
        out.extend_from_slice(&body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::lha::larc;

    /// Deterministic non-repeating bytes (xorshift32).
    fn noisy(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut s = 0x9e37_79b9u32;
        while v.len() < n {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            v.push((s >> 24) as u8);
        }
        v
    }

    #[test]
    fn lzs_encode_roundtrip() {
        for data in [
            b"the quick brown fox jumps over the lazy dog. ".repeat(500),
            b"a".repeat(3000), // long run -> max-length copies
            noisy(5000),       // literal-only path
            Vec::new(),        // empty
            b"ab".to_vec(),    // shorter than a copy command
            b"abcabcabcabcabcabc".to_vec(),
        ] {
            let packed = encode_lzs(&data);
            let out = larc::decode(b"-lzs-", &packed, data.len()).unwrap();
            assert_eq!(out, data);
        }
        // Compressible input must actually shrink.
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(500);
        assert!(encode_lzs(&data).len() < data.len());
    }

    #[test]
    fn lz5_encode_roundtrip() {
        for data in [
            b"the quick brown fox jumps over the lazy dog. ".repeat(500),
            vec![7u8; 5000], // long run -> max-length copies
            noisy(5000),
            Vec::new(),
            b"ab".to_vec(),
            b"abcabcabcabcabcabc".to_vec(),
        ] {
            let packed = encode_lz5(&data);
            let out = larc::decode(b"-lz5-", &packed, data.len()).unwrap();
            assert_eq!(out, data);
        }
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(500);
        assert!(encode_lz5(&data).len() < data.len());
    }

    #[test]
    fn wraps_across_ring_boundary() {
        // Inputs larger than the ring force positions to wrap.
        for n in [2050usize, 4097, 9000] {
            let mut data = Vec::with_capacity(n);
            while data.len() < n {
                data.extend_from_slice(b"0123456789abcdef");
            }
            data.truncate(n);
            let out = larc::decode(b"-lzs-", &encode_lzs(&data), n).unwrap();
            assert_eq!(out, data);
            let out = larc::decode(b"-lz5-", &encode_lz5(&data), n).unwrap();
            assert_eq!(out, data);
        }
    }
}
