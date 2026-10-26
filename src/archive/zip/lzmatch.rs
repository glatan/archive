//! Shared greedy LZ77 matcher for the legacy ZIP codecs (Reduce, Implode).
//!
//! A token is either a literal byte (`dist == 0`) or a back reference
//! (`dist`, `len`). Matches never self-overlap (`len <= dist`), mirroring the
//! reference implementation (hwzip, public domain).

use alloc::vec;
use alloc::vec::Vec;

/// Knuth's multiplicative hash constant.
const HASH_MUL: u32 = 2_654_435_761;
/// Hash table size for the 3-byte hash chains.
const HASH_SIZE: usize = 1 << 15;
/// Maximum number of chain candidates examined per position.
const CHAIN_DEPTH: usize = 64;

/// An LZ77 token: `dist == 0` encodes a literal in `litlen`; otherwise
/// `litlen` is the match length.
#[derive(Clone, Copy)]
pub(super) struct Token {
    pub dist: u16,
    pub litlen: u16,
}

/// Greedy LZ77 parse of `input` honouring the given distance and length
/// bounds. When `allow_overlap` is false, match lengths are truncated so
/// that `len <= dist`.
pub(super) fn lz_match(
    input: &[u8],
    max_dist: usize,
    max_len: usize,
    min_len: usize,
    allow_overlap: bool,
) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut head = vec![usize::MAX; HASH_SIZE];
    let mut prev_pos = vec![usize::MAX; input.len().max(1)];

    let hash = |data: &[u8], i: usize| -> usize {
        let v = (data[i] as u32) | ((data[i + 1] as u32) << 8) | ((data[i + 2] as u32) << 16);
        (v.wrapping_mul(HASH_MUL) >> 17) as usize
    };

    let mut i = 0usize;
    while i < input.len() {
        let remaining = input.len() - i;
        if remaining >= min_len && remaining >= 3 {
            let h = hash(input, i);
            let mut best_len = 0usize;
            let mut best_dist = 0usize;
            let mut cand = head[h];
            let mut steps = 0;
            while cand != usize::MAX && steps < CHAIN_DEPTH {
                let dist = i - cand;
                if dist > max_dist {
                    break;
                }
                let limit = max_len.min(remaining);
                let mut l = 0usize;
                while l < limit && input[cand + l] == input[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if l >= limit {
                        break;
                    }
                }
                cand = prev_pos[cand];
                steps += 1;
            }
            if !allow_overlap && best_len > best_dist {
                best_len = best_dist;
            }
            if best_len >= min_len {
                tokens.push(Token {
                    dist: best_dist as u16,
                    litlen: best_len as u16,
                });
                for (off, slot) in prev_pos[i..i + best_len].iter_mut().enumerate() {
                    let j = i + off;
                    if j + 3 <= input.len() {
                        let hh = hash(input, j);
                        *slot = head[hh];
                        head[hh] = j;
                    }
                }
                i += best_len;
                continue;
            }
        }
        tokens.push(Token {
            dist: 0,
            litlen: input[i] as u16,
        });
        if i + 3 <= input.len() {
            let h = hash(input, i);
            prev_pos[i] = head[h];
            head[h] = i;
        }
        i += 1;
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reconstruct(input: &[u8], tokens: &[Token]) -> Vec<u8> {
        let mut out = Vec::new();
        for token in tokens {
            if token.dist == 0 {
                out.push(token.litlen as u8);
            } else {
                let dist = usize::from(token.dist);
                let len = usize::from(token.litlen);
                assert!(dist <= out.len(), "distance before output start");
                for _ in 0..len {
                    let byte = out[out.len() - dist];
                    out.push(byte);
                }
            }
        }
        assert_eq!(out, input, "token stream must reconstruct the input");
        out
    }

    #[test]
    fn empty_and_short_inputs_are_literals() {
        assert!(lz_match(b"", 256, 16, 3, false).is_empty());

        let tokens = lz_match(b"ab", 256, 16, 3, false);
        assert_eq!(tokens.len(), 2);
        assert!(tokens.iter().all(|token| token.dist == 0));
        reconstruct(b"ab", &tokens);
    }

    #[test]
    fn overlap_setting_caps_match_length() {
        let input = b"abc".repeat(100);
        let no_overlap = lz_match(&input, 4096, 256, 3, false);
        assert!(no_overlap.iter().all(|token| {
            token.dist == 0 || usize::from(token.litlen) <= usize::from(token.dist)
        }));
        assert!(no_overlap.iter().any(|token| token.dist != 0));
        reconstruct(&input, &no_overlap);

        let overlap = lz_match(&input, 4096, 256, 3, true);
        assert!(overlap.iter().any(|token| {
            token.dist != 0 && usize::from(token.litlen) > usize::from(token.dist)
        }));
        reconstruct(&input, &overlap);
    }

    #[test]
    fn bounded_tokens_reconstruct_mixed_inputs() {
        let mut input = Vec::new();
        for i in 0..4096u32 {
            input.push((i.wrapping_mul(37) % 251) as u8);
        }
        input.extend_from_slice(b"the quick brown fox the quick brown fox");
        input.extend(std::iter::repeat_n(0u8, 1024));

        for (max_dist, max_len, min_len, allow_overlap) in [
            (64, 8, 3, false),
            (256, 32, 3, true),
            (4096, 258, 3, false),
            (4096, 258, 16, true),
        ] {
            let tokens = lz_match(&input, max_dist, max_len, min_len, allow_overlap);
            reconstruct(&input, &tokens);
            for token in tokens {
                if token.dist != 0 {
                    let len = usize::from(token.litlen);
                    assert!(len <= max_len);
                    assert!(usize::from(token.dist) <= max_dist);
                    if !allow_overlap {
                        assert!(len <= usize::from(token.dist));
                    }
                }
            }
        }
    }
}
