//! Burrows-Wheeler Transform (BWT) and its inverse.
//!
//! The forward transform sorts the cyclic rotations of the block. The sort is
//! the induced-sorting suffix array (SA-IS) of the block written twice and
//! terminated by a unique smallest sentinel. Equal rotations keep the smaller
//! start index.

use alloc::vec;
use alloc::vec::Vec;

const EMPTY: u32 = u32::MAX;

/// Perform the forward BWT.
///
/// Returns `(transformed, original_pointer)` where `original_pointer` is the
/// index in the sorted rotation matrix corresponding to the original string.
pub(crate) fn forward_bwt(data: &[u8]) -> (Vec<u8>, u32) {
    let n = data.len();
    if n == 0 {
        return (Vec::new(), 0);
    }
    if n == 1 {
        return (vec![data[0]], 0);
    }

    // Doubling makes each rotation a length-n prefix of a linear suffix.
    // The sentinel is the smallest symbol, so among identical rotations the
    // larger start index sorts first. Those runs are reversed below.
    let mut text = Vec::with_capacity(2 * n + 1);
    text.extend(data.iter().map(|&b| u32::from(b) + 1));
    text.extend(data.iter().map(|&b| u32::from(b) + 1));
    text.push(0);
    let mut sa = vec![EMPTY; text.len()];
    sais(&text, &mut sa);

    let mut order = Vec::with_capacity(n);
    for &pos in &sa {
        if (pos as usize) < n {
            order.push(pos);
        }
    }
    debug_assert_eq!(order.len(), n);

    let period = minimal_period(data);
    if period < n {
        let mut i = 0;
        while i < order.len() {
            let mut j = i + 1;
            while j < order.len() && order[j].abs_diff(order[j - 1]) % (period as u32) == 0 {
                j += 1;
            }
            order[i..j].reverse();
            i = j;
        }
    }

    let mut result = vec![0u8; n];
    let mut original_ptr = 0u32;
    for (i, &start) in order.iter().enumerate() {
        if start == 0 {
            original_ptr = i as u32;
            result[i] = data[n - 1];
        } else {
            result[i] = data[start as usize - 1];
        }
    }
    (result, original_ptr)
}

/// Smallest `p` in `1..data.len()` such that `data` has cyclic period `p`.
///
/// Returns `data.len()` when every rotation is distinct.
fn minimal_period(data: &[u8]) -> usize {
    let n = data.len();
    let mut doubled = Vec::with_capacity(n * 2);
    doubled.extend_from_slice(data);
    doubled.extend_from_slice(data);
    let m = doubled.len();
    let mut zeta = vec![0usize; m];
    let mut left = 0usize;
    let mut right = 0usize;
    for i in 1..m {
        if i < right {
            zeta[i] = zeta[i - left].min(right - i);
        }
        while i + zeta[i] < m && doubled[zeta[i]] == doubled[i + zeta[i]] {
            zeta[i] += 1;
        }
        if i + zeta[i] > right {
            left = i;
            right = i + zeta[i];
        }
        if i < n && zeta[i] >= n {
            return i;
        }
    }
    n
}

/// Suffix array of `s` by induced sorting.
///
/// `s` ends with a unique smallest sentinel. `Nong, Zhang, Chan` classify
/// each suffix as L-type or S-type, sort the LMS suffixes by the same
/// procedure on a shorter string, then induce the rest from those.
fn sais(s: &[u32], sa: &mut [u32]) {
    let n = s.len();
    if n == 1 {
        sa[0] = 0;
        return;
    }

    let mut is_s = vec![false; n];
    is_s[n - 1] = true;
    for i in (0..n - 1).rev() {
        is_s[i] = if s[i] == s[i + 1] {
            is_s[i + 1]
        } else {
            s[i] < s[i + 1]
        };
    }

    let alphabet = s.iter().copied().max().unwrap_or(0) as usize + 1;
    let mut freq = vec![0usize; alphabet];
    for &c in s {
        freq[c as usize] += 1;
    }
    let bucket_end = bucket_ends(&freq);

    sa.fill(EMPTY);
    let mut tail = bucket_end.clone();
    for (i, &symbol) in s.iter().enumerate().skip(1) {
        if is_lms_at(&is_s, i) {
            let c = symbol as usize;
            tail[c] -= 1;
            sa[tail[c]] = i as u32;
        }
    }
    induce(s, sa, &is_s, &freq);

    let mut lms_sorted = Vec::new();
    for &pos in sa.iter() {
        if pos != EMPTY && is_lms_at(&is_s, pos as usize) {
            lms_sorted.push(pos);
        }
    }
    let lms_count = lms_sorted.len();

    let mut name_of = vec![EMPTY; n];
    let mut names = 0u32;
    if let Some(&first) = lms_sorted.first() {
        name_of[first as usize] = 0;
        let mut prev = first as usize;
        for &cur_u in lms_sorted.iter().skip(1) {
            let cur = cur_u as usize;
            if !lms_substr_eq(s, &is_s, prev, cur) {
                names += 1;
            }
            name_of[cur] = names;
            prev = cur;
        }
        names += 1;
    }

    let mut lms_pos = Vec::with_capacity(lms_count);
    for i in 1..n {
        if is_lms_at(&is_s, i) {
            lms_pos.push(i as u32);
        }
    }

    if names as usize != lms_count {
        let mut reduced = vec![0u32; lms_count];
        for (i, &pos) in lms_pos.iter().enumerate() {
            reduced[i] = name_of[pos as usize];
        }
        let mut reduced_sa = vec![EMPTY; lms_count];
        sais(&reduced, &mut reduced_sa);
        for (slot, &rank) in lms_sorted.iter_mut().zip(reduced_sa.iter()) {
            *slot = lms_pos[rank as usize];
        }
    }

    sa.fill(EMPTY);
    let mut tail = bucket_end;
    for &pos in lms_sorted.iter().rev() {
        let c = s[pos as usize] as usize;
        tail[c] -= 1;
        sa[tail[c]] = pos;
    }
    induce(s, sa, &is_s, &freq);
}

fn is_lms_at(is_s: &[bool], i: usize) -> bool {
    i > 0 && is_s[i] && !is_s[i - 1]
}

fn bucket_ends(freq: &[usize]) -> Vec<usize> {
    let mut ends = vec![0usize; freq.len()];
    let mut sum = 0usize;
    for (c, &count) in freq.iter().enumerate() {
        sum += count;
        ends[c] = sum;
    }
    ends
}

fn induce(s: &[u32], sa: &mut [u32], is_s: &[bool], freq: &[usize]) {
    let n = s.len();
    let mut head = vec![0usize; freq.len()];
    let mut sum = 0usize;
    for (c, &count) in freq.iter().enumerate() {
        head[c] = sum;
        sum += count;
    }
    for i in 0..n {
        let pos = sa[i];
        if pos == EMPTY || pos == 0 {
            continue;
        }
        let prev = pos as usize - 1;
        if !is_s[prev] {
            let c = s[prev] as usize;
            sa[head[c]] = prev as u32;
            head[c] += 1;
        }
    }

    let tail = bucket_ends(freq);
    let mut cursor = tail;
    for i in (0..n).rev() {
        let pos = sa[i];
        if pos == EMPTY || pos == 0 {
            continue;
        }
        let prev = pos as usize - 1;
        if is_s[prev] {
            let c = s[prev] as usize;
            cursor[c] -= 1;
            sa[cursor[c]] = prev as u32;
        }
    }
}

/// LMS substrings are equal when the bytes from one LMS index through the
/// next LMS index match, including both endpoints.
fn lms_substr_eq(s: &[u32], is_s: &[bool], a: usize, b: usize) -> bool {
    if s[a] != s[b] {
        return false;
    }
    let mut i = a;
    let mut j = b;
    loop {
        i += 1;
        j += 1;
        let i_end = i >= s.len();
        let j_end = j >= s.len();
        if i_end || j_end {
            return i_end && j_end;
        }
        if s[i] != s[j] {
            return false;
        }
        let i_lms = is_lms_at(is_s, i);
        let j_lms = is_lms_at(is_s, j);
        if i_lms && j_lms {
            return true;
        }
        if i_lms != j_lms {
            return false;
        }
    }
}

/// Perform the inverse BWT.
///
/// Given the BWT output and the original pointer, reconstruct the original data.
pub(crate) fn inverse_bwt(bwt: &[u8], original_ptr: u32) -> Vec<u8> {
    let n = bwt.len();
    if n == 0 {
        return Vec::new();
    }

    // Count frequencies
    let mut count = [0u32; 256];
    for &b in bwt {
        count[b as usize] += 1;
    }

    // Cumulative counts
    let mut cumul = [0u32; 256];
    let mut sum = 0u32;
    for i in 0..256 {
        cumul[i] = sum;
        sum += count[i];
    }

    // Build LF-mapping (T-transform)
    let mut lf = vec![0u32; n];
    let mut running = cumul;
    for (i, &b) in bwt.iter().enumerate() {
        lf[i] = running[b as usize];
        running[b as usize] += 1;
    }

    // Follow the chain
    let mut result = vec![0u8; n];
    let mut idx = original_ptr as usize;
    for i in (0..n).rev() {
        result[i] = bwt[idx];
        idx = lf[idx] as usize;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_empty() {
        let (bwt, ptr) = forward_bwt(b"");
        assert!(bwt.is_empty());
        let orig = inverse_bwt(&bwt, ptr);
        assert!(orig.is_empty());
    }

    #[test]
    fn test_roundtrip_single() {
        let (bwt, ptr) = forward_bwt(b"a");
        assert_eq!(bwt, b"a");
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, b"a");
    }

    #[test]
    fn test_roundtrip_banana() {
        let input = b"banana";
        let (bwt, ptr) = forward_bwt(input);
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, input);
    }

    #[test]
    fn test_roundtrip_all_same() {
        let input = b"aaaaaaa";
        let (bwt, ptr) = forward_bwt(input);
        assert_eq!(bwt, b"aaaaaaa");
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, input);
    }

    #[test]
    fn test_roundtrip_hello() {
        let input = b"hello world";
        let (bwt, ptr) = forward_bwt(input);
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, input);
    }

    #[test]
    fn test_roundtrip_repeated_pattern() {
        let input = b"abcabcabcabc";
        let (bwt, ptr) = forward_bwt(input);
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, input);
    }

    #[test]
    fn test_roundtrip_all_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        let (bwt, ptr) = forward_bwt(&input);
        let orig = inverse_bwt(&bwt, ptr);
        assert_eq!(orig, input);
    }

    fn bwt_sum(bwt: &[u8]) -> u64 {
        let mut sum = 0u64;
        for (i, &byte) in bwt.iter().enumerate() {
            sum = sum
                .wrapping_mul(131)
                .wrapping_add(u64::from(byte))
                .wrapping_add(i as u64);
        }
        sum
    }

    fn lcg_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    #[test]
    fn test_bwt_banana_vector() {
        let (bwt, ptr) = forward_bwt(b"banana");
        assert_eq!(ptr, 3);
        assert_eq!(bwt, b"nnbaaa");
    }

    #[test]
    fn test_bwt_hello_vector() {
        let (bwt, ptr) = forward_bwt(b"hello world");
        assert_eq!(ptr, 3);
        assert_eq!(bwt, b"olhdrellwo ");
    }

    #[test]
    fn test_bwt_repeated_abc_vector() {
        let (bwt, ptr) = forward_bwt(b"abcabcabcabc");
        assert_eq!(ptr, 0);
        assert_eq!(bwt, b"ccccaaaabbbb");
    }

    #[test]
    fn test_bwt_all_same_pointer() {
        let (bwt, ptr) = forward_bwt(b"aaaaaaa");
        assert_eq!(ptr, 0);
        assert_eq!(bwt, b"aaaaaaa");

        let (bwt, ptr) = forward_bwt(&[0xA5; 4096]);
        assert_eq!(ptr, 0);
        assert!(bwt.iter().all(|&byte| byte == 0xA5));
        assert_eq!(bwt_sum(&bwt), 6_974_107_980_074_706_944);
    }

    #[test]
    fn test_bwt_lcg32_vector() {
        let (bwt, ptr) = forward_bwt(&lcg_bytes(32));
        assert_eq!(ptr, 12);
        assert_eq!(
            bwt,
            [
                0x8d, 0x81, 0xcd, 0x43, 0x67, 0x25, 0x6e, 0x99, 0x20, 0xb2, 0x54, 0xcc, 0xdb, 0x73,
                0x76, 0xa6, 0x4b, 0x99, 0xe2, 0x75, 0xf2, 0x1e, 0x34, 0xf1, 0x75, 0xab, 0xce, 0x4b,
                0x84, 0xe2, 0x7f, 0xea,
            ]
        );
    }

    #[test]
    fn test_bwt_lcg1024() {
        let input = lcg_bytes(1024);
        let (bwt, ptr) = forward_bwt(&input);
        assert_eq!(ptr, 476);
        assert_eq!(bwt_sum(&bwt), 602_706_271_351_461_935);
        assert_eq!(inverse_bwt(&bwt, ptr), input);
    }

    #[test]
    fn test_bwt_long_repeat() {
        let input: Vec<u8> = b"abcd".iter().copied().cycle().take(100_000).collect();
        let (bwt, ptr) = forward_bwt(&input);
        assert_eq!(ptr, 0);
        assert_eq!(bwt_sum(&bwt), 1_464_676_845_024_789_360);
        assert_eq!(inverse_bwt(&bwt, ptr), input);
    }
}
