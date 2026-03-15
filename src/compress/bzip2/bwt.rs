//! Burrows-Wheeler Transform (BWT) and its inverse.

use alloc::vec;
use alloc::vec::Vec;

/// Perform the forward BWT.
///
/// Returns `(transformed, original_pointer)` where `original_pointer` is the
/// index in the sorted rotation matrix corresponding to the original string.
pub(crate) fn forward_bwt(data: &[u8]) -> (Vec<u8>, u32) {
    let n = data.len();
    if n == 0 {
        return (Vec::new(), 0);
    }

    // Build suffix array using prefix-doubling.
    let mut sa: Vec<u32> = (0..n as u32).collect();
    let mut rank = vec![0i32; n];
    let mut tmp = vec![0i32; n];

    for (i, &b) in data.iter().enumerate() {
        rank[i] = b as i32;
    }

    let mut k = 1usize;
    while k < n {
        let rank_ref = &rank;
        let kk = k;
        let nn = n;
        sa.sort_by(|&a, &b| {
            let a = a as usize;
            let b = b as usize;
            let c = rank_ref[a].cmp(&rank_ref[b]);
            if c != core::cmp::Ordering::Equal {
                return c;
            }
            let ra = rank_ref[(a + kk) % nn];
            let rb = rank_ref[(b + kk) % nn];
            ra.cmp(&rb)
        });

        tmp[sa[0] as usize] = 0;
        for i in 1..n {
            let prev = sa[i - 1] as usize;
            let curr = sa[i] as usize;
            let same = rank[prev] == rank[curr] && rank[(prev + kk) % nn] == rank[(curr + kk) % nn];
            tmp[curr] = tmp[prev] + if same { 0 } else { 1 };
        }

        rank.copy_from_slice(&tmp);

        if rank[sa[n - 1] as usize] as usize == n - 1 {
            break;
        }
        k *= 2;
    }

    let mut result = vec![0u8; n];
    let mut original_ptr = 0u32;
    for (i, &s) in sa.iter().enumerate() {
        if s == 0 {
            original_ptr = i as u32;
            result[i] = data[n - 1];
        } else {
            result[i] = data[s as usize - 1];
        }
    }

    (result, original_ptr)
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
}
