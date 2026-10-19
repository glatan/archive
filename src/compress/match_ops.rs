//! Overlap-safe backward copies and bounded match lengths.
//!
//! `copy_match` writes `len` bytes taken from `offset` bytes before the end
//! of one output buffer. `copy_match_with_prefix` does the same across a
//! dictionary placed in front of that buffer: the dictionary prefix is
//! copied first, and only the part already in the output uses `copy_match`.
//! `copy_ring` reads and writes a power-of-two history buffer through a
//! mask. A caller that succeeds after a partial copy decides how many
//! bytes to pass in.

use alloc::vec::Vec;

/// `copy_match` was asked for a distance this buffer cannot satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyMatchError {
    /// Distance zero does not name a byte already in the buffer.
    ZeroOffset,
    /// `offset` is greater than the bytes already written.
    OffsetOutOfRange,
}

#[cfg_attr(
    not(any(
        feature = "deflate",
        feature = "zstd",
        feature = "lzs",
        feature = "lzo",
        feature = "vcdiff",
        feature = "xca",
        feature = "snappy",
        feature = "fastlz",
        feature = "lz4",
        feature = "brotli",
        feature = "lzip",
        feature = "lzma-alone",
        feature = "erofs",
        feature = "lzrw1",
        feature = "lzrw1a",
        feature = "lzrw2",
        feature = "lzrw3",
        feature = "lzrw3a",
        feature = "lzsa",
        feature = "zx0",
        feature = "zx1",
        feature = "zx2",
        feature = "zx5",
        feature = "lzxd",
        feature = "mscab",
        feature = "lzf",
    )),
    allow(dead_code)
)]
/// Append `len` bytes copied from `offset` bytes before the current end.
///
/// The source and the destination overlap when `len > offset`. The copy is
/// split into non-overlapping chunks: the first chunk is at most `offset`
/// bytes, and each later chunk repeats the bytes already appended.
pub(crate) fn copy_match(
    output: &mut Vec<u8>,
    offset: usize,
    len: usize,
) -> Result<(), CopyMatchError> {
    if offset == 0 {
        return Err(CopyMatchError::ZeroOffset);
    }
    if offset > output.len() {
        return Err(CopyMatchError::OffsetOutOfRange);
    }
    if len == 0 {
        return Ok(());
    }

    output.reserve(len);
    let base = output.len();
    let first = len.min(offset);
    append_from(output, base - offset, first);

    let mut filled = first;
    while filled < len {
        let n = (len - filled).min(filled);
        append_from(output, base, n);
        filled += n;
    }
    Ok(())
}

#[cfg_attr(
    not(any(
        feature = "lzxd",
        feature = "mscab",
        feature = "lzsa",
        feature = "zx0",
        feature = "zx1",
        feature = "zx2",
        feature = "zx5",
    )),
    allow(dead_code)
)]
/// Append `len` bytes from `distance` before the end of `prefix ++ output`.
///
/// Bytes that still lie in `prefix` are copied from there. The remainder is
/// [`copy_match`]. A match that lies entirely in `prefix` does not call
/// `copy_match`, because that distance can exceed `output.len()`.
pub(crate) fn copy_match_with_prefix(
    prefix: &[u8],
    output: &mut Vec<u8>,
    distance: usize,
    len: usize,
) -> Result<(), CopyMatchError> {
    let avail = prefix.len() + output.len();
    if distance == 0 {
        return Err(CopyMatchError::ZeroOffset);
    }
    if distance > avail {
        return Err(CopyMatchError::OffsetOutOfRange);
    }
    let start = avail - distance;
    let from_prefix = prefix.len().saturating_sub(start).min(len);
    if from_prefix > 0 {
        output.extend_from_slice(&prefix[start..start + from_prefix]);
    }
    let rest = len - from_prefix;
    if rest > 0 {
        copy_match(output, distance, rest)?;
    }
    Ok(())
}

#[cfg_attr(
    not(any(
        feature = "vcdiff",
        feature = "mppc",
        feature = "zx0",
        feature = "zx1",
        feature = "zx2",
        feature = "zx5",
    )),
    allow(dead_code)
)]
/// Common prefix of two indexes into the virtual buffer `prefix ++ body`.
///
/// Each side is split where it crosses from `prefix` into `body`, and each
/// piece is measured with [`match_len`].
pub(crate) fn match_len_window(
    prefix: &[u8],
    body: &[u8],
    mut a: usize,
    mut b: usize,
    max_len: usize,
) -> usize {
    let total = prefix.len() + body.len();
    let mut matched = 0;
    while matched < max_len && a < total && b < total {
        let a_slice = window_from(prefix, body, a);
        let b_slice = window_from(prefix, body, b);
        let room = max_len - matched;
        let n = match_len(a_slice, b_slice, room);
        matched += n;
        if n == 0 || n < a_slice.len().min(b_slice.len()).min(room) {
            break;
        }
        a += n;
        b += n;
    }
    matched
}

#[cfg_attr(
    not(any(feature = "mscab", feature = "lha", feature = "arj", feature = "mppc",)),
    allow(dead_code)
)]
/// Copy `len` bytes inside a power-of-two ring.
///
/// `src` and `dst` are absolute indexes. Each access is reduced with
/// `ring.len() - 1`. A distance of zero (`src` and `dst` on the same
/// slot) is a self-copy, not an error: LHA stores offset 0 to mean one
/// byte back, and the caller turns that into `src == dst - 1` before
/// calling. The first `emit` copied bytes are also appended to `out`.
/// `emit` may be smaller than `len` when the window must keep bytes that
/// the output does not.
pub(crate) fn copy_ring(
    ring: &mut [u8],
    mut src: usize,
    mut dst: usize,
    mut len: usize,
    out: &mut Vec<u8>,
    mut emit: usize,
) {
    debug_assert!(ring.len().is_power_of_two() && !ring.is_empty());
    debug_assert!(emit <= len);
    let mask = ring.len() - 1;
    while len > 0 {
        let s = src & mask;
        let d = dst & mask;
        let mut n = len.min(ring.len() - s).min(ring.len() - d);
        let dist = (d + ring.len() - s) & mask;
        if dist == 0 {
            n = 1;
        } else if dist < n {
            n = dist;
        }
        if d != s {
            ring.copy_within(s..s + n, d);
        }
        let emit_n = n.min(emit);
        if emit_n > 0 {
            out.extend_from_slice(&ring[d..d + emit_n]);
            emit -= emit_n;
        }
        // Indexes are absolute and reduced with `mask`, so a copy that
        // starts just below zero stays defined for a corrupt offset.
        src = src.wrapping_add(n);
        dst = dst.wrapping_add(n);
        len -= n;
    }
}

fn window_from<'a>(prefix: &'a [u8], body: &'a [u8], pos: usize) -> &'a [u8] {
    if pos < prefix.len() {
        &prefix[pos..]
    } else {
        body.get(pos - prefix.len()..).unwrap_or(&[])
    }
}

/// Copy `n` initialized bytes starting at `src` onto the end of `output`.
///
/// `src + n` must be at most the current length, so the source does not
/// overlap the spare capacity being filled.
fn append_from(output: &mut Vec<u8>, src: usize, n: usize) {
    debug_assert!(src.saturating_add(n) <= output.len());
    let dst = output.len();
    debug_assert!(dst + n <= output.capacity());
    // Source ends at or before `dst`, and both ranges sit inside the
    // allocation. `copy_nonoverlapping` allows the ranges to touch.
    unsafe {
        let ptr = output.as_mut_ptr();
        core::ptr::copy_nonoverlapping(ptr.add(src), ptr.add(dst), n);
        output.set_len(dst + n);
    }
}

#[cfg_attr(
    not(any(
        feature = "deflate",
        feature = "lzs",
        feature = "lzrw1",
        feature = "lzrw1a",
        feature = "lzrw2",
        feature = "lzrw3",
        feature = "lzrw3a",
        feature = "lzsa",
        feature = "snappy",
        feature = "zstd",
        feature = "lz4",
        feature = "fastlz",
        feature = "brotli",
        feature = "lzo",
        feature = "rzip",
        feature = "lzip",
        feature = "lzma-alone",
        feature = "packbits",
        feature = "zx0",
        feature = "zx1",
        feature = "zx2",
        feature = "zx5",
        feature = "lzf",
        feature = "vcdiff",
        feature = "mppc",
        feature = "xca",
    )),
    allow(dead_code)
)]
/// Length of the common prefix of `a` and `b`, capped by `max_len`.
///
/// The baseline x86_64 crate and the default i686 crate compare 16 bytes
/// with SSE2. An `x86-64-v3` crate compares 32 bytes with AVX2, and an
/// `x86-64-v4` crate compares 64 bytes with AVX-512BW. aarch64 compares 16
/// bytes with NEON. A wasm32 crate built with `simd128` compares 16 bytes.
/// Each path finishes the tail with [`match_len_scalar`].
pub(crate) fn match_len(a: &[u8], b: &[u8], max_len: usize) -> usize {
    let limit = max_len.min(a.len()).min(b.len());
    #[cfg(target_arch = "x86_64")]
    {
        match_len_x86(a, b, limit)
    }
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    {
        unsafe { match_len_sse2(a, b, limit) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { match_len_neon(a, b, limit) }
    }
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        unsafe { match_len_wasm(a, b, limit) }
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "x86", target_feature = "sse2"),
        target_arch = "aarch64",
        all(target_arch = "wasm32", target_feature = "simd128"),
    )))]
    {
        match_len_scalar(a, b, limit)
    }
}

pub(crate) fn match_len_scalar(a: &[u8], b: &[u8], limit: usize) -> usize {
    let n = limit.min(a.len()).min(b.len());
    for i in 0..n {
        if a[i] != b[i] {
            return i;
        }
    }
    n
}

#[cfg(target_arch = "x86_64")]
fn match_len_x86(a: &[u8], b: &[u8], limit: usize) -> usize {
    // The baseline crate uses SSE2. `target-cpu=x86-64-v3` uses AVX2.
    // `target-cpu=x86-64-v4` uses AVX-512BW. None of the paths read CPUID.
    // v4 also enables AVX2, so the 64-byte path has to win that cfg.
    #[cfg(target_feature = "avx512bw")]
    unsafe {
        match_len_avx512(a, b, limit)
    }
    #[cfg(all(target_feature = "avx2", not(target_feature = "avx512bw")))]
    unsafe {
        match_len_avx2(a, b, limit)
    }
    #[cfg(not(target_feature = "avx2"))]
    unsafe {
        match_len_sse2(a, b, limit)
    }
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
unsafe fn match_len_avx512(a: &[u8], b: &[u8], limit: usize) -> usize {
    use core::arch::x86_64::{__m512i, _mm512_cmpeq_epi8_mask, _mm512_loadu_si512};

    let mut i = 0;
    while i + 64 <= limit {
        let left = unsafe { _mm512_loadu_si512(a.as_ptr().add(i).cast::<__m512i>()) };
        let right = unsafe { _mm512_loadu_si512(b.as_ptr().add(i).cast::<__m512i>()) };
        let mask = _mm512_cmpeq_epi8_mask(left, right);
        if mask != u64::MAX {
            return i + mask.trailing_ones() as usize;
        }
        i += 64;
    }
    i + match_len_scalar(&a[i..], &b[i..], limit - i)
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
unsafe fn match_len_wasm(a: &[u8], b: &[u8], limit: usize) -> usize {
    use core::arch::wasm32::{i8x16_bitmask, i8x16_eq, v128_load};

    let mut i = 0;
    while i + 16 <= limit {
        let left = unsafe { v128_load(a.as_ptr().add(i).cast()) };
        let right = unsafe { v128_load(b.as_ptr().add(i).cast()) };
        let mask = i8x16_bitmask(i8x16_eq(left, right));
        if mask != 0xFFFF {
            return i + mask.trailing_ones() as usize;
        }
        i += 16;
    }
    i + match_len_scalar(&a[i..], &b[i..], limit - i)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn match_len_neon(a: &[u8], b: &[u8], limit: usize) -> usize {
    use core::arch::aarch64::{vceqq_u8, vld1q_u8};

    let mut i = 0;
    while i + 16 <= limit {
        let left = unsafe { vld1q_u8(a.as_ptr().add(i)) };
        let right = unsafe { vld1q_u8(b.as_ptr().add(i)) };
        let mask = unsafe { crate::compress::scan::neon_movemask(vceqq_u8(left, right)) };
        if mask != 0xFFFF {
            return i + (mask as u16).trailing_ones() as usize;
        }
        i += 16;
    }
    i + match_len_scalar(&a[i..], &b[i..], limit - i)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(
    any(
        not(target_feature = "avx2"),
        all(not(test), target_feature = "avx512bw")
    ),
    allow(dead_code)
)]
#[target_feature(enable = "avx2")]
unsafe fn match_len_avx2(a: &[u8], b: &[u8], limit: usize) -> usize {
    use core::arch::x86_64::{
        __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
    };

    let mut i = 0;
    while i + 32 <= limit {
        let left = unsafe { _mm256_loadu_si256(a.as_ptr().add(i).cast::<__m256i>()) };
        let right = unsafe { _mm256_loadu_si256(b.as_ptr().add(i).cast::<__m256i>()) };
        let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(left, right)) as u32;
        if mask != 0xFFFF_FFFF {
            return i + mask.trailing_ones() as usize;
        }
        i += 32;
    }
    i + match_len_scalar(&a[i..], &b[i..], limit - i)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[cfg_attr(all(not(test), target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "sse2")]
unsafe fn match_len_sse2(a: &[u8], b: &[u8], limit: usize) -> usize {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{__m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{__m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8};

    let mut i = 0;
    while i + 16 <= limit {
        let left = unsafe { _mm_loadu_si128(a.as_ptr().add(i).cast::<__m128i>()) };
        let right = unsafe { _mm_loadu_si128(b.as_ptr().add(i).cast::<__m128i>()) };
        let mask = _mm_movemask_epi8(_mm_cmpeq_epi8(left, right)) as u32;
        if mask != 0xFFFF {
            return i + (mask as u16).trailing_ones() as usize;
        }
        i += 16;
    }
    i + match_len_scalar(&a[i..], &b[i..], limit - i)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn copy_bytewise(output: &mut Vec<u8>, offset: usize, len: usize) {
        let target = output.len() + len;
        while output.len() < target {
            let byte = output[output.len() - offset];
            output.push(byte);
        }
    }

    #[test]
    fn copy_matches_bytewise_reference() {
        let offsets: [usize; 10] = [1, 2, 3, 4, 7, 8, 15, 16, 31, 32];
        for offset in offsets {
            let lengths = [offset.saturating_sub(1), offset, offset + 1, offset * 3 + 5];
            for len in lengths {
                if len == 0 {
                    continue;
                }
                let mut seed = vec![0u8; offset + 8];
                for (i, byte) in seed.iter_mut().enumerate() {
                    *byte = (i * 17 + 3) as u8;
                }
                let mut expected = seed.clone();
                let mut actual = seed;
                copy_bytewise(&mut expected, offset, len);
                copy_match(&mut actual, offset, len).unwrap();
                assert_eq!(actual, expected, "offset {offset} len {len}");
            }
        }
    }

    #[test]
    fn copy_rejects_zero_and_out_of_range_offsets() {
        let mut output = vec![1, 2, 3];
        assert_eq!(
            copy_match(&mut output, 0, 1),
            Err(CopyMatchError::ZeroOffset)
        );
        assert_eq!(
            copy_match(&mut output, 4, 1),
            Err(CopyMatchError::OffsetOutOfRange)
        );
        assert_eq!(output, vec![1, 2, 3]);
    }

    #[test]
    fn copy_zero_length_is_a_noop() {
        let mut output = vec![9, 8, 7];
        copy_match(&mut output, 2, 0).unwrap();
        assert_eq!(output, vec![9, 8, 7]);
    }

    fn scalar_prefix(a: &[u8], b: &[u8], max_len: usize) -> usize {
        let n = max_len.min(a.len()).min(b.len());
        a[..n]
            .iter()
            .zip(b[..n].iter())
            .take_while(|(left, right)| left == right)
            .count()
    }

    #[test]
    fn match_len_matches_scalar_prefix() {
        let widths = [0, 1, 15, 16, 17, 31, 32, 33, 48, 63, 64, 100];
        for n in widths {
            let same: Vec<u8> = (0..n).map(|i| (i * 3) as u8).collect();
            assert_eq!(match_len(&same, &same, n), scalar_prefix(&same, &same, n));
            assert_eq!(
                match_len_scalar(&same, &same, n),
                scalar_prefix(&same, &same, n)
            );
            if n == 0 {
                continue;
            }
            for at in [0, n / 2, n - 1] {
                let mut other = same.clone();
                other[at] ^= 0xFF;
                assert_eq!(
                    match_len(&same, &other, n),
                    scalar_prefix(&same, &other, n),
                    "mismatch at {at} of {n}"
                );
                assert_eq!(
                    match_len(&same, &other, at),
                    scalar_prefix(&same, &other, at)
                );
            }
        }
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn match_len_sse2_matches_scalar() {
        let n = 80;
        let a: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[47] ^= 1;
        let sse2 = unsafe { super::match_len_sse2(&a, &b, n) };
        assert_eq!(sse2, match_len_scalar(&a, &b, n));
        assert_eq!(unsafe { super::match_len_sse2(&a, &a, n) }, n);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn match_len_avx2_matches_scalar() {
        let n = 96;
        let a: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[47] ^= 1;
        let avx2 = unsafe { super::match_len_avx2(&a, &b, n) };
        assert_eq!(avx2, match_len_scalar(&a, &b, n));
        assert_eq!(unsafe { super::match_len_avx2(&a, &a, n) }, n);
        let tail = unsafe { super::match_len_avx2(&a, &a, 31) };
        assert_eq!(tail, 31);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512bw"))]
    #[test]
    fn match_len_avx512_matches_scalar() {
        let n = 160;
        let a: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[70] ^= 1;
        let wide = unsafe { super::match_len_avx512(&a, &b, n) };
        assert_eq!(wide, match_len_scalar(&a, &b, n));
        assert_eq!(unsafe { super::match_len_avx512(&a, &a, n) }, n);
        let tail = unsafe { super::match_len_avx512(&a, &a, 63) };
        assert_eq!(tail, 63);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn match_len_wasm_matches_scalar() {
        let n = 80;
        let a: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[47] ^= 1;
        let wide = unsafe { super::match_len_wasm(&a, &b, n) };
        assert_eq!(wide, match_len_scalar(&a, &b, n));
        assert_eq!(unsafe { super::match_len_wasm(&a, &a, n) }, n);
        let tail = unsafe { super::match_len_wasm(&a, &a, 15) };
        assert_eq!(tail, 15);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn match_len_neon_matches_scalar() {
        let n = 80;
        let a: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let mut b = a.clone();
        b[47] ^= 1;
        let neon = unsafe { super::match_len_neon(&a, &b, n) };
        assert_eq!(neon, match_len_scalar(&a, &b, n));
        assert_eq!(unsafe { super::match_len_neon(&a, &a, n) }, n);
        let tail = unsafe { super::match_len_neon(&a, &a, 15) };
        assert_eq!(tail, 15);
    }

    #[test]
    fn copy_with_prefix_spans_dictionary_then_overlaps() {
        let prefix = b"EF";
        let mut output = vec![b'A', b'B', b'C', b'D'];
        copy_match_with_prefix(prefix, &mut output, 6, 5).unwrap();
        assert_eq!(output, b"ABCDEFABC");
    }

    #[test]
    fn match_len_window_crosses_the_boundary() {
        let prefix = b"abcd";
        let body = b"cdefghij";
        // prefix[2..] is "cd"; the body starts "cd" and then diverges.
        assert_eq!(match_len_window(prefix, body, 2, 4, 8), 2);
        assert_eq!(match_len_window(prefix, body, 0, 4, 4), 0);
        assert_eq!(match_len_window(b"aaaa", b"aaaa", 2, 4, 6), 4);
    }

    fn copy_ring_bytewise(ring: &mut [u8], mut src: usize, mut dst: usize, len: usize) -> Vec<u8> {
        let mask = ring.len() - 1;
        let mut out = Vec::new();
        for _ in 0..len {
            let b = ring[src & mask];
            ring[dst & mask] = b;
            out.push(b);
            src = src.wrapping_add(1);
            dst = dst.wrapping_add(1);
        }
        out
    }

    #[test]
    fn copy_ring_matches_masked_byte_loop() {
        let cases = [
            (8, 6, 1, 6),
            (8, 0, 1, 7),
            (16, 14, 2, 10),
            (8, 3, 3, 4),
            (8, 1, 0, 5),
            (8, usize::MAX, 0, 5),
            (8, usize::MAX - 2, 1, 6),
        ];
        for (size, src, dst, len) in cases {
            let mut seed = vec![0u8; size];
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = (i * 9 + 1) as u8;
            }
            let mut expected = seed.clone();
            let want = copy_ring_bytewise(&mut expected, src, dst, len);
            let mut actual = seed.clone();
            let mut got = Vec::new();
            copy_ring(&mut actual, src, dst, len, &mut got, len);
            assert_eq!(actual, expected, "src {src} dst {dst} len {len}");
            assert_eq!(got, want);

            let emit = len / 2;
            let mut partial_ring = seed;
            let mut partial = Vec::new();
            copy_ring(&mut partial_ring, src, dst, len, &mut partial, emit);
            assert_eq!(partial_ring, expected);
            assert_eq!(partial, want[..emit]);
        }
    }
}
