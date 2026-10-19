//! Byte scan shared by BCJ and LZX.
//!
//! `find_byte` returns the first index whose byte is one of the needles.
//! The baseline x86_64 crate scans 16 bytes at a time with SSE2. A crate
//! built with `target-cpu=x86-64-v3` scans 32 bytes with AVX2. aarch64
//! scans 16 bytes with NEON. The index matches [`find_byte_scalar`].

/// First index in `from..=last` whose byte is `first` or `second`.
///
/// The baseline x86_64 crate scans 16 bytes at a time. An `x86-64-v3`
/// crate scans 32 bytes. Both then run the scalar tail. The returned
/// index is the same as [`find_byte_scalar`].
pub(crate) fn find_byte(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    if from > last || data.is_empty() {
        return None;
    }
    let last = last.min(data.len() - 1);
    if from > last {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { find_byte_x86(data, from, last, first, second) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(hit) = unsafe { find_byte_neon(data, from, last, first, second) } {
            return Some(hit);
        }
        let consumed = from + ((data.len() - from) / 16) * 16;
        let tail = consumed.min(last.saturating_add(1));
        find_byte_scalar(data, tail.max(from), last, first, second)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        find_byte_scalar(data, from, last, first, second)
    }
}

pub(crate) fn find_byte_scalar(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    if from > last || data.is_empty() {
        return None;
    }
    let last = last.min(data.len() - 1);
    let mut i = from;
    while i <= last {
        let b = data[i];
        if b == first || second == Some(b) {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(target_arch = "x86_64")]
unsafe fn find_byte_x86(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    #[cfg(target_feature = "avx2")]
    let (hit, width) = (
        unsafe { find_byte_avx2(data, from, last, first, second) },
        32,
    );
    #[cfg(not(target_feature = "avx2"))]
    let (hit, width) = (
        unsafe { find_byte_sse2(data, from, last, first, second) },
        16,
    );
    if let Some(hit) = hit {
        return Some(hit);
    }
    let consumed = from + ((data.len() - from) / width) * width;
    let tail = consumed.min(last.saturating_add(1));
    find_byte_scalar(data, tail.max(from), last, first, second)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
unsafe fn find_byte_avx2(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    use core::arch::x86_64::{
        __m256i, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8, _mm256_or_si256,
        _mm256_set1_epi8,
    };

    let needle_a = _mm256_set1_epi8(first as i8);
    let needle_b = _mm256_set1_epi8(second.unwrap_or(first) as i8);
    let mut i = from;
    while i + 32 <= data.len() {
        let v = unsafe { _mm256_loadu_si256(data.as_ptr().add(i).cast::<__m256i>()) };
        let mut cmp = _mm256_cmpeq_epi8(v, needle_a);
        if second.is_some() {
            cmp = _mm256_or_si256(cmp, _mm256_cmpeq_epi8(v, needle_b));
        }
        let mask = _mm256_movemask_epi8(cmp) as u32;
        if mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            if i + bit <= last {
                return Some(i + bit);
            }
            return None;
        }
        if i + 31 > last {
            return None;
        }
        i += 32;
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(all(not(test), target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "sse2")]
unsafe fn find_byte_sse2(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    use core::arch::x86_64::{
        __m128i, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8, _mm_or_si128, _mm_set1_epi8,
    };

    let needle_a = _mm_set1_epi8(first as i8);
    let needle_b = _mm_set1_epi8(second.unwrap_or(first) as i8);
    let mut i = from;
    while i + 16 <= data.len() {
        let v = unsafe { _mm_loadu_si128(data.as_ptr().add(i).cast::<__m128i>()) };
        let mut cmp = _mm_cmpeq_epi8(v, needle_a);
        if second.is_some() {
            cmp = _mm_or_si128(cmp, _mm_cmpeq_epi8(v, needle_b));
        }
        let mask = _mm_movemask_epi8(cmp) as u32;
        if mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            if i + bit <= last {
                return Some(i + bit);
            }
            return None;
        }
        if i + 15 > last {
            return None;
        }
        i += 16;
    }
    None
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn find_byte_neon(
    data: &[u8],
    from: usize,
    last: usize,
    first: u8,
    second: Option<u8>,
) -> Option<usize> {
    use core::arch::aarch64::{vceqq_u8, vdupq_n_u8, vld1q_u8, vorrq_u8};

    let needle_a = vdupq_n_u8(first);
    let needle_b = vdupq_n_u8(second.unwrap_or(first));
    let mut i = from;
    while i + 16 <= data.len() {
        let v = unsafe { vld1q_u8(data.as_ptr().add(i)) };
        let mut cmp = vceqq_u8(v, needle_a);
        if second.is_some() {
            cmp = vorrq_u8(cmp, vceqq_u8(v, needle_b));
        }
        let mask = unsafe { neon_movemask(cmp) };
        if mask != 0 {
            let bit = mask.trailing_zeros() as usize;
            if i + bit <= last {
                return Some(i + bit);
            }
            return None;
        }
        if i + 15 > last {
            return None;
        }
        i += 16;
    }
    None
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn neon_movemask(cmp: core::arch::aarch64::uint8x16_t) -> u32 {
    use core::arch::aarch64::{vaddv_u8, vandq_u8, vget_high_u8, vget_low_u8, vld1q_u8};

    // Compare lanes are 0x00 or 0xFF. Keep one distinct bit per lane.
    const BITS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
    let bits = unsafe { vandq_u8(cmp, vld1q_u8(BITS.as_ptr())) };
    let lo = vaddv_u8(vget_low_u8(bits));
    let hi = vaddv_u8(vget_high_u8(bits));
    (u32::from(hi) << 8) | u32::from(lo)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn test_find_byte_matches_scalar_scan() {
        let data: Vec<u8> = (0..300u32)
            .map(|i| match i % 17 {
                0 => 0xE8,
                1 => 0xE9,
                _ => (i % 251) as u8,
            })
            .collect();
        for from in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            for last in [from, from + 5, from + 40, data.len() - 1] {
                let last = last.min(data.len() - 1);
                assert_eq!(
                    find_byte(&data, from, last, 0xE8, Some(0xE9)),
                    find_byte_scalar(&data, from, last, 0xE8, Some(0xE9)),
                    "from {from} last {last}"
                );
                assert_eq!(
                    find_byte(&data, from, last, 0xE8, None),
                    find_byte_scalar(&data, from, last, 0xE8, None)
                );
            }
        }
        let empty = vec![0u8; 80];
        assert_eq!(find_byte(&empty, 0, 70, 0xE8, Some(0xE9)), None);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn find_byte_sse2_matches_scalar_inside_groups() {
        let mut data = vec![0u8; 64];
        data[20] = 0xE8;
        data[50] = 0xE9;
        let sse2 = unsafe { super::find_byte_sse2(&data, 0, 63, 0xE8, Some(0xE9)) };
        assert_eq!(sse2, find_byte_scalar(&data, 0, 63, 0xE8, Some(0xE9)));
        let later = unsafe { super::find_byte_sse2(&data, 21, 63, 0xE8, Some(0xE9)) };
        assert_eq!(later, find_byte_scalar(&data, 21, 63, 0xE8, Some(0xE9)));
        let none = vec![1u8; 32];
        assert_eq!(
            unsafe { super::find_byte_sse2(&none, 0, 31, 0xE8, None) },
            None
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn find_byte_neon_matches_scalar_inside_groups() {
        let mut data = vec![0u8; 64];
        data[20] = 0xE8;
        data[50] = 0xE9;
        let neon = unsafe { super::find_byte_neon(&data, 0, 63, 0xE8, Some(0xE9)) };
        assert_eq!(neon, find_byte_scalar(&data, 0, 63, 0xE8, Some(0xE9)));
        let later = unsafe { super::find_byte_neon(&data, 21, 63, 0xE8, Some(0xE9)) };
        assert_eq!(later, find_byte_scalar(&data, 21, 63, 0xE8, Some(0xE9)));
        let none = vec![1u8; 32];
        assert_eq!(
            unsafe { super::find_byte_neon(&none, 0, 31, 0xE8, None) },
            None
        );
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn find_byte_avx2_matches_scalar_inside_groups() {
        let mut data = vec![0u8; 96];
        data[20] = 0xE8;
        data[70] = 0xE9;
        let avx2 = unsafe { super::find_byte_avx2(&data, 0, 95, 0xE8, Some(0xE9)) };
        assert_eq!(avx2, find_byte_scalar(&data, 0, 95, 0xE8, Some(0xE9)));
        let later = unsafe { super::find_byte_avx2(&data, 21, 95, 0xE8, Some(0xE9)) };
        assert_eq!(later, find_byte_scalar(&data, 21, 95, 0xE8, Some(0xE9)));
        let none = vec![1u8; 64];
        assert_eq!(
            unsafe { super::find_byte_avx2(&none, 0, 63, 0xE8, None) },
            None
        );
    }
}
