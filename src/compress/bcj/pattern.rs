//! 16-byte pattern compare for the aligned BCJ scans.
//!
//! x86_64 and i686 use SSE2. aarch64 uses NEON. wasm32 with `simd128`
//! uses a 16-byte compare. Other targets compare one byte at a time.
//! Bit `i` is set when byte `i` matches. The window stays 16 bytes
//! because each caller packs four-byte instructions.

pub(super) fn pattern_bits(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    #[cfg(any(
        target_arch = "x86_64",
        all(target_arch = "x86", target_feature = "sse2")
    ))]
    {
        unsafe { pattern_bits_sse2(chunk, mask, expect) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { pattern_bits_neon(chunk, mask, expect) }
    }
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        unsafe { pattern_bits_wasm(chunk, mask, expect) }
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        all(target_arch = "x86", target_feature = "sse2"),
        target_arch = "aarch64",
        all(target_arch = "wasm32", target_feature = "simd128"),
    )))]
    {
        pattern_bits_scalar(chunk, mask, expect)
    }
}

#[cfg(any(
    test,
    not(any(
        target_arch = "x86_64",
        all(target_arch = "x86", target_feature = "sse2"),
        target_arch = "aarch64",
        all(target_arch = "wasm32", target_feature = "simd128"),
    ))
))]
fn pattern_bits_scalar(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    let mut bits = 0u32;
    for (i, byte) in chunk.iter().take(16).enumerate() {
        if byte & mask[i] == expect[i] {
            bits |= 1 << i;
        }
    }
    bits
}

pub(super) fn groups_of_four(bits: u32) -> u32 {
    let mut hits = 0u32;
    for k in 0..4 {
        if (bits >> (k * 4)) & 0xF == 0xF {
            hits |= 1 << k;
        }
    }
    hits
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn pattern_bits_sse2(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{
        __m128i, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
    };
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
    };

    let raw = unsafe { _mm_loadu_si128(chunk.as_ptr().cast::<__m128i>()) };
    let mask_v = unsafe { _mm_loadu_si128(mask.as_ptr().cast::<__m128i>()) };
    let expect_v = unsafe { _mm_loadu_si128(expect.as_ptr().cast::<__m128i>()) };
    let got = _mm_and_si128(raw, mask_v);
    _mm_movemask_epi8(_mm_cmpeq_epi8(got, expect_v)) as u32
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
unsafe fn pattern_bits_wasm(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    use core::arch::wasm32::{i8x16_bitmask, i8x16_eq, v128_and, v128_load};

    let raw = unsafe { v128_load(chunk.as_ptr().cast()) };
    let mask_v = unsafe { v128_load(mask.as_ptr().cast()) };
    let expect_v = unsafe { v128_load(expect.as_ptr().cast()) };
    let got = v128_and(raw, mask_v);
    u32::from(i8x16_bitmask(i8x16_eq(got, expect_v)))
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn pattern_bits_neon(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    use core::arch::aarch64::{vandq_u8, vceqq_u8, vld1q_u8};

    let raw = unsafe { vld1q_u8(chunk.as_ptr()) };
    let mask_v = unsafe { vld1q_u8(mask.as_ptr()) };
    let expect_v = unsafe { vld1q_u8(expect.as_ptr()) };
    let got = vandq_u8(raw, mask_v);
    unsafe { crate::compress::scan::neon_movemask(vceqq_u8(got, expect_v)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ([u8; 16], [u8; 16], [u8; 16]) {
        let mut chunk = [0u8; 16];
        let mut mask = [0xFFu8; 16];
        let mut expect = [0u8; 16];
        for i in 0..16 {
            chunk[i] = (i as u8).wrapping_mul(17).wrapping_add(3);
            expect[i] = chunk[i];
        }
        chunk[5] ^= 0x01;
        mask[7] = 0x0F;
        expect[7] &= 0x0F;
        (chunk, mask, expect)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn pattern_bits_sse2_matches_scalar() {
        let (chunk, mask, expect) = sample();
        let sse2 = unsafe { pattern_bits_sse2(&chunk, &mask, &expect) };
        assert_eq!(sse2, pattern_bits_scalar(&chunk, &mask, &expect));
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn pattern_bits_wasm_matches_scalar() {
        let (chunk, mask, expect) = sample();
        let wide = unsafe { pattern_bits_wasm(&chunk, &mask, &expect) };
        assert_eq!(wide, pattern_bits_scalar(&chunk, &mask, &expect));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn pattern_bits_neon_matches_scalar() {
        let (chunk, mask, expect) = sample();
        let neon = unsafe { pattern_bits_neon(&chunk, &mask, &expect) };
        assert_eq!(neon, pattern_bits_scalar(&chunk, &mask, &expect));
    }
}
