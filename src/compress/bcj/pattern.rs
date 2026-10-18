//! 16-byte pattern compare for the aligned BCJ scans.
//!
//! x86_64 uses SSE2 and aarch64 uses NEON. Other targets compare one
//! byte at a time. Bit `i` is set when byte `i` matches.

pub(super) fn pattern_bits(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { pattern_bits_sse2(chunk, mask, expect) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { pattern_bits_neon(chunk, mask, expect) }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        pattern_bits_scalar(chunk, mask, expect)
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn pattern_bits_sse2(chunk: &[u8], mask: &[u8; 16], expect: &[u8; 16]) -> u32 {
    use core::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
    };

    let raw = unsafe { _mm_loadu_si128(chunk.as_ptr().cast::<__m128i>()) };
    let mask_v = unsafe { _mm_loadu_si128(mask.as_ptr().cast::<__m128i>()) };
    let expect_v = unsafe { _mm_loadu_si128(expect.as_ptr().cast::<__m128i>()) };
    let got = _mm_and_si128(raw, mask_v);
    _mm_movemask_epi8(_mm_cmpeq_epi8(got, expect_v)) as u32
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
