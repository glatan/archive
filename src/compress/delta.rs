//! Delta filter shared by XZ / 7z style filter chains.
//!
//! Ported from the public-domain liblzma delta filter
//! (`delta_encoder.c` / `delta_decoder.c`; `delta_coder.c` holds the
//! shared init/dispatch). See
//! `THIRD_PARTY_NOTICES` section 2.

use alloc::vec::Vec;

#[cfg(target_arch = "x86")]
use core::arch::x86 as sse;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as sse;

use crate::error::Error;

/// Stateful byte-wise Delta filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    distance: usize,
    history: [u8; 256],
    pos: usize,
}

impl Filter {
    /// Create a new Delta filter.
    pub fn new(distance: usize) -> Result<Self, Error> {
        if !(1..=256).contains(&distance) {
            return Err(Error::InvalidData("delta: distance must be 1..=256"));
        }
        Ok(Self {
            distance,
            history: [0; 256],
            pos: 0,
        })
    }

    /// Encode a buffer in place.
    pub fn encode_in_place(&mut self, buffer: &mut [u8]) {
        if self.simd_distance() {
            self.encode_simd(buffer);
        } else {
            self.encode_scalar(buffer);
        }
    }

    /// Decode a buffer in place.
    pub fn decode_in_place(&mut self, buffer: &mut [u8]) {
        if self.simd_distance() {
            self.decode_simd(buffer);
        } else {
            self.decode_scalar(buffer);
        }
    }

    fn encode_scalar(&mut self, buffer: &mut [u8]) {
        for byte in buffer {
            let prev = self.history[self.distance.wrapping_add(self.pos) & 0xFF];
            let input = *byte;
            self.history[self.pos & 0xFF] = input;
            self.pos = self.pos.wrapping_sub(1);
            *byte = input.wrapping_sub(prev);
        }
    }

    fn decode_scalar(&mut self, buffer: &mut [u8]) {
        for byte in buffer {
            let decoded =
                byte.wrapping_add(self.history[self.distance.wrapping_add(self.pos) & 0xFF]);
            self.history[self.pos & 0xFF] = decoded;
            self.pos = self.pos.wrapping_sub(1);
            *byte = decoded;
        }
    }

    /// Distance 1 is a byte-wise scan. Other SIMD distances are multiples
    /// of the 16-byte vector width, so each lane stays on its own chain.
    /// An `x86-64-v3` build uses 32-byte chunks only when the distance is
    /// 1 or a multiple of 32. An `x86-64-v4` build uses 64-byte chunks
    /// when the distance is 1 or a multiple of 64, and keeps 32 and 16
    /// on the narrower paths. Distance 16 stays on 16-byte chunks.
    /// i686 SSE2 and wasm32 `simd128` use the 16-byte path for distance
    /// 1 and multiples of 16.
    fn simd_distance(&self) -> bool {
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "x86", target_feature = "sse2"),
            target_arch = "aarch64",
            all(target_arch = "wasm32", target_feature = "simd128"),
        ))]
        {
            self.distance == 1 || self.distance.is_multiple_of(16)
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "x86", target_feature = "sse2"),
            target_arch = "aarch64",
            all(target_arch = "wasm32", target_feature = "simd128"),
        )))]
        {
            let _ = self;
            false
        }
    }

    fn encode_simd(&mut self, buffer: &mut [u8]) {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512bw"))]
        if self.distance == 1 || self.distance.is_multiple_of(64) {
            self.encode_width64(buffer, true);
            return;
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        if self.distance == 1 || self.distance.is_multiple_of(32) {
            self.encode_width32(buffer, true);
            return;
        }
        self.encode_width16(buffer, true);
    }

    fn decode_simd(&mut self, buffer: &mut [u8]) {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512bw"))]
        if self.distance == 1 || self.distance.is_multiple_of(64) {
            self.encode_width64(buffer, false);
            return;
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        if self.distance == 1 || self.distance.is_multiple_of(32) {
            self.encode_width32(buffer, false);
            return;
        }
        self.encode_width16(buffer, false);
    }

    /// 16-byte chunks once `pos` is 15 modulo 16, then a scalar tail.
    fn encode_width16(&mut self, buffer: &mut [u8], encode: bool) {
        #[cfg(any(
            target_arch = "x86_64",
            all(target_arch = "x86", target_feature = "sse2")
        ))]
        {
            let prefix = (((self.pos & 0xFF) + 1) & 15).min(buffer.len());
            if encode {
                self.encode_scalar(&mut buffer[..prefix]);
            } else {
                self.decode_scalar(&mut buffer[..prefix]);
            }
            let mut off = prefix;
            while off + 16 <= buffer.len() {
                unsafe {
                    if encode {
                        self.encode_chunk16(&mut buffer[off..off + 16]);
                    } else {
                        self.decode_chunk16(&mut buffer[off..off + 16]);
                    }
                }
                off += 16;
            }
            if encode {
                self.encode_scalar(&mut buffer[off..]);
            } else {
                self.decode_scalar(&mut buffer[off..]);
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let prefix = (((self.pos & 0xFF) + 1) & 15).min(buffer.len());
            if encode {
                self.encode_scalar(&mut buffer[..prefix]);
            } else {
                self.decode_scalar(&mut buffer[..prefix]);
            }
            let mut off = prefix;
            while off + 16 <= buffer.len() {
                unsafe {
                    if encode {
                        self.encode_chunk16_neon(&mut buffer[off..off + 16]);
                    } else {
                        self.decode_chunk16_neon(&mut buffer[off..off + 16]);
                    }
                }
                off += 16;
            }
            if encode {
                self.encode_scalar(&mut buffer[off..]);
            } else {
                self.decode_scalar(&mut buffer[off..]);
            }
        }
        #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
        {
            let prefix = (((self.pos & 0xFF) + 1) & 15).min(buffer.len());
            if encode {
                self.encode_scalar(&mut buffer[..prefix]);
            } else {
                self.decode_scalar(&mut buffer[..prefix]);
            }
            let mut off = prefix;
            while off + 16 <= buffer.len() {
                unsafe {
                    if encode {
                        self.encode_chunk16_wasm(&mut buffer[off..off + 16]);
                    } else {
                        self.decode_chunk16_wasm(&mut buffer[off..off + 16]);
                    }
                }
                off += 16;
            }
            if encode {
                self.encode_scalar(&mut buffer[off..]);
            } else {
                self.decode_scalar(&mut buffer[off..]);
            }
        }
        #[cfg(not(any(
            target_arch = "x86_64",
            all(target_arch = "x86", target_feature = "sse2"),
            target_arch = "aarch64",
            all(target_arch = "wasm32", target_feature = "simd128"),
        )))]
        {
            let _ = (buffer, encode);
        }
    }

    /// 32-byte chunks once `pos` is 31 modulo 32, then a scalar tail.
    ///
    /// The ring store is contiguous only when the distance is 1 or a
    /// multiple of 32. Callers keep every other SIMD distance on
    /// [`Self::encode_width16`].
    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
    fn encode_width32(&mut self, buffer: &mut [u8], encode: bool) {
        let prefix = (((self.pos & 0xFF) + 1) & 31).min(buffer.len());
        if encode {
            self.encode_scalar(&mut buffer[..prefix]);
        } else {
            self.decode_scalar(&mut buffer[..prefix]);
        }
        let mut off = prefix;
        while off + 32 <= buffer.len() {
            unsafe {
                if encode {
                    self.encode_chunk32(&mut buffer[off..off + 32]);
                } else {
                    self.decode_chunk32(&mut buffer[off..off + 32]);
                }
            }
            off += 32;
        }
        if encode {
            self.encode_scalar(&mut buffer[off..]);
        } else {
            self.decode_scalar(&mut buffer[off..]);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn encode_chunk16_neon(&mut self, chunk: &mut [u8]) {
        use core::arch::aarch64::{vld1q_u8, vst1q_u8, vsubq_u8};

        let p = self.pos & 0xFF;
        let input = unsafe { vld1q_u8(chunk.as_ptr()) };
        let out = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF];
            let prev = neon_insert_carry(input, carry);
            vsubq_u8(input, prev)
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { neon_load_reversed(self.history.as_ptr().add(r - 15)) };
            vsubq_u8(input, prev)
        };
        unsafe { vst1q_u8(chunk.as_mut_ptr(), out) };
        unsafe { neon_store_reversed(self.history.as_mut_ptr().add(p - 15), input) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn decode_chunk16_neon(&mut self, chunk: &mut [u8]) {
        use core::arch::aarch64::{vaddq_u8, vdupq_n_u8, vld1q_u8, vst1q_u8};

        let p = self.pos & 0xFF;
        let input = unsafe { vld1q_u8(chunk.as_ptr()) };
        let decoded = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF];
            let sum = neon_prefix_sum(input);
            vaddq_u8(sum, vdupq_n_u8(carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { neon_load_reversed(self.history.as_ptr().add(r - 15)) };
            vaddq_u8(input, prev)
        };
        unsafe { vst1q_u8(chunk.as_mut_ptr(), decoded) };
        unsafe { neon_store_reversed(self.history.as_mut_ptr().add(p - 15), decoded) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    unsafe fn encode_chunk16(&mut self, chunk: &mut [u8]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::{
            __m128i, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_or_si128, _mm_slli_si128,
            _mm_storeu_si128, _mm_sub_epi8,
        };
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::{
            __m128i, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_or_si128, _mm_slli_si128,
            _mm_storeu_si128, _mm_sub_epi8,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm_loadu_si128(chunk.as_ptr().cast::<__m128i>()) };
        let out = if self.distance == 1 {
            let carry = i32::from(self.history[(p + 1) & 0xFF]);
            let prev = _mm_or_si128(_mm_slli_si128(input, 1), _mm_cvtsi32_si128(carry));
            _mm_sub_epi8(input, prev)
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed16(self.history.as_ptr().add(r - 15)) };
            _mm_sub_epi8(input, prev)
        };
        unsafe { _mm_storeu_si128(chunk.as_mut_ptr().cast::<__m128i>(), out) };
        unsafe { store_reversed16(self.history.as_mut_ptr().add(p - 15), input) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sse2")]
    unsafe fn decode_chunk16(&mut self, chunk: &mut [u8]) {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::{
            __m128i, _mm_add_epi8, _mm_loadu_si128, _mm_set1_epi8, _mm_storeu_si128,
        };
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::{
            __m128i, _mm_add_epi8, _mm_loadu_si128, _mm_set1_epi8, _mm_storeu_si128,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm_loadu_si128(chunk.as_ptr().cast::<__m128i>()) };
        let decoded = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF] as i8;
            let sum = unsafe { prefix_sum16(input) };
            _mm_add_epi8(sum, _mm_set1_epi8(carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed16(self.history.as_ptr().add(r - 15)) };
            _mm_add_epi8(input, prev)
        };
        unsafe { _mm_storeu_si128(chunk.as_mut_ptr().cast::<__m128i>(), decoded) };
        unsafe { store_reversed16(self.history.as_mut_ptr().add(p - 15), decoded) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[target_feature(enable = "simd128")]
    unsafe fn encode_chunk16_wasm(&mut self, chunk: &mut [u8]) {
        use core::arch::wasm32::{i8x16_sub, v128_load, v128_store};

        let p = self.pos & 0xFF;
        let input = unsafe { v128_load(chunk.as_ptr().cast()) };
        let out = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF];
            i8x16_sub(input, wasm_insert_carry(input, carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { wasm_load_reversed(self.history.as_ptr().add(r - 15)) };
            i8x16_sub(input, prev)
        };
        unsafe { v128_store(chunk.as_mut_ptr().cast(), out) };
        unsafe { wasm_store_reversed(self.history.as_mut_ptr().add(p - 15), input) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[target_feature(enable = "simd128")]
    unsafe fn decode_chunk16_wasm(&mut self, chunk: &mut [u8]) {
        use core::arch::wasm32::{i8x16_add, u8x16_splat, v128_load, v128_store};

        let p = self.pos & 0xFF;
        let input = unsafe { v128_load(chunk.as_ptr().cast()) };
        let decoded = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF];
            i8x16_add(wasm_prefix_sum(input), u8x16_splat(carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { wasm_load_reversed(self.history.as_ptr().add(r - 15)) };
            i8x16_add(input, prev)
        };
        unsafe { v128_store(chunk.as_mut_ptr().cast(), decoded) };
        unsafe { wasm_store_reversed(self.history.as_mut_ptr().add(p - 15), decoded) };
        self.pos = self.pos.wrapping_sub(16);
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
    #[target_feature(enable = "avx2")]
    unsafe fn encode_chunk32(&mut self, chunk: &mut [u8]) {
        use core::arch::x86_64::{
            __m256i, _mm_cvtsi32_si128, _mm_or_si128, _mm_slli_si128, _mm_srli_si128, _mm_sub_epi8,
            _mm256_castsi256_si128, _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_set_m128i,
            _mm256_storeu_si256, _mm256_sub_epi8,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm256_loadu_si256(chunk.as_ptr().cast::<__m256i>()) };
        let out = if self.distance == 1 {
            let carry = i32::from(self.history[(p + 1) & 0xFF]);
            let low = _mm256_castsi256_si128(input);
            let high = _mm256_extracti128_si256(input, 1);
            let prev_low = _mm_or_si128(_mm_slli_si128(low, 1), _mm_cvtsi32_si128(carry));
            let prev_high = _mm_or_si128(_mm_slli_si128(high, 1), _mm_srli_si128(low, 15));
            _mm256_set_m128i(_mm_sub_epi8(high, prev_high), _mm_sub_epi8(low, prev_low))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed32(self.history.as_ptr().add(r - 31)) };
            _mm256_sub_epi8(input, prev)
        };
        unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast::<__m256i>(), out) };
        unsafe { store_reversed32(self.history.as_mut_ptr().add(p - 31), input) };
        self.pos = self.pos.wrapping_sub(32);
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
    #[target_feature(enable = "avx2")]
    unsafe fn decode_chunk32(&mut self, chunk: &mut [u8]) {
        use core::arch::x86_64::{
            __m256i, _mm256_add_epi8, _mm256_loadu_si256, _mm256_set1_epi8, _mm256_storeu_si256,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm256_loadu_si256(chunk.as_ptr().cast::<__m256i>()) };
        let decoded = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF] as i8;
            let sum = unsafe { prefix_sum32(input) };
            _mm256_add_epi8(sum, _mm256_set1_epi8(carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed32(self.history.as_ptr().add(r - 31)) };
            _mm256_add_epi8(input, prev)
        };
        unsafe { _mm256_storeu_si256(chunk.as_mut_ptr().cast::<__m256i>(), decoded) };
        unsafe { store_reversed32(self.history.as_mut_ptr().add(p - 31), decoded) };
        self.pos = self.pos.wrapping_sub(32);
    }

    /// 64-byte chunks once `pos` is 63 modulo 64, then a scalar tail.
    ///
    /// Checked before the 32-byte path: distance 64 is also a multiple of
    /// 32. The ring store stays inside the 256-byte history.
    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
    fn encode_width64(&mut self, buffer: &mut [u8], encode: bool) {
        let prefix = (((self.pos & 0xFF) + 1) & 63).min(buffer.len());
        if encode {
            self.encode_scalar(&mut buffer[..prefix]);
        } else {
            self.decode_scalar(&mut buffer[..prefix]);
        }
        let mut off = prefix;
        while off + 64 <= buffer.len() {
            unsafe {
                if encode {
                    self.encode_chunk64(&mut buffer[off..off + 64]);
                } else {
                    self.decode_chunk64(&mut buffer[off..off + 64]);
                }
            }
            off += 64;
        }
        if encode {
            self.encode_scalar(&mut buffer[off..]);
        } else {
            self.decode_scalar(&mut buffer[off..]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
    #[target_feature(enable = "avx512bw")]
    unsafe fn encode_chunk64(&mut self, chunk: &mut [u8]) {
        use core::arch::x86_64::{
            __m512i, _mm_cvtsi32_si128, _mm_or_si128, _mm_slli_si128, _mm_srli_si128, _mm_sub_epi8,
            _mm512_castsi512_si128, _mm512_extracti32x4_epi32, _mm512_loadu_si512,
            _mm512_storeu_si512, _mm512_sub_epi8,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm512_loadu_si512(chunk.as_ptr().cast::<__m512i>()) };
        let out = if self.distance == 1 {
            let carry = i32::from(self.history[(p + 1) & 0xFF]);
            let l0 = _mm512_castsi512_si128(input);
            let l1 = _mm512_extracti32x4_epi32::<1>(input);
            let l2 = _mm512_extracti32x4_epi32::<2>(input);
            let l3 = _mm512_extracti32x4_epi32::<3>(input);
            let prev0 = _mm_or_si128(_mm_slli_si128(l0, 1), _mm_cvtsi32_si128(carry));
            let prev1 = _mm_or_si128(_mm_slli_si128(l1, 1), _mm_srli_si128(l0, 15));
            let prev2 = _mm_or_si128(_mm_slli_si128(l2, 1), _mm_srli_si128(l1, 15));
            let prev3 = _mm_or_si128(_mm_slli_si128(l3, 1), _mm_srli_si128(l2, 15));
            lanes4(
                _mm_sub_epi8(l0, prev0),
                _mm_sub_epi8(l1, prev1),
                _mm_sub_epi8(l2, prev2),
                _mm_sub_epi8(l3, prev3),
            )
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed64(self.history.as_ptr().add(r - 63)) };
            _mm512_sub_epi8(input, prev)
        };
        unsafe { _mm512_storeu_si512(chunk.as_mut_ptr().cast::<__m512i>(), out) };
        unsafe { store_reversed64(self.history.as_mut_ptr().add(p - 63), input) };
        self.pos = self.pos.wrapping_sub(64);
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
    #[target_feature(enable = "avx512bw")]
    unsafe fn decode_chunk64(&mut self, chunk: &mut [u8]) {
        use core::arch::x86_64::{
            __m512i, _mm512_add_epi8, _mm512_loadu_si512, _mm512_set1_epi8, _mm512_storeu_si512,
        };

        let p = self.pos & 0xFF;
        let input = unsafe { _mm512_loadu_si512(chunk.as_ptr().cast::<__m512i>()) };
        let decoded = if self.distance == 1 {
            let carry = self.history[(p + 1) & 0xFF] as i8;
            let sum = unsafe { prefix_sum64(input) };
            _mm512_add_epi8(sum, _mm512_set1_epi8(carry))
        } else {
            let r = (p + self.distance) & 0xFF;
            let prev = unsafe { load_reversed64(self.history.as_ptr().add(r - 63)) };
            _mm512_add_epi8(input, prev)
        };
        unsafe { _mm512_storeu_si512(chunk.as_mut_ptr().cast::<__m512i>(), decoded) };
        unsafe { store_reversed64(self.history.as_mut_ptr().add(p - 63), decoded) };
        self.pos = self.pos.wrapping_sub(64);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn reverse16(v: sse::__m128i) -> sse::__m128i {
    use sse::{
        _mm_or_si128, _mm_shuffle_epi32, _mm_shufflehi_epi16, _mm_shufflelo_epi16, _mm_slli_epi16,
        _mm_srli_epi16,
    };

    let swapped = _mm_or_si128(_mm_slli_epi16(v, 8), _mm_srli_epi16(v, 8));
    let lo = _mm_shufflelo_epi16(swapped, 0xB1);
    let hi = _mm_shufflehi_epi16(lo, 0xB1);
    _mm_shuffle_epi32(hi, 0x1B)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn load_reversed16(ptr: *const u8) -> sse::__m128i {
    use sse::{__m128i, _mm_loadu_si128};

    let mem = unsafe { _mm_loadu_si128(ptr.cast::<__m128i>()) };
    unsafe { reverse16(mem) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn store_reversed16(ptr: *mut u8, buf_order: sse::__m128i) {
    use sse::{__m128i, _mm_storeu_si128};

    let mem = unsafe { reverse16(buf_order) };
    unsafe { _mm_storeu_si128(ptr.cast::<__m128i>(), mem) };
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
unsafe fn prefix_sum16(v: sse::__m128i) -> sse::__m128i {
    use sse::{_mm_add_epi8, _mm_slli_si128};

    let mut v = v;
    v = _mm_add_epi8(v, _mm_slli_si128(v, 1));
    v = _mm_add_epi8(v, _mm_slli_si128(v, 2));
    v = _mm_add_epi8(v, _mm_slli_si128(v, 4));
    _mm_add_epi8(v, _mm_slli_si128(v, 8))
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
unsafe fn reverse32(v: core::arch::x86_64::__m256i) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::{_mm256_permute2x128_si256, _mm256_setr_epi8, _mm256_shuffle_epi8};

    let swapped = _mm256_permute2x128_si256(v, v, 0x01);
    let index = _mm256_setr_epi8(
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6,
        5, 4, 3, 2, 1, 0,
    );
    _mm256_shuffle_epi8(swapped, index)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
unsafe fn load_reversed32(ptr: *const u8) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::{__m256i, _mm256_loadu_si256};

    let mem = unsafe { _mm256_loadu_si256(ptr.cast::<__m256i>()) };
    unsafe { reverse32(mem) }
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
unsafe fn store_reversed32(ptr: *mut u8, buf_order: core::arch::x86_64::__m256i) {
    use core::arch::x86_64::{__m256i, _mm256_storeu_si256};

    let mem = unsafe { reverse32(buf_order) };
    unsafe { _mm256_storeu_si256(ptr.cast::<__m256i>(), mem) };
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
unsafe fn prefix_sum32(v: core::arch::x86_64::__m256i) -> core::arch::x86_64::__m256i {
    use core::arch::x86_64::{
        _mm_add_epi8, _mm_cvtsi128_si32, _mm_set1_epi8, _mm_srli_si128, _mm256_castsi256_si128,
        _mm256_extracti128_si256, _mm256_set_m128i,
    };

    let low = unsafe { prefix_sum16(_mm256_castsi256_si128(v)) };
    let mut high = unsafe { prefix_sum16(_mm256_extracti128_si256(v, 1)) };
    let lane_total = _mm_cvtsi128_si32(_mm_srli_si128(low, 15)) as i8;
    high = _mm_add_epi8(high, _mm_set1_epi8(lane_total));
    _mm256_set_m128i(high, low)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
fn lanes4(
    l0: core::arch::x86_64::__m128i,
    l1: core::arch::x86_64::__m128i,
    l2: core::arch::x86_64::__m128i,
    l3: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::{_mm512_castsi128_si512, _mm512_inserti32x4};

    let mut v = _mm512_castsi128_si512(l0);
    v = _mm512_inserti32x4::<1>(v, l1);
    v = _mm512_inserti32x4::<2>(v, l2);
    _mm512_inserti32x4::<3>(v, l3)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
unsafe fn reverse64(v: core::arch::x86_64::__m512i) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::{
        _mm_setr_epi8, _mm512_broadcast_i32x4, _mm512_shuffle_epi8, _mm512_shuffle_i32x4,
    };

    // Byte reverse inside each 128-bit lane, then reverse the four lanes.
    // `_mm512_permutexvar_epi8` needs AVX-512VBMI, which x86-64-v4 lacks.
    let index16 = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    let index = _mm512_broadcast_i32x4(index16);
    let lanes = _mm512_shuffle_epi8(v, index);
    _mm512_shuffle_i32x4::<0x1B>(lanes, lanes)
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
unsafe fn load_reversed64(ptr: *const u8) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::{__m512i, _mm512_loadu_si512};

    let mem = unsafe { _mm512_loadu_si512(ptr.cast::<__m512i>()) };
    unsafe { reverse64(mem) }
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
unsafe fn store_reversed64(ptr: *mut u8, buf_order: core::arch::x86_64::__m512i) {
    use core::arch::x86_64::{__m512i, _mm512_storeu_si512};

    let mem = unsafe { reverse64(buf_order) };
    unsafe { _mm512_storeu_si512(ptr.cast::<__m512i>(), mem) };
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
unsafe fn prefix_sum64(v: core::arch::x86_64::__m512i) -> core::arch::x86_64::__m512i {
    use core::arch::x86_64::{
        _mm_add_epi8, _mm_cvtsi128_si32, _mm_set1_epi8, _mm_srli_si128, _mm512_castsi512_si128,
        _mm512_extracti32x4_epi32,
    };

    let l0 = unsafe { prefix_sum16(_mm512_castsi512_si128(v)) };
    let c0 = _mm_cvtsi128_si32(_mm_srli_si128(l0, 15)) as i8;
    let l1 = _mm_add_epi8(
        unsafe { prefix_sum16(_mm512_extracti32x4_epi32::<1>(v)) },
        _mm_set1_epi8(c0),
    );
    let c1 = _mm_cvtsi128_si32(_mm_srli_si128(l1, 15)) as i8;
    let l2 = _mm_add_epi8(
        unsafe { prefix_sum16(_mm512_extracti32x4_epi32::<2>(v)) },
        _mm_set1_epi8(c1),
    );
    let c2 = _mm_cvtsi128_si32(_mm_srli_si128(l2, 15)) as i8;
    let l3 = _mm_add_epi8(
        unsafe { prefix_sum16(_mm512_extracti32x4_epi32::<3>(v)) },
        _mm_set1_epi8(c2),
    );
    lanes4(l0, l1, l2, l3)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn neon_reverse(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::{vextq_u8, vrev64q_u8};

    let rev = vrev64q_u8(v);
    vextq_u8(rev, rev, 8)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn neon_insert_carry(
    input: core::arch::aarch64::uint8x16_t,
    carry: u8,
) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::{vdupq_n_u8, vextq_u8, vsetq_lane_u8};

    let lane = vsetq_lane_u8(carry, vdupq_n_u8(0), 15);
    vextq_u8(lane, input, 15)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn neon_prefix_sum(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::{vaddq_u8, vdupq_n_u8, vextq_u8};

    let z = vdupq_n_u8(0);
    let mut v = v;
    v = vaddq_u8(v, vextq_u8(z, v, 15));
    v = vaddq_u8(v, vextq_u8(z, v, 14));
    v = vaddq_u8(v, vextq_u8(z, v, 12));
    vaddq_u8(v, vextq_u8(z, v, 8))
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon_load_reversed(ptr: *const u8) -> core::arch::aarch64::uint8x16_t {
    use core::arch::aarch64::vld1q_u8;

    let mem = unsafe { vld1q_u8(ptr) };
    neon_reverse(mem)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn neon_store_reversed(ptr: *mut u8, buf_order: core::arch::aarch64::uint8x16_t) {
    use core::arch::aarch64::vst1q_u8;

    let mem = neon_reverse(buf_order);
    unsafe { vst1q_u8(ptr, mem) };
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
fn wasm_reverse(v: core::arch::wasm32::v128) -> core::arch::wasm32::v128 {
    use core::arch::wasm32::{i8x16_swizzle, u8x16};

    i8x16_swizzle(
        v,
        u8x16(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
    )
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
fn wasm_insert_carry(input: core::arch::wasm32::v128, carry: u8) -> core::arch::wasm32::v128 {
    use core::arch::wasm32::{i8x16_replace_lane, i8x16_swizzle, u8x16};

    let shifted = i8x16_swizzle(
        input,
        u8x16(0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
    );
    i8x16_replace_lane::<0>(shifted, carry as i8)
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
fn wasm_prefix_sum(v: core::arch::wasm32::v128) -> core::arch::wasm32::v128 {
    use core::arch::wasm32::{i8x16_add, i8x16_swizzle, u8x16};

    let mut v = v;
    v = i8x16_add(
        v,
        i8x16_swizzle(
            v,
            u8x16(0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
        ),
    );
    v = i8x16_add(
        v,
        i8x16_swizzle(
            v,
            u8x16(0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13),
        ),
    );
    v = i8x16_add(
        v,
        i8x16_swizzle(
            v,
            u8x16(0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
        ),
    );
    i8x16_add(
        v,
        i8x16_swizzle(
            v,
            u8x16(
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7,
            ),
        ),
    )
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
unsafe fn wasm_load_reversed(ptr: *const u8) -> core::arch::wasm32::v128 {
    use core::arch::wasm32::v128_load;

    let mem = unsafe { v128_load(ptr.cast()) };
    wasm_reverse(mem)
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
unsafe fn wasm_store_reversed(ptr: *mut u8, buf_order: core::arch::wasm32::v128) {
    use core::arch::wasm32::v128_store;

    let mem = wasm_reverse(buf_order);
    unsafe { v128_store(ptr.cast(), mem) };
}

/// Encode bytes using the Delta filter.
pub fn encode(input: &[u8], distance: usize) -> Result<Vec<u8>, Error> {
    let mut filter = Filter::new(distance)?;
    let mut output = input.to_vec();
    filter.encode_in_place(&mut output);
    Ok(output)
}

/// Decode bytes using the Delta filter.
pub fn decode(input: &[u8], distance: usize) -> Result<Vec<u8>, Error> {
    let mut filter = Filter::new(distance)?;
    let mut output = input.to_vec();
    filter.decode_in_place(&mut output);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_delta_known_vector_distance_one() {
        let input = b"BANANA";
        let encoded = encode(input, 1).unwrap();
        assert_eq!(encoded, vec![66, 255, 13, 243, 13, 243]);
        assert_eq!(decode(&encoded, 1).unwrap(), input);
    }

    #[test]
    fn test_delta_roundtrip_distance_four() {
        let input = (0u8..=255).cycle().take(1024).collect::<Vec<_>>();
        let encoded = encode(&input, 4).unwrap();
        let decoded = decode(&encoded, 4).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn test_delta_streaming_matches_one_shot() {
        let input = (0u8..=63).cycle().take(300).collect::<Vec<_>>();
        let one_shot = encode(&input, 3).unwrap();

        let mut streaming = input.clone();
        let mut filter = Filter::new(3).unwrap();
        filter.encode_in_place(&mut streaming[..120]);
        filter.encode_in_place(&mut streaming[120..]);
        assert_eq!(streaming, one_shot);

        let mut decoder = Filter::new(3).unwrap();
        decoder.decode_in_place(&mut streaming[..111]);
        decoder.decode_in_place(&mut streaming[111..]);
        assert_eq!(streaming, input);
    }

    #[test]
    fn test_delta_rejects_invalid_distance() {
        assert!(Filter::new(0).is_err());
        assert!(Filter::new(257).is_err());
    }

    #[test]
    fn test_simd_matches_scalar_for_every_distance() {
        let data: Vec<u8> = (0..600u32)
            .map(|i| i.wrapping_mul(17).wrapping_add(3) as u8)
            .collect();
        for distance in 1..=256 {
            let mut scalar = Filter::new(distance).unwrap();
            let mut vector = Filter::new(distance).unwrap();
            let mut a = data.clone();
            let mut b = data.clone();
            scalar.encode_scalar(&mut a);
            vector.encode_in_place(&mut b);
            assert_eq!(a, b, "encode distance {distance}");
            assert_eq!(scalar.history, vector.history);
            assert_eq!(scalar.pos, vector.pos);

            let mut scalar_dec = Filter::new(distance).unwrap();
            let mut vector_dec = Filter::new(distance).unwrap();
            scalar_dec.decode_scalar(&mut a);
            vector_dec.decode_in_place(&mut b);
            assert_eq!(a, data, "scalar decode distance {distance}");
            assert_eq!(b, data, "vector decode distance {distance}");
            assert_eq!(scalar_dec.history, vector_dec.history);
            assert_eq!(scalar_dec.pos, vector_dec.pos);
        }
    }

    #[test]
    fn test_simd_streaming_matches_scalar() {
        let data: Vec<u8> = (0..400u32)
            .map(|i| i.wrapping_mul(31).wrapping_add(9) as u8)
            .collect();
        for distance in [1usize, 16, 32, 48, 256] {
            for step in [1usize, 15, 16, 17, 31, 32, 33, 64, 255] {
                let mut scalar = Filter::new(distance).unwrap();
                let mut vector = Filter::new(distance).unwrap();
                let mut a = data.clone();
                let mut b = data.clone();
                let mut at = 0;
                while at < data.len() {
                    let end = (at + step).min(data.len());
                    scalar.encode_scalar(&mut a[at..end]);
                    vector.encode_in_place(&mut b[at..end]);
                    at = end;
                }
                assert_eq!(a, b, "distance {distance} step {step}");
                assert_eq!(scalar.pos, vector.pos);
                assert_eq!(scalar.history, vector.history);
            }
        }
    }
}
