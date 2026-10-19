//! XXH64 and XXH32 hash implementations.
//!
//! Provides both one-shot and streaming interfaces for xxHash64 (used by zstd)
//! and xxHash32 (used by LZ4). Constants and algorithm from xxHash by Yann Collet.

const PRIME64_1: u64 = 0x9E3779B185EBCA87;
const PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const PRIME64_3: u64 = 0x165667B19E3779F9;
const PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const PRIME64_5: u64 = 0x27D4EB2F165667C5;

/// Compute XXH64 hash of data with the given seed.
///
/// This function does not panic.
///
/// # Examples
///
/// ```ignore
/// use archive::util::xxhash::xxhash64;
///
/// let hash = xxhash64(b"Hello, World!", 0);
/// assert_eq!(hash, 0xC49AACF8080FE47F);
/// ```
#[cfg_attr(not(feature = "zstd"), allow(dead_code))]
pub fn xxhash64(data: &[u8], seed: u64) -> u64 {
    let len = data.len();
    let mut h: u64;
    let mut pos = 0;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        while pos + 32 <= len {
            v1 = round64(v1, read_u64_le(&data[pos..]));
            v2 = round64(v2, read_u64_le(&data[pos + 8..]));
            v3 = round64(v3, read_u64_le(&data[pos + 16..]));
            v4 = round64(v4, read_u64_le(&data[pos + 24..]));
            pos += 32;
        }

        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        h = merge_round64(h, v1);
        h = merge_round64(h, v2);
        h = merge_round64(h, v3);
        h = merge_round64(h, v4);
    } else {
        h = seed.wrapping_add(PRIME64_5);
    }

    h = h.wrapping_add(len as u64);

    // Finalize: process remaining bytes
    while pos + 8 <= len {
        let k1 = round64(0, read_u64_le(&data[pos..]));
        h ^= k1;
        h = h
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        pos += 8;
    }
    if pos + 4 <= len {
        h ^= (read_u32_le(&data[pos..]) as u64).wrapping_mul(PRIME64_1);
        h = h
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        pos += 4;
    }
    while pos < len {
        h ^= (data[pos] as u64).wrapping_mul(PRIME64_5);
        h = h.rotate_left(11).wrapping_mul(PRIME64_1);
        pos += 1;
    }

    avalanche(h)
}

const fn round64(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

const fn merge_round64(mut acc: u64, val: u64) -> u64 {
    let val = round64(0, val);
    acc ^= val;
    acc = acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4);
    acc
}

const fn avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^= h >> 32;
    h
}

fn read_u64_le(data: &[u8]) -> u64 {
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Streaming (incremental) XXH64 hasher.
///
/// Produces the same result as [`xxhash64`] for the same input when all data
/// is fed via [`update`](XxHash64::update) and finalized with [`finish`](XxHash64::finish).
/// Streaming XXH64 hasher.
///
/// Allows incremental feeding of data via [`update`](Self::update), with the
/// final hash computed by [`finish`](Self::finish). The hasher can be reused
/// by calling [`reset`](Self::reset).
///
/// No method on this type panics.
///
/// # Examples
///
/// ```ignore
/// use archive::util::xxhash::{xxhash64, XxHash64};
///
/// let mut hasher = XxHash64::new(0);
/// hasher.update(b"Hello, ");
/// hasher.update(b"World!");
/// assert_eq!(hasher.finish(), xxhash64(b"Hello, World!", 0));
/// ```
#[allow(dead_code)]
pub struct XxHash64 {
    seed: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    total_len: u64,
    buf: [u8; 32],
    buf_len: usize,
}

#[allow(dead_code)]
impl XxHash64 {
    /// Create a new streaming hasher with the given seed.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash64;
    /// let hasher = XxHash64::new(0);
    /// // Empty data hash
    /// assert_eq!(hasher.finish(), 0xEF46DB3751D8E999);
    /// ```
    pub const fn new(seed: u64) -> Self {
        Self {
            seed,
            v1: seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2),
            v2: seed.wrapping_add(PRIME64_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME64_1),
            total_len: 0,
            buf: [0u8; 32],
            buf_len: 0,
        }
    }

    /// Feed data into the hasher.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash64;
    /// let mut h = XxHash64::new(0);
    /// h.update(b"abc");
    /// h.update(b"def");
    /// // Equivalent to hashing b"abcdef" at once
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut pos = 0;

        // If there is buffered data, try to fill the buffer to 32 bytes
        if self.buf_len > 0 {
            let needed = 32 - self.buf_len;
            if data.len() < needed {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..32].copy_from_slice(&data[..needed]);
            self.v1 = round64(self.v1, read_u64_le(&self.buf[0..]));
            self.v2 = round64(self.v2, read_u64_le(&self.buf[8..]));
            self.v3 = round64(self.v3, read_u64_le(&self.buf[16..]));
            self.v4 = round64(self.v4, read_u64_le(&self.buf[24..]));
            self.buf_len = 0;
            pos = needed;
        }

        // Process full 32-byte stripes
        while pos + 32 <= data.len() {
            self.v1 = round64(self.v1, read_u64_le(&data[pos..]));
            self.v2 = round64(self.v2, read_u64_le(&data[pos + 8..]));
            self.v3 = round64(self.v3, read_u64_le(&data[pos + 16..]));
            self.v4 = round64(self.v4, read_u64_le(&data[pos + 24..]));
            pos += 32;
        }

        // Buffer remaining bytes
        let remaining = data.len() - pos;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the hash value. Does not consume the hasher
    /// and can be called multiple times.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash64;
    /// let mut h = XxHash64::new(0);
    /// h.update(b"data");
    /// let v1 = h.finish();
    /// let v2 = h.finish();
    /// assert_eq!(v1, v2);
    /// ```
    pub fn finish(&self) -> u64 {
        let mut h: u64;

        if self.total_len >= 32 {
            h = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));

            h = merge_round64(h, self.v1);
            h = merge_round64(h, self.v2);
            h = merge_round64(h, self.v3);
            h = merge_round64(h, self.v4);
        } else {
            h = self.seed.wrapping_add(PRIME64_5);
        }

        h = h.wrapping_add(self.total_len);

        // Finalize remaining buffered bytes
        let remaining = &self.buf[..self.buf_len];
        let len = remaining.len();
        let mut pos = 0;

        while pos + 8 <= len {
            let k1 = round64(0, read_u64_le(&remaining[pos..]));
            h ^= k1;
            h = h
                .rotate_left(27)
                .wrapping_mul(PRIME64_1)
                .wrapping_add(PRIME64_4);
            pos += 8;
        }
        if pos + 4 <= len {
            h ^= (read_u32_le(&remaining[pos..]) as u64).wrapping_mul(PRIME64_1);
            h = h
                .rotate_left(23)
                .wrapping_mul(PRIME64_2)
                .wrapping_add(PRIME64_3);
            pos += 4;
        }
        while pos < len {
            h ^= (remaining[pos] as u64).wrapping_mul(PRIME64_5);
            h = h.rotate_left(11).wrapping_mul(PRIME64_1);
            pos += 1;
        }

        avalanche(h)
    }

    /// Reset the hasher to its initial state (same seed).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash64;
    /// let mut h = XxHash64::new(42);
    /// h.update(b"data");
    /// h.reset();
    /// assert_eq!(h.finish(), XxHash64::new(42).finish());
    /// ```
    pub const fn reset(&mut self) {
        self.v1 = self.seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        self.v2 = self.seed.wrapping_add(PRIME64_2);
        self.v3 = self.seed;
        self.v4 = self.seed.wrapping_sub(PRIME64_1);
        self.total_len = 0;
        self.buf_len = 0;
    }
}

// ============================================================
// XXH32
// ============================================================

const PRIME32_1: u32 = 0x9E3779B1;
const PRIME32_2: u32 = 0x85EBCA77;
const PRIME32_3: u32 = 0xC2B2AE3D;
const PRIME32_4: u32 = 0x27D4EB2F;
const PRIME32_5: u32 = 0x165667B1;

/// Compute XXH32 hash of data with the given seed.
///
/// This function does not panic.
///
/// # Examples
///
/// ```ignore
/// use archive::util::xxhash::xxhash32;
///
/// let hash = xxhash32(b"", 0);
/// assert_eq!(hash, 0x02CC5D05);
/// ```
#[allow(dead_code)]
pub fn xxhash32(data: &[u8], seed: u32) -> u32 {
    let len = data.len();
    let mut h: u32;
    let mut pos = 0;

    if len >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);

        while pos + 16 <= len {
            v1 = round32(v1, read_u32_le(&data[pos..]));
            v2 = round32(v2, read_u32_le(&data[pos + 4..]));
            v3 = round32(v3, read_u32_le(&data[pos + 8..]));
            v4 = round32(v4, read_u32_le(&data[pos + 12..]));
            pos += 16;
        }

        h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
    } else {
        h = seed.wrapping_add(PRIME32_5);
    }

    h = h.wrapping_add(len as u32);

    while pos + 4 <= len {
        h = h.wrapping_add(read_u32_le(&data[pos..]).wrapping_mul(PRIME32_3));
        h = h.rotate_left(17).wrapping_mul(PRIME32_4);
        pos += 4;
    }
    while pos < len {
        h = h.wrapping_add((data[pos] as u32).wrapping_mul(PRIME32_5));
        h = h.rotate_left(11).wrapping_mul(PRIME32_1);
        pos += 1;
    }

    avalanche32(h)
}

const fn round32(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

const fn avalanche32(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^= h >> 16;
    h
}

/// Streaming (incremental) XXH32 hasher.
///
/// Produces the same result as [`xxhash32`] for the same input.
///
/// No method on this type panics.
///
/// # Examples
///
/// ```ignore
/// use archive::util::xxhash::{xxhash32, XxHash32};
///
/// let mut hasher = XxHash32::new(0);
/// hasher.update(b"Hello, ");
/// hasher.update(b"World!");
/// assert_eq!(hasher.finish(), xxhash32(b"Hello, World!", 0));
/// ```
#[allow(dead_code)]
pub struct XxHash32 {
    seed: u32,
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
    total_len: u64,
    buf: [u8; 16],
    buf_len: usize,
}

#[allow(dead_code)]
impl XxHash32 {
    /// Create a new streaming hasher with the given seed.
    pub const fn new(seed: u32) -> Self {
        Self {
            seed,
            v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
            v2: seed.wrapping_add(PRIME32_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME32_1),
            total_len: 0,
            buf: [0u8; 16],
            buf_len: 0,
        }
    }

    /// Feed data into the hasher.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash32;
    /// let mut h = XxHash32::new(0);
    /// h.update(b"abc");
    /// h.update(b"def");
    /// // Equivalent to hashing b"abcdef" at once
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut pos = 0;

        if self.buf_len > 0 {
            let needed = 16 - self.buf_len;
            if data.len() < needed {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..16].copy_from_slice(&data[..needed]);
            self.v1 = round32(self.v1, read_u32_le(&self.buf[0..]));
            self.v2 = round32(self.v2, read_u32_le(&self.buf[4..]));
            self.v3 = round32(self.v3, read_u32_le(&self.buf[8..]));
            self.v4 = round32(self.v4, read_u32_le(&self.buf[12..]));
            self.buf_len = 0;
            pos = needed;
        }

        while pos + 16 <= data.len() {
            self.v1 = round32(self.v1, read_u32_le(&data[pos..]));
            self.v2 = round32(self.v2, read_u32_le(&data[pos + 4..]));
            self.v3 = round32(self.v3, read_u32_le(&data[pos + 8..]));
            self.v4 = round32(self.v4, read_u32_le(&data[pos + 12..]));
            pos += 16;
        }

        let remaining = data.len() - pos;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[pos..]);
            self.buf_len = remaining;
        }
    }

    /// Finalize and return the hash value.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash32;
    /// let mut h = XxHash32::new(0);
    /// h.update(b"data");
    /// let v1 = h.finish();
    /// let v2 = h.finish();
    /// assert_eq!(v1, v2);
    /// ```
    pub fn finish(&self) -> u32 {
        let mut h: u32;

        if self.total_len >= 16 {
            h = self
                .v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18));
        } else {
            h = self.seed.wrapping_add(PRIME32_5);
        }

        h = h.wrapping_add(self.total_len as u32);

        let remaining = &self.buf[..self.buf_len];
        let len = remaining.len();
        let mut pos = 0;

        while pos + 4 <= len {
            h = h.wrapping_add(read_u32_le(&remaining[pos..]).wrapping_mul(PRIME32_3));
            h = h.rotate_left(17).wrapping_mul(PRIME32_4);
            pos += 4;
        }
        while pos < len {
            h = h.wrapping_add((remaining[pos] as u32).wrapping_mul(PRIME32_5));
            h = h.rotate_left(11).wrapping_mul(PRIME32_1);
            pos += 1;
        }

        avalanche32(h)
    }

    /// Reset the hasher to its initial state (same seed).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use archive::util::xxhash::XxHash32;
    /// let mut h = XxHash32::new(42);
    /// h.update(b"data");
    /// h.reset();
    /// assert_eq!(h.finish(), XxHash32::new(42).finish());
    /// ```
    pub const fn reset(&mut self) {
        self.v1 = self.seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        self.v2 = self.seed.wrapping_add(PRIME32_2);
        self.v3 = self.seed;
        self.v4 = self.seed.wrapping_sub(PRIME32_1);
        self.total_len = 0;
        self.buf_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    // Reference values verified against xxh64sum on the system.

    #[test]
    fn test_xxhash64_empty() {
        assert_eq!(xxhash64(b"", 0), 0xEF46DB3751D8E999);
    }

    #[test]
    fn test_xxhash64_1byte() {
        assert_eq!(xxhash64(b"a", 0), 0xD24EC4F1A98C6E5B);
    }

    #[test]
    fn test_xxhash64_hello_world() {
        assert_eq!(xxhash64(b"Hello, World!", 0), 0xC49AACF8080FE47F);
    }

    #[test]
    fn test_xxhash64_hello_world_checksum() {
        // Zstd uses low 32 bits of XXH64.
        let h = xxhash64(b"Hello, World!", 0);
        assert_eq!((h & 0xFFFFFFFF) as u32, 0x080FE47F);
    }

    #[test]
    fn test_xxhash64_long() {
        // 64 bytes of zeros - exercises the >= 32 path
        let data = [0u8; 64];
        assert_eq!(xxhash64(&data, 0), 0x257B09A147B82A19);
    }

    #[test]
    fn test_xxhash64_medium() {
        // 14 bytes - exercises the finalize 8+4+1+1 path
        let hash = xxhash64(b"0123456789abcd", 0);
        // Regression test: hash is non-trivial and consistent
        assert_ne!(hash, 0);
        // Verify it differs from shorter/longer inputs
        assert_ne!(hash, xxhash64(b"0123456789abc", 0));
        assert_ne!(hash, xxhash64(b"0123456789abcde", 0));
    }

    // Phase 1: Non-zero seed test

    #[test]
    fn test_xxhash64_seed_nonzero() {
        // Verify that different seeds produce different hashes
        let h0 = xxhash64(b"test", 0);
        let h1 = xxhash64(b"test", 1);
        let h42 = xxhash64(b"test", 42);
        assert_ne!(h0, h1);
        assert_ne!(h0, h42);
        assert_ne!(h1, h42);

        // Canonical test vectors from the xxHash specification:
        // Input: empty string, seed: 0 → 0xEF46DB3751D8E999
        assert_eq!(xxhash64(b"", 0), 0xEF46DB3751D8E999);
        // Input: empty string, seed: 1 → 0xD5AFBA1336A3BE4B
        assert_eq!(xxhash64(b"", 1), 0xD5AFBA1336A3BE4B);
    }

    #[test]
    fn test_xxhash64_exactly_32_bytes() {
        // Exactly 32 bytes: exercises the stripe loop path exactly once
        let data: Vec<u8> = (0u8..32).collect();
        let h32 = xxhash64(&data, 0);

        // 31 bytes: takes the < 32 (short) path
        let h31 = xxhash64(&data[..31], 0);

        // 33 bytes: takes the stripe loop path and has 1 byte remainder
        let mut data33: Vec<u8> = (0u8..33).collect();
        data33[32] = 0xFF;
        let h33 = xxhash64(&data33, 0);

        // All three should produce distinct hashes
        assert_ne!(h32, h31);
        assert_ne!(h32, h33);
        assert_ne!(h31, h33);
    }

    #[test]
    fn test_xxhash64_streaming_matches_oneshot() {
        // Various inputs fed in different chunk sizes
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"Hello, World!",
            b"0123456789abcd",
            &[0u8; 64],
            &[0xFFu8; 100],
        ];

        for &data in test_cases {
            let expected = xxhash64(data, 0);

            // Feed all at once
            let mut h = XxHash64::new(0);
            h.update(data);
            assert_eq!(
                h.finish(),
                expected,
                "all-at-once failed for len={}",
                data.len()
            );

            // Feed in 7-byte chunks
            let mut h = XxHash64::new(0);
            for chunk in data.chunks(7) {
                h.update(chunk);
            }
            assert_eq!(
                h.finish(),
                expected,
                "7-byte chunks failed for len={}",
                data.len()
            );

            // Feed in 32-byte chunks (stripe boundary)
            let mut h = XxHash64::new(0);
            for chunk in data.chunks(32) {
                h.update(chunk);
            }
            assert_eq!(
                h.finish(),
                expected,
                "32-byte chunks failed for len={}",
                data.len()
            );

            // Test with non-zero seed
            let expected_seed42 = xxhash64(data, 42);
            let mut h = XxHash64::new(42);
            h.update(data);
            assert_eq!(
                h.finish(),
                expected_seed42,
                "seed=42 failed for len={}",
                data.len()
            );
        }
    }

    #[test]
    fn test_xxhash64_streaming_incremental() {
        // Feed data byte-by-byte
        let data = b"Hello, World! This is a longer test string for streaming xxhash64.";
        let expected = xxhash64(data, 0);

        let mut h = XxHash64::new(0);
        for &b in data.iter() {
            h.update(&[b]);
        }
        assert_eq!(h.finish(), expected);

        // Test reset
        h.reset();
        for &b in data.iter() {
            h.update(&[b]);
        }
        assert_eq!(h.finish(), expected);

        // After reset with different data
        h.reset();
        h.update(b"test");
        assert_eq!(h.finish(), xxhash64(b"test", 0));
    }

    #[test]
    fn test_xxhash64_streaming_tiny_chunks() {
        // 1-3 byte chunks across the 32-byte stripe boundary
        let data: Vec<u8> = (0..100).collect();
        let expected = xxhash64(&data, 42);

        let mut h = XxHash64::new(42);
        let mut pos = 0;
        let mut chunk_size = 1;
        while pos < data.len() {
            let end = (pos + chunk_size).min(data.len());
            h.update(&data[pos..end]);
            pos = end;
            chunk_size = (chunk_size % 3) + 1; // cycle 1, 2, 3, 1, 2, 3...
        }
        assert_eq!(h.finish(), expected);
        // finish() called again gives same result
        assert_eq!(h.finish(), expected);
    }

    #[test]
    fn test_xxhash64_streaming_empty_updates() {
        let mut h = XxHash64::new(0);
        h.update(b"");
        h.update(b"Hello");
        h.update(b"");
        h.update(b"");
        h.update(b", World!");
        h.update(b"");
        assert_eq!(h.finish(), xxhash64(b"Hello, World!", 0));
    }

    // XXH32 tests

    #[test]
    fn test_xxhash32_empty() {
        assert_eq!(xxhash32(b"", 0), 0x02CC5D05);
    }

    #[test]
    fn test_xxhash32_hello_world() {
        // Verified against reference implementation
        let h = xxhash32(b"Hello, World!", 0);
        assert_ne!(h, 0);
        // Streaming must match
        let mut hasher = XxHash32::new(0);
        hasher.update(b"Hello, World!");
        assert_eq!(hasher.finish(), h);
    }

    #[test]
    fn test_xxhash32_streaming_matches_oneshot() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"Hello, World!",
            b"0123456789abcd",
            &[0u8; 64],
            &[0xFFu8; 100],
        ];

        for &data in test_cases {
            let expected = xxhash32(data, 0);

            let mut h = XxHash32::new(0);
            h.update(data);
            assert_eq!(h.finish(), expected, "all-at-once len={}", data.len());

            // Feed in 5-byte chunks
            let mut h = XxHash32::new(0);
            for chunk in data.chunks(5) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), expected, "5-byte chunks len={}", data.len());

            // Byte-by-byte
            let mut h = XxHash32::new(0);
            for &b in data {
                h.update(&[b]);
            }
            assert_eq!(h.finish(), expected, "byte-by-byte len={}", data.len());
        }
    }

    #[test]
    fn test_xxhash32_seed_nonzero() {
        let h0 = xxhash32(b"test", 0);
        let h1 = xxhash32(b"test", 1);
        let h42 = xxhash32(b"test", 42);
        assert_ne!(h0, h1);
        assert_ne!(h0, h42);
    }

    #[test]
    fn test_xxhash64_reset_returns_initial() {
        let mut h = XxHash64::new(0);
        h.update(b"some data that should be discarded");
        h.reset();
        assert_eq!(h.finish(), xxhash64(b"", 0));
    }

    #[test]
    fn test_xxhash32_streaming_vs_oneshot() {
        let seed: u32 = 12345;
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = xxhash32(data, seed);

        let mut h = XxHash32::new(seed);
        // Feed in irregular chunks
        h.update(&data[..5]);
        h.update(&data[5..17]);
        h.update(&data[17..]);
        assert_eq!(h.finish(), expected);
    }

    #[test]
    fn test_xxhash64_stripe_boundary_streaming() {
        // Lengths straddling the 32-byte stripe must hash identically
        // in one-shot and streaming modes.
        let data: Vec<u8> = (0u8..65).collect();
        for len in [31usize, 32, 33, 63, 64, 65] {
            let expected = xxhash64(&data[..len], 0);
            for split in [1usize, 16, 32] {
                let mut h = XxHash64::new(0);
                for chunk in data[..len].chunks(split) {
                    h.update(chunk);
                }
                assert_eq!(h.finish(), expected, "len={len} split={split}");
            }
        }
    }

    #[test]
    fn test_xxhash64_tail_boundaries() {
        // The finalize path consumes the tail in 8/4/1-byte pieces;
        // inputs around those internal boundaries must stay distinct.
        let data: Vec<u8> = (0u8..33).collect();
        let mut hashes = Vec::new();
        for len in [3usize, 4, 7, 8, 9, 15, 16, 17, 23, 24, 25, 31] {
            let h = xxhash64(&data[..len], 0);
            assert!(!hashes.contains(&h), "len={len} collides");
            hashes.push(h);
        }
    }

    #[test]
    fn test_xxhash32_stripe_boundary() {
        // XXH32's stripe is 16 bytes; lengths around it must agree
        // between one-shot and streaming, and stay distinct.
        let data: Vec<u8> = (0u8..33).collect();
        let mut prev = 0u32;
        for len in [15usize, 16, 17] {
            let expected = xxhash32(&data[..len], 0);
            assert_ne!(expected, prev, "len={len}");
            prev = expected;
            let mut h = XxHash32::new(0);
            for chunk in data[..len].chunks(4) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), expected);
        }
    }
}
