//! MD5 implementation for lrzip integrity verification.
//!
//! Implements the MD5 message-digest algorithm as specified in RFC 1321.

/// Per-round shift amounts (RFC 1321, section 3.4).
#[rustfmt::skip]
const S: [u32; 64] = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

/// Precomputed table of `floor(2^32 * |sin(i + 1)|)` for i = 0..63 (RFC 1321, section 3.4).
#[rustfmt::skip]
const K: [u32; 64] = [
    0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
    0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
    0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
    0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
    0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
    0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
    0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
    0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
    0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
    0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
    0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
    0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
    0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
    0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
    0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
    0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
];

/// Initial hash state (RFC 1321, section 3.3).
const INITIAL_STATE: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

/// Compute the MD5 digest of `data` (RFC 1321).
///
/// Returns the 16-byte (128-bit) digest in little-endian word order, matching
/// the standard MD5 output format.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finish()
}

/// Incremental MD5 hasher.
#[derive(Debug, Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Create a new MD5 hasher initialized to the RFC 1321 initial values.
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Feed `data` into the hasher.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buffer_len > 0 {
            let to_copy = (64 - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            data = &data[to_copy..];

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalise the hash and return the 16-byte digest.
    pub fn finish(mut self) -> [u8; 16] {
        // Append the mandatory 0x80 padding byte.
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If there is no room for the 8-byte length field, flush and start a
        // fresh block.
        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0u8; 64];
            self.buffer_len = 0;
        }

        // Zero-pad to byte 56, then append the 64-bit bit-length in
        // little-endian order (RFC 1321, section 3.2).
        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        let bit_len = self.total_len.wrapping_mul(8);
        self.buffer[56..64].copy_from_slice(&bit_len.to_le_bytes());
        let block = self.buffer;
        self.compress(&block);

        // Emit state words in little-endian order (RFC 1321, section 3.5).
        let mut out = [0u8; 16];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Process one 512-bit (64-byte) block (RFC 1321, section 3.4).
    fn compress(&mut self, block: &[u8; 64]) {
        // Load block as 16 little-endian u32 words.
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let j = i * 4;
            *word = u32::from_le_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;

        for i in 0usize..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321, section A.5 test suite.

    #[test]
    fn test_md5_empty() {
        // MD5 ("") = d41d8cd98f00b204e9800998ecf8427e
        assert_eq!(
            md5(b""),
            [
                0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
                0x42, 0x7e,
            ]
        );
    }

    #[test]
    fn test_md5_abc() {
        // MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
        assert_eq!(
            md5(b"abc"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72,
            ]
        );
    }

    #[test]
    fn test_md5_message_digest() {
        // MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
        assert_eq!(
            md5(b"message digest"),
            [
                0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1,
                0x61, 0xd0,
            ]
        );
    }

    #[test]
    fn test_md5_a_to_z() {
        // MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            [
                0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67,
                0xe1, 0x3b,
            ]
        );
    }

    #[test]
    fn test_md5_alphanumeric() {
        // MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
        //   = d174ab98d277d9f5a5611c2c9f419d9f
        assert_eq!(
            md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            [
                0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41,
                0x9d, 0x9f,
            ]
        );
    }

    #[test]
    fn test_md5_digits_repeated() {
        // MD5 ("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
        //   = 57edf4a22be3c955ac49da2e2107b67a
        assert_eq!(
            md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            [
                0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07,
                0xb6, 0x7a,
            ]
        );
    }

    #[test]
    fn test_md5_incremental() {
        // Verify that splitting input yields the same result as a single call.
        let mut hasher = Md5::new();
        hasher.update(b"message ");
        hasher.update(b"digest");
        assert_eq!(
            hasher.finish(),
            [
                0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1,
                0x61, 0xd0,
            ]
        );
    }
}
