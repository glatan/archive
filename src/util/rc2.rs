//! RC2 block cipher implementation (RFC 2268).
//!
//! Provides a 64-bit block cipher with variable key size and effective key bits.
//! Used by ZIP Strong Encryption (algorithm IDs 0x6602 and 0x6702).

use alloc::vec::Vec;

use crate::error::Error;

const BLOCK_SIZE: usize = 8;

/// Permutation table (PITABLE) from RFC 2268 section 2.
const PITABLE: [u8; 256] = [
    0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
    0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
    0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
    0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
    0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
    0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
    0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
    0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
    0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
    0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
    0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
    0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
    0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
    0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
    0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
    0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD,
];

/// RC2 block cipher (RFC 2268).
#[derive(Clone)]
pub(crate) struct Rc2 {
    /// Expanded key schedule: 64 words of 16 bits each.
    xkey: [u16; 64],
}

impl Rc2 {
    /// Create a new RC2 cipher with the given key and effective key bit length.
    ///
    /// `key` can be 1-128 bytes. `effective_bits` limits the effective key
    /// strength (typically matches the key length in bits, e.g., 128 for a
    /// 16-byte key).
    pub(crate) fn new(key: &[u8], effective_bits: usize) -> Self {
        let xkey = expand_key(key, effective_bits);
        Self { xkey }
    }

    /// Encrypt a single 8-byte block.
    #[allow(dead_code)]
    pub(crate) fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut r = [0u16; 4];
        for i in 0..4 {
            r[i] = u16::from_le_bytes([block[i * 2], block[i * 2 + 1]]);
        }

        // 16 mixing rounds with 2 mashing rounds interleaved
        for j in 0..16 {
            // Mixing round
            let k_idx = j * 4;
            r[0] = r[0]
                .wrapping_add(self.xkey[k_idx])
                .wrapping_add(r[3] & r[2])
                .wrapping_add(!r[3] & r[1]);
            r[0] = r[0].rotate_left(1);

            r[1] = r[1]
                .wrapping_add(self.xkey[k_idx + 1])
                .wrapping_add(r[0] & r[3])
                .wrapping_add(!r[0] & r[2]);
            r[1] = r[1].rotate_left(2);

            r[2] = r[2]
                .wrapping_add(self.xkey[k_idx + 2])
                .wrapping_add(r[1] & r[0])
                .wrapping_add(!r[1] & r[3]);
            r[2] = r[2].rotate_left(3);

            r[3] = r[3]
                .wrapping_add(self.xkey[k_idx + 3])
                .wrapping_add(r[2] & r[1])
                .wrapping_add(!r[2] & r[0]);
            r[3] = r[3].rotate_left(5);

            // Mashing after round 5 and round 11
            if j == 4 || j == 10 {
                r[0] = r[0].wrapping_add(self.xkey[r[3] as usize & 63]);
                r[1] = r[1].wrapping_add(self.xkey[r[0] as usize & 63]);
                r[2] = r[2].wrapping_add(self.xkey[r[1] as usize & 63]);
                r[3] = r[3].wrapping_add(self.xkey[r[2] as usize & 63]);
            }
        }

        let mut out = [0u8; 8];
        for i in 0..4 {
            let bytes = r[i].to_le_bytes();
            out[i * 2] = bytes[0];
            out[i * 2 + 1] = bytes[1];
        }
        out
    }

    /// Decrypt a single 8-byte block.
    pub(crate) fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let mut r = [0u16; 4];
        for i in 0..4 {
            r[i] = u16::from_le_bytes([block[i * 2], block[i * 2 + 1]]);
        }

        // Reverse: 16 mixing rounds with 2 mashing rounds interleaved
        for j in (0..16).rev() {
            // Reverse mashing after round 5 and round 11
            if j == 4 || j == 10 {
                r[3] = r[3].wrapping_sub(self.xkey[r[2] as usize & 63]);
                r[2] = r[2].wrapping_sub(self.xkey[r[1] as usize & 63]);
                r[1] = r[1].wrapping_sub(self.xkey[r[0] as usize & 63]);
                r[0] = r[0].wrapping_sub(self.xkey[r[3] as usize & 63]);
            }

            // Reverse mixing round
            let k_idx = j * 4;
            r[3] = r[3].rotate_right(5);
            r[3] = r[3]
                .wrapping_sub(self.xkey[k_idx + 3])
                .wrapping_sub(r[2] & r[1])
                .wrapping_sub(!r[2] & r[0]);

            r[2] = r[2].rotate_right(3);
            r[2] = r[2]
                .wrapping_sub(self.xkey[k_idx + 2])
                .wrapping_sub(r[1] & r[0])
                .wrapping_sub(!r[1] & r[3]);

            r[1] = r[1].rotate_right(2);
            r[1] = r[1]
                .wrapping_sub(self.xkey[k_idx + 1])
                .wrapping_sub(r[0] & r[3])
                .wrapping_sub(!r[0] & r[2]);

            r[0] = r[0].rotate_right(1);
            r[0] = r[0]
                .wrapping_sub(self.xkey[k_idx])
                .wrapping_sub(r[3] & r[2])
                .wrapping_sub(!r[3] & r[1]);
        }

        let mut out = [0u8; 8];
        for i in 0..4 {
            let bytes = r[i].to_le_bytes();
            out[i * 2] = bytes[0];
            out[i * 2 + 1] = bytes[1];
        }
        out
    }

    /// Decrypt data in CBC mode, returning the plaintext with PKCS#7 padding removed.
    pub(crate) fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 8]) -> Result<Vec<u8>, Error> {
        if data.is_empty() || !data.len().is_multiple_of(BLOCK_SIZE) {
            return Err(Error::InvalidData(
                "rc2: ciphertext must be a non-empty multiple of 8 bytes",
            ));
        }

        let mut out = Vec::with_capacity(data.len());
        let mut prev = *iv;
        for chunk in data.as_chunks::<BLOCK_SIZE>().0 {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            let current = block;
            let decrypted = self.decrypt_block(&block);
            for i in 0..BLOCK_SIZE {
                block[i] = decrypted[i] ^ prev[i];
            }
            out.extend_from_slice(&block);
            prev = current;
        }

        remove_pkcs7_padding_8(&out)
    }
}

/// Expand the key per RFC 2268 section 2.
fn expand_key(key: &[u8], effective_bits: usize) -> [u16; 64] {
    let key_len = key.len();
    let t1 = effective_bits;
    let t8 = t1.div_ceil(8);
    let tm = (255u8) >> (8 * t8 - t1);

    // Step 1: copy key bytes to L[0..key_len-1]
    let mut l = [0u8; 128];
    l[..key_len].copy_from_slice(key);

    // Step 2: expand L to 128 bytes
    for i in key_len..128 {
        let idx = (l[i - 1] as usize).wrapping_add(l[i - key_len] as usize) & 0xFF;
        l[i] = PITABLE[idx];
    }

    // Step 3: mask
    l[128 - t8] = PITABLE[l[128 - t8] as usize & (tm as usize)];

    // Step 4: fill remaining from right to left
    for i in (0..128 - t8).rev() {
        let idx = l[i + 1] as usize ^ l[i + t8] as usize;
        l[i] = PITABLE[idx];
    }

    // Step 5: convert to 16-bit words (little-endian)
    let mut xkey = [0u16; 64];
    for i in 0..64 {
        xkey[i] = u16::from_le_bytes([l[i * 2], l[i * 2 + 1]]);
    }
    xkey
}

/// Remove PKCS#7 padding for 8-byte block ciphers.
fn remove_pkcs7_padding_8(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    if pad_byte == 0 || pad_byte as usize > BLOCK_SIZE || pad_byte as usize > data.len() {
        return Err(Error::InvalidData(
            "rc2: invalid PKCS#7 padding in decrypted data",
        ));
    }
    for &b in &data[data.len() - pad_byte as usize..] {
        if b != pad_byte {
            return Err(Error::InvalidData(
                "rc2: invalid PKCS#7 padding in decrypted data",
            ));
        }
    }
    Ok(data[..data.len() - pad_byte as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 2268 section 5, test vector 1:
    /// Key = 00000000 00000000 (8 bytes), effective bits = 63
    /// Plaintext = 00000000 00000000
    /// Ciphertext = EB B7 73 F9 93 27 8E FF
    #[test]
    fn test_rc2_rfc2268_vector1() {
        let key = [0x00u8; 8];
        let rc2 = Rc2::new(&key, 63);
        let plaintext = [0x00u8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0xEB, 0xB7, 0x73, 0xF9, 0x93, 0x27, 0x8E, 0xFF]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 2:
    /// Key = FFFFFFFF FFFFFFFF (8 bytes), effective bits = 64
    /// Plaintext = FFFFFFFF FFFFFFFF
    /// Ciphertext = 27 8B 27 E4 2E 2F 0D 49
    #[test]
    fn test_rc2_rfc2268_vector2() {
        let key = [0xFFu8; 8];
        let rc2 = Rc2::new(&key, 64);
        let plaintext = [0xFFu8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x27, 0x8B, 0x27, 0xE4, 0x2E, 0x2F, 0x0D, 0x49]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 3:
    /// Key = 30000000 00000000 (8 bytes), effective bits = 64
    /// Plaintext = 10000000 00000001
    /// Ciphertext = 30 64 9E DF 9B E7 D2 C2
    #[test]
    fn test_rc2_rfc2268_vector3() {
        let key: [u8; 8] = [0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let rc2 = Rc2::new(&key, 64);
        let plaintext: [u8; 8] = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x30, 0x64, 0x9E, 0xDF, 0x9B, 0xE7, 0xD2, 0xC2]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 4:
    /// Key = 88 (1 byte), effective bits = 64
    /// Plaintext = 00000000 00000000
    /// Ciphertext = 61 A8 A2 44 AD AC CC F0
    #[test]
    fn test_rc2_rfc2268_vector4() {
        let key = [0x88u8];
        let rc2 = Rc2::new(&key, 64);
        let plaintext = [0x00u8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x61, 0xA8, 0xA2, 0x44, 0xAD, 0xAC, 0xCC, 0xF0]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 5:
    /// Key = 88bca90e 90875a (7 bytes), effective bits = 64
    /// Plaintext = 00000000 00000000
    /// Ciphertext = 6C CF 43 08 97 4C 26 7F
    #[test]
    fn test_rc2_rfc2268_vector5() {
        let key: [u8; 7] = [0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A];
        let rc2 = Rc2::new(&key, 64);
        let plaintext = [0x00u8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x6C, 0xCF, 0x43, 0x08, 0x97, 0x4C, 0x26, 0x7F]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 6:
    /// Key = 88bca90e 90875a7f 0f79c384 627bafb2 (16 bytes), effective bits = 64
    /// Plaintext = 00000000 00000000
    /// Ciphertext = 1A 80 7D 27 2B BE 5D B1
    #[test]
    fn test_rc2_rfc2268_vector6() {
        let key: [u8; 16] = [
            0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A, 0x7F, 0x0F, 0x79, 0xC3, 0x84, 0x62, 0x7B,
            0xAF, 0xB2,
        ];
        let rc2 = Rc2::new(&key, 64);
        let plaintext = [0x00u8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x1A, 0x80, 0x7D, 0x27, 0x2B, 0xBE, 0x5D, 0xB1]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// RFC 2268 section 5, test vector 7:
    /// Key = 88bca90e 90875a7f 0f79c384 627bafb2 (16 bytes), effective bits = 128
    /// Plaintext = 00000000 00000000
    /// Ciphertext = 22 69 55 2A B0 F8 5C A6
    #[test]
    fn test_rc2_rfc2268_vector7() {
        let key: [u8; 16] = [
            0x88, 0xBC, 0xA9, 0x0E, 0x90, 0x87, 0x5A, 0x7F, 0x0F, 0x79, 0xC3, 0x84, 0x62, 0x7B,
            0xAF, 0xB2,
        ];
        let rc2 = Rc2::new(&key, 128);
        let plaintext = [0x00u8; 8];
        let ciphertext = rc2.encrypt_block(&plaintext);
        assert_eq!(ciphertext, [0x22, 0x69, 0x55, 0x2A, 0xB0, 0xF8, 0x5C, 0xA6]);
        let decrypted = rc2.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc2_cbc_roundtrip() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
        let rc2 = Rc2::new(&key, 64);

        let plaintext = b"RC2 CBC test";
        let mut padded = plaintext.to_vec();
        let pad_len = BLOCK_SIZE - (padded.len() % BLOCK_SIZE);
        padded.resize(padded.len() + pad_len, pad_len as u8);

        let mut encrypted = Vec::new();
        let mut prev = iv;
        for chunk in padded.as_chunks::<BLOCK_SIZE>().0 {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            for i in 0..BLOCK_SIZE {
                block[i] ^= prev[i];
            }
            let enc = rc2.encrypt_block(&block);
            encrypted.extend_from_slice(&enc);
            prev = enc;
        }

        let decrypted = rc2.decrypt_cbc(&encrypted, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc2_cbc_empty_rejected() {
        let rc2 = Rc2::new(&[0u8; 8], 64);
        assert!(rc2.decrypt_cbc(&[], &[0u8; 8]).is_err());
    }

    #[test]
    fn test_rc2_cbc_non_aligned_rejected() {
        let rc2 = Rc2::new(&[0u8; 8], 64);
        assert!(rc2.decrypt_cbc(&[0u8; 7], &[0u8; 8]).is_err());
    }
}
