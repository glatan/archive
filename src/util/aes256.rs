//! Minimal AES helpers for archive formats that need in-crate crypto.
//!
//! This implementation is not constant-time: the inverse S-box uses a
//! data-dependent exhaustive search and the GF(2^8) helpers loop on
//! data-dependent conditions. It exists for legacy format
//! interoperability (WinZip AES (0x9901), 7z AES, and PEA AES-EAX) and is
//! not suitable where timing side channels are a concern.

use alloc::vec::Vec;

use crate::error::Error;

const BLOCK_SIZE: usize = 16;
#[cfg(any(feature = "zip", feature = "pea"))]
const RCON_AES128: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
#[cfg(feature = "zip")]
const RCON_AES192: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
const RCON_AES256: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

macro_rules! define_aes_cipher {
    ($name:ident, $key_len:expr, $nk:expr, $nr:expr, $rcon:ident) => {
        #[derive(Clone)]
        pub(crate) struct $name {
            round_keys: [[u8; BLOCK_SIZE]; $nr + 1],
        }

        impl $name {
            pub(crate) fn new(key: &[u8; $key_len]) -> Self {
                const NK: usize = $nk;
                const NR: usize = $nr;
                const EXPANDED_WORDS: usize = 4 * (NR + 1);

                let mut words = [[0u8; 4]; EXPANDED_WORDS];
                for i in 0..NK {
                    words[i].copy_from_slice(&key[i * 4..(i + 1) * 4]);
                }
                for i in NK..EXPANDED_WORDS {
                    let mut temp = words[i - 1];
                    if i % NK == 0 {
                        temp = sub_word(rot_word(temp));
                        temp[0] ^= $rcon[(i / NK) - 1];
                    } else if NK > 6 && i % NK == 4 {
                        temp = sub_word(temp);
                    }
                    words[i] = xor_word(words[i - NK], temp);
                }

                let mut round_keys = [[0u8; BLOCK_SIZE]; NR + 1];
                for round in 0..=NR {
                    for col in 0..4 {
                        round_keys[round][col * 4..(col + 1) * 4]
                            .copy_from_slice(&words[round * 4 + col]);
                    }
                }

                Self { round_keys }
            }

            #[allow(dead_code)]
            pub(crate) fn encrypt_cbc_zero_padded(
                &self,
                plaintext: &[u8],
                iv: &[u8; BLOCK_SIZE],
            ) -> Vec<u8> {
                let blocks = plaintext.len().div_ceil(BLOCK_SIZE);
                let mut out = Vec::with_capacity(blocks * BLOCK_SIZE);
                let mut prev = *iv;
                for chunk in plaintext.chunks(BLOCK_SIZE) {
                    let mut block = [0u8; BLOCK_SIZE];
                    block[..chunk.len()].copy_from_slice(chunk);
                    xor_in_place(&mut block, &prev);
                    self.encrypt_block(&mut block);
                    out.extend_from_slice(&block);
                    prev = block;
                }
                out
            }

            #[allow(dead_code)]
            pub(crate) fn decrypt_cbc_truncated(
                &self,
                ciphertext: &[u8],
                iv: &[u8; BLOCK_SIZE],
                expected_len: usize,
            ) -> Result<Vec<u8>, Error> {
                if !ciphertext.len().is_multiple_of(BLOCK_SIZE) {
                    return Err(Error::InvalidData(
                        "7z: AES packed stream size must be a multiple of 16 bytes",
                    ));
                }
                if expected_len > ciphertext.len() {
                    return Err(Error::SizeMismatch {
                        expected: expected_len as u32,
                        actual: ciphertext.len() as u32,
                    });
                }

                let mut out = Vec::with_capacity(ciphertext.len());
                let mut prev = *iv;
                for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
                    let mut block = [0u8; BLOCK_SIZE];
                    block.copy_from_slice(chunk);
                    let current = block;
                    self.decrypt_block(&mut block);
                    xor_in_place(&mut block, &prev);
                    out.extend_from_slice(&block);
                    prev = current;
                }
                out.truncate(expected_len);
                Ok(out)
            }

            #[cfg_attr(not(feature = "zip"), allow(dead_code))]
            pub(crate) fn apply_ctr_zip_compatible(&self, data: &[u8]) -> Vec<u8> {
                let mut out = Vec::with_capacity(data.len());
                let mut nonce = [0u8; BLOCK_SIZE];

                for chunk in data.chunks(BLOCK_SIZE) {
                    increment_zip_ctr(&mut nonce);
                    let mut keystream = nonce;
                    self.encrypt_block(&mut keystream);

                    let mut block = [0u8; BLOCK_SIZE];
                    for (index, &byte) in chunk.iter().enumerate() {
                        block[index] = byte ^ keystream[index];
                    }
                    out.extend_from_slice(&block[..chunk.len()]);
                }

                out
            }

            pub(crate) fn encrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                const NR: usize = $nr;
                add_round_key(block, &self.round_keys[0]);
                for round in 1..NR {
                    sub_bytes(block);
                    shift_rows(block);
                    mix_columns(block);
                    add_round_key(block, &self.round_keys[round]);
                }
                sub_bytes(block);
                shift_rows(block);
                add_round_key(block, &self.round_keys[NR]);
            }

            #[allow(dead_code)]
            fn decrypt_block(&self, block: &mut [u8; BLOCK_SIZE]) {
                const NR: usize = $nr;
                add_round_key(block, &self.round_keys[NR]);
                for round in (1..NR).rev() {
                    inv_shift_rows(block);
                    inv_sub_bytes(block);
                    add_round_key(block, &self.round_keys[round]);
                    inv_mix_columns(block);
                }
                inv_shift_rows(block);
                inv_sub_bytes(block);
                add_round_key(block, &self.round_keys[0]);
            }
        }
    };
}

#[cfg(any(feature = "zip", feature = "pea"))]
define_aes_cipher!(Aes128, 16, 4, 10, RCON_AES128);
#[cfg(feature = "zip")]
define_aes_cipher!(Aes192, 24, 6, 12, RCON_AES192);
define_aes_cipher!(Aes256, 32, 8, 14, RCON_AES256);

#[inline]
const fn xor_word(a: [u8; 4], b: [u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline]
const fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

#[inline]
const fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [sbox(word[0]), sbox(word[1]), sbox(word[2]), sbox(word[3])]
}

#[inline]
fn add_round_key(state: &mut [u8; BLOCK_SIZE], round_key: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        state[i] ^= round_key[i];
    }
}

fn sub_bytes(state: &mut [u8; BLOCK_SIZE]) {
    for byte in state.iter_mut() {
        *byte = sbox(*byte);
    }
}

fn inv_sub_bytes(state: &mut [u8; BLOCK_SIZE]) {
    for byte in state.iter_mut() {
        *byte = inv_sbox(*byte);
    }
}

fn shift_rows(state: &mut [u8; BLOCK_SIZE]) {
    let original = *state;
    for row in 0..4 {
        for col in 0..4 {
            state[col * 4 + row] = original[((col + row) % 4) * 4 + row];
        }
    }
}

fn inv_shift_rows(state: &mut [u8; BLOCK_SIZE]) {
    let original = *state;
    for row in 0..4 {
        for col in 0..4 {
            state[col * 4 + row] = original[((col + 4 - row) % 4) * 4 + row];
        }
    }
}

fn mix_columns(state: &mut [u8; BLOCK_SIZE]) {
    for col in 0..4 {
        let i = col * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; BLOCK_SIZE]) {
    for col in 0..4 {
        let i = col * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        state[i + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        state[i + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        state[i + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

#[inline]
fn xor_in_place(block: &mut [u8; BLOCK_SIZE], with: &[u8; BLOCK_SIZE]) {
    for i in 0..BLOCK_SIZE {
        block[i] ^= with[i];
    }
}

#[cfg_attr(not(feature = "zip"), allow(dead_code))]
const fn increment_zip_ctr(counter: &mut [u8; BLOCK_SIZE]) {
    let mut index = 0usize;
    while index < 8 {
        counter[index] = counter[index].wrapping_add(1);
        if counter[index] != 0 {
            break;
        }
        index += 1;
    }
}

const fn sbox(byte: u8) -> u8 {
    affine(gf_inv(byte))
}

fn inv_sbox(byte: u8) -> u8 {
    for candidate in 0..=u8::MAX {
        if sbox(candidate) == byte {
            return candidate;
        }
    }
    0
}

#[inline]
const fn gf_inv(byte: u8) -> u8 {
    if byte == 0 { 0 } else { gf_pow(byte, 254) }
}

const fn gf_pow(mut base: u8, mut exp: u16) -> u8 {
    let mut result = 1u8;
    while exp != 0 {
        if exp & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

#[inline]
const fn affine(byte: u8) -> u8 {
    byte ^ byte.rotate_left(1)
        ^ byte.rotate_left(2)
        ^ byte.rotate_left(3)
        ^ byte.rotate_left(4)
        ^ 0x63
}

const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_block_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let cipher = Aes256::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49,
                0x60, 0x89,
            ]
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ]
        );
    }

    #[test]
    fn test_cbc_roundtrip_zero_padding() {
        let key = [0x42; 32];
        let iv = [0x24; BLOCK_SIZE];
        let cipher = Aes256::new(&key);
        let plaintext = b"aes-cbc zero padded payload";
        let encrypted = cipher.encrypt_cbc_zero_padded(plaintext, &iv);
        let decrypted = cipher
            .decrypt_cbc_truncated(&encrypted, &iv, plaintext.len())
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_roundtrip() {
        let key = [0x11; 32];
        let cipher = Aes256::new(&key);
        let plaintext = b"zip aes ctr payload";
        let encrypted = cipher.apply_ctr_zip_compatible(plaintext);
        assert_ne!(encrypted, plaintext);
        let decrypted = cipher.apply_ctr_zip_compatible(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_ctr_roundtrip() {
        let key = [0x22; 16];
        let cipher = Aes128::new(&key);
        let plaintext = b"zip aes128 ctr payload";
        let encrypted = cipher.apply_ctr_zip_compatible(plaintext);
        assert_ne!(encrypted, plaintext);
        let decrypted = cipher.apply_ctr_zip_compatible(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes192_ctr_roundtrip() {
        let key = [0x33; 24];
        let cipher = Aes192::new(&key);
        let plaintext = b"zip aes192 ctr payload";
        let encrypted = cipher.apply_ctr_zip_compatible(plaintext);
        assert_ne!(encrypted, plaintext);
        let decrypted = cipher.apply_ctr_zip_compatible(&encrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_block_vector() {
        // FIPS 197 example vector for AES-128.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let cipher = Aes128::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4,
                0xC5, 0x5A,
            ]
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ]
        );
    }

    #[test]
    fn test_aes192_block_vector() {
        // FIPS 197 example vector for AES-192.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ];
        let cipher = Aes192::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        cipher.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0, 0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D,
                0x71, 0x91,
            ]
        );
        cipher.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ]
        );
    }

    #[test]
    fn test_cbc_rejects_non_block_multiple() {
        let key = [0x42; 32];
        let iv = [0; BLOCK_SIZE];
        let cipher = Aes256::new(&key);
        for len in [1usize, 15, 17, 31] {
            let ciphertext = alloc::vec![0u8; len];
            assert!(
                matches!(
                    cipher.decrypt_cbc_truncated(&ciphertext, &iv, 0),
                    Err(Error::InvalidData(_))
                ),
                "len {len} must be rejected"
            );
        }
        // Exactly one block is accepted.
        assert!(cipher.decrypt_cbc_truncated(&[0u8; 16], &iv, 0).is_ok());
    }

    #[test]
    fn test_cbc_rejects_expected_len_beyond_ciphertext() {
        let key = [0x42; 32];
        let iv = [0; BLOCK_SIZE];
        let cipher = Aes256::new(&key);
        let ciphertext = [0u8; 32];
        assert!(matches!(
            cipher.decrypt_cbc_truncated(&ciphertext, &iv, 33),
            Err(Error::SizeMismatch { .. })
        ));
        // Boundary: expected_len == ciphertext.len() is accepted.
        assert!(cipher.decrypt_cbc_truncated(&ciphertext, &iv, 32).is_ok());
    }

    #[test]
    fn test_cbc_empty_plaintext() {
        let key = [0x42; 32];
        let iv = [0; BLOCK_SIZE];
        let cipher = Aes256::new(&key);
        let encrypted = cipher.encrypt_cbc_zero_padded(b"", &iv);
        assert!(encrypted.is_empty());
        assert_eq!(
            cipher.decrypt_cbc_truncated(&encrypted, &iv, 0).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn test_ctr_block_boundary() {
        let key = [0x11; 32];
        let cipher = Aes256::new(&key);
        for len in [15usize, 16, 17, 31, 32, 33] {
            let plaintext = alloc::vec![0xA5u8; len];
            let encrypted = cipher.apply_ctr_zip_compatible(&plaintext);
            // CTR is a stream cipher: ciphertext length == plaintext length.
            assert_eq!(encrypted.len(), len);
            assert_eq!(
                cipher.apply_ctr_zip_compatible(&encrypted),
                plaintext,
                "len {len}"
            );
        }
    }

    #[test]
    fn test_ctr_empty() {
        let key = [0x11; 32];
        let cipher = Aes256::new(&key);
        assert!(cipher.apply_ctr_zip_compatible(b"").is_empty());
    }
}
