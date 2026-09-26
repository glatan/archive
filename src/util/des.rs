//! DES and Triple DES (3DES) block cipher implementation (FIPS 46-3).
//!
//! Provides:
//! - [`Des`]: single DES with 8-byte key, 8-byte block
//! - [`Des3`]: Triple DES with 16-byte (2-key) or 24-byte (3-key)
//! - CBC-mode decryption with PKCS#7 padding removal for ZIP Strong Encryption

use alloc::vec::Vec;

use crate::error::Error;

const BLOCK_SIZE: usize = 8;

/// Initial Permutation (IP) table — FIPS 46-3 §1.
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Final Permutation (IP^-1) table — FIPS 46-3 §1.
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion permutation (E) — FIPS 46-3 §1.
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// Permutation (P) applied after S-box substitution — FIPS 46-3 §1.
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

/// Permuted Choice 1 (PC-1) — FIPS 46-3 §2, key schedule.
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

/// Permuted Choice 2 (PC-2) — FIPS 46-3 §2, key schedule.
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

/// Number of left shifts per round in the key schedule.
const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// DES S-boxes (S1..S8), each 4 rows x 16 columns — FIPS 46-3 §1.
const SBOXES: [[u8; 64]; 8] = [
    // S1
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    // S2
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    // S3
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    // S4
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    // S5
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    // S6
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    // S7
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    // S8
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        2, 0, 14, 9, 11, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Convert 8 bytes to a 64-bit value (big-endian).
const fn bytes_to_u64(bytes: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*bytes)
}

/// Convert a 64-bit value to 8 bytes (big-endian).
const fn u64_to_bytes(val: u64) -> [u8; 8] {
    val.to_be_bytes()
}

/// Apply a bit permutation table. `table` entries are 1-based bit positions
/// from a `src_bits`-wide input value.
fn permute(input: u64, table: &[u8], src_bits: u32) -> u64 {
    let mut output = 0u64;
    for (i, &pos) in table.iter().enumerate() {
        // pos is 1-based; bit 1 is the MSB of the src_bits-wide value
        let bit = (input >> (src_bits - pos as u32)) & 1;
        output |= bit << (table.len() as u32 - 1 - i as u32);
    }
    output
}

/// Feistel function f(R, K) — FIPS 46-3 §1.
fn feistel(r: u32, subkey: u64) -> u32 {
    // Expand R from 32 to 48 bits
    let expanded = permute(r as u64, &E, 32);
    // XOR with subkey
    let xored = expanded ^ subkey;
    // Apply S-boxes: 48 bits → 32 bits (8 groups of 6 bits → 8 groups of 4 bits)
    let mut s_output = 0u32;
    for (i, sbox) in SBOXES.iter().enumerate() {
        let shift = (7 - i) * 6;
        let six_bits = ((xored >> shift) & 0x3F) as u8;
        // Row = bit5 * 2 + bit0, Column = bits 4..1
        let row = ((six_bits >> 5) << 1) | (six_bits & 1);
        let col = (six_bits >> 1) & 0x0F;
        let val = sbox[(row as usize) * 16 + col as usize];
        s_output |= (val as u32) << ((7 - i) * 4);
    }
    // Apply P permutation
    permute(s_output as u64, &P, 32) as u32
}

/// DES block cipher (FIPS 46-3).
#[derive(Clone)]
pub(crate) struct Des {
    subkeys: [u64; 16],
}

impl Des {
    /// Create a new DES cipher with the given 8-byte key.
    pub(crate) fn new(key: &[u8; 8]) -> Self {
        let subkeys = generate_subkeys(bytes_to_u64(key));
        Self { subkeys }
    }

    /// Encrypt a single 8-byte block.
    pub(crate) fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        des_process_block(bytes_to_u64(block), &self.subkeys, false)
    }

    /// Decrypt a single 8-byte block.
    pub(crate) fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        des_process_block(bytes_to_u64(block), &self.subkeys, true)
    }

    /// Decrypt data in CBC mode, returning the plaintext with PKCS#7 padding removed.
    pub(crate) fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 8]) -> Result<Vec<u8>, Error> {
        decrypt_cbc_8(data, iv, |block| self.decrypt_block(block))
    }
}

/// Triple DES (3DES / TDEA) cipher.
///
/// Accepts 16-byte (2-key: K1, K2, K3=K1) or 24-byte (3-key: K1, K2, K3) keys.
/// Encryption: E_K1(D_K2(E_K3(plaintext)))
/// Decryption: D_K3(E_K2(D_K1(ciphertext)))
#[derive(Clone)]
pub(crate) struct Des3 {
    k1: Des,
    k2: Des,
    k3: Des,
}

impl Des3 {
    /// Create a new 3DES cipher. `key` must be 16 or 24 bytes.
    pub(crate) fn new(key: &[u8]) -> Result<Self, Error> {
        match key.len() {
            16 => {
                let mut k1 = [0u8; 8];
                let mut k2 = [0u8; 8];
                k1.copy_from_slice(&key[..8]);
                k2.copy_from_slice(&key[8..16]);
                Ok(Self {
                    k1: Des::new(&k1),
                    k2: Des::new(&k2),
                    k3: Des::new(&k1), // 2-key: K3 = K1
                })
            }
            24 => {
                let mut k1 = [0u8; 8];
                let mut k2 = [0u8; 8];
                let mut k3 = [0u8; 8];
                k1.copy_from_slice(&key[..8]);
                k2.copy_from_slice(&key[8..16]);
                k3.copy_from_slice(&key[16..24]);
                Ok(Self {
                    k1: Des::new(&k1),
                    k2: Des::new(&k2),
                    k3: Des::new(&k3),
                })
            }
            _ => Err(Error::InvalidData("des: 3DES key must be 16 or 24 bytes")),
        }
    }

    /// Encrypt a single 8-byte block with 3DES (EDE).
    #[allow(dead_code)]
    pub(crate) fn encrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let step1 = self.k1.encrypt_block(block);
        let step2 = self.k2.decrypt_block(&step1);
        self.k3.encrypt_block(&step2)
    }

    /// Decrypt a single 8-byte block with 3DES (EDE).
    pub(crate) fn decrypt_block(&self, block: &[u8; 8]) -> [u8; 8] {
        let step1 = self.k3.decrypt_block(block);
        let step2 = self.k2.encrypt_block(&step1);
        self.k1.decrypt_block(&step2)
    }

    /// Decrypt data in CBC mode, returning the plaintext with PKCS#7 padding removed.
    pub(crate) fn decrypt_cbc(&self, data: &[u8], iv: &[u8; 8]) -> Result<Vec<u8>, Error> {
        decrypt_cbc_8(data, iv, |block| self.decrypt_block(block))
    }
}

/// Generate 16 subkeys from a 64-bit DES key.
fn generate_subkeys(key: u64) -> [u64; 16] {
    // Apply PC-1: 64 bits → 56 bits
    let pc1_out = permute(key, &PC1, 64);
    let mut c = (pc1_out >> 28) as u32 & 0x0FFF_FFFF;
    let mut d = pc1_out as u32 & 0x0FFF_FFFF;

    let mut subkeys = [0u64; 16];
    for (round, &shift) in SHIFTS.iter().enumerate() {
        for _ in 0..shift {
            c = ((c << 1) | (c >> 27)) & 0x0FFF_FFFF;
            d = ((d << 1) | (d >> 27)) & 0x0FFF_FFFF;
        }
        let cd = ((c as u64) << 28) | (d as u64);
        subkeys[round] = permute(cd, &PC2, 56);
    }
    subkeys
}

/// Process a single DES block (encrypt or decrypt).
fn des_process_block(input: u64, subkeys: &[u64; 16], decrypt: bool) -> [u8; 8] {
    // Initial permutation
    let permuted = permute(input, &IP, 64);
    let mut l = (permuted >> 32) as u32;
    let mut r = permuted as u32;

    // 16 rounds of Feistel network
    for round in 0..16 {
        let subkey = if decrypt {
            subkeys[15 - round]
        } else {
            subkeys[round]
        };
        let new_r = l ^ feistel(r, subkey);
        l = r;
        r = new_r;
    }

    // Swap and apply final permutation
    let pre_fp = ((r as u64) << 32) | (l as u64);
    u64_to_bytes(permute(pre_fp, &FP, 64))
}

/// CBC-mode decryption with 8-byte blocks and PKCS#7 padding removal.
fn decrypt_cbc_8(
    data: &[u8],
    iv: &[u8; 8],
    decrypt_fn: impl Fn(&[u8; 8]) -> [u8; 8],
) -> Result<Vec<u8>, Error> {
    if data.is_empty() || !data.len().is_multiple_of(BLOCK_SIZE) {
        return Err(Error::InvalidData(
            "des: ciphertext must be a non-empty multiple of 8 bytes",
        ));
    }

    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.as_chunks::<BLOCK_SIZE>().0 {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        let current = block;
        let decrypted = decrypt_fn(&block);
        for i in 0..BLOCK_SIZE {
            block[i] = decrypted[i] ^ prev[i];
        }
        out.extend_from_slice(&block);
        prev = current;
    }

    remove_pkcs7_padding_8(&out)
}

/// Remove PKCS#7 padding for 8-byte block ciphers.
fn remove_pkcs7_padding_8(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    if pad_byte == 0 || pad_byte as usize > BLOCK_SIZE || pad_byte as usize > data.len() {
        return Err(Error::InvalidData(
            "des: invalid PKCS#7 padding in decrypted data",
        ));
    }
    for &b in &data[data.len() - pad_byte as usize..] {
        if b != pad_byte {
            return Err(Error::InvalidData(
                "des: invalid PKCS#7 padding in decrypted data",
            ));
        }
    }
    Ok(data[..data.len() - pad_byte as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_des_known_vector_1() {
        // OpenSSL-verified: Key=0133457799BBCDFF, PT=0123456789ABCDEF
        let key: [u8; 8] = [0x01, 0x33, 0x45, 0x77, 0x99, 0xBB, 0xCD, 0xFF];
        let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let expected: [u8; 8] = [0x1E, 0xD2, 0xCD, 0x64, 0x84, 0x90, 0x78, 0xB9];

        let des = Des::new(&key);
        let ciphertext = des.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected);

        let decrypted = des.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_des_known_vector_2() {
        // Well-known DES test: Key=0E329232EA6D0D73, PT=8787878787878787, CT=0000000000000000
        let key: [u8; 8] = [0x0E, 0x32, 0x92, 0x32, 0xEA, 0x6D, 0x0D, 0x73];
        let plaintext: [u8; 8] = [0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87];
        let expected: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let des = Des::new(&key);
        let ciphertext = des.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected);

        let decrypted = des.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_des_roundtrip() {
        let key = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        let des = Des::new(&key);
        let plaintext: [u8; 8] = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let ciphertext = des.encrypt_block(&plaintext);
        assert_ne!(ciphertext, plaintext);
        let decrypted = des.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_3des_24byte_key_roundtrip() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let des3 = Des3::new(&key).unwrap();
        let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ciphertext = des3.encrypt_block(&plaintext);
        assert_ne!(ciphertext, plaintext);
        let decrypted = des3.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_3des_16byte_key_roundtrip() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let des3 = Des3::new(&key).unwrap();
        let plaintext: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let ciphertext = des3.encrypt_block(&plaintext);
        assert_ne!(ciphertext, plaintext);
        let decrypted = des3.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_3des_invalid_key_size() {
        assert!(Des3::new(&[0u8; 12]).is_err());
        assert!(Des3::new(&[0u8; 8]).is_err());
    }

    #[test]
    fn test_des_cbc_roundtrip() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
        let des = Des::new(&key);

        // Encrypt with CBC manually
        let plaintext = b"hello!!"; // 7 bytes, will be padded to 8
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
            let enc = des.encrypt_block(&block);
            encrypted.extend_from_slice(&enc);
            prev = enc;
        }

        let decrypted = des.decrypt_cbc(&encrypted, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_3des_cbc_roundtrip() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        ];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
        let des3 = Des3::new(&key).unwrap();

        let plaintext = b"3DES CBC test data padding!!"; // 28 bytes
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
            let enc = des3.encrypt_block(&block);
            encrypted.extend_from_slice(&enc);
            prev = enc;
        }

        let decrypted = des3.decrypt_cbc(&encrypted, &iv).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbc_empty_data_rejected() {
        let des = Des::new(&[0u8; 8]);
        assert!(des.decrypt_cbc(&[], &[0u8; 8]).is_err());
    }

    #[test]
    fn test_cbc_non_aligned_data_rejected() {
        let des = Des::new(&[0u8; 8]);
        assert!(des.decrypt_cbc(&[0u8; 7], &[0u8; 8]).is_err());
    }
}
