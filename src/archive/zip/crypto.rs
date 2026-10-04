use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::util::aes256::{Aes128, Aes192, Aes256};
use crate::util::crc32::Crc32;
use crate::util::sha1::{Sha1, sha1};

pub(crate) const ZIP_STRONG_ENCRYPTION_EXTRA_FIELD_ID: u16 = 0x0017;

pub(crate) const ZIP_AES_EXTRA_FIELD_ID: u16 = 0x9901;
pub(crate) const ZIP_AES_METHOD: u16 = 99;
pub(crate) const ZIP_AES_VENDOR_VERSION_AE1: u16 = 0x0001;
pub(crate) const ZIP_AES_AUTH_CODE_LEN: usize = 10;
pub(crate) const ZIP_AES_PASSWORD_VERIFY_LEN: usize = 2;
pub(crate) const ZIP_TRADITIONAL_HEADER_LEN: usize = 12;
const ZIP_AES_VENDOR_ID: [u8; 2] = *b"AE";
const HMAC_BLOCK_SIZE: usize = 64;
const PBKDF2_ITERATIONS: u32 = 1000;

static ZIP_AES_SALT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZipAesExtraField {
    pub(crate) vendor_version: u16,
    pub(crate) strength: ZipAesStrength,
    pub(crate) actual_compression_method: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZipAesStrength {
    #[default]
    Aes256,
    Aes128,
    Aes192,
}

impl ZipAesStrength {
    const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    const fn salt_len(self) -> usize {
        match self {
            Self::Aes128 => 8,
            Self::Aes192 => 12,
            Self::Aes256 => 16,
        }
    }

    const fn encoded(self) -> u8 {
        match self {
            Self::Aes128 => 0x01,
            Self::Aes192 => 0x02,
            Self::Aes256 => 0x03,
        }
    }

    const fn from_encoded(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(Self::Aes128),
            0x02 => Ok(Self::Aes192),
            0x03 => Ok(Self::Aes256),
            _ => Err(Error::Unsupported("zip: unsupported AES strength")),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ZipAesEncodedPayload {
    pub(crate) extra: ZipAesExtraField,
    pub(crate) payload: Vec<u8>,
}

/// Parsed Strong Encryption Header from extra field 0x0017 (APPNOTE §7).
///
/// Strong Encryption decryption is intentionally not implemented: APPNOTE
/// §10.1 states that implementing the strong-encryption technology requires
/// a separate license agreement from PKWARE (patent-encumbered; see
/// THIRD_PARTY_NOTICES). This header is parsed only to identify the
/// algorithm for error reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrongEncryptionHeader {
    /// Format version (expected: 2).
    pub(crate) format: u16,
    /// Encryption algorithm ID.
    pub(crate) alg_id: u16,
    /// Key bit length.
    pub(crate) bitlen: u16,
    /// Flags: 0x0001 = password, 0x0002 = certificate, 0x0003 = either.
    pub(crate) flags: u16,
}

impl StrongEncryptionHeader {
    /// Return a human-readable name for the encryption algorithm.
    pub(crate) const fn algorithm_name(&self) -> &'static str {
        match self.alg_id {
            0x6601 => "DES",
            0x6602 => "RC2 (need version < 5.2)",
            0x6603 => "3DES 168",
            0x6609 => "3DES 112",
            0x660E => "AES-128",
            0x660F => "AES-192",
            0x6610 => "AES-256",
            0x6702 => "RC2 (need version >= 5.2)",
            0x6720 => "Blowfish",
            0x6721 => "Twofish",
            0x6801 => "RC4",
            _ => "Unknown",
        }
    }
}

/// Parse the Strong Encryption Header from Central Directory extra field 0x0017
/// (APPNOTE §4.5.12, §7). Detection only — decryption is not implemented.
pub(crate) fn parse_strong_encryption_extra(
    extra: &[u8],
) -> Result<Option<StrongEncryptionHeader>, Error> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if pos + size > extra.len() {
            return Err(Error::UnexpectedEof);
        }
        if header_id == ZIP_STRONG_ENCRYPTION_EXTRA_FIELD_ID {
            // Minimum: Format(2) + AlgID(2) + Bitlen(2) + Flags(2) = 8 bytes
            if size < 8 {
                return Err(Error::InvalidData(
                    "zip: strong encryption extra field too short",
                ));
            }
            let format = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
            let alg_id = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]);
            let bitlen = u16::from_le_bytes([extra[pos + 4], extra[pos + 5]]);
            let flags = u16::from_le_bytes([extra[pos + 6], extra[pos + 7]]);
            return Ok(Some(StrongEncryptionHeader {
                format,
                alg_id,
                bitlen,
                flags,
            }));
        }
        pos += size;
    }
    Ok(None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraditionalZipCrypto {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl TraditionalZipCrypto {
    const fn new() -> Self {
        Self {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        }
    }

    fn from_password(password: &[u8]) -> Self {
        let mut state = Self::new();
        for &byte in password {
            state.update(byte);
        }
        state
    }

    fn update(&mut self, byte: u8) {
        self.key0 = crc32_update_raw(self.key0, byte);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xFF)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.key2 = crc32_update_raw(self.key2, (self.key1 >> 24) as u8);
    }

    const fn decrypt_byte(&self) -> u8 {
        let temp = self.key2 | 2;
        (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(plaintext.len());
        for &byte in plaintext {
            let encrypted = byte ^ self.decrypt_byte();
            self.update(byte);
            output.push(encrypted);
        }
        output
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(ciphertext.len());
        for &byte in ciphertext {
            let plaintext = byte ^ self.decrypt_byte();
            self.update(plaintext);
            output.push(plaintext);
        }
        output
    }
}

pub(crate) fn encode_aes_payload(
    password: &[u8],
    compressed_data: &[u8],
    actual_compression_method: u16,
    salt_seed: &[u8],
    strength: ZipAesStrength,
) -> Result<ZipAesEncodedPayload, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData("zip: empty AES password"));
    }

    let salt = generate_salt(strength.salt_len(), salt_seed);
    let derived = derive_keys(password, &salt, strength)?;
    let ciphertext = apply_zip_aes_ctr(&derived.encryption_key, strength, compressed_data)?;
    let auth_code = hmac_sha1(&derived.authentication_key, &ciphertext);

    let mut payload = Vec::with_capacity(
        salt.len() + ZIP_AES_PASSWORD_VERIFY_LEN + ciphertext.len() + ZIP_AES_AUTH_CODE_LEN,
    );
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&derived.password_verifier);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&auth_code[..ZIP_AES_AUTH_CODE_LEN]);

    Ok(ZipAesEncodedPayload {
        extra: ZipAesExtraField {
            vendor_version: ZIP_AES_VENDOR_VERSION_AE1,
            strength,
            actual_compression_method,
        },
        payload,
    })
}

pub(crate) fn decode_aes_payload(
    password: &[u8],
    encrypted_data: &[u8],
    extra: ZipAesExtraField,
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData("zip: empty AES password"));
    }
    if extra.vendor_version > 2 {
        return Err(Error::Unsupported("zip: AES vendor version > 2 (AE-3+)"));
    }
    if extra.vendor_version == 0 {
        return Err(Error::InvalidData("zip: invalid AES vendor version 0"));
    }
    let salt_len = extra.strength.salt_len();
    let minimum_len = salt_len + ZIP_AES_PASSWORD_VERIFY_LEN + ZIP_AES_AUTH_CODE_LEN;
    if encrypted_data.len() < minimum_len {
        return Err(Error::UnexpectedEof);
    }

    let salt = &encrypted_data[..salt_len];
    let verifier_pos = salt_len;
    let verifier = &encrypted_data[verifier_pos..verifier_pos + ZIP_AES_PASSWORD_VERIFY_LEN];
    let auth_code_pos = encrypted_data.len() - ZIP_AES_AUTH_CODE_LEN;
    let ciphertext = &encrypted_data[verifier_pos + ZIP_AES_PASSWORD_VERIFY_LEN..auth_code_pos];
    let auth_code = &encrypted_data[auth_code_pos..];

    let derived = derive_keys(password, salt, extra.strength)?;
    if verifier != derived.password_verifier {
        return Err(Error::InvalidData("zip: invalid AES password"));
    }

    let expected_auth = hmac_sha1(&derived.authentication_key, ciphertext);
    if auth_code != &expected_auth[..ZIP_AES_AUTH_CODE_LEN] {
        return Err(Error::InvalidData("zip: AES authentication code mismatch"));
    }

    apply_zip_aes_ctr(&derived.encryption_key, extra.strength, ciphertext)
}

pub(crate) fn encode_traditional_payload(
    password: &[u8],
    compressed_data: &[u8],
    crc32: u32,
    mod_time: u16,
    use_data_descriptor: bool,
    seed_material: &[u8],
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData("zip: empty traditional password"));
    }

    let mut header = generate_salt(ZIP_TRADITIONAL_HEADER_LEN, seed_material);
    header[ZIP_TRADITIONAL_HEADER_LEN - 1] =
        traditional_verifier(crc32, mod_time, use_data_descriptor);

    let mut crypto = TraditionalZipCrypto::from_password(password);
    let encrypted_header = crypto.encrypt(&header);
    let encrypted_payload = crypto.encrypt(compressed_data);
    let mut output = Vec::with_capacity(ZIP_TRADITIONAL_HEADER_LEN + encrypted_payload.len());
    output.extend_from_slice(&encrypted_header);
    output.extend_from_slice(&encrypted_payload);
    Ok(output)
}

pub(crate) fn decode_traditional_payload(
    password: &[u8],
    encrypted_data: &[u8],
    crc32: u32,
    mod_time: u16,
    use_data_descriptor: bool,
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData("zip: empty traditional password"));
    }
    if encrypted_data.len() < ZIP_TRADITIONAL_HEADER_LEN {
        return Err(Error::UnexpectedEof);
    }

    let mut crypto = TraditionalZipCrypto::from_password(password);
    let header = crypto.decrypt(&encrypted_data[..ZIP_TRADITIONAL_HEADER_LEN]);
    let expected_verifier = traditional_verifier(crc32, mod_time, use_data_descriptor);
    if header[ZIP_TRADITIONAL_HEADER_LEN - 1] != expected_verifier {
        return Err(Error::InvalidData("zip: invalid traditional password"));
    }
    Ok(crypto.decrypt(&encrypted_data[ZIP_TRADITIONAL_HEADER_LEN..]))
}

pub(crate) fn append_aes_extra_field(output: &mut Vec<u8>, extra: ZipAesExtraField) {
    output.extend_from_slice(&ZIP_AES_EXTRA_FIELD_ID.to_le_bytes());
    output.extend_from_slice(&7u16.to_le_bytes());
    output.extend_from_slice(&extra.vendor_version.to_le_bytes());
    output.extend_from_slice(&ZIP_AES_VENDOR_ID);
    output.push(extra.strength.encoded());
    output.extend_from_slice(&extra.actual_compression_method.to_le_bytes());
}

pub(crate) fn parse_aes_extra_field(extra: &[u8]) -> Result<Option<ZipAesExtraField>, Error> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let size = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        pos += 4;
        if pos + size > extra.len() {
            return Err(Error::UnexpectedEof);
        }
        if header_id == ZIP_AES_EXTRA_FIELD_ID {
            if size != 7 {
                return Err(Error::InvalidData("zip: invalid AES extra field"));
            }
            let vendor_version = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
            if extra[pos + 2..pos + 4] != ZIP_AES_VENDOR_ID {
                return Err(Error::InvalidData("zip: invalid AES vendor"));
            }
            let strength = ZipAesStrength::from_encoded(extra[pos + 4])?;
            let actual_compression_method = u16::from_le_bytes([extra[pos + 5], extra[pos + 6]]);
            return Ok(Some(ZipAesExtraField {
                vendor_version,
                strength,
                actual_compression_method,
            }));
        }
        pos += size;
    }
    Ok(None)
}

struct DerivedKeys {
    encryption_key: Vec<u8>,
    authentication_key: Vec<u8>,
    password_verifier: [u8; 2],
}

fn derive_keys(
    password: &[u8],
    salt: &[u8],
    strength: ZipAesStrength,
) -> Result<DerivedKeys, Error> {
    let key_len = strength.key_len();
    let mut derived = pbkdf2_hmac_sha1(
        password,
        salt,
        PBKDF2_ITERATIONS,
        key_len + key_len + ZIP_AES_PASSWORD_VERIFY_LEN,
    );
    if derived.len() != key_len * 2 + ZIP_AES_PASSWORD_VERIFY_LEN {
        return Err(Error::InvalidData("zip: invalid derived key length"));
    }

    let encryption_key = derived[..key_len].to_vec();
    let authentication_key = derived[key_len..key_len * 2].to_vec();
    let mut password_verifier = [0u8; 2];
    password_verifier.copy_from_slice(&derived[key_len * 2..key_len * 2 + 2]);
    derived.fill(0);

    Ok(DerivedKeys {
        encryption_key,
        authentication_key,
        password_verifier,
    })
}

fn apply_zip_aes_ctr(
    encryption_key: &[u8],
    strength: ZipAesStrength,
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    match strength {
        ZipAesStrength::Aes128 => {
            let key: [u8; 16] = encryption_key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: invalid AES-128 key length"))?;
            Ok(Aes128::new(&key).apply_ctr_zip_compatible(data))
        }
        ZipAesStrength::Aes192 => {
            let key: [u8; 24] = encryption_key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: invalid AES-192 key length"))?;
            Ok(Aes192::new(&key).apply_ctr_zip_compatible(data))
        }
        ZipAesStrength::Aes256 => {
            let key: [u8; 32] = encryption_key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: invalid AES-256 key length"))?;
            Ok(Aes256::new(&key).apply_ctr_zip_compatible(data))
        }
    }
}

pub(crate) fn pbkdf2_hmac_sha1(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Vec<u8> {
    let blocks = output_len.div_ceil(20);
    let mut output = Vec::with_capacity(blocks * 20);
    for block_index in 1..=blocks {
        let mut input = Vec::with_capacity(salt.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(&(block_index as u32).to_be_bytes());

        let mut u = hmac_sha1(password, &input);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for (acc, value) in t.iter_mut().zip(u.iter()) {
                *acc ^= *value;
            }
        }
        output.extend_from_slice(&t);
    }
    output.truncate(output_len);
    output
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut actual_key = [0u8; HMAC_BLOCK_SIZE];
    if key.len() > HMAC_BLOCK_SIZE {
        actual_key[..20].copy_from_slice(&sha1(key));
    } else {
        actual_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut outer_pad = [0x5Cu8; HMAC_BLOCK_SIZE];
    for index in 0..HMAC_BLOCK_SIZE {
        inner_pad[index] ^= actual_key[index];
        outer_pad[index] ^= actual_key[index];
    }

    let mut inner = Sha1::new();
    inner.update(&inner_pad);
    inner.update(data);
    let inner_digest = inner.finish();

    let mut outer = Sha1::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finish()
}

fn generate_salt(len: usize, seed_material: &[u8]) -> Vec<u8> {
    let mut salt = vec![0u8; len];
    if fill_os_random(&mut salt) {
        return salt;
    }

    let counter = ZIP_AES_SALT_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1);
    let mut block = 0u32;
    let mut written = 0usize;
    while written < salt.len() {
        let mut hasher = Sha1::new();
        hasher.update(&counter.to_le_bytes());
        hasher.update(&block.to_le_bytes());
        hasher.update(seed_material);
        let digest = hasher.finish();
        let take = (salt.len() - written).min(digest.len());
        salt[written..written + take].copy_from_slice(&digest[..take]);
        written += take;
        block = block.wrapping_add(1);
    }
    salt
}

const fn traditional_verifier(crc32: u32, mod_time: u16, use_data_descriptor: bool) -> u8 {
    if use_data_descriptor {
        (mod_time >> 8) as u8
    } else {
        (crc32 >> 24) as u8
    }
}

fn crc32_update_raw(raw: u32, byte: u8) -> u32 {
    let mut crc = Crc32::from_raw(raw);
    crc.update(&[byte]);
    crc.finish_raw()
}

#[cfg(feature = "std")]
fn fill_os_random(buffer: &mut [u8]) -> bool {
    use std::fs::File;
    use std::io::Read;

    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(buffer))
        .is_ok()
}

#[cfg(not(feature = "std"))]
fn fill_os_random(_buffer: &mut [u8]) -> bool {
    false
}

/// Parsed Archive Decryption Header (APPNOTE §4.3.10).
///
/// This header appears before the Central Directory when Central Directory
/// Encryption is in effect. Its structure is:
///
/// - Format (2B)
/// - AlgID (2B)
/// - Bitlen (2B)
/// - Flags (2B)
/// - ErdSize (2B) + ErdData (variable)
/// - Reserved1 (4B)
/// - VSize (2B) + VData (variable)
/// - VCRC32 (4B)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveDecryptionHeader {
    /// Format version.
    pub(crate) format: u16,
    /// Encryption algorithm ID.
    pub(crate) alg_id: u16,
    /// Key bit length.
    pub(crate) bitlen: u16,
    /// Flags.
    pub(crate) flags: u16,
    /// Encrypted random data.
    pub(crate) erd_data: Vec<u8>,
    /// Total bytes consumed from the input.
    pub(crate) header_size: usize,
}

/// Parse the Archive Decryption Header (APPNOTE §4.3.10).
///
/// This header has no signature. It appears at a known position (pointed to by
/// the EOCD cd_offset when CD encryption is active, before the actual CD data).
///
/// Returns the parsed header and the total number of bytes consumed.
pub(crate) fn parse_archive_decryption_header(
    data: &[u8],
) -> Result<(ArchiveDecryptionHeader, usize), Error> {
    if data.len() < 12 {
        return Err(Error::UnexpectedEof);
    }
    let mut pos = 0usize;

    // Format (2B)
    let format = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    // AlgID (2B)
    let alg_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    // Bitlen (2B)
    let bitlen = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    // Flags (2B)
    let flags = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // ErdSize (2B) + ErdData
    if pos + 2 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let erd_size = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + erd_size > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let erd_data = data[pos..pos + erd_size].to_vec();
    pos += erd_size;

    // Reserved1 (4B)
    if pos + 4 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    pos += 4;

    // VSize (2B) + VData (variable) + VCRC32 (4B)
    if pos + 2 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let v_size = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + v_size + 4 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    pos += v_size; // VData
    pos += 4; // VCRC32

    Ok((
        ArchiveDecryptionHeader {
            format,
            alg_id,
            bitlen,
            flags,
            erd_data,
            header_size: pos,
        },
        pos,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1_vector() {
        let digest = hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            digest,
            [
                0xDE, 0x7C, 0x9B, 0x85, 0xB8, 0xB7, 0x8A, 0xA6, 0xBC, 0x8A, 0x7A, 0x36, 0xF7, 0x0A,
                0x90, 0x70, 0x1C, 0x9D, 0xB4, 0xD9,
            ]
        );
    }

    #[test]
    fn test_pbkdf2_sha1_vector() {
        let derived = pbkdf2_hmac_sha1(b"password", b"salt", 1, 20);
        assert_eq!(
            derived,
            vec![
                0x0C, 0x60, 0xC8, 0x0F, 0x96, 0x1F, 0x0E, 0x71, 0xF3, 0xA9, 0xB5, 0x24, 0xAF, 0x60,
                0x12, 0x06, 0x2F, 0xE0, 0x37, 0xA6,
            ]
        );
    }

    #[test]
    fn test_zip_aes_roundtrip() {
        let encoded =
            encode_aes_payload(b"secret", b"payload", 8, b"name", ZipAesStrength::Aes256).unwrap();
        let decoded = decode_aes_payload(b"secret", &encoded.payload, encoded.extra).unwrap();
        assert_eq!(decoded, b"payload");
        assert!(matches!(
            decode_aes_payload(b"wrong", &encoded.payload, encoded.extra),
            Err(Error::InvalidData("zip: invalid AES password"))
        ));
    }

    #[test]
    fn test_zip_aes_strengths_roundtrip() {
        for strength in [
            ZipAesStrength::Aes128,
            ZipAesStrength::Aes192,
            ZipAesStrength::Aes256,
        ] {
            let encoded = encode_aes_payload(b"secret", b"payload", 8, b"name", strength).unwrap();
            assert_eq!(encoded.extra.strength, strength);
            let decoded = decode_aes_payload(b"secret", &encoded.payload, encoded.extra).unwrap();
            assert_eq!(decoded, b"payload");
        }
    }

    #[test]
    fn test_zip_traditional_roundtrip() {
        let encoded =
            encode_traditional_payload(b"secret", b"payload", 0x1234_5678, 0x4321, false, b"name")
                .unwrap();
        let decoded =
            decode_traditional_payload(b"secret", &encoded, 0x1234_5678, 0x4321, false).unwrap();
        assert_eq!(decoded, b"payload");
        assert!(matches!(
            decode_traditional_payload(b"wrong", &encoded, 0x1234_5678, 0x4321, false),
            Err(Error::InvalidData("zip: invalid traditional password"))
        ));
    }

    #[test]
    fn test_parse_strong_encryption_extra_aes256() {
        // Build an extra field block with header ID 0x0017
        let mut extra = Vec::new();
        extra.extend_from_slice(&ZIP_STRONG_ENCRYPTION_EXTRA_FIELD_ID.to_le_bytes()); // 0x0017
        extra.extend_from_slice(&8u16.to_le_bytes()); // data size = 8
        extra.extend_from_slice(&2u16.to_le_bytes()); // Format = 2
        extra.extend_from_slice(&0x6610u16.to_le_bytes()); // AlgID = AES-256
        extra.extend_from_slice(&256u16.to_le_bytes()); // Bitlen = 256
        extra.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags = password

        let header = parse_strong_encryption_extra(&extra).unwrap().unwrap();
        assert_eq!(header.format, 2);
        assert_eq!(header.alg_id, 0x6610);
        assert_eq!(header.bitlen, 256);
        assert_eq!(header.flags, 0x0001);
        assert_eq!(header.algorithm_name(), "AES-256");
    }

    #[test]
    fn test_parse_strong_encryption_extra_3des() {
        let mut extra = Vec::new();
        extra.extend_from_slice(&ZIP_STRONG_ENCRYPTION_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&8u16.to_le_bytes());
        extra.extend_from_slice(&2u16.to_le_bytes()); // Format = 2
        extra.extend_from_slice(&0x6603u16.to_le_bytes()); // AlgID = 3DES 168
        extra.extend_from_slice(&168u16.to_le_bytes()); // Bitlen = 168
        extra.extend_from_slice(&0x0002u16.to_le_bytes()); // Flags = certificate

        let header = parse_strong_encryption_extra(&extra).unwrap().unwrap();
        assert_eq!(header.alg_id, 0x6603);
        assert_eq!(header.algorithm_name(), "3DES 168");
        assert_eq!(header.flags, 0x0002);
    }

    #[test]
    fn test_parse_strong_encryption_extra_not_present() {
        // Extra field with a different header ID
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x0001u16.to_le_bytes()); // ZIP64
        extra.extend_from_slice(&8u16.to_le_bytes());
        extra.extend_from_slice(&[0u8; 8]);

        let result = parse_strong_encryption_extra(&extra).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_strong_encryption_extra_too_short() {
        let mut extra = Vec::new();
        extra.extend_from_slice(&ZIP_STRONG_ENCRYPTION_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&4u16.to_le_bytes()); // only 4 bytes of data (need 8)
        extra.extend_from_slice(&[0u8; 4]);

        let result = parse_strong_encryption_extra(&extra);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_strong_encryption_algorithm_names() {
        let cases = [
            (0x6601, "DES"),
            (0x6602, "RC2 (need version < 5.2)"),
            (0x6603, "3DES 168"),
            (0x6609, "3DES 112"),
            (0x660E, "AES-128"),
            (0x660F, "AES-192"),
            (0x6610, "AES-256"),
            (0x6702, "RC2 (need version >= 5.2)"),
            (0x6720, "Blowfish"),
            (0x6721, "Twofish"),
            (0x6801, "RC4"),
            (0x0000, "Unknown"),
            (0xFFFF, "Unknown"),
        ];
        for (alg_id, expected_name) in cases {
            let header = StrongEncryptionHeader {
                format: 2,
                alg_id,
                bitlen: 0,
                flags: 0,
            };
            assert_eq!(header.algorithm_name(), expected_name);
        }
    }

    // --- Tests for Archive Decryption Header parsing (§4.3.10) ---

    #[test]
    fn test_parse_archive_decryption_header_aes256() {
        let mut data = Vec::new();
        // Format (2B) = 2
        data.extend_from_slice(&2u16.to_le_bytes());
        // AlgID (2B) = AES-256
        data.extend_from_slice(&0x6610u16.to_le_bytes());
        // Bitlen (2B) = 256
        data.extend_from_slice(&256u16.to_le_bytes());
        // Flags (2B) = password
        data.extend_from_slice(&0x0001u16.to_le_bytes());
        // ErdSize (2B) = 16
        data.extend_from_slice(&16u16.to_le_bytes());
        // ErdData (16B)
        data.extend_from_slice(&[0xAA; 16]);
        // Reserved1 (4B)
        data.extend_from_slice(&0u32.to_le_bytes());
        // VSize (2B) = 4
        data.extend_from_slice(&4u16.to_le_bytes());
        // VData (4B)
        data.extend_from_slice(&[0xBB; 4]);
        // VCRC32 (4B)
        data.extend_from_slice(&0x12345678u32.to_le_bytes());

        let (header, consumed) = parse_archive_decryption_header(&data).unwrap();
        assert_eq!(header.format, 2);
        assert_eq!(header.alg_id, 0x6610);
        assert_eq!(header.bitlen, 256);
        assert_eq!(header.flags, 0x0001);
        assert_eq!(header.erd_data, vec![0xAA; 16]);
        assert_eq!(consumed, data.len());
        assert_eq!(header.header_size, data.len());
    }

    #[test]
    fn test_parse_archive_decryption_header_3des() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes()); // Format
        data.extend_from_slice(&0x6603u16.to_le_bytes()); // AlgID = 3DES 168
        data.extend_from_slice(&168u16.to_le_bytes()); // Bitlen
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags
        data.extend_from_slice(&8u16.to_le_bytes()); // ErdSize
        data.extend_from_slice(&[0xCC; 8]); // ErdData
        data.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
        data.extend_from_slice(&0u16.to_le_bytes()); // VSize = 0
        data.extend_from_slice(&0u32.to_le_bytes()); // VCRC32

        let (header, consumed) = parse_archive_decryption_header(&data).unwrap();
        assert_eq!(header.alg_id, 0x6603);
        assert_eq!(header.bitlen, 168);
        assert_eq!(header.erd_data, vec![0xCC; 8]);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_archive_decryption_header_truncated() {
        // Too short to contain even the fixed fields
        let result = parse_archive_decryption_header(&[0; 10]);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_parse_archive_decryption_header_truncated_erd() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes()); // Format
        data.extend_from_slice(&0x6610u16.to_le_bytes()); // AlgID
        data.extend_from_slice(&256u16.to_le_bytes()); // Bitlen
        data.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags
        data.extend_from_slice(&100u16.to_le_bytes()); // ErdSize = 100 (too large for remaining data)
        data.extend_from_slice(&[0; 10]); // Only 10 bytes of ERD data

        let result = parse_archive_decryption_header(&data);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }
}
