use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::error::Error;
use crate::util::aes256::{Aes128, Aes192, Aes256};
use crate::util::crc32::Crc32;
use crate::util::des::{Des, Des3};
use crate::util::rc2::Rc2;
use crate::util::rc4::Rc4;
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
/// This identifies the algorithm and key parameters used by ZIP Strong Encryption.
/// AES-128/192/256 decryption is supported via [`decrypt_strong_encryption_aes`].
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

/// Parsed decryption header from the file data of a strongly encrypted entry (APPNOTE §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrongEncryptionDataHeader {
    /// IV data.
    pub(crate) iv: alloc::vec::Vec<u8>,
    /// Size field from the header.
    pub(crate) size: u32,
    /// Format version.
    pub(crate) format: u16,
    /// Encryption algorithm ID.
    pub(crate) alg_id: u16,
    /// Key bit length.
    pub(crate) bitlen: u16,
    /// Flags.
    pub(crate) flags: u16,
    /// Encrypted random data.
    pub(crate) erd_data: alloc::vec::Vec<u8>,
    /// Remaining encrypted data (after the parsed header).
    pub(crate) encrypted_data: alloc::vec::Vec<u8>,
}

impl StrongEncryptionDataHeader {
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
/// (APPNOTE §4.5.12, §7).
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

/// Parse the decryption header from file data of a strongly encrypted entry (APPNOTE §7).
///
/// The structure is:
/// - IVSize (2B) + IV (IVSize bytes)
/// - Size (4B)
/// - Format (2B)
/// - AlgID (2B)
/// - Bitlen (2B)
/// - Flags (2B)
/// - ErdSize (2B) + ErdData (ErdSize bytes)
/// - (remaining bytes are encrypted file data)
///
/// If Flags & 0x4000 is set there are additional Reserved fields and VData/VCRC32,
/// but we do not parse those yet.
pub(crate) fn parse_strong_encryption_data_header(
    data: &[u8],
) -> Result<StrongEncryptionDataHeader, Error> {
    if data.len() < 2 {
        return Err(Error::UnexpectedEof);
    }
    let mut pos = 0usize;

    // IVSize (2B) + IV
    let iv_size = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + iv_size > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let iv = data[pos..pos + iv_size].to_vec();
    pos += iv_size;

    // Size (4B) + Format (2B) + AlgID (2B) + Bitlen (2B) + Flags (2B) = 12B
    if pos + 12 > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let size = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    let format = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let alg_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let bitlen = u16::from_le_bytes([data[pos], data[pos + 1]]);
    pos += 2;
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

    // If Flags & 0x4000 is set, there are Reserved1 (4B), Reserved2 (2B, if Flags & 0x4000),
    // VSize (2B), VData, and VCRC32 (4B). For now we skip past them.
    if flags & 0x4000 != 0 {
        // Reserved1 (4B)
        if pos + 4 > data.len() {
            return Err(Error::UnexpectedEof);
        }
        pos += 4;
        // Reserved2 (2B) -- present when bit 14 of flags is set (which it is in this branch)
        // Actually APPNOTE says Reserved2 only present if "certificate" auth -- we already
        // checked 0x4000. Skip it.
        // VSize (2B) + VData (VSize) + VCRC32 (4B)
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
    } else {
        // Password-only: Reserved1 (4B) + VSize (2B) + VData + VCRC32 (4B)
        if pos + 4 > data.len() {
            return Err(Error::UnexpectedEof);
        }
        pos += 4; // Reserved1
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
    }

    let encrypted_data = data[pos..].to_vec();

    Ok(StrongEncryptionDataHeader {
        iv,
        size,
        format,
        alg_id,
        bitlen,
        flags,
        erd_data,
        encrypted_data,
    })
}

/// Decrypt a strongly encrypted ZIP entry using AES (APPNOTE §7.2).
///
/// Supports password-based decryption with AES-128 (0x660E), AES-192 (0x660F),
/// and AES-256 (0x6610).
///
/// The protocol:
/// 1. Derive a master key from the password via PBKDF2-HMAC-SHA1 using the IV as salt.
/// 2. Decrypt the ERD (Encrypted Random Data) with AES-CBC using the master key and IV.
/// 3. Derive a session key by hashing the decrypted ERD with SHA-1 (truncated to key size).
/// 4. Decrypt the file data with AES-CBC using the session key (IV from first 16 bytes).
pub(crate) fn decrypt_strong_encryption_aes(
    password: &[u8],
    header: &StrongEncryptionDataHeader,
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData(
            "zip: empty password for strong encryption",
        ));
    }

    let key_size = match header.alg_id {
        0x660E => 16usize, // AES-128
        0x660F => 24usize, // AES-192
        0x6610 => 32usize, // AES-256
        _ => {
            return Err(Error::Unsupported(
                "zip: strong encryption algorithm is not AES",
            ));
        }
    };

    // Step 1: Derive master key from password using PBKDF2-HMAC-SHA1.
    // The IV from the data header is used as the salt.
    let master_key = pbkdf2_hmac_sha1(password, &header.iv, PBKDF2_ITERATIONS, key_size);

    // Step 2: Decrypt ERD using AES-CBC with master key and IV.
    if header.erd_data.is_empty() {
        return Err(Error::InvalidData(
            "zip: strong encryption ERD data is empty",
        ));
    }
    let iv = strong_encryption_iv_array(&header.iv)?;
    let decrypted_erd = decrypt_aes_cbc_by_key_size(&master_key, &header.erd_data, &iv)?;
    let decrypted_erd = remove_pkcs7_padding(&decrypted_erd)?;

    // Step 3: Derive session key from decrypted ERD via SHA-1 hash, truncated to key_size.
    let erd_hash = sha1(&decrypted_erd);
    // If key_size > 20, we need multiple SHA-1 blocks. For AES-128 (16) and AES-192 (24)
    // and AES-256 (32), we use counter-based expansion.
    let session_key = if key_size <= 20 {
        erd_hash[..key_size].to_vec()
    } else {
        // For keys larger than SHA-1 output (20 bytes), derive enough material
        // by hashing with a counter suffix.
        let mut key_material = Vec::with_capacity(key_size);
        key_material.extend_from_slice(&erd_hash);
        let mut counter = 1u8;
        while key_material.len() < key_size {
            let mut hasher = Sha1::new();
            hasher.update(&decrypted_erd);
            hasher.update(&[counter]);
            let extra = hasher.finish();
            key_material.extend_from_slice(&extra);
            counter = counter.wrapping_add(1);
        }
        key_material.truncate(key_size);
        key_material
    };

    // Step 4: Decrypt file data using AES-CBC with session key.
    // The first 16 bytes of the encrypted data serve as the IV.
    if header.encrypted_data.len() < 16 {
        return Err(Error::InvalidData(
            "zip: strong encryption data too short for IV",
        ));
    }
    let data_iv: [u8; 16] = header.encrypted_data[..16]
        .try_into()
        .map_err(|_| Error::InvalidData("zip: strong encryption data IV length"))?;
    let ciphertext = &header.encrypted_data[16..];
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    let decrypted = decrypt_aes_cbc_by_key_size(&session_key, ciphertext, &data_iv)?;
    remove_pkcs7_padding(&decrypted)
}

/// Decrypt a strongly encrypted ZIP entry using any supported algorithm (APPNOTE §7.2).
///
/// Dispatches based on `header.alg_id`:
/// - 0x6601 → DES (8-byte key)
/// - 0x6602 → RC2 (version < 5.2)
/// - 0x6603 → 3DES 168 (24-byte key)
/// - 0x6609 → 3DES 112 (16-byte key)
/// - 0x660E → AES-128 (delegates to [`decrypt_strong_encryption_aes`])
/// - 0x660F → AES-192 (delegates to [`decrypt_strong_encryption_aes`])
/// - 0x6610 → AES-256 (delegates to [`decrypt_strong_encryption_aes`])
/// - 0x6702 → RC2 (version >= 5.2)
/// - 0x6801 → RC4 (stream cipher)
/// - 0x6720 (Blowfish), 0x6721 (Twofish) → Unsupported
pub(crate) fn decrypt_strong_encryption(
    password: &[u8],
    header: &StrongEncryptionDataHeader,
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData(
            "zip: empty password for strong encryption",
        ));
    }

    match header.alg_id {
        // AES variants — delegate to existing implementation
        0x660E..=0x6610 => decrypt_strong_encryption_aes(password, header),

        // DES (8-byte key, 8-byte block)
        0x6601 => decrypt_strong_encryption_block8(password, header, 8, |key, data, iv| {
            let k: [u8; 8] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: DES key length"))?;
            Des::new(&k).decrypt_cbc(data, iv)
        }),

        // 3DES 168 (24-byte key, 8-byte block)
        0x6603 => decrypt_strong_encryption_block8(password, header, 24, |key, data, iv| {
            Des3::new(key)?.decrypt_cbc(data, iv)
        }),

        // 3DES 112 (16-byte key, 8-byte block)
        0x6609 => decrypt_strong_encryption_block8(password, header, 16, |key, data, iv| {
            Des3::new(key)?.decrypt_cbc(data, iv)
        }),

        // RC2 (8-byte block, variable key)
        0x6602 | 0x6702 => {
            let key_size = (header.bitlen as usize) / 8;
            let effective_bits = header.bitlen as usize;
            decrypt_strong_encryption_block8(password, header, key_size, |key, data, iv| {
                Rc2::new(key, effective_bits).decrypt_cbc(data, iv)
            })
        }

        // RC4 (stream cipher)
        0x6801 => decrypt_strong_encryption_rc4(password, header),

        // Blowfish / Twofish — intentionally not implemented
        0x6720 => Err(Error::Unsupported(
            "zip: strong encryption (Blowfish) not supported",
        )),
        0x6721 => Err(Error::Unsupported(
            "zip: strong encryption (Twofish) not supported",
        )),

        _ => Err(Error::Unsupported(
            "zip: strong encryption (unknown algorithm)",
        )),
    }
}

/// Decrypt strong encryption using an 8-byte block cipher (DES, 3DES, RC2).
///
/// The protocol is identical to the AES path but uses 8-byte blocks/IVs:
/// 1. Derive master key via PBKDF2-HMAC-SHA1 (IV as salt)
/// 2. Decrypt ERD with CBC using master key and first 8 bytes of IV
/// 3. Derive session key via SHA-1 of decrypted ERD
/// 4. Decrypt file data with CBC using session key (first 8 bytes of encrypted data as IV)
fn decrypt_strong_encryption_block8(
    password: &[u8],
    header: &StrongEncryptionDataHeader,
    key_size: usize,
    decrypt_cbc: impl Fn(&[u8], &[u8], &[u8; 8]) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    // Step 1: Derive master key
    let master_key = pbkdf2_hmac_sha1(password, &header.iv, PBKDF2_ITERATIONS, key_size);

    // Step 2: Decrypt ERD
    if header.erd_data.is_empty() {
        return Err(Error::InvalidData(
            "zip: strong encryption ERD data is empty",
        ));
    }
    let iv = strong_encryption_iv8(&header.iv)?;
    let decrypted_erd = decrypt_cbc(&master_key, &header.erd_data, &iv)?;

    // Step 3: Derive session key via SHA-1
    let session_key = derive_session_key(&decrypted_erd, key_size);

    // Step 4: Decrypt file data
    if header.encrypted_data.len() < 8 {
        return Err(Error::InvalidData(
            "zip: strong encryption data too short for IV",
        ));
    }
    let data_iv: [u8; 8] = header.encrypted_data[..8]
        .try_into()
        .map_err(|_| Error::InvalidData("zip: strong encryption data IV length"))?;
    let ciphertext = &header.encrypted_data[8..];
    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    decrypt_cbc(&session_key, ciphertext, &data_iv)
}

/// Decrypt strong encryption using RC4 (stream cipher).
///
/// RC4 is a stream cipher, so there is no block/IV for the data phase, but
/// the key derivation still uses PBKDF2 with the header IV as salt.
fn decrypt_strong_encryption_rc4(
    password: &[u8],
    header: &StrongEncryptionDataHeader,
) -> Result<Vec<u8>, Error> {
    let key_size = (header.bitlen as usize) / 8;

    // Step 1: Derive master key
    let master_key = pbkdf2_hmac_sha1(password, &header.iv, PBKDF2_ITERATIONS, key_size);

    // Step 2: Decrypt ERD with RC4
    if header.erd_data.is_empty() {
        return Err(Error::InvalidData(
            "zip: strong encryption ERD data is empty",
        ));
    }
    let mut erd_data = header.erd_data.clone();
    Rc4::new(&master_key).apply(&mut erd_data);

    // Step 3: Derive session key via SHA-1
    let session_key = derive_session_key(&erd_data, key_size);

    // Step 4: Decrypt file data with RC4
    let mut data = header.encrypted_data.clone();
    Rc4::new(&session_key).apply(&mut data);
    Ok(data)
}

/// Derive a session key from decrypted ERD via SHA-1, expanding if needed.
fn derive_session_key(decrypted_erd: &[u8], key_size: usize) -> Vec<u8> {
    let erd_hash = sha1(decrypted_erd);
    if key_size <= 20 {
        erd_hash[..key_size].to_vec()
    } else {
        let mut key_material = Vec::with_capacity(key_size);
        key_material.extend_from_slice(&erd_hash);
        let mut counter = 1u8;
        while key_material.len() < key_size {
            let mut hasher = Sha1::new();
            hasher.update(decrypted_erd);
            hasher.update(&[counter]);
            let extra = hasher.finish();
            key_material.extend_from_slice(&extra);
            counter = counter.wrapping_add(1);
        }
        key_material.truncate(key_size);
        key_material
    }
}

/// Extract the first 8 bytes from the header IV for 8-byte block ciphers.
fn strong_encryption_iv8(iv: &[u8]) -> Result<[u8; 8], Error> {
    if iv.len() < 8 {
        let mut arr = [0u8; 8];
        arr[..iv.len()].copy_from_slice(iv);
        Ok(arr)
    } else {
        iv[..8]
            .try_into()
            .map_err(|_| Error::InvalidData("zip: strong encryption IV too short"))
    }
}

/// Helper to decrypt AES-CBC given a key of 16, 24, or 32 bytes.
fn decrypt_aes_cbc_by_key_size(
    key: &[u8],
    ciphertext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let len = ciphertext.len();
    if len == 0 || !len.is_multiple_of(16) {
        return Err(Error::InvalidData(
            "zip: strong encryption ciphertext not block-aligned",
        ));
    }
    match key.len() {
        16 => {
            let k: [u8; 16] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-128 key length"))?;
            Aes128::new(&k).decrypt_cbc_truncated(ciphertext, iv, len)
        }
        24 => {
            let k: [u8; 24] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-192 key length"))?;
            Aes192::new(&k).decrypt_cbc_truncated(ciphertext, iv, len)
        }
        32 => {
            let k: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-256 key length"))?;
            Aes256::new(&k).decrypt_cbc_truncated(ciphertext, iv, len)
        }
        _ => Err(Error::InvalidData(
            "zip: unsupported AES key size for strong encryption",
        )),
    }
}

/// Encrypt with AES-CBC for the given key size. Used for constructing test vectors.
#[cfg(test)]
pub(crate) fn encrypt_aes_cbc_by_key_size(
    key: &[u8],
    plaintext: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    match key.len() {
        16 => {
            let k: [u8; 16] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-128 key length"))?;
            Ok(Aes128::new(&k).encrypt_cbc_zero_padded(plaintext, iv))
        }
        24 => {
            let k: [u8; 24] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-192 key length"))?;
            Ok(Aes192::new(&k).encrypt_cbc_zero_padded(plaintext, iv))
        }
        32 => {
            let k: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::InvalidData("zip: AES-256 key length"))?;
            Ok(Aes256::new(&k).encrypt_cbc_zero_padded(plaintext, iv))
        }
        _ => Err(Error::InvalidData(
            "zip: unsupported AES key size for strong encryption",
        )),
    }
}

/// Remove PKCS#7 padding from a decrypted block.
fn remove_pkcs7_padding(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let pad_byte = *data.last().unwrap();
    if pad_byte == 0 || pad_byte as usize > 16 || pad_byte as usize > data.len() {
        return Err(Error::InvalidData(
            "zip: invalid PKCS#7 padding in strong encryption",
        ));
    }
    // Verify all padding bytes are correct
    for &b in &data[data.len() - pad_byte as usize..] {
        if b != pad_byte {
            return Err(Error::InvalidData(
                "zip: invalid PKCS#7 padding in strong encryption",
            ));
        }
    }
    Ok(data[..data.len() - pad_byte as usize].to_vec())
}

/// Apply PKCS#7 padding to plaintext.
#[cfg(test)]
pub(crate) fn apply_pkcs7_padding(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut out = data.to_vec();
    out.resize(data.len() + pad_len, pad_len as u8);
    out
}

/// Convert the IV from the data header to a fixed-size array.
fn strong_encryption_iv_array(iv: &[u8]) -> Result<[u8; 16], Error> {
    if iv.len() < 16 {
        // Pad with zeros if shorter
        let mut arr = [0u8; 16];
        arr[..iv.len()].copy_from_slice(iv);
        Ok(arr)
    } else {
        iv[..16]
            .try_into()
            .map_err(|_| Error::InvalidData("zip: strong encryption IV too short"))
    }
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

/// Decrypt an encrypted Central Directory (APPNOTE §7.5).
///
/// The encrypted CD block is structured the same as an encrypted file entry.
/// It starts with a Strong Encryption Data Header followed by the encrypted
/// payload. The `full_encrypted_block` should contain this entire block.
///
/// The `header` provides the algorithm metadata from the Archive Decryption
/// Header for validation.
pub(crate) fn decrypt_central_directory(
    password: &[u8],
    full_encrypted_block: &[u8],
    header: &ArchiveDecryptionHeader,
) -> Result<Vec<u8>, Error> {
    if password.is_empty() {
        return Err(Error::InvalidData(
            "zip: empty password for central directory decryption",
        ));
    }

    // Validate algorithm is supported
    match header.alg_id {
        0x6601 | 0x6602 | 0x6603 | 0x6609 | 0x660E | 0x660F | 0x6610 | 0x6702 | 0x6801 => {}
        _ => {
            return Err(Error::Unsupported(
                "zip: central directory encryption algorithm not supported",
            ));
        }
    }

    // Parse the encrypted block as a Strong Encryption Data Header.
    // This gives us the IV, ERD, and the encrypted CD payload.
    let data_header = parse_strong_encryption_data_header(full_encrypted_block)?;

    // Decrypt using the standard strong encryption protocol.
    decrypt_strong_encryption(password, &data_header)
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
    fn test_parse_strong_encryption_data_header() {
        // Build a minimal strong encryption data header (password-based, no cert)
        let mut data = Vec::new();
        // IVSize (2B) = 16
        data.extend_from_slice(&16u16.to_le_bytes());
        // IV (16B)
        data.extend_from_slice(&[0xAA; 16]);
        // Size (4B)
        data.extend_from_slice(&100u32.to_le_bytes());
        // Format (2B)
        data.extend_from_slice(&2u16.to_le_bytes());
        // AlgID (2B) = AES-256
        data.extend_from_slice(&0x6610u16.to_le_bytes());
        // Bitlen (2B) = 256
        data.extend_from_slice(&256u16.to_le_bytes());
        // Flags (2B) = password (no 0x4000 bit)
        data.extend_from_slice(&0x0001u16.to_le_bytes());
        // ErdSize (2B) = 8
        data.extend_from_slice(&8u16.to_le_bytes());
        // ErdData (8B)
        data.extend_from_slice(&[0xBB; 8]);
        // Reserved1 (4B)
        data.extend_from_slice(&0u32.to_le_bytes());
        // VSize (2B) = 4
        data.extend_from_slice(&4u16.to_le_bytes());
        // VData (4B)
        data.extend_from_slice(&[0xCC; 4]);
        // VCRC32 (4B)
        data.extend_from_slice(&0x12345678u32.to_le_bytes());
        // Remaining encrypted data
        data.extend_from_slice(b"encrypted_payload");

        let header = parse_strong_encryption_data_header(&data).unwrap();
        assert_eq!(header.iv, vec![0xAA; 16]);
        assert_eq!(header.size, 100);
        assert_eq!(header.format, 2);
        assert_eq!(header.alg_id, 0x6610);
        assert_eq!(header.bitlen, 256);
        assert_eq!(header.flags, 0x0001);
        assert_eq!(header.erd_data, vec![0xBB; 8]);
        assert_eq!(header.encrypted_data, b"encrypted_payload");
        assert_eq!(header.algorithm_name(), "AES-256");
    }

    #[test]
    fn test_parse_strong_encryption_data_header_truncated() {
        // Too short to even contain IVSize
        let result = parse_strong_encryption_data_header(&[0x10]);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
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

    /// Build a StrongEncryptionDataHeader that was "encrypted" with the given
    /// password using the strong encryption protocol, so `decrypt_strong_encryption_aes`
    /// can recover the original plaintext.
    fn build_strong_encrypted_data(
        password: &[u8],
        plaintext: &[u8],
        alg_id: u16,
        key_size: usize,
    ) -> StrongEncryptionDataHeader {
        let iv = [0x11u8; 16];
        let master_key = pbkdf2_hmac_sha1(password, &iv, PBKDF2_ITERATIONS, key_size);
        let erd_plain = b"random_erd_data_for_test_padding!"; // 32 bytes
        let erd_padded = apply_pkcs7_padding(erd_plain);
        let erd_encrypted = encrypt_aes_cbc_by_key_size(&master_key, &erd_padded, &iv).unwrap();

        let erd_hash = sha1(erd_plain);
        let session_key = if key_size <= 20 {
            erd_hash[..key_size].to_vec()
        } else {
            let mut key_material = Vec::with_capacity(key_size);
            key_material.extend_from_slice(&erd_hash);
            let mut counter = 1u8;
            while key_material.len() < key_size {
                let mut hasher = Sha1::new();
                hasher.update(erd_plain.as_slice());
                hasher.update(&[counter]);
                let extra = hasher.finish();
                key_material.extend_from_slice(&extra);
                counter = counter.wrapping_add(1);
            }
            key_material.truncate(key_size);
            key_material
        };

        let data_iv = [0x22u8; 16];
        let padded_plaintext = apply_pkcs7_padding(plaintext);
        let encrypted_data_body =
            encrypt_aes_cbc_by_key_size(&session_key, &padded_plaintext, &data_iv).unwrap();
        let mut encrypted_data = Vec::with_capacity(16 + encrypted_data_body.len());
        encrypted_data.extend_from_slice(&data_iv);
        encrypted_data.extend_from_slice(&encrypted_data_body);

        StrongEncryptionDataHeader {
            iv: iv.to_vec(),
            size: 0,
            format: 2,
            alg_id,
            bitlen: (key_size * 8) as u16,
            flags: 0x0001,
            erd_data: erd_encrypted,
            encrypted_data,
        }
    }

    #[test]
    fn test_strong_encryption_aes256_decrypt() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-256!";
        let header = build_strong_encrypted_data(password, plaintext, 0x6610, 32);
        let result = decrypt_strong_encryption_aes(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_aes192_decrypt() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-192!";
        let header = build_strong_encrypted_data(password, plaintext, 0x660F, 24);
        let result = decrypt_strong_encryption_aes(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_aes128_decrypt() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-128!";
        let header = build_strong_encrypted_data(password, plaintext, 0x660E, 16);
        let result = decrypt_strong_encryption_aes(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_wrong_password() {
        let password = b"correct_password";
        let plaintext = b"secret data";
        let header = build_strong_encrypted_data(password, plaintext, 0x6610, 32);
        let result = decrypt_strong_encryption_aes(b"wrong_password", &header);
        assert!(result.is_err());
    }

    #[test]
    fn test_strong_encryption_empty_password() {
        let header = build_strong_encrypted_data(b"x", b"data", 0x6610, 32);
        let result = decrypt_strong_encryption_aes(b"", &header);
        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "zip: empty password for strong encryption"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_non_aes_rejected() {
        let header = StrongEncryptionDataHeader {
            iv: vec![0; 16],
            size: 0,
            format: 2,
            alg_id: 0x6603, // 3DES
            bitlen: 168,
            flags: 0x0001,
            erd_data: vec![0; 16],
            encrypted_data: vec![0; 32],
        };
        let result = decrypt_strong_encryption_aes(b"password", &header);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption algorithm is not AES"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_empty_erd_rejected() {
        let header = StrongEncryptionDataHeader {
            iv: vec![0; 16],
            size: 0,
            format: 2,
            alg_id: 0x6610,
            bitlen: 256,
            flags: 0x0001,
            erd_data: vec![],
            encrypted_data: vec![0; 32],
        };
        let result = decrypt_strong_encryption_aes(b"password", &header);
        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "zip: strong encryption ERD data is empty"
            ))
        ));
    }

    #[test]
    fn test_pkcs7_padding_roundtrip() {
        for len in 0..=32 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let padded = apply_pkcs7_padding(&data);
            assert_eq!(padded.len() % 16, 0);
            assert!(padded.len() > data.len());
            let unpadded = remove_pkcs7_padding(&padded).unwrap();
            assert_eq!(unpadded, data);
        }
    }

    #[test]
    fn test_pkcs7_padding_invalid() {
        assert!(remove_pkcs7_padding(&[0u8; 16]).is_err());
        let mut bad = [0x42u8; 16];
        bad[15] = 3;
        bad[14] = 3;
        bad[13] = 0xFF;
        assert!(remove_pkcs7_padding(&bad).is_err());
    }

    #[test]
    fn test_strong_encryption_block_aligned_plaintext() {
        let password = b"pwd";
        let plaintext = b"exactly16bytesXX"; // 16 bytes
        let header = build_strong_encrypted_data(password, plaintext, 0x6610, 32);
        let result = decrypt_strong_encryption_aes(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    // --- Tests for new cipher integrations via decrypt_strong_encryption ---

    /// Apply PKCS#7 padding for 8-byte block ciphers.
    fn apply_pkcs7_padding_8(data: &[u8]) -> Vec<u8> {
        let pad_len = 8 - (data.len() % 8);
        let mut out = data.to_vec();
        out.resize(data.len() + pad_len, pad_len as u8);
        out
    }

    /// Encrypt with DES-CBC for building test data.
    fn encrypt_des_cbc(key: &[u8; 8], plaintext: &[u8], iv: &[u8; 8]) -> Vec<u8> {
        let des = Des::new(key);
        let mut out = Vec::new();
        let mut prev = *iv;
        for chunk in plaintext.chunks(8) {
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..8 {
                block[i] ^= prev[i];
            }
            let enc = des.encrypt_block(&block);
            out.extend_from_slice(&enc);
            prev = enc;
        }
        out
    }

    /// Encrypt with 3DES-CBC for building test data.
    fn encrypt_3des_cbc(key: &[u8], plaintext: &[u8], iv: &[u8; 8]) -> Vec<u8> {
        let des3 = Des3::new(key).unwrap();
        let mut out = Vec::new();
        let mut prev = *iv;
        for chunk in plaintext.chunks(8) {
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..8 {
                block[i] ^= prev[i];
            }
            let enc = des3.encrypt_block(&block);
            out.extend_from_slice(&enc);
            prev = enc;
        }
        out
    }

    /// Encrypt with RC2-CBC for building test data.
    fn encrypt_rc2_cbc(
        key: &[u8],
        effective_bits: usize,
        plaintext: &[u8],
        iv: &[u8; 8],
    ) -> Vec<u8> {
        let rc2 = Rc2::new(key, effective_bits);
        let mut out = Vec::new();
        let mut prev = *iv;
        for chunk in plaintext.chunks(8) {
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..8 {
                block[i] ^= prev[i];
            }
            let enc = rc2.encrypt_block(&block);
            out.extend_from_slice(&enc);
            prev = enc;
        }
        out
    }

    /// Build a StrongEncryptionDataHeader for 8-byte block ciphers (DES/3DES/RC2).
    fn build_strong_encrypted_data_block8(
        password: &[u8],
        plaintext: &[u8],
        alg_id: u16,
        key_size: usize,
        encrypt_cbc_fn: impl Fn(&[u8], &[u8], &[u8; 8]) -> Vec<u8>,
    ) -> StrongEncryptionDataHeader {
        let iv = [0x11u8; 16]; // 16-byte IV in header, first 8 used for 8-byte blocks
        let iv8: [u8; 8] = [0x11u8; 8];
        let master_key = pbkdf2_hmac_sha1(password, &iv, PBKDF2_ITERATIONS, key_size);

        let erd_plain = b"erd_test_data!!"; // 15 bytes, will need padding
        let erd_padded = apply_pkcs7_padding_8(erd_plain);
        let erd_encrypted = encrypt_cbc_fn(&master_key, &erd_padded, &iv8);

        let session_key = derive_session_key(erd_plain, key_size);

        let data_iv = [0x22u8; 8];
        let padded_plaintext = apply_pkcs7_padding_8(plaintext);
        let encrypted_data_body = encrypt_cbc_fn(&session_key, &padded_plaintext, &data_iv);
        let mut encrypted_data = Vec::with_capacity(8 + encrypted_data_body.len());
        encrypted_data.extend_from_slice(&data_iv);
        encrypted_data.extend_from_slice(&encrypted_data_body);

        StrongEncryptionDataHeader {
            iv: iv.to_vec(),
            size: 0,
            format: 2,
            alg_id,
            bitlen: (key_size * 8) as u16,
            flags: 0x0001,
            erd_data: erd_encrypted,
            encrypted_data,
        }
    }

    /// Build a StrongEncryptionDataHeader for RC4.
    fn build_strong_encrypted_data_rc4(
        password: &[u8],
        plaintext: &[u8],
        key_size: usize,
    ) -> StrongEncryptionDataHeader {
        let iv = [0x11u8; 16];
        let master_key = pbkdf2_hmac_sha1(password, &iv, PBKDF2_ITERATIONS, key_size);

        let erd_plain = b"erd_for_rc4_test";
        let mut erd_encrypted = erd_plain.to_vec();
        Rc4::new(&master_key).apply(&mut erd_encrypted);

        let session_key = derive_session_key(erd_plain, key_size);

        let mut encrypted_data = plaintext.to_vec();
        Rc4::new(&session_key).apply(&mut encrypted_data);

        StrongEncryptionDataHeader {
            iv: iv.to_vec(),
            size: 0,
            format: 2,
            alg_id: 0x6801,
            bitlen: (key_size * 8) as u16,
            flags: 0x0001,
            erd_data: erd_encrypted,
            encrypted_data,
        }
    }

    #[test]
    fn test_strong_encryption_des_decrypt() {
        let password = b"des_password";
        let plaintext = b"Hello, DES Strong Encryption!";
        let header =
            build_strong_encrypted_data_block8(password, plaintext, 0x6601, 8, |key, data, iv| {
                let k: [u8; 8] = key[..8].try_into().unwrap();
                encrypt_des_cbc(&k, data, iv)
            });
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_3des_168_decrypt() {
        let password = b"3des_password";
        let plaintext = b"Hello, 3DES-168!";
        let header =
            build_strong_encrypted_data_block8(password, plaintext, 0x6603, 24, |key, data, iv| {
                encrypt_3des_cbc(&key[..24], data, iv)
            });
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_3des_112_decrypt() {
        let password = b"3des112_password";
        let plaintext = b"Hello, 3DES-112!";
        let header =
            build_strong_encrypted_data_block8(password, plaintext, 0x6609, 16, |key, data, iv| {
                encrypt_3des_cbc(&key[..16], data, iv)
            });
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_rc2_decrypt() {
        let password = b"rc2_password";
        let plaintext = b"Hello, RC2!";
        let key_size = 16;
        let effective_bits = 128;
        let header = build_strong_encrypted_data_block8(
            password,
            plaintext,
            0x6602,
            key_size,
            |key, data, iv| encrypt_rc2_cbc(&key[..key_size], effective_bits, data, iv),
        );
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_rc4_decrypt() {
        let password = b"rc4_password";
        let plaintext = b"Hello, RC4 Strong Encryption!";
        let header = build_strong_encrypted_data_rc4(password, plaintext, 16);
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_aes_via_dispatch() {
        // Verify AES still works through the new dispatch function
        let password = b"aes_dispatch";
        let plaintext = b"AES via dispatch";
        let header = build_strong_encrypted_data(password, plaintext, 0x6610, 32);
        let result = decrypt_strong_encryption(password, &header).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn test_strong_encryption_blowfish_unsupported() {
        let header = StrongEncryptionDataHeader {
            iv: vec![0; 16],
            size: 0,
            format: 2,
            alg_id: 0x6720,
            bitlen: 128,
            flags: 0x0001,
            erd_data: vec![0; 16],
            encrypted_data: vec![0; 32],
        };
        let result = decrypt_strong_encryption(b"password", &header);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption (Blowfish) not supported"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_twofish_unsupported() {
        let header = StrongEncryptionDataHeader {
            iv: vec![0; 16],
            size: 0,
            format: 2,
            alg_id: 0x6721,
            bitlen: 128,
            flags: 0x0001,
            erd_data: vec![0; 16],
            encrypted_data: vec![0; 32],
        };
        let result = decrypt_strong_encryption(b"password", &header);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption (Twofish) not supported"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_empty_password_dispatch() {
        let header = StrongEncryptionDataHeader {
            iv: vec![0; 16],
            size: 0,
            format: 2,
            alg_id: 0x6601,
            bitlen: 64,
            flags: 0x0001,
            erd_data: vec![0; 16],
            encrypted_data: vec![0; 32],
        };
        let result = decrypt_strong_encryption(b"", &header);
        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "zip: empty password for strong encryption"
            ))
        ));
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

    #[test]
    fn test_decrypt_central_directory_empty_password() {
        let header = ArchiveDecryptionHeader {
            format: 2,
            alg_id: 0x6610,
            bitlen: 256,
            flags: 0x0001,
            erd_data: vec![0xAA; 16],
            header_size: 0,
        };
        let result = decrypt_central_directory(b"", &[0; 32], &header);
        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "zip: empty password for central directory decryption"
            ))
        ));
    }

    #[test]
    fn test_decrypt_central_directory_unsupported_algorithm() {
        let header = ArchiveDecryptionHeader {
            format: 2,
            alg_id: 0x6720, // Blowfish - not supported
            bitlen: 128,
            flags: 0x0001,
            erd_data: vec![0xAA; 16],
            header_size: 0,
        };
        let result = decrypt_central_directory(b"password", &[0; 32], &header);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: central directory encryption algorithm not supported"
            ))
        ));
    }
}
