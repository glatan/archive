//! PBKDF2 (RFC 2898 / PKCS#5) key derivation over in-crate hashes,
//! used by the PEA crypto subheader (HMAC-SHA1 for AES-128 streams,
//! HMAC-Whirlpool for EAX256).

use alloc::vec::Vec;

/// PBKDF2: DK = T1 || T2 || ... truncated to out_len bytes, where
/// T_i = U_1 xor ... xor U_c and U_1 = HMAC(password, salt || i_be32).
pub(crate) fn pbkdf2<const D: usize>(
    hash: fn(&[u8]) -> [u8; D],
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out_len: usize,
) -> Vec<u8> {
    let blocks = out_len.div_ceil(D);
    let mut out = Vec::with_capacity(blocks * D);
    for index in 1..=blocks {
        let mut input = Vec::with_capacity(salt.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(&(index as u32).to_be_bytes());
        let mut u = hmac(hash, password, &input);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac(hash, password, &u);
            for (acc, value) in t.iter_mut().zip(u.iter()) {
                *acc ^= *value;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(out_len);
    out
}

/// HMAC over hash: hash table empty (SHA-1 and Whirlpool both use a 64-byte block).
pub(crate) fn hmac<const D: usize>(hash: fn(&[u8]) -> [u8; D], key: &[u8], data: &[u8]) -> [u8; D] {
    let mut pad = [0u8; 64];
    if key.len() > 64 {
        pad[..D].copy_from_slice(&hash(key));
    } else {
        pad[..key.len()].copy_from_slice(key);
    }

    for b in pad.iter_mut() {
        *b ^= 0x36;
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&pad);
    inner.extend_from_slice(data);
    let inner_digest = hash(&inner);

    for b in pad.iter_mut() {
        *b ^= 0x36 ^ 0x5C;
    }
    let mut outer = Vec::with_capacity(64 + D);
    outer.extend_from_slice(&pad);
    outer.extend_from_slice(&inner_digest);
    hash(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{sha1::sha1, whirlpool::whirlpool};

    fn hex(digest: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        for b in digest {
            s.push_str(&alloc::format!("{b:02x}"));
        }
        s
    }

    #[test]
    fn test_pbkdf2_sha1_rfc6070() {
        // RFC 6070 PBKDF2-HMAC-SHA1 vectors
        assert_eq!(
            hex(&pbkdf2(sha1, b"password", b"salt", 1, 20)),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        assert_eq!(
            hex(&pbkdf2(sha1, b"password", b"salt", 2, 20)),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
    }

    #[test]
    fn test_pbkdf2_sha1_xkey_layout() {
        // FCA TXKey is 34 bytes: ak || hk || pw verifier, spanning
        // two HMAC-SHA1 output blocks
        let dk = pbkdf2(sha1, b"pw", b"0123456789ab", 1000, 34);
        assert_eq!(dk.len(), 34);
        assert_eq!(dk[..20], pbkdf2(sha1, b"pw", b"0123456789ab", 1000, 20));
    }

    #[test]
    fn test_pbkdf2_whirlpool() {
        // PBKDF2-HMAC-Whirlpool(password, salt, 1000, 66), the FCA256
        // TX256Key derivation; verified against OpenSSL
        let dk = pbkdf2(whirlpool, b"password", b"salt", 1000, 66);
        assert_eq!(
            hex(&dk),
            "5ad7361484c7dde6b23e573c4b61d1fd16023fd6c0170d0b26d70f7ac8c683f06e767804750357b4032297c2ad36cbd84d01476c1298826b71f605dbcda9e0551157"
        );
    }

    #[test]
    fn test_hmac_sha1_rfc2202() {
        // RFC 2202 case 2: key "Jefe", data "what do ya want for nothing?"
        assert_eq!(
            hex(&hmac(sha1, b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn test_hmac_long_key() {
        // key longer than the 64-byte block gets hashed first
        let key = [0xAAu8; 80];
        let short = hmac(sha1, &sha1(&key), b"msg");
        assert_eq!(hmac(sha1, &key, b"msg"), short);
    }

    #[test]
    fn test_pbkdf2_sha1_4096_iterations() {
        // RFC 6070 PBKDF2-HMAC-SHA1 vector: c = 4096
        assert_eq!(
            hex(&pbkdf2(sha1, b"password", b"salt", 4096, 20)),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }

    #[test]
    fn test_pbkdf2_out_len_boundaries() {
        // out_len = 0 yields an empty key.
        assert!(pbkdf2(sha1, b"pw", b"salt", 1, 0).is_empty());
        // Derived keys are prefix-stable across the block boundary:
        // dk(20) is the first block, dk(21) appends one byte of block 2.
        let dk20 = pbkdf2(sha1, b"pw", b"salt", 1, 20);
        assert_eq!(pbkdf2(sha1, b"pw", b"salt", 1, 19), dk20[..19]);
        let dk21 = pbkdf2(sha1, b"pw", b"salt", 1, 21);
        assert_eq!(dk21[..20], dk20[..]);
        // Exact two-block boundary.
        let dk40 = pbkdf2(sha1, b"pw", b"salt", 1, 40);
        let dk41 = pbkdf2(sha1, b"pw", b"salt", 1, 41);
        assert_eq!(dk41[..40], dk40[..]);
    }

    #[test]
    fn test_hmac_block_size_key_boundary() {
        // Keys longer than the 64-byte block are hashed first; a key
        // of exactly 64 bytes is used verbatim.
        let key64 = [0xABu8; 64];
        let key65 = [0xABu8; 65];
        let msg = b"msg";
        assert_eq!(hmac(sha1, &key65, msg), hmac(sha1, &sha1(&key65), msg));
        // At exactly 64 bytes the key must NOT be pre-hashed.
        assert_ne!(hmac(sha1, &key64, msg), hmac(sha1, &sha1(&key64), msg));
    }
}
