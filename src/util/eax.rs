//! AES OMAC1/CMAC and EAX helpers for the PEA authenticated-
//! encryption streams (PeaZip pea_utils.pas decode path; Ehrhardt
//! aes_omac/aes_eax semantics).
//!
//! OMAC1 is NIST SP 800-38B CMAC. EAX follows Bellare-Rogaway-Wagner
//! (eprint 2003/069): the tag is the XOR of the OMACs of the nonce,
//! the header, and the ciphertext, each prefixed with a zero block
//! tagged 0/1/2, and CTR starts at the nonce tag. The CTR counter
//! increments the full 128-bit block big-endian, with E(IV) as the
//! first keystream block (Ehrhardt AES_CTR / IncMSBFull default).

use alloc::vec::Vec;

use crate::error::Error;

/// 16-byte block cipher bound used by the OMAC/EAX helpers.
pub(crate) trait BlockCipher {
    fn encrypt(&self, block: &mut [u8; 16]);
}

impl BlockCipher for crate::util::aes256::Aes128 {
    fn encrypt(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }
}

impl BlockCipher for crate::util::aes256::Aes256 {
    fn encrypt(&self, block: &mut [u8; 16]) {
        self.encrypt_block(block);
    }
}

fn xor_block(a: &mut [u8; 16], b: &[u8]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// GF(2^128) doubling used for the CMAC subkeys (poly x^128+x^7+x^2+x+1).
fn dbl(block: &mut [u8; 16]) {
    let carry = block[0] >> 7;
    for i in 0..15 {
        block[i] = (block[i] << 1) | (block[i + 1] >> 7);
    }
    block[15] = (block[15] << 1) ^ (if carry != 0 { 0x87 } else { 0 });
}

/// One-shot OMAC1/CMAC tag over data.
fn omac1<C: BlockCipher>(cipher: &C, data: &[u8]) -> [u8; 16] {
    let mut subkey = [0u8; 16];
    cipher.encrypt(&mut subkey);
    let mut state = [0u8; 16];
    let blocks = data.len().div_ceil(16).max(1);
    for block in 0..blocks - 1 {
        xor_block(&mut state, &data[block * 16..block * 16 + 16]);
        cipher.encrypt(&mut state);
    }
    let mut last = [0u8; 16];
    if data.len().is_multiple_of(16) && !data.is_empty() {
        last.copy_from_slice(&data[(blocks - 1) * 16..]);
        dbl(&mut subkey);
    } else {
        let tail = &data[(blocks - 1) * 16..];
        last[..tail.len()].copy_from_slice(tail);
        last[tail.len()] = 0x80;
        dbl(&mut subkey);
        dbl(&mut subkey);
    }
    xor_block(&mut last, &state);
    xor_block(&mut last, &subkey);
    cipher.encrypt(&mut last);
    last
}

/// OMAC tag with the EAX single-block prefix (last byte = index).
fn omac_tagged<C: BlockCipher>(cipher: &C, index: u8, data: &[u8]) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16 + data.len());
    buf.extend_from_slice(&[0u8; 16]);
    buf[15] = index;
    buf.extend_from_slice(data);
    omac1(cipher, &buf)
}

/// FCA CTR: keystream block i is E(counter_i) with counter_0 = IV and
/// counter incremented as a 128-bit big-endian integer per block.
pub(crate) fn ctr_apply<C: BlockCipher>(cipher: &C, iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut counter = *iv;
    for chunk in data.chunks(16) {
        let mut keystream = counter;
        cipher.encrypt(&mut keystream);
        out.extend(chunk.iter().zip(keystream.iter()).map(|(a, b)| a ^ b));
        for b in counter.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }
    out
}

/// EAX nonce tag (OMAC of the tag-0 block followed by the nonce);
/// also the CTR start value used by EAX encryption.
pub(crate) fn eax_nonce_tag<C: BlockCipher>(cipher: &C, nonce: &[u8]) -> [u8; 16] {
    omac_tagged(cipher, 0, nonce)
}

/// Full EAX tag over nonce, header, and ciphertext.
fn eax_tag<C: BlockCipher>(cipher: &C, nonce: &[u8], header: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let nonce_tag = omac_tagged(cipher, 0, nonce);
    let hdr_tag = omac_tagged(cipher, 1, header);
    let msg_tag = omac_tagged(cipher, 2, ciphertext);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = nonce_tag[i] ^ hdr_tag[i] ^ msg_tag[i];
    }
    tag
}

/// Verify the 16-byte EAX tag of ciphertext under nonce/header.
pub(crate) fn eax_verify_tag<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<(), Error> {
    if eax_tag(cipher, nonce, header, ciphertext) != *tag {
        return Err(Error::InvalidData("pea stream authentication failed"));
    }
    Ok(())
}

/// EAX verify + decrypt: checks the 16-byte tag, then returns the
/// decrypted plaintext. header is the EAX associated data (empty for
/// PEA streams).
#[cfg(test)]
pub(crate) fn eax_decrypt_verify<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    eax_verify_tag(cipher, nonce, header, ciphertext, tag)?;
    let nonce_tag = omac_tagged(cipher, 0, nonce);
    Ok(ctr_apply(cipher, &nonce_tag, ciphertext))
}

/// EAX encrypt + tag (test helper: mirrors the reference write path).
#[cfg(test)]
pub(crate) fn eax_encrypt<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    header: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let nonce_tag = omac_tagged(cipher, 0, nonce);
    let ciphertext = ctr_apply(cipher, &nonce_tag, plaintext);
    let hdr_tag = omac_tagged(cipher, 1, header);
    let msg_tag = omac_tagged(cipher, 2, &ciphertext);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = nonce_tag[i] ^ hdr_tag[i] ^ msg_tag[i];
    }
    (ciphertext, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::aes256::Aes128;

    fn parse_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // EAX-AES-128 vectors from the EAX paper (via libtomcrypt
    // eax_test.c), plus Brian Gladman vectors.
    #[test]
    fn test_eax_paper_vectors() {
        struct V {
            nonce: &'static str,
            header: &'static str,
            plaintext: &'static str,
            ciphertext: &'static str,
            tag: &'static str,
        }
        let key: [u8; 16] = parse_hex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        for v in [
            V {
                nonce: "",
                header: "",
                plaintext: "",
                ciphertext: "",
                tag: "9ad07e7dbff301f505de596b9615dfff",
            },
            V {
                nonce: "000102030405060708090a0b0c0d0e0f",
                header: "",
                plaintext: "",
                ciphertext: "",
                tag: "1ce10d3effd4cadbe2e44b58d60ab9ec",
            },
            V {
                nonce: "",
                header: "000102030405060708090a0b0c0d0e0f",
                plaintext: "",
                ciphertext: "",
                tag: "3a698f7a270e51b0f65b3d3e47193cff",
            },
            V {
                nonce: "000102030405060708090a0b0c0d0e0f",
                header: "000102030405060708090a0b0c0d0e0f",
                plaintext: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                ciphertext: "29d878d1a3be857b6fb8c8ea5950a778331fbf2ccf33986f35e8cf121dcb30bc",
                tag: "4fbe0338be1c8c7e1d7ae7e45b92c587",
            },
            V {
                nonce: "000102030405060708090a0b0c0d0e",
                header: "000102030405060708090a0b0c0d",
                plaintext: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
                ciphertext: "dd25c754c5b17c5928b69b73155f7bb8888faf37091ad92c8a24db868b",
                tag: "0d1a14e52224ffd23a05fa02cdef52da",
            },
        ] {
            let cipher = Aes128::new(&key);
            let nonce = parse_hex(v.nonce);
            let header = parse_hex(v.header);
            let pt = parse_hex(v.plaintext);
            let ct = parse_hex(v.ciphertext);
            let tag: [u8; 16] = parse_hex(v.tag).try_into().unwrap();
            let (enc, etag) = eax_encrypt(&cipher, &nonce, &header, &pt);
            assert_eq!(enc, ct);
            assert_eq!(etag, tag);
            assert_eq!(
                eax_decrypt_verify(&cipher, &nonce, &header, &ct, &tag).unwrap(),
                pt
            );
        }
    }

    #[test]
    fn test_eax_gladman_vectors() {
        struct V {
            key: &'static str,
            nonce: &'static str,
            header: &'static str,
            plaintext: &'static str,
            ciphertext: &'static str,
            tag: &'static str,
        }
        for v in [
            V {
                key: "233952dee4d5ed5f9b9c6d6ff80ff478",
                nonce: "62ec67f9c3a4a407fcb2a8c49031a8b3",
                header: "6bfb914fd07eae6b",
                plaintext: "",
                ciphertext: "",
                tag: "e037830e8389f27b025a2d6527e79d01",
            },
            V {
                key: "91945d3f4dcbee0bf45ef52255f095a4",
                nonce: "becaf043b0a23d843194ba972c66debd",
                header: "fa3bfd4806eb53fa",
                plaintext: "f7fb",
                ciphertext: "19dd",
                tag: "5c4c9331049d0bdab0277408f67967e5",
            },
            V {
                key: "01f74ad64077f2e704c0f60ada3dd523",
                nonce: "70c3db4f0d26368400a10ed05d2bff5e",
                header: "234a3463c1264ac6",
                plaintext: "1a47cb4933",
                ciphertext: "d851d5bae0",
                tag: "3a59f238a23e39199dc9266626c40f80",
            },
        ] {
            let key: [u8; 16] = parse_hex(v.key).try_into().unwrap();
            let cipher = Aes128::new(&key);
            let nonce = parse_hex(v.nonce);
            let header = parse_hex(v.header);
            let pt = parse_hex(v.plaintext);
            let ct = parse_hex(v.ciphertext);
            let tag: [u8; 16] = parse_hex(v.tag).try_into().unwrap();
            let (enc, etag) = eax_encrypt(&cipher, &nonce, &header, &pt);
            assert_eq!(enc, ct);
            assert_eq!(etag, tag);
            assert_eq!(
                eax_decrypt_verify(&cipher, &nonce, &header, &ct, &tag).unwrap(),
                pt
            );
        }
    }

    #[test]
    fn test_eax_rejects_bad_tag() {
        let cipher = Aes128::new(&[0x42; 16]);
        let (ct, tag) = eax_encrypt(&cipher, &[7; 16], &[], b"payload");
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(matches!(
            eax_decrypt_verify(&cipher, &[7; 16], &[], &ct, &bad),
            Err(Error::InvalidData(_))
        ));
        let mut ct2 = ct;
        ct2[0] ^= 1;
        assert!(eax_decrypt_verify(&cipher, &[7; 16], &[], &ct2, &tag).is_err());
    }
}
