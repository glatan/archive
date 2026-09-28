//! RC4 stream cipher implementation.
//!
//! Used by ZIP Strong Encryption (algorithm ID 0x6801).
//! Implements KSA (Key Scheduling Algorithm) and PRGA (Pseudo-Random Generation Algorithm).

/// RC4 stream cipher state.
pub(crate) struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher from the given key.
    ///
    /// The key can be 1-256 bytes. The internal state is initialized via KSA.
    pub(crate) fn new(key: &[u8]) -> Self {
        // Key Scheduling Algorithm (KSA)
        let mut s = [0u8; 256];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR the given data with the RC4 keystream in place.
    ///
    /// Since RC4 is a symmetric stream cipher, the same operation is used
    /// for both encryption and decryption.
    pub(crate) fn apply(&mut self, data: &mut [u8]) {
        // Pseudo-Random Generation Algorithm (PRGA)
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known RC4 test vector: Key="Key", Plaintext="Plaintext"
    /// Expected ciphertext: BBF316E8D940AF0AD3
    #[test]
    fn test_rc4_known_vector() {
        let mut rc4 = Rc4::new(b"Key");
        let mut data = *b"Plaintext";
        rc4.apply(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    /// Known RC4 test vector: Key="Wiki", Plaintext="pedia"
    /// Expected ciphertext: 1021BF0420
    #[test]
    fn test_rc4_wiki_vector() {
        let mut rc4 = Rc4::new(b"Wiki");
        let mut data = *b"pedia";
        rc4.apply(&mut data);
        assert_eq!(data, [0x10, 0x21, 0xBF, 0x04, 0x20]);
    }

    /// Verify RC4 encrypt/decrypt roundtrip (XOR is its own inverse).
    #[test]
    fn test_rc4_roundtrip() {
        let plaintext = b"Hello, RC4 stream cipher!";
        let mut encrypted = plaintext.to_vec();
        Rc4::new(b"secret_key").apply(&mut encrypted);
        assert_ne!(encrypted, plaintext);

        let mut decrypted = encrypted.clone();
        Rc4::new(b"secret_key").apply(&mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rc4_empty_data() {
        let mut data: [u8; 0] = [];
        Rc4::new(b"key").apply(&mut data);
        assert_eq!(data, []);
    }
}
