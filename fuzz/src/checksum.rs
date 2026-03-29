//! Dual-hash fingerprinting for round-trip integrity verification.
//!
//! Every piece of test data is fingerprinted with both SHA3-512 and BLAKE3
//! before encoding. After the decode round-trip the fingerprint is re-computed
//! and compared. Using two independent hash families guards against the
//! astronomically unlikely case of a single-hash collision masking corruption.

use sha3::{Digest, Sha3_512};

/// A pair of cryptographic hashes that uniquely identifies a byte sequence.
pub struct DataFingerprint {
    pub sha3_512: [u8; 64],
    pub blake3: [u8; 32],
}

/// Compute a [`DataFingerprint`] (SHA3-512 + BLAKE3) for the given data.
pub fn fingerprint(data: &[u8]) -> DataFingerprint {
    let sha3_512 = {
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; 64];
        hash.copy_from_slice(&result);
        hash
    };

    let blake3 = {
        let hash = blake3::hash(data);
        *hash.as_bytes()
    };

    DataFingerprint { sha3_512, blake3 }
}

/// Verify that `decompressed` matches the `original` fingerprint.
///
/// Returns `Ok(())` on match, or an error string describing which hash(es)
/// diverged.
pub fn verify(original: &DataFingerprint, decompressed: &[u8]) -> Result<(), String> {
    let actual = fingerprint(decompressed);

    let sha3_match = original.sha3_512 == actual.sha3_512;
    let blake3_match = original.blake3 == actual.blake3;

    match (sha3_match, blake3_match) {
        (true, true) => Ok(()),
        (false, true) => Err("SHA3-512 mismatch (BLAKE3 matched)".to_string()),
        (true, false) => Err("BLAKE3 mismatch (SHA3-512 matched)".to_string()),
        (false, false) => Err("Both SHA3-512 and BLAKE3 mismatch".to_string()),
    }
}
