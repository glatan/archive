//! Chrome extension package (CRX2/CRX3) read support.
//!
//! Decoder for the CRX₃ container described in Chromium's
//! `components/crx_file/crx3.proto` (snapshot in
//! `docs/spec/sources/`): a `Cr24` magic, version 3, a little-endian
//! header length, a protobuf-encoded `CrxFileHeader` carrying signing
//! proofs and the `crx_id`, followed by an ordinary ZIP archive.
//! The older fixed-layout version 2 header (`Cr24`, version 2,
//! u32 key length, u32 signature length, key, signature, ZIP) from
//! Chromium's `components/crx_file/crx_file.h` is also accepted; its
//! key/signature pair is exposed as a single RSA PKCS#1 proof.
//!
//! Signature proofs are parsed and exposed (public key + signature +
//! algorithm) but not verified — verification requires RSA-PSS /
//! ECDSA P-256 / RSA PKCS#1, which is intentionally out of scope. The
//! cheaper `crx_id` consistency check (first 16 bytes of
//! `SHA-256(rsa_public_key)`) is exposed as
//! `decode::Crx3Image::verify_crx_id`. Writing CRX files is
//! also out of scope.

use crate::error::Error;

/// CRX2/CRX3 container decoding.
pub mod decode;

/// Codec struct for trait-based CRX2/CRX3 decode operations.
pub struct Crx3Codec;

impl crate::traits::ArchiveDecode for Crx3Codec {
    type Entry = decode::Crx3Entry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| {
            img.entries
                .into_iter()
                .map(|e| decode::Crx3Entry {
                    name: e.name,
                    data: e.data,
                })
                .collect()
        })
    }
}
