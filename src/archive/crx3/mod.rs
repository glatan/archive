//! Chrome extension package (CRX3) read support.
//!
//! Decoder for the CRX₃ container described in Chromium's
//! `components/crx_file/crx3.proto` (snapshot in
//! `docs/spec/sources/`): a `Cr24` magic, version 3, a little-endian
//! header length, a protobuf-encoded `CrxFileHeader` carrying signing
//! proofs and the `crx_id`, followed by an ordinary ZIP archive.
//!
//! Signature proofs are parsed and exposed (public key + signature +
//! algorithm) but not verified — verification requires RSA-PSS /
//! ECDSA P-256, which is intentionally out of scope. Writing CRX
//! files is also out of scope.

use crate::error::Error;

/// CRX3 container decoding.
pub mod decode;

/// Codec struct for trait-based CRX3 decode operations.
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
