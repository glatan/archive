//! ZIM archive (`.zim`) format support.
//!
//! Decoder for the ZIM file format used by Kiwix/openZIM, plus a
//! minimal v5 writer. Supports major versions 5 and 6, stored and
//! xz/zstd-compressed clusters, extended (8-byte offset) clusters,
//! and redirect entry resolution. The writer emits a single-cluster
//! archive with an MD5 checksum trailer. MIME metadata exposure,
//! title search APIs, and archive checksum *verification* are
//! intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// ZIM archive decoding.
pub mod decode;
pub mod encode;

/// Codec struct for trait-based ZIM decode operations.
pub struct ZimCodec;

impl crate::traits::ArchiveDecode for ZimCodec {
    type Entry = decode::ZimEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
