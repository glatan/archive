//! ZIM archive (`.zim`) format support.
//!
//! Read-only decoder for the ZIM file format used by Kiwix/openZIM.
//! Supports major versions 5 and 6, stored and xz/zstd-compressed
//! clusters, extended (8-byte offset) clusters, and redirect entry
//! resolution. MIME metadata, title ordering, archive checksum
//! verification, and writing are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// ZIM archive decoding.
pub mod decode;

/// Codec struct for trait-based ZIM decode operations.
pub struct ZimCodec;

impl crate::traits::ArchiveDecode for ZimCodec {
    type Entry = decode::ZimEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
