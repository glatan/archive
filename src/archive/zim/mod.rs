//! ZIM archive (`.zim`) format support.
//!
//! Decoder for the ZIM file format used by Kiwix/openZIM, plus a
//! minimal v5 writer. Supports major versions 5 and 6, stored and
//! xz/zstd-compressed clusters, extended (8-byte offset) clusters,
//! and redirect entry resolution. `decode_parts` reads split
//! `.zimaa`/`.zimab` archives, and the archive MD5 checksum is
//! verified when present. The writer emits a single-cluster archive
//! with an MD5 checksum trailer. Entries expose MIME type and title
//! metadata, and `decode_title_order` lists entries in title-pointer
//! order; fulltext index search is intentionally out of scope.

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
