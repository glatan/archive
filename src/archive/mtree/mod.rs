//! mtree(5) manifest format support.
//!
//! Read-only parser for BSD mtree files (the libarchive/FreeBSD
//! dialect, including `#mtree` signature, `/set`/`/unset` defaults,
//! relative and full entries, and `..` directory pop). Entries expose
//! filesystem metadata as fields; since mtree carries no file content,
//! [`crate::traits::ArchiveEntry::data`] is always empty.

use alloc::vec::Vec;

use crate::error::Error;

/// mtree manifest decoding.
pub mod decode;

/// Codec struct for trait-based mtree decode operations.
pub struct MtreeCodec;

impl crate::traits::ArchiveDecode for MtreeCodec {
    type Entry = decode::MtreeEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
