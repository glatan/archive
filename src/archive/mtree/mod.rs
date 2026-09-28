//! mtree(5) manifest format support.
//!
//! Parser and emitter for BSD mtree files (the libarchive/FreeBSD
//! dialect, including `#mtree` signature, `/set`/`/unset` defaults,
//! relative and full entries, and `..` directory pop on read). Entries
//! expose filesystem metadata as fields; since mtree carries no file
//! content, [`crate::traits::ArchiveEntry::data`] is always empty.
//! The encoder writes the equivalent full-path form (`./a/b/c.txt`)
//! with `\ooo` escapes and `<alg>digest=` keywords.

use alloc::vec::Vec;

use crate::error::Error;

/// mtree manifest decoding.
pub mod decode;

/// mtree manifest encoding.
pub mod encode;

/// Codec struct for trait-based mtree decode operations.
pub struct MtreeCodec;

impl crate::traits::ArchiveDecode for MtreeCodec {
    type Entry = decode::MtreeEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
