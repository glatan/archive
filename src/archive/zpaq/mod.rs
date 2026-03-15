//! zpaq multi-entry archive format.
//!
//! This is the high-level archive layer built on top of the low-level
//! [`crate::compress::zpaq`] codec.
//!
//! Use this module when you want filename/comment metadata or multiple entries
//! per archive. For a single payload block without archive metadata, use
//! `compress::zpaq`.
//!
//! Current scope includes:
//! - basic multi-entry archives via `ZpaqEncoder`
//! - same-block append workflows that reuse an existing parsed header/model
//! - crate-local journaling transactions via `ZpaqJournalEncoder`
//!   together with `decode_journal_latest` / `decode_journal_versions`
//! - materialized archive editing via `ZpaqArchiveEditor`, including
//!   import from plain archives or latest journal view followed by
//!   push/put/delete and rewrite

use alloc::vec::Vec;

use crate::error::Error;

/// zpaq archive decoding.
pub mod decode;
/// zpaq archive encoding.
pub mod encode;

/// Codec struct for trait-based zpaq decode operations.
///
/// Note: ZPAQ archive encoding is complex (levels, journal) so `ArchiveEncode`
/// is not implemented. Use [`encode::ZpaqEncoder`] directly for encoding.
pub struct ZpaqCodec;

impl crate::traits::ArchiveDecode for ZpaqCodec {
    type Entry = decode::ZpaqEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
