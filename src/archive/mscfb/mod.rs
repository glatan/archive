//! Microsoft Compound File Binary (`.doc`, `.xls`, `.msi`, OLE2) read support.
//!
//! Read-only decoder for the container defined in [MS-CFB] (v20210625,
//! sections 2.1-2.6). Supports version 3 (512-byte sectors) and
//! version 4 (4096-byte sectors) files: header parsing, the 109-entry
//! in-header DIFAT plus chained DIFAT sectors, FAT sector chains, the
//! directory entry array with storage/stream enumeration via child and
//! sibling stream IDs, the mini FAT and mini stream for streams below
//! the 4096-byte cutoff, and UTF-16LE name decoding.
//!
//! Writing compound files, transactions, the range lock sector, and
//! structured-storage property semantics are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// Microsoft Compound File Binary decoding.
pub mod decode;

/// Codec struct for trait-based MS-CFB decode operations.
pub struct MscfbCodec;

impl crate::traits::ArchiveDecode for MscfbCodec {
    type Entry = decode::CfbEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
