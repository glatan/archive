//! Microsoft Compound File Binary (`.doc`, `.xls`, `.msi`, OLE2) read/write support.
//!
//! Reader and writer for the container defined in [MS-CFB] (v20210625,
//! sections 2.1-2.6). Supports version 3 (512-byte sectors) and
//! version 4 (4096-byte sectors) files: header parsing, the 109-entry
//! in-header DIFAT plus chained DIFAT sectors, FAT sector chains, the
//! directory entry array with storage/stream enumeration via child and
//! sibling stream IDs, the mini FAT and mini stream for streams below
//! the 4096-byte cutoff, and UTF-16LE name decoding. Stream
//! entries expose their directory metadata (CLSID, state bits,
//! creation/modification FILETIMEs); the root storage's metadata
//! is available via root_meta. `decode::decode_strict` additionally
//! enforces the directory-entry invariants of [MS-CFB] 2.6.1/2.6.4
//! (color flags, NOSTREAM sibling/child conventions, unique sibling
//! names) that the lenient decoder tolerates.
//!
//! [`encode::CfbEncoder`] writes whole compound file images: nested
//! storages, mini-stream packing below the cutoff, balanced sibling
//! trees per the [MS-CFB] 2.6.4 sort rule, and chained DIFAT sectors
//! for large images. Transactions, the range lock sector, and
//! structured-storage property semantics are intentionally out of
//! scope.

use alloc::vec::Vec;

use crate::error::Error;

/// Microsoft Compound File Binary decoding.
pub mod decode;

/// Microsoft Compound File Binary encoding.
pub mod encode;

/// Codec struct for trait-based MS-CFB decode operations.
pub struct MscfbCodec;

impl crate::traits::ArchiveDecode for MscfbCodec {
    type Entry = decode::CfbEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
