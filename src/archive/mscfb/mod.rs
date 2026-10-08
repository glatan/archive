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
//! names) that the lenient decoder tolerates. `decode::get_stream`
//! resolves a '/'-separated stream path by descending the sibling
//! red-black trees under the [MS-CFB] 2.6.4 uppercase-mapped
//! ordering, and `decode::decode_sorted` enumerates stream entries
//! in that order even for unsorted on-disk trees.
//!
//! [`encode::CfbEncoder`] writes whole compound file images: nested
//! storages, mini-stream packing below the cutoff, balanced sibling
//! trees per the [MS-CFB] 2.6.4 sort rule, and chained DIFAT sectors
//! for large images. Transactions, the range lock sector, and
//! structured-storage property semantics are intentionally out of
//! scope.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

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

/// [MS-CFB] 2.6.4 sort key: the name uppercased as UTF-16 code units.
/// Ordering is by unit count first, then by unit values.
///
/// The spec requires the *simple* case conversion variant, i.e. a 1:1
/// per-character mapping that never changes the unit count, so the key
/// length stays equal to the original name's UTF-16 length (matching
/// the spec's name-length-first comparison). `str::to_uppercase` uses
/// full case mappings that can expand (e.g. ß → "SS"), so we take the
/// first char of each mapping instead. Astral characters are left
/// untouched because the spec operates on UTF-16 code units and never
/// uppercases surrogate code points. For the rare chars whose
/// UnicodeData simple uppercase differs from that first char (ß → ẞ,
/// ligatures), this is an approximation.
pub(crate) fn sort_key(name: &str) -> Vec<u16> {
    let upper: String = name
        .chars()
        .map(|c| {
            if u32::from(c) > 0xFFFF {
                c
            } else {
                c.to_uppercase().next().unwrap_or(c)
            }
        })
        .collect();
    upper.encode_utf16().collect()
}

/// [MS-CFB] 2.6.4 sibling ordering comparison on [`sort_key`] output.
pub(crate) fn key_cmp(a: &[u16], b: &[u16]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}
