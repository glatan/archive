//! ISO 9660 (ECMA-119) CD-ROM filesystem image read support.
//!
//! Decoder for the volume/directory record format described in
//! ECMA-119 (= ISO 9660; snapshot in `docs/spec/sources/ecma119.pdf`)
//! plus the Rock Ridge Interchange Protocol (IEEE P1282 v1.12,
//! `rrip112.pdf`) and the Microsoft Joliet supplementary volume
//! specification (`jolspec.html`).
//!
//! Name selection per entry follows the usual priority: Rock Ridge
//! `NM` names from the primary volume tree, then UCS-2 Joliet names
//! from a supplementary volume tree, then plain ISO9660 identifiers
//! with the `;version` suffix stripped. Rock Ridge `PX` (POSIX
//! attributes), `SL` (symlink), `TF` (timestamps) and `NM` entries,
//! and SUSP `SP`/`CE`/`ST` framing are supported. Files carrying a
//! zisofs `ZF` system use entry are transparently decompressed
//! (`pz` algorithm: per-block zlib streams with the block pointer
//! table; 32/64/128KiB block sizes).
//!
//! Multi-extent files, interleaved files (`unit_size`/`gap_size`),
//! extended attribute records content, non-`pz` `ZF` compression
//! algorithms, El Torito boot records, and writing ISO images are
//! intentionally out of scope.

use crate::error::Error;

/// ISO 9660 filesystem image decoding.
pub mod decode;

/// Codec struct for trait-based ISO 9660 decode operations.
pub struct Iso9660Codec;

impl crate::traits::ArchiveDecode for Iso9660Codec {
    type Entry = decode::IsoEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}
