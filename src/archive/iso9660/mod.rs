//! ISO 9660 (ECMA-119) CD-ROM filesystem image read/write support.
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
//! attributes), `PN` (device numbers), `SL` (symlink), `TF`
//! (timestamps) and `NM` entries, SUSP `SP`/`CE`/`ST` framing, and the
//! `CL`/`RE` deep-directory relocation links (RRIP §4.1.5; `PL` parent
//! links are skipped, not needed by the path-based walk) are
//! supported. Multi-extent files (ECMA-119 §9.1.6 File Flags bit 7)
//! and interleaved files (`unit_size`/`gap_size`, §6.4.3) are
//! reassembled transparently. Files carrying a zisofs `ZF` system
//! use entry are transparently decompressed (`pz` algorithm:
//! per-block zlib streams with the block pointer table; 32/64/128KiB
//! block sizes). El Torito boot records (VD type 0) are
//! recognised: the boot catalog validation entry and all
//! initial/section entries are parsed, and the referenced boot
//! image is extracted into `ElToritoEntry::image` (`IsoImage::el_torito`).
//! Descriptor metadata — system/volume-set/publisher/preparer/
//! application and copyright/abstract/bibliographic identifiers
//! plus the four 17-byte volume timestamps (ECMA-119 §8.4.5,
//! §8.4.19-8.4.29) — is exposed via `IsoImage::meta` (primary) and
//! `IsoImage::joliet_meta` (supplementary).
//! Extended attribute records (ECMA-119 §9.5) are parsed into
//! `IsoEntry::xa` and act as a fallback for owner/group/mode/
//! mtime when Rock Ridge fields are absent. The remaining SUSP
//! surface is decoded too: `PX` file serials (`IsoEntry::ino`),
//! `SF` sparse parameters, `ER`/`ES` extension references
//! (`IsoEntry::susp_ext`), and Apple `AA`/`BA` records
//! (`IsoEntry::apple`); `PD` padding is skipped per SUSP.
//!
//! The `encode` module writes primary-volume images: plain
//! ISO9660 level 1/2 identifiers with L and M path tables, or
//! SUSP/Rock Ridge (`SP`/`ER`, `NM`, `PX`, `TF`, `SL`) when
//! enabled. It does not emit Joliet SVDs, El Torito records,
//! multi-extent files or interleaved recording.
//!
//! Sparse (`SF`) payload decoding and non-`pz` `ZF` compression
//! algorithms are intentionally out of scope for the decoder.

use crate::error::Error;

/// ISO 9660 filesystem image decoding.
pub mod decode;
/// ISO 9660 filesystem image encoding.
pub mod encode;

/// Codec struct for trait-based ISO 9660 decode operations.
pub struct Iso9660Codec;

impl crate::traits::ArchiveDecode for Iso9660Codec {
    type Entry = decode::IsoEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}

/// Encoder struct for trait-based ISO 9660 encode operations.
///
/// Produces a plain ISO9660 image (level-2 identifiers); use
/// [`encode::IsoEncoder`] for Rock Ridge output or level control.
pub struct Iso9660ArchiveEncoder {
    inner: encode::IsoEncoder,
}

impl Iso9660ArchiveEncoder {
    /// Create a new trait-based ISO 9660 encoder (plain image).
    pub const fn new() -> Self {
        Self {
            inner: encode::IsoEncoder::new(),
        }
    }
}

impl Default for Iso9660ArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for Iso9660ArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<alloc::vec::Vec<u8>, Error> {
        self.inner.finish()
    }
}
