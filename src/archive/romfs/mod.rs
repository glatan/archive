//! Linux romfs read-only filesystem image support.
//!
//! Decoder for the ROM File System described in the kernel's
//! `Documentation/filesystems/romfs.rst` (snapshot in
//! `docs/spec/sources/`). Big-endian throughout: `-rom1fs-` magic,
//! AFFS-style longword-sum checksums, 16-byte-aligned file headers
//! with type/executable bits in the low nibble of the `next` pointer,
//! explicit hard links, and directory children reached through
//! `spec.info`.
//!
//! Writing romfs images is intentionally out of scope (genromfs is
//! the reference producer).

use crate::error::Error;

/// Linux romfs filesystem image decoding.
pub mod decode;

/// Codec struct for trait-based romfs decode operations.
pub struct RomfsCodec;

impl crate::traits::ArchiveDecode for RomfsCodec {
    type Entry = decode::RomfsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}
