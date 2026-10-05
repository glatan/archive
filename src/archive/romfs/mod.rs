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
//! The `encode` module writes genromfs-compatible images: regular
//! files, directories (with `.`/`..` helper headers and implicit
//! parents), symlinks, hard links, and block/char/socket/fifo nodes.

use crate::error::Error;

/// Linux romfs filesystem image decoding.
pub mod decode;
/// Linux romfs filesystem image encoding.
pub mod encode;

/// Codec struct for trait-based romfs decode operations.
pub struct RomfsCodec;

impl crate::traits::ArchiveDecode for RomfsCodec {
    type Entry = decode::RomfsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}

/// Encoder struct for trait-based romfs encode operations.
pub struct RomfsArchiveEncoder {
    inner: encode::RomfsEncoder,
}

impl RomfsArchiveEncoder {
    /// Create a new trait-based romfs encoder (empty volume name).
    pub const fn new() -> Self {
        Self {
            inner: encode::RomfsEncoder::new(),
        }
    }
}

impl Default for RomfsArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for RomfsArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<alloc::vec::Vec<u8>, Error> {
        self.inner.finish()
    }
}
