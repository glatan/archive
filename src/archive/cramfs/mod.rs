//! Linux cramfs read-only filesystem image support.
//!
//! Decoder for the cramfs format described in the kernel's
//! `Documentation/filesystems/cramfs.rst`, `fs/cramfs/README`, and
//! `include/uapi/linux/cramfs_fs.h` (snapshots in
//! `docs/spec/sources/`). Supports little-endian images: the 64-byte
//! superblock (magic `0x28cd3d45`, optionally shifted to offset 512),
//! 12-byte inodes with width-first directory entries, zlib-compressed
//! per-page data blocks with end-offset block pointers, hole blocks
//! (zero pointers), and the `CRAMFS_FLAG_EXT_BLOCK_POINTERS`
//! uncompressed/direct block pointer extension.
//!
//! The encoder (`encode` module / [`CramfsArchiveEncoder`]) produces
//! mkfs.cramfs-compatible little-endian images: sorted contiguous
//! directory entries, zlib-compressed 4 KiB data blocks, and the
//! `CRAMFS_FLAG_FSID_VERSION_2` fsid checksum.
//!
//! Big-endian images are intentionally out of scope (the kernel itself
//! refuses foreign-endian images).

use crate::error::Error;

/// Linux cramfs filesystem image decoding.
pub mod decode;

/// Linux cramfs filesystem image encoding.
pub mod encode;

/// Codec struct for trait-based cramfs decode operations.
pub struct CramfsCodec;

impl crate::traits::ArchiveDecode for CramfsCodec {
    type Entry = decode::CramfsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}

/// Encoder struct for trait-based cramfs encode operations.
pub struct CramfsArchiveEncoder {
    inner: encode::CramfsEncoder,
}

impl CramfsArchiveEncoder {
    /// Create a new trait-based cramfs encoder.
    pub const fn new() -> Self {
        Self {
            inner: encode::CramfsEncoder::new(),
        }
    }
}

impl Default for CramfsArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for CramfsArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<alloc::vec::Vec<u8>, Error> {
        self.inner.finish()
    }
}
