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
//! Writing cramfs images and big-endian images are intentionally out
//! of scope (the kernel itself refuses foreign-endian images).

use crate::error::Error;

/// Linux cramfs filesystem image decoding.
pub mod decode;

/// Codec struct for trait-based cramfs decode operations.
pub struct CramfsCodec;

impl crate::traits::ArchiveDecode for CramfsCodec {
    type Entry = decode::CramfsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}
