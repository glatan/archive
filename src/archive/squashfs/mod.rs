//! SquashFS (`.sqfs` / `.squashfs`) read support.
//!
//! SquashFS 4.0 is a compressed read-only filesystem image: a 96-byte
//! superblock, compressed metadata block runs (inode and directory tables),
//! lookup tables (fragment / ID / export / xattr), and per-file data blocks.
//! Supported compressors: zlib ("gzip"), LZO, xz, LZ4, zstd. LZMA 1
//! (compressor id 2, deprecated upstream) is rejected.
//!
//! The `encode` module writes an image (regular files, symlinks,
//! implicit directories, one compressor, optional fragment table and
//! multiple UID/GID ids; no xattr/export tables). The decoder also
//! resolves inode extended attributes (xattr table) and extended
//! directory index entries; interpreting other filesystem semantics
//! (device nodes) beyond name/content listing is intentionally out of
//! scope.

use alloc::vec::Vec;

use crate::error::Error;

/// `.squashfs` image decoding.
pub mod decode;
pub mod encode;

pub use decode::{
    SquashfsCompression, SquashfsDirIndex, SquashfsEntry, SquashfsImage, SquashfsKind,
    SquashfsSuperblock, SquashfsXattr, decode, decode_with_limit,
};

/// Codec struct for trait-based `.squashfs` decode operations.
pub struct SquashfsCodec;

impl crate::traits::ArchiveDecode for SquashfsCodec {
    type Entry = decode::SquashfsEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        Ok(decode::decode(input)?.entries)
    }
}
