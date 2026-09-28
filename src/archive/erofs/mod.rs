//! Linux EROFS (Enhanced Read-Only File System) image support.
//!
//! Decoder for the read-only filesystem described in the kernel's
//! `Documentation/filesystems/erofs.rst` and `fs/erofs/erofs_fs.h`
//! (snapshots in `docs/spec/sources/`). Little-endian throughout:
//! `0xE0F5E1E2` magic at offset 1024, compact (32-byte) and extended
//! (64-byte) inodes located at `meta_blkaddr * block_size + 32 * nid`,
//! dirent blocks with `erofs_dirent` headers followed by packed names,
//! flat data layouts with optional tail-packing inline data, and
//! chunk-based files for deduplication.
//!
//! Compressed inodes (`z_erofs`: LZ4, MicroLZMA, DEFLATE, Zstandard
//! pcluster layouts 1 and 3), multi-device images, metabox images,
//! packed-fragment and ztailpacking images are intentionally out of
//! scope; encountering them is reported as `Error::Unsupported`.
//! Extended attributes are skipped without interpretation. Writing
//! erofs images is intentionally out of scope (mkfs.erofs is the
//! reference producer).

use crate::error::Error;

/// Linux erofs filesystem image decoding.
pub mod decode;

/// Codec struct for trait-based erofs decode operations.
pub struct ErofsCodec;

impl crate::traits::ArchiveDecode for ErofsCodec {
    type Entry = decode::ErofsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}
