//! Linux EROFS (Enhanced Read-Only File System) image support.
//!
//! Decoder for the read-only filesystem described in the kernel's
//! `Documentation/filesystems/erofs.rst` and `fs/erofs/erofs_fs.h`
//! (snapshots in `docs/spec/sources/`). Little-endian throughout:
//! `0xE0F5E1E2` magic at offset 1024, compact (32-byte) and extended
//! (64-byte) inodes located at `meta_blkaddr * block_size + 32 * nid`,
//! dirent blocks with `erofs_dirent` headers followed by packed names,
//! flat data layouts with optional tail-packing inline data,
//! chunk-based files for deduplication, and `z_erofs` compressed
//! inodes (datalayout 1 `COMPRESSED_FULL` and 3 `COMPRESSED_COMPACT`)
//! backed by the LZ4, MicroLZMA, DEFLATE and Zstandard codecs. The
//! `available_compr_algs` superblock bitmap and compression-config
//! records are honored; per-inode big pclusters, compacted 2-byte
//! indexes, `Z_EROFS_ADVISE_EXTENTS` extent records and partial
//! references are supported. Tail data may live outside the file's
//! own data blocks: `Z_EROFS_ADVISE_INLINE_PCLUSTER` inline
//! tail-packing (`INCOMPAT_ZTAILPACKING`) and packed-inode fragments
//! (`INCOMPAT_FRAGMENTS`, `Z_EROFS_ADVISE_FRAGMENT_PCLUSTER` tails,
//! `Z_EROFS_FRAGMENT_INODE_BIT` whole-file records) are decoded
//! through the `packed_nid` inode.
//!
//! Superblock metadata that does not affect decoding — the volume
//! UUID, mkfs build time, feature bitmaps and xattr bookkeeping
//! fields — is parsed and exposed via `decode::ErofsImage::superblock`.
//! Extended attributes are interpreted per inode (inline ibody
//! entries plus shared-xattr references, short and long name
//! prefixes) and exposed as `decode::ErofsEntry::xattrs`.
//!
//! Metabox images (`INCOMPAT_METABOX`) are supported: the metabox
//! inode (superblock extension slot 0, `metabox_nid`) decodes to a
//! second metadata space holding metabox-hosted inode slots (dirent
//! nid bit63), their xattr ibodies, chunk index tables, z_erofs map
//! data and inline tails; shared xattrs and long xattr prefixes may
//! also live there (`COMPAT_SHARED_EA_IN_METABOX`). Multi-device
//! images remain out of scope and are reported as
//! `Error::Unsupported`.
//!
//! The encoder (`encode` module / `ErofsArchiveEncoder`)
//! produces uncompressed images equivalent to plain `mkfs.erofs`
//! output: flat `FLAT_PLAIN`/`FLAT_INLINE` data layouts, compact or
//! extended inodes, name-sorted dirent blocks, and the
//! `EROFS_FEATURE_COMPAT_SB_CHKSUM` superblock CRC32C. Writing
//! z_erofs compressed, chunk-based, fragment or metabox images is
//! intentionally out of scope (mkfs.erofs is the reference
//! producer for those).

use crate::error::Error;

/// Linux erofs filesystem image decoding.
pub mod decode;

/// Linux erofs filesystem image encoding (uncompressed flat layouts).
pub mod encode;

mod z;

/// Codec struct for trait-based erofs decode operations.
pub struct ErofsCodec;

impl crate::traits::ArchiveDecode for ErofsCodec {
    type Entry = decode::ErofsEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}

/// Encoder struct for trait-based erofs encode operations.
pub struct ErofsArchiveEncoder {
    inner: encode::ErofsEncoder,
}

impl ErofsArchiveEncoder {
    /// Create a new trait-based erofs encoder.
    pub const fn new() -> Self {
        Self {
            inner: encode::ErofsEncoder::new(),
        }
    }
}

impl Default for ErofsArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for ErofsArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<alloc::vec::Vec<u8>, Error> {
        self.inner.finish()
    }
}
