//! EROFS image decoder.
//!
//! Implements superblock, inode, dirent, and flat/chunked data
//! extraction per `Documentation/filesystems/erofs.rst` and
//! `fs/erofs/erofs_fs.h`.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32c::crc32c;

const SUPER_OFF: usize = 1024;
const SUPER_SIZE: usize = 128;
const MAGIC: u32 = 0xE0F5_E1E2;
const INODE_SLOT: usize = 32;
const INODE_COMPACT: usize = 32;
const INODE_EXTENDED: usize = 64;
const DIRENT_SIZE: usize = 12;
const NULL_ADDR: u64 = u64::MAX;

/// `feature_compat` bit: the superblock carries a CRC32C checksum
/// (`EROFS_FEATURE_COMPAT_SB_CHKSUM`); always verified when set.
pub const COMPAT_SB_CHKSUM: u32 = 0x1;
/// `feature_compat` bit: `epoch`/`fixed_nsec`/`build_time` carry
/// mkfs time information (`EROFS_FEATURE_COMPAT_MTIME`).
pub const COMPAT_MTIME: u32 = 0x2;
/// `feature_compat` bit: inode xattr headers may carry a 32-bit
/// name bloom filter (`EROFS_FEATURE_COMPAT_XATTR_FILTER`). The
/// filter only accelerates keyed xattr lookups, so it is reported
/// in the bitmap but never interpreted.
pub const COMPAT_XATTR_FILTER: u32 = 0x4;
/// `feature_compat` bit: shared xattrs may live in the metabox
/// inode (`EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX`).
pub const COMPAT_SHARED_EA_IN_METABOX: u32 = 0x8;
/// `feature_compat` bit: long xattr name prefixes are literal
/// strings rather than predefined indexes
/// (`EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX`).
pub const COMPAT_PLAIN_XATTR_PFX: u32 = 0x10;
/// `feature_compat` bit: inodes may reference shared xattrs through
/// `ishare_xattr_prefix_id` (`EROFS_FEATURE_COMPAT_ISHARE_XATTRS`).
pub const COMPAT_ISHARE_XATTRS: u32 = 0x20;

const INCOMPAT_LZ4_0PADDING: u32 = 0x1;
const INCOMPAT_COMPR_CFGS: u32 = 0x2;
// The dedicated big-pcluster bit was folded into COMPR_CFGS upstream
// (INCOMPAT_BIG_PCLUSTER aliases bit 0x2): big pclusters
// are self-describing via per-inode advise bits and this feature only
// gates their presence at mount time.
const INCOMPAT_BIG_PCLUSTER: u32 = 0x2;
// Bit 0x8 (INCOMPAT_DEVICE_TABLE) doubles as INCOMPAT_COMPR_HEAD2
// since Linux 5.18: it only marks that compressed inodes may use the
// second map-header algorithm and is harmless here; real multi-device
// images remain rejected via `extra_devices != 0`.
const INCOMPAT_ZTAILPACKING: u32 = 0x10;
const INCOMPAT_FRAGMENTS: u32 = 0x20;
const INCOMPAT_48BIT: u32 = 0x80;
const INCOMPAT_METABOX: u32 = 0x100;

const DATALAYOUT_FLAT_PLAIN: u8 = 0;
pub(crate) const DATALAYOUT_COMPRESSED_FULL: u8 = 1;
const DATALAYOUT_FLAT_INLINE: u8 = 2;
pub(crate) const DATALAYOUT_COMPRESSED_COMPACT: u8 = 3;
const DATALAYOUT_CHUNK_BASED: u8 = 4;

const CHUNK_FORMAT_INDEXES: u16 = 0x20;
const CHUNK_FORMAT_48BIT: u16 = 0x40;
const CHUNK_FORMAT_ALL: u16 = 0x7F;

/// Entry kind for an erofs dirent/inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link; `data` holds the target path bytes.
    Symlink,
    /// Device, fifo, socket, or unknown type. The payload carries
    /// the erofs `file_type` value from the dirent (`0` for entries
    /// constructed without dirent type information).
    Other(u8),
}

/// A decoded erofs entry. `name` is the full path relative to the
/// volume root (components joined with `/`).
#[derive(Debug, Clone)]
pub struct ErofsEntry {
    /// Full path without a leading slash.
    pub name: String,
    /// Entry kind (from the inode mode).
    pub kind: ErofsKind,
    /// Unix mode (`st_mode` style: file type + permissions).
    pub mode: u16,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Modification time, seconds since the Unix epoch. For compact
    /// inodes this is `superblock.epoch + i_mtime`.
    pub mtime: i64,
    /// Modification time nanoseconds (compact inodes report the
    /// superblock `fixed_nsec` value).
    pub mtime_nsec: u32,
    /// File contents or symlink target; empty for directories and
    /// special files.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ErofsEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Parsed `erofs_super_block` metadata: the on-disk fields that
/// describe the volume but do not gate decoding. All values are
/// little-endian-decoded from the superblock record at offset 1024.
/// The xattr-related fields are bookkeeping only; xattr contents
/// themselves are not interpreted (see module docs).
#[derive(Debug, Clone)]
pub struct ErofsSuperblock {
    /// Raw `feature_compat` bitmap; see the `COMPAT_*` constants.
    /// Compat features never gate decoding (`COMPAT_SB_CHKSUM` is
    /// always verified when present).
    pub feature_compat: u32,
    /// Raw `feature_incompat` bitmap; images carrying unsupported
    /// bits are rejected before this value can be observed.
    pub feature_incompat: u32,
    /// Total valid inode count (`inos`; `f_files - f_favail`).
    pub inos: u64,
    /// Total filesystem blocks (`blocks_lo`, extended by
    /// `blocks_hi` when `INCOMPAT_48BIT` is set).
    pub blocks: u64,
    /// Start block address of the inode metadata area
    /// (`meta_blkaddr`).
    pub meta_blkaddr: u32,
    /// Start block address of the shared xattr area
    /// (`xattr_blkaddr`); `0` when the image has none.
    pub xattr_blkaddr: u32,
    /// 128-bit volume UUID (`uuid`); all-zero when unset.
    pub uuid: [u8; 16],
    /// Base seconds added to compact-inode `i_mtime` values
    /// (`epoch`).
    pub epoch: u64,
    /// Fixed nanoseconds reported for compact-inode mtimes
    /// (`fixed_nsec`).
    pub fixed_nsec: u32,
    /// mkfs timestamp as seconds on top of `epoch` (`build_time`);
    /// meaningful when `feature_compat` has `COMPAT_MTIME`.
    pub build_time: u32,
    /// Number of long xattr name prefixes (`xattr_prefix_count`);
    /// `0` disables the feature. The prefix records live in the
    /// packed/meta inode at `xattr_prefix_start * 4` and are not
    /// interpreted.
    pub xattr_prefix_count: u8,
    /// Long xattr name prefix table offset inside the packed/meta
    /// inode, in 4-byte units (`xattr_prefix_start`).
    pub xattr_prefix_start: u32,
    /// Nid of the special packed inode (`packed_nid`); `0` when
    /// the image carries none.
    pub packed_nid: u64,
    /// Base prefix id for inode-shared xattrs
    /// (`ishare_xattr_prefix_id`); meaningful under
    /// `COMPAT_ISHARE_XATTRS`.
    pub ishare_xattr_prefix_id: u8,
}

/// Decoded erofs image.
#[derive(Debug)]
pub struct ErofsImage {
    /// Volume label (may be empty).
    pub volume_name: String,
    /// Total filesystem blocks as recorded in the superblock.
    pub blocks: u64,
    /// Filesystem block size in bytes.
    pub block_size: u32,
    /// Superblock metadata that does not affect decoding (volume
    /// UUID, mkfs build time, xattr bookkeeping, feature bitmaps).
    pub superblock: ErofsSuperblock,
    /// Entries in depth-first directory order.
    pub entries: Vec<ErofsEntry>,
}

pub(crate) fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub(crate) fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub(crate) fn u64le(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}

pub(crate) struct Inode {
    /// Parsed inode core size (32 or 64).
    pub(crate) isize: usize,
    /// Inline xattr area size following the inode core.
    pub(crate) xattr_isize: usize,
    pub(crate) datalayout: u8,
    mode: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    pub(crate) size: u64,
    mtime: i64,
    mtime_nsec: u32,
    /// Flat-layout start block, or `NULL_ADDR` for a fully-sparse
    /// (`FLAT_PLAIN` hole) or fully-inline (`FLAT_INLINE`) inode.
    startblk: u64,
    /// Whether `startblk` carries 48-bit addressing.
    startblk_is_null_capable: bool,
    /// Chunk-based inode format word (`erofs_inode_chunk_info`).
    chunk_format: u16,
}

impl Inode {
    fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }

    fn is_reg(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }

    fn is_lnk(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
}

pub(crate) struct Img<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) blksz: usize,
    /// Directory block size: `1 << dirblkbits`, or `blksz` when the
    /// superblock `dirblkbits` field is zero.
    dirblksz: usize,
    meta_blkaddr: u64,
    epoch: u64,
    fixed_nsec: u32,
    /// `available_compr_algs` bitmap; `1 << LZ4` when the image
    /// carries no compression-config records.
    pub(crate) avail_compr_algs: u16,
    /// `INCOMPAT_LZ4_0PADDING`: LZ4 streams are right-aligned inside
    /// their pcluster with leading zero padding.
    pub(crate) lz4_0padding: bool,
    /// `INCOMPAT_BIG_PCLUSTER` superblock bit; required for
    /// CBLKCNT multi-lcluster pclusters.
    pub(crate) big_pcluster: bool,
    /// LZMA dictionary size from the compression-config record
    /// (`0` when no config is present).
    #[cfg_attr(
        not(any(
            feature = "lzma-alone",
            feature = "lzip",
            feature = "xz",
            feature = "sevenz",
            feature = "lrzip"
        )),
        allow(dead_code)
    )]
    pub(crate) lzma_dict_size: u32,
}

impl Img<'_> {
    fn iloc(&self, nid: u64) -> Result<usize, Error> {
        let off = self
            .meta_blkaddr
            .checked_mul(self.blksz as u64)
            .and_then(|v| {
                nid.checked_mul(INODE_SLOT as u64)
                    .and_then(|n| v.checked_add(n))
            })
            .ok_or(Error::InvalidData("erofs inode offset overflow"))?;
        usize::try_from(off).map_err(|_| Error::InvalidData("erofs inode offset overflow"))
    }

    fn read_inode(&self, nid: u64) -> Result<(usize, Inode), Error> {
        let off = self.iloc(nid)?;
        let hdr = self
            .data
            .get(off..off.checked_add(INODE_SLOT).ok_or(Error::UnexpectedEof)?)
            .ok_or(Error::UnexpectedEof)?;
        let ifmt = u16le(hdr, 0);
        let extended = ifmt & 1 == 1;
        let datalayout = ((ifmt >> 1) & 0x7) as u8;
        if datalayout >= 5 {
            return Err(Error::Unsupported("erofs reserved datalayout"));
        }
        let isize = if extended {
            INODE_EXTENDED
        } else {
            INODE_COMPACT
        };
        let inode = self
            .data
            .get(off..off.checked_add(isize).ok_or(Error::UnexpectedEof)?)
            .ok_or(Error::UnexpectedEof)?;
        // erofs_xattr_ibody_size: 12-byte header + 4 * (n - 1) bytes.
        let xattr_icount = u16le(inode, 2) as usize;
        let xattr_isize = if xattr_icount == 0 {
            0
        } else {
            12 + 4 * (xattr_icount - 1)
        };
        let mode = u16le(inode, 4);
        let nb = u16le(inode, 6);
        let is_dir = mode & 0o170000 == 0o040000;
        // `i_nb` is `nlink` for directories and multi-link compact
        // inodes; for extended inodes and compact single-link files
        // it carries the high 16 bits of the 48-bit start block.
        let (nlink, startblk_hi, addrmask) = if extended {
            (u32le(inode, 44), nb as u64, 0xFFFF_FFFF_FFFF)
        } else if !is_dir && (ifmt >> 4) & 1 == 1 {
            (1, nb as u64, 0xFFFF_FFFF_FFFF)
        } else {
            (nb as u32, 0, 0xFFFF_FFFF)
        };
        let (size, iu, uid, gid, mtime, mtime_nsec) = if extended {
            (
                u64le(inode, 8),
                u32le(inode, 16),
                u32le(inode, 24),
                u32le(inode, 28),
                u64le(inode, 32) as i64,
                u32le(inode, 40),
            )
        } else {
            (
                u32le(inode, 8) as u64,
                u32le(inode, 16),
                u16le(inode, 24) as u32,
                u16le(inode, 26) as u32,
                self.epoch as i64 + i64::from(u32le(inode, 12)),
                self.fixed_nsec,
            )
        };
        let mut startblk = u64::from(iu) | (startblk_hi << 32);
        let null_capable = datalayout == DATALAYOUT_FLAT_PLAIN;
        if null_capable && (startblk ^ NULL_ADDR) & addrmask == 0 {
            startblk = NULL_ADDR;
        }
        let chunk_format = if datalayout == DATALAYOUT_CHUNK_BASED {
            let f = iu as u16;
            if f & !CHUNK_FORMAT_ALL != 0 {
                return Err(Error::Unsupported("erofs unknown chunk format bits"));
            }
            if f & CHUNK_FORMAT_48BIT != 0 {
                return Err(Error::Unsupported("erofs 48-bit chunk indexes"));
            }
            f
        } else {
            0
        };
        Ok((
            off,
            Inode {
                isize,
                xattr_isize,
                datalayout,
                mode,
                uid,
                gid,
                nlink,
                size,
                mtime,
                mtime_nsec,
                startblk,
                startblk_is_null_capable: null_capable,
                chunk_format,
            },
        ))
    }

    /// Read `size` bytes of flat-inode data: `floor(size / blksz)`
    /// whole blocks at `startblk` plus, for `FLAT_INLINE`, the
    /// trailing `size % blksz` bytes stored right after the inode
    /// metadata (`iloc + isize + xattr_isize`).
    fn read_flat(&self, ino: &Inode, ino_off: usize, inline: bool) -> Result<Vec<u8>, Error> {
        let size = usize::try_from(ino.size)
            .map_err(|_| Error::Unsupported("erofs file larger than memory"))?;
        let blksz = self.blksz;
        if ino.startblk_is_null_capable && ino.startblk == NULL_ADDR {
            // Hole inode: whole file reads as zeros.
            return Ok(alloc::vec![0u8; size]);
        }
        let nblocks = if inline {
            size / blksz
        } else {
            size.div_ceil(blksz)
        };
        // Fully-inline inodes record NULL_ADDR as the start block.
        let has_blocks = !(inline && ino.startblk & 0xFFFF_FFFF == 0xFFFF_FFFF);
        if !has_blocks && nblocks > 0 {
            return Err(Error::InvalidData("erofs inline inode missing data blocks"));
        }
        let body = nblocks
            .checked_mul(blksz)
            .ok_or(Error::InvalidData("erofs size overflow"))?;
        let mut out = Vec::with_capacity(size);
        if has_blocks && body > 0 {
            let data_off = ino
                .startblk
                .checked_mul(blksz as u64)
                .ok_or(Error::InvalidData("erofs data offset overflow"))?;
            let data_off = usize::try_from(data_off)
                .map_err(|_| Error::InvalidData("erofs data offset overflow"))?;
            let end = data_off
                .checked_add(body)
                .ok_or(Error::InvalidData("erofs data out of range"))?;
            out.extend_from_slice(
                self.data
                    .get(data_off..end)
                    .ok_or(Error::InvalidData("erofs data out of range"))?,
            );
        }
        if inline {
            let tail = size.saturating_sub(body.min(size));
            if tail > 0 {
                let tail_off = ino_off
                    .checked_add(ino.isize)
                    .and_then(|v| v.checked_add(ino.xattr_isize))
                    .ok_or(Error::InvalidData("erofs inline offset overflow"))?;
                let end = tail_off
                    .checked_add(tail)
                    .ok_or(Error::InvalidData("erofs inline tail out of range"))?;
                out.extend_from_slice(
                    self.data
                        .get(tail_off..end)
                        .ok_or(Error::InvalidData("erofs inline tail out of range"))?,
                );
            }
        }
        out.truncate(size);
        Ok(out)
    }

    fn read_chunked(&self, ino: &Inode, ino_off: usize) -> Result<Vec<u8>, Error> {
        let size = usize::try_from(ino.size)
            .map_err(|_| Error::Unsupported("erofs file larger than memory"))?;
        if size == 0 {
            return Ok(Vec::new());
        }
        let chunkbits = self
            .blksz
            .checked_shl(u32::from(ino.chunk_format & 0x1f))
            .ok_or(Error::InvalidData("erofs chunk size overflow"))?;
        let nchunks = size.div_ceil(chunkbits);
        let esz = if ino.chunk_format & CHUNK_FORMAT_INDEXES != 0 {
            8
        } else {
            4
        };
        // Extents follow the inode and xattr ibody, 8-byte aligned,
        // preceded by a 4-byte `erofs_inode_chunk_info`.
        let eoff = ino_off
            .checked_add((ino.isize + ino.xattr_isize + 7) & !7)
            .and_then(|v| v.checked_add(4))
            .ok_or(Error::InvalidData("erofs extent offset overflow"))?;
        let eend = eoff
            .checked_add(
                nchunks
                    .checked_mul(esz)
                    .ok_or(Error::InvalidData("erofs extent overflow"))?,
            )
            .ok_or(Error::InvalidData("erofs extent overflow"))?;
        let extents = self
            .data
            .get(eoff..eend)
            .ok_or(Error::InvalidData("erofs chunk extents out of range"))?;
        let mut out = Vec::with_capacity(size);
        for i in 0..nchunks {
            let take = (size - out.len()).min(chunkbits);
            let (blk, device_id) = if esz == 4 {
                (u64::from(u32le(extents, i * 4)), 0u16)
            } else {
                let e = &extents[i * 8..i * 8 + 8];
                (
                    u64::from(u32le(e, 4)) | (u64::from(u16le(e, 0)) << 32),
                    u16le(e, 2),
                )
            };
            if blk == NULL_ADDR || (esz == 4 && blk == 0xFFFF_FFFF) {
                out.resize(out.len() + take, 0);
                continue;
            }
            if device_id != 0 {
                return Err(Error::Unsupported("erofs multi-device chunk"));
            }
            let off = blk
                .checked_mul(self.blksz as u64)
                .ok_or(Error::InvalidData("erofs chunk offset overflow"))?;
            let off = usize::try_from(off)
                .map_err(|_| Error::InvalidData("erofs chunk offset overflow"))?;
            let end = off
                .checked_add(take)
                .ok_or(Error::InvalidData("erofs chunk out of range"))?;
            out.extend_from_slice(
                self.data
                    .get(off..end)
                    .ok_or(Error::InvalidData("erofs chunk out of range"))?,
            );
        }
        Ok(out)
    }

    fn read_data(&self, ino: &Inode, ino_off: usize) -> Result<Vec<u8>, Error> {
        match ino.datalayout {
            DATALAYOUT_FLAT_PLAIN => self.read_flat(ino, ino_off, false),
            DATALAYOUT_COMPRESSED_FULL | DATALAYOUT_COMPRESSED_COMPACT => {
                super::z::read_compressed(self, ino, ino_off)
            }
            DATALAYOUT_FLAT_INLINE => self.read_flat(ino, ino_off, true),
            DATALAYOUT_CHUNK_BASED => self.read_chunked(ino, ino_off),
            _ => Err(Error::Unsupported("erofs unknown datalayout")),
        }
    }
}

fn kind_of(ino: &Inode, file_type: u8) -> ErofsKind {
    if ino.is_dir() {
        ErofsKind::Directory
    } else if ino.is_reg() {
        ErofsKind::File
    } else if ino.is_lnk() {
        ErofsKind::Symlink
    } else {
        ErofsKind::Other(file_type)
    }
}

fn walk_dir(
    img: &Img<'_>,
    nid: u64,
    path: &str,
    depth: usize,
    visited: &mut BTreeSet<u64>,
    entries: &mut Vec<ErofsEntry>,
) -> Result<(), Error> {
    if depth > 64 {
        return Err(Error::InvalidData("erofs directory nesting too deep"));
    }
    if !visited.insert(nid) {
        return Err(Error::InvalidData("erofs directory cycle"));
    }
    let (ino_off, ino) = img.read_inode(nid)?;
    if !ino.is_dir() {
        return Err(Error::InvalidData("erofs dirent nid is not a directory"));
    }
    let data = img.read_data(&ino, ino_off)?;
    let dsize = usize::try_from(ino.size).map_err(|_| Error::InvalidData("erofs dir size"))?;
    let data = &data[..dsize.min(data.len())];
    let mut off = 0usize;
    while off < data.len() {
        // Each directory block (of `dirblksz` bytes, possibly a
        // sub-page block when `dirblkbits` is nonzero) is a
        // self-contained dirent/name area.
        let block = &data[off..(off + img.dirblksz).min(data.len())];
        if block.len() < DIRENT_SIZE {
            return Err(Error::InvalidData("erofs truncated dirent block"));
        }
        let nameoff0 = usize::from(u16le(block, 8));
        if nameoff0 < DIRENT_SIZE || nameoff0 > block.len() {
            return Err(Error::InvalidData("erofs corrupt dirent block"));
        }
        // Dirents are 12-byte records packed from offset 0; the
        // name area starts at `nameoff0`.
        let mut i = 0usize;
        while i * DIRENT_SIZE < nameoff0 {
            let d = &block[i * DIRENT_SIZE..i * DIRENT_SIZE + DIRENT_SIZE];
            let child_nid = u64le(d, 0) & 0x7FFF_FFFF_FFFF_FFFF;
            let nameoff = usize::from(u16le(d, 8));
            let next_nameoff = if (i + 1) * DIRENT_SIZE < nameoff0 {
                usize::from(u16le(block, (i + 1) * DIRENT_SIZE + 8))
            } else {
                block.len()
            };
            if nameoff < nameoff0 || nameoff > block.len() || next_nameoff > block.len() {
                return Err(Error::InvalidData("erofs dirent name out of range"));
            }
            let nameend = next_nameoff.max(nameoff).min(block.len());
            let raw = &block[nameoff..nameend];
            // The last name in a block may be padded with NUL bytes.
            let nul = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            let name = &raw[..nul];
            if name.is_empty() {
                return Err(Error::InvalidData("erofs empty dirent name"));
            }
            let file_type = d[10];
            let sname = core::str::from_utf8(name)
                .map_err(|_| Error::InvalidData("erofs non-utf8 name"))?;
            if sname == "." || sname == ".." {
                i += 1;
                continue;
            }
            if sname.contains('/') {
                return Err(Error::InvalidData("erofs dirent name contains slash"));
            }
            if child_nid == nid {
                return Err(Error::InvalidData("erofs dirent self reference"));
            }
            let mut cpath = String::with_capacity(path.len() + sname.len() + 1);
            if !path.is_empty() {
                cpath.push_str(path);
                cpath.push('/');
            }
            cpath.push_str(sname);
            let (c_off, c_ino) = img.read_inode(child_nid)?;
            let kind = kind_of(&c_ino, file_type);
            let cdata = if kind == ErofsKind::Directory || c_ino.size == 0 {
                Vec::new()
            } else {
                img.read_data(&c_ino, c_off)?
            };
            entries.push(ErofsEntry {
                name: cpath.clone(),
                kind,
                mode: c_ino.mode,
                uid: c_ino.uid,
                gid: c_ino.gid,
                nlink: c_ino.nlink,
                mtime: c_ino.mtime,
                mtime_nsec: c_ino.mtime_nsec,
                data: cdata,
            });
            if kind == ErofsKind::Directory {
                walk_dir(img, child_nid, &cpath, depth + 1, visited, entries)?;
            }
            i += 1;
        }
        off += img.dirblksz;
    }
    Ok(())
}

/// Decode an erofs filesystem image.
pub fn decode(input: &[u8]) -> Result<ErofsImage, Error> {
    let sb = input
        .get(SUPER_OFF..SUPER_OFF + SUPER_SIZE)
        .ok_or(Error::UnexpectedEof)?;
    if u32le(sb, 0) != MAGIC {
        return Err(Error::InvalidData("not an erofs image"));
    }
    let feature_compat = u32le(sb, 8);
    let blkszbits = sb[12];
    if !(9..=16).contains(&blkszbits) {
        return Err(Error::InvalidData("erofs invalid block size bits"));
    }
    let blksz = 1usize << blkszbits;
    let sb_size = SUPER_SIZE + sb[13] as usize * 16;
    if input.len() < SUPER_OFF + sb_size || blksz < SUPER_OFF + sb_size {
        return Err(Error::UnexpectedEof);
    }
    if feature_compat & COMPAT_SB_CHKSUM != 0 {
        // CRC32C over `blksz - 1024` bytes starting at the superblock
        // offset, checksum field zeroed, seeded ~0 with no final
        // complement (`erofs_crc32c(~0, sb, len)`).
        let csum_len = blksz - SUPER_OFF;
        let mut region = input[SUPER_OFF..SUPER_OFF + csum_len].to_vec();
        region[4..8].fill(0);
        let stored = u32le(sb, 4);
        let actual = crc32c(&region) ^ 0xFFFF_FFFF;
        if actual != stored {
            return Err(Error::ChecksumMismatch {
                expected: stored,
                actual,
            });
        }
    }
    let feature_incompat = u32le(sb, 80);
    let extra_devices = u16le(sb, 86);
    let dirblkbits = sb[90];
    // Directory blocks are sub-page blocks of `1 << dirblkbits`
    // bytes; 0 selects full filesystem blocks (the only size mkfs
    // currently emits).
    if dirblkbits != 0 && !(4..=blkszbits).contains(&dirblkbits) {
        return Err(Error::InvalidData("erofs invalid dirblkbits"));
    }
    let dirblksz = if dirblkbits == 0 {
        blksz
    } else {
        1usize << dirblkbits
    };
    // Features that change metadata addressing or reference external
    // blobs are out of scope. Long xattr name prefixes do not affect
    // what this decoder interprets.
    if feature_incompat & (INCOMPAT_ZTAILPACKING | INCOMPAT_FRAGMENTS | INCOMPAT_METABOX) != 0
        || extra_devices != 0
    {
        return Err(Error::Unsupported("erofs incompatible feature set"));
    }
    // `INCOMPAT_COMPR_CFGS`: the `u1` union carries the
    // `available_compr_algs` bitmap and each set algorithm is
    // described by a 4-aligned `le16 len` + data record right after
    // the superblock. Without configs the only available algorithm
    // is LZ4 (default settings).
    let (avail_compr_algs, lzma_dict_size) = if feature_incompat & INCOMPAT_COMPR_CFGS != 0 {
        let algs = u16le(sb, 84);
        if algs & !0xF != 0 {
            return Err(Error::Unsupported("erofs unknown compression algorithms"));
        }
        let mut dict_size = 0u32;
        let mut off = SUPER_OFF + sb_size;
        let mut bits = algs;
        let mut alg = 0u8;
        while bits != 0 {
            if bits & 1 != 0 {
                off = (off + 3) & !3;
                let hdr = input.get(off..off + 2).ok_or(Error::UnexpectedEof)?;
                let len = match usize::from(u16le(hdr, 0)) {
                    0 => 1 << 16, // a zero size encodes 65536
                    v => v,
                };
                off += 2;
                let cfg = input.get(off..off + len).ok_or(Error::UnexpectedEof)?;
                match alg {
                    1 => {
                        // z_erofs_lzma_cfgs { dict_size, format }
                        if len < 6 || u16le(cfg, 4) != 0 {
                            return Err(Error::InvalidData("erofs lzma config"));
                        }
                        let d = u32le(cfg, 0);
                        if !(4096..=8 * 1024 * 1024).contains(&d) {
                            return Err(Error::Unsupported("erofs lzma dict size"));
                        }
                        dict_size = d;
                    }
                    2 => {
                        // z_erofs_deflate_cfgs { windowbits }
                        if len < 1 || cfg[0] > 15 {
                            return Err(Error::Unsupported("erofs deflate windowbits"));
                        }
                    }
                    // z_erofs_zstd_cfgs { format, windowlog }
                    3 if len < 2 || cfg[0] != 0 => {
                        return Err(Error::InvalidData("erofs zstd config"));
                    }
                    _ => {}
                }
                off += len;
            }
            bits >>= 1;
            alg += 1;
        }
        (algs, dict_size)
    } else {
        (1u16, 0)
    };
    let has_48bit = feature_incompat & INCOMPAT_48BIT != 0;
    let rootnid = if has_48bit && u64le(sb, 112) != 0 {
        u64le(sb, 112)
    } else {
        u64::from(u16le(sb, 14))
    };
    let blocks = if has_48bit {
        u64::from(u32le(sb, 36)) | (u64::from(u16le(sb, 14)) << 32)
    } else {
        u64::from(u32le(sb, 36))
    };
    let meta_blkaddr = u64::from(u32le(sb, 40));
    let volume_name = {
        let v = &sb[64..80];
        let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
        String::from_utf8_lossy(&v[..end]).into_owned()
    };
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[48..64]);
    let superblock = ErofsSuperblock {
        feature_compat,
        feature_incompat,
        inos: u64le(sb, 16),
        blocks,
        meta_blkaddr: u32le(sb, 40),
        xattr_blkaddr: u32le(sb, 44),
        uuid,
        epoch: u64le(sb, 24),
        fixed_nsec: u32le(sb, 32),
        build_time: u32le(sb, 108),
        xattr_prefix_count: sb[91],
        xattr_prefix_start: u32le(sb, 92),
        packed_nid: u64le(sb, 96),
        ishare_xattr_prefix_id: sb[105],
    };
    let img = Img {
        data: input,
        blksz,
        dirblksz,
        meta_blkaddr,
        epoch: u64le(sb, 24),
        fixed_nsec: u32le(sb, 32),
        avail_compr_algs,
        lz4_0padding: feature_incompat & INCOMPAT_LZ4_0PADDING != 0,
        big_pcluster: feature_incompat & INCOMPAT_BIG_PCLUSTER != 0,
        lzma_dict_size,
    };
    if img
        .iloc(rootnid)
        .is_ok_and(|o| o + INODE_SLOT > input.len())
        || img.iloc(rootnid).is_err()
    {
        return Err(Error::InvalidData("erofs root inode out of range"));
    }
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    walk_dir(&img, rootnid, "", 0, &mut visited, &mut entries)?;
    Ok(ErofsImage {
        volume_name,
        blocks,
        block_size: blksz as u32,
        superblock,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn le16(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn le64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    const BLK: usize = 4096;

    struct DirEnt {
        nid: u64,
        name: &'static [u8],
        ftype: u8,
    }

    /// Minimal erofs image builder: 4 KiB blocks, metadata at block
    /// 0, compact inodes only. Slots after the superblock hold inode
    /// records and inline tail data; data blocks start at block 1.
    struct ImgBuilder {
        data: Vec<u8>,
        /// Next free 32-byte inode slot (nid units).
        next_slot: u64,
        /// Next free data block.
        next_blk: u64,
    }

    impl ImgBuilder {
        fn new() -> Self {
            let mut data = vec![0u8; BLK];
            let sb = &mut data[SUPER_OFF..SUPER_OFF + SUPER_SIZE];
            sb[0..4].copy_from_slice(&le32(MAGIC));
            sb[12] = 12;
            sb[24..32].copy_from_slice(&le64(1_600_000_000));
            sb[36..40].copy_from_slice(&le32(1));
            sb[40..44].copy_from_slice(&le32(0));
            Self {
                data,
                next_slot: (SUPER_OFF + SUPER_SIZE) as u64 / 32, // slot 36
                next_blk: 1,
            }
        }

        fn inode_off(&self, nid: u64) -> usize {
            nid as usize * 32
        }

        /// Reserve `bytes` of inode-area space starting at the next
        /// slot; returns the nid of the first slot.
        fn take_slots(&mut self, bytes: usize) -> u64 {
            let nid = self.next_slot;
            self.next_slot += bytes.div_ceil(32) as u64;
            let need = nid as usize * 32 + bytes;
            if need > self.data.len() {
                self.data.resize(need, 0);
            }
            nid
        }

        /// Write a compact inode at a fresh slot; returns (nid,
        /// inode offset). Extra `tail` bytes after the inode core
        /// are reserved for inline data by the caller.
        fn add_inode(
            &mut self,
            tail: usize,
            datalayout: u8,
            mode: u16,
            nlink: u16,
            size: u32,
            iu: u32,
        ) -> u64 {
            let nid = self.take_slots(32 + tail);
            let off = self.inode_off(nid);
            let mut ifmt: u16 = (datalayout as u16) << 1;
            let nlink1 = mode & 0o170000 != 0o040000 && nlink == 1;
            if nlink1 {
                ifmt |= 0x10; // EROFS_I_NLINK_1_BIT
            }
            self.data[off..off + 2].copy_from_slice(&le16(ifmt));
            self.data[off + 4..off + 6].copy_from_slice(&le16(mode));
            // With NLINK_1 the i_nb field carries the startblk high
            // bits instead of nlink (0 for our small test images).
            self.data[off + 6..off + 8].copy_from_slice(&le16(if nlink1 { 0 } else { nlink }));
            self.data[off + 8..off + 12].copy_from_slice(&le32(size));
            self.data[off + 12..off + 16].copy_from_slice(&le32(0));
            self.data[off + 16..off + 20].copy_from_slice(&le32(iu));
            self.data[off + 24..off + 26].copy_from_slice(&le16(1000));
            self.data[off + 26..off + 28].copy_from_slice(&le16(100));
            nid
        }

        /// Allocate a data block and fill it with `bytes`.
        fn add_block(&mut self, bytes: &[u8]) -> u64 {
            assert!(bytes.len() <= BLK);
            let blk = self.next_blk;
            self.next_blk += 1;
            let off = blk as usize * BLK;
            if self.data.len() < off + BLK {
                self.data.resize(off + BLK, 0);
            }
            self.data[off..off + bytes.len()].copy_from_slice(bytes);
            self.data[1060..1064].copy_from_slice(&le32(self.next_blk as u32));
            blk
        }

        /// Build directory block contents for `ents`.
        fn dir_bytes(ents: &[DirEnt]) -> Vec<u8> {
            let mut name_area = Vec::new();
            let mut nameoffs = Vec::with_capacity(ents.len());
            for e in ents {
                nameoffs.push((ents.len() * DIRENT_SIZE + name_area.len()) as u16);
                name_area.extend_from_slice(e.name);
            }
            let mut blk = vec![0u8; ents.len() * DIRENT_SIZE + name_area.len()];
            for (i, e) in ents.iter().enumerate() {
                let o = i * DIRENT_SIZE;
                blk[o..o + 8].copy_from_slice(&le64(e.nid));
                blk[o + 8..o + 10].copy_from_slice(&le16(nameoffs[i]));
                blk[o + 10] = e.ftype;
            }
            blk[ents.len() * DIRENT_SIZE..].copy_from_slice(&name_area);
            blk
        }

        /// Add a directory inode with `.`/`..` plus `children`.
        /// The data is fully inline when it fits in a block tail.
        fn add_dir(&mut self, children: &[DirEnt]) -> u64 {
            let mut ents = Vec::with_capacity(children.len() + 2);
            ents.push(DirEnt {
                nid: 0,
                name: b".",
                ftype: 4,
            });
            ents.push(DirEnt {
                nid: 0,
                name: b"..",
                ftype: 4,
            });
            for c in children {
                ents.push(DirEnt {
                    nid: c.nid,
                    name: c.name,
                    ftype: c.ftype,
                });
            }
            let bytes = Self::dir_bytes(&ents);
            let size = bytes.len() as u32;
            let nblocks = bytes.len() / BLK;
            let startblk = if nblocks > 0 {
                self.add_block(&bytes[..nblocks * BLK])
            } else {
                0xFFFF_FFFF
            };
            let tail = &bytes[nblocks * BLK..];
            let datalayout = if tail.is_empty() && nblocks > 0 {
                DATALAYOUT_FLAT_PLAIN
            } else {
                DATALAYOUT_FLAT_INLINE
            };
            let nid = self.add_inode(tail.len(), datalayout, 0o40755, 2, size, startblk as u32);
            if !tail.is_empty() {
                let off = self.inode_off(nid) + 32;
                self.data[off..off + tail.len()].copy_from_slice(tail);
            }
            nid
        }

        /// Add a regular file with `content`.
        fn add_file(&mut self, content: &[u8]) -> u64 {
            let size = content.len() as u32;
            let nblocks = content.len() / BLK;
            let startblk = if nblocks > 0 {
                self.add_block(&content[..nblocks * BLK])
            } else {
                0xFFFF_FFFF
            };
            let tail = &content[nblocks * BLK..];
            let datalayout = if tail.is_empty() && nblocks > 0 {
                DATALAYOUT_FLAT_PLAIN
            } else {
                DATALAYOUT_FLAT_INLINE
            };
            let nid = self.add_inode(tail.len(), datalayout, 0o100644, 1, size, startblk as u32);
            if !tail.is_empty() {
                let off = self.inode_off(nid) + 32;
                self.data[off..off + tail.len()].copy_from_slice(tail);
            }
            nid
        }

        /// Add a symlink with `target`.
        fn add_symlink(&mut self, target: &[u8]) -> u64 {
            let size = target.len() as u32;
            let nid = self.add_inode(
                target.len(),
                DATALAYOUT_FLAT_INLINE,
                0o120777,
                1,
                size,
                0xFFFF_FFFF,
            );
            let off = self.inode_off(nid) + 32;
            self.data[off..off + target.len()].copy_from_slice(target);
            nid
        }

        /// Add an extended (64-byte) inode file with `content`.
        fn add_file_extended(&mut self, content: &[u8]) -> u64 {
            let size = content.len() as u64;
            let nblocks = content.len() / BLK;
            let startblk = if nblocks > 0 {
                self.add_block(&content[..nblocks * BLK])
            } else {
                0xFFFF_FFFF
            };
            let tail = &content[nblocks * BLK..];
            let datalayout = if tail.is_empty() && nblocks > 0 {
                DATALAYOUT_FLAT_PLAIN
            } else {
                DATALAYOUT_FLAT_INLINE
            };
            let nid = self.take_slots(64 + tail.len());
            let off = self.inode_off(nid);
            let ifmt: u16 = ((datalayout as u16) << 1) | 1;
            self.data[off..off + 2].copy_from_slice(&le16(ifmt));
            self.data[off + 4..off + 6].copy_from_slice(&le16(0o100640));
            self.data[off + 6..off + 8].copy_from_slice(&le16(0));
            self.data[off + 8..off + 16].copy_from_slice(&le64(size));
            self.data[off + 16..off + 20].copy_from_slice(&le32(startblk as u32));
            self.data[off + 24..off + 28].copy_from_slice(&le32(2000));
            self.data[off + 28..off + 32].copy_from_slice(&le32(200));
            self.data[off + 32..off + 40].copy_from_slice(&le64(1_700_000_000));
            self.data[off + 40..off + 44].copy_from_slice(&le32(123_456_789));
            self.data[off + 44..off + 48].copy_from_slice(&le32(3));
            if !tail.is_empty() {
                let toff = off + 64;
                self.data[toff..toff + tail.len()].copy_from_slice(tail);
            }
            nid
        }

        /// Set superblock incompat feature bits.
        #[allow(dead_code)]
        fn set_incompat(&mut self, bits: u32) {
            let cur = u32le(&self.data[SUPER_OFF..SUPER_OFF + SUPER_SIZE], 80);
            self.data[SUPER_OFF + 80..SUPER_OFF + 84].copy_from_slice(&le32(cur | bits));
        }

        /// Write `available_compr_algs` + per-algorithm config
        /// records (`le16 len` + data, 4-aligned) after the
        /// superblock, in increasing algorithm order. Inode slots
        /// are bumped past the records.
        #[allow(dead_code)]
        fn set_compr_cfgs(&mut self, algs: u16, cfgs: &[&[u8]]) {
            self.set_incompat(INCOMPAT_COMPR_CFGS);
            self.data[SUPER_OFF + 84..SUPER_OFF + 86].copy_from_slice(&le16(algs));
            let mut off = SUPER_OFF + SUPER_SIZE;
            for cfg in cfgs {
                off = (off + 3) & !3;
                let need = off + 2 + cfg.len();
                if need > self.data.len() {
                    self.data.resize(need, 0);
                }
                self.data[off..off + 2].copy_from_slice(&le16(cfg.len() as u16));
                self.data[off + 2..off + 2 + cfg.len()].copy_from_slice(cfg);
                off += 2 + cfg.len();
            }
            let min_slot = (off as u64).div_ceil(32);
            if self.next_slot < min_slot {
                self.next_slot = min_slot;
            }
        }

        /// Allocate `n` contiguous data blocks; `bytes` fills them
        /// from offset 0 and the rest is zero. Returns the first
        /// block number.
        fn add_pcluster(&mut self, bytes: &[u8], n: usize, right_align: bool) -> u64 {
            assert!(bytes.len() <= n * BLK);
            let blk = self.next_blk;
            let off = blk as usize * BLK;
            if self.data.len() < off + n * BLK {
                self.data.resize(off + n * BLK, 0);
            }
            let pos = if right_align {
                off + n * BLK - bytes.len()
            } else {
                off
            };
            self.data[pos..pos + bytes.len()].copy_from_slice(bytes);
            self.next_blk += n as u64;
            self.data[1060..1064].copy_from_slice(&le32(self.next_blk as u32));
            blk
        }

        /// Add a compressed inode (datalayout 1 or 3) whose metadata
        /// area (`z_erofs_map_header` + index records) is `meta`.
        /// `iu` is written to the inode's `i_u` field.
        fn add_zinode(&mut self, datalayout: u8, size: u32, meta: &[u8]) -> u64 {
            let nid = self.add_inode(meta.len(), datalayout, 0o100644, 1, size, 0);
            let off = self.inode_off(nid);
            self.data[off + 32..off + 32 + meta.len()].copy_from_slice(meta);
            nid
        }

        fn build(mut self, root: u64) -> Vec<u8> {
            self.data[1038..1040].copy_from_slice(&le16(root as u16));
            self.data
        }
    }

    /// `z_erofs_map_header` (8 bytes): `[lo32, advise, algo, cbits]`.
    fn zmap_header(advise: u16, algtype: u8, clusterbits: u8) -> [u8; 8] {
        let mut h = [0u8; 8];
        h[4..6].copy_from_slice(&le16(advise));
        h[6] = algtype;
        h[7] = clusterbits;
        h
    }

    /// Non-compact `z_erofs_lcluster_index` head/plain entry.
    fn zidx_head(advise: u16, clusterofs: u16, blkaddr: u32) -> [u8; 8] {
        let mut d = [0u8; 8];
        d[0..2].copy_from_slice(&le16(advise));
        d[2..4].copy_from_slice(&le16(clusterofs));
        d[4..8].copy_from_slice(&le32(blkaddr));
        d
    }

    /// Non-compact NONHEAD index entry.
    #[allow(dead_code)]
    fn zidx_nonhead(delta0: u16, delta1: u16) -> [u8; 8] {
        let mut d = [0u8; 8];
        d[0..2].copy_from_slice(&le16(2)); // LCLUSTER_TYPE_NONHEAD
        d[4..6].copy_from_slice(&le16(delta0));
        d[6..8].copy_from_slice(&le16(delta1));
        d
    }

    /// Bit-pack `entries` (`type << lobits | lo`) into one compacted
    /// pack of `entry_bits`-wide fields followed by `base`.
    fn zpack(entries: &[u16], entry_bits: u32, base: u32) -> Vec<u8> {
        let mut pack = vec![0u8; 4 + entries.len() * entry_bits as usize / 8];
        let mut pos = 0usize;
        for &v in entries {
            for bit in 0..entry_bits as usize {
                if v >> bit & 1 != 0 {
                    pack[(pos + bit) / 8] |= 1 << ((pos + bit) & 7);
                }
            }
            pos += entry_bits as usize;
        }
        let n = pack.len();
        pack[n - 4..].copy_from_slice(&le32(base));
        pack
    }

    /// Compact 4-byte pack: two 16-bit entries + trailing `base`.
    #[allow(dead_code)]
    fn zpack4(e0: u16, e1: u16, base: u32) -> [u8; 8] {
        let mut p = [0u8; 8];
        p[0..2].copy_from_slice(&le16(e0));
        p[2..4].copy_from_slice(&le16(e1));
        p[4..8].copy_from_slice(&le32(base));
        p
    }

    fn build_sample() -> Vec<u8> {
        let mut b = ImgBuilder::new();
        let hello = b.add_file(b"hello erofs\n");
        let big = b.add_file(&vec![b'A'; 5000]);
        let link = b.add_symlink(b"hello.txt");
        let one = b.add_file(b"X");
        let sub = b.add_dir(&[DirEnt {
            nid: one,
            name: b"one.dat",
            ftype: 8,
        }]);
        let root = b.add_dir(&[
            DirEnt {
                nid: big,
                name: b"big.txt",
                ftype: 8,
            },
            DirEnt {
                nid: hello,
                name: b"hello.txt",
                ftype: 8,
            },
            DirEnt {
                nid: link,
                name: b"link.txt",
                ftype: 10,
            },
            DirEnt {
                nid: sub,
                name: b"subdir",
                ftype: 4,
            },
        ]);
        b.build(root)
    }

    #[test]
    fn decode_sample_tree() {
        let img = build_sample();
        let out = decode(&img).expect("decode");
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "big.txt",
                "hello.txt",
                "link.txt",
                "subdir",
                "subdir/one.dat"
            ]
        );
        let big = &out.entries[0];
        assert_eq!(big.kind, ErofsKind::File);
        assert_eq!(big.data.len(), 5000);
        assert!(big.data.iter().all(|&c| c == b'A'));
        let hello = &out.entries[1];
        assert_eq!(hello.data, b"hello erofs\n");
        assert_eq!(hello.mode, 0o100644);
        assert_eq!(hello.mtime, 1_600_000_000);
        assert_eq!(hello.nlink, 1);
        let link = &out.entries[2];
        assert_eq!(link.kind, ErofsKind::Symlink);
        assert_eq!(link.data, b"hello.txt");
        let sub = &out.entries[3];
        assert_eq!(sub.kind, ErofsKind::Directory);
        assert!(sub.data.is_empty());
        assert_eq!(out.entries[4].data, b"X");
    }

    #[test]
    fn extended_inode() {
        let mut b = ImgBuilder::new();
        let f = b.add_file_extended(b"ext data");
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"ext.bin",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries.len(), 1);
        let e = &out.entries[0];
        assert_eq!(e.data, b"ext data");
        assert_eq!(e.mode, 0o100640);
        assert_eq!(e.uid, 2000);
        assert_eq!(e.gid, 200);
        assert_eq!(e.mtime, 1_700_000_000);
        assert_eq!(e.mtime_nsec, 123_456_789);
        assert_eq!(e.nlink, 3);
    }

    #[test]
    fn flat_plain_exact_block() {
        let mut b = ImgBuilder::new();
        let f = b.add_file(&vec![7u8; BLK]);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"exact.bin",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, vec![7u8; BLK]);
    }

    #[test]
    fn hole_file_reads_zeros() {
        let mut b = ImgBuilder::new();
        let f = b.add_inode(0, DATALAYOUT_FLAT_PLAIN, 0o100644, 1, 100, 0xFFFF_FFFF);
        // NLINK_1 compact inode: i_nb carries startblk_hi; a real
        // hole inode has all 48 address bits set.
        let off = b.inode_off(f);
        b.data[off + 6..off + 8].copy_from_slice(&le16(0xFFFF));
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"hole",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, vec![0u8; 100]);
    }

    #[test]
    fn superblock_metadata_fields() {
        // Superblock fields that are irrelevant to decoding still
        // get parsed and exposed verbatim (erofs_fs.h offsets).
        let mut b = ImgBuilder::new();
        b.data[SUPER_OFF + 8..SUPER_OFF + 12]
            .copy_from_slice(&le32(COMPAT_MTIME | COMPAT_XATTR_FILTER));
        b.data[SUPER_OFF + 16..SUPER_OFF + 24].copy_from_slice(&le64(42)); // inos
        b.data[SUPER_OFF + 32..SUPER_OFF + 36].copy_from_slice(&le32(987_654_321));
        b.data[SUPER_OFF + 44..SUPER_OFF + 48].copy_from_slice(&le32(7)); // xattr_blkaddr
        let uuid = [0xABu8; 16];
        b.data[SUPER_OFF + 48..SUPER_OFF + 64].copy_from_slice(&uuid);
        b.data[SUPER_OFF + 64..SUPER_OFF + 73].copy_from_slice(b"vol_erofs");
        b.data[SUPER_OFF + 91] = 3; // xattr_prefix_count
        b.data[SUPER_OFF + 92..SUPER_OFF + 96].copy_from_slice(&le32(0x1234));
        b.data[SUPER_OFF + 96..SUPER_OFF + 104].copy_from_slice(&le64(55)); // packed_nid
        b.data[SUPER_OFF + 105] = 9; // ishare_xattr_prefix_id
        b.data[SUPER_OFF + 108..SUPER_OFF + 112].copy_from_slice(&le32(1_700_000_123));
        let f = b.add_file(b"x");
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"f",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.volume_name, "vol_erofs");
        let sb = &out.superblock;
        assert_eq!(sb.feature_compat, COMPAT_MTIME | COMPAT_XATTR_FILTER);
        assert_eq!(sb.feature_incompat, 0);
        assert_eq!(sb.inos, 42);
        assert_eq!(sb.blocks, out.blocks);
        assert_eq!(sb.meta_blkaddr, 0);
        assert_eq!(sb.xattr_blkaddr, 7);
        assert_eq!(sb.uuid, uuid);
        assert_eq!(sb.epoch, 1_600_000_000); // ImgBuilder default
        assert_eq!(sb.fixed_nsec, 987_654_321);
        assert_eq!(sb.build_time, 1_700_000_123);
        assert_eq!(sb.xattr_prefix_count, 3);
        assert_eq!(sb.xattr_prefix_start, 0x1234);
        assert_eq!(sb.packed_nid, 55);
        assert_eq!(sb.ishare_xattr_prefix_id, 9);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut img = build_sample();
        img[1024] = 0;
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_truncated() {
        let img = build_sample();
        assert!(matches!(decode(&img[..1100]), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn rejects_dir_cycle() {
        let mut b = ImgBuilder::new();
        let root = b.add_dir(&[DirEnt {
            nid: 36,
            name: b"self",
            ftype: 4,
        }]);
        // root nid is the first allocated slot (36) -> self reference
        assert_eq!(root, 36);
        let img = b.build(root);
        assert!(matches!(
            decode(&img),
            Err(Error::InvalidData("erofs dirent self reference"))
        ));
    }

    #[test]
    fn rejects_name_oob() {
        let mut b = ImgBuilder::new();
        let root = b.add_dir(&[DirEnt {
            nid: 40,
            name: b"x",
            ftype: 8,
        }]);
        let mut img = b.build(root);
        // Root dir data is inline at root inode offset + 32; the
        // first dirent's nameoff is at +8.
        let ioff = 36 * 32 + 32;
        img[ioff + 8] = 0xff;
        img[ioff + 9] = 0xff;
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_dangling_nonhead() {
        let mut b = ImgBuilder::new();
        // datalayout 3 = COMPRESSED_COMPACT whose first compacted
        // index is a NONHEAD: a dangling reference with no owning
        // head must be rejected rather than decoded.
        let mut meta = zmap_header(0, 0, 0).to_vec();
        meta.extend_from_slice(&zpack(&[2 << 12 | 1], 16, 0));
        let f = b.add_zinode(3, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z.bin",
            ftype: 8,
        }]);
        let img = b.build(root);
        assert!(decode(&img).is_err());
    }

    /// Compressible 8 KiB payload (two lclusters) for fixtures.
    #[allow(dead_code)]
    fn zdata() -> Vec<u8> {
        let mut v = Vec::with_capacity(8192);
        for i in 0..8192u32 {
            v.push(b'a' + (i / 64 % 26) as u8);
        }
        v
    }

    #[test]
    fn dirblksz_subpage_directory() {
        // dirblkbits = 10 -> 1 KiB directory blocks; entries span
        // two sub-page blocks inside one fs block.
        let mut b = ImgBuilder::new();
        b.data[SUPER_OFF + 90] = 10;
        let f1 = b.add_file(b"first-data");
        let f2 = b.add_file(b"second-data");
        let d0 = ImgBuilder::dir_bytes(&[
            DirEnt {
                nid: 0,
                name: b".",
                ftype: 4,
            },
            DirEnt {
                nid: 0,
                name: b"..",
                ftype: 4,
            },
            DirEnt {
                nid: f1,
                name: b"first",
                ftype: 8,
            },
        ]);
        let d1 = ImgBuilder::dir_bytes(&[DirEnt {
            nid: f2,
            name: b"second",
            ftype: 8,
        }]);
        let mut dirdata = vec![0u8; 2048];
        dirdata[..d0.len()].copy_from_slice(&d0);
        dirdata[1024..1024 + d1.len()].copy_from_slice(&d1);
        let blk = b.add_block(&dirdata);
        let root = b.add_inode(0, DATALAYOUT_FLAT_PLAIN, 0o40755, 2, 2048, blk as u32);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["first", "second"]);
        assert_eq!(out.entries[0].data, b"first-data");
        assert_eq!(out.entries[1].data, b"second-data");
    }

    #[test]
    fn rejects_dirblkbits_out_of_range() {
        let mut b = ImgBuilder::new();
        b.data[SUPER_OFF + 90] = 13; // > blkszbits (12)
        let root = b.add_dir(&[]);
        let img = b.build(root);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
        let mut b = ImgBuilder::new();
        b.data[SUPER_OFF + 90] = 3; // 8-byte blocks cannot hold dirents
        let root = b.add_dir(&[]);
        let img = b.build(root);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_full_lz4_nonhead() {
        // One LZ4 pcluster whose extent covers two lclusters:
        // HEAD1 at lcn0, NONHEAD at lcn1.
        let mut b = ImgBuilder::new();
        let data = vec![b'x'; 8192];
        let c = crate::compress::lz4::encode::encode_block(&data);
        assert!(c.len() <= BLK);
        let p = b.add_pcluster(&c, 1, false);
        let mut meta = zmap_header(0, 0, 0).to_vec();
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        meta.extend_from_slice(&zidx_nonhead(1, 0));
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_full_lz4_0padding() {
        // INCOMPAT_LZ4_0PADDING: streams right-aligned in pclusters.
        let mut b = ImgBuilder::new();
        b.set_incompat(INCOMPAT_LZ4_0PADDING);
        let data = vec![b'y'; 8192];
        let c = crate::compress::lz4::encode::encode_block(&data);
        let p = b.add_pcluster(&c, 1, true);
        let mut meta = zmap_header(0, 0, 0).to_vec();
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        meta.extend_from_slice(&zidx_nonhead(1, 0));
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[test]
    fn compressed_plain_and_hole() {
        // lcn0: PLAIN lcluster with raw data; lcn1: hole lcluster.
        let mut b = ImgBuilder::new();
        let raw = [0x5Au8; BLK];
        let p = b.add_pcluster(&raw, 1, false);
        let mut meta = zmap_header(0, 0, 0).to_vec();
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(0, 0, p as u32)); // PLAIN
        meta.extend_from_slice(&zidx_head(1 | 0x4000, 0, 0)); // HOLE
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data[..BLK], raw);
        assert!(out.entries[0].data[BLK..].iter().all(|&c| c == 0));
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_head2_and_partial_ref() {
        // lcn0 HEAD1 + PARTIAL_REF, lcn1 HEAD2; both algorithms LZ4.
        let mut b = ImgBuilder::new();
        let data = zdata();
        let c0 = crate::compress::lz4::encode::encode_block(&data[..4096]);
        let c1 = crate::compress::lz4::encode::encode_block(&data[4096..]);
        let p0 = b.add_pcluster(&c0, 1, false);
        let p1 = b.add_pcluster(&c1, 1, false);
        let mut meta = zmap_header(0, 0, 0).to_vec(); // algos 0/0 = LZ4
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1 | 0x8000, 0, p0 as u32));
        meta.extend_from_slice(&zidx_head(3, 0, p1 as u32)); // HEAD2
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_big_pcluster_cblkcnt() {
        // advise BIG_PCLUSTER_1 + a CBLKCNT NONHEAD carrying a
        // 2-block compressed length. The sb feature bit aliases
        // COMPR_CFGS, so an LZ4 algorithm record is present.
        let mut b = ImgBuilder::new();
        b.set_compr_cfgs(0b0001, &[&[0u8; 14]]);
        let data = vec![b'w'; 8192];
        let c = crate::compress::lz4::encode::encode_block(&data);
        let p = b.add_pcluster(&c, 2, false); // legacy left-aligned
        let mut meta = zmap_header(0x0002, 0, 0).to_vec();
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        meta.extend_from_slice(&zidx_nonhead(2 | 0x0800, 0)); // CBLKCNT=2
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_compact_4b() {
        // datalayout 3 (COMPRESSED_COMPACT): 4-byte packs hold two
        // 16-bit entries plus a trailing base blkaddr. Every inode
        // slot gives ebase % 32 == 8, so compacted_4b_initial = 6 and
        // both indexes live in the first pack.
        let mut b = ImgBuilder::new();
        let data = zdata();
        let c0 = crate::compress::lz4::encode::encode_block(&data[..4096]);
        let c1 = crate::compress::lz4::encode::encode_block(&data[4096..]);
        let p0 = b.add_pcluster(&c0, 1, false);
        let p1 = b.add_pcluster(&c1, 1, false);
        assert_eq!(p1, p0 + 1);
        // entries: HEAD1/lo=0 -> v = 1 << 12; base = p0 - 1.
        let mut meta = zmap_header(0, 0, 0).to_vec();
        meta.extend_from_slice(&zpack4(1 << 12, 1 << 12, p0 as u32 - 1));
        let f = b.add_zinode(3, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_compact_2b() {
        // COMPACTED_2B advise: 23 lclusters exercise the initial 4B
        // packs (lcn 0..5), one 16-entry 2B pack (lcn 6..21) and the
        // trailing 4B pack (lcn 22).
        let mut b = ImgBuilder::new();
        let nlcluster = 23;
        let mut data = Vec::new();
        let mut pclusters = Vec::new();
        for i in 0..nlcluster {
            let chunk = vec![b'0' + i as u8; BLK];
            data.extend_from_slice(&chunk);
            pclusters.push(crate::compress::lz4::encode::encode_block(&chunk));
        }
        let pstart = b.next_blk;
        for c in &pclusters {
            assert!(c.len() <= BLK);
            b.add_pcluster(c, 1, false);
        }
        let head: u16 = 1 << 12; // HEAD1, lo = 0
        let mut meta = zmap_header(0x0001, 0, 0).to_vec(); // COMPACTED_2B
        // ebase % 32 == 8 -> c4b_init = 6 (packs at ebase+0/8/16)
        meta.extend_from_slice(&zpack4(head, head, pstart as u32 - 1));
        meta.extend_from_slice(&zpack4(head, head, pstart as u32 + 1));
        meta.extend_from_slice(&zpack4(head, head, pstart as u32 + 3));
        // 2B pack: 16 entries x 14 bits (lobits=12), base = last
        // head blkaddr of the previous pack.
        meta.extend_from_slice(&zpack(&[head; 16], 14, pstart as u32 + 5));
        // trailing 4B pack with the last index.
        meta.extend_from_slice(&zpack4(head, 0, pstart as u32 + 21));
        let f = b.add_zinode(3, (nlcluster * BLK) as u32, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_extents_recsz16() {
        // ADVISE_EXTENTS with 16-byte z_erofs_extent records.
        let mut b = ImgBuilder::new();
        let data = vec![b'q'; 8192];
        let c = crate::compress::lz4::encode::encode_block(&data);
        let pb = b.add_pcluster(&c, 1, false);
        let pa = pb as usize * BLK;
        let mut meta = Vec::new();
        // header: extents_lo=1, advise = EXTENTS | recszbits<<1
        // (recsz=16 -> ilog2(16)-2 = 2 -> advise = 1 | 4 = 5).
        let mut h = [0u8; 8];
        h[0..4].copy_from_slice(&le32(1));
        h[4..6].copy_from_slice(&le16(5));
        meta.extend_from_slice(&h);
        meta.resize(16, 0); // records are 16-aligned
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&le32(c.len() as u32 | (1 << 28))); // fmt=1 -> LZ4
        rec[4..8].copy_from_slice(&le32(pa as u32));
        meta.extend_from_slice(&rec);
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn compressed_extents_recsz8() {
        // Fixed-lcluster extent records: plen + pstart per 4K extent.
        let mut b = ImgBuilder::new();
        let data = zdata();
        let c0 = crate::compress::lz4::encode::encode_block(&data[..4096]);
        let c1 = crate::compress::lz4::encode::encode_block(&data[4096..]);
        let p0 = b.add_pcluster(&c0, 1, false);
        let p1 = b.add_pcluster(&c1, 1, false);
        let mut meta = Vec::new();
        // advise = EXTENTS | (ilog2(8)-2)<<1 = 1|2 = 3; clusterbits 0.
        let mut h = [0u8; 8];
        h[4..6].copy_from_slice(&le16(3));
        meta.extend_from_slice(&h);
        for (c, p) in [(&c0, p0), (&c1, p1)] {
            let mut rec = [0u8; 8];
            rec[0..4].copy_from_slice(&le32(c.len() as u32 | (1 << 28)));
            rec[4..8].copy_from_slice(&le32(p as u32 * BLK as u32));
            meta.extend_from_slice(&rec);
        }
        let f = b.add_zinode(1, 8192, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "deflate")]
    #[test]
    fn compressed_deflate() {
        let mut b = ImgBuilder::new();
        // algs = LZ4 | DEFLATE; cfg records in alg order.
        let lz4cfg = [0u8; 14];
        let deflatecfg = [15u8, 0, 0, 0, 0, 0]; // windowbits = 15
        b.set_compr_cfgs(0b0101, &[&lz4cfg, &deflatecfg]);
        let data = vec![b'v'; 4096];
        let c = crate::compress::deflate::encode::encode(
            &data,
            crate::compress::deflate::encode::Level::Default,
        );
        let p = b.add_pcluster(&c, 1, true);
        let mut meta = zmap_header(0, 2, 0).to_vec(); // algo = DEFLATE
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn compressed_zstd() {
        let mut b = ImgBuilder::new();
        let lz4cfg = [0u8; 14];
        let zstdcfg = [0u8; 6]; // format 0
        b.set_compr_cfgs(0b1001, &[&lz4cfg, &zstdcfg]);
        let data = vec![b'u'; 4096];
        let c = crate::compress::zstd::encode::encode(&data);
        let p = b.add_pcluster(&c, 1, true);
        let mut meta = zmap_header(0, 3, 0).to_vec(); // algo = ZSTD
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[cfg(any(
        feature = "lzma-alone",
        feature = "lzip",
        feature = "xz",
        feature = "sevenz",
        feature = "lrzip"
    ))]
    #[test]
    fn compressed_microlzma() {
        use crate::compress::lzma::LzmaProperties;

        let mut b = ImgBuilder::new();
        let lz4cfg = [0u8; 14];
        let mut lzmacfg = [0u8; 14];
        lzmacfg[0..4].copy_from_slice(&le32(8192)); // dict_size
        b.set_compr_cfgs(0b0011, &[&lz4cfg, &lzmacfg]);
        let data = vec![b't'; 4096];
        let props = LzmaProperties::LZIP;
        let mut stream = crate::compress::lzma::lzma_encode_with_props_no_eos(&data, 8192, props);
        // MicroLZMA replaces the leading 0x00 with ~props.
        stream[0] = !props.to_props_byte();
        let p = b.add_pcluster(&stream, 1, true);
        let mut meta = zmap_header(0, 1, 0).to_vec(); // algo = LZMA
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        let out = decode(&img).expect("decode");
        assert_eq!(out.entries[0].data, data);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let mut b = ImgBuilder::new();
        let p = b.add_pcluster(&[0u8; 16], 1, false);
        let mut meta = zmap_header(0, 4, 0).to_vec(); // algo id >= MAX
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        assert!(matches!(decode(&img), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_unavailable_algorithm() {
        // HEAD1 selects LZMA but the image only offers LZ4 (no
        // compression configs -> default bitmap).
        let mut b = ImgBuilder::new();
        let p = b.add_pcluster(&[0u8; 16], 1, false);
        let mut meta = zmap_header(0, 1, 0).to_vec();
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, p as u32));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_packed_inode_bit() {
        let mut b = ImgBuilder::new();
        let mut meta = zmap_header(0, 0, 0x80).to_vec(); // FRAGMENT_INODE_BIT
        // Z_EROFS_FULL_INDEX_START: 8 reserved bytes.
        meta.extend_from_slice(&[0u8; 8]);
        meta.extend_from_slice(&zidx_head(1, 0, 1));
        let f = b.add_zinode(1, 4096, &meta);
        let root = b.add_dir(&[DirEnt {
            nid: f,
            name: b"z",
            ftype: 8,
        }]);
        let img = b.build(root);
        assert!(matches!(decode(&img), Err(Error::Unsupported(_))));
    }
}
