//! `.squashfs` image decoding.
//!
//! Parses the SquashFS 4.0 on-disk format: superblock, metadata block runs
//! (inode / directory tables), lookup tables (fragment / ID / export), and
//! data/fragment blocks. All six compressor IDs are recognized; LZMA 1 (id 2,
//! deprecated upstream) is rejected as unsupported.

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::{lz4, lzo, xz, zlib, zstd};
use crate::error::Error;

const SUPERBLOCK_SIZE: usize = 96;
const MAGIC: u32 = 0x7371_7368;
const META_BLOCK_SIZE: usize = 8192;
const META_UNCOMPRESSED: u16 = 0x8000;
const META_SIZE_MASK: u16 = 0x7fff;
const BLOCK_UNCOMPRESSED: u32 = 1 << 24;
const BLOCK_SIZE_MASK: u32 = 0x00ff_ffff;
const NO_INDEX: u32 = u32::MAX;
const TABLE_ABSENT: u64 = u64::MAX;

const FLAG_COMPRESSOR_OPTIONS: u16 = 0x0400;

const TYPE_BASIC_DIR: u16 = 1;
const TYPE_BASIC_FILE: u16 = 2;
const TYPE_BASIC_SYMLINK: u16 = 3;
const TYPE_BASIC_BLKDEV: u16 = 4;
const TYPE_BASIC_CHRDEV: u16 = 5;
const TYPE_BASIC_FIFO: u16 = 6;
const TYPE_BASIC_SOCKET: u16 = 7;
const TYPE_EXT_DIR: u16 = 8;
const TYPE_EXT_FILE: u16 = 9;
const TYPE_EXT_SYMLINK: u16 = 10;
const TYPE_EXT_BLKDEV: u16 = 11;
const TYPE_EXT_CHRDEV: u16 = 12;
const TYPE_EXT_FIFO: u16 = 13;
const TYPE_EXT_SOCKET: u16 = 14;

/// Compressor selected by the superblock (used for both data and metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SquashfsCompression {
    /// ID 1: zlib streams ("gzip" in upstream naming).
    Gzip,
    /// ID 2: LZMA 1 (deprecated upstream, unsupported here).
    Lzma,
    /// ID 3: LZO1X.
    Lzo,
    /// ID 4: xz streams (LZMA2).
    Xz,
    /// ID 5: LZ4 raw blocks.
    Lz4,
    /// ID 6: zstd frames.
    Zstd,
}

impl SquashfsCompression {
    fn from_id(id: u16) -> Result<Self, Error> {
        match id {
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Lzma),
            3 => Ok(Self::Lzo),
            4 => Ok(Self::Xz),
            5 => Ok(Self::Lz4),
            6 => Ok(Self::Zstd),
            _ => Err(Error::InvalidData("squashfs: unknown compressor id")),
        }
    }

    fn decompress(&self, data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
        match self {
            Self::Gzip => zlib::decode::decode_bounded(data, max_output),
            Self::Lzma => Err(Error::Unsupported(
                "squashfs: LZMA1 compressor is deprecated and unsupported",
            )),
            Self::Lzo => lzo::decode::decompress_lzo1x(data, max_output),
            Self::Xz => xz::decode::decode_bounded(data, max_output),
            Self::Lz4 => lz4::decode::decode_block(data, max_output),
            Self::Zstd => zstd::decode::decode_bounded(data, max_output),
        }
    }
}

/// Parsed superblock fields.
#[derive(Debug, Clone)]
pub struct SquashfsSuperblock {
    /// Number of inodes in the image.
    pub inode_count: u32,
    /// Filesystem creation time (seconds since epoch).
    pub mkfs_time: u32,
    /// Data block size in bytes (4 KiB ..= 1 MiB, power of two).
    pub block_size: u32,
    /// Fragment table entry count (0 when fragments are unused).
    pub frag_count: u32,
    /// Compressor for data and metadata blocks.
    pub compression: SquashfsCompression,
    /// Raw flag bits.
    pub flags: u16,
    /// ID table entry count.
    pub id_count: u16,
    /// Number of bytes the archive occupies (may be less than file size
    /// because images are padded to the device block size).
    pub bytes_used: u64,
}

/// Kind of a filesystem object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SquashfsKind {
    /// Directory.
    Directory,
    /// Regular file.
    File,
    /// Symbolic link (`data` holds the target).
    Symlink,
    /// Block device node.
    BlockDevice,
    /// Character device node.
    CharDevice,
    /// Named pipe.
    Fifo,
    /// Unix socket.
    Socket,
}

/// A filesystem object extracted from the image.
#[derive(Debug, Clone)]
pub struct SquashfsEntry {
    /// Full path from the archive root (e.g. `usr/bin/tool`); the root
    /// directory itself is emitted as `.`.
    pub name: String,
    /// Object type.
    pub kind: SquashfsKind,
    /// Unix permission bits.
    pub mode: u16,
    /// Owner UID (resolved through the ID table).
    pub uid: u32,
    /// Owner GID (resolved through the ID table).
    pub gid: u32,
    /// Modification time (seconds since epoch).
    pub mtime: u32,
    /// SquashFS inode number.
    pub inode: u32,
    /// File contents; the symlink target for symlinks; empty for other kinds.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for SquashfsEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A decoded SquashFS image.
#[derive(Debug, Clone)]
pub struct SquashfsImage {
    /// Parsed superblock.
    pub superblock: SquashfsSuperblock,
    /// All filesystem objects, directories first (pre-order walk).
    pub entries: Vec<SquashfsEntry>,
}

fn le16(input: &[u8], pos: usize) -> Result<u16, Error> {
    let bytes = input.get(pos..pos + 2).ok_or(Error::UnexpectedEof)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le32(input: &[u8], pos: usize) -> Result<u32, Error> {
    let bytes = input.get(pos..pos + 4).ok_or(Error::UnexpectedEof)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le64(input: &[u8], pos: usize) -> Result<u64, Error> {
    let bytes = input.get(pos..pos + 8).ok_or(Error::UnexpectedEof)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// A decompressed run of consecutive metadata blocks. `blocks` maps each
/// block's on-disk offset (relative to the run start) to its offset in the
/// concatenated `data` stream.
struct MetaRun {
    data: Vec<u8>,
    blocks: Vec<(u64, usize)>,
}

impl MetaRun {
    /// Resolve a SquashFS 64-bit metadata reference (`disk_pos << 16 | inner`)
    /// into a byte offset within `data`.
    fn resolve(&self, reference: u64) -> Result<usize, Error> {
        let disk = reference >> 16;
        let inner = (reference & 0xffff) as usize;
        let stream = self
            .blocks
            .iter()
            .find(|&&(pos, _)| pos == disk)
            .map(|&(_, stream)| stream)
            .ok_or(Error::InvalidData("squashfs: bad metadata reference"))?;
        let index = stream + inner;
        if index >= self.data.len() {
            return Err(Error::InvalidData("squashfs: metadata offset out of range"));
        }
        Ok(index)
    }

    fn resolve_dir(&self, block_index: u32, block_offset: u16) -> Result<usize, Error> {
        self.resolve((u64::from(block_index) << 16) | u64::from(block_offset))
    }
}

struct Reader<'a> {
    input: &'a [u8],
    compression: SquashfsCompression,
    block_size: usize,
}

impl Reader<'_> {
    /// Decompress one metadata block starting at `pos`; returns its contents
    /// and the position just past the block.
    fn read_metadata_block(&self, pos: usize) -> Result<(Vec<u8>, usize), Error> {
        let header = le16(self.input, pos)?;
        let size = usize::from(header & META_SIZE_MASK);
        let raw = self
            .input
            .get(pos + 2..pos + 2 + size)
            .ok_or(Error::UnexpectedEof)?;
        let data = if header & META_UNCOMPRESSED != 0 {
            raw.to_vec()
        } else {
            self.compression.decompress(raw, META_BLOCK_SIZE)?
        };
        if data.len() > META_BLOCK_SIZE {
            return Err(Error::InvalidData("squashfs: metadata block overflow"));
        }
        Ok((data, pos + 2 + size))
    }

    /// Decompress a contiguous run of metadata blocks in `[start, end)`.
    fn read_meta_run(&self, start: usize, end: usize) -> Result<MetaRun, Error> {
        let mut run = MetaRun {
            data: Vec::new(),
            blocks: Vec::new(),
        };
        let mut pos = start;
        while pos < end {
            let (block, next) = self.read_metadata_block(pos)?;
            run.blocks.push(((pos - start) as u64, run.data.len()));
            run.data.extend_from_slice(&block);
            pos = next;
        }
        Ok(run)
    }

    /// Read a lookup-table location list at `list_start`, then decompress the
    /// referenced metadata blocks into the concatenated table bytes.
    fn read_lookup_table(
        &self,
        list_start: usize,
        entry_size: usize,
        count: usize,
    ) -> Result<Vec<u8>, Error> {
        let block_count = count
            .checked_mul(entry_size)
            .map(|n| n.div_ceil(META_BLOCK_SIZE))
            .ok_or(Error::InvalidData("squashfs: table size overflow"))?;
        let list_len = block_count
            .checked_mul(8)
            .ok_or(Error::InvalidData("squashfs: table size overflow"))?;
        if list_start + list_len > self.input.len() {
            return Err(Error::UnexpectedEof);
        }
        let mut table = Vec::with_capacity(block_count * META_BLOCK_SIZE);
        for i in 0..block_count {
            let pos = le64(self.input, list_start + i * 8)? as usize;
            let (block, _) = self.read_metadata_block(pos)?;
            table.extend_from_slice(&block);
        }
        Ok(table)
    }

    /// Read a data or fragment block. `size` is the raw `block_sizes` value
    /// (bit 24 = stored uncompressed, lower 24 bits = on-disk size).
    fn read_data_block(
        &self,
        pos: usize,
        size_field: u32,
        expected: usize,
    ) -> Result<Vec<u8>, Error> {
        let size = (size_field & BLOCK_SIZE_MASK) as usize;
        if size == 0 {
            return Ok(alloc::vec![0u8; expected]);
        }
        let raw = self
            .input
            .get(pos..pos + size)
            .ok_or(Error::UnexpectedEof)?;
        if size_field & BLOCK_UNCOMPRESSED != 0 {
            if raw.len() > expected {
                return Err(Error::InvalidData("squashfs: data block size mismatch"));
            }
            Ok(raw.to_vec())
        } else {
            self.compression.decompress(raw, expected)
        }
    }
}

/// Common inode header fields plus the byte offset just past the header.
struct InodeHeader {
    inode_type: u16,
    mode: u16,
    uid_idx: u16,
    gid_idx: u16,
    mtime: u32,
    inode: u32,
}

impl InodeHeader {
    fn parse(data: &[u8], pos: usize) -> Result<Self, Error> {
        Ok(Self {
            inode_type: le16(data, pos)?,
            mode: le16(data, pos + 2)?,
            uid_idx: le16(data, pos + 4)?,
            gid_idx: le16(data, pos + 6)?,
            mtime: le32(data, pos + 8)?,
            inode: le32(data, pos + 12)?,
        })
    }
}

/// Location of a directory listing within the directory table.
#[derive(Clone, Copy)]
struct DirListing {
    block_index: u32,
    block_offset: u16,
    size: u32,
}

enum InodeBody {
    Dir(DirListing),
    File {
        blocks_start: u64,
        frag_index: u32,
        frag_offset: u32,
        file_size: u64,
        block_sizes: Vec<u32>,
    },
    Symlink(Vec<u8>),
    Device(u32),
    Ipc,
}

/// Parse the type-specific inode body. `pos` points just past the common
/// header inside the decompressed inode table.
fn parse_inode_body(data: &[u8], pos: usize, header: &InodeHeader) -> Result<InodeBody, Error> {
    match header.inode_type {
        TYPE_BASIC_DIR => Ok(InodeBody::Dir(DirListing {
            block_index: le32(data, pos)?,
            // link_count at pos+4, file_size (listing+3) at pos+8
            block_offset: le16(data, pos + 10)?,
            size: u32::from(le16(data, pos + 8)?).saturating_sub(3),
        })),
        TYPE_EXT_DIR => Ok(InodeBody::Dir(DirListing {
            // link_count u32, file_size u32, block_index u32, parent u32,
            // index_count u16, block_offset u16, xattr u32
            size: le32(data, pos + 4)?.saturating_sub(3),
            block_index: le32(data, pos + 8)?,
            block_offset: le16(data, pos + 18)?,
        })),
        TYPE_BASIC_SYMLINK | TYPE_EXT_SYMLINK => {
            let target_size = le32(data, pos + 4)? as usize;
            let target = data
                .get(pos + 8..pos + 8 + target_size)
                .ok_or(Error::UnexpectedEof)?
                .to_vec();
            Ok(InodeBody::Symlink(target))
        }
        TYPE_BASIC_BLKDEV | TYPE_BASIC_CHRDEV | TYPE_EXT_BLKDEV | TYPE_EXT_CHRDEV => {
            Ok(InodeBody::Device(le32(data, pos + 4)?))
        }
        TYPE_BASIC_FIFO | TYPE_BASIC_SOCKET | TYPE_EXT_FIFO | TYPE_EXT_SOCKET => Ok(InodeBody::Ipc),
        _ => Err(Error::InvalidData("squashfs: unknown inode type")),
    }
}

fn le_block_sizes(
    data: &[u8],
    pos: usize,
    file_size: u64,
    frag_index: u32,
    block_size: u32,
) -> Result<Vec<u32>, Error> {
    let count = if frag_index == NO_INDEX {
        file_size.div_ceil(u64::from(block_size))
    } else {
        file_size / u64::from(block_size)
    };
    let count =
        usize::try_from(count).map_err(|_| Error::InvalidData("squashfs: too many blocks"))?;
    let mut sizes = Vec::with_capacity(count);
    for i in 0..count {
        sizes.push(le32(data, pos + i * 4)?);
    }
    Ok(sizes)
}

/// Parse one inode; returns the common header, the body, and the stream
/// offset just past the inode.
fn parse_inode(
    data: &[u8],
    pos: usize,
    block_size: u32,
) -> Result<(InodeHeader, InodeBody), Error> {
    let header = InodeHeader::parse(data, pos)?;
    let body = match header.inode_type {
        TYPE_BASIC_FILE => {
            let frag_index = le32(data, pos + 16 + 4)?;
            let file_size = u64::from(le32(data, pos + 16 + 12)?);
            InodeBody::File {
                blocks_start: u64::from(le32(data, pos + 16)?),
                frag_index,
                frag_offset: le32(data, pos + 16 + 8)?,
                file_size,
                block_sizes: le_block_sizes(
                    data,
                    pos + 16 + 16,
                    file_size,
                    frag_index,
                    block_size,
                )?,
            }
        }
        TYPE_EXT_FILE => {
            let frag_index = le32(data, pos + 16 + 28)?;
            let file_size = le64(data, pos + 16 + 8)?;
            InodeBody::File {
                blocks_start: le64(data, pos + 16)?,
                frag_index,
                frag_offset: le32(data, pos + 16 + 32)?,
                file_size,
                block_sizes: le_block_sizes(
                    data,
                    pos + 16 + 40,
                    file_size,
                    frag_index,
                    block_size,
                )?,
            }
        }
        _ => parse_inode_body(data, pos + 16, &header)?,
    };
    Ok((header, body))
}

fn basic_type(inode_type: u16) -> Result<u16, Error> {
    match inode_type {
        TYPE_BASIC_DIR | TYPE_EXT_DIR => Ok(TYPE_BASIC_DIR),
        TYPE_BASIC_FILE | TYPE_EXT_FILE => Ok(TYPE_BASIC_FILE),
        TYPE_BASIC_SYMLINK | TYPE_EXT_SYMLINK => Ok(TYPE_BASIC_SYMLINK),
        TYPE_BASIC_BLKDEV | TYPE_EXT_BLKDEV => Ok(TYPE_BASIC_BLKDEV),
        TYPE_BASIC_CHRDEV | TYPE_EXT_CHRDEV => Ok(TYPE_BASIC_CHRDEV),
        TYPE_BASIC_FIFO | TYPE_EXT_FIFO => Ok(TYPE_BASIC_FIFO),
        TYPE_BASIC_SOCKET | TYPE_EXT_SOCKET => Ok(TYPE_BASIC_SOCKET),
        _ => Err(Error::InvalidData("squashfs: unknown inode type")),
    }
}

fn kind_of(basic: u16) -> SquashfsKind {
    match basic {
        TYPE_BASIC_DIR => SquashfsKind::Directory,
        TYPE_BASIC_FILE => SquashfsKind::File,
        TYPE_BASIC_SYMLINK => SquashfsKind::Symlink,
        TYPE_BASIC_BLKDEV => SquashfsKind::BlockDevice,
        TYPE_BASIC_CHRDEV => SquashfsKind::CharDevice,
        TYPE_BASIC_FIFO => SquashfsKind::Fifo,
        _ => SquashfsKind::Socket,
    }
}

/// Decode a SquashFS 4.0 image. All filesystem objects are materialized into
/// [`SquashfsImage::entries`] in pre-order; regular file contents and symlink
/// targets are read eagerly.
///
/// # Errors
///
/// Returns an error for malformed headers, unknown compressor/inode types,
/// out-of-range references, or decompression failures.
pub fn decode(input: &[u8]) -> Result<SquashfsImage, Error> {
    decode_with_limit(input, None)
}

/// Decode with a cap on the bytes a single data/fragment block may expand to
/// and on each metadata block (fixed at 8 KiB by the format).
///
/// # Errors
///
/// Same as [`decode`].
pub fn decode_with_limit(input: &[u8], _max_output: Option<usize>) -> Result<SquashfsImage, Error> {
    if input.len() < SUPERBLOCK_SIZE {
        return Err(Error::UnexpectedEof);
    }
    if le32(input, 0)? != MAGIC {
        return Err(Error::InvalidData("squashfs: bad magic"));
    }
    let inode_count = le32(input, 4)?;
    let block_size = le32(input, 12)?;
    let frag_count = le32(input, 16)?;
    let compression = SquashfsCompression::from_id(le16(input, 20)?)?;
    let block_log = le16(input, 22)?;
    let flags = le16(input, 24)?;
    let id_count = le16(input, 26)?;
    if le16(input, 28)? != 4 || le16(input, 30)? != 0 {
        return Err(Error::InvalidData("squashfs: unsupported version"));
    }
    if !(4096..=(1 << 20)).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(Error::InvalidData("squashfs: bad block size"));
    }
    if u32::from(block_log) != block_size.trailing_zeros() {
        return Err(Error::InvalidData(
            "squashfs: block_size/block_log mismatch",
        ));
    }
    let root_inode_ref = le64(input, 32)?;
    let bytes_used = le64(input, 40)?.min(input.len() as u64);
    let id_table_start = le64(input, 48)?;
    let xattr_table_start = le64(input, 56)?;
    let inode_table_start = le64(input, 64)?;
    let dir_table_start = le64(input, 72)?;
    let frag_table_start = le64(input, 80)?;
    let export_table_start = le64(input, 88)?;

    for &offset in &[inode_table_start, dir_table_start] {
        if offset >= bytes_used {
            return Err(Error::InvalidData("squashfs: table offset out of range"));
        }
    }
    if dir_table_start <= inode_table_start {
        return Err(Error::InvalidData("squashfs: table ordering violated"));
    }

    let reader = Reader {
        input,
        compression,
        block_size: block_size as usize,
    };

    // Optional compressor-options metadata block right after the superblock;
    // it carries no decoder-required information and is skipped.

    // The directory table ends where the first trailing section begins
    // (fragment/export/ID/xattr location lists) or at `bytes_used`.
    let dir_table_end = [
        frag_table_start,
        export_table_start,
        id_table_start,
        xattr_table_start,
    ]
    .into_iter()
    .filter(|&v| v != TABLE_ABSENT && v > dir_table_start)
    .min()
    .unwrap_or(bytes_used);

    let inode_run = reader.read_meta_run(inode_table_start as usize, dir_table_start as usize)?;
    let dir_run = reader.read_meta_run(dir_table_start as usize, dir_table_end as usize)?;

    let frag_table = if frag_table_start == TABLE_ABSENT || frag_count == 0 {
        Vec::new()
    } else {
        reader.read_lookup_table(frag_table_start as usize, 16, frag_count as usize)?
    };
    let id_table = if id_table_start == TABLE_ABSENT {
        Vec::new()
    } else {
        reader.read_lookup_table(id_table_start as usize, 4, usize::from(id_count))?
    };

    let mut entries = Vec::new();
    let mut visited = 0u32;
    walk_dir(
        &reader,
        &inode_run,
        &dir_run,
        &frag_table,
        &id_table,
        root_inode_ref,
        String::new(),
        &mut entries,
        &mut visited,
        inode_count,
    )?;

    let _ = flags & FLAG_COMPRESSOR_OPTIONS;

    Ok(SquashfsImage {
        superblock: SquashfsSuperblock {
            inode_count,
            mkfs_time: le32(input, 8)?,
            block_size,
            frag_count,
            compression,
            flags,
            id_count,
            bytes_used: le64(input, 40)?,
        },
        entries,
    })
}

fn lookup_id(id_table: &[u8], index: u16) -> Result<u32, Error> {
    le32(id_table, usize::from(index) * 4)
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    reader: &Reader<'_>,
    inode_run: &MetaRun,
    dir_run: &MetaRun,
    frag_table: &[u8],
    id_table: &[u8],
    inode_ref: u64,
    path: String,
    entries: &mut Vec<SquashfsEntry>,
    visited: &mut u32,
    inode_count: u32,
) -> Result<(), Error> {
    *visited += 1;
    if *visited > inode_count {
        return Err(Error::InvalidData("squashfs: inode count exceeded"));
    }
    let pos = inode_run.resolve(inode_ref)?;
    let (header, body) = parse_inode(&inode_run.data, pos, reader.block_size as u32)?;
    let uid = lookup_id(id_table, header.uid_idx).unwrap_or(0);
    let gid = lookup_id(id_table, header.gid_idx).unwrap_or(0);
    let basic = basic_type(header.inode_type)?;
    let name = if path.is_empty() {
        String::from(".")
    } else {
        path.clone()
    };

    let (data, listing): (Vec<u8>, Option<DirListing>) = match &body {
        InodeBody::Dir(listing) => (Vec::new(), Some(*listing)),
        InodeBody::File {
            blocks_start,
            frag_index,
            frag_offset,
            file_size,
            block_sizes,
        } => (
            read_file(
                reader,
                frag_table,
                *blocks_start,
                *frag_index,
                *frag_offset,
                *file_size,
                block_sizes,
            )?,
            None,
        ),
        InodeBody::Symlink(target) => (target.clone(), None),
        InodeBody::Device(dev) => (dev.to_le_bytes().to_vec(), None),
        InodeBody::Ipc => (Vec::new(), None),
    };

    entries.push(SquashfsEntry {
        name,
        kind: kind_of(basic),
        mode: header.mode,
        uid,
        gid,
        mtime: header.mtime,
        inode: header.inode,
        data,
    });

    if let Some(listing) = listing {
        let children = read_dir_listing(dir_run, listing)?;
        for (child_ref, child_type, child_name) in children {
            let child_path = if path.is_empty() {
                child_name.clone()
            } else {
                alloc::format!("{path}/{child_name}")
            };
            let child_pos = inode_run.resolve(child_ref)?;
            let (child_header, _) =
                parse_inode(&inode_run.data, child_pos, reader.block_size as u32)?;
            if basic_type(child_header.inode_type)? != child_type {
                return Err(Error::InvalidData("squashfs: directory type mismatch"));
            }
            if child_header.inode_type == TYPE_BASIC_DIR || child_header.inode_type == TYPE_EXT_DIR
            {
                walk_dir(
                    reader,
                    inode_run,
                    dir_run,
                    frag_table,
                    id_table,
                    child_ref,
                    child_path,
                    entries,
                    visited,
                    inode_count,
                )?;
            } else {
                *visited += 1;
                if *visited > inode_count {
                    return Err(Error::InvalidData("squashfs: inode count exceeded"));
                }
                let (ch, body) = parse_inode(&inode_run.data, child_pos, reader.block_size as u32)?;
                let data = match &body {
                    InodeBody::File {
                        blocks_start,
                        frag_index,
                        frag_offset,
                        file_size,
                        block_sizes,
                    } => read_file(
                        reader,
                        frag_table,
                        *blocks_start,
                        *frag_index,
                        *frag_offset,
                        *file_size,
                        block_sizes,
                    )?,
                    InodeBody::Symlink(target) => target.clone(),
                    InodeBody::Device(dev) => dev.to_le_bytes().to_vec(),
                    _ => Vec::new(),
                };
                entries.push(SquashfsEntry {
                    name: child_path,
                    kind: kind_of(basic_type(ch.inode_type)?),
                    mode: ch.mode,
                    uid: lookup_id(id_table, ch.uid_idx).unwrap_or(0),
                    gid: lookup_id(id_table, ch.gid_idx).unwrap_or(0),
                    mtime: ch.mtime,
                    inode: ch.inode,
                    data,
                });
            }
        }
    }
    Ok(())
}

/// Parse a directory listing of `size` uncompressed bytes starting at the
/// given directory-table location.
fn read_dir_listing(
    dir_run: &MetaRun,
    listing: DirListing,
) -> Result<Vec<(u64, u16, String)>, Error> {
    if listing.size == 0 {
        return Ok(Vec::new());
    }
    let mut pos = dir_run.resolve_dir(listing.block_index, listing.block_offset)?;
    let end = pos
        .checked_add(listing.size as usize)
        .filter(|&e| e <= dir_run.data.len())
        .ok_or(Error::InvalidData(
            "squashfs: directory listing out of range",
        ))?;
    let mut entries = Vec::new();
    while pos < end {
        // Header: count(u32, off-by-one), start(u32), inode_number(u32).
        let count = le32(&dir_run.data, pos)? as usize + 1;
        let block_start = le32(&dir_run.data, pos + 4)?;
        let base_inode = le32(&dir_run.data, pos + 8)? as i64;
        pos += 12;
        for _ in 0..count {
            let offset = le16(&dir_run.data, pos)?;
            let inode_diff = le16(&dir_run.data, pos + 2)? as i16 as i64;
            let entry_type = le16(&dir_run.data, pos + 4)?;
            let name_len = usize::from(le16(&dir_run.data, pos + 6)?) + 1;
            pos += 8;
            if pos + name_len > dir_run.data.len() {
                return Err(Error::UnexpectedEof);
            }
            let name = String::from_utf8_lossy(&dir_run.data[pos..pos + name_len]).into_owned();
            pos += name_len;
            let _inode_number = base_inode + inode_diff;
            let child_ref = (u64::from(block_start) << 16) | u64::from(offset);
            entries.push((child_ref, entry_type, name));
        }
    }
    if pos != end {
        return Err(Error::InvalidData(
            "squashfs: directory listing size mismatch",
        ));
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn read_file(
    reader: &Reader<'_>,
    frag_table: &[u8],
    blocks_start: u64,
    frag_index: u32,
    frag_offset: u32,
    file_size: u64,
    block_sizes: &[u32],
) -> Result<Vec<u8>, Error> {
    let block_size = reader.block_size as u64;
    let mut out = Vec::with_capacity(file_size.min(1 << 26) as usize);
    let mut pos = blocks_start;
    for (i, &size_field) in block_sizes.iter().enumerate() {
        let remaining = file_size.saturating_sub(i as u64 * block_size);
        let expected = remaining.min(block_size) as usize;
        let block = reader.read_data_block(pos as usize, size_field, expected)?;
        pos += u64::from(size_field & BLOCK_SIZE_MASK);
        out.extend_from_slice(&block);
    }
    let tail = file_size % block_size;
    if frag_index != NO_INDEX && tail > 0 {
        let base = frag_index as usize * 16;
        let frag_start = le64(frag_table, base)? as usize;
        let frag_size = le32(frag_table, base + 8)?;
        let frag = reader.read_data_block(frag_start, frag_size, reader.block_size)?;
        let offset = frag_offset as usize;
        let end = offset
            .checked_add(tail as usize)
            .filter(|&e| e <= frag.len())
            .ok_or(Error::InvalidData("squashfs: fragment offset out of range"))?;
        out.extend_from_slice(&frag[offset..end]);
    }
    if out.len() as u64 != file_size {
        return Err(Error::InvalidData("squashfs: file size mismatch"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::zlib;
    use alloc::vec;

    const COMPRESS_ID: u16 = 1; // zlib ("gzip" upstream)

    /// Node for the test image builder.
    enum Node {
        File(
            &'static str,
            &'static [u8],
            bool, /* use fragment tail */
        ),
        Dir(&'static str, Vec<Node>),
        Symlink(&'static str, &'static str),
        /// Regular file emitted as an extended file inode (TYPE_EXT_FILE).
        ExtFile(
            &'static str,
            &'static [u8],
            bool, /* use fragment tail */
        ),
        /// Arbitrary inode with a caller-supplied type-specific body.
        Raw(
            &'static str,
            u16, /* inode type */
            u16, /* mode */
            Vec<u8>,
        ),
    }

    struct Builder {
        data_region: Vec<u8>,
        inode_stream: Vec<u8>,
        dir_stream: Vec<u8>,
        fragment_payload: Vec<u8>,
        fragment_offsets: Vec<u32>, // per-frag offset within fragment_payload
        frag_block_start: u64,
        compress: bool,
        block_size: u32,
        next_inode: u32,
        /// Emit directories as extended directory inodes (TYPE_EXT_DIR).
        ext_dirs: bool,
    }

    impl Builder {
        fn new(compress: bool) -> Self {
            Self {
                data_region: Vec::new(),
                inode_stream: Vec::new(),
                dir_stream: Vec::new(),
                fragment_payload: Vec::new(),
                fragment_offsets: Vec::new(),
                frag_block_start: 0,
                compress,
                block_size: 4096,
                next_inode: 1,
                ext_dirs: false,
            }
        }

        fn pack_flag(&self, raw: &[u8]) -> (Vec<u8>, bool) {
            if self.compress {
                (zlib::encode::encode(raw), false)
            } else {
                (raw.to_vec(), true)
            }
        }

        /// Append `raw` to `stream` as metadata blocks (8 KiB chunks), each
        /// preceded by the 16-bit size header.
        fn emit_meta_run(&self, out: &mut Vec<u8>, stream: &[u8]) {
            for chunk in stream.chunks(META_BLOCK_SIZE) {
                if self.compress {
                    let packed = zlib::encode::encode(chunk);
                    let (body, flag) = if packed.len() < chunk.len() {
                        (packed, 0u16)
                    } else {
                        (chunk.to_vec(), META_UNCOMPRESSED)
                    };
                    out.extend_from_slice(&((body.len() as u16) | flag).to_le_bytes());
                    out.extend_from_slice(&body);
                } else {
                    out.extend_from_slice(
                        &((chunk.len() as u16) | META_UNCOMPRESSED).to_le_bytes(),
                    );
                    out.extend_from_slice(chunk);
                }
            }
        }

        fn emit_inode(&mut self, inode_type: u16, mode: u16, body: &[u8]) -> usize {
            let pos = self.inode_stream.len();
            let inode = self.next_inode;
            self.next_inode += 1;
            self.inode_stream
                .extend_from_slice(&inode_type.to_le_bytes());
            self.inode_stream.extend_from_slice(&mode.to_le_bytes());
            self.inode_stream.extend_from_slice(&0u16.to_le_bytes()); // uid idx
            self.inode_stream.extend_from_slice(&0u16.to_le_bytes()); // gid idx
            self.inode_stream.extend_from_slice(&0u32.to_le_bytes()); // mtime
            self.inode_stream.extend_from_slice(&inode.to_le_bytes());
            self.inode_stream.extend_from_slice(body);
            pos
        }

        fn emit_dir(&mut self, children: Vec<Node>) -> usize {
            let mut listing_size = 0u32;
            // We need each child's stream offset; emit children first and
            // remember offsets. Dir inode is emitted afterwards at dir_pos
            // would misorder — instead emit dir inode now with values we can
            // compute, since children are emitted below into the same stream.
            //
            // Simpler: emit children first, then the dir inode; refs point to
            // stream offsets regardless of order.
            let mut entries = Vec::new();
            for child in children {
                let (off, ty, name, ino) = self.emit_node(child);
                entries.push((off, ty, name, ino));
            }
            let listing_off = self.dir_stream.len();
            if !entries.is_empty() {
                // One dir header covering all entries.
                let start = 0u32; // inode meta block 0 relative offset
                let base = entries.first().unwrap().3;
                self.dir_stream
                    .extend_from_slice(&(entries.len() as u32 - 1).to_le_bytes());
                self.dir_stream.extend_from_slice(&start.to_le_bytes());
                self.dir_stream.extend_from_slice(&base.to_le_bytes());
                for (off, ty, name, ino) in &entries {
                    self.dir_stream
                        .extend_from_slice(&(*off as u16).to_le_bytes());
                    self.dir_stream
                        .extend_from_slice(&(*ino as i16 - base as i16).to_le_bytes());
                    self.dir_stream.extend_from_slice(&ty.to_le_bytes());
                    self.dir_stream
                        .extend_from_slice(&(name.len() as u16 - 1).to_le_bytes());
                    self.dir_stream.extend_from_slice(name.as_bytes());
                }
                listing_size = self.dir_stream.len() as u32 - listing_off as u32;
            }
            if self.ext_dirs {
                // extended dir body: link_count u32, file_size(+3) u32,
                // block_index u32, parent u32, index_count u16,
                // block_offset u16, xattr u32
                let mut body = Vec::new();
                body.extend_from_slice(&(entries.len() as u32 + 2).to_le_bytes());
                body.extend_from_slice(&(listing_size + 3).to_le_bytes());
                body.extend_from_slice(&0u32.to_le_bytes());
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&0u16.to_le_bytes());
                body.extend_from_slice(&(listing_off as u16).to_le_bytes());
                body.extend_from_slice(&NO_INDEX.to_le_bytes());
                return self.emit_inode(TYPE_EXT_DIR, 0o755, &body);
            }
            // basic dir body: block_index, link_count, file_size(+3),
            // block_offset, parent
            let mut body = Vec::new();
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&(entries.len() as u32 + 2).to_le_bytes());
            body.extend_from_slice(&((listing_size + 3) as u16).to_le_bytes());
            body.extend_from_slice(&(listing_off as u16).to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            self.emit_inode(TYPE_BASIC_DIR, 0o755, &body)
        }

        fn emit_node(&mut self, node: Node) -> (usize, u16, String, u32) {
            match node {
                Node::File(name, content, use_frag) => {
                    self.emit_file(name, content, use_frag, false)
                }
                Node::ExtFile(name, content, use_frag) => {
                    self.emit_file(name, content, use_frag, true)
                }
                Node::Raw(name, inode_type, mode, body) => {
                    let ino = self.next_inode;
                    let pos = self.emit_inode(inode_type, mode, &body);
                    let entry_type = basic_type(inode_type).unwrap();
                    (pos, entry_type, name.to_owned(), ino)
                }
                Node::Dir(name, children) => {
                    let ino = self.next_inode;
                    let pos = self.emit_dir(children);
                    (pos, TYPE_BASIC_DIR, name.to_owned(), ino)
                }
                Node::Symlink(name, target) => {
                    let mut body = Vec::new();
                    body.extend_from_slice(&1u32.to_le_bytes());
                    body.extend_from_slice(&(target.len() as u32).to_le_bytes());
                    body.extend_from_slice(target.as_bytes());
                    let ino = self.next_inode;
                    let pos = self.emit_inode(TYPE_BASIC_SYMLINK, 0o777, &body);
                    (pos, TYPE_BASIC_SYMLINK, name.to_owned(), ino)
                }
            }
        }

        fn emit_file(
            &mut self,
            name: &str,
            content: &[u8],
            use_frag: bool,
            extended: bool,
        ) -> (usize, u16, String, u32) {
            let mut body = Vec::new();
            let blocks_start = self.data_region.len() as u64 + self.frag_block_start;
            let bs = self.block_size as usize;
            let (block_count, tail) = if use_frag {
                (content.len() / bs, content.len() % bs)
            } else {
                (content.len().div_ceil(bs), 0)
            };
            for i in 0..block_count {
                let chunk = &content[i * bs..(i * bs + bs).min(content.len())];
                let (packed, raw_flag) = self.pack_flag(chunk);
                let (body_bytes, flag) = if packed.len() < chunk.len() {
                    (packed, 0u32)
                } else {
                    (chunk.to_vec(), BLOCK_UNCOMPRESSED)
                };
                let _ = raw_flag;
                let field = body_bytes.len() as u32 | flag;
                self.data_region.extend_from_slice(&body_bytes);
                body.extend_from_slice(&field.to_le_bytes());
            }
            let frag_index = if use_frag && tail > 0 {
                self.fragment_offsets
                    .push(self.fragment_payload.len() as u32);
                self.fragment_payload
                    .extend_from_slice(&content[content.len() - tail..]);
                0u32
            } else {
                NO_INDEX
            };
            let frag_off = if frag_index == NO_INDEX {
                0
            } else {
                *self.fragment_offsets.last().unwrap()
            };
            let mut full = Vec::new();
            let inode_type = if extended {
                // extended file body (SquashFS 4.0 §5.3 / kernel
                // `squashfs_lreg_inode`): blocks_start u64,
                // file_size u64, sparse u64, link_count u32,
                // frag_index u32, block_offset u32, xattr u32,
                // block_sizes[]
                full.extend_from_slice(&blocks_start.to_le_bytes());
                full.extend_from_slice(&(content.len() as u64).to_le_bytes());
                full.extend_from_slice(&0u64.to_le_bytes()); // sparse
                full.extend_from_slice(&2u32.to_le_bytes()); // link_count
                full.extend_from_slice(&frag_index.to_le_bytes());
                full.extend_from_slice(&frag_off.to_le_bytes());
                full.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
                TYPE_EXT_FILE
            } else {
                full.extend_from_slice(&(blocks_start as u32).to_le_bytes());
                full.extend_from_slice(&frag_index.to_le_bytes());
                full.extend_from_slice(&frag_off.to_le_bytes());
                full.extend_from_slice(&(content.len() as u32).to_le_bytes());
                TYPE_BASIC_FILE
            };
            full.extend_from_slice(&body);
            let ino = self.next_inode;
            let pos = self.emit_inode(inode_type, 0o644, &full);
            (pos, TYPE_BASIC_FILE, name.to_owned(), ino)
        }

        fn build(mut self, children: Vec<Node>) -> Vec<u8> {
            // Data region begins right after the superblock.
            self.frag_block_start = SUPERBLOCK_SIZE as u64;
            let root_pos = self.emit_dir(children);
            let root_ref = (root_pos as u64) & 0xffff; // block 0

            // Pack fragment block (single block holding all tails).
            let frag_count = u32::from(!self.fragment_payload.is_empty());
            let mut frag_block = Vec::new();
            let mut frag_size_field = 0u32;
            if frag_count > 0 {
                let (packed, _) = self.pack_flag(&self.fragment_payload);
                let (body, flag) = if packed.len() < self.fragment_payload.len() {
                    (packed, 0u32)
                } else {
                    (self.fragment_payload.clone(), BLOCK_UNCOMPRESSED)
                };
                frag_size_field = body.len() as u32 | flag;
                frag_block = body;
            }

            let mut img = vec![0u8; SUPERBLOCK_SIZE];
            // data region
            let data_start = img.len();
            // blocks_start in inodes was computed relative to frag_block_start=96
            img.extend_from_slice(&self.data_region.clone());
            let frag_pos = img.len();
            img.extend_from_slice(&frag_block);
            let inode_table_start = img.len();
            let mut meta = Vec::new();
            self.emit_meta_run(&mut meta, &self.inode_stream.clone());
            img.extend_from_slice(&meta);
            let dir_table_start = img.len();
            let mut dir_meta = Vec::new();
            self.emit_meta_run(&mut dir_meta, &self.dir_stream.clone());
            img.extend_from_slice(&dir_meta);
            let frag_table_start = img.len();
            if frag_count > 0 {
                // location list (1 u64) + meta block with the table entry
                let entry_pos = frag_table_start + 8;
                img.extend_from_slice(&(entry_pos as u64).to_le_bytes());
                let mut entry = Vec::new();
                entry.extend_from_slice(&(frag_pos as u64).to_le_bytes());
                entry.extend_from_slice(&frag_size_field.to_le_bytes());
                entry.extend_from_slice(&0u32.to_le_bytes());
                self.emit_meta_run(&mut img, &entry);
            }
            let id_table_start = img.len();
            // ID table: one entry (uid/gid 0)
            let id_meta_pos = id_table_start + 8;
            img.extend_from_slice(&(id_meta_pos as u64).to_le_bytes());
            self.emit_meta_run(&mut img, &0u32.to_le_bytes());

            let bytes_used = img.len() as u64;
            // superblock
            img[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            img[4..8].copy_from_slice(&(self.next_inode - 1).to_le_bytes());
            img[8..12].copy_from_slice(&0u32.to_le_bytes()); // mkfs_time
            img[12..16].copy_from_slice(&self.block_size.to_le_bytes());
            img[16..20].copy_from_slice(&frag_count.to_le_bytes());
            img[20..22].copy_from_slice(&COMPRESS_ID.to_le_bytes());
            img[22..24].copy_from_slice(&12u16.to_le_bytes()); // block_log
            img[24..26].copy_from_slice(&0u16.to_le_bytes()); // flags
            img[26..28].copy_from_slice(&1u16.to_le_bytes()); // id_count
            img[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
            img[30..32].copy_from_slice(&0u16.to_le_bytes()); // minor
            img[32..40].copy_from_slice(&root_ref.to_le_bytes());
            img[40..48].copy_from_slice(&bytes_used.to_le_bytes());
            img[48..56].copy_from_slice(&(id_table_start as u64).to_le_bytes());
            img[56..64].copy_from_slice(&TABLE_ABSENT.to_le_bytes()); // xattr
            img[64..72].copy_from_slice(&(inode_table_start as u64).to_le_bytes());
            img[72..80].copy_from_slice(&(dir_table_start as u64).to_le_bytes());
            if frag_count > 0 {
                img[80..88].copy_from_slice(&(frag_table_start as u64).to_le_bytes());
            } else {
                img[80..88].copy_from_slice(&TABLE_ABSENT.to_le_bytes());
            }
            img[88..96].copy_from_slice(&TABLE_ABSENT.to_le_bytes()); // export
            let _ = data_start;
            img
        }
    }

    #[test]
    fn parses_basic_image() {
        let img =
            Builder::new(false).build(vec![Node::File("hello.txt", b"hello squashfs", false)]);
        let image = decode(&img).unwrap();
        assert_eq!(image.superblock.block_size, 4096);
        assert_eq!(image.entries.len(), 2);
        assert_eq!(image.entries[0].name, ".");
        assert_eq!(image.entries[0].kind, SquashfsKind::Directory);
        assert_eq!(image.entries[1].name, "hello.txt");
        assert_eq!(image.entries[1].kind, SquashfsKind::File);
        assert_eq!(image.entries[1].data, b"hello squashfs");
    }

    #[test]
    fn parses_compressed_metadata_and_data() {
        let content: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let mut owned = Vec::new();
        owned.extend_from_slice(&content);
        let img = Builder::new(true).build(vec![Node::File(
            "big.bin",
            Box::leak(owned.into_boxed_slice()),
            false,
        )]);
        let image = decode(&img).unwrap();
        let file = &image.entries[1];
        assert_eq!(file.name, "big.bin");
        assert_eq!(file.data, content);
    }

    #[test]
    fn parses_subdir_symlink() {
        let img = Builder::new(false).build(vec![
            Node::Dir("usr", vec![Node::File("tool", b"tool-data", false)]),
            Node::Symlink("link", "usr/tool"),
        ]);
        let image = decode(&img).unwrap();
        let names: Vec<_> = image.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".", "usr", "usr/tool", "link"]);
        assert_eq!(image.entries[2].data, b"tool-data");
        assert_eq!(image.entries[3].kind, SquashfsKind::Symlink);
        assert_eq!(image.entries[3].data, b"usr/tool");
    }

    #[test]
    fn parses_fragment_tail() {
        let img = Builder::new(false).build(vec![Node::File("tail.bin", b"tail-end", true)]);
        let image = decode(&img).unwrap();
        let file = &image.entries[1];
        assert_eq!(file.data, b"tail-end");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut img = Builder::new(false).build(vec![]);
        img[0] = 0;
        assert!(decode(&img).is_err());
    }

    #[test]
    fn rejects_bad_version() {
        let mut img = Builder::new(false).build(vec![]);
        img[28] = 3;
        assert!(decode(&img).is_err());
    }

    #[test]
    fn rejects_bad_block_size() {
        let mut img = Builder::new(false).build(vec![]);
        img[12..16].copy_from_slice(&12345u32.to_le_bytes());
        assert!(decode(&img).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let img = Builder::new(false).build(vec![Node::File("f", b"x", false)]);
        let truncated = &img[..img.len() - 20];
        assert!(decode(truncated).is_err());
    }

    /// Concatenate little-endian u32 fields into an inode body.
    fn le32_body(fields: &[u32]) -> Vec<u8> {
        fields.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// spec #16: extended directory inode (§5.2) —
    /// `link_count u32, file_size u32, block_index u32, parent u32,
    /// index_count u16, block_offset u16, xattr u32`.
    #[test]
    fn parses_extended_dir_inode() {
        // Direct parse_inode check with distinct values in every field.
        let mut b = Builder::new(false);
        let mut body = Vec::new();
        body.extend_from_slice(&3u32.to_le_bytes()); // link_count
        body.extend_from_slice(&(0x1234u32 + 3).to_le_bytes()); // file_size
        body.extend_from_slice(&0x0000_abcdu32.to_le_bytes()); // block_index
        body.extend_from_slice(&7u32.to_le_bytes()); // parent
        body.extend_from_slice(&0u16.to_le_bytes()); // index_count
        body.extend_from_slice(&0x0765u16.to_le_bytes()); // block_offset
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
        let pos = b.emit_inode(TYPE_EXT_DIR, 0o750, &body);
        let (header, parsed) = parse_inode(&b.inode_stream, pos, b.block_size).unwrap();
        assert_eq!(header.inode_type, TYPE_EXT_DIR);
        assert_eq!(header.mode, 0o750);
        assert_eq!(
            kind_of(basic_type(header.inode_type).unwrap()),
            SquashfsKind::Directory
        );
        match parsed {
            InodeBody::Dir(listing) => {
                assert_eq!(listing.size, 0x1234);
                assert_eq!(listing.block_index, 0xabcd);
                assert_eq!(listing.block_offset, 0x0765);
            }
            _ => panic!("expected directory body"),
        }

        // Full image where root and subdirectory are extended dir inodes;
        // the subdirectory listing sits at a non-zero block_offset.
        let mut b = Builder::new(false);
        b.ext_dirs = true;
        let img = b.build(vec![
            Node::Dir(
                "sub",
                vec![
                    Node::File("a.txt", b"alpha", false),
                    Node::Dir("empty", vec![]),
                ],
            ),
            Node::File("b.txt", b"bravo", false),
        ]);
        let image = decode(&img).unwrap();
        let names: Vec<_> = image.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".", "sub", "sub/a.txt", "sub/empty", "b.txt"]);
        assert_eq!(image.entries[0].kind, SquashfsKind::Directory);
        assert_eq!(image.entries[1].kind, SquashfsKind::Directory);
        assert_eq!(image.entries[3].kind, SquashfsKind::Directory);
        assert_eq!(image.entries[2].data, b"alpha");
        assert_eq!(image.entries[4].data, b"bravo");
    }

    /// spec #17: extended file inode (§5.3, kernel `squashfs_lreg_inode`) —
    /// `blocks_start u64, file_size u64, sparse u64, link_count u32,
    /// frag_index u32, block_offset u32, xattr u32, block_sizes[]`.
    #[test]
    fn parses_extended_file_inode() {
        let big: Vec<u8> = (0..(4096 + 1000u32)).map(|i| (i % 253) as u8).collect();
        let big: &'static [u8] = Box::leak(big.into_boxed_slice());
        // A basic fragment file first so the extended file's fragment tail
        // lands at a non-zero offset inside the shared fragment block.
        let img = Builder::new(false).build(vec![
            Node::File("first.bin", b"first-tail", true),
            Node::ExtFile("ext-frag.bin", big, true),
            Node::ExtFile("ext-blocks.bin", big, false),
        ]);
        let image = decode(&img).unwrap();
        let names: Vec<_> = image.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".", "first.bin", "ext-frag.bin", "ext-blocks.bin"]);
        assert_eq!(image.entries[1].data, b"first-tail");
        for entry in &image.entries[2..] {
            assert_eq!(entry.kind, SquashfsKind::File);
            assert_eq!(entry.mode, 0o644);
            assert_eq!(entry.data, big);
        }

        // Direct parse_inode check of the parsed fields.
        let mut b = Builder::new(false);
        let mut body = Vec::new();
        body.extend_from_slice(&0x1_0000_0060u64.to_le_bytes()); // blocks_start
        body.extend_from_slice(&(4096u64 * 2 + 5).to_le_bytes()); // file_size
        body.extend_from_slice(&0u64.to_le_bytes()); // sparse
        body.extend_from_slice(&1u32.to_le_bytes()); // link_count
        body.extend_from_slice(&3u32.to_le_bytes()); // frag_index
        body.extend_from_slice(&0x40u32.to_le_bytes()); // block_offset
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
        body.extend_from_slice(&le32_body(&[0x100, BLOCK_UNCOMPRESSED | 4096]));
        let pos = b.emit_inode(TYPE_EXT_FILE, 0o600, &body);
        let (header, parsed) = parse_inode(&b.inode_stream, pos, b.block_size).unwrap();
        assert_eq!(
            kind_of(basic_type(header.inode_type).unwrap()),
            SquashfsKind::File
        );
        match parsed {
            InodeBody::File {
                blocks_start,
                frag_index,
                frag_offset,
                file_size,
                block_sizes,
            } => {
                assert_eq!(blocks_start, 0x1_0000_0060);
                assert_eq!(file_size, 4096 * 2 + 5);
                assert_eq!(frag_index, 3);
                assert_eq!(frag_offset, 0x40);
                assert_eq!(block_sizes, [0x100, BLOCK_UNCOMPRESSED | 4096]);
            }
            _ => panic!("expected file body"),
        }
    }

    /// spec #18: extended symlink inode (§5.4) shares the basic layout
    /// (`link_count u32, target_size u32, target[]`) plus a trailing xattr.
    #[test]
    fn parses_extended_symlink_inode() {
        let target = b"../usr/bin/tool";
        let mut body = le32_body(&[1, target.len() as u32]);
        body.extend_from_slice(target);
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
        let img = Builder::new(false).build(vec![
            Node::Raw("ext-link", TYPE_EXT_SYMLINK, 0o777, body),
            Node::Symlink("basic-link", "../usr/bin/tool"),
        ]);
        let image = decode(&img).unwrap();
        let names: Vec<_> = image.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".", "ext-link", "basic-link"]);
        for entry in &image.entries[1..] {
            assert_eq!(entry.kind, SquashfsKind::Symlink);
            assert_eq!(entry.mode, 0o777);
            assert_eq!(entry.data, target);
        }
    }

    /// spec #19: device (§5.5: `link_count u32, rdev u32[, xattr u32]`) and
    /// IPC (§5.6: `link_count u32[, xattr u32]`) inodes, basic + extended,
    /// and their SquashfsKind mapping.
    #[test]
    fn parses_device_and_ipc_inodes() {
        let rdev_blk = (8u32 << 8) | 1; // sda1
        let rdev_chr = (1u32 << 8) | 3; // /dev/null
        let img = Builder::new(false).build(vec![
            Node::Raw("blk", TYPE_BASIC_BLKDEV, 0o660, le32_body(&[1, rdev_blk])),
            Node::Raw(
                "blk-ext",
                TYPE_EXT_BLKDEV,
                0o660,
                le32_body(&[1, rdev_blk + 1, NO_INDEX]),
            ),
            Node::Raw("chr", TYPE_BASIC_CHRDEV, 0o666, le32_body(&[1, rdev_chr])),
            Node::Raw(
                "chr-ext",
                TYPE_EXT_CHRDEV,
                0o666,
                le32_body(&[1, rdev_chr + 2, NO_INDEX]),
            ),
            Node::Raw("fifo", TYPE_BASIC_FIFO, 0o644, le32_body(&[1])),
            Node::Raw("fifo-ext", TYPE_EXT_FIFO, 0o644, le32_body(&[1, NO_INDEX])),
            Node::Raw("sock", TYPE_BASIC_SOCKET, 0o755, le32_body(&[1])),
            Node::Raw(
                "sock-ext",
                TYPE_EXT_SOCKET,
                0o755,
                le32_body(&[1, NO_INDEX]),
            ),
        ]);
        let image = decode(&img).unwrap();
        let got: Vec<_> = image.entries[1..]
            .iter()
            .map(|e| (e.name.as_str(), e.kind, e.mode, e.data.clone()))
            .collect();
        let dev = |v: u32| v.to_le_bytes().to_vec();
        assert_eq!(
            got,
            [
                ("blk", SquashfsKind::BlockDevice, 0o660, dev(rdev_blk)),
                (
                    "blk-ext",
                    SquashfsKind::BlockDevice,
                    0o660,
                    dev(rdev_blk + 1)
                ),
                ("chr", SquashfsKind::CharDevice, 0o666, dev(rdev_chr)),
                (
                    "chr-ext",
                    SquashfsKind::CharDevice,
                    0o666,
                    dev(rdev_chr + 2)
                ),
                ("fifo", SquashfsKind::Fifo, 0o644, vec![]),
                ("fifo-ext", SquashfsKind::Fifo, 0o644, vec![]),
                ("sock", SquashfsKind::Socket, 0o755, vec![]),
                ("sock-ext", SquashfsKind::Socket, 0o755, vec![]),
            ]
        );
    }
}
