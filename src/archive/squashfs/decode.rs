//! `.squashfs` image decoding.
//!
//! Parses the SquashFS 4.0 on-disk format: superblock, metadata block runs
//! (inode / directory tables), lookup tables (fragment / ID / xattr),
//! extended-directory index entries (section 6.1), and data/fragment blocks.
//! All six compressor IDs are recognized; LZMA 1 blocks (id 2, deprecated
//! upstream) carry `.lzma`-alone payloads.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::{lz4, lzma, lzo, xz, zlib, zstd};
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

const XATTR_OOL_FLAG: u16 = 0x0100;
const XATTR_PREFIX_MASK: u16 = 0x00ff;
/// Out-of-line xattr value references point at plain value structures, which
/// cannot themselves be references, so resolution is bounded to a single hop.
const MAX_XATTR_OOL_DEPTH: usize = 1;

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
    /// ID 2: LZMA 1 (deprecated upstream); blocks are `.lzma`-alone payloads.
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
    /// On-disk compressor identifier (superblock field).
    pub fn id(self) -> u16 {
        match self {
            Self::Gzip => 1,
            Self::Lzma => 2,
            Self::Lzo => 3,
            Self::Xz => 4,
            Self::Lz4 => 5,
            Self::Zstd => 6,
        }
    }

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
            Self::Lzma => lzma1_decode(data, max_output),
            Self::Lzo => lzo::decode::decompress_lzo1x(data, max_output),
            Self::Xz => xz::decode::decode_bounded(data, max_output),
            Self::Lz4 => lz4::decode::decode_block(data, max_output),
            Self::Zstd => zstd::decode::decode_bounded(data, max_output),
        }
    }
}

/// Decode one LZMA1 (compressor id 2) block. Upstream mksquashfs writes a
/// `.lzma`-alone payload per block: `[5B props][8B LE unpacked size][raw
/// LZMA1 stream]`. Both upstream variants are accepted: the SDK form ends
/// exactly at the declared size without an end-of-payload marker, while the
/// liblzma form appends one. The range decoder may leave up to 2 flush
/// bytes unread; anything more is rejected as trailing data.
fn lzma1_decode(data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    const HEADER: usize = 13;
    const SLACK: usize = 2;
    if data.len() < HEADER {
        return Err(Error::UnexpectedEof);
    }
    let props = lzma::LzmaProperties::from_props_byte(data[0])
        .map_err(|_| Error::InvalidData("squashfs: lzma invalid properties byte"))?;
    let dict_size = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    if dict_size == 0 {
        return Err(Error::InvalidData(
            "squashfs: lzma dictionary size must be non-zero",
        ));
    }
    let unpacked_size = u64::from_le_bytes(data[5..13].try_into().unwrap());
    let stream = &data[HEADER..];
    if stream.is_empty() {
        return Err(Error::UnexpectedEof);
    }
    let decoded = if unpacked_size == u64::MAX {
        let (decoded, consumed) = lzma::lzma_decode_with_props(stream, dict_size, props)?;
        if stream.len() - consumed > SLACK {
            return Err(Error::InvalidData("squashfs: lzma trailing data"));
        }
        decoded
    } else {
        let expected = usize::try_from(unpacked_size)
            .map_err(|_| Error::InvalidData("squashfs: lzma unpacked size overflows"))?;
        let (decoded, consumed) =
            lzma::lzma_decode_with_props_and_size(stream, dict_size, props, expected)?;
        if stream.len() - consumed <= SLACK {
            decoded
        } else {
            // Declared size plus an end-of-payload marker (liblzma variant).
            let (decoded, consumed) = lzma::lzma_decode_with_props(stream, dict_size, props)
                .map_err(|_| Error::InvalidData("squashfs: lzma trailing data"))?;
            if decoded.len() != expected || stream.len() - consumed > SLACK {
                return Err(Error::InvalidData("squashfs: lzma trailing data"));
            }
            decoded
        }
    };
    if decoded.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(decoded)
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

/// A resolved extended attribute (§10). `name` carries its namespace prefix
/// (`user.` / `trusted.` / `security.`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashfsXattr {
    /// Full attribute name including the namespace prefix.
    pub name: String,
    /// Attribute value bytes.
    pub value: Vec<u8>,
}

/// A directory index entry (§6.1) attached to an extended directory inode;
/// it names the first entry after a directory header and locates the
/// metadata block holding that header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SquashfsDirIndex {
    /// Byte offset of the indexed header relative to the first header of
    /// this listing in the uncompressed directory stream.
    pub index: u32,
    /// Start of the directory-table metadata block holding the indexed
    /// header, relative to the directory table start.
    pub start: u32,
    /// Name of the first entry following the indexed header.
    pub name: String,
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
    /// Extended attributes resolved through the xattr table (§10); empty
    /// when the inode has none or the image carries no xattr table.
    pub xattrs: Vec<SquashfsXattr>,
    /// Directory index entries (§6.1) parsed from an extended directory
    /// inode; empty for basic directories and non-directories.
    pub dir_index: Vec<SquashfsDirIndex>,
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
    let end = pos.checked_add(2).ok_or(Error::UnexpectedEof)?;
    let bytes = input.get(pos..end).ok_or(Error::UnexpectedEof)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le32(input: &[u8], pos: usize) -> Result<u32, Error> {
    let end = pos.checked_add(4).ok_or(Error::UnexpectedEof)?;
    let bytes = input.get(pos..end).ok_or(Error::UnexpectedEof)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le64(input: &[u8], pos: usize) -> Result<u64, Error> {
    let end = pos.checked_add(8).ok_or(Error::UnexpectedEof)?;
    let bytes = input.get(pos..end).ok_or(Error::UnexpectedEof)?;
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

/// Decoded xattr id table (section 10): the 16-byte lookup entries plus the
/// metadata run holding the key/value pairs they reference.
struct XattrTable {
    /// Decompressed, concatenated lookup-table blocks (16 bytes per entry:
    /// xattr_ref u64, count u32, size u32).
    lookup: Vec<u8>,
    /// Number of lookup entries.
    count: usize,
    /// Key/value metadata run; references are relative to kv_start, the
    /// run's first block.
    kv_run: MetaRun,
}

impl XattrTable {
    /// Resolve the key/value pairs addressed by lookup entry index.
    fn pairs(&self, index: u32) -> Result<Vec<SquashfsXattr>, Error> {
        if index as usize >= self.count {
            return Err(Error::InvalidData("squashfs: xattr index out of range"));
        }
        let base = index as usize * 16;
        let kv_ref = le64(&self.lookup, base)?;
        let count = le32(&self.lookup, base + 8)? as usize;
        // The size field is not a serialized byte count: upstream
        // mksquashfs writes the sum of strlen(full_name)+1+vsize for stat
        // purposes, and the kernel ignores it during parsing. Pairs are
        // therefore walked by `count` within the key/value run.
        let _size = le32(&self.lookup, base + 12)?;
        let start = self.kv_run.resolve(kv_ref)?;
        let block = self
            .kv_run
            .data
            .get(start..)
            .ok_or(Error::InvalidData("squashfs: xattr data out of range"))?;
        let mut pos = 0;
        let mut out = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let raw_type = le16(block, pos)?;
            let name_size = usize::from(le16(block, pos + 2)?);
            pos += 4;
            let prefix = match raw_type & XATTR_PREFIX_MASK {
                0 => "user.",
                1 => "trusted.",
                2 => "security.",
                _ => {
                    return Err(Error::InvalidData("squashfs: unknown xattr prefix"));
                }
            };
            let name_bytes = block
                .get(pos..pos + name_size)
                .ok_or(Error::UnexpectedEof)?;
            let name = alloc::format!("{prefix}{}", String::from_utf8_lossy(name_bytes));
            pos += name_size;
            let value_size = le32(block, pos)? as usize;
            pos += 4;
            let value = if raw_type & XATTR_OOL_FLAG != 0 {
                if value_size != 8 {
                    return Err(Error::InvalidData("squashfs: bad out-of-line xattr value"));
                }
                let value_ref = le64(block, pos)?;
                pos += 8;
                self.ool_value(value_ref, 0)?
            } else {
                let value = block
                    .get(pos..pos + value_size)
                    .ok_or(Error::UnexpectedEof)?
                    .to_vec();
                pos += value_size;
                value
            };
            out.push(SquashfsXattr { name, value });
        }
        Ok(out)
    }

    /// Resolve an out-of-line value reference (u32 size + bytes) inside the
    /// key/value run. The depth parameter enforces MAX_XATTR_OOL_DEPTH: a
    /// value structure cannot itself be a reference, so a single hop
    /// suffices and anything deeper indicates a malformed table.
    fn ool_value(&self, value_ref: u64, depth: usize) -> Result<Vec<u8>, Error> {
        if depth >= MAX_XATTR_OOL_DEPTH {
            return Err(Error::InvalidData("squashfs: xattr value ref too deep"));
        }
        let pos = self.kv_run.resolve(value_ref)?;
        let size = le32(&self.kv_run.data, pos)? as usize;
        let start = pos + 4;
        let end = start
            .checked_add(size)
            .filter(|&e| e <= self.kv_run.data.len())
            .ok_or(Error::InvalidData("squashfs: xattr value out of range"))?;
        Ok(self.kv_run.data[start..end].to_vec())
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

    /// Parse the xattr id-table header at table_start (section 10):
    /// kv_start u64, count u32, unused u32, then the absolute locations of
    /// the lookup-table metadata blocks (512 16-byte entries each). The
    /// key/value metadata blocks occupy [kv_start, table_start) and are
    /// decompressed as one run so references -- metadata block offsets
    /// relative to kv_start -- resolve through MetaRun::resolve.
    fn read_xattr_table(&self, table_start: usize) -> Result<XattrTable, Error> {
        let kv_start = le64(self.input, table_start)? as usize;
        let count = le32(self.input, table_start + 8)? as usize;
        let lookup = self.read_lookup_table(table_start + 16, 16, count)?;
        if kv_start >= table_start {
            return Err(Error::InvalidData("squashfs: bad xattr table"));
        }
        let kv_run = self.read_meta_run(kv_start, table_start)?;
        Ok(XattrTable {
            lookup,
            count,
            kv_run,
        })
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
#[derive(Clone, Debug)]
struct DirListing {
    block_index: u32,
    block_offset: u16,
    size: u32,
    /// §6.1 index entries following an extended directory inode (empty for
    /// basic directories).
    index: Vec<SquashfsDirIndex>,
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
/// header inside the decompressed inode table. Returns the body and the
/// inode's xattr index (`NO_INDEX` when the inode type carries none).
fn parse_inode_body(
    data: &[u8],
    pos: usize,
    header: &InodeHeader,
) -> Result<(InodeBody, u32), Error> {
    match header.inode_type {
        TYPE_BASIC_DIR => Ok((
            InodeBody::Dir(DirListing {
                block_index: le32(data, pos)?,
                // link_count at pos+4, file_size (listing+3) at pos+8
                block_offset: le16(data, pos + 10)?,
                size: u32::from(le16(data, pos + 8)?).saturating_sub(3),
                index: Vec::new(),
            }),
            NO_INDEX,
        )),
        TYPE_EXT_DIR => {
            // link_count u32, file_size u32, block_index u32, parent u32,
            // index_count u16, block_offset u16, xattr u32; `index_count`
            // §6.1 index entries follow the inode.
            let index_count = usize::from(le16(data, pos + 16)?);
            let mut index = Vec::with_capacity(index_count);
            let mut ipos = pos + 24;
            for _ in 0..index_count {
                let name_size = (le32(data, ipos + 8)? as usize)
                    .checked_add(1)
                    .ok_or(Error::UnexpectedEof)?;
                let name_start = ipos.checked_add(12).ok_or(Error::UnexpectedEof)?;
                let name_end = name_start
                    .checked_add(name_size)
                    .ok_or(Error::UnexpectedEof)?;
                let name = data.get(name_start..name_end).ok_or(Error::UnexpectedEof)?;
                index.push(SquashfsDirIndex {
                    index: le32(data, ipos)?,
                    start: le32(data, ipos + 4)?,
                    name: String::from_utf8_lossy(name).into_owned(),
                });
                ipos = name_end;
            }
            Ok((
                InodeBody::Dir(DirListing {
                    size: le32(data, pos + 4)?.saturating_sub(3),
                    block_index: le32(data, pos + 8)?,
                    block_offset: le16(data, pos + 18)?,
                    index,
                }),
                le32(data, pos + 20)?,
            ))
        }
        TYPE_BASIC_SYMLINK | TYPE_EXT_SYMLINK => {
            let target_size = le32(data, pos + 4)? as usize;
            let target = data
                .get(pos + 8..pos + 8 + target_size)
                .ok_or(Error::UnexpectedEof)?
                .to_vec();
            // Extended symlinks append an xattr index after the target.
            let xattr = if header.inode_type == TYPE_EXT_SYMLINK {
                le32(data, pos + 8 + target_size)?
            } else {
                NO_INDEX
            };
            Ok((InodeBody::Symlink(target), xattr))
        }
        // link_count u32, rdev u32[, xattr u32 on extended inodes]
        TYPE_BASIC_BLKDEV | TYPE_BASIC_CHRDEV => {
            Ok((InodeBody::Device(le32(data, pos + 4)?), NO_INDEX))
        }
        TYPE_EXT_BLKDEV | TYPE_EXT_CHRDEV => Ok((
            InodeBody::Device(le32(data, pos + 4)?),
            le32(data, pos + 8)?,
        )),
        // link_count u32[, xattr u32 on extended inodes]
        TYPE_BASIC_FIFO | TYPE_BASIC_SOCKET => Ok((InodeBody::Ipc, NO_INDEX)),
        TYPE_EXT_FIFO | TYPE_EXT_SOCKET => Ok((InodeBody::Ipc, le32(data, pos + 4)?)),
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

/// Parse one inode; returns the common header, the body, and the inode's
/// xattr index (`NO_INDEX` for inode types without an xattr field).
fn parse_inode(
    data: &[u8],
    pos: usize,
    block_size: u32,
) -> Result<(InodeHeader, InodeBody, u32), Error> {
    let header = InodeHeader::parse(data, pos)?;
    let (body, xattr) = match header.inode_type {
        TYPE_BASIC_FILE => {
            let frag_index = le32(data, pos + 16 + 4)?;
            let file_size = u64::from(le32(data, pos + 16 + 12)?);
            (
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
                },
                NO_INDEX,
            )
        }
        TYPE_EXT_FILE => {
            let frag_index = le32(data, pos + 16 + 28)?;
            let file_size = le64(data, pos + 16 + 8)?;
            (
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
                },
                le32(data, pos + 16 + 36)?,
            )
        }
        _ => parse_inode_body(data, pos + 16, &header)?,
    };
    Ok((header, body, xattr))
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
    let xattr_table = if xattr_table_start == TABLE_ABSENT {
        None
    } else {
        Some(reader.read_xattr_table(xattr_table_start as usize)?)
    };

    let mut entries = Vec::new();
    let mut visited = 0u32;
    let mut frag_cache = BTreeMap::new();
    walk_dir(
        &reader,
        &inode_run,
        &dir_run,
        &frag_table,
        &id_table,
        xattr_table.as_ref(),
        root_inode_ref,
        String::new(),
        &mut entries,
        &mut visited,
        inode_count,
        &mut frag_cache,
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

/// Resolve an inode's xattr index through the (optional) xattr table.
fn read_xattrs(table: Option<&XattrTable>, index: u32) -> Result<Vec<SquashfsXattr>, Error> {
    match (table, index) {
        (_, NO_INDEX) => Ok(Vec::new()),
        (Some(table), index) => table.pairs(index),
        (None, _) => Err(Error::InvalidData(
            "squashfs: inode xattr index without xattr table",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_dir(
    reader: &Reader<'_>,
    inode_run: &MetaRun,
    dir_run: &MetaRun,
    frag_table: &[u8],
    id_table: &[u8],
    xattr_table: Option<&XattrTable>,
    inode_ref: u64,
    path: String,
    entries: &mut Vec<SquashfsEntry>,
    visited: &mut u32,
    inode_count: u32,
    frag_cache: &mut BTreeMap<(usize, u32), Vec<u8>>,
) -> Result<(), Error> {
    *visited += 1;
    if *visited > inode_count {
        return Err(Error::InvalidData("squashfs: inode count exceeded"));
    }
    let pos = inode_run.resolve(inode_ref)?;
    let (header, body, xattr_idx) = parse_inode(&inode_run.data, pos, reader.block_size as u32)?;
    let uid = lookup_id(id_table, header.uid_idx).unwrap_or(0);
    let gid = lookup_id(id_table, header.gid_idx).unwrap_or(0);
    let basic = basic_type(header.inode_type)?;
    let name = if path.is_empty() {
        String::from(".")
    } else {
        path.clone()
    };

    let (data, listing): (Vec<u8>, Option<DirListing>) = match &body {
        InodeBody::Dir(listing) => (Vec::new(), Some(listing.clone())),
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
                frag_cache,
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
        xattrs: read_xattrs(xattr_table, xattr_idx)?,
        dir_index: listing
            .as_ref()
            .map(|l| l.index.clone())
            .unwrap_or_default(),
    });

    if let Some(listing) = listing {
        let children = read_dir_listing(dir_run, &listing)?;
        for (child_ref, child_type, child_name) in children {
            let child_path = if path.is_empty() {
                child_name.clone()
            } else {
                alloc::format!("{path}/{child_name}")
            };
            let child_pos = inode_run.resolve(child_ref)?;
            let (child_header, child_body, child_xattr) =
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
                    xattr_table,
                    child_ref,
                    child_path,
                    entries,
                    visited,
                    inode_count,
                    frag_cache,
                )?;
            } else {
                *visited += 1;
                if *visited > inode_count {
                    return Err(Error::InvalidData("squashfs: inode count exceeded"));
                }
                let data = match &child_body {
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
                        frag_cache,
                    )?,
                    InodeBody::Symlink(target) => target.clone(),
                    InodeBody::Device(dev) => dev.to_le_bytes().to_vec(),
                    _ => Vec::new(),
                };
                entries.push(SquashfsEntry {
                    name: child_path,
                    kind: kind_of(basic_type(child_header.inode_type)?),
                    mode: child_header.mode,
                    uid: lookup_id(id_table, child_header.uid_idx).unwrap_or(0),
                    gid: lookup_id(id_table, child_header.gid_idx).unwrap_or(0),
                    mtime: child_header.mtime,
                    inode: child_header.inode,
                    data,
                    xattrs: read_xattrs(xattr_table, child_xattr)?,
                    dir_index: Vec::new(),
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
    listing: &DirListing,
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
        let count =
            (le32(&dir_run.data, pos)? as usize)
                .checked_add(1)
                .ok_or(Error::InvalidData(
                    "squashfs: directory entry count overflow",
                ))?;
        let block_start = le32(&dir_run.data, pos + 4)?;
        let base_inode = le32(&dir_run.data, pos + 8)? as i64;
        pos += 12;
        for _ in 0..count {
            let offset = le16(&dir_run.data, pos)?;
            let inode_diff = le16(&dir_run.data, pos + 2)? as i16 as i64;
            let entry_type = le16(&dir_run.data, pos + 4)?;
            let name_len = usize::from(le16(&dir_run.data, pos + 6)?) + 1;
            pos += 8;
            let name_end = pos
                .checked_add(name_len)
                .filter(|&e| e <= dir_run.data.len())
                .ok_or(Error::UnexpectedEof)?;
            let name = String::from_utf8_lossy(&dir_run.data[pos..name_end]).into_owned();
            pos = name_end;
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
    frag_cache: &mut BTreeMap<(usize, u32), Vec<u8>>,
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
        let base = (frag_index as usize)
            .checked_mul(16)
            .ok_or(Error::InvalidData("squashfs: fragment index out of range"))?;
        let frag_start = le64(frag_table, base)? as usize;
        let frag_size_pos = base
            .checked_add(8)
            .ok_or(Error::InvalidData("squashfs: fragment index out of range"))?;
        let frag_size = le32(frag_table, frag_size_pos)?;
        let key = (frag_start, frag_size);
        if let Entry::Vacant(slot) = frag_cache.entry(key) {
            let decoded = reader.read_data_block(frag_start, frag_size, reader.block_size)?;
            slot.insert(decoded);
        }
        let frag = &frag_cache[&key];
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
    use crate::compress::{lzma, zlib};
    use alloc::vec;

    const COMPRESS_ID: u16 = 1; // zlib ("gzip" upstream)
    const COMPRESS_ID_LZMA: u16 = 2;

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
        /// When set, blocks are emitted as compressor-id-2 LZMA1 `.lzma`
        /// payloads instead of zlib: `true` appends the end-of-payload
        /// marker (liblzma variant), `false` ends at the declared size
        /// (SDK variant).
        lzma_eos: Option<bool>,
        block_size: u32,
        next_inode: u32,
        /// Emit directories as extended directory inodes (TYPE_EXT_DIR).
        ext_dirs: bool,
        /// Uncompressed xattr key/value pair stream (section 10); emitted
        /// as metadata blocks when xattr_lookup is non-empty.
        xattr_stream: Vec<u8>,
        /// 16-byte xattr lookup entries (xattr_ref, count, size).
        xattr_lookup: Vec<u8>,
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
                lzma_eos: None,
                block_size: 4096,
                next_inode: 1,
                ext_dirs: false,
                xattr_stream: Vec::new(),
                xattr_lookup: Vec::new(),
            }
        }

        fn pack_flag(&self, raw: &[u8]) -> (Vec<u8>, bool) {
            if self.lzma_eos.is_some() {
                (self.lzma1_pack(raw), false)
            } else if self.compress {
                (zlib::encode::encode(raw), false)
            } else {
                (raw.to_vec(), true)
            }
        }

        /// `.lzma`-alone payload: props byte 0x5D (lc3/lp0/pb2), dictionary
        /// size = image block_size, 8-byte little-endian uncompressed size,
        /// raw LZMA1 stream.
        fn lzma1_pack(&self, raw: &[u8]) -> Vec<u8> {
            let props = lzma::LzmaProperties::LZIP;
            let stream = if self.lzma_eos == Some(true) {
                lzma::lzma_encode_with_props(raw, self.block_size, props)
            } else {
                lzma::lzma_encode_with_props_no_eos(raw, self.block_size, props)
            };
            let mut out = Vec::with_capacity(13 + stream.len());
            out.push(props.to_props_byte());
            out.extend_from_slice(&self.block_size.to_le_bytes());
            out.extend_from_slice(&(raw.len() as u64).to_le_bytes());
            out.extend_from_slice(&stream);
            out
        }

        /// Append `raw` to `stream` as metadata blocks (8 KiB chunks), each
        /// preceded by the 16-bit size header.
        fn emit_meta_run(&self, out: &mut Vec<u8>, stream: &[u8]) {
            for chunk in stream.chunks(META_BLOCK_SIZE) {
                if self.compress || self.lzma_eos.is_some() {
                    let packed = self.pack_flag(chunk).0;
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
            // xattr section (section 10): key/value metadata blocks, then
            // the lookup-table metadata blocks, then the uncompressed
            // id-table header (kv_start, count, unused, locations[]).
            let xattr_table_start = if self.xattr_lookup.is_empty() {
                TABLE_ABSENT
            } else {
                let kv_start = img.len() as u64;
                self.emit_meta_run(&mut img, &self.xattr_stream.clone());
                let mut locations = Vec::new();
                for chunk in self.xattr_lookup.chunks(META_BLOCK_SIZE) {
                    locations.push(img.len() as u64);
                    self.emit_meta_run(&mut img, chunk);
                }
                let table_start = img.len() as u64;
                img.extend_from_slice(&kv_start.to_le_bytes());
                img.extend_from_slice(&((self.xattr_lookup.len() / 16) as u32).to_le_bytes());
                img.extend_from_slice(&0u32.to_le_bytes()); // unused
                for location in locations {
                    img.extend_from_slice(&location.to_le_bytes());
                }
                table_start
            };
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
            let compress_id = if self.lzma_eos.is_some() {
                COMPRESS_ID_LZMA
            } else {
                COMPRESS_ID
            };
            img[20..22].copy_from_slice(&compress_id.to_le_bytes());
            img[22..24].copy_from_slice(&12u16.to_le_bytes()); // block_log
            img[24..26].copy_from_slice(&0u16.to_le_bytes()); // flags
            img[26..28].copy_from_slice(&1u16.to_le_bytes()); // id_count
            img[28..30].copy_from_slice(&4u16.to_le_bytes()); // major
            img[30..32].copy_from_slice(&0u16.to_le_bytes()); // minor
            img[32..40].copy_from_slice(&root_ref.to_le_bytes());
            img[40..48].copy_from_slice(&bytes_used.to_le_bytes());
            img[48..56].copy_from_slice(&(id_table_start as u64).to_le_bytes());
            img[56..64].copy_from_slice(&xattr_table_start.to_le_bytes());
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

    /// spec #38: compressor id 2 (LZMA1 `.lzma`-alone payloads) end-to-end,
    /// liblzma variant with an end-of-payload marker after the declared size.
    #[test]
    fn lzma1_image_roundtrip() {
        let content: Vec<u8> = (0..9000u32).map(|i| (i % 97) as u8).collect();
        let content: &'static [u8] = Box::leak(content.into_boxed_slice());
        let mut b = Builder::new(false);
        b.lzma_eos = Some(true);
        let img = b.build(vec![
            Node::File("lzma.bin", content, false),
            Node::File("tail.bin", b"tail-lzma", true),
            Node::Symlink("ln", "lzma.bin"),
        ]);
        let image = decode(&img).unwrap();
        assert_eq!(image.superblock.compression, SquashfsCompression::Lzma);
        let names: Vec<_> = image.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, [".", "lzma.bin", "tail.bin", "ln"]);
        assert_eq!(image.entries[1].data, content);
        assert_eq!(image.entries[2].data, b"tail-lzma");
        assert_eq!(image.entries[3].data, b"lzma.bin");
    }

    /// spec #38: SDK variant — declared unpacked size, no end-of-payload
    /// marker in the stream.
    #[test]
    fn lzma1_known_size_no_eos() {
        let content: Vec<u8> = (0..5000u32).map(|i| (i % 61) as u8).collect();
        let content: &'static [u8] = Box::leak(content.into_boxed_slice());
        let mut b = Builder::new(false);
        b.lzma_eos = Some(false);
        let img = b.build(vec![Node::File("sdk.bin", content, false)]);
        let image = decode(&img).unwrap();
        assert_eq!(image.entries[1].data, content);
    }

    /// spec #38: the per-block output bound rejects an LZMA1 payload that
    /// expands past the expected size, at the dispatch level and inside
    /// image decode.
    #[test]
    fn lzma1_blocks_bounded() {
        let raw: Vec<u8> = (0..300u32).map(|i| (i % 41) as u8).collect();
        let payload = Builder::new(false).lzma1_pack(&raw);
        assert!(matches!(
            SquashfsCompression::Lzma.decompress(&payload, raw.len() - 1),
            Err(Error::OutputLimitExceeded { .. })
        ));
        assert_eq!(
            SquashfsCompression::Lzma
                .decompress(&payload, raw.len())
                .unwrap(),
            raw
        );

        // Image level: a file inode declaring a file_size smaller than the
        // block's decoded length fails through the same bound.
        let mut b = Builder::new(false);
        b.lzma_eos = Some(true);
        let mut body = Vec::new();
        body.extend_from_slice(&(SUPERBLOCK_SIZE as u32).to_le_bytes()); // blocks_start
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // frag_index
        body.extend_from_slice(&0u32.to_le_bytes()); // frag_offset
        body.extend_from_slice(&50u32.to_le_bytes()); // file_size < 300
        body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // block_sizes[0]
        b.data_region.extend_from_slice(&payload);
        let img = b.build(vec![Node::Raw("over.bin", TYPE_BASIC_FILE, 0o644, body)]);
        assert!(decode(&img).is_err());
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
        let (header, parsed, xattr_idx) = parse_inode(&b.inode_stream, pos, b.block_size).unwrap();
        assert_eq!(header.inode_type, TYPE_EXT_DIR);
        assert_eq!(header.mode, 0o750);
        assert_eq!(xattr_idx, NO_INDEX);
        assert_eq!(
            kind_of(basic_type(header.inode_type).unwrap()),
            SquashfsKind::Directory
        );
        match parsed {
            InodeBody::Dir(listing) => {
                assert_eq!(listing.size, 0x1234);
                assert_eq!(listing.block_index, 0xabcd);
                assert_eq!(listing.block_offset, 0x0765);
                assert!(listing.index.is_empty());
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
        let (header, parsed, xattr_idx) = parse_inode(&b.inode_stream, pos, b.block_size).unwrap();
        assert_eq!(xattr_idx, NO_INDEX);
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

    /// Extended file inode body (section 5.3) for an empty file carrying the
    /// given xattr index.
    fn ext_file_body(xattr: u32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0u64.to_le_bytes()); // blocks_start
        body.extend_from_slice(&0u64.to_le_bytes()); // file_size
        body.extend_from_slice(&0u64.to_le_bytes()); // sparse
        body.extend_from_slice(&1u32.to_le_bytes()); // link_count
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // frag_index
        body.extend_from_slice(&0u32.to_le_bytes()); // block_offset
        body.extend_from_slice(&xattr.to_le_bytes());
        body
    }

    /// spec #39: xattr table decode (section 10) -- id-table header
    /// (kv_start, count, locations[]), 16-byte lookup entries, and key/value
    /// pairs with inline and out-of-line values resolved through inode
    /// indexes.
    #[test]
    fn parses_xattr_table() {
        // Key/value stream: a pair block at offset 0 and an out-of-line
        // value structure at offset 48.
        let mut kv = Vec::new();
        // pair 1: inline "user.comment" = "hello"
        kv.extend_from_slice(&0u16.to_le_bytes()); // type: "user." prefix
        kv.extend_from_slice(&7u16.to_le_bytes()); // name size
        kv.extend_from_slice(b"comment");
        kv.extend_from_slice(&5u32.to_le_bytes()); // value size
        kv.extend_from_slice(b"hello");
        // pair 2: out-of-line "security.selinux" -> value ref at offset 48
        kv.extend_from_slice(&(2u16 | XATTR_OOL_FLAG).to_le_bytes());
        kv.extend_from_slice(&7u16.to_le_bytes());
        kv.extend_from_slice(b"selinux");
        kv.extend_from_slice(&8u32.to_le_bytes()); // out-of-line => size 8
        kv.extend_from_slice(&48u64.to_le_bytes()); // kv block 0, offset 48
        let pair_size = kv.len();
        kv.resize(48, 0);
        kv.extend_from_slice(&11u32.to_le_bytes());
        kv.extend_from_slice(b"targetvalue");

        // Lookup entry 0: kv ref to block 0 offset 0, 2 pairs, pair_size.
        let mut lookup = Vec::new();
        lookup.extend_from_slice(&0u64.to_le_bytes());
        lookup.extend_from_slice(&2u32.to_le_bytes());
        lookup.extend_from_slice(&(pair_size as u32).to_le_bytes());

        let mut b = Builder::new(false);
        b.xattr_stream = kv;
        b.xattr_lookup = lookup;
        let img = b.build(vec![
            Node::Raw("tagged", TYPE_EXT_FILE, 0o644, ext_file_body(0)),
            Node::File("plain", b"no attrs", false),
        ]);
        let image = decode(&img).unwrap();
        let tagged = image.entries.iter().find(|e| e.name == "tagged").unwrap();
        assert_eq!(
            tagged.xattrs,
            [
                SquashfsXattr {
                    name: "user.comment".into(),
                    value: b"hello".to_vec(),
                },
                SquashfsXattr {
                    name: "security.selinux".into(),
                    value: b"targetvalue".to_vec(),
                },
            ]
        );
        let plain = image.entries.iter().find(|e| e.name == "plain").unwrap();
        assert!(plain.xattrs.is_empty());
        assert!(plain.dir_index.is_empty());
    }

    /// spec #39: a second lookup entry indexes a distinct pair block, and a
    /// "trusted." prefix is mapped.
    #[test]
    fn parses_xattr_second_lookup_entry() {
        let mut kv = Vec::new();
        // entry 0's pair: "user.a" = "x" (10 bytes)
        kv.extend_from_slice(&0u16.to_le_bytes());
        kv.extend_from_slice(&1u16.to_le_bytes());
        kv.extend_from_slice(b"a");
        kv.extend_from_slice(&1u32.to_le_bytes());
        kv.extend_from_slice(b"x");
        // entry 1's pair block at offset 10: "trusted.key" = "val" (14 bytes)
        kv.extend_from_slice(&1u16.to_le_bytes());
        kv.extend_from_slice(&3u16.to_le_bytes());
        kv.extend_from_slice(b"key");
        kv.extend_from_slice(&3u32.to_le_bytes());
        kv.extend_from_slice(b"val");

        let mut lookup = Vec::new();
        for (kv_ref, size) in [(0u64, 10u32), (10u64, 14u32)] {
            lookup.extend_from_slice(&kv_ref.to_le_bytes());
            lookup.extend_from_slice(&1u32.to_le_bytes());
            lookup.extend_from_slice(&size.to_le_bytes());
        }

        let mut b = Builder::new(false);
        b.xattr_stream = kv;
        b.xattr_lookup = lookup;
        let img = b.build(vec![Node::Raw(
            "tagged",
            TYPE_EXT_FILE,
            0o644,
            ext_file_body(1),
        )]);
        let image = decode(&img).unwrap();
        let tagged = image.entries.iter().find(|e| e.name == "tagged").unwrap();
        assert_eq!(
            tagged.xattrs,
            [SquashfsXattr {
                name: "trusted.key".into(),
                value: b"val".to_vec(),
            }]
        );
    }

    /// spec #39: malformed xattr references are rejected.
    #[test]
    fn rejects_bad_xattrs() {
        // Inode xattr index without an xattr table (superblock TABLE_ABSENT).
        let img = Builder::new(false).build(vec![Node::Raw(
            "tagged",
            TYPE_EXT_FILE,
            0o644,
            ext_file_body(0),
        )]);
        assert!(decode(&img).is_err());

        // Inode xattr index beyond the lookup entry count.
        let mut lookup = Vec::new();
        lookup.extend_from_slice(&0u64.to_le_bytes());
        lookup.extend_from_slice(&0u32.to_le_bytes());
        lookup.extend_from_slice(&0u32.to_le_bytes());
        let mut b = Builder::new(false);
        b.xattr_stream = vec![0; 4];
        b.xattr_lookup = lookup;
        let img = b.build(vec![Node::Raw(
            "tagged",
            TYPE_EXT_FILE,
            0o644,
            ext_file_body(5),
        )]);
        assert!(decode(&img).is_err());

        // Out-of-line value reference pointing outside the kv run.
        let mut kv = Vec::new();
        kv.extend_from_slice(&XATTR_OOL_FLAG.to_le_bytes());
        kv.extend_from_slice(&1u16.to_le_bytes());
        kv.extend_from_slice(b"a");
        kv.extend_from_slice(&8u32.to_le_bytes());
        kv.extend_from_slice(&(0xffffu64 << 16).to_le_bytes()); // bogus block
        let pair_size = kv.len();
        let mut lookup = Vec::new();
        lookup.extend_from_slice(&0u64.to_le_bytes());
        lookup.extend_from_slice(&1u32.to_le_bytes());
        lookup.extend_from_slice(&(pair_size as u32).to_le_bytes());
        let mut b = Builder::new(false);
        b.xattr_stream = kv;
        b.xattr_lookup = lookup;
        let img = b.build(vec![Node::Raw(
            "tagged",
            TYPE_EXT_FILE,
            0o644,
            ext_file_body(0),
        )]);
        assert!(decode(&img).is_err());
    }

    /// spec #41: directory index read (section 6.1) -- index_count entries
    /// following an extended directory inode are parsed and exposed.
    #[test]
    fn parses_dir_index() {
        let mut body = Vec::new();
        body.extend_from_slice(&2u32.to_le_bytes()); // link_count
        body.extend_from_slice(&3u32.to_le_bytes()); // file_size < 4 => empty
        body.extend_from_slice(&0u32.to_le_bytes()); // block_index
        body.extend_from_slice(&1u32.to_le_bytes()); // parent
        body.extend_from_slice(&2u16.to_le_bytes()); // index_count
        body.extend_from_slice(&0u16.to_le_bytes()); // block_offset
        body.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
        // index entry 0
        body.extend_from_slice(&0u32.to_le_bytes()); // index offset
        body.extend_from_slice(&0u32.to_le_bytes()); // start
        body.extend_from_slice(&2u32.to_le_bytes()); // name_size = 3 - 1
        body.extend_from_slice(b"aaa");
        // index entry 1
        body.extend_from_slice(&40u32.to_le_bytes());
        body.extend_from_slice(&8192u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(b"bbbb");
        let img = Builder::new(false).build(vec![Node::Raw("big", TYPE_EXT_DIR, 0o755, body)]);
        let image = decode(&img).unwrap();
        let dir = image.entries.iter().find(|e| e.name == "big").unwrap();
        assert_eq!(dir.kind, SquashfsKind::Directory);
        assert_eq!(
            dir.dir_index,
            [
                SquashfsDirIndex {
                    index: 0,
                    start: 0,
                    name: "aaa".into(),
                },
                SquashfsDirIndex {
                    index: 40,
                    start: 8192,
                    name: "bbbb".into(),
                },
            ]
        );
        // The basic root directory carries no index.
        assert!(image.entries[0].dir_index.is_empty());
    }

    /// spec #41: a truncated index entry is rejected.
    #[test]
    fn rejects_truncated_dir_index() {
        let mut b = Builder::new(false);
        let mut body = Vec::new();
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // index_count
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&NO_INDEX.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes()); // name_size = 9 bytes
        body.extend_from_slice(b"ab"); // but only 2 follow
        let pos = b.emit_inode(TYPE_EXT_DIR, 0o755, &body);
        assert!(parse_inode(&b.inode_stream, pos, b.block_size).is_err());
    }
}
