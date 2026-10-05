//! erofs image encoding.
//!
//! Produces uncompressed little-endian images equivalent to
//! `mkfs.erofs` output without compression or `-E` feature flags:
//! the superblock at `EROFS_SUPER_OFFSET` (1024) with the inode
//! metadata area at block 0, compact (32-byte) or extended (64-byte)
//! inode slots, `erofs_dirent` directory blocks sorted by name, and
//! the flat data layouts — `EROFS_INODE_FLAT_INLINE` (whole blocks
//! at `raw_blkaddr` plus an inline tail right after the inode
//! metadata, or fully inline when the payload fits in the tail) and
//! `EROFS_INODE_FLAT_PLAIN` for block-aligned payloads, or whenever
//! inline data is disabled via `ErofsEncoder::set_inline_data`.
//! The `EROFS_FEATURE_COMPAT_SB_CHKSUM` superblock CRC32C is emitted
//! by default (`ErofsEncoder::set_checksum`). Layout references:
//! `Documentation/filesystems/erofs.rst` and `fs/erofs/erofs_fs.h`
//! (snapshots in `docs/spec/sources/`).
//!
//! Compressed (z_erofs), chunk-based, fragment, metabox and
//! multi-device images are intentionally out of scope for the
//! encoder; the decoder accepts them, mkfs.erofs produces them.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32c::crc32c;

use super::decode::COMPAT_SB_CHKSUM;

const SUPER_OFF: usize = 1024;
const SUPER_SIZE: usize = 128;
const MAGIC: u32 = 0xE0F5_E1E2;
const INODE_SLOT: usize = 32;
const DIRENT_SIZE: usize = 12;
/// First allocatable inode slot: right after the superblock record
/// (`meta_blkaddr` is emitted as 0, so nid*32 is an absolute offset).
const FIRST_NID: u64 = (SUPER_OFF + SUPER_SIZE) as u64 / INODE_SLOT as u64;

const DATALAYOUT_FLAT_PLAIN: u8 = 0;
const DATALAYOUT_FLAT_INLINE: u8 = 2;
const INODE_COMPACT: usize = 32;
const INODE_EXTENDED: usize = 64;
const NLINK_1: u16 = 0x10; // EROFS_I_NLINK_1_BIT

const S_IFMT: u16 = 0o170000;
const S_IFDIR: u16 = 0o040000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;

const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_LNK: u8 = 7;

/// `raw_blkaddr` value for fully-inline / empty flat inodes.
const NULL_BLKADDR: u64 = 0xFFFF_FFFF;

const MAX_NAME: usize = 255; // EROFS_NAME_LEN
const MAX_DEPTH: usize = 64; // matches the decoder walk limit

/// Metadata for an erofs entry.
///
/// Values that exceed the compact-inode field widths select a
/// 64-byte extended inode automatically (size over `u32::MAX`,
/// uid/gid over `u16::MAX`, negative or over-`u32::MAX` mtime,
/// nonzero `mtime_nsec`).
///
/// # Examples
///
/// ```
/// use archive::archive::erofs::encode::ErofsEntryOptions;
///
/// let opts = ErofsEntryOptions {
///     mode: 0o755,
///     uid: 1000,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ErofsEntryOptions {
    /// Permission bits (e.g. `0o644`). The file-type bits are
    /// supplied by the `add_*` method used; bits outside `0o7777`
    /// are ignored.
    pub mode: u16,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time, seconds since the Unix epoch. Compact
    /// inodes store this as a u32 delta on top of the superblock
    /// `epoch` (emitted as 0).
    pub mtime: i64,
    /// Modification time nanoseconds. Compact inodes cannot carry
    /// this; any nonzero value selects an extended inode.
    pub mtime_nsec: u32,
}

impl Default for ErofsEntryOptions {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        }
    }
}

#[derive(Debug)]
struct Node {
    name: String,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: u32,
    /// File / symlink payload; empty for directories.
    data: Vec<u8>,
    children: Vec<Node>,
}

impl Node {
    fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// Builder for erofs filesystem images.
///
/// Paths use `/` separators; missing parent directories are created
/// implicitly with mode `0o755`. Re-adding an existing path replaces
/// the entry (unless it would orphan a non-empty directory). Dirents
/// are sorted by name within each directory, matching mkfs.erofs.
///
/// # Examples
///
/// ```
/// use archive::archive::erofs::{decode, encode};
///
/// let mut enc = encode::ErofsEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// enc.add_dir("subdir");
/// let image = enc.finish().unwrap();
/// let decoded = decode::decode(&image).unwrap();
/// assert_eq!(decoded.entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct ErofsEncoder {
    root: Node,
    volume: [u8; 16],
    /// Filesystem block size as a bit shift (default 12 = 4 KiB).
    blkszbits: u8,
    /// Emit `FLAT_INLINE` inode tails (mkfs.erofs `-Einline_data`,
    /// the default) instead of padding every file to whole blocks.
    inline_data: bool,
    /// Emit `EROFS_FEATURE_COMPAT_SB_CHKSUM` superblock CRC32C
    /// (mkfs.erofs default).
    checksum: bool,
    /// First path/insert error, reported by `finish` (the `add_*`
    /// methods are infallible for trait compatibility).
    error: Option<&'static str>,
}

impl Default for ErofsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ErofsEncoder {
    /// Create a new encoder with an empty root directory (mode
    /// `0o755`, 4 KiB blocks, inline data and the superblock
    /// checksum enabled).
    ///
    /// This method does not panic.
    pub const fn new() -> Self {
        Self {
            root: Node {
                name: String::new(),
                mode: S_IFDIR | 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                data: Vec::new(),
                children: Vec::new(),
            },
            volume: [0; 16],
            blkszbits: 12,
            inline_data: true,
            checksum: true,
            error: None,
        }
    }

    /// Set the 16-byte volume name stored in the superblock
    /// (`mkfs.erofs -L`). Longer names are truncated; the name ends
    /// at the first NUL byte.
    ///
    /// This method does not panic.
    pub fn set_volume_name(&mut self, name: &str) {
        self.volume = [0; 16];
        let bytes = name.as_bytes();
        let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
        let n = end.min(16);
        self.volume[..n].copy_from_slice(&bytes[..n]);
    }

    /// Set the filesystem block size as a bit shift (`mkfs.erofs
    /// -b`, default 12 = 4 KiB). Values that cannot hold the
    /// superblock (below 11 = 2 KiB) or exceed 16 are rejected by
    /// [`ErofsEncoder::finish`].
    ///
    /// This method does not panic.
    pub fn set_blkszbits(&mut self, bits: u8) {
        self.blkszbits = bits;
    }

    /// Enable or disable inline tail data (`mkfs.erofs
    /// -Einline_data` / `-Enoinline_data`, default enabled). When
    /// disabled every file is emitted `FLAT_PLAIN`, padded to whole
    /// blocks.
    ///
    /// This method does not panic.
    pub fn set_inline_data(&mut self, enabled: bool) {
        self.inline_data = enabled;
    }

    /// Enable or disable the `EROFS_FEATURE_COMPAT_SB_CHKSUM`
    /// superblock CRC32C (default enabled, matching mkfs.erofs).
    ///
    /// This method does not panic.
    pub fn set_checksum(&mut self, enabled: bool) {
        self.checksum = enabled;
    }

    /// Add a regular file (mode `0o644`, uid/gid 0, mtime 0).
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::erofs::{decode, encode};
    /// let mut enc = encode::ErofsEncoder::new();
    /// enc.add_file("dir/a.txt", b"data"); // `dir` is created implicitly
    /// let img = decode::decode(&enc.finish().unwrap()).unwrap();
    /// assert_eq!(img.entries[0].name, "dir");
    /// ```
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.add_file_with_options(path, data, &ErofsEntryOptions::default());
    }

    /// Add a regular file with custom metadata.
    ///
    /// This method does not panic.
    pub fn add_file_with_options(&mut self, path: &str, data: &[u8], opts: &ErofsEntryOptions) {
        self.insert(path, S_IFREG | (opts.mode & 0o7777), opts, data);
    }

    /// Add a directory (mode `0o755`, uid/gid 0, mtime 0).
    ///
    /// This method does not panic.
    pub fn add_dir(&mut self, path: &str) {
        self.add_dir_with_options(
            path,
            &ErofsEntryOptions {
                mode: 0o755,
                ..Default::default()
            },
        );
    }

    /// Add a directory with custom metadata.
    ///
    /// This method does not panic.
    pub fn add_dir_with_options(&mut self, path: &str, opts: &ErofsEntryOptions) {
        self.insert(path, S_IFDIR | (opts.mode & 0o7777), opts, &[]);
    }

    /// Add a symlink (mode `0o777`); `target` is stored verbatim as
    /// the entry data.
    ///
    /// This method does not panic.
    pub fn add_symlink(&mut self, path: &str, target: &str) {
        self.add_symlink_with_options(
            path,
            target,
            &ErofsEntryOptions {
                mode: 0o777,
                ..Default::default()
            },
        );
    }

    /// Add a symlink with custom metadata.
    ///
    /// This method does not panic.
    pub fn add_symlink_with_options(&mut self, path: &str, target: &str, opts: &ErofsEntryOptions) {
        self.insert(
            path,
            S_IFLNK | (opts.mode & 0o7777),
            opts,
            target.as_bytes(),
        );
    }

    /// Insert `path` into the tree, creating intermediate
    /// directories. Structural errors are recorded in `self.error`
    /// and reported by [`ErofsEncoder::finish`].
    fn insert(&mut self, path: &str, mode: u16, opts: &ErofsEntryOptions, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let mut cur = &mut self.root;
        let mut it = path.trim_matches('/').split('/').peekable();
        while let Some(comp) = it.next() {
            if comp.is_empty() || comp == "." || comp == ".." || comp.as_bytes().contains(&0) {
                self.error = Some("erofs invalid path");
                return;
            }
            let idx = match cur.children.iter().position(|n| n.name == comp) {
                Some(i) => i,
                None => {
                    cur.children.push(Node {
                        name: String::from(comp),
                        mode: S_IFDIR | 0o755,
                        uid: 0,
                        gid: 0,
                        mtime: 0,
                        mtime_nsec: 0,
                        data: Vec::new(),
                        children: Vec::new(),
                    });
                    cur.children.len() - 1
                }
            };
            let child = &mut cur.children[idx];
            if it.peek().is_none() {
                if child.is_dir() && !child.children.is_empty() && mode & S_IFMT != S_IFDIR {
                    self.error = Some("erofs path replaces non-empty directory");
                    return;
                }
                child.mode = mode;
                child.uid = opts.uid;
                child.gid = opts.gid;
                child.mtime = opts.mtime;
                child.mtime_nsec = opts.mtime_nsec;
                child.data.clear();
                child.data.extend_from_slice(data);
                return;
            }
            if !child.is_dir() {
                self.error = Some("erofs path traverses non-directory");
                return;
            }
            cur = child;
        }
        self.error = Some("erofs empty path");
    }

    /// Finalize and return the erofs image bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an `add_*` call recorded a path error, or
    /// if a name, the block size, the directory depth, or the total
    /// image size exceeds an erofs field limit.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if let Some(msg) = self.error {
            return Err(Error::InvalidData(msg));
        }
        if !(9..=16).contains(&self.blkszbits) {
            return Err(Error::InvalidData("erofs invalid block size bits"));
        }
        let blksz = 1usize << self.blkszbits;
        if blksz < SUPER_OFF + SUPER_SIZE {
            return Err(Error::InvalidData("erofs block too small for superblock"));
        }
        let mut root = self.root;
        validate(&root, 0)?;
        sort_dir(&mut root);

        // Inode slots are allocated depth-first from FIRST_NID;
        // each inode occupies ceil((isize + inline tail) / 32) slots.
        let mut flat: Vec<Flat> = Vec::new();
        let mut next_slot = FIRST_NID;
        flatten(&mut flat, &root, 0, blksz, self.inline_data, &mut next_slot);

        // Data blocks start at the first block boundary past the
        // inode metadata area.
        if next_slot > u64::from(u32::MAX) {
            return Err(Error::InvalidData("erofs image too large"));
        }
        let data_blk = (next_slot as usize * INODE_SLOT).div_ceil(blksz);
        let mut next_blk = data_blk as u64;
        for i in 0..flat.len() {
            if flat[i].is_dir() {
                flat[i].data = dir_bytes(&flat, i, blksz);
                debug_assert_eq!(flat[i].data.len() as u64, flat[i].size);
            }
            let nblocks = flat[i].blocks(blksz);
            flat[i].startblk = if nblocks == 0 {
                NULL_BLKADDR
            } else {
                let b = next_blk;
                next_blk += nblocks as u64;
                b
            };
        }
        // `blocks` and the 32-bit `raw_blkaddr` share the limit; the
        // top block address additionally reserves the NULL marker.
        if next_blk > u64::from(u32::MAX) {
            return Err(Error::InvalidData("erofs image too large"));
        }
        let total = (next_blk as usize)
            .checked_mul(blksz)
            .ok_or(Error::InvalidData("erofs image too large"))?;
        let mut out = alloc::vec![0u8; total];

        for f in &flat {
            write_inode(&mut out, f);
            // Inline tail data sits right after the inode core.
            if f.tail > 0 {
                let off = f.nid as usize * INODE_SLOT + f.isize();
                let body = f.data.len() - f.tail;
                out[off..off + f.tail].copy_from_slice(&f.data[body..]);
            }
            if f.startblk != NULL_BLKADDR {
                let body = (f.blocks(blksz) * blksz).min(f.data.len());
                let dst = f.startblk as usize * blksz;
                out[dst..dst + body].copy_from_slice(&f.data[..body]);
            }
        }

        // ---- superblock ----
        let sb = SUPER_OFF;
        out[sb..sb + 4].copy_from_slice(&MAGIC.to_le_bytes());
        let compat = if self.checksum { COMPAT_SB_CHKSUM } else { 0 };
        out[sb + 8..sb + 12].copy_from_slice(&compat.to_le_bytes());
        out[sb + 12] = self.blkszbits;
        out[sb + 14..sb + 16].copy_from_slice(&(flat[0].nid as u16).to_le_bytes());
        out[sb + 16..sb + 24].copy_from_slice(&(flat.len() as u64).to_le_bytes());
        // epoch (24..32), fixed_nsec (32..36), xattr_blkaddr (44..48),
        // uuid (48..64), feature_incompat (80..84), extra_devices,
        // dirblkbits, xattr prefix bookkeeping, packed_nid,
        // build_time and rootnid_8b all stay zero.
        out[sb + 36..sb + 40].copy_from_slice(&(next_blk as u32).to_le_bytes());
        // meta_blkaddr = 0: inode slots address the whole image.
        out[sb + 64..sb + 80].copy_from_slice(&self.volume);
        if self.checksum {
            // EROFS_FEATURE_COMPAT_SB_CHKSUM: CRC32C over
            // `blksz - 1024` bytes from the superblock offset, the
            // checksum field zeroed, seeded ~0, no final complement
            // (erofs_crc32c). `crc32c` applies the complement, so
            // xor it back out.
            let mut region = out[sb..sb + (blksz - SUPER_OFF)].to_vec();
            region[4..8].fill(0);
            let sum = crc32c(&region) ^ 0xFFFF_FFFF;
            out[sb + 4..sb + 8].copy_from_slice(&sum.to_le_bytes());
        }
        Ok(out)
    }

    /// Finalize the image and write it to a writer. Returns the
    /// number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the image cannot be built or writing fails.
    #[cfg(feature = "std")]
    pub fn finish_to<W: std::io::Write>(self, mut writer: W) -> std::io::Result<usize> {
        let image = self.finish()?;
        writer.write_all(&image)?;
        Ok(image.len())
    }
}

/// One node flattened into emission (nid) order.
#[derive(Debug)]
struct Flat {
    /// Parent index in `flat`; the root's parent is itself.
    parent: usize,
    /// Last path component (empty for the root).
    name: String,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: u32,
    nlink: u32,
    /// File / symlink payload; the serialized dirent stream for
    /// directories (filled after nid assignment).
    data: Vec<u8>,
    children: Vec<usize>,
    nid: u64,
    size: u64,
    datalayout: u8,
    extended: bool,
    /// Inline tail bytes stored after the inode core.
    tail: usize,
    /// First data block, or `NULL_BLKADDR`.
    startblk: u64,
}

impl Flat {
    fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    fn isize(&self) -> usize {
        if self.extended {
            INODE_EXTENDED
        } else {
            INODE_COMPACT
        }
    }

    /// Whole data blocks stored at `startblk`.
    fn blocks(&self, blksz: usize) -> usize {
        let size = self.size as usize;
        if self.datalayout == DATALAYOUT_FLAT_INLINE {
            size / blksz
        } else {
            size.div_ceil(blksz)
        }
    }
}

/// Recursively flatten `dir` in pre-order, assigning nids.
fn flatten(
    flat: &mut Vec<Flat>,
    dir: &Node,
    parent: usize,
    blksz: usize,
    inline: bool,
    next_slot: &mut u64,
) -> usize {
    let idx = flat.len();
    let is_dir = dir.is_dir();
    let size = if is_dir {
        // `.`/`..` plus each child's name, packed into dir blocks.
        let mut lens = Vec::with_capacity(dir.children.len() + 2);
        lens.push(1usize);
        lens.push(2);
        lens.extend(dir.children.iter().map(|c| c.name.len()));
        dir_size(&lens, blksz) as u64
    } else {
        dir.data.len() as u64
    };
    let (datalayout, tail) = layout_of(size, blksz, inline);
    let nlink = if is_dir {
        2 + dir.children.iter().filter(|c| c.is_dir()).count() as u32
    } else {
        1
    };
    let extended = size > u64::from(u32::MAX)
        || dir.uid > u32::from(u16::MAX)
        || dir.gid > u32::from(u16::MAX)
        || nlink > u32::from(u16::MAX)
        || !(0..=u64::from(u32::MAX) as i64).contains(&dir.mtime)
        || dir.mtime_nsec != 0;
    let isize = if extended {
        INODE_EXTENDED
    } else {
        INODE_COMPACT
    };
    let nid = *next_slot;
    *next_slot += (isize + tail).div_ceil(INODE_SLOT) as u64;
    flat.push(Flat {
        parent,
        name: dir.name.clone(),
        mode: dir.mode,
        uid: dir.uid,
        gid: dir.gid,
        mtime: dir.mtime,
        mtime_nsec: dir.mtime_nsec,
        nlink,
        data: dir.data.clone(),
        children: Vec::new(),
        nid,
        size,
        datalayout,
        extended,
        tail,
        startblk: NULL_BLKADDR,
    });
    for c in &dir.children {
        let ci = flatten(flat, c, idx, blksz, inline, next_slot);
        flat[idx].children.push(ci);
    }
    idx
}

/// Pick the data layout and inline tail length for `size` bytes of
/// payload, mirroring mkfs.erofs: `FLAT_INLINE` with a tail when the
/// payload is not block-aligned (or empty), `FLAT_PLAIN` when it
/// fills whole blocks or inline data is disabled.
fn layout_of(size: u64, blksz: usize, inline: bool) -> (u8, usize) {
    let tail = (size % blksz as u64) as usize;
    if !inline || (tail == 0 && size > 0) {
        (DATALAYOUT_FLAT_PLAIN, 0)
    } else {
        (DATALAYOUT_FLAT_INLINE, tail)
    }
}

/// Directory stream size: entries of `12 + name_len` bytes greedily
/// packed into `blksz`-sized blocks; full blocks occupy `blksz`
/// bytes and the last keeps only its used bytes.
fn dir_size(name_lens: &[usize], blksz: usize) -> usize {
    let mut size = 0usize;
    let mut used = 0usize;
    for &l in name_lens {
        let cost = DIRENT_SIZE + l;
        if used > 0 && used + cost > blksz {
            size += blksz;
            used = 0;
        }
        used += cost;
    }
    size + used
}

/// Serialize the dirent blocks for `flat[dir]`: `.`/`..` first,
/// then the (already name-sorted) children. Each block carries a
/// packed `erofs_dirent` array followed by the name area; all but
/// the last block are padded to `blksz`.
fn dir_bytes(flat: &[Flat], dir: usize, blksz: usize) -> Vec<u8> {
    let ftype = |mode: u16| -> u8 {
        match mode & S_IFMT {
            S_IFDIR => FT_DIR,
            S_IFREG => FT_REG,
            S_IFLNK => FT_LNK,
            _ => 0, // EROFS_FT_UNKNOWN
        }
    };
    let mut ents: Vec<(u64, &[u8], u8)> = Vec::with_capacity(flat[dir].children.len() + 2);
    ents.push((flat[dir].nid, b".", FT_DIR));
    ents.push((flat[flat[dir].parent].nid, b"..", FT_DIR));
    for &c in &flat[dir].children {
        ents.push((flat[c].nid, flat[c].name.as_bytes(), ftype(flat[c].mode)));
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < ents.len() {
        let mut used = 0usize;
        let mut j = i;
        while j < ents.len() {
            let cost = DIRENT_SIZE + ents[j].1.len();
            if used > 0 && used + cost > blksz {
                break;
            }
            used += cost;
            j += 1;
        }
        let mut blk = alloc::vec![0u8; used];
        let mut noff = (j - i) * DIRENT_SIZE;
        for (k, &(nid, name, ft)) in ents[i..j].iter().enumerate() {
            let d = k * DIRENT_SIZE;
            blk[d..d + 8].copy_from_slice(&nid.to_le_bytes());
            blk[d + 8..d + 10].copy_from_slice(&(noff as u16).to_le_bytes());
            blk[d + 10] = ft;
            blk[noff..noff + name.len()].copy_from_slice(name);
            noff += name.len();
        }
        out.extend_from_slice(&blk);
        if j < ents.len() {
            out.resize(out.len().next_multiple_of(blksz), 0);
        }
        i = j;
    }
    out
}

/// Write the 32-byte compact or 64-byte extended inode record for
/// `f` at `nid * 32`.
fn write_inode(out: &mut [u8], f: &Flat) {
    let off = f.nid as usize * INODE_SLOT;
    let nlink1 = !f.extended && !f.is_dir() && f.nlink == 1;
    let mut ifmt = u16::from(f.datalayout) << 1;
    if f.extended {
        ifmt |= 1;
    }
    if nlink1 {
        ifmt |= NLINK_1;
    }
    out[off..off + 2].copy_from_slice(&ifmt.to_le_bytes());
    // i_xattr_icount (2..4) stays zero: no inline xattr ibody.
    out[off + 4..off + 6].copy_from_slice(&f.mode.to_le_bytes());
    let iu = f.startblk as u32;
    if f.extended {
        out[off + 6..off + 8].copy_from_slice(&((f.startblk >> 32) as u16).to_le_bytes());
        out[off + 8..off + 16].copy_from_slice(&f.size.to_le_bytes());
        out[off + 16..off + 20].copy_from_slice(&iu.to_le_bytes());
        out[off + 20..off + 24].copy_from_slice(&(f.nid as u32).to_le_bytes());
        out[off + 24..off + 28].copy_from_slice(&f.uid.to_le_bytes());
        out[off + 28..off + 32].copy_from_slice(&f.gid.to_le_bytes());
        out[off + 32..off + 40].copy_from_slice(&(f.mtime as u64).to_le_bytes());
        out[off + 40..off + 44].copy_from_slice(&f.mtime_nsec.to_le_bytes());
        out[off + 44..off + 48].copy_from_slice(&f.nlink.to_le_bytes());
    } else {
        // With NLINK_1 the i_nb union carries startblk_hi; otherwise
        // it is the 16-bit link count.
        let nb = if nlink1 {
            (f.startblk >> 32) as u16
        } else {
            f.nlink as u16
        };
        out[off + 6..off + 8].copy_from_slice(&nb.to_le_bytes());
        out[off + 8..off + 12].copy_from_slice(&(f.size as u32).to_le_bytes());
        out[off + 12..off + 16].copy_from_slice(&(f.mtime as u32).to_le_bytes());
        out[off + 16..off + 20].copy_from_slice(&iu.to_le_bytes());
        out[off + 20..off + 24].copy_from_slice(&(f.nid as u32).to_le_bytes());
        out[off + 24..off + 26].copy_from_slice(&(f.uid as u16).to_le_bytes());
        out[off + 26..off + 28].copy_from_slice(&(f.gid as u16).to_le_bytes());
    }
}

/// Sort every directory's children by name (erofs dirents are
/// sorted for binary search).
fn sort_dir(dir: &mut Node) {
    dir.children
        .sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    for c in &mut dir.children {
        if c.is_dir() {
            sort_dir(c);
        }
    }
}

/// Check format field limits before layout.
fn validate(dir: &Node, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(Error::InvalidData("erofs nesting too deep"));
    }
    for c in &dir.children {
        if c.name.len() > MAX_NAME {
            return Err(Error::InvalidData("erofs name too long"));
        }
        if c.is_dir() {
            validate(c, depth + 1)?;
        }
    }
    Ok(())
}

/// Serialize `entries` as `(path, data)` regular files; convenience
/// wrapper for the common case.
///
/// # Errors
///
/// Propagates [`ErofsEncoder::finish`] errors.
pub fn encode(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut enc = ErofsEncoder::new();
    for (name, data) in entries {
        enc.add_file(name, data);
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::super::decode::{self, ErofsKind};
    use super::*;
    use crate::traits::ArchiveEntry;
    use alloc::vec;

    fn find<'a>(img: &'a decode::ErofsImage, path: &str) -> &'a decode::ErofsEntry {
        img.entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("missing {path}"))
    }

    #[test]
    fn roundtrip_basic() {
        let mut enc = ErofsEncoder::new();
        enc.set_volume_name("testvol");
        enc.add_file("hello.txt", b"hello erofs");
        enc.add_file_with_options(
            "exec.sh",
            b"#!/bin/sh",
            &ErofsEntryOptions {
                mode: 0o755,
                uid: 1000,
                gid: 100,
                mtime: 1_600_000_000,
                ..Default::default()
            },
        );
        enc.add_file("empty.txt", b"");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.volume_name, "testvol");
        assert_eq!(dec.block_size, 4096);
        assert_eq!(
            dec.superblock.feature_compat & COMPAT_SB_CHKSUM,
            COMPAT_SB_CHKSUM
        );
        assert_eq!(dec.entries.len(), 3);
        let h = find(&dec, "hello.txt");
        assert_eq!(h.kind, ErofsKind::File);
        assert_eq!(h.data(), b"hello erofs");
        let x = find(&dec, "exec.sh");
        assert_eq!(x.mode & 0o7777, 0o755);
        assert_eq!(x.uid, 1000);
        assert_eq!(x.gid, 100);
        assert_eq!(x.mtime, 1_600_000_000);
        assert_eq!(x.nlink, 1);
        assert_eq!(find(&dec, "empty.txt").data(), b"");
    }

    #[test]
    fn roundtrip_nested_dirs() {
        let mut enc = ErofsEncoder::new();
        enc.add_file("a/b/c/deep.txt", b"deep");
        enc.add_file("a/top.txt", b"top");
        enc.add_dir("empty");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 6);
        assert_eq!(find(&dec, "a/b/c/deep.txt").data(), b"deep");
        assert_eq!(find(&dec, "a/top.txt").data(), b"top");
        assert_eq!(find(&dec, "a/b").kind, ErofsKind::Directory);
        let e = find(&dec, "empty");
        assert_eq!(e.kind, ErofsKind::Directory);
        assert_eq!(e.nlink, 2);
        // '.'/'..' dirents never surface as entries.
        assert!(
            dec.entries
                .iter()
                .all(|e| e.name() != "." && !e.name().ends_with("/."))
        );
    }

    #[test]
    fn roundtrip_symlink() {
        let mut enc = ErofsEncoder::new();
        enc.add_file("dir/t.txt", b"payload");
        enc.add_symlink("link", "dir/t.txt");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        let l = find(&dec, "link");
        assert_eq!(l.kind, ErofsKind::Symlink);
        assert_eq!(l.data(), b"dir/t.txt");
        assert_eq!(l.mode & S_IFMT, S_IFLNK);
    }

    /// FLAT_INLINE emits the unaligned tail after the inode;
    /// FLAT_PLAIN pads to whole blocks, so a no-inline image is
    /// larger for the same payload.
    #[test]
    fn roundtrip_inline_vs_plain() {
        let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();

        let mut enc = ErofsEncoder::new();
        enc.add_file("big.bin", &payload);
        let inline_img = enc.finish().unwrap();
        let dec = decode::decode(&inline_img).unwrap();
        assert_eq!(find(&dec, "big.bin").data(), &payload[..]);
        // 9000 = 2*4096 + 808: the tail is inlined; verify the inode
        // advertises FLAT_INLINE (datalayout bits 1..3 == 2).
        let nid = dirent_nid(&inline_img, b"big.bin");
        let ifmt = u16::from_le_bytes([
            inline_img[nid as usize * 32],
            inline_img[nid as usize * 32 + 1],
        ]);
        assert_eq!((ifmt >> 1) & 0x7, u16::from(DATALAYOUT_FLAT_INLINE));

        let mut enc = ErofsEncoder::new();
        enc.set_inline_data(false);
        enc.add_file("big.bin", &payload);
        let plain_img = enc.finish().unwrap();
        let dec = decode::decode(&plain_img).unwrap();
        assert_eq!(find(&dec, "big.bin").data(), &payload[..]);
        let nid = dirent_nid(&plain_img, b"big.bin");
        let ifmt = u16::from_le_bytes([
            plain_img[nid as usize * 32],
            plain_img[nid as usize * 32 + 1],
        ]);
        assert_eq!((ifmt >> 1) & 0x7, u16::from(DATALAYOUT_FLAT_PLAIN));
        assert!(plain_img.len() > inline_img.len());
    }

    /// Files whose size is an exact block multiple use FLAT_PLAIN
    /// even with inline data enabled.
    #[test]
    fn roundtrip_block_aligned_plain() {
        let payload = vec![0xABu8; 8192];
        let mut enc = ErofsEncoder::new();
        enc.add_file("exact.bin", &payload);
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(find(&dec, "exact.bin").data(), &payload[..]);
        let nid = dirent_nid(&img, b"exact.bin");
        let ifmt = u16::from_le_bytes([img[nid as usize * 32], img[nid as usize * 32 + 1]]);
        assert_eq!((ifmt >> 1) & 0x7, u16::from(DATALAYOUT_FLAT_PLAIN));
    }

    /// Read the nid out of the root directory dirent for name.
    /// Test-image root data either sits inline after the 32-byte
    /// root inode (FLAT_INLINE) or in the data block raw_blkaddr
    /// points at (FLAT_PLAIN); both are small single blocks here.
    fn dirent_nid(img: &[u8], name: &[u8]) -> u64 {
        let blksz = 1usize << img[SUPER_OFF + 12];
        let root = FIRST_NID as usize * INODE_SLOT;
        let ifmt = u16::from_le_bytes(img[root..root + 2].try_into().unwrap());
        let isize = if ifmt & 1 == 1 { 64 } else { 32 };
        let size = if ifmt & 1 == 1 {
            u64::from_le_bytes(img[root + 8..root + 16].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(img[root + 8..root + 12].try_into().unwrap()) as usize
        };
        let startblk = u32::from_le_bytes(img[root + 16..root + 20].try_into().unwrap());
        let inline = (ifmt >> 1) & 0x7 == u16::from(DATALAYOUT_FLAT_INLINE);
        let data: Vec<u8> = if inline && u64::from(startblk) == NULL_BLKADDR {
            img[root + isize..root + isize + size].to_vec()
        } else if inline {
            let body = size / blksz * blksz;
            let mut d = img[startblk as usize * blksz..startblk as usize * blksz + body].to_vec();
            d.extend_from_slice(&img[root + isize..root + isize + (size - body)]);
            d
        } else {
            img[startblk as usize * blksz..startblk as usize * blksz + size].to_vec()
        };
        let data = &data[..];
        let nameoff0 = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
        let n = nameoff0 / DIRENT_SIZE;
        for i in 0..n {
            let d = &data[i * DIRENT_SIZE..];
            let noff = u16::from_le_bytes(d[8..10].try_into().unwrap()) as usize;
            let end = if i + 1 < n {
                u16::from_le_bytes(
                    data[(i + 1) * DIRENT_SIZE + 8..(i + 1) * DIRENT_SIZE + 10]
                        .try_into()
                        .unwrap(),
                ) as usize
            } else {
                data.len()
            };
            let raw = &data[noff..end];
            let nul = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
            if &raw[..nul] == name {
                return u64::from_le_bytes(d[..8].try_into().unwrap());
            }
        }
        panic!("dirent not found");
    }

    #[test]
    fn roundtrip_extended_inode() {
        // mtime_nsec forces the 64-byte extended layout.
        let mut enc = ErofsEncoder::new();
        enc.add_file_with_options(
            "ts.dat",
            b"data!",
            &ErofsEntryOptions {
                mtime: -500,
                mtime_nsec: 123_456_789,
                uid: 70_000,
                ..Default::default()
            },
        );
        let img = enc.finish().unwrap();
        let nid = dirent_nid(&img, b"ts.dat");
        let ifmt = u16::from_le_bytes([img[nid as usize * 32], img[nid as usize * 32 + 1]]);
        assert_eq!(ifmt & 1, 1);
        let dec = decode::decode(&img).unwrap();
        let e = find(&dec, "ts.dat");
        assert_eq!(e.data(), b"data!");
        assert_eq!(e.uid, 70_000);
        assert_eq!(e.mtime, -500);
        assert_eq!(e.mtime_nsec, 123_456_789);
    }

    /// Enough entries to span multiple dirent blocks.
    #[test]
    fn roundtrip_many_entries() {
        let mut enc = ErofsEncoder::new();
        for i in 0..400u32 {
            enc.add_file(&alloc::format!("d/f{i:04}.bin"), &[i as u8]);
        }
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 401);
        let e = find(&dec, "d/f0250.bin");
        assert_eq!(e.data(), &[250u8]);
    }

    #[test]
    fn roundtrip_block_size() {
        let mut enc = ErofsEncoder::new();
        enc.set_blkszbits(13);
        enc.add_file("f", b"x");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.block_size, 8192);
        assert_eq!(find(&dec, "f").data(), b"x");
    }

    #[test]
    fn roundtrip_no_checksum() {
        let mut enc = ErofsEncoder::new();
        enc.set_checksum(false);
        enc.add_file("f", b"x");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.superblock.feature_compat, 0);
    }

    /// The emitted SB_CHKSUM verifies against any mutation inside
    /// the covered region.
    #[test]
    fn checksum_detects_corruption() {
        let mut enc = ErofsEncoder::new();
        enc.add_file("f", b"data");
        let mut img = enc.finish().unwrap();
        img[1024 + 64] ^= 0xff; // volume name byte, inside the csum range
        assert!(matches!(
            decode::decode(&img),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_bad_paths() {
        let mut enc = ErofsEncoder::new();
        enc.add_file("a//b", b"x");
        assert!(enc.finish().is_err());

        let mut enc = ErofsEncoder::new();
        enc.add_file("a/../b", b"x");
        assert!(enc.finish().is_err());

        let mut enc = ErofsEncoder::new();
        enc.add_file("a/./b", b"x");
        assert!(enc.finish().is_err());

        let mut enc = ErofsEncoder::new();
        enc.add_file("file", b"x");
        enc.add_file("file/sub", b"x");
        assert!(enc.finish().is_err());

        // Long component name (256 > EROFS_NAME_LEN).
        let mut enc = ErofsEncoder::new();
        enc.add_file(&"n".repeat(256), b"x");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let mut enc = ErofsEncoder::new();
        let mut path = String::new();
        for i in 0..70 {
            if i > 0 {
                path.push('/');
            }
            path.push('d');
        }
        enc.add_dir(&path);
        assert!(enc.finish().is_err());
    }

    #[test]
    fn rejects_bad_blkszbits() {
        for bits in [0u8, 8, 10, 17] {
            let mut enc = ErofsEncoder::new();
            enc.set_blkszbits(bits);
            enc.add_file("f", b"x");
            assert!(enc.finish().is_err(), "blkszbits {bits} accepted");
        }
    }

    #[test]
    fn encode_convenience() {
        let img = encode(&[("a.txt", b"alpha"), ("b/c.txt", b"nested")]).unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 3);
        assert_eq!(find(&dec, "b/c.txt").data(), b"nested");
    }
}
