//! SquashFS 4.0 image writer.
//!
//! [`SquashfsEncoder`] produces an image with a root directory
//! tree of regular files, symlinks, and device/IPC special inodes.
//! File tails go to ordinary data blocks unless
//! [`SquashfsEncoder::with_fragments`] packs them into a shared
//! fragment table; all-zero data blocks are stored sparse.
//! `add_file`/`add_symlink` and the `add_*_device`/`add_fifo`/
//! `add_socket` calls use uid/gid 0; the `*_owned` variants record
//! additional ids in the UID/GID table. Optional extras:
//! [`SquashfsEncoder::with_export_table`] emits the inode export
//! table, [`SquashfsEncoder::with_dir_index`] writes extended
//! directory inodes with §6.1 index entries, and the `*_xattrs`
//! calls emit extended inodes plus a §10 xattr table (inodes
//! without attributes keep their basic types). Data blocks and
//! metadata
//! blocks use the configured compressor and fall back to stored
//! when compression does not shrink a block. The inode table is
//! always stored uncompressed: directory listings embed on-disk
//! metadata-block offsets that must stay stable while dir inode
//! bodies are patched. Inode numbers are
//! assigned consecutively per directory so listing deltas fit the
//! signed 16-bit field. Inodes never straddle metadata blocks;
//! directory listings are packed into metadata blocks unless a
//! single listing exceeds 8 KiB (allowed to straddle).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::decode::SquashfsCompression;
use crate::compress::{lz4, lzo, xz, zlib, zstd};
use crate::error::Error;

const MAGIC: u32 = 0x7371_7368;
const META_BLOCK_SIZE: usize = 8192;
const META_UNCOMPRESSED: u16 = 0x8000;
const META_SIZE_MASK: u16 = 0x7fff;
const BLOCK_UNCOMPRESSED: u32 = 1 << 24;
const NO_INDEX: u32 = u32::MAX;
const TABLE_ABSENT: u64 = u64::MAX;

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

/// Duplicates removed, no xattrs (informational bits); fragment
/// flags are OR'd in when the fragment table is disabled.
const FLAGS: u16 = 0x0040 | 0x0100;
/// Fragments stored uncompressed / no fragment table (informational).
const FLAG_FRAG_MASK: u16 = 0x0008 | 0x0010;
/// Compressor options block present (required for LZ4).
const FLAG_COMP_OPT: u16 = 0x0400;

const DEFAULT_BLOCK_SIZE: u32 = 128 * 1024;

/// Encoder for SquashFS 4.0 images (regular files + directories).
pub struct SquashfsEncoder {
    compression: SquashfsCompression,
    block_size: u32,
    mtime: u32,
    fragments: bool,
    export_table: bool,
    dir_index: bool,
    /// UID/GID table: index 0 is always id 0; later ids are appended
    /// on first use. Both uid and gid draw from this one table.
    ids: Vec<u32>,
    files: Vec<QueuedNode>,
}

struct QueuedNode {
    name: String,
    data: NodeData,
    uid: u32,
    gid: u32,
    /// Extended attributes as `(full name, value)`: the name
    /// must carry a `user.`/`trusted.`/`security.`
    /// prefix.
    xattrs: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct DirNode {
    /// name -> dir node index.
    dirs: BTreeMap<String, usize>,
    /// name -> file node index.
    files: BTreeMap<String, usize>,
}

#[derive(Clone)]
enum NodeData {
    File(Vec<u8>),
    Symlink(Vec<u8>),
    /// `rdev` already encoded in the 32-bit `new_encode_dev`
    /// layout.
    BlockDev(u32),
    CharDev(u32),
    Fifo,
    Socket,
}

impl NodeData {
    /// Directory-listing type field for this node.
    fn dir_type(&self) -> u16 {
        match self {
            NodeData::File(_) => TYPE_BASIC_FILE,
            NodeData::Symlink(_) => TYPE_BASIC_SYMLINK,
            NodeData::BlockDev(_) => TYPE_BASIC_BLKDEV,
            NodeData::CharDev(_) => TYPE_BASIC_CHRDEV,
            NodeData::Fifo => TYPE_BASIC_FIFO,
            NodeData::Socket => TYPE_BASIC_SOCKET,
        }
    }
}

struct FileNode {
    data: NodeData,
    uid_idx: u16,
    guid_idx: u16,
    /// `(raw type, name without prefix, value)` — validated.
    xattrs: Vec<(u16, Vec<u8>, Vec<u8>)>,
}

/// Encode `major`/`minor` into the 32-bit `new_encode_dev`
/// layout used by the SquashFS device inode `rdev` field.
fn encode_dev(major: u32, minor: u32) -> u32 {
    ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & !0xff) << 12)
}

impl SquashfsEncoder {
    /// New encoder: zlib ("gzip") compressor, 128 KiB blocks, mtime 0.
    pub fn new() -> Self {
        Self {
            compression: SquashfsCompression::Gzip,
            block_size: DEFAULT_BLOCK_SIZE,
            mtime: 0,
            fragments: false,
            export_table: false,
            dir_index: false,
            ids: vec![0],
            files: Vec::new(),
        }
    }

    /// Set the compressor for data and metadata blocks.
    ///
    /// [`SquashfsCompression::Lzma`] is rejected at finish (deprecated
    /// upstream, unsupported by the decoder).
    pub fn with_compression(mut self, compression: SquashfsCompression) -> Self {
        self.compression = compression;
        self
    }

    /// Set the data-block size (4 KiB ..= 1 MiB, power of two).
    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.block_size = block_size;
        self
    }

    /// Set the mtime recorded on every inode (seconds since epoch).
    pub fn with_mtime(mut self, mtime: u32) -> Self {
        self.mtime = mtime;
        self
    }

    /// Pack each file's tail (the remainder after full data blocks)
    /// into shared fragment blocks and emit a fragment table
    /// (§7). Without this, tails occupy a whole data block each and
    /// `frag_index` stays `NO_INDEX`.
    pub fn with_fragments(mut self) -> Self {
        self.fragments = true;
        self
    }

    /// Emit an export table mapping inode numbers to inode-table
    /// references (§8 layout: metadata blocks of u64 refs plus a
    /// location list). Without this the table offset is absent.
    pub fn with_export_table(mut self) -> Self {
        self.export_table = true;
        self
    }

    /// Write non-empty directories as extended directory inodes
    /// carrying a §6.1 index (one index entry per listing header).
    /// Empty directories keep basic dir inodes.
    pub fn with_dir_index(mut self) -> Self {
        self.dir_index = true;
        self
    }

    /// Queue one file owned by uid/gid 0.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_owned(name, data, 0, 0);
    }

    /// Queue one file with explicit owner ids. The UID and GID tables
    /// share a single id list; ids are deduplicated on first use.
    pub fn add_file_owned(&mut self, name: &str, data: &[u8], uid: u32, gid: u32) {
        self.files.push(QueuedNode {
            name: String::from(name),
            data: NodeData::File(data.to_vec()),
            uid,
            gid,
            xattrs: Vec::new(),
        });
    }

    /// Queue one file carrying extended attributes (`uid`/`gid` 0).
    /// Each xattr name must carry a `user.`/`trusted.`/`security.`
    /// prefix; the file is written as an extended file inode and a
    /// §10 xattr table is emitted.
    pub fn add_file_xattrs(&mut self, name: &str, data: &[u8], xattrs: &[(&str, &[u8])]) {
        self.files.push(QueuedNode {
            name: String::from(name),
            data: NodeData::File(data.to_vec()),
            uid: 0,
            gid: 0,
            xattrs: xattrs
                .iter()
                .map(|(n, v)| (String::from(*n), v.to_vec()))
                .collect(),
        });
    }

    /// Queue one symlink carrying extended attributes (`uid`/`gid` 0).
    /// Written as an extended symlink inode; see `add_file_xattrs`
    /// for the xattr name requirements.
    pub fn add_symlink_xattrs(&mut self, name: &str, target: &str, xattrs: &[(&str, &[u8])]) {
        self.files.push(QueuedNode {
            name: String::from(name),
            data: NodeData::Symlink(target.as_bytes().to_vec()),
            uid: 0,
            gid: 0,
            xattrs: xattrs
                .iter()
                .map(|(n, v)| (String::from(*n), v.to_vec()))
                .collect(),
        });
    }

    fn add_special(&mut self, name: &str, data: NodeData) {
        self.files.push(QueuedNode {
            name: String::from(name),
            data,
            uid: 0,
            gid: 0,
            xattrs: Vec::new(),
        });
    }

    /// Queue a block device node (`uid`/`gid` 0). `major`/`minor` are
    /// encoded in the 32-bit `new_encode_dev` layout.
    pub fn add_block_device(&mut self, name: &str, major: u32, minor: u32) {
        self.add_special(name, NodeData::BlockDev(encode_dev(major, minor)));
    }

    /// Queue a character device node (`uid`/`gid` 0).
    pub fn add_char_device(&mut self, name: &str, major: u32, minor: u32) {
        self.add_special(name, NodeData::CharDev(encode_dev(major, minor)));
    }

    /// Queue a FIFO (named pipe) node (`uid`/`gid` 0).
    pub fn add_fifo(&mut self, name: &str) {
        self.add_special(name, NodeData::Fifo);
    }

    /// Queue a socket node (`uid`/`gid` 0).
    pub fn add_socket(&mut self, name: &str) {
        self.add_special(name, NodeData::Socket);
    }

    /// Queue one symlink (`name` -> `target`) owned by uid/gid 0.
    /// The target is stored verbatim; no normalization is applied.
    pub fn add_symlink(&mut self, name: &str, target: &str) {
        self.add_symlink_owned(name, target, 0, 0);
    }

    /// Queue one symlink with explicit owner ids.
    pub fn add_symlink_owned(&mut self, name: &str, target: &str, uid: u32, gid: u32) {
        self.files.push(QueuedNode {
            name: String::from(name),
            data: NodeData::Symlink(target.as_bytes().to_vec()),
            uid,
            gid,
            xattrs: Vec::new(),
        });
    }

    /// Serialize the image.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] for bad paths, unsupported compressor,
    /// bad block size, or layout fields that overflow their wire type.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.compression == SquashfsCompression::Lzma {
            return Err(Error::Unsupported(
                "squashfs: LZMA1 compressor is deprecated and unsupported",
            ));
        }
        let block_size = self.block_size as usize;
        if !(4096..=(1 << 20)).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(Error::InvalidData("squashfs: bad block size"));
        }

        // ---- id table: index 0 = id 0; first-use order after that ----
        let mut encoder_ids = self.ids;
        let id_idx = |ids: &mut Vec<u32>, id: u32| -> Result<u16, Error> {
            match ids.iter().position(|&x| x == id) {
                Some(i) => Ok(i as u16),
                None => {
                    if ids.len() >= u16::MAX as usize {
                        return Err(Error::InvalidData("squashfs: too many ids"));
                    }
                    ids.push(id);
                    Ok((ids.len() - 1) as u16)
                }
            }
        };

        // ---- directory tree ----
        let mut dirs: Vec<DirNode> = vec![DirNode::default()]; // 0 = root
        let mut files: Vec<FileNode> = Vec::new();
        for q in &self.files {
            let mut d = 0usize;
            let mut parts = q.name.split('/').peekable();
            while let Some(part) = parts.next() {
                if part.is_empty() || part == "." || part == ".." {
                    return Err(Error::InvalidData("squashfs: bad path component"));
                }
                if parts.peek().is_some() {
                    d = match dirs[d].dirs.get(part) {
                        Some(&i) => i,
                        None => {
                            let i = dirs.len();
                            dirs.push(DirNode::default());
                            dirs[d].dirs.insert(String::from(part), i);
                            i
                        }
                    };
                } else {
                    if dirs[d].dirs.contains_key(part) || dirs[d].files.contains_key(part) {
                        return Err(Error::InvalidData("squashfs: duplicate name"));
                    }
                    let mut xattrs = Vec::with_capacity(q.xattrs.len());
                    for (name, value) in &q.xattrs {
                        xattrs.push(parse_xattr(name, value)?);
                    }
                    dirs[d].files.insert(String::from(part), files.len());
                    files.push(FileNode {
                        data: q.data.clone(),
                        uid_idx: id_idx(&mut encoder_ids, q.uid)?,
                        guid_idx: id_idx(&mut encoder_ids, q.gid)?,
                        xattrs,
                    });
                }
            }
        }

        // ---- inode numbering ----
        // root = 1; each dir's children (subdirs then files, name
        // order) get consecutive numbers so listing diffs stay small.
        let mut dir_ino: Vec<u32> = alloc::vec![0; dirs.len()];
        let mut file_ino: Vec<u32> = alloc::vec![0; files.len()];
        dir_ino[0] = 1;
        let mut next = 2u32;
        let mut dir_order: Vec<usize> = vec![0];
        let mut qi = 0usize;
        while qi < dir_order.len() {
            let d = dir_order[qi];
            for &sub in dirs[d].dirs.values() {
                dir_ino[sub] = next;
                next += 1;
                dir_order.push(sub);
            }
            for &f in dirs[d].files.values() {
                file_ino[f] = next;
                next += 1;
            }
            qi += 1;
        }
        let inode_count = next - 1;

        // Parent inode per dir (root's parent is itself).
        let mut dir_parent: Vec<u32> = alloc::vec![1; dirs.len()];
        for &d in &dir_order {
            for &sub in dirs[d].dirs.values() {
                dir_parent[sub] = dir_ino[d];
            }
        }

        // ---- compressor options block ----
        // LZ4 requires an (uncompressed) metadata block right after
        // the superblock: { u32 version = 1, u32 flags }. Other
        // compressors may omit it.
        let comp_opts = if self.compression == SquashfsCompression::Lz4 {
            let mut b = Vec::with_capacity(10);
            b.extend_from_slice(&(META_UNCOMPRESSED | 8u16).to_le_bytes());
            b.extend_from_slice(&1u32.to_le_bytes()); // version
            b.extend_from_slice(&0u32.to_le_bytes()); // flags
            b
        } else {
            Vec::new()
        };

        // ---- file data blocks ----
        // (blocks_start, block_sizes) per file index.
        let mut data_area = Vec::new();
        // Data blocks sit right after the superblock and the optional
        // compressor options block, so blocks_start is absolute.
        // Each layout: (blocks_start, block_sizes, frag_index,
        // frag_offset). Symlinks carry no data.
        let mut layouts: Vec<(u64, Vec<u32>, u32, u32)> = Vec::with_capacity(files.len());
        // Pending fragment block (concatenated tails, <= block_size)
        // and its table entries: (absolute start, raw size field).
        let mut frag_stream: Vec<u8> = Vec::new();
        let mut frag_entries: Vec<(u64, u32)> = Vec::new();
        for f in &files {
            let data = match &f.data {
                NodeData::File(d) => d.as_slice(),
                _ => {
                    layouts.push((0, Vec::new(), NO_INDEX, 0));
                    continue;
                }
            };
            let start = 96 + comp_opts.len() as u64 + data_area.len() as u64;
            let mut sizes = Vec::new();
            let (block_data, tail) = if self.fragments {
                let full = data.len() / block_size;
                data.split_at(full * block_size)
            } else {
                (data, &[][..])
            };
            for chunk in block_data.chunks(block_size) {
                // An all-zero block is stored sparse: a
                // entry of 0 carries no data and reads back as a full
                // run of zeros.
                if chunk.iter().all(|&b| b == 0) {
                    sizes.push(0);
                } else {
                    sizes.push(emit_data_block(&mut data_area, self.compression, chunk));
                }
            }
            let mut frag_index = NO_INDEX;
            let mut frag_offset = 0u32;
            if !tail.is_empty() {
                // Flush the pending fragment when the tail does
                // not fit.
                if frag_stream.len() + tail.len() > block_size {
                    let fstart = 96 + comp_opts.len() as u64 + data_area.len() as u64;
                    let raw = emit_data_block(&mut data_area, self.compression, &frag_stream);
                    frag_entries.push((fstart, raw));
                    frag_stream.clear();
                }
                frag_index = frag_entries.len() as u32;
                frag_offset = frag_stream.len() as u32;
                frag_stream.extend_from_slice(tail);
            }
            layouts.push((start, sizes, frag_index, frag_offset));
        }
        // Flush the final pending fragment.
        if !frag_stream.is_empty() {
            let fstart = 96 + comp_opts.len() as u64 + data_area.len() as u64;
            let raw = emit_data_block(&mut data_area, self.compression, &frag_stream);
            frag_entries.push((fstart, raw));
        }

        // ---- xattr key/value stream + lookup entries ----
        // Filled while emitting inodes; each fixpoint pass rebuilds
        // them identically.
        let mut kv_stream: Vec<u8> = Vec::new();
        let mut xattr_lookup: Vec<u8> = Vec::new(); // packed 16B entries

        // ---- children lists (name-sorted, computed once) ----
        // Per dir (in dir_order order): (name, inode number, type).
        let mut dir_children: Vec<Vec<(String, u32, u16)>> = Vec::with_capacity(dir_order.len());
        for &d in &dir_order {
            let mut children: Vec<(String, u32, u16)> = Vec::new();
            for (name, &sub) in &dirs[d].dirs {
                children.push((name.clone(), dir_ino[sub], TYPE_BASIC_DIR));
            }
            for (name, &f) in &dirs[d].files {
                children.push((name.clone(), file_ino[f], files[f].data.dir_type()));
            }
            children.sort_by(|a, b| a.0.cmp(&b.0));
            dir_children.push(children);
        }
        // dir idx -> position in dir_order.
        let mut dir_pos: Vec<usize> = alloc::vec![0; dirs.len()];
        for (i, &d) in dir_order.iter().enumerate() {
            dir_pos[d] = i;
        }

        // ---- inode table stream + listing run plan (fixpoint) ----
        // Extended dir inodes embed one index entry per listing header
        // run, but the run split depends on which metadata chunk each
        // child inode lands in -- which depends on dir body sizes.
        // Iterate emission until the partitioning stabilizes.
        enum Node {
            Dir(usize),
            File(usize),
        }
        let mut nodes: Vec<(u32, Node)> = Vec::new();
        for (i, &ino) in dir_ino.iter().enumerate() {
            nodes.push((ino, Node::Dir(i)));
        }
        for (i, &ino) in file_ino.iter().enumerate() {
            nodes.push((ino, Node::File(i)));
        }
        nodes.sort_by_key(|(n, _)| *n);

        /// Positions inside the inode stream patched once the
        /// directory table is packed.
        struct DirPatch {
            /// u32 field: dir-table disk position of the listing block.
            block_index: usize,
            /// file_size field position (u16 basic, u32 extended).
            file_size: usize,
            file_size_u32: bool,
            /// u16 field: listing offset inside its metadata block.
            block_offset: usize,
            /// Per index entry: (patch pos, run index) for the u32
            /// start field.
            index_starts: Vec<(usize, usize)>,
        }

        let mut inode_stream = Vec::new();
        let mut inode_stream_off: Vec<(u32, usize)> = Vec::new();
        let mut dir_patch: BTreeMap<usize, DirPatch> = BTreeMap::new();
        // Per dir (dir_order position): runs as child-index ranges.
        let mut run_plan: Vec<Vec<(usize, usize)>> = alloc::vec![Vec::new(); dir_order.len()];
        let mut inode_disk: Vec<u64> = Vec::new();
        let mut converged = false;

        for _pass in 0..16 {
            inode_stream.clear();
            inode_stream_off.clear();
            dir_patch.clear();
            kv_stream.clear();
            xattr_lookup.clear();

            for (ino, node) in &nodes {
                let ino = *ino;
                match node {
                    Node::Dir(d) => {
                        let runs = &run_plan[dir_pos[*d]];
                        let children = &dir_children[dir_pos[*d]];
                        let nlink = 2 + dirs[*d].dirs.len() as u32;
                        if self.dir_index && !runs.is_empty() {
                            // ext dir body: nlink u32, file_size u32,
                            // block_index u32, parent u32, i_count u16,
                            // block_offset u16, xattr u32, then
                            // i_count index entries
                            // {index u32, start u32, name_size-1 u32, name}.
                            let idx_len: usize =
                                runs.iter().map(|&(rs, _)| 12 + children[rs].0.len()).sum();
                            pad_for(&mut inode_stream, 16 + 24 + idx_len);
                            inode_stream_off.push((ino, inode_stream.len()));
                            let body = inode_stream.len() + 16;
                            inode_stream.extend_from_slice(&TYPE_EXT_DIR.to_le_bytes());
                            inode_stream.extend_from_slice(&0o755u16.to_le_bytes());
                            inode_stream.extend_from_slice(&0u16.to_le_bytes());
                            inode_stream.extend_from_slice(&0u16.to_le_bytes());
                            inode_stream.extend_from_slice(&self.mtime.to_le_bytes());
                            inode_stream.extend_from_slice(&ino.to_le_bytes());
                            inode_stream.extend_from_slice(&nlink.to_le_bytes());
                            inode_stream.extend_from_slice(&0u32.to_le_bytes()); // file_size (patch)
                            inode_stream.extend_from_slice(&0u32.to_le_bytes()); // block_index (patch)
                            inode_stream.extend_from_slice(&dir_parent[*d].to_le_bytes());
                            inode_stream.extend_from_slice(&(runs.len() as u16).to_le_bytes());
                            inode_stream.extend_from_slice(&0u16.to_le_bytes()); // block_offset (patch)
                            inode_stream.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
                            let mut index_starts = Vec::with_capacity(runs.len());
                            let mut listing_off = 0u32;
                            for &(rs, re) in runs {
                                inode_stream.extend_from_slice(&listing_off.to_le_bytes());
                                index_starts.push((inode_stream.len(), index_starts.len()));
                                inode_stream.extend_from_slice(&0u32.to_le_bytes()); // start (patch)
                                let name = &children[rs].0;
                                inode_stream
                                    .extend_from_slice(&((name.len() - 1) as u32).to_le_bytes());
                                inode_stream.extend_from_slice(name.as_bytes());
                                listing_off += 12
                                    + children[rs..re]
                                        .iter()
                                        .map(|(n, _, _)| 8 + n.len() as u32)
                                        .sum::<u32>();
                            }
                            dir_patch.insert(
                                *d,
                                DirPatch {
                                    block_index: body + 8,
                                    file_size: body + 4,
                                    file_size_u32: true,
                                    block_offset: body + 18,
                                    index_starts,
                                },
                            );
                        } else {
                            pad_for(&mut inode_stream, 16 + 16);
                            inode_stream_off.push((ino, inode_stream.len()));
                            let body = inode_stream.len() + 16;
                            dir_patch.insert(
                                *d,
                                DirPatch {
                                    block_index: body,
                                    file_size: body + 8,
                                    file_size_u32: false,
                                    block_offset: body + 10,
                                    index_starts: Vec::new(),
                                },
                            );
                            emit_dir_inode(
                                &mut inode_stream,
                                &DirInodeFields {
                                    ino,
                                    parent: dir_parent[*d],
                                    nlink,
                                    mtime: self.mtime,
                                    start_block: 0,
                                    file_size: 0,
                                    block_offset: 0,
                                },
                            );
                        }
                    }
                    Node::File(f) => {
                        let node = &files[*f];
                        let (start, sizes, frag_index, frag_offset) = &layouts[*f];
                        // An attributed node becomes an extended inode:
                        // append its xattr pairs to the kv stream and
                        // record its lookup index first.
                        let xattr_idx = if node.xattrs.is_empty() {
                            NO_INDEX
                        } else {
                            emit_xattr_pairs(&mut kv_stream, &mut xattr_lookup, &node.xattrs)?
                        };
                        match &node.data {
                            NodeData::Symlink(target) => {
                                let xlen = if xattr_idx == NO_INDEX { 0 } else { 4 };
                                let body_len = 16 + 8 + target.len() + xlen;
                                pad_for(&mut inode_stream, body_len);
                                inode_stream_off.push((ino, inode_stream.len()));
                                emit_symlink_inode(
                                    &mut inode_stream,
                                    ino,
                                    node.uid_idx,
                                    node.guid_idx,
                                    self.mtime,
                                    target,
                                    xattr_idx,
                                );
                            }
                            NodeData::File(data) => {
                                let file_size = data.len() as u64;
                                let fields = FileInodeFields {
                                    ino,
                                    uid_idx: node.uid_idx,
                                    guid_idx: node.guid_idx,
                                    mtime: self.mtime,
                                    blocks_start: *start,
                                    file_size,
                                    frag_index: *frag_index,
                                    frag_offset: *frag_offset,
                                    xattr_idx,
                                    block_sizes: sizes.clone(),
                                };
                                if fields.blocks_start > u32::MAX as u64
                                    || fields.file_size > u32::MAX as u64
                                    || xattr_idx != NO_INDEX
                                {
                                    let body_len = 16 + 40 + sizes.len() * 4;
                                    pad_for(&mut inode_stream, body_len);
                                    inode_stream_off.push((ino, inode_stream.len()));
                                    emit_ext_file_inode(&mut inode_stream, &fields);
                                } else {
                                    let body_len = 16 + 16 + sizes.len() * 4;
                                    pad_for(&mut inode_stream, body_len);
                                    inode_stream_off.push((ino, inode_stream.len()));
                                    emit_basic_file_inode(&mut inode_stream, &fields);
                                }
                            }
                            NodeData::BlockDev(rdev) | NodeData::CharDev(rdev) => {
                                pad_for(&mut inode_stream, 16 + 8);
                                inode_stream_off.push((ino, inode_stream.len()));
                                emit_dev_ipc_inode(
                                    &mut inode_stream,
                                    node.data.dir_type(),
                                    ino,
                                    node.uid_idx,
                                    node.guid_idx,
                                    self.mtime,
                                    Some(*rdev),
                                );
                            }
                            NodeData::Fifo | NodeData::Socket => {
                                pad_for(&mut inode_stream, 16 + 4);
                                inode_stream_off.push((ino, inode_stream.len()));
                                emit_dev_ipc_inode(
                                    &mut inode_stream,
                                    node.data.dir_type(),
                                    ino,
                                    node.uid_idx,
                                    node.guid_idx,
                                    self.mtime,
                                    None,
                                );
                            }
                        }
                    }
                }
            }

            let (_, disk) = pack_meta_stored(&inode_stream);
            inode_disk = disk;

            // Compute the actual run split: consecutive children whose
            // inodes share a metadata chunk and whose inode-number
            // diff stays within i16. A header covers at most 256
            // entries.
            let inode_off: BTreeMap<u32, usize> = inode_stream_off.iter().copied().collect();
            let child_ref = |ino: u32| -> (usize, usize) {
                let off = inode_off.get(&ino).copied().unwrap_or(0);
                (off / META_BLOCK_SIZE, off % META_BLOCK_SIZE)
            };
            let mut new_plan: Vec<Vec<(usize, usize)>> = alloc::vec![Vec::new(); dir_order.len()];
            for (di, children) in dir_children.iter().enumerate() {
                let mut s = 0usize;
                while s < children.len() {
                    let chunk = child_ref(children[s].1).0;
                    let base = children[s].1 as i64;
                    let mut e = s + 1;
                    while e < children.len() && e - s < 256 {
                        let (c, _) = child_ref(children[e].1);
                        if c != chunk || children[e].1 as i64 - base > i16::MAX as i64 {
                            break;
                        }
                        e += 1;
                    }
                    new_plan[di].push((s, e));
                    s = e;
                }
            }
            if new_plan == run_plan {
                converged = true;
                break;
            }
            run_plan = new_plan;
        }
        if !converged {
            return Err(Error::InvalidData(
                "squashfs: dir index layout did not converge",
            ));
        }

        let inode_off: BTreeMap<u32, usize> = inode_stream_off.iter().copied().collect();
        let root_stream_off = inode_off
            .get(&1)
            .copied()
            .ok_or(Error::InvalidData("squashfs: missing root inode"))?;
        let root_inode_ref = {
            let c = root_stream_off / META_BLOCK_SIZE;
            (inode_disk[c] << 16) | (root_stream_off % META_BLOCK_SIZE) as u64
        };

        // ---- directory table stream (from the converged plan) ----
        let mut dir_stream = Vec::new();
        // Per dir: (listing stream offset, listing byte len).
        let mut dir_listing: Vec<(usize, u32)> = Vec::new();
        let child_ref = |ino: u32| -> (usize, usize) {
            let off = inode_off.get(&ino).copied().unwrap_or(0);
            (off / META_BLOCK_SIZE, off % META_BLOCK_SIZE)
        };
        for (di, children) in dir_children.iter().enumerate() {
            if children.is_empty() {
                dir_listing.push((0, 0));
                continue;
            }
            let mut listing = Vec::new();
            for &(rs, re) in &run_plan[di] {
                let run = &children[rs..re];
                let (chunk, _) = child_ref(run[0].1);
                listing.extend_from_slice(&((run.len() as u32 - 1).to_le_bytes()));
                listing.extend_from_slice(&(inode_disk[chunk] as u32).to_le_bytes());
                listing.extend_from_slice(&run[0].1.to_le_bytes());
                let base = run[0].1 as i64;
                for (name, ino, ty) in run {
                    let (_, inner) = child_ref(*ino);
                    let diff = *ino as i64 - base;
                    if !(i16::MIN as i64..=i16::MAX as i64).contains(&diff) {
                        return Err(Error::InvalidData("squashfs: listing inode diff overflow"));
                    }
                    listing.extend_from_slice(&(inner as u16).to_le_bytes());
                    listing.extend_from_slice(&(diff as i16).to_le_bytes());
                    listing.extend_from_slice(&ty.to_le_bytes());
                    listing.extend_from_slice(&((name.len() - 1) as u16).to_le_bytes());
                    listing.extend_from_slice(name.as_bytes());
                }
            }
            // Pad the dir chunk when the listing would straddle but
            // fits in a fresh block.
            let rem = META_BLOCK_SIZE - (dir_stream.len() % META_BLOCK_SIZE);
            if listing.len() > rem && listing.len() <= META_BLOCK_SIZE {
                dir_stream.resize(dir_stream.len() + rem, 0);
            }
            let soff = dir_stream.len();
            dir_stream.extend_from_slice(&listing);
            dir_listing.push((soff, listing.len() as u32));
        }

        let (dir_meta, dir_disk) = pack_meta(&dir_stream, self.compression);
        // Patch dir inodes: listing position, size, and (for extended
        // dirs) each index entry start = the dir-table metadata block
        // holding the indexed header.
        for (i, &(soff, size)) in dir_listing.iter().enumerate() {
            let d = dir_order[i];
            let p = &dir_patch[&d];
            if size == 0 {
                continue;
            }
            let block_index = dir_disk[soff / META_BLOCK_SIZE] as u32;
            inode_stream[p.block_index..p.block_index + 4]
                .copy_from_slice(&block_index.to_le_bytes());
            if p.file_size_u32 {
                inode_stream[p.file_size..p.file_size + 4]
                    .copy_from_slice(&(size + 3).to_le_bytes());
            } else {
                inode_stream[p.file_size..p.file_size + 2]
                    .copy_from_slice(&(size as u16 + 3).to_le_bytes());
            }
            inode_stream[p.block_offset..p.block_offset + 2]
                .copy_from_slice(&((soff % META_BLOCK_SIZE) as u16).to_le_bytes());
            let mut listing_off = 0usize;
            for (k, &(pos, _run)) in p.index_starts.iter().enumerate() {
                let header_pos = soff + listing_off;
                let start = dir_disk[header_pos / META_BLOCK_SIZE] as u32;
                inode_stream[pos..pos + 4].copy_from_slice(&start.to_le_bytes());
                let (rs, re) = run_plan[i][k];
                listing_off += 12
                    + dir_children[i][rs..re]
                        .iter()
                        .map(|(n, _, _)| 8 + n.len() as u32)
                        .sum::<u32>() as usize;
            }
        }

        // Re-pack inode stream with patched dir inodes (stored; wire
        // layout identical to the first pass).
        let (inode_meta, _) = pack_meta_stored(&inode_stream);

        // ---- fragment table (16B entries: start u64, size u32,
        // unused u32) + location list ----
        let frag_count = frag_entries.len() as u32;
        let mut frag_stream_entries = Vec::with_capacity(frag_entries.len() * 16);
        for &(start, raw) in &frag_entries {
            frag_stream_entries.extend_from_slice(&start.to_le_bytes());
            frag_stream_entries.extend_from_slice(&raw.to_le_bytes());
            frag_stream_entries.extend_from_slice(&0u32.to_le_bytes());
        }
        let (frag_meta, frag_disk) = pack_meta(&frag_stream_entries, self.compression);

        // ---- export table: u64 inode refs indexed by inode number-1 ----
        let export_stream = if self.export_table {
            let mut es = Vec::with_capacity(inode_count as usize * 8);
            let inode_ref = |stream_off: usize| -> u64 {
                let c = stream_off / META_BLOCK_SIZE;
                (inode_disk[c] << 16) | (stream_off % META_BLOCK_SIZE) as u64
            };
            for ino in 1..=inode_count {
                let off = inode_off.get(&ino).copied().unwrap_or(0);
                es.extend_from_slice(&inode_ref(off).to_le_bytes());
            }
            es
        } else {
            Vec::new()
        };
        let (export_meta, export_disk) = pack_meta(&export_stream, self.compression);

        // ---- ID table: collected ids as u32 entries ----
        let id_count = encoder_ids.len() as u16;
        let mut id_stream = Vec::with_capacity(encoder_ids.len() * 4);
        for &id in &encoder_ids {
            id_stream.extend_from_slice(&id.to_le_bytes());
        }
        let (id_meta, _) = pack_meta(&id_stream, self.compression);

        // ---- xattr table: kv metadata run, lookup metadata run,
        // then the uncompressed header {kv_start, count, unused,
        // locations[]} ----
        let (kv_meta, _) = pack_meta(&kv_stream, self.compression);
        let (xattr_lookup_meta, xattr_lookup_disk) = pack_meta(&xattr_lookup, self.compression);

        // ---- assemble ----
        let data_len = comp_opts.len() as u64 + data_area.len() as u64;
        let inode_table_start = 96 + data_len;
        let dir_table_start = inode_table_start + inode_meta.len() as u64;
        let frag_meta_start = dir_table_start + dir_meta.len() as u64;
        let frag_table_start = frag_meta_start + frag_meta.len() as u64;
        let export_meta_start = frag_table_start + frag_disk.len() as u64 * 8;
        let export_table_start = export_meta_start + export_meta.len() as u64;
        let id_meta_start = export_table_start + export_disk.len() as u64 * 8;
        let id_table_start = id_meta_start + id_meta.len() as u64;
        let kv_start = id_table_start + 8;
        let xattr_table_start = kv_start + kv_meta.len() as u64 + xattr_lookup_meta.len() as u64;
        let bytes_used = if xattr_lookup.is_empty() {
            kv_start
        } else {
            xattr_table_start + 16 + xattr_lookup_disk.len() as u64 * 8
        };

        let mut out = Vec::with_capacity(bytes_used as usize);
        // superblock
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&inode_count.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes()); // mkfs_time
        out.extend_from_slice(&(block_size as u32).to_le_bytes());
        out.extend_from_slice(&frag_count.to_le_bytes());
        out.extend_from_slice(&self.compression.id().to_le_bytes());
        out.extend_from_slice(&(block_size.trailing_zeros() as u16).to_le_bytes());
        let flags = FLAGS
            | if self.fragments { 0 } else { FLAG_FRAG_MASK }
            | if comp_opts.is_empty() {
                0
            } else {
                FLAG_COMP_OPT
            };
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&id_count.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes()); // major
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&root_inode_ref.to_le_bytes());
        out.extend_from_slice(&bytes_used.to_le_bytes());
        out.extend_from_slice(&id_table_start.to_le_bytes());
        out.extend_from_slice(
            &(if xattr_lookup.is_empty() {
                TABLE_ABSENT
            } else {
                xattr_table_start
            })
            .to_le_bytes(),
        ); // xattr
        out.extend_from_slice(&inode_table_start.to_le_bytes());
        out.extend_from_slice(&dir_table_start.to_le_bytes());
        out.extend_from_slice(
            &(if frag_count == 0 {
                TABLE_ABSENT
            } else {
                frag_table_start
            })
            .to_le_bytes(),
        ); // frag
        out.extend_from_slice(
            &(if self.export_table {
                export_table_start
            } else {
                TABLE_ABSENT
            })
            .to_le_bytes(),
        ); // export
        debug_assert_eq!(out.len(), 96);

        out.extend_from_slice(&comp_opts);
        out.extend_from_slice(&data_area);
        out.extend_from_slice(&inode_meta);
        out.extend_from_slice(&dir_meta);
        out.extend_from_slice(&frag_meta);
        for &d in &frag_disk {
            out.extend_from_slice(&(frag_meta_start + d).to_le_bytes());
        }
        out.extend_from_slice(&export_meta);
        for &d in &export_disk {
            out.extend_from_slice(&(export_meta_start + d).to_le_bytes());
        }
        out.extend_from_slice(&id_meta);
        out.extend_from_slice(&id_meta_start.to_le_bytes()); // location list
        out.extend_from_slice(&kv_meta);
        out.extend_from_slice(&xattr_lookup_meta);
        if !xattr_lookup.is_empty() {
            out.extend_from_slice(&kv_start.to_le_bytes());
            out.extend_from_slice(&(xattr_lookup.len() as u32 / 16).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // unused
            for &d in &xattr_lookup_disk {
                out.extend_from_slice(&(kv_start + kv_meta.len() as u64 + d).to_le_bytes());
            }
        }
        debug_assert_eq!(out.len() as u64, bytes_used);
        Ok(out)
    }
}

/// Pad `stream` with zeros to the next metadata-block boundary when
/// a blob of `len` bytes would otherwise straddle it.
fn pad_for(stream: &mut Vec<u8>, len: usize) {
    let rem = META_BLOCK_SIZE - (stream.len() % META_BLOCK_SIZE);
    if len > rem && len <= META_BLOCK_SIZE {
        stream.resize(stream.len() + rem, 0);
    }
}

struct FileInodeFields {
    ino: u32,
    uid_idx: u16,
    guid_idx: u16,
    mtime: u32,
    blocks_start: u64,
    file_size: u64,
    frag_index: u32,
    frag_offset: u32,
    xattr_idx: u32,
    block_sizes: Vec<u32>,
}

struct DirInodeFields {
    ino: u32,
    parent: u32,
    nlink: u32,
    mtime: u32,
    start_block: u32,
    file_size: u16,
    block_offset: u16,
}

fn emit_dir_inode(out: &mut Vec<u8>, f: &DirInodeFields) {
    out.extend_from_slice(&TYPE_BASIC_DIR.to_le_bytes());
    out.extend_from_slice(&0o755u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&f.mtime.to_le_bytes());
    out.extend_from_slice(&f.ino.to_le_bytes());
    out.extend_from_slice(&f.start_block.to_le_bytes());
    out.extend_from_slice(&f.nlink.to_le_bytes());
    out.extend_from_slice(&f.file_size.to_le_bytes());
    out.extend_from_slice(&f.block_offset.to_le_bytes());
    out.extend_from_slice(&f.parent.to_le_bytes());
}

fn emit_basic_file_inode(out: &mut Vec<u8>, f: &FileInodeFields) {
    out.extend_from_slice(&TYPE_BASIC_FILE.to_le_bytes());
    out.extend_from_slice(&0o644u16.to_le_bytes());
    out.extend_from_slice(&f.uid_idx.to_le_bytes());
    out.extend_from_slice(&f.guid_idx.to_le_bytes());
    out.extend_from_slice(&f.mtime.to_le_bytes());
    out.extend_from_slice(&f.ino.to_le_bytes());
    out.extend_from_slice(&(f.blocks_start as u32).to_le_bytes());
    out.extend_from_slice(&f.frag_index.to_le_bytes());
    out.extend_from_slice(&f.frag_offset.to_le_bytes());
    out.extend_from_slice(&(f.file_size as u32).to_le_bytes());
    for &s in &f.block_sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
}

fn emit_ext_file_inode(out: &mut Vec<u8>, f: &FileInodeFields) {
    out.extend_from_slice(&TYPE_EXT_FILE.to_le_bytes());
    out.extend_from_slice(&0o644u16.to_le_bytes());
    out.extend_from_slice(&f.uid_idx.to_le_bytes());
    out.extend_from_slice(&f.guid_idx.to_le_bytes());
    out.extend_from_slice(&f.mtime.to_le_bytes());
    out.extend_from_slice(&f.ino.to_le_bytes());
    out.extend_from_slice(&f.blocks_start.to_le_bytes());
    out.extend_from_slice(&f.file_size.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // sparse
    out.extend_from_slice(&1u32.to_le_bytes()); // nlink
    out.extend_from_slice(&f.frag_index.to_le_bytes());
    out.extend_from_slice(&f.frag_offset.to_le_bytes());
    out.extend_from_slice(&f.xattr_idx.to_le_bytes());
    for &s in &f.block_sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
}

fn emit_symlink_inode(
    out: &mut Vec<u8>,
    ino: u32,
    uid_idx: u16,
    guid_idx: u16,
    mtime: u32,
    target: &[u8],
    xattr_idx: u32,
) {
    let ty = if xattr_idx == NO_INDEX {
        TYPE_BASIC_SYMLINK
    } else {
        TYPE_EXT_SYMLINK
    };
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&0o777u16.to_le_bytes());
    out.extend_from_slice(&uid_idx.to_le_bytes());
    out.extend_from_slice(&guid_idx.to_le_bytes());
    out.extend_from_slice(&mtime.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // nlink
    out.extend_from_slice(&(target.len() as u32).to_le_bytes());
    out.extend_from_slice(target);
    if xattr_idx != NO_INDEX {
        out.extend_from_slice(&xattr_idx.to_le_bytes());
    }
}

/// Emit a basic device or IPC inode: nlink u32, then an rdev u32 for
/// device types.
fn emit_dev_ipc_inode(
    out: &mut Vec<u8>,
    inode_type: u16,
    ino: u32,
    uid_idx: u16,
    guid_idx: u16,
    mtime: u32,
    rdev: Option<u32>,
) {
    out.extend_from_slice(&inode_type.to_le_bytes());
    let mode: u16 = if rdev.is_some() { 0o644 } else { 0o755 };
    out.extend_from_slice(&mode.to_le_bytes());
    out.extend_from_slice(&uid_idx.to_le_bytes());
    out.extend_from_slice(&guid_idx.to_le_bytes());
    out.extend_from_slice(&mtime.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // nlink
    if let Some(rdev) = rdev {
        out.extend_from_slice(&rdev.to_le_bytes());
    }
}

/// Split a user./trusted./security. prefixed xattr name into its raw
/// type id and the stored remainder.
fn parse_xattr(name: &str, value: &[u8]) -> Result<(u16, Vec<u8>, Vec<u8>), Error> {
    let (prefix, ty) = [("user.", 0u16), ("trusted.", 1), ("security.", 2)]
        .iter()
        .find_map(|(p, t)| name.strip_prefix(p).map(|r| (r, *t)))
        .ok_or(Error::InvalidData("squashfs: bad xattr name prefix"))?;
    if prefix.is_empty() || prefix.len() > u16::MAX as usize {
        return Err(Error::InvalidData("squashfs: bad xattr name"));
    }
    Ok((ty, prefix.as_bytes().to_vec(), value.to_vec()))
}

/// Append one inode's xattr pairs to the kv stream and return its
/// lookup-table index. The pair set is padded so it does not
/// straddle a metadata block when it fits in one.
fn emit_xattr_pairs(
    kv_stream: &mut Vec<u8>,
    lookup: &mut Vec<u8>,
    xattrs: &[(u16, Vec<u8>, Vec<u8>)],
) -> Result<u32, Error> {
    let set_len: usize = xattrs.iter().map(|(_, n, v)| 8 + n.len() + v.len()).sum();
    if set_len > u32::MAX as usize {
        return Err(Error::InvalidData("squashfs: xattr block too large"));
    }
    pad_for(kv_stream, set_len);
    let off = kv_stream.len();
    let xattr_ref = (((off / META_BLOCK_SIZE) << 16) | (off % META_BLOCK_SIZE)) as u64;
    for (ty, name, value) in xattrs {
        kv_stream.extend_from_slice(&ty.to_le_bytes());
        kv_stream.extend_from_slice(&(name.len() as u16).to_le_bytes());
        kv_stream.extend_from_slice(name);
        kv_stream.extend_from_slice(&(value.len() as u32).to_le_bytes());
        kv_stream.extend_from_slice(value);
    }
    let index = lookup.len() / 16;
    lookup.extend_from_slice(&xattr_ref.to_le_bytes());
    lookup.extend_from_slice(&(xattrs.len() as u32).to_le_bytes());
    lookup.extend_from_slice(&(set_len as u32).to_le_bytes());
    Ok(index as u32)
}

/// Emit one data block (compressed if smaller, else stored).
/// Returns the raw `block_sizes` field value.
fn emit_data_block(out: &mut Vec<u8>, compression: SquashfsCompression, chunk: &[u8]) -> u32 {
    let compressed = compress(compression, chunk);
    if compressed.len() < chunk.len() && compressed.len() <= 0x00ff_ffff {
        out.extend_from_slice(&compressed);
        compressed.len() as u32
    } else {
        out.extend_from_slice(chunk);
        BLOCK_UNCOMPRESSED | chunk.len() as u32
    }
}

/// Pack stream into stored (uncompressed) metadata blocks.
fn pack_meta_stored(stream: &[u8]) -> (Vec<u8>, Vec<u64>) {
    let mut out = Vec::new();
    let mut disk = Vec::new();
    for chunk in stream.chunks(META_BLOCK_SIZE) {
        disk.push(out.len() as u64);
        out.extend_from_slice(&(META_UNCOMPRESSED | chunk.len() as u16).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    (out, disk)
}

/// Split `stream` into <=8 KiB metadata blocks and emit each as a
/// `u16` header + payload (compressed if smaller, else stored with
/// the uncompressed flag). Returns `(wire_bytes, disk_offsets)`
/// where `disk_offsets[i]` is the on-disk offset of block i within
/// the emitted region.
fn pack_meta(stream: &[u8], compression: SquashfsCompression) -> (Vec<u8>, Vec<u64>) {
    let mut out = Vec::new();
    let mut disk = Vec::new();
    for chunk in stream.chunks(META_BLOCK_SIZE) {
        disk.push(out.len() as u64);
        let compressed = compress(compression, chunk);
        if compressed.len() < chunk.len() && compressed.len() <= META_SIZE_MASK as usize {
            out.extend_from_slice(&(compressed.len() as u16).to_le_bytes());
            out.extend_from_slice(&compressed);
        } else {
            out.extend_from_slice(&(META_UNCOMPRESSED | chunk.len() as u16).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    (out, disk)
}

fn compress(compression: SquashfsCompression, data: &[u8]) -> Vec<u8> {
    match compression {
        SquashfsCompression::Gzip => zlib::encode::encode(data),
        SquashfsCompression::Lzo => lzo::encode::compress_lzo1x(data),
        SquashfsCompression::Xz => xz::encode::encode(data),
        SquashfsCompression::Lz4 => lz4::encode::encode_block(data),
        SquashfsCompression::Zstd => zstd::encode::encode(data),
        SquashfsCompression::Lzma => Vec::new(), // rejected at finish
    }
}

impl Default for SquashfsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for SquashfsEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry as _;

    fn roundtrip(files: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
        let mut enc = SquashfsEncoder::new();
        for (n, d) in files {
            enc.add_file(n, d);
        }
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        dec.entries
            .iter()
            .map(|e| (e.name().to_string(), e.data().to_vec()))
            .collect()
    }

    #[test]
    fn sparse_blocks_roundtrip() {
        // A full all-zero data block is written sparse (block_sizes 0)
        // yet decodes back to the identical contents.
        let mut data = alloc::vec![0xABu8; DEFAULT_BLOCK_SIZE as usize];
        data.extend_from_slice(&alloc::vec![0u8; DEFAULT_BLOCK_SIZE as usize]);
        data.extend_from_slice(b"tail");
        let entries = roundtrip(&[("sparse.bin", &data)]);
        let f = entries.iter().find(|(n, _)| n == "sparse.bin").unwrap();
        assert_eq!(f.1, data);
    }

    #[test]
    fn device_and_ipc_inodes_roundtrip() {
        let mut enc = SquashfsEncoder::new();
        enc.add_block_device("blk0", 8, 0);
        enc.add_char_device("null", 1, 3);
        enc.add_fifo("pipe");
        enc.add_socket("sock");
        enc.add_file("f", b"x");
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let kind = |n: &str| dec.entries.iter().find(|e| e.name == n).unwrap().kind;
        use crate::archive::squashfs::decode::SquashfsKind;
        assert_eq!(kind("blk0"), SquashfsKind::BlockDevice);
        assert_eq!(kind("null"), SquashfsKind::CharDevice);
        assert_eq!(kind("pipe"), SquashfsKind::Fifo);
        assert_eq!(kind("sock"), SquashfsKind::Socket);
        // rdev: new_encode_dev(8,0) == 2048; (1,3) == 259
        let data_of = |n: &str| {
            dec.entries
                .iter()
                .find(|e| e.name == n)
                .unwrap()
                .data
                .clone()
        };
        assert_eq!(data_of("blk0"), (8u32 << 8).to_le_bytes());
        assert_eq!(data_of("null"), ((1u32 << 8) | 3).to_le_bytes());
    }

    #[test]
    fn xattrs_roundtrip() {
        let mut enc = SquashfsEncoder::new();
        enc.add_file_xattrs(
            "tagged",
            b"payload",
            &[("user.comment", b"hello"), ("security.selinux", b"tv")],
        );
        enc.add_symlink_xattrs("ln", "/target", &[("trusted.key", b"v")]);
        enc.add_file("plain", b"no attrs");
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let tagged = dec.entries.iter().find(|e| e.name == "tagged").unwrap();
        assert_eq!(
            tagged.xattrs,
            [
                crate::archive::squashfs::decode::SquashfsXattr {
                    name: "user.comment".into(),
                    value: b"hello".to_vec(),
                },
                crate::archive::squashfs::decode::SquashfsXattr {
                    name: "security.selinux".into(),
                    value: b"tv".to_vec(),
                },
            ]
        );
        let ln = dec.entries.iter().find(|e| e.name == "ln").unwrap();
        assert_eq!(ln.xattrs.len(), 1);
        assert_eq!(ln.xattrs[0].name, "trusted.key");
        let plain = dec.entries.iter().find(|e| e.name == "plain").unwrap();
        assert!(plain.xattrs.is_empty());
    }

    #[test]
    fn rejects_bad_xattr_name() {
        let mut enc = SquashfsEncoder::new();
        enc.add_file_xattrs("f", b"x", &[("system.foo", b"v")]);
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn export_table_roundtrip() {
        let mut enc = SquashfsEncoder::new().with_export_table();
        enc.add_file("a", b"1");
        enc.add_file("b/c", b"2");
        let img = enc.finish().unwrap();
        // Superblock export_table_start field is set (offset 88).
        assert_ne!(&img[88..96], &[0xff; 8]);
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let a = dec.entries.iter().find(|e| e.name == "a").unwrap();
        assert_eq!(a.data, b"1");
    }

    #[test]
    fn dir_index_roundtrip() {
        let mut enc = SquashfsEncoder::new().with_dir_index();
        for i in 0..40 {
            enc.add_file(&alloc::format!("d/f{i:03}"), b"x");
        }
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let d = dec.entries.iter().find(|e| e.name == "d").unwrap();
        assert!(!d.dir_index.is_empty());
        // All files still decode.
        let f = dec.entries.iter().find(|e| e.name == "d/f039").unwrap();
        assert_eq!(f.data, b"x");
    }

    #[test]
    fn single_file_roundtrip() {
        let entries = roundtrip(&[("hello.txt", b"hi squashfs")]);
        let root = entries.iter().find(|(n, _)| n == ".").unwrap();
        let _ = root;
        let f = entries.iter().find(|(n, _)| n == "hello.txt").unwrap();
        assert_eq!(f.1, b"hi squashfs");
    }

    #[test]
    fn nested_dirs_roundtrip() {
        let entries = roundtrip(&[
            ("a/b/c/deep.txt", b"deep"),
            ("a/sibling.txt", b"sib"),
            ("top.txt", b"top"),
        ]);
        for (name, want) in [
            ("a/b/c/deep.txt", &b"deep"[..]),
            ("a/sibling.txt", &b"sib"[..]),
            ("top.txt", &b"top"[..]),
        ] {
            let got = entries.iter().find(|(n, _)| n == name).unwrap();
            assert_eq!(got.1, want, "{name}");
        }
    }

    #[test]
    fn multi_block_file() {
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = SquashfsEncoder::new().with_block_size(4096);
        enc.add_file("big.bin", &data);
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let e = dec.entries.iter().find(|e| e.name() == "big.bin").unwrap();
        assert_eq!(e.data(), data.as_slice());
    }

    #[test]
    fn empty_file_and_empty_dir() {
        let mut enc = SquashfsEncoder::new();
        enc.add_file("empty", b"");
        enc.add_file("dir/sub/f", b"x");
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let e = dec.entries.iter().find(|e| e.name() == "empty").unwrap();
        assert!(e.data().is_empty());
    }

    #[test]
    fn compressors_roundtrip() {
        for comp in [
            SquashfsCompression::Lzo,
            SquashfsCompression::Xz,
            SquashfsCompression::Lz4,
            SquashfsCompression::Zstd,
        ] {
            let mut enc = SquashfsEncoder::new().with_compression(comp);
            enc.add_file("f", &[b'z'; 100_000]);
            let img = enc.finish().unwrap();
            let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
            assert_eq!(
                dec.entries
                    .iter()
                    .find(|e| e.name() == "f")
                    .unwrap()
                    .data()
                    .len(),
                100_000
            );
        }
    }

    #[test]
    fn rejects_bad_paths_and_compressor() {
        let mut enc = SquashfsEncoder::new();
        enc.add_file("a//b", b"x");
        assert!(enc.finish().is_err());
        let mut enc = SquashfsEncoder::new();
        enc.add_file("../up", b"x");
        assert!(enc.finish().is_err());
        let enc = SquashfsEncoder::new().with_compression(SquashfsCompression::Lzma);
        assert!(matches!(enc.finish(), Err(Error::Unsupported(_))));
    }

    #[test]
    fn symlink_roundtrip() {
        let mut enc = SquashfsEncoder::new();
        enc.add_symlink("link", "/target/path");
        enc.add_symlink_owned("sub/rel", "../a.txt", 1000, 200);
        enc.add_file("a.txt", b"content");
        let img = enc.finish().unwrap();
        // id_count = 3: 0, 1000, 200
        assert_eq!(u16::from_le_bytes([img[26], img[27]]), 3);
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let link = dec.entries.iter().find(|e| e.name == "link").unwrap();
        assert_eq!(link.data, b"/target/path");
        let rel = dec.entries.iter().find(|e| e.name == "sub/rel").unwrap();
        assert_eq!(rel.data, b"../a.txt");
    }

    #[test]
    fn fragments_roundtrip() {
        let block = 4096usize;
        let mut enc = SquashfsEncoder::new()
            .with_block_size(block as u32)
            .with_fragments();
        let a: Vec<u8> = (0..(block + 100) as u32).map(|i| (i % 13) as u8).collect();
        let b: Vec<u8> = (0..50u32).map(|i| (i % 7) as u8).collect();
        enc.add_file("a.bin", &a);
        enc.add_file("dir/b.bin", &b);
        let img = enc.finish().unwrap();
        // frag_count > 0 in the superblock (offset 16)
        assert!(u32::from_le_bytes([img[16], img[17], img[18], img[19]]) > 0);
        // frag_table_start != TABLE_ABSENT (offset 80)
        assert_ne!(
            u64::from_le_bytes(img[80..88].try_into().unwrap()),
            u64::MAX
        );
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        assert_eq!(
            dec.entries.iter().find(|e| e.name == "a.bin").unwrap().data,
            a
        );
        assert_eq!(
            dec.entries
                .iter()
                .find(|e| e.name == "dir/b.bin")
                .unwrap()
                .data,
            b
        );
    }

    #[test]
    fn fragments_disabled_by_default() {
        let mut enc = SquashfsEncoder::new().with_block_size(4096);
        enc.add_file("a", &[1, 2, 3]);
        let img = enc.finish().unwrap();
        assert_eq!(u32::from_le_bytes([img[16], img[17], img[18], img[19]]), 0);
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        let e = dec.entries.iter().find(|e| e.name == "a").unwrap();
        assert_eq!(e.data, vec![1, 2, 3]);
    }

    #[test]
    fn multiple_ids_roundtrip() {
        let mut enc = SquashfsEncoder::new();
        enc.add_file("a", b"1");
        enc.add_file_owned("b", b"2", 1000, 0);
        enc.add_file_owned("c", b"3", 1000, 200);
        let img = enc.finish().unwrap();
        // id_count = 3: 0, 1000, 200 (offset 26)
        assert_eq!(u16::from_le_bytes([img[26], img[27]]), 3);
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        for (name, want) in [("a", b"1" as &[u8]), ("b", b"2"), ("c", b"3")] {
            let e = dec.entries.iter().find(|e| e.name == name).unwrap();
            assert_eq!(e.data, want);
        }
    }

    #[test]
    fn inodes_do_not_straddle_metablock() {
        // Many files push the inode table past 8 KiB; each inode
        // must start inside one metadata block.
        let mut enc = SquashfsEncoder::new();
        for i in 0..400 {
            enc.add_file(&alloc::format!("file_{i:04}"), &[i as u8; 4]);
        }
        let img = enc.finish().unwrap();
        let dec = crate::archive::squashfs::decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 401);
    }
}
