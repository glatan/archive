//! SquashFS 4.0 image writer.
//!
//! [`SquashfsEncoder`] produces an image with a root directory
//! tree of regular files and symlinks. File tails go to ordinary
//! data blocks unless [`SquashfsEncoder::with_fragments`] packs them
//! into a shared fragment table. `add_file`/`add_symlink` use
//! uid/gid 0; the `*_owned` variants record additional ids in the
//! UID/GID table. No xattr/export tables are emitted. Data blocks and metadata
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
const TYPE_EXT_FILE: u16 = 9;

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
    /// UID/GID table: index 0 is always id 0; later ids are appended
    /// on first use. Both uid and gid draw from this one table.
    ids: Vec<u32>,
    files: Vec<(String, NodeData, u32, u32)>,
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
}

struct FileNode {
    data: NodeData,
    uid_idx: u16,
    guid_idx: u16,
}

impl SquashfsEncoder {
    /// New encoder: zlib ("gzip") compressor, 128 KiB blocks, mtime 0.
    pub fn new() -> Self {
        Self {
            compression: SquashfsCompression::Gzip,
            block_size: DEFAULT_BLOCK_SIZE,
            mtime: 0,
            fragments: false,
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

    /// Queue one file owned by uid/gid 0.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_owned(name, data, 0, 0);
    }

    /// Queue one file with explicit owner ids. The UID and GID tables
    /// share a single id list; ids are deduplicated on first use.
    pub fn add_file_owned(&mut self, name: &str, data: &[u8], uid: u32, gid: u32) {
        self.files
            .push((String::from(name), NodeData::File(data.to_vec()), uid, gid));
    }

    /// Queue one symlink (`name` -> `target`) owned by uid/gid 0.
    /// The target is stored verbatim; no normalization is applied.
    pub fn add_symlink(&mut self, name: &str, target: &str) {
        self.add_symlink_owned(name, target, 0, 0);
    }

    /// Queue one symlink with explicit owner ids.
    pub fn add_symlink_owned(&mut self, name: &str, target: &str, uid: u32, gid: u32) {
        self.files.push((
            String::from(name),
            NodeData::Symlink(target.as_bytes().to_vec()),
            uid,
            gid,
        ));
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
        for (name, data, uid, gid) in &self.files {
            let mut d = 0usize;
            let mut parts = name.split('/').peekable();
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
                    dirs[d].files.insert(String::from(part), files.len());
                    files.push(FileNode {
                        data: data.clone(),
                        uid_idx: id_idx(&mut encoder_ids, *uid)?,
                        guid_idx: id_idx(&mut encoder_ids, *gid)?,
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
                NodeData::Symlink(_) => {
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
                sizes.push(emit_data_block(&mut data_area, self.compression, chunk));
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

        // ---- inode table stream ----
        // Emit in inode-number order. Dir listing fields are patched
        // later, so record patch positions.
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

        let mut inode_stream = Vec::new();
        let mut inode_stream_off: Vec<(u32, usize)> = Vec::new(); // (ino, off)
        let mut dir_patch: BTreeMap<usize, usize> = BTreeMap::new(); // dir idx -> patch pos
        for (ino, node) in &nodes {
            let ino = *ino;
            match node {
                Node::Dir(d) => {
                    let body_len = 16 + 16;
                    pad_for(&mut inode_stream, body_len);
                    inode_stream_off.push((ino, inode_stream.len()));
                    dir_patch.insert(*d, inode_stream.len() + 16);
                    let nlink = 2 + dirs[*d].dirs.len() as u32;
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
                Node::File(f) => {
                    let node = &files[*f];
                    let (start, sizes, frag_index, frag_offset) = &layouts[*f];
                    match &node.data {
                        NodeData::Symlink(target) => {
                            let body_len = 16 + 8 + target.len();
                            pad_for(&mut inode_stream, body_len);
                            inode_stream_off.push((ino, inode_stream.len()));
                            emit_symlink_inode(
                                &mut inode_stream,
                                ino,
                                node.uid_idx,
                                node.guid_idx,
                                self.mtime,
                                target,
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
                                block_sizes: sizes.clone(),
                            };
                            if fields.blocks_start > u32::MAX as u64
                                || fields.file_size > u32::MAX as u64
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
                    }
                }
            }
        }

        // ---- pack inode metadata chunks (stored uncompressed so
        // wire offsets are content-independent; dir listings embed
        // these offsets and the inode stream is patched afterwards) ----
        let (_, inode_disk) = pack_meta_stored(&inode_stream);
        let disk_of = |chunk_idx: usize| inode_disk[chunk_idx];
        let inode_ref = |stream_off: usize| -> u64 {
            let c = stream_off / META_BLOCK_SIZE;
            (disk_of(c) << 16) | (stream_off % META_BLOCK_SIZE) as u64
        };
        let root_stream_off = inode_stream_off
            .iter()
            .find(|(n, _)| *n == 1)
            .map(|(_, o)| *o)
            .ok_or(Error::InvalidData("squashfs: missing root inode"))?;
        let root_inode_ref = inode_ref(root_stream_off);

        // ---- directory table stream ----
        // For each dir, children = subdirs+files sorted by name; group
        // consecutive runs sharing the inode-table chunk index.
        let mut dir_stream = Vec::new();
        let mut dir_listing: Vec<(u32, u16, u32)> = Vec::new(); // (block_index, block_offset, size)
        for &d in &dir_order {
            // children sorted by name across dirs+files.
            let mut children: Vec<(&String, u32, u16, usize)> = Vec::new();
            for (name, &sub) in &dirs[d].dirs {
                children.push((name, dir_ino[sub], TYPE_BASIC_DIR, sub));
            }
            for (name, &f) in &dirs[d].files {
                let ty = match files[f].data {
                    NodeData::File(_) => TYPE_BASIC_FILE,
                    NodeData::Symlink(_) => TYPE_BASIC_SYMLINK,
                };
                children.push((name, file_ino[f], ty, f));
            }
            children.sort_by(|a, b| a.0.cmp(b.0));
            if children.is_empty() {
                dir_listing.push((0, 0, 0));
                continue;
            }

            // Map each child ino -> (chunk_idx, inner off).
            let child_ref = |ino: u32| -> (usize, usize) {
                let off = inode_stream_off
                    .iter()
                    .find(|(n, _)| *n == ino)
                    .map(|(_, o)| *o)
                    .unwrap_or(0);
                (off / META_BLOCK_SIZE, off % META_BLOCK_SIZE)
            };

            // Build listing: runs grouped by child inode chunk.
            let mut listing = Vec::new();
            let mut gi = 0usize;
            while gi < children.len() {
                let (chunk, _) = child_ref(children[gi].1);
                let mut gj = gi;
                while gj < children.len() && child_ref(children[gj].1).0 == chunk {
                    gj += 1;
                }
                let run = &children[gi..gj];
                // header
                listing.extend_from_slice(&((run.len() as u32 - 1).to_le_bytes()));
                listing.extend_from_slice(&(disk_of(chunk) as u32).to_le_bytes());
                listing.extend_from_slice(&run[0].1.to_le_bytes()); // base inode
                let base = run[0].1 as i64;
                for (name, ino, ty, _) in run {
                    let (_, inner) = child_ref(*ino);
                    let diff64 = *ino as i64 - base;
                    if diff64 > i16::MAX as i64 {
                        return Err(Error::InvalidData("squashfs: listing inode diff overflow"));
                    }
                    let diff = diff64 as i16;
                    listing.extend_from_slice(&(inner as u16).to_le_bytes());
                    listing.extend_from_slice(&diff.to_le_bytes());
                    listing.extend_from_slice(&ty.to_le_bytes());
                    listing.extend_from_slice(&((name.len() - 1) as u16).to_le_bytes());
                    listing.extend_from_slice(name.as_bytes());
                }
                gi = gj;
            }

            // Place listing: pad dir chunk if it would straddle but
            // fits in a fresh block.
            let rem = META_BLOCK_SIZE - (dir_stream.len() % META_BLOCK_SIZE);
            if listing.len() > rem && listing.len() <= META_BLOCK_SIZE {
                dir_stream.resize(dir_stream.len() + rem, 0);
            }
            let soff = dir_stream.len();
            dir_stream.extend_from_slice(&listing);
            dir_listing.push((
                (soff / META_BLOCK_SIZE) as u32, // chunk idx -> patched to disk pos later
                (soff % META_BLOCK_SIZE) as u16,
                listing.len() as u32,
            ));
        }

        let (dir_meta, dir_disk) = pack_meta(&dir_stream, self.compression);
        // Patch listing block_index: chunk idx -> disk offset within dir region.
        for (i, (chunk_idx, inner, size)) in dir_listing.iter().enumerate() {
            let d = dir_order[i];
            let p = dir_patch[&d];
            if *size == 0 {
                continue; // empty listing: fields stay 0/3/0
            }
            let block_index = dir_disk[*chunk_idx as usize] as u32;
            inode_stream[p..p + 4].copy_from_slice(&block_index.to_le_bytes());
            inode_stream[p + 8..p + 10].copy_from_slice(&(*size as u16 + 3).to_le_bytes());
            inode_stream[p + 10..p + 12].copy_from_slice(&inner.to_le_bytes());
        }

        // Re-pack inode stream with patched dir inodes (stored;
        // wire layout identical to the first pass).
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

        // ---- ID table: collected ids as u32 entries ----
        let id_count = encoder_ids.len() as u16;
        let mut id_stream = Vec::with_capacity(encoder_ids.len() * 4);
        for &id in &encoder_ids {
            id_stream.extend_from_slice(&id.to_le_bytes());
        }
        let (id_meta, _) = pack_meta(&id_stream, self.compression);

        // ---- assemble ----
        let data_len = comp_opts.len() as u64 + data_area.len() as u64;
        let inode_table_start = 96 + data_len;
        let dir_table_start = inode_table_start + inode_meta.len() as u64;
        let frag_meta_start = dir_table_start + dir_meta.len() as u64;
        let frag_table_start = frag_meta_start + frag_meta.len() as u64;
        let id_meta_start = frag_table_start + frag_disk.len() as u64 * 8;
        let id_table_start = id_meta_start + id_meta.len() as u64;
        let bytes_used = id_table_start + 8;

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
        out.extend_from_slice(&TABLE_ABSENT.to_le_bytes()); // xattr
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
        out.extend_from_slice(&TABLE_ABSENT.to_le_bytes()); // export
        debug_assert_eq!(out.len(), 96);

        out.extend_from_slice(&comp_opts);
        out.extend_from_slice(&data_area);
        out.extend_from_slice(&inode_meta);
        out.extend_from_slice(&dir_meta);
        out.extend_from_slice(&frag_meta);
        for &d in &frag_disk {
            out.extend_from_slice(&(frag_meta_start + d).to_le_bytes());
        }
        out.extend_from_slice(&id_meta);
        out.extend_from_slice(&id_meta_start.to_le_bytes()); // location list
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
    out.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
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
) {
    out.extend_from_slice(&TYPE_BASIC_SYMLINK.to_le_bytes());
    out.extend_from_slice(&0o777u16.to_le_bytes());
    out.extend_from_slice(&uid_idx.to_le_bytes());
    out.extend_from_slice(&guid_idx.to_le_bytes());
    out.extend_from_slice(&mtime.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // nlink
    out.extend_from_slice(&(target.len() as u32).to_le_bytes());
    out.extend_from_slice(target);
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
