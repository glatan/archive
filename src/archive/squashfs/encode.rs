//! SquashFS 4.0 image writer.
//!
//! [`SquashfsEncoder`] produces a minimal image: a root directory
//! tree of regular files, no fragment table (file tails are stored
//! as ordinary data blocks), no xattr/export tables, and a single
//! UID/GID 0 entry in the ID table. Data blocks and metadata
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
const TYPE_EXT_FILE: u16 = 9;

/// No fragments, duplicates removed, no xattrs (informational bits).
const FLAGS: u16 = 0x0008 | 0x0010 | 0x0040 | 0x0100;
/// Compressor options block present (required for LZ4).
const FLAG_COMP_OPT: u16 = 0x0400;

const DEFAULT_BLOCK_SIZE: u32 = 128 * 1024;

/// Encoder for SquashFS 4.0 images (regular files + directories).
pub struct SquashfsEncoder {
    compression: SquashfsCompression,
    block_size: u32,
    mtime: u32,
    files: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct DirNode {
    /// name -> dir node index.
    dirs: BTreeMap<String, usize>,
    /// name -> file node index.
    files: BTreeMap<String, usize>,
}

struct FileNode {
    data: Vec<u8>,
}

impl SquashfsEncoder {
    /// New encoder: zlib ("gzip") compressor, 128 KiB blocks, mtime 0.
    pub fn new() -> Self {
        Self {
            compression: SquashfsCompression::Gzip,
            block_size: DEFAULT_BLOCK_SIZE,
            mtime: 0,
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

    /// Queue one regular file. `name` is a `/`-separated path;
    /// intermediate directories are created implicitly.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.files.push((String::from(name), data.to_vec()));
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

        // ---- directory tree ----
        let mut dirs: Vec<DirNode> = vec![DirNode::default()]; // 0 = root
        let mut files: Vec<FileNode> = Vec::new();
        for (name, data) in &self.files {
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
                    files.push(FileNode { data: data.clone() });
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
        let mut layouts: Vec<(u64, Vec<u32>)> = Vec::with_capacity(files.len());
        for f in &files {
            let start = 96 + comp_opts.len() as u64 + data_area.len() as u64;
            let mut sizes = Vec::new();
            for chunk in f.data.chunks(block_size) {
                sizes.push(emit_data_block(&mut data_area, self.compression, chunk));
            }
            layouts.push((start, sizes));
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
                    let (start, sizes) = &layouts[*f];
                    let file_size = files[*f].data.len() as u64;
                    if *start > u32::MAX as u64 || file_size > u32::MAX as u64 {
                        let body_len = 16 + 40 + sizes.len() * 4;
                        pad_for(&mut inode_stream, body_len);
                        inode_stream_off.push((ino, inode_stream.len()));
                        emit_ext_file_inode(
                            &mut inode_stream,
                            ino,
                            self.mtime,
                            *start,
                            file_size,
                            sizes,
                        );
                    } else {
                        let body_len = 16 + 16 + sizes.len() * 4;
                        pad_for(&mut inode_stream, body_len);
                        inode_stream_off.push((ino, inode_stream.len()));
                        emit_basic_file_inode(
                            &mut inode_stream,
                            ino,
                            self.mtime,
                            *start as u32,
                            file_size as u32,
                            sizes,
                        );
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
                children.push((name, file_ino[f], TYPE_BASIC_FILE, f));
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

        // ---- ID table: one metadata block containing [u32 0] ----
        let (id_meta, _) = pack_meta(&0u32.to_le_bytes(), self.compression);

        // ---- assemble ----
        let data_len = comp_opts.len() as u64 + data_area.len() as u64;
        let inode_table_start = 96 + data_len;
        let dir_table_start = inode_table_start + inode_meta.len() as u64;
        let id_meta_start = dir_table_start + dir_meta.len() as u64;
        let id_table_start = id_meta_start + id_meta.len() as u64;
        let bytes_used = id_table_start + 8;

        let mut out = Vec::with_capacity(bytes_used as usize);
        // superblock
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&inode_count.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes()); // mkfs_time
        out.extend_from_slice(&(block_size as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // frag_count
        out.extend_from_slice(&self.compression.id().to_le_bytes());
        out.extend_from_slice(&(block_size.trailing_zeros() as u16).to_le_bytes());
        let flags = FLAGS
            | if comp_opts.is_empty() {
                0
            } else {
                FLAG_COMP_OPT
            };
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // id_count
        out.extend_from_slice(&4u16.to_le_bytes()); // major
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&root_inode_ref.to_le_bytes());
        out.extend_from_slice(&bytes_used.to_le_bytes());
        out.extend_from_slice(&id_table_start.to_le_bytes());
        out.extend_from_slice(&TABLE_ABSENT.to_le_bytes()); // xattr
        out.extend_from_slice(&inode_table_start.to_le_bytes());
        out.extend_from_slice(&dir_table_start.to_le_bytes());
        out.extend_from_slice(&TABLE_ABSENT.to_le_bytes()); // frag
        out.extend_from_slice(&TABLE_ABSENT.to_le_bytes()); // export
        debug_assert_eq!(out.len(), 96);

        out.extend_from_slice(&comp_opts);
        out.extend_from_slice(&data_area);
        out.extend_from_slice(&inode_meta);
        out.extend_from_slice(&dir_meta);
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

fn emit_basic_file_inode(
    out: &mut Vec<u8>,
    ino: u32,
    mtime: u32,
    blocks_start: u32,
    file_size: u32,
    block_sizes: &[u32],
) {
    out.extend_from_slice(&TYPE_BASIC_FILE.to_le_bytes());
    out.extend_from_slice(&0o644u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&mtime.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&blocks_start.to_le_bytes());
    out.extend_from_slice(&NO_INDEX.to_le_bytes()); // frag index
    out.extend_from_slice(&0u32.to_le_bytes()); // frag offset
    out.extend_from_slice(&file_size.to_le_bytes());
    for &s in block_sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
}

fn emit_ext_file_inode(
    out: &mut Vec<u8>,
    ino: u32,
    mtime: u32,
    blocks_start: u64,
    file_size: u64,
    block_sizes: &[u32],
) {
    out.extend_from_slice(&TYPE_EXT_FILE.to_le_bytes());
    out.extend_from_slice(&0o644u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&mtime.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    out.extend_from_slice(&blocks_start.to_le_bytes());
    out.extend_from_slice(&file_size.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // sparse
    out.extend_from_slice(&1u32.to_le_bytes()); // nlink
    out.extend_from_slice(&NO_INDEX.to_le_bytes()); // frag index
    out.extend_from_slice(&0u32.to_le_bytes()); // frag offset
    out.extend_from_slice(&NO_INDEX.to_le_bytes()); // xattr
    for &s in block_sizes {
        out.extend_from_slice(&s.to_le_bytes());
    }
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
