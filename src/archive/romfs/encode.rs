//! romfs image encoding.
//!
//! Writes the fixed big-endian layout described in
//! `docs/spec/sources/romfs.rst`: a `-rom1fs-` superblock, the
//! NUL-terminated volume name, and 16-byte-aligned file headers
//! chained through `next` offsets whose low nibble carries the
//! type/executable bits. Directory listings carry `.`/`..` helper
//! headers (the root header doubles as the root `.` entry) and file
//! data is padded to 16-byte boundaries, matching genromfs output.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{
    MAGIC, ROMFH_SIZE, TYPE_BLOCK, TYPE_CHAR, TYPE_DIR, TYPE_FIFO, TYPE_HARDLINK, TYPE_REG,
    TYPE_SOCKET, TYPE_SYMLINK, align16, checksum,
};

/// Longest name the decoder's 512-byte header scan window can reach:
/// the name and its NUL must fit in `512 - ROMFH_SIZE` bytes.
const MAX_NAME: usize = 495;
/// Path component limit; the decoder rejects nesting deeper than 128.
const MAX_DEPTH: usize = 128;

/// Payload queued for one image entry.
#[derive(Debug)]
enum NodeData {
    /// Regular file bytes.
    File(Vec<u8>),
    /// Directory; children are assembled in `finish`.
    Directory,
    /// Symlink target bytes.
    Symlink(Vec<u8>),
    /// Hard link to another entry's full path.
    Hardlink(String),
    /// Block device `(major, minor)`.
    Block(u16, u16),
    /// Char device `(major, minor)`.
    Char(u16, u16),
    /// Socket node.
    Socket,
    /// FIFO node.
    Fifo,
}

#[derive(Debug)]
struct Queued {
    /// Full path relative to the volume root, `/`-separated.
    path: String,
    exec: bool,
    data: NodeData,
}

/// Builder for romfs filesystem images.
///
/// Entries are queued with `add_*` methods and the image is serialized
/// by [`RomfsEncoder::finish`]. Intermediate directories are created
/// implicitly; `.`/`..` helper headers are emitted automatically.
///
/// # Examples
///
/// ```
/// use archive::archive::romfs::{decode, encode};
///
/// let mut enc = encode::RomfsEncoder::new().with_volume_name("vol");
/// enc.add_file("hello.txt", b"hi");
/// enc.add_directory("sub");
/// let img = enc.finish().unwrap();
/// let entries = decode::decode(&img).unwrap().entries;
/// assert_eq!(entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct RomfsEncoder {
    volume: String,
    entries: Vec<Queued>,
}

/// Directory-tree node assembled at `finish`.
struct Node {
    /// Last path component; `"."` for the root header.
    name: String,
    ty: u32,
    exec: bool,
    /// Parent directory index; the root's parent is itself.
    parent: usize,
    children: Vec<usize>,
    /// Regular file / symlink payload.
    data: Vec<u8>,
    /// `major << 16 | minor` for block and char nodes.
    dev: u32,
    /// Hard link target node index.
    link: Option<usize>,
}

/// One emitted header: a real node or a `.`/`..` helper.
enum Slot {
    /// Queued entry.
    Node(usize),
    /// `.` hard link to the directory itself.
    Dot(usize),
    /// `..` hard link to the directory's parent.
    DotDot(usize),
}

impl Default for RomfsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RomfsEncoder {
    /// New encoder with an empty volume name.
    pub const fn new() -> Self {
        Self {
            volume: String::new(),
            entries: Vec::new(),
        }
    }

    /// Set the superblock volume name (NUL-terminated, 16-aligned).
    pub fn with_volume_name(mut self, name: &str) -> Self {
        self.volume = String::from(name);
        self
    }

    fn queue(&mut self, path: &str, exec: bool, data: NodeData) {
        self.entries.push(Queued {
            path: String::from(path),
            exec,
            data,
        });
    }

    /// Queue a regular file without the executable bit.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.queue(name, false, NodeData::File(data.to_vec()));
    }

    /// Queue a regular file with the executable bit (mode `0o555`).
    pub fn add_executable_file(&mut self, name: &str, data: &[u8]) {
        self.queue(name, true, NodeData::File(data.to_vec()));
    }

    /// Queue a directory. Missing parents are created implicitly;
    /// directories always carry the executable bit like genromfs
    /// marks them (searchable, `0o555`).
    pub fn add_directory(&mut self, name: &str) {
        self.queue(name, true, NodeData::Directory);
    }

    /// Queue a symlink (`name` -> `target`); the target is stored
    /// verbatim as the entry's data.
    pub fn add_symlink(&mut self, name: &str, target: &str) {
        self.queue(name, true, NodeData::Symlink(target.as_bytes().to_vec()));
    }

    /// Queue a hard link: `spec.info` points at the header of
    /// `target`, which must be another queued path (added before or
    /// after this call). The target's exec bit is inherited.
    pub fn add_hardlink(&mut self, name: &str, target: &str) {
        self.queue(name, false, NodeData::Hardlink(String::from(target)));
    }

    /// Queue a block device node (`spec.info` = 16/16-bit
    /// major/minor).
    pub fn add_block_device(&mut self, name: &str, major: u16, minor: u16) {
        self.queue(name, false, NodeData::Block(major, minor));
    }

    /// Queue a char device node (`spec.info` = 16/16-bit
    /// major/minor).
    pub fn add_char_device(&mut self, name: &str, major: u16, minor: u16) {
        self.queue(name, false, NodeData::Char(major, minor));
    }

    /// Queue a socket node (`spec.info` MBZ).
    pub fn add_socket(&mut self, name: &str) {
        self.queue(name, false, NodeData::Socket);
    }

    /// Queue a FIFO node (`spec.info` MBZ).
    pub fn add_fifo(&mut self, name: &str) {
        self.queue(name, false, NodeData::Fifo);
    }

    /// Serialize the image.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] for bad paths (empty, absolute,
    /// `.`/`..`/empty components, names over 495 bytes, duplicates,
    /// children of non-directories), hard links with no matching
    /// target, or an image exceeding `u32::MAX` bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let vol = self.volume.as_bytes();
        if vol.len() > MAX_NAME || vol.contains(&0) {
            return Err(Error::InvalidData("romfs bad volume name"));
        }
        let first = ROMFH_SIZE + align16(vol.len() + 1);

        // ---- assemble the directory tree ----
        let mut nodes = Vec::new();
        nodes.push(Node {
            name: String::from("."),
            ty: TYPE_DIR,
            exec: true,
            parent: 0,
            children: Vec::new(),
            data: Vec::new(),
            dev: 0,
            link: None,
        });
        let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
        let mut links: Vec<(usize, &str)> = Vec::new();
        for q in &self.entries {
            let comps: Vec<&str> = q.path.split('/').collect();
            if comps.len() > MAX_DEPTH
                || comps.iter().any(|c| {
                    c.is_empty()
                        || *c == "."
                        || *c == ".."
                        || c.len() > MAX_NAME
                        || c.as_bytes().contains(&0)
                })
            {
                return Err(Error::InvalidData("romfs bad path"));
            }
            let (ty, payload, dev, target) = match &q.data {
                NodeData::File(d) => (TYPE_REG, d.clone(), 0, None),
                NodeData::Directory => (TYPE_DIR, Vec::new(), 0, None),
                NodeData::Symlink(d) => (TYPE_SYMLINK, d.clone(), 0, None),
                NodeData::Hardlink(t) => (TYPE_HARDLINK, Vec::new(), 0, Some(t.as_str())),
                NodeData::Block(ma, mi) => (
                    TYPE_BLOCK,
                    Vec::new(),
                    (*ma as u32) << 16 | *mi as u32,
                    None,
                ),
                NodeData::Char(ma, mi) => {
                    (TYPE_CHAR, Vec::new(), (*ma as u32) << 16 | *mi as u32, None)
                }
                NodeData::Socket => (TYPE_SOCKET, Vec::new(), 0, None),
                NodeData::Fifo => (TYPE_FIFO, Vec::new(), 0, None),
            };
            let mut parent = 0usize;
            let mut prefix = String::new();
            for (i, comp) in comps.iter().enumerate() {
                if i > 0 {
                    prefix.push('/');
                }
                prefix.push_str(comp);
                let existing = nodes[parent]
                    .children
                    .iter()
                    .copied()
                    .find(|&c| nodes[c].name == *comp);
                if i + 1 == comps.len() {
                    match existing {
                        // Re-declaring an (implicit) directory is a no-op.
                        Some(e) if ty == TYPE_DIR && nodes[e].ty == TYPE_DIR => {}
                        Some(_) => return Err(Error::InvalidData("romfs duplicate path")),
                        None => {
                            let idx = nodes.len();
                            nodes.push(Node {
                                name: String::from(*comp),
                                ty,
                                exec: q.exec,
                                parent,
                                children: Vec::new(),
                                data: payload.clone(),
                                dev,
                                link: None,
                            });
                            nodes[parent].children.push(idx);
                            by_path.insert(prefix.clone(), idx);
                            if let Some(t) = target {
                                links.push((idx, t));
                            }
                        }
                    }
                } else {
                    parent = match existing {
                        Some(e) if nodes[e].ty == TYPE_DIR => e,
                        Some(_) => {
                            return Err(Error::InvalidData("romfs path crosses non-directory"));
                        }
                        None => {
                            let idx = nodes.len();
                            nodes.push(Node {
                                name: String::from(*comp),
                                ty: TYPE_DIR,
                                exec: true,
                                parent,
                                children: Vec::new(),
                                data: Vec::new(),
                                dev: 0,
                                link: None,
                            });
                            nodes[parent].children.push(idx);
                            by_path.insert(prefix.clone(), idx);
                            idx
                        }
                    };
                }
            }
        }
        for (idx, target) in links {
            let t = *by_path
                .get(target)
                .ok_or(Error::InvalidData("romfs hard link target missing"))?;
            nodes[idx].link = Some(t);
            nodes[idx].exec = nodes[t].exec;
        }

        // ---- emission order: dir header, then its children chain
        // contiguously (a dir child is followed by its own subtree
        // before the next sibling), like genromfs ----
        let mut flat: Vec<Slot> = Vec::new();
        let mut chains: Vec<Vec<usize>> = nodes.iter().map(|_| Vec::new()).collect();
        let mut pos: Vec<usize> = alloc::vec![0; nodes.len()];
        fn emit_children(
            dir: usize,
            nodes: &[Node],
            flat: &mut Vec<Slot>,
            chains: &mut [Vec<usize>],
            pos: &mut [usize],
        ) {
            if dir != 0 {
                chains[dir].push(flat.len());
                flat.push(Slot::Dot(dir));
            }
            chains[dir].push(flat.len());
            flat.push(Slot::DotDot(dir));
            for &c in &nodes[dir].children {
                chains[dir].push(flat.len());
                pos[c] = flat.len();
                flat.push(Slot::Node(c));
                if nodes[c].ty == TYPE_DIR {
                    emit_children(c, nodes, flat, chains, pos);
                }
            }
        }
        // The root header doubles as the `.` entry: its own chain
        // starts at itself (spec points to itself).
        pos[0] = flat.len();
        flat.push(Slot::Node(0));
        chains[0].push(0);
        emit_children(0, &nodes, &mut flat, &mut chains, &mut pos);

        fn name_of<'a>(r: &'a Slot, nodes: &'a [Node]) -> &'a [u8] {
            match r {
                Slot::Node(i) => nodes[*i].name.as_bytes(),
                Slot::Dot(_) => b".",
                Slot::DotDot(_) => b"..",
            }
        }
        fn payload_of<'a>(r: &'a Slot, nodes: &'a [Node]) -> &'a [u8] {
            match r {
                Slot::Node(i) if matches!(nodes[*i].ty, TYPE_REG | TYPE_SYMLINK) => &nodes[*i].data,
                _ => &[],
            }
        }

        // ---- header offsets ----
        let mut offs: Vec<u32> = Vec::with_capacity(flat.len());
        let mut cur = first;
        for r in &flat {
            if cur > u32::MAX as usize {
                return Err(Error::InvalidData("romfs image too large"));
            }
            offs.push(cur as u32);
            cur += ROMFH_SIZE + align16(name_of(r, &nodes).len() + 1);
            let dlen = payload_of(r, &nodes).len();
            if dlen > 0 {
                cur = align16(cur + dlen);
            }
        }
        let image_end = cur;

        // sibling chains
        let mut next_of = alloc::vec![0u32; flat.len()];
        for chain in &chains {
            for w in chain.windows(2) {
                next_of[w[0]] = offs[w[1]];
            }
        }
        let spec_of = |r: &Slot| -> u32 {
            match r {
                Slot::Dot(d) => offs[pos[*d]],
                Slot::DotDot(d) => offs[pos[nodes[*d].parent]],
                Slot::Node(i) => match nodes[*i].ty {
                    TYPE_DIR => offs[chains[*i][0]],
                    TYPE_HARDLINK => offs[pos[nodes[*i].link.unwrap()]],
                    TYPE_BLOCK | TYPE_CHAR => nodes[*i].dev,
                    _ => 0,
                },
            }
        };

        // ---- serialize ----
        let mut out = alloc::vec![0u8; image_end.div_ceil(1024) * 1024];
        for (i, r) in flat.iter().enumerate() {
            let off = offs[i] as usize;
            let name = name_of(r, &nodes);
            let meta = ROMFH_SIZE + align16(name.len() + 1);
            let (ty, exec) = match r {
                Slot::Node(i) => (nodes[*i].ty, nodes[*i].exec),
                _ => (TYPE_HARDLINK, false),
            };
            let next_field = next_of[i] | (ty & 0x7) | if exec { 0x8 } else { 0 };
            out[off..off + 4].copy_from_slice(&next_field.to_be_bytes());
            out[off + 4..off + 8].copy_from_slice(&spec_of(r).to_be_bytes());
            out[off + 8..off + 12]
                .copy_from_slice(&(payload_of(r, &nodes).len() as u32).to_be_bytes());
            out[off + 16..off + 16 + name.len()].copy_from_slice(name);
            let payload = payload_of(r, &nodes);
            if !payload.is_empty() {
                out[off + meta..off + meta + payload.len()].copy_from_slice(payload);
            }
            // checksum field zeroes the longword sum of header + padded name
            let ck = checksum(&out[off..off + meta]).wrapping_neg();
            out[off + 12..off + 16].copy_from_slice(&ck.to_be_bytes());
        }

        // ---- superblock ----
        out[..8].copy_from_slice(MAGIC);
        out[8..12].copy_from_slice(&(image_end as u32).to_be_bytes());
        out[16..16 + vol.len()].copy_from_slice(vol);
        let ck_len = image_end.min(512);
        let ck = checksum(&out[..ck_len]).wrapping_neg();
        out[12..16].copy_from_slice(&ck.to_be_bytes());
        Ok(out)
    }
}

/// Serialize `entries` as `(path, data)` regular files; convenience
/// wrapper for the common case.
///
/// # Errors
///
/// Propagates [`RomfsEncoder::finish`] errors.
pub fn encode(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut enc = RomfsEncoder::new();
    for (name, data) in entries {
        enc.add_file(name, data);
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::super::decode::{self, RomfsKind};
    use super::*;
    use crate::traits::ArchiveEntry;

    fn find<'a>(img: &'a decode::RomfsImage, path: &str) -> &'a decode::RomfsEntry {
        img.entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("missing {path}"))
    }

    #[test]
    fn roundtrip_basic() {
        let mut enc = RomfsEncoder::new().with_volume_name("testvol");
        enc.add_file("hello.txt", b"hello romfs");
        enc.add_executable_file("exec.sh", b"#!/bin/sh\n");
        enc.add_symlink("link", "hello.txt");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.name, "testvol");
        assert_eq!(dec.entries.len(), 3);
        assert_eq!(find(&dec, "hello.txt").data(), b"hello romfs");
        assert_ne!(find(&dec, "exec.sh").mode & 0o111, 0);
        assert_eq!(find(&dec, "hello.txt").mode & 0o111, 0);
        let l = find(&dec, "link");
        assert_eq!(l.kind, RomfsKind::Symlink);
        assert_eq!(l.data(), b"hello.txt");
    }

    #[test]
    fn roundtrip_nested_dirs() {
        let mut enc = RomfsEncoder::new();
        enc.add_file("a/b/c/deep.txt", b"deep");
        enc.add_file("a/top.txt", b"top");
        enc.add_directory("empty");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(find(&dec, "a/b/c/deep.txt").data(), b"deep");
        assert_eq!(find(&dec, "a/top.txt").data(), b"top");
        assert_eq!(find(&dec, "a/b").kind, RomfsKind::Directory);
        assert_eq!(find(&dec, "empty").kind, RomfsKind::Directory);
        // '.'/'..' helpers never surface as entries
        assert!(
            dec.entries
                .iter()
                .all(|e| e.name() != "." && !e.name().ends_with("/."))
        );
    }

    #[test]
    fn roundtrip_hardlink_and_devices() {
        let mut enc = RomfsEncoder::new();
        enc.add_file("target.bin", b"shared");
        enc.add_hardlink("alias.bin", "target.bin");
        enc.add_char_device("dev/console", 5, 1);
        enc.add_block_device("dev/sda", 8, 16);
        enc.add_socket("sock");
        enc.add_fifo("pipe");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        let h = find(&dec, "alias.bin");
        assert_eq!(h.kind, RomfsKind::Hardlink);
        assert_eq!(h.data(), b"shared");
        let console = find(&dec, "dev/console");
        assert_eq!(console.kind, RomfsKind::Other(TYPE_CHAR));
        assert_eq!(console.dev, Some((5, 1)));
        let sda = find(&dec, "dev/sda");
        assert_eq!(sda.kind, RomfsKind::Other(TYPE_BLOCK));
        assert_eq!(sda.dev, Some((8, 16)));
        assert_eq!(find(&dec, "sock").kind, RomfsKind::Other(TYPE_SOCKET));
        assert_eq!(find(&dec, "sock").dev, None);
        assert_eq!(find(&dec, "pipe").dev, None);
    }

    /// Superblock and every header checksum must cancel to zero —
    /// `decode` enforces this, and we verify the sums directly too.
    #[test]
    fn checksum_matches() {
        let mut enc = RomfsEncoder::new();
        enc.add_file("a.txt", b"x");
        enc.add_directory("dir");
        enc.add_file("dir/b.txt", b"yy");
        let img = enc.finish().unwrap();
        decode::decode(&img).unwrap();
        let size = u32::from_be_bytes([img[8], img[9], img[10], img[11]]) as usize;
        assert_eq!(checksum(&img[..size.min(512)]), 0);
        // first header: root "." entry, meta = 16 + 16
        let first = ROMFH_SIZE + align16(1);
        assert_eq!(checksum(&img[first..first + ROMFH_SIZE + 16]), 0);
    }

    #[test]
    fn rejects_bad_paths() {
        for bad in ["", "/abs", "a//b", "a/./b", "../x", "a/../y"] {
            let mut enc = RomfsEncoder::new();
            enc.add_file(bad, b"x");
            assert!(enc.finish().is_err(), "accepted {bad:?}");
        }
        // duplicate
        let mut enc = RomfsEncoder::new();
        enc.add_file("dup", b"1");
        enc.add_file("dup", b"2");
        assert!(enc.finish().is_err());
        // child of a regular file
        let mut enc = RomfsEncoder::new();
        enc.add_file("f", b"x");
        enc.add_file("f/sub", b"y");
        assert!(enc.finish().is_err());
        // overlong component
        let mut enc = RomfsEncoder::new();
        let long = "n".repeat(MAX_NAME + 1);
        enc.add_file(&long, b"x");
        assert!(enc.finish().is_err());
        // too deep
        let mut enc = RomfsEncoder::new();
        let deep = (0..MAX_DEPTH + 1)
            .map(|_| "d")
            .collect::<Vec<_>>()
            .join("/");
        enc.add_file(&deep, b"x");
        assert!(enc.finish().is_err());
        // hard link to a missing target
        let mut enc = RomfsEncoder::new();
        enc.add_hardlink("l", "nowhere");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn encodes_empty_image() {
        let img = RomfsEncoder::new().finish().unwrap();
        assert_eq!(&img[..8], MAGIC);
        let dec = decode::decode(&img).unwrap();
        assert!(dec.entries.is_empty());
    }
}
