//! cramfs image encoding.
//!
//! Produces little-endian images equivalent to `mkfs.cramfs` output:
//! a 64-byte superblock plus root inode, an inode region in
//! "width-first" order (each directory's entries contiguous, sorted by
//! name), and zlib-compressed 4 KiB data blocks emitted depth-first.
//! The fsid CRC is stored under `CRAMFS_FLAG_FSID_VERSION_2`, computed
//! as mkfs.cramfs does (CRC-32 of the image with the crc field zeroed).
//! Layout references: `fs/cramfs/README` and
//! `include/uapi/linux/cramfs_fs.h` (snapshots in `docs/spec/sources/`).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::zlib;
use crate::error::Error;
use crate::util::crc32::Crc32;

const MAGIC: u32 = 0x28cd_3d45;
const SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const BLKSIZE: usize = 4096;
const SUPER_LEN: usize = 76;

const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

const FLAG_FSID_VERSION_2: u32 = 0x001;
const FLAG_SORTED_DIRS: u32 = 0x002;

const MAX_NAME: usize = 252; // namelen is a 6-bit count of 4-byte units
const MAX_SIZE: usize = 0x00FF_FFFF; // size is a 24-bit field
const MAX_OFFSET_BYTES: usize = 1 << 28; // offset field: 26 bits, /4 units
const MAX_BLK_PTR: usize = 1 << 30; // block pointers reserve 2 flag bits
const MAX_DEPTH: usize = 64; // matches the decoder walk limit

/// Metadata for a cramfs entry.
///
/// # Examples
///
/// ```
/// use archive::archive::cramfs::encode::CramfsEntryOptions;
///
/// let opts = CramfsEntryOptions {
///     mode: 0o755,
///     uid: 1000,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct CramfsEntryOptions {
    /// Permission bits (e.g. `0o644`). The file-type bits are supplied
    /// by the `add_*` method used; bits outside `0o7777` are ignored.
    pub mode: u16,
    /// Owner uid (stored in a 16-bit field).
    pub uid: u32,
    /// Owner gid (stored in an 8-bit field).
    pub gid: u32,
}

impl Default for CramfsEntryOptions {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }
}

#[derive(Debug)]
struct Node {
    name: String,
    mode: u16,
    uid: u32,
    gid: u32,
    /// File contents or symlink target; empty for directories.
    data: Vec<u8>,
    children: Vec<Node>,
    /// Name to child index. Valid while `insert` builds the tree.
    /// `sort_dir` reorders `children` and does not consult this map.
    by_name: BTreeMap<String, usize>,
}

impl Node {
    fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// Regular files and symlinks carry compressed data blocks.
    fn is_data_leaf(&self) -> bool {
        matches!(self.mode & S_IFMT, S_IFREG | S_IFLNK)
    }

    /// Byte size of the emitted inode record (12-byte inode + name
    /// padded to a multiple of 4).
    fn rec_len(&self) -> usize {
        12 + self.name.len().div_ceil(4) * 4
    }
}

/// Builder for creating cramfs filesystem images.
///
/// Paths use `/` separators; missing parent directories are created
/// implicitly with mode `0o755`. Re-adding an existing path replaces
/// the entry (unless it would orphan a non-empty directory). Entries
/// are sorted by name within each directory, matching mkfs.cramfs.
///
/// # Examples
///
/// ```
/// use archive::archive::cramfs::{decode, encode};
///
/// let mut enc = encode::CramfsEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// enc.add_dir("subdir");
/// let image = enc.finish().unwrap();
/// let decoded = decode::decode(&image).unwrap();
/// assert_eq!(decoded.entries.len(), 2);
/// assert_eq!(decoded.fsid_crc_ok, Some(true));
/// ```
#[derive(Debug)]
pub struct CramfsEncoder {
    root: Node,
    volume: [u8; 16],
    /// First path/insert error, reported by `finish` (the `add_*`
    /// methods are infallible for trait compatibility).
    error: Option<&'static str>,
}

impl Default for CramfsEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CramfsEncoder {
    /// Create a new encoder with an empty root directory (mode `0o755`).
    ///
    /// This method does not panic.
    pub const fn new() -> Self {
        Self {
            root: Node {
                name: String::new(),
                mode: S_IFDIR | 0o755,
                uid: 0,
                gid: 0,
                data: Vec::new(),
                children: Vec::new(),
                by_name: BTreeMap::new(),
            },
            volume: [0; 16],
            error: None,
        }
    }

    /// Set the 16-byte volume name stored in the superblock
    /// (`mkfs.cramfs -n`). Longer names are truncated.
    ///
    /// This method does not panic.
    pub fn set_name(&mut self, name: &str) {
        self.volume = [0; 16];
        let n = name.len().min(16);
        self.volume[..n].copy_from_slice(&name.as_bytes()[..n]);
    }

    /// Add a regular file (mode `0o644`, uid/gid 0).
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cramfs::{decode, encode};
    /// let mut enc = encode::CramfsEncoder::new();
    /// enc.add_file("dir/a.txt", b"data"); // `dir` is created implicitly
    /// let img = decode::decode(&enc.finish().unwrap()).unwrap();
    /// assert_eq!(img.entries[0].name, "dir");
    /// ```
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.add_file_with_options(path, data, &CramfsEntryOptions::default());
    }

    /// Add a regular file with custom mode/uid/gid.
    ///
    /// This method does not panic.
    pub fn add_file_with_options(&mut self, path: &str, data: &[u8], opts: &CramfsEntryOptions) {
        self.insert(
            path,
            S_IFREG | (opts.mode & 0o7777),
            opts.uid,
            opts.gid,
            data,
        );
    }

    /// Add a directory (mode `0o755`, uid/gid 0).
    ///
    /// This method does not panic.
    pub fn add_dir(&mut self, path: &str) {
        self.add_dir_with_options(
            path,
            &CramfsEntryOptions {
                mode: 0o755,
                ..Default::default()
            },
        );
    }

    /// Add a directory with custom mode/uid/gid.
    ///
    /// This method does not panic.
    pub fn add_dir_with_options(&mut self, path: &str, opts: &CramfsEntryOptions) {
        self.insert(
            path,
            S_IFDIR | (opts.mode & 0o7777),
            opts.uid,
            opts.gid,
            &[],
        );
    }

    /// Add a symlink (mode `0o777`); `target` is stored compressed like
    /// file data.
    ///
    /// This method does not panic.
    pub fn add_symlink(&mut self, path: &str, target: &str) {
        self.insert(path, S_IFLNK | 0o777, 0, 0, target.as_bytes());
    }

    /// Insert `path` into the tree, creating intermediate directories.
    /// Structural errors are recorded in `self.error` and reported by
    /// [`CramfsEncoder::finish`].
    fn insert(&mut self, path: &str, mode: u16, uid: u32, gid: u32, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        let mut cur = &mut self.root;
        let mut it = path.trim_matches('/').split('/').peekable();
        while let Some(comp) = it.next() {
            if comp.is_empty() || comp == "." || comp == ".." || comp.as_bytes().contains(&0) {
                self.error = Some("cramfs invalid path");
                return;
            }
            let idx = match cur.by_name.get(comp).copied() {
                Some(i) => i,
                None => {
                    let idx = cur.children.len();
                    cur.by_name.insert(String::from(comp), idx);
                    cur.children.push(Node {
                        name: String::from(comp),
                        mode: S_IFDIR | 0o755,
                        uid: 0,
                        gid: 0,
                        data: Vec::new(),
                        children: Vec::new(),
                        by_name: BTreeMap::new(),
                    });
                    idx
                }
            };
            let child = &mut cur.children[idx];
            if it.peek().is_none() {
                if child.is_dir() && !child.children.is_empty() && mode & S_IFMT != S_IFDIR {
                    self.error = Some("cramfs path replaces non-empty directory");
                    return;
                }
                child.mode = mode;
                child.uid = uid;
                child.gid = gid;
                child.data.clear();
                child.data.extend_from_slice(data);
                return;
            }
            if !child.is_dir() {
                self.error = Some("cramfs path traverses non-directory");
                return;
            }
            cur = child;
        }
        self.error = Some("cramfs empty path");
    }

    /// Finalize and return the cramfs image bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an `add_*` call recorded a path error, or if
    /// a name, uid/gid, file size, directory size, or total image size
    /// exceeds a cramfs field limit.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if let Some(msg) = self.error {
            return Err(Error::InvalidData(msg));
        }
        let mut root = self.root;
        validate(&root, 0)?;
        sort_dir(&mut root);

        // Inode emission order: directories are processed depth-first,
        // each emitting its children as one contiguous run ("width-
        // first" in fs/cramfs/README terms). `runs` maps an emitted
        // position to (first child position, run bytes); usize::MAX is
        // the root sentinel.
        let mut order: Vec<&Node> = Vec::new();
        let mut runs: Vec<(usize, usize, u32)> = Vec::new();
        let mut stack: Vec<(usize, &Node)> = alloc::vec![(usize::MAX, &root)];
        while let Some((pos, dir)) = stack.pop() {
            let first = order.len();
            let mut bytes = 0u32;
            for c in &dir.children {
                order.push(c);
                bytes += c.rec_len() as u32;
            }
            runs.push((pos, first, bytes));
            // Reverse push so subdirectories are visited in entry order.
            for (i, c) in dir.children.iter().enumerate().rev() {
                if c.is_dir() && !c.children.is_empty() {
                    stack.push((first + i, c));
                }
            }
        }

        // Inode record byte offsets (records start at offset 76 and are
        // always 4-aligned, so offsets/4 fit the 26-bit field).
        let mut rec_off: Vec<usize> = Vec::with_capacity(order.len());
        let mut cur = SUPER_LEN;
        for n in &order {
            rec_off.push(cur);
            cur += n.rec_len();
        }
        if cur > MAX_OFFSET_BYTES {
            return Err(Error::InvalidData("cramfs image too large"));
        }

        let mut offset_field = alloc::vec![0u32; order.len()];
        let mut size_field = alloc::vec![0u32; order.len()];
        let mut root_run = (0usize, 0u32);
        for (pos, first, bytes) in runs {
            if pos == usize::MAX {
                root_run = (first, bytes);
            } else {
                size_field[pos] = bytes;
                offset_field[pos] = (rec_off[first] / 4) as u32;
            }
        }
        for (i, n) in order.iter().enumerate() {
            if n.is_data_leaf() {
                size_field[i] = n.data.len() as u32;
            }
        }

        // File data area (block-pointer arrays must be 4-aligned; all
        // record lengths are multiples of 4 so `cur` already is).
        let data_base = cur;
        let mut data: Vec<u8> = Vec::new();
        let mut index: BTreeMap<usize, usize> = BTreeMap::new();
        for (i, n) in order.iter().enumerate() {
            index.insert(*n as *const Node as usize, i);
        }
        let mut nblocks = 0u32;
        emit_data(
            &root,
            data_base,
            &mut data,
            &index,
            &mut offset_field,
            &mut nblocks,
        )?;

        // Assemble: superblock + inode region + data, padded to the
        // block size like mkfs.cramfs.
        let total = (data_base + data.len()).next_multiple_of(BLKSIZE);
        let mut out = alloc::vec![0u8; total];
        for (i, n) in order.iter().enumerate() {
            let o = rec_off[i];
            let w0 = n.mode as u32 | ((n.uid & 0xFFFF) << 16);
            let w1 = (size_field[i] & 0xFF_FFFF) | ((n.gid & 0xFF) << 24);
            let w2 = (n.name.len().div_ceil(4) as u32) | (offset_field[i] << 6);
            out[o..o + 4].copy_from_slice(&w0.to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&w1.to_le_bytes());
            out[o + 8..o + 12].copy_from_slice(&w2.to_le_bytes());
            out[o + 12..o + 12 + n.name.len()].copy_from_slice(n.name.as_bytes());
        }
        out[data_base..data_base + data.len()].copy_from_slice(&data);

        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(FLAG_FSID_VERSION_2 | FLAG_SORTED_DIRS).to_le_bytes());
        out[16..32].copy_from_slice(SIGNATURE);
        out[36..40].copy_from_slice(&0u32.to_le_bytes()); // fsid.edition
        out[40..44].copy_from_slice(&nblocks.to_le_bytes()); // fsid.blocks
        out[44..48].copy_from_slice(&((order.len() + 1) as u32).to_le_bytes()); // fsid.files
        out[48..64].copy_from_slice(&self.volume);
        // Root inode: directory, namelen 0.
        let root_off = if root_run.1 > 0 {
            (rec_off[root_run.0] / 4) as u32
        } else {
            0
        };
        out[64..68].copy_from_slice(&((S_IFDIR | 0o755) as u32).to_le_bytes());
        out[68..72].copy_from_slice(&(root_run.1 & 0xFF_FFFF).to_le_bytes());
        out[72..76].copy_from_slice(&(root_off << 6).to_le_bytes());
        // fsid.crc: CRC-32 of the image with the crc field zeroed.
        let mut crc = Crc32::new();
        crc.update(&out[..32]);
        crc.update(&[0; 4]);
        crc.update(&out[36..total]);
        out[32..36].copy_from_slice(&crc.finish().to_le_bytes());
        Ok(out)
    }

    /// Finalize the image and write it to a writer. Returns the number
    /// of bytes written.
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

/// Emit compressed data blocks for `dir`'s leaves in depth-first
/// (`find`) order, patching each leaf's inode offset field.
fn emit_data(
    dir: &Node,
    base: usize,
    area: &mut Vec<u8>,
    index: &BTreeMap<usize, usize>,
    offsets: &mut [u32],
    nblocks_total: &mut u32,
) -> Result<(), Error> {
    for c in &dir.children {
        if c.is_data_leaf() && !c.data.is_empty() {
            let start = base + area.len(); // 4-aligned by construction
            if start >= MAX_OFFSET_BYTES {
                return Err(Error::InvalidData("cramfs image too large"));
            }
            offsets[index[&(c as *const Node as usize)]] = (start / 4) as u32;
            let nblocks = c.data.len().div_ceil(BLKSIZE);
            *nblocks_total += nblocks as u32;
            let ptrs = area.len();
            area.resize(ptrs + nblocks * 4, 0);
            for (b, chunk) in c.data.chunks(BLKSIZE).enumerate() {
                area.extend_from_slice(&zlib::encode::encode(chunk));
                // Pointer i holds the absolute end offset of block i.
                let end = base + area.len();
                if end >= MAX_BLK_PTR {
                    return Err(Error::InvalidData("cramfs image too large"));
                }
                area[ptrs + b * 4..ptrs + b * 4 + 4].copy_from_slice(&(end as u32).to_le_bytes());
            }
            let padded = area.len().next_multiple_of(4);
            area.resize(padded, 0);
        }
        if c.is_dir() {
            emit_data(c, base, area, index, offsets, nblocks_total)?;
        }
    }
    Ok(())
}

/// Sort every directory's children by name (mkfs.cramfs sets
/// `CRAMFS_FLAG_SORTED_DIRS` for this layout).
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
        return Err(Error::InvalidData("cramfs nesting too deep"));
    }
    let mut run_bytes = 0usize;
    for c in &dir.children {
        run_bytes += c.rec_len();
        if c.name.len() > MAX_NAME {
            return Err(Error::InvalidData("cramfs name too long"));
        }
        if c.uid > 0xFFFF {
            return Err(Error::InvalidData("cramfs uid too large"));
        }
        if c.gid > 0xFF {
            return Err(Error::InvalidData("cramfs gid too large"));
        }
        if c.is_data_leaf() && c.data.len() > MAX_SIZE {
            return Err(Error::InvalidData("cramfs file too large"));
        }
        if c.is_dir() {
            validate(c, depth + 1)?;
        }
    }
    if run_bytes > MAX_SIZE {
        return Err(Error::InvalidData("cramfs directory too large"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::cramfs::decode::{self, CramfsKind};
    use crate::traits::ArchiveEntry;

    #[test]
    fn roundtrip_basic() {
        let mut enc = CramfsEncoder::new();
        enc.set_name("testvol");
        enc.add_file("a.txt", b"alpha");
        enc.add_file("b.txt", b"beta file contents");
        enc.add_file("empty.txt", b"");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.name, "testvol");
        assert_eq!(dec.fsid_crc_ok, Some(true));
        assert_eq!(dec.entries.len(), 3);
        let a = dec.entries.iter().find(|e| e.name() == "a.txt").unwrap();
        assert_eq!(a.kind, CramfsKind::File);
        assert_eq!(a.data(), b"alpha");
        let e = dec
            .entries
            .iter()
            .find(|e| e.name() == "empty.txt")
            .unwrap();
        assert_eq!(e.data(), b"");
    }

    #[test]
    fn roundtrip_nested_dirs() {
        let mut enc = CramfsEncoder::new();
        enc.add_dir("dir1");
        enc.add_file("dir1/file.txt", b"shallow");
        enc.add_dir("dir1/sub");
        enc.add_file("dir1/sub/deep.txt", b"deep contents!");
        enc.add_file("top.txt", b"top");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 5);
        let find = |p: &str| dec.entries.iter().find(|e| e.name() == p).unwrap();
        assert_eq!(find("dir1").kind, CramfsKind::Directory);
        assert_eq!(find("dir1/sub").kind, CramfsKind::Directory);
        assert_eq!(find("dir1/file.txt").data(), b"shallow");
        assert_eq!(find("dir1/sub/deep.txt").data(), b"deep contents!");
        assert_eq!(find("top.txt").data(), b"top");
        // sorted order: dir children are contiguous inode runs
        assert_eq!(dec.entries[0].name, "dir1");
    }

    #[test]
    fn roundtrip_symlink() {
        let mut enc = CramfsEncoder::new();
        enc.add_file("dir/t.txt", b"payload");
        enc.add_symlink("link", "dir/t.txt");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        let link = dec.entries.iter().find(|e| e.name() == "link").unwrap();
        assert_eq!(link.kind, CramfsKind::Symlink);
        assert_eq!(link.data(), b"dir/t.txt");
    }

    #[test]
    fn roundtrip_multiblock_file() {
        let data: Vec<u8> = (0..10000u32).map(|i| (i % 253) as u8).collect();
        let mut enc = CramfsEncoder::new();
        enc.add_file("big.bin", &data);
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries[0].data(), &data[..]);
    }

    #[test]
    fn roundtrip_options_and_implicit_parents() {
        let mut enc = CramfsEncoder::new();
        enc.add_file_with_options(
            "a/b/c.txt",
            b"nested",
            &CramfsEntryOptions {
                mode: 0o600,
                uid: 1000,
                gid: 42,
            },
        );
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 3);
        let f = dec
            .entries
            .iter()
            .find(|e| e.name() == "a/b/c.txt")
            .unwrap();
        assert_eq!(f.mode, S_IFREG | 0o600);
        assert_eq!(f.uid, 1000);
        assert_eq!(f.gid, 42);
        assert_eq!(f.data(), b"nested");
    }

    #[test]
    fn empty_image_decodes() {
        let img = CramfsEncoder::new().finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert!(dec.entries.is_empty());
        assert_eq!(dec.fsid_crc_ok, Some(true));
    }

    #[test]
    fn rejects_invalid_input() {
        // name too long (>252 bytes)
        let mut enc = CramfsEncoder::new();
        enc.add_file(&"x".repeat(253), b"d");
        assert!(enc.finish().is_err());
        // uid / gid field overflow
        let mut enc = CramfsEncoder::new();
        enc.add_file_with_options(
            "a",
            b"d",
            &CramfsEntryOptions {
                uid: 0x1_0000,
                ..Default::default()
            },
        );
        assert!(enc.finish().is_err());
        let mut enc = CramfsEncoder::new();
        enc.add_file_with_options(
            "a",
            b"d",
            &CramfsEntryOptions {
                gid: 0x100,
                ..Default::default()
            },
        );
        assert!(enc.finish().is_err());
        // file over the 24-bit size limit
        let mut enc = CramfsEncoder::new();
        enc.add_file("big", &alloc::vec![0u8; MAX_SIZE + 1]);
        assert!(enc.finish().is_err());
        // path conflicts and bad components
        let mut enc = CramfsEncoder::new();
        enc.add_file("a", b"d");
        enc.add_file("a/b", b"d");
        assert!(enc.finish().is_err());
        let mut enc = CramfsEncoder::new();
        enc.add_file("x//y", b"d");
        assert!(enc.finish().is_err());
        let mut enc = CramfsEncoder::new();
        enc.add_file("", b"d");
        assert!(enc.finish().is_err());
        // nesting beyond the decoder depth limit
        let mut enc = CramfsEncoder::new();
        let deep = (0..70).map(|_| "d").collect::<Vec<_>>().join("/");
        enc.add_file(&deep, b"d");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn trait_encoder_roundtrip() {
        use crate::traits::ArchiveEncode;
        let mut enc = crate::archive::cramfs::CramfsArchiveEncoder::new();
        enc.add_file("x.txt", b"y");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries[0].data(), b"y");
    }
}
