//! cramfs image decoding.
//!
//! Layout references: `fs/cramfs/README` and
//! `include/uapi/linux/cramfs_fs.h` (Linux kernel sources, snapshots
//! in `docs/spec/sources/`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::zlib;
use crate::error::Error;

const MAGIC: u32 = 0x28cd_3d45;
const SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const BLKSIZE: usize = 4096;

const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

const FLAG_HOLES: u32 = 0x100;
const FLAG_WRONG_SIG: u32 = 0x200;
const FLAG_SHIFTED_ROOT: u32 = 0x400;
const FLAG_EXT_BLOCK_PTRS: u32 = 0x800;
const SUPPORTED_FLAGS: u32 =
    0xFF | FLAG_HOLES | FLAG_WRONG_SIG | FLAG_SHIFTED_ROOT | FLAG_EXT_BLOCK_PTRS;

const BLK_UNCOMPRESSED: u32 = 1 << 31;
const BLK_DIRECT_PTR: u32 = 1 << 30;
const BLK_FLAGS: u32 = BLK_UNCOMPRESSED | BLK_DIRECT_PTR;

/// Entry kind for a cramfs directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CramfsKind {
    /// Regular file; `data` holds decompressed contents.
    File,
    /// Directory; `data` is empty and `name` is a path prefix of
    /// later entries.
    Directory,
    /// Symbolic link; `data` holds the (decompressed) target bytes.
    Symlink,
    /// FIFO / socket / device node. `data` is empty.
    Other(u16),
}

/// A decoded cramfs entry. `name` is the full path relative to the
/// image root (components joined with `/`).
#[derive(Debug, Clone)]
pub struct CramfsEntry {
    /// Full path (`dir/sub/file`), without a leading slash.
    pub name: String,
    /// Entry kind.
    pub kind: CramfsKind,
    /// Unix mode bits (`st_mode`).
    pub mode: u16,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid (low 8 bits only, per format).
    pub gid: u32,
    /// File contents or symlink target; empty for other kinds.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for CramfsEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decoded cramfs image.
#[derive(Debug)]
pub struct CramfsImage {
    /// Volume name from the superblock (may be empty).
    pub name: String,
    /// Entries in directory traversal order (depth-first over paths).
    pub entries: Vec<CramfsEntry>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn lossy_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

struct Inode {
    mode: u16,
    uid: u16,
    size: u32,
    gid: u8,
    namelen: u8,
    offset: u32,
}

fn parse_inode(b: &[u8], o: usize) -> Result<Inode, Error> {
    if b.len() < o + 12 {
        return Err(Error::UnexpectedEof);
    }
    let w0 = u32le(b, o);
    let w1 = u32le(b, o + 4);
    let w2 = u32le(b, o + 8);
    Ok(Inode {
        mode: (w0 & 0xFFFF) as u16,
        uid: (w0 >> 16) as u16,
        size: w1 & 0xFF_FFFF,
        gid: (w1 >> 24) as u8,
        namelen: (w2 & 0x3F) as u8,
        offset: w2 >> 6,
    })
}

struct Image<'a> {
    input: &'a [u8],
    /// Absolute file offset of the superblock (0 or 512).
    base: usize,
    ext_block_ptrs: bool,
}

impl<'a> Image<'a> {
    /// Absolute offset of a cramfs "offset" field (stored /4).
    fn field_off(&self, offset: u32) -> Result<usize, Error> {
        self.base
            .checked_add(offset as usize * 4)
            .ok_or(Error::InvalidData("cramfs offset overflow"))
    }

    /// Read one inode + name at absolute position `pos`; returns the
    /// inode, name, and bytes consumed.
    fn read_dirent(&self, pos: usize) -> Result<(Inode, String, usize), Error> {
        let ino = parse_inode(self.input, pos)?;
        let name_start = pos + 12;
        let name_len = ino.namelen as usize * 4;
        let raw = self
            .input
            .get(name_start..name_start + name_len)
            .ok_or(Error::UnexpectedEof)?;
        Ok((ino, lossy_name(raw), 12 + name_len))
    }

    /// Decompress / extract a file or symlink body.
    fn file_data(&self, ino: &Inode) -> Result<Vec<u8>, Error> {
        let size = ino.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        if ino.offset == 0 {
            // A non-empty file without a data offset is corrupt
            // (holes still have a block-pointer array).
            return Err(Error::InvalidData("cramfs file with offset 0"));
        }
        let nblocks = size.div_ceil(BLKSIZE);
        let ptr_base = self.field_off(ino.offset)?;
        let ptrs_end = ptr_base + nblocks * 4;
        if self.input.len() < ptrs_end {
            return Err(Error::UnexpectedEof);
        }
        let mut out = Vec::with_capacity(size);
        // Block i starts where block i-1 ended; the first block
        // follows the pointer array.
        let mut blk_start = ptrs_end;
        for i in 0..nblocks {
            let ptr = u32le(self.input, ptr_base + i * 4);
            let want = (size - out.len()).min(BLKSIZE);
            if ptr == 0 {
                // hole: entire block is NUL bytes
                out.resize(out.len() + want, 0);
                continue;
            }
            if self.ext_block_ptrs && ptr & BLK_FLAGS != 0 {
                if ptr & BLK_DIRECT_PTR != 0 {
                    let start = self
                        .base
                        .checked_add(((ptr & !BLK_FLAGS) << 2) as usize)
                        .ok_or(Error::InvalidData("cramfs ptr overflow"))?;
                    if ptr & BLK_UNCOMPRESSED != 0 {
                        let raw = self
                            .input
                            .get(start..start + want)
                            .ok_or(Error::UnexpectedEof)?;
                        out.extend_from_slice(raw);
                    } else {
                        let clen = u16le(
                            self.input
                                .get(start..start + 2)
                                .ok_or(Error::UnexpectedEof)?,
                            0,
                        ) as usize;
                        let raw = self
                            .input
                            .get(start + 2..start + 2 + clen)
                            .ok_or(Error::UnexpectedEof)?;
                        out.extend_from_slice(&zlib::decode::decode_bounded(raw, want + BLKSIZE)?);
                    }
                    continue;
                }
                if ptr & BLK_UNCOMPRESSED != 0 {
                    // contiguous uncompressed block at blk_start
                    let raw = self
                        .input
                        .get(blk_start..blk_start + want)
                        .ok_or(Error::UnexpectedEof)?;
                    out.extend_from_slice(raw);
                    blk_start += want;
                    continue;
                }
            }
            let end = self
                .base
                .checked_add((ptr & !BLK_FLAGS) as usize)
                .ok_or(Error::InvalidData("cramfs ptr overflow"))?;
            if end < blk_start || end > self.input.len() {
                return Err(Error::UnexpectedEof);
            }
            let raw = &self.input[blk_start..end];
            out.extend_from_slice(&zlib::decode::decode_bounded(raw, want + BLKSIZE)?);
            blk_start = end;
        }
        out.truncate(size);
        if out.len() != size {
            return Err(Error::InvalidData("cramfs short file data"));
        }
        Ok(out)
    }

    /// Walk a directory inode region and emit entries recursively.
    fn walk_dir(
        &self,
        ino: &Inode,
        prefix: &str,
        out: &mut Vec<CramfsEntry>,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > 64 {
            return Err(Error::InvalidData("cramfs nesting too deep"));
        }
        let dir_start = self.field_off(ino.offset)?;
        let dir_end = dir_start
            .checked_add(ino.size as usize)
            .ok_or(Error::InvalidData("cramfs dir overflow"))?;
        if self.input.len() < dir_end {
            return Err(Error::UnexpectedEof);
        }
        let mut pos = dir_start;
        while pos < dir_end {
            let (child, name, used) = self.read_dirent(pos)?;
            if used == 0 || name.is_empty() {
                return Err(Error::InvalidData("cramfs empty dirent"));
            }
            pos += used;
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                alloc::format!("{prefix}/{name}")
            };
            let kind = child.mode & S_IFMT;
            let entry_kind = match kind {
                S_IFREG => CramfsKind::File,
                S_IFDIR => CramfsKind::Directory,
                S_IFLNK => CramfsKind::Symlink,
                other => CramfsKind::Other(other),
            };
            let data = match kind {
                S_IFREG | S_IFLNK => self.file_data(&child)?,
                _ => Vec::new(),
            };
            out.push(CramfsEntry {
                name: path.clone(),
                kind: entry_kind,
                mode: child.mode,
                uid: child.uid as u32,
                gid: child.gid as u32,
                data,
            });
            if kind == S_IFDIR && child.size > 0 {
                self.walk_dir(&child, &path, out, depth + 1)?;
            }
        }
        Ok(())
    }
}

/// Decode a little-endian cramfs image.
pub fn decode(input: &[u8]) -> Result<CramfsImage, Error> {
    // Superblock at offset 0, or 512 for shifted-root images.
    let base = if input.len() >= 76 && u32le(input, 0) == MAGIC {
        0
    } else if input.len() >= 512 + 76 && u32le(input, 512) == MAGIC {
        512
    } else {
        return Err(Error::InvalidData("not a cramfs image"));
    };
    let sb = &input[base..];
    if &sb[16..32] != SIGNATURE {
        return Err(Error::InvalidData("cramfs bad signature"));
    }
    let size = u32le(sb, 4) as usize;
    let flags = u32le(sb, 8);
    if flags & !SUPPORTED_FLAGS != 0 {
        return Err(Error::Unsupported("cramfs feature flags"));
    }
    if base + size > input.len() || size < 76 {
        return Err(Error::UnexpectedEof);
    }
    let root = parse_inode(sb, 64)?;
    if root.mode & S_IFMT != S_IFDIR {
        return Err(Error::InvalidData("cramfs root not a directory"));
    }
    let image = Image {
        input,
        base,
        ext_block_ptrs: flags & FLAG_EXT_BLOCK_PTRS != 0,
    };
    let mut entries = Vec::new();
    if root.size > 0 {
        image.walk_dir(&root, "", &mut entries, 0)?;
    }
    Ok(CramfsImage {
        name: lossy_name(&sb[48..64]),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;

    /// Build a little-endian cramfs image.
    /// : (path, mode, data). Entries are regrouped so each
    /// directory's children are contiguous (cramfs requirement).
    fn build(files: &[(&str, u16, &[u8])]) -> Vec<u8> {
        use alloc::collections::BTreeMap;

        let parents: Vec<String> = files
            .iter()
            .map(|(p, _, _)| match p.rfind('/') {
                Some(i) => p[..i].to_string(),
                None => String::new(),
            })
            .collect();
        // Group children by parent; emit groups in width-first order:
        // root children first, then each directory's children as the
        // directory is visited.
        let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, par) in parents.iter().enumerate() {
            groups.entry(par.clone()).or_default().push(i);
        }
        let mut order: Vec<usize> = Vec::new();
        let mut queue: alloc::collections::VecDeque<String> = alloc::collections::VecDeque::new();
        queue.push_back(String::new());
        while let Some(par) = queue.pop_front() {
            if let Some(kids) = groups.get(&par) {
                for &k in kids {
                    order.push(k);
                    if files[k].1 & S_IFMT == S_IFDIR {
                        queue.push_back(files[k].0.to_string());
                    }
                }
            }
        }
        assert_eq!(order.len(), files.len());

        // Inode records in emitted order.
        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut inode_pos: Vec<(u32, u32)> = Vec::new();
        for &i in &order {
            let (path, mode, content) = files[i];
            let name = path.rsplit('/').next().unwrap();
            let namelen = name.len().div_ceil(4);
            let is_leaf = mode & S_IFMT == S_IFREG || mode & S_IFMT == S_IFLNK;
            let size_field: u32 = if is_leaf { content.len() as u32 } else { 0 };
            let mut rec = Vec::new();
            rec.extend_from_slice(&(mode as u32).to_le_bytes()); // mode|uid
            rec.extend_from_slice(&(size_field & 0xFF_FFFF).to_le_bytes());
            rec.extend_from_slice(&(namelen as u32).to_le_bytes());
            let mut name_padded = name.as_bytes().to_vec();
            name_padded.resize(namelen * 4, 0);
            rec.extend_from_slice(&name_padded);
            records.push(rec);
            inode_pos.push((0, size_field));
        }
        // Inode byte offsets (records laid out sequentially at 76).
        let mut rec_off = Vec::new();
        {
            let mut cur = 76usize;
            for r in &records {
                rec_off.push(cur);
                cur += r.len();
            }
        }
        // Map emitted position -> files[] index for parent checks.
        // Directory sizes/offsets: children are the contiguous emitted
        // run matching the parent path.
        for (pos, &i) in order.iter().enumerate() {
            let (path, mode, _) = files[i];
            if mode & S_IFMT == S_IFDIR {
                let mut sz = 0usize;
                let mut first: Option<usize> = None;
                for (pos2, &j) in order.iter().enumerate() {
                    if parents[j] == path {
                        sz += records[pos2].len();
                        if first.is_none() {
                            first = Some(pos2);
                        }
                    }
                }
                inode_pos[pos].1 = sz as u32;
                if let Some(p2) = first {
                    inode_pos[pos].0 = (rec_off[p2] / 4) as u32;
                }
            }
        }
        // File data area follows the inode region (aligned to 4).
        let mut data_base = 76 + records.iter().map(|r| r.len()).sum::<usize>();
        while !data_base.is_multiple_of(4) {
            data_base += 1;
        }
        let mut data_area: Vec<u8> = Vec::new();
        for (pos, &i) in order.iter().enumerate() {
            let (_, mode, content) = files[i];
            let is_leaf = mode & S_IFMT == S_IFREG || mode & S_IFMT == S_IFLNK;
            if !is_leaf || content.is_empty() {
                continue;
            }
            let nblocks = content.len().div_ceil(BLKSIZE);
            let fdata_off = data_base + data_area.len();
            inode_pos[pos].0 = (fdata_off / 4) as u32;
            let mut ptrs = Vec::new();
            let mut blocks = Vec::new();
            let mut cur_end = fdata_off + nblocks * 4;
            for chunk in content.chunks(BLKSIZE) {
                let comp = crate::compress::zlib::encode::encode(chunk);
                cur_end += comp.len();
                ptrs.push(cur_end as u32);
                blocks.push(comp);
            }
            for p in ptrs {
                data_area.extend_from_slice(&p.to_le_bytes());
            }
            for b in blocks {
                data_area.extend_from_slice(&b);
            }
            while !data_area.len().is_multiple_of(4) {
                data_area.push(0);
            }
        }
        // Patch inode word2 = namelen | offset<<6, word1 = size|gid<<24.
        for (pos, rec) in records.iter_mut().enumerate() {
            let namelen = u32le(rec, 8) & 0x3F;
            let w2 = namelen | (inode_pos[pos].0 << 6);
            rec[8..12].copy_from_slice(&w2.to_le_bytes());
            let w1 = inode_pos[pos].1 & 0xFF_FFFF;
            rec[4..8].copy_from_slice(&w1.to_le_bytes());
        }
        let mut out = alloc::vec![0u8; 76];
        for r in &records {
            out.extend_from_slice(r);
        }
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(&data_area);
        // Superblock.
        let total = out.len() as u32;
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&total.to_le_bytes());
        out[8..12].copy_from_slice(&0u32.to_le_bytes());
        out[12..16].copy_from_slice(&0u32.to_le_bytes());
        out[16..32].copy_from_slice(SIGNATURE);
        out[40..44].copy_from_slice(&1u32.to_le_bytes());
        out[44..48].copy_from_slice(&(files.len() as u32).to_le_bytes());
        out[48..64].copy_from_slice(b"testfs          ");
        // Root inode: dir, size = root children region, offset = 76/4.
        let mut root_sz = 0usize;
        for &j in &order {
            if parents[j].is_empty() {
                break;
            }
            let _ = j;
        }
        for (pos, &j) in order.iter().enumerate() {
            if parents[j].is_empty() {
                root_sz += records[pos].len();
            }
        }
        let w0 = (S_IFDIR | 0o755) as u32;
        let w1 = (root_sz as u32) & 0xFF_FFFF;
        let w2 = (76u32 / 4) << 6;
        out[64..68].copy_from_slice(&w0.to_le_bytes());
        out[68..72].copy_from_slice(&w1.to_le_bytes());
        out[72..76].copy_from_slice(&w2.to_le_bytes());
        out
    }

    #[test]
    fn decodes_flat_files() {
        let f = build(&[
            ("a.txt", S_IFREG | 0o644, b"alpha"),
            ("b.txt", S_IFREG | 0o644, b"beta file contents"),
        ]);
        let img = decode(&f).unwrap();
        assert_eq!(img.entries.len(), 2);
        assert_eq!(img.entries[0].name(), "a.txt");
        assert_eq!(img.entries[0].data(), b"alpha");
        assert_eq!(img.entries[1].data(), b"beta file contents");
    }

    #[test]
    fn decodes_nested_dirs_and_symlink() {
        let f = build(&[
            ("dir1", S_IFDIR | 0o755, &[]),
            ("link", S_IFLNK | 0o777, b"dir1/sub/deep.txt"),
            ("dir1/sub", S_IFDIR | 0o755, &[]),
            ("dir1/file.txt", S_IFREG | 0o644, b"shallow"),
            ("dir1/sub/deep.txt", S_IFREG | 0o644, b"deep contents!"),
        ]);
        let img = decode(&f).unwrap();
        assert_eq!(img.entries.len(), 5);
        let deep = img
            .entries
            .iter()
            .find(|e| e.name() == "dir1/sub/deep.txt")
            .unwrap();
        assert_eq!(deep.data(), b"deep contents!");
        let link = img.entries.iter().find(|e| e.name() == "link").unwrap();
        assert_eq!(link.kind, CramfsKind::Symlink);
        assert_eq!(link.data(), b"dir1/sub/deep.txt");
    }

    #[test]
    fn decodes_multiblock_file() {
        let data: Vec<u8> = (0..10000u32).map(|i| (i % 253) as u8).collect();
        let f = build(&[("big.bin", S_IFREG | 0o644, &data)]);
        let img = decode(&f).unwrap();
        assert_eq!(img.entries[0].data(), &data[..]);
    }

    #[test]
    fn rejects_bad_magic_and_trailing_garbage() {
        let f = build(&[("a", S_IFREG | 0o644, b"x")]);
        let mut bad = f.clone();
        bad[0] = 0;
        assert!(decode(&bad).is_err());
        assert!(decode(&f[..f.len() / 2]).is_err());
    }

    #[test]
    fn decodes_shifted_root() {
        let inner = build(&[("s.txt", S_IFREG | 0o644, b"shifted")]);
        // place image at offset 512 (shifted root)
        let mut f = alloc::vec![0u8; 512];
        f.extend_from_slice(&inner);
        // set SHIFTED_ROOT flag
        let flags = u32le(&f, 512 + 8) | FLAG_SHIFTED_ROOT;
        f[512 + 8..512 + 12].copy_from_slice(&flags.to_le_bytes());
        let img = decode(&f).unwrap();
        assert_eq!(img.entries.len(), 1);
        assert_eq!(img.entries[0].data(), b"shifted");
    }
}
