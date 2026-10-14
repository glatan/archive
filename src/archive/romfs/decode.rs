//! romfs image decoding.
//!
//! Layout reference: `Documentation/filesystems/romfs.rst`
//! (snapshot in `docs/spec/sources/romfs.rst`). All multi-byte
//! values are big-endian; every file header begins on a 16-byte
//! boundary.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

pub(crate) const MAGIC: &[u8; 8] = b"-rom1fs-";
pub(crate) const ROMFH_SIZE: usize = 16;
pub(crate) const ALIGN: usize = 16;

pub(crate) const TYPE_HARDLINK: u32 = 0;
pub(crate) const TYPE_DIR: u32 = 1;
pub(crate) const TYPE_REG: u32 = 2;
pub(crate) const TYPE_SYMLINK: u32 = 3;
pub(crate) const TYPE_BLOCK: u32 = 4;
pub(crate) const TYPE_CHAR: u32 = 5;
pub(crate) const TYPE_SOCKET: u32 = 6;
pub(crate) const TYPE_FIFO: u32 = 7;

const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
const S_IFBLK: u16 = 0x6000;
const S_IFCHR: u16 = 0x2000;
const S_IFSOCK: u16 = 0xC000;
const S_IFIFO: u16 = 0x1000;

/// Entry kind for a romfs file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RomfsKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link; `data` holds the target bytes.
    Symlink,
    /// Hard link; resolved to the target's kind and data.
    Hardlink,
    /// Block / char device, socket, or fifo. The payload is the
    /// raw type nibble from the `next` field (4=block, 5=char,
    /// 6=socket, 7=fifo); device major/minor numbers for block/char
    /// entries are exposed via `RomfsEntry::dev`.
    Other(u32),
}

/// A decoded romfs entry. `name` is the full path relative to the
/// volume root (components joined with `/`).
#[derive(Debug, Clone)]
pub struct RomfsEntry {
    /// Full path without a leading slash.
    pub name: String,
    /// Entry kind.
    pub kind: RomfsKind,
    /// Unix mode (`st_mode` style: file type + permissions).
    /// romfs has no ownership/permission bits beyond the
    /// executable flag; world-readable 0o444 (+0o111 when the
    /// executable bit is set) is reported like the kernel does.
    pub mode: u16,
    /// File contents or symlink/hardlink target data; empty for
    /// directories and special files.
    pub data: Vec<u8>,
    /// Device `(major, minor)` pair decoded from `spec.info`;
    /// `Some` only for block and char devices (romfs.rst: 16/16
    /// bits major/minor). Socket/fifo `spec.info` is unused (MBZ)
    /// and stays `None`. Analogous to the iso9660 `dev_t` field.
    pub dev: Option<(u16, u16)>,
}

impl crate::traits::ArchiveEntry for RomfsEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decoded romfs image.
#[derive(Debug)]
pub struct RomfsImage {
    /// Volume name from the superblock (may be empty).
    pub name: String,
    /// Entries in header-chain order (depth-first by directory).
    pub entries: Vec<RomfsEntry>,
}

fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub(crate) fn align16(n: usize) -> usize {
    n.div_ceil(ALIGN) * ALIGN
}

/// AFFS-style checksum: sum of big-endian longwords. A tail of
/// fewer than 4 bytes is shifted into place (padded with zeros).
pub(crate) fn checksum(b: &[u8]) -> u32 {
    let mut sum = 0u32;
    for i in (0..b.len()).step_by(4) {
        let mut v = 0u32;
        for (j, &c) in b[i..(i + 4).min(b.len())].iter().enumerate() {
            v |= u32::from(c) << (24 - 8 * j);
        }
        sum = sum.wrapping_add(v);
    }
    sum
}

struct Hdr {
    /// Absolute offset of the next sibling header (0 = none).
    next: u32,
    ty: u32,
    exec: bool,
    spec: u32,
    size: u32,
    /// Offset and length of the name field.
    name_off: usize,
    name_len: usize,
    /// Offset of the data region (name padded to 16).
    data_off: usize,
}

fn parse_hdr(input: &[u8], off: usize) -> Result<Hdr, Error> {
    if !off.is_multiple_of(ALIGN) || input.len() < off + ROMFH_SIZE {
        return Err(Error::InvalidData("romfs unaligned/truncated header"));
    }
    let next = u32be(input, off);
    let spec = u32be(input, off + 4);
    let size = u32be(input, off + 8);
    // Name: NUL-terminated starting at off+16, padded to 16.
    let name_start = off + ROMFH_SIZE;
    let scan_end = (off + 512).min(input.len());
    let hay = &input[name_start..scan_end];
    let nlen = hay
        .iter()
        .position(|&c| c == 0)
        .ok_or(Error::InvalidData("romfs unterminated name"))?;
    let hdr = Hdr {
        next: next & !0xF,
        ty: next & 0x7,
        exec: next & 0x8 != 0,
        spec,
        size,
        name_off: name_start,
        name_len: nlen,
        data_off: name_start + align16(nlen + 1),
    };
    // Metadata checksum covers the 16-byte header plus the padded
    // name; the checksum field makes the longword sum zero.
    let meta_end = name_start + align16(nlen + 1);
    if meta_end <= input.len() && checksum(&input[off..meta_end]) != 0 {
        return Err(Error::InvalidData("romfs bad header checksum"));
    }
    Ok(hdr)
}

fn mode_for(ty: u32, exec: bool) -> u16 {
    let base = match ty {
        TYPE_DIR => S_IFDIR,
        TYPE_REG => S_IFREG,
        TYPE_SYMLINK => S_IFLNK,
        TYPE_BLOCK => S_IFBLK,
        TYPE_CHAR => S_IFCHR,
        TYPE_SOCKET => S_IFSOCK,
        TYPE_FIFO => S_IFIFO,
        _ => S_IFIFO,
    };
    // World-readable; +x everywhere when the exec bit is set
    // (romfs_modemap semantics).
    base | 0o444 | if exec { 0o111 } else { 0 }
}

/// `spec.info` is a 16/16-bit major/minor pair for block and char
/// devices (romfs.rst mapping table); it is unused (MBZ) for every
/// other type.
fn device_number(ty: u32, spec: u32) -> Option<(u16, u16)> {
    match ty {
        TYPE_BLOCK | TYPE_CHAR => Some(((spec >> 16) as u16, (spec & 0xFFFF) as u16)),
        _ => None,
    }
}

struct Image<'a> {
    input: &'a [u8],
    end: usize,
}

impl<'a> Image<'a> {
    fn hdr(&self, off: u32) -> Result<Hdr, Error> {
        if off as usize >= self.end {
            return Err(Error::InvalidData("romfs header out of range"));
        }
        parse_hdr(&self.input[..self.end], off as usize)
    }

    fn name(&self, h: &Hdr) -> String {
        String::from_utf8_lossy(&self.input[h.name_off..h.name_off + h.name_len]).into_owned()
    }

    fn data(&self, h: &Hdr) -> Result<Vec<u8>, Error> {
        let size = h.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }
        self.input
            .get(h.data_off..h.data_off + size)
            .map(|s| s.to_vec())
            .ok_or(Error::UnexpectedEof)
    }

    /// Follow a directory child chain starting at `first`, emitting
    /// entries recursively. `visited` guards against header loops.
    fn walk(
        &self,
        mut off: u32,
        prefix: &str,
        out: &mut Vec<RomfsEntry>,
        visited: &mut BTreeSet<u32>,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > 128 {
            return Err(Error::InvalidData("romfs nesting too deep"));
        }
        while off != 0 {
            if !visited.insert(off) {
                return Err(Error::InvalidData("romfs header cycle"));
            }
            let h = self.hdr(off)?;
            let name = self.name(&h);
            let next = h.next;
            if name == "." || name == ".." {
                off = next;
                continue;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                alloc::format!("{prefix}/{name}")
            };
            match h.ty {
                TYPE_DIR => {
                    out.push(RomfsEntry {
                        name: path.clone(),
                        kind: RomfsKind::Directory,
                        mode: mode_for(h.ty, h.exec),
                        data: Vec::new(),
                        dev: None,
                    });
                    self.walk(h.spec, &path, out, visited, depth + 1)?;
                }
                TYPE_HARDLINK => {
                    // spec = offset of the target header.
                    let t = self.hdr(h.spec)?;
                    let kind = match t.ty {
                        TYPE_REG => RomfsKind::File,
                        TYPE_SYMLINK => RomfsKind::Symlink,
                        TYPE_DIR => RomfsKind::Directory,
                        TYPE_HARDLINK => RomfsKind::Hardlink,
                        other => RomfsKind::Other(other),
                    };
                    let data = match t.ty {
                        TYPE_REG | TYPE_SYMLINK => self.data(&t)?,
                        _ => Vec::new(),
                    };
                    out.push(RomfsEntry {
                        name: path,
                        kind: RomfsKind::Hardlink,
                        mode: mode_for(t.ty, t.exec),
                        data: {
                            let _ = kind;
                            data
                        },
                        dev: device_number(t.ty, t.spec),
                    });
                }
                ty => {
                    let data = if ty == TYPE_REG || ty == TYPE_SYMLINK {
                        self.data(&h)?
                    } else {
                        Vec::new()
                    };
                    out.push(RomfsEntry {
                        name: path,
                        kind: match ty {
                            TYPE_REG => RomfsKind::File,
                            TYPE_SYMLINK => RomfsKind::Symlink,
                            other => RomfsKind::Other(other),
                        },
                        mode: mode_for(ty, h.exec),
                        data,
                        dev: device_number(ty, h.spec),
                    });
                }
            }
            off = next;
        }
        Ok(())
    }
}

/// Decode a romfs image.
pub fn decode(input: &[u8]) -> Result<RomfsImage, Error> {
    if input.len() < 16 || &input[..8] != MAGIC {
        return Err(Error::InvalidData("not a romfs image"));
    }
    let size = u32be(input, 8) as usize;
    if size > input.len() || size < 16 {
        return Err(Error::InvalidData("romfs bad size"));
    }
    // Superblock checksum: the checksum field is set so that the
    // longword sum of the first min(512, size) bytes is zero.
    let checked_len = size.min(512);
    if !checked_len.is_multiple_of(4) {
        return Err(Error::InvalidData("romfs unaligned size"));
    }
    let sum = checksum(&input[..checked_len]);
    if sum != 0 {
        return Err(Error::ChecksumMismatch {
            expected: 0,
            actual: sum,
        });
    }
    // Volume name: NUL-terminated, padded to 16.
    let vol_end = size.min(16 + 512);
    let nlen = input[16..vol_end]
        .iter()
        .position(|&c| c == 0)
        .ok_or(Error::InvalidData("romfs unterminated volume name"))?;
    let name = String::from_utf8_lossy(&input[16..16 + nlen]).into_owned();
    let first = 16 + align16(nlen + 1);
    if first >= size {
        // image with no file headers
        return Ok(RomfsImage {
            name,
            entries: Vec::new(),
        });
    }
    let img = Image { input, end: size };
    let mut entries = Vec::new();
    let mut visited = BTreeSet::new();
    // The first header is the root directory itself ("." pseudo entry
    // or a plain dir header). Its `next` chain enumerates top-level
    // entries? No: the first header at `first` is the root dir, whose
    // spec points to its children.
    let root = img.hdr(first as u32)?;
    if root.ty == TYPE_DIR {
        img.walk(root.spec, "", &mut entries, &mut visited, 0)?;
    } else {
        // Non-directory root: treat the header chain as the listing.
        img.walk(first as u32, "", &mut entries, &mut visited, 0)?;
    }
    Ok(RomfsImage { name, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;

    /// One fixture row for `build_typed`:
    /// (path, explicit type, exec, spec.info, data).
    type Row<'a> = (&'a str, Option<u32>, bool, u32, Option<&'a [u8]>);

    /// Build a romfs image. `files`: (path, exec, data); dirs passed
    /// as (path, false, None). Entries must be given so that each
    /// directory's children form a contiguous chain per genromfs
    /// conventions (we emit siblings in list order and fix `next`).
    fn build(entries: &[(&str, bool, Option<&[u8]>)]) -> Vec<u8> {
        let typed: Vec<Row<'_>> = entries
            .iter()
            .map(|&(p, exec, data)| (p, None, exec, 0, data))
            .collect();
        build_typed(&typed)
    }

    /// Like `build`, but a `None` type selects the dir/regular
    /// guess that `build` uses.
    fn build_typed(entries: &[Row<'_>]) -> Vec<u8> {
        use alloc::collections::BTreeMap;
        // Assign types: a path that is a prefix of another is a dir.
        let paths: Vec<&str> = entries.iter().map(|e| e.0).collect();
        let is_dir = |p: &str| {
            paths
                .iter()
                .any(|q| q.starts_with(p) && q.len() > p.len() && q.as_bytes()[p.len()] == b'/')
        };
        // Emit headers in depth-first order; each dir's children form
        // a sibling chain.
        struct Rec {
            name: String,
            ty: u32,
            exec: bool,
            spec: u32,
            size: u32,
            data: Vec<u8>,
            children: Vec<usize>,
        }
        // Build tree
        let mut idx_of: BTreeMap<String, usize> = BTreeMap::new();
        let mut recs: Vec<Rec> = Vec::new();
        for (p, ty, exec, spec, data) in entries.iter() {
            let ty = ty.unwrap_or_else(|| if is_dir(p) { TYPE_DIR } else { TYPE_REG });
            recs.push(Rec {
                name: p.rsplit('/').next().unwrap().to_string(),
                ty,
                exec: *exec,
                spec: *spec,
                size: data.map_or(0, |d| d.len() as u32),
                data: data.map_or_else(Vec::new, |d| d.to_vec()),
                children: Vec::new(),
            });
            idx_of.insert(p.to_string(), recs.len() - 1);
        }
        let mut roots = Vec::new();
        for (p, ..) in entries {
            match p.rfind('/') {
                Some(i) => {
                    let par = &p[..i];
                    let pi = *idx_of.get(par).unwrap();
                    recs[pi].children.push(*idx_of.get(*p).unwrap());
                }
                None => roots.push(*idx_of.get(*p).unwrap()),
            }
        }
        // Layout: volume name at 16 (empty), headers start at 32.
        // Emit order: all top-level entries first (one sibling
        // chain), then for each directory its children contiguously.
        let mut order: Vec<usize> = Vec::new();
        fn emit_subtree(i: usize, recs: &[Rec], order: &mut Vec<usize>) {
            order.extend_from_slice(&recs[i].children);
            for &c in &recs[i].children {
                if recs[c].ty == TYPE_DIR {
                    emit_subtree(c, recs, order);
                }
            }
        }
        order.extend_from_slice(&roots);
        for &r in &roots {
            if recs[r].ty == TYPE_DIR {
                emit_subtree(r, &recs, &mut order);
            }
        }
        // Header offsets
        let mut offs = vec![0usize; recs.len()];
        {
            let mut cur = 32usize;
            for &i in &order {
                offs[i] = cur;
                cur += ROMFH_SIZE + align16(recs[i].name.len() + 1);
                if recs[i].ty == TYPE_REG {
                    cur += recs[i].size as usize;
                    cur = align16(cur);
                }
            }
        }
        let mut next_of = vec![0u32; recs.len()];
        for r in &recs {
            for w in r.children.windows(2) {
                next_of[w[0]] = offs[w[1]] as u32;
            }
        }
        for w in roots.windows(2) {
            next_of[w[0]] = offs[w[1]] as u32;
        }
        // dir spec = first child header
        for r in recs.iter_mut() {
            if r.ty == TYPE_DIR {
                r.spec = r.children.first().map_or(0, |&c| offs[c] as u32);
            }
        }
        // Assemble
        let mut out = alloc::vec![0u8; 32];
        for &i in &order {
            let r = &recs[i];
            let off = offs[i];
            let mut namep = r.name.clone().into_bytes();
            namep.push(0);
            namep.resize(align16(namep.len()), 0);
            let meta_len = ROMFH_SIZE + namep.len();
            if out.len() < off + meta_len {
                out.resize(off + meta_len, 0);
            }
            let next_field = next_of[i] | (r.ty & 0x7) | if r.exec { 0x8 } else { 0 };
            out[off..off + 4].copy_from_slice(&next_field.to_be_bytes());
            out[off + 4..off + 8].copy_from_slice(&r.spec.to_be_bytes());
            out[off + 8..off + 12].copy_from_slice(&r.size.to_be_bytes());
            // checksum: sum over header+name+pad; fill after writing
            out[off + 12..off + 16].copy_from_slice(&0u32.to_be_bytes());
            out[off + 16..off + 16 + r.name.len()].copy_from_slice(r.name.as_bytes());
            // checksum field makes the longword sum of the region zero
            let ck = checksum(&out[off..off + meta_len]).wrapping_neg();
            out[off + 12..off + 16].copy_from_slice(&ck.to_be_bytes());
            let data_off = off + meta_len;
            if r.ty == TYPE_REG && r.size > 0 {
                let data = &recs[i].data;
                out.resize(align16(data_off + data.len()), 0);
                out[data_off..data_off + data.len()].copy_from_slice(data);
            }
        }
        // pad to 1024
        let total = align16(out.len());
        out.resize(total.div_ceil(1024) * 1024, 0);
        // superblock
        out[..8].copy_from_slice(MAGIC);
        let total_len = out.len() as u32;
        out[8..12].copy_from_slice(&total_len.to_be_bytes());
        out[12..16].copy_from_slice(&0u32.to_be_bytes());
        let cksum_len = out.len().min(512);
        let ck = checksum(&out[..cksum_len]).wrapping_neg();
        out[12..16].copy_from_slice(&ck.to_be_bytes());
        out
    }

    #[test]
    fn decodes_flat_and_nested() {
        let f = build(&[
            ("hello.txt", false, Some(b"hello romfs")),
            ("dir1", false, None),
            ("dir1/inner.txt", false, Some(b"inner data")),
        ]);
        let img = decode(&f).unwrap();
        assert_eq!(img.entries.len(), 3);
        assert_eq!(img.entries[0].name(), "hello.txt");
        assert_eq!(img.entries[0].data(), b"hello romfs");
        assert_eq!(img.entries[1].kind, RomfsKind::Directory);
        assert_eq!(img.entries[2].name(), "dir1/inner.txt");
        assert_eq!(img.entries[2].data(), b"inner data");
    }

    #[test]
    fn decodes_genromfs_fixture() {
        let f = include_bytes!("../../../tests/fixtures/romfs/genromfs.romfs");
        let img = decode(&f[..]).unwrap();
        assert_eq!(img.name, "testvol");
        let find = |p: &str| {
            img.entries
                .iter()
                .find(|e| e.name() == p)
                .unwrap_or_else(|| panic!("missing {p}"))
        };
        assert_eq!(find("hello.txt").data(), b"hello romfs");
        assert_eq!(find("dir1/file.bin").data(), b"nested");
        assert_eq!(find("dir1/sub/big.dat").data().len(), 5000);
        assert_eq!(find("symlink").kind, RomfsKind::Symlink);
        assert_eq!(find("symlink").data(), b"dir1/file.bin");
        // hardlink.txt resolves to hello.txt's data
        assert_eq!(find("hardlink.txt").kind, RomfsKind::Hardlink);
        assert_eq!(find("hardlink.txt").data(), b"hello romfs");
        // exec.sh carries the executable bit
        assert_ne!(find("exec.sh").mode & 0o111, 0);
        assert_eq!(find("hello.txt").mode & 0o111, 0);
    }

    /// spec.info for block/char devices is a 16/16-bit major/minor
    /// pair (romfs.rst mapping table).
    #[test]
    fn exposes_device_major_minor() {
        let f = build_typed(&[
            // Leading non-dir entry: the first header doubles as
            // the volume root, which decode does not surface.
            ("top.txt", None, false, 0, Some(b"x")),
            ("dev", None, false, 0, None),
            ("dev/console", Some(TYPE_CHAR), false, (5 << 16) | 1, None),
            ("dev/sda", Some(TYPE_BLOCK), false, (8 << 16) | 16, None),
        ]);
        let img = decode(&f).unwrap();
        let find = |p: &str| img.entries.iter().find(|e| e.name == p).unwrap();
        let console = find("dev/console");
        assert_eq!(console.kind, RomfsKind::Other(TYPE_CHAR));
        assert_eq!(console.dev, Some((5, 1)));
        assert_eq!(console.mode & S_IFCHR, S_IFCHR);
        let sda = find("dev/sda");
        assert_eq!(sda.kind, RomfsKind::Other(TYPE_BLOCK));
        assert_eq!(sda.dev, Some((8, 16)));
        assert_eq!(find("dev").dev, None);
    }

    /// spec.info is unused (MBZ) for socket/fifo: never a device
    /// number even when nonzero.
    #[test]
    fn socket_fifo_have_no_device() {
        let f = build_typed(&[
            ("sock", Some(TYPE_SOCKET), false, 0x1234, None),
            ("pipe", Some(TYPE_FIFO), false, 0x5678, None),
            ("plain.txt", None, false, 0, Some(b"x")),
        ]);
        let img = decode(&f).unwrap();
        let find = |p: &str| img.entries.iter().find(|e| e.name == p).unwrap();
        assert_eq!(find("sock").kind, RomfsKind::Other(TYPE_SOCKET));
        assert_eq!(find("sock").dev, None);
        assert_eq!(find("pipe").kind, RomfsKind::Other(TYPE_FIFO));
        assert_eq!(find("pipe").dev, None);
        assert_eq!(find("plain.txt").dev, None);
    }

    /// Rewrite the `next` field of the header at `off` and repair
    /// both the header and superblock checksums so the corruption
    /// under test is only the pointer value itself.
    fn patch_next(f: &mut [u8], off: usize, next: u32) {
        let old = u32be(f, off);
        f[off..off + 4].copy_from_slice(&((old & 0xF) | (next & !0xF)).to_be_bytes());
        // header checksum
        f[off + 12..off + 16].copy_from_slice(&0u32.to_be_bytes());
        let ne = f[off + 16..].iter().position(|&c| c == 0).unwrap();
        let meta = ROMFH_SIZE + align16(ne + 1);
        let ck = checksum(&f[off..off + meta]).wrapping_neg();
        f[off + 12..off + 16].copy_from_slice(&ck.to_be_bytes());
        // superblock checksum over first min(512, size)
        f[12..16].copy_from_slice(&0u32.to_be_bytes());
        let len = (u32be(f, 8) as usize).min(512);
        let ck = checksum(&f[..len]).wrapping_neg();
        f[12..16].copy_from_slice(&ck.to_be_bytes());
    }

    #[test]
    fn rejects_header_cycle_and_oob() {
        // sibling chain pointing at itself -> cycle detection
        let mut f = build(&[("a.txt", false, Some(b"x"))]);
        patch_next(&mut f, 32, 32);
        assert!(decode(&f).is_err());
        // sibling chain pointing past the image end
        let mut f2 = build(&[("a.txt", false, Some(b"x"))]);
        patch_next(&mut f2, 32, 8192);
        assert!(decode(&f2).is_err());
    }

    #[test]
    fn rejects_bad_magic_and_checksum() {
        let mut f = build(&[("a.txt", false, Some(b"x"))]);
        f[0] = b'x';
        assert!(decode(&f).is_err());
        let mut f2 = build(&[("a.txt", false, Some(b"x"))]);
        f2[20] ^= 0xFF; // breaks superblock checksum
        assert!(decode(&f2).is_err());
    }

    #[test]
    fn truncated_at_every_position() {
        // The superblock `size` field must be ≤ the input length, so
        // every proper prefix of a valid image fails.
        let f = build(&[
            ("a.txt", false, Some(b"romfs truncation sweep")),
            ("dir", true, None),
            ("dir/b.bin", false, Some(&[1u8, 2, 3])),
        ]);
        for cut in 1..f.len() {
            assert!(decode(&f[..cut]).is_err(), "cut={cut} must not decode");
        }
    }
}
