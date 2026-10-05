//! ISO 9660 (ECMA-119) image encoding.
//!
//! Writes a primary-volume image: the zeroed 16-sector System Area,
//! a Primary Volume Descriptor, a terminator descriptor, the type-L
//! (little-endian) and type-M (big-endian) path tables (ECMA-119
//! §9.4), then directory and file extents. Directory extents carry
//! `.`/`..` records followed by children sorted by file identifier
//! (§9.3); records never cross a logical-block boundary (§9.1.13)
//! and all multi-byte fields are written both-endian (§7.3.3), so
//! the output passes every consistency check the decoder enforces.
//!
//! File identifiers are mangled to ISO9660 d-characters
//! (`A-Z`, `0-9`, `_`), uppercased and suffixed with `;1` for files:
//! level 1 truncates to the 8.3 form, level 2 (the default) allows
//! name plus extension up to 30 characters (§7.5). Collisions after
//! mangling are disambiguated with decimal digits. With
//! `with_rock_ridge` each record additionally carries
//! SUSP (`SP`/`ER` on the root `.` record) and RRIP 1.12 `PX`, `NM`,
//! `TF` and `SL` system use entries, preserving the original names,
//! modes, modification times and symlink targets. Joliet
//! supplementary volumes, El Torito, multi-extent files and
//! interleaved recording are not emitted.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

const SECTOR: usize = 2048;
/// Primary volume descriptor LBN, after the 16-sector System Area.
const VD_LBN: usize = 16;
const FLAG_DIR: u8 = 0x02;
/// Matches the decoder's directory walk limit.
const MAX_DEPTH: usize = 64;
/// `LEN_DR` is a single byte (ECMA-119 §9.1.1).
const MAX_REC: usize = 255;
/// Chunking budget for `NM`/`SL` records so one directory record
/// stays within `MAX_REC` after `PX`/`TF` are added.
const SU_CHUNK: usize = 180;

/// Payload queued for one image entry.
#[derive(Debug)]
enum NodeData {
    /// Regular file bytes.
    File(Vec<u8>),
    /// Directory; children are assembled in `finish`.
    Directory,
    /// Symlink target bytes (Rock Ridge `SL` only).
    Symlink(Vec<u8>),
}

#[derive(Debug)]
struct Queued {
    /// Full path relative to the volume root, `/`-separated.
    path: String,
    exec: bool,
    data: NodeData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
    Symlink,
}

/// Directory-tree node assembled at `finish`.
#[derive(Debug)]
struct Node {
    /// Last path component as added; `""` for the root.
    name: String,
    /// Mangled ISO9660 file identifier (`;1` suffix on files).
    iso: Vec<u8>,
    kind: Kind,
    exec: bool,
    /// Parent directory index; the root's parent is itself.
    parent: usize,
    children: Vec<usize>,
    /// File contents or symlink target; empty for directories.
    data: Vec<u8>,
    /// Rock Ridge system use bytes for this node's record in its
    /// parent directory (empty on a plain image).
    su: Vec<u8>,
    /// System use bytes for the directory's own `.` record.
    su_dot: Vec<u8>,
    /// System use bytes for the directory's `..` record.
    su_dd: Vec<u8>,
    /// Extent LBN and (for directories) allocated byte size.
    lbn: u32,
    size: u32,
    /// Rock Ridge `PX` file serial number.
    ino: u32,
}

/// Builder for ISO 9660 images.
///
/// Entries are queued with `add_*` methods and the image is
/// serialized by [`IsoEncoder::finish`]. Intermediate directories
/// are created implicitly. The default output is a plain primary
/// volume with level-2 (30-character) identifiers; use
/// [`IsoEncoder::with_level`] for strict 8.3 names and
/// [`IsoEncoder::with_rock_ridge()`] to add SUSP/Rock Ridge system
/// use fields that preserve POSIX names, modes and symlinks.
/// Recording timestamps default to the Unix epoch for
/// reproducible images; [`IsoEncoder::with_mtime`] overrides them.
///
/// # Examples
///
/// ```
/// use archive::archive::iso9660::{decode, encode};
///
/// let mut enc = encode::IsoEncoder::new().with_volume_name("myvol");
/// enc.add_file("hello.txt", b"hi");
/// enc.add_directory("sub");
/// let img = enc.finish().unwrap();
/// let out = decode::decode(&img).unwrap();
/// assert_eq!(out.volume_id, "MYVOL");
/// assert_eq!(out.entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct IsoEncoder {
    volume: String,
    /// Interchange level: 1 (8.3) or 2 (30-character identifiers).
    level: u8,
    /// Emit SUSP/Rock Ridge system use fields.
    rock_ridge: bool,
    /// Recording time for all entries and the volume, Unix seconds.
    mtime: i64,
    entries: Vec<Queued>,
}

impl Default for IsoEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl IsoEncoder {
    /// New encoder: plain ISO9660, level-2 identifiers, epoch mtime.
    pub const fn new() -> Self {
        Self {
            volume: String::new(),
            level: 2,
            rock_ridge: false,
            mtime: 0,
            entries: Vec::new(),
        }
    }

    /// Set the PVD volume identifier (mangled to ≤32 d-characters,
    /// space-padded; `CDROM` when empty).
    pub fn with_volume_name(mut self, name: &str) -> Self {
        self.volume = String::from(name);
        self
    }

    /// Set the interchange level: 1 for strict 8.3 identifiers,
    /// 2 for name+extension up to 30 characters (ECMA-119 §7.5).
    /// Other values are rejected by [`IsoEncoder::finish`].
    pub fn with_level(mut self, level: u8) -> Self {
        self.level = level;
        self
    }

    /// Emit SUSP (`SP`/`ER`) and Rock Ridge (`NM`/`PX`/`TF`/`SL`)
    /// system use fields, preserving original names, modes,
    /// timestamps and symlink targets. Required for symlinks.
    pub fn with_rock_ridge(mut self) -> Self {
        self.rock_ridge = true;
        self
    }

    /// Set the recording timestamp (Unix seconds) used for every
    /// directory record, Rock Ridge `TF` entry and the volume
    /// creation/modification/effective times.
    pub fn with_mtime(mut self, secs: i64) -> Self {
        self.mtime = secs;
        self
    }

    fn queue(&mut self, path: &str, exec: bool, data: NodeData) {
        self.entries.push(Queued {
            path: String::from(path),
            exec,
            data,
        });
    }

    /// Queue a regular file (Rock Ridge mode `0o100444`).
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.queue(path, false, NodeData::File(data.to_vec()));
    }

    /// Queue a regular file with the execute bits set
    /// (Rock Ridge mode `0o100555`).
    pub fn add_executable_file(&mut self, path: &str, data: &[u8]) {
        self.queue(path, true, NodeData::File(data.to_vec()));
    }

    /// Queue a directory. Missing parents are created implicitly.
    pub fn add_directory(&mut self, path: &str) {
        self.queue(path, true, NodeData::Directory);
    }

    /// Queue a symlink (`path` -> `target`). Rock Ridge output
    /// (`IsoEncoder::with_rock_ridge`) is required; plain images
    /// have no way to represent links and `finish` fails.
    pub fn add_symlink(&mut self, path: &str, target: &str) {
        self.queue(path, true, NodeData::Symlink(target.as_bytes().to_vec()));
    }

    /// Serialize the image.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] for an unsupported level, bad paths
    /// (empty, absolute, `.`/`..`/empty components, NUL bytes,
    /// nesting beyond 64, duplicates, children of non-directories),
    /// a symlink on a non-Rock-Ridge image, names or link targets
    /// too long for a directory record, or an image exceeding the
    /// 32-bit block fields.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.level != 1 && self.level != 2 {
            return Err(Error::InvalidData("iso9660 bad interchange level"));
        }
        let level = self.level;
        let dt7 = dir_time(self.mtime);

        // ---- assemble the directory tree ----
        let mut nodes: Vec<Node> = vec![Node {
            name: String::new(),
            iso: Vec::new(),
            kind: Kind::Dir,
            exec: true,
            parent: 0,
            children: Vec::new(),
            data: Vec::new(),
            su: Vec::new(),
            su_dot: Vec::new(),
            su_dd: Vec::new(),
            lbn: 0,
            size: 0,
            ino: 0,
        }];
        for q in &self.entries {
            let comps: Vec<&str> = q.path.split('/').collect();
            if comps.len() > MAX_DEPTH
                || comps
                    .iter()
                    .any(|c| c.is_empty() || *c == "." || *c == ".." || c.as_bytes().contains(&0))
            {
                return Err(Error::InvalidData("iso9660 bad path"));
            }
            let (kind, exec) = match &q.data {
                NodeData::File(_) => (Kind::File, q.exec),
                NodeData::Directory => (Kind::Dir, true),
                NodeData::Symlink(t) => {
                    if t.is_empty() {
                        return Err(Error::InvalidData("iso9660 empty symlink target"));
                    }
                    (Kind::Symlink, true)
                }
            };
            let data = match &q.data {
                NodeData::File(d) | NodeData::Symlink(d) => {
                    if d.len() > u32::MAX as usize {
                        return Err(Error::InvalidData("iso9660 file too large"));
                    }
                    d.clone()
                }
                NodeData::Directory => Vec::new(),
            };
            let mut parent = 0usize;
            for (ci, comp) in comps.iter().enumerate() {
                let existing = nodes[parent]
                    .children
                    .iter()
                    .copied()
                    .find(|&c| nodes[c].name == *comp);
                if ci + 1 == comps.len() {
                    match existing {
                        // Re-declaring an (implicit) directory is a no-op.
                        Some(e) if kind == Kind::Dir && nodes[e].kind == Kind::Dir => {}
                        Some(_) => return Err(Error::InvalidData("iso9660 duplicate path")),
                        None => {
                            let idx = nodes.len();
                            nodes.push(Node {
                                name: String::from(*comp),
                                iso: Vec::new(),
                                kind,
                                exec,
                                parent,
                                children: Vec::new(),
                                data: data.clone(),
                                su: Vec::new(),
                                su_dot: Vec::new(),
                                su_dd: Vec::new(),
                                lbn: 0,
                                size: 0,
                                ino: idx as u32,
                            });
                            nodes[parent].children.push(idx);
                        }
                    }
                } else {
                    parent = match existing {
                        Some(e) if nodes[e].kind == Kind::Dir => e,
                        Some(_) => {
                            return Err(Error::InvalidData("iso9660 path crosses non-directory"));
                        }
                        None => {
                            let idx = nodes.len();
                            nodes.push(Node {
                                name: String::from(*comp),
                                iso: Vec::new(),
                                kind: Kind::Dir,
                                exec: true,
                                parent,
                                children: Vec::new(),
                                data: Vec::new(),
                                su: Vec::new(),
                                su_dot: Vec::new(),
                                su_dd: Vec::new(),
                                lbn: 0,
                                size: 0,
                                ino: idx as u32,
                            });
                            nodes[parent].children.push(idx);
                            idx
                        }
                    };
                }
            }
        }
        if !self.rock_ridge && nodes.iter().any(|n| n.kind == Kind::Symlink) {
            return Err(Error::InvalidData("iso9660 symlink needs rock ridge"));
        }

        // ---- ISO9660 identifiers, deduplicated per directory ----
        for d in 0..nodes.len() {
            if nodes[d].kind != Kind::Dir {
                continue;
            }
            let mut taken = BTreeSet::new();
            for c in nodes[d].children.clone() {
                let (id, stem_end) = iso_ident(&nodes[c].name, nodes[c].kind == Kind::Dir, level)?;
                nodes[c].iso = unique_ident(&mut taken, id, stem_end)?;
            }
            // ECMA-119 §9.3: children sorted by file identifier.
            let mut ch = nodes[d].children.clone();
            ch.sort_by(|&a, &b| nodes[a].iso.cmp(&nodes[b].iso));
            nodes[d].children = ch;
        }

        // ---- Rock Ridge system use fields ----
        if self.rock_ridge {
            for i in 0..nodes.len() {
                let n = &nodes[i];
                if n.kind != Kind::Dir {
                    continue;
                }
                let subs = n
                    .children
                    .iter()
                    .filter(|&&c| nodes[c].kind == Kind::Dir)
                    .count() as u32;
                let px_tf = [&su_px(0o040_555, 2 + subs, n.ino)[..], &su_tf(&dt7)[..]].concat();
                if i == 0 {
                    // Root "." carries the SUSP marker + extension
                    // reference ahead of the POSIX fields.
                    nodes[0].su_dot = [&su_sp()[..], &su_er()[..], &px_tf[..]].concat();
                } else {
                    nodes[i].su_dot = px_tf.clone();
                }
                nodes[i].su_dd = px_tf;
            }
            for i in 1..nodes.len() {
                let n = &nodes[i];
                let (mode, nlink) = match n.kind {
                    Kind::Dir => {
                        let subs = n
                            .children
                            .iter()
                            .filter(|&&c| nodes[c].kind == Kind::Dir)
                            .count() as u32;
                        (0o040_555, 2 + subs)
                    }
                    Kind::File if n.exec => (0o100_555, 1),
                    Kind::File => (0o100_444, 1),
                    Kind::Symlink => (0o120_777, 1),
                };
                let mut su = su_px(mode, nlink, n.ino).to_vec();
                su.extend_from_slice(&su_nm(n.name.as_bytes()));
                su.extend_from_slice(&su_tf(&dt7));
                if n.kind == Kind::Symlink {
                    su.extend_from_slice(&su_sl(&n.data)?);
                }
                if rec_len(n.iso.len(), su.len()) > MAX_REC {
                    return Err(Error::InvalidData("iso9660 name too long for record"));
                }
                nodes[i].su = su;
            }
        }

        // ---- directory sizes (records padded to block ends) ----
        for d in 0..nodes.len() {
            if nodes[d].kind != Kind::Dir {
                continue;
            }
            let mut used = 0usize;
            let put = |l: usize, used: &mut usize| {
                let rem = SECTOR - *used % SECTOR;
                if l > rem {
                    *used += rem;
                }
                *used += l;
            };
            put(rec_len(1, nodes[d].su_dot.len()), &mut used);
            put(rec_len(1, nodes[d].su_dd.len()), &mut used);
            for &c in &nodes[d].children {
                put(rec_len(nodes[c].iso.len(), nodes[c].su.len()), &mut used);
            }
            nodes[d].size = used.next_multiple_of(SECTOR) as u32;
        }

        // ---- path table order: BFS, parents before children ----
        let mut pt_order: Vec<usize> = vec![0];
        let mut pt_index = vec![0u32; nodes.len()];
        let mut i = 0;
        while i < pt_order.len() {
            let d = pt_order[i];
            for &c in &nodes[d].children {
                if nodes[c].kind == Kind::Dir {
                    pt_order.push(c);
                }
            }
            i += 1;
        }
        for (i, &d) in pt_order.iter().enumerate() {
            pt_index[d] = i as u32 + 1;
        }
        let pt_size: u32 = pt_order
            .iter()
            .map(|&d| {
                let idlen = if d == 0 { 1 } else { nodes[d].iso.len() };
                (8 + idlen + usize::from(idlen % 2 == 1)) as u32
            })
            .sum();

        // ---- LBN assignment ----
        let mut lbn = 18u32; // PVD @16, terminator @17
        let pt_blocks = (pt_size as usize).div_ceil(SECTOR);
        let pt_l = lbn;
        lbn = lbn
            .checked_add(pt_blocks as u32)
            .ok_or(Error::InvalidData("iso9660 image too large"))?;
        let pt_m = lbn;
        lbn = lbn
            .checked_add(pt_blocks as u32)
            .ok_or(Error::InvalidData("iso9660 image too large"))?;
        for &d in &pt_order {
            nodes[d].lbn = lbn;
            lbn = lbn
                .checked_add(nodes[d].size / SECTOR as u32)
                .ok_or(Error::InvalidData("iso9660 image too large"))?;
        }
        for n in nodes.iter_mut().skip(1) {
            match n.kind {
                Kind::File => {
                    n.lbn = lbn;
                    lbn = lbn
                        .checked_add(n.data.len().div_ceil(SECTOR) as u32)
                        .ok_or(Error::InvalidData("iso9660 image too large"))?;
                }
                // Symlink records get the libarchive unused-extent sentinel.
                Kind::Symlink => n.lbn = 0xFFFF_FFF0,
                Kind::Dir => {}
            }
        }
        let vol_blocks = lbn;

        // ---- serialize ----
        let mut img = vec![0u8; vol_blocks as usize * SECTOR];

        // Path tables (§9.4): same record order, LE vs BE fields.
        for (be, lbn0) in [(false, pt_l), (true, pt_m)] {
            let mut t = Vec::with_capacity(pt_size as usize);
            for &d in &pt_order {
                let id: &[u8] = if d == 0 { &[0] } else { &nodes[d].iso };
                t.push(id.len() as u8);
                t.push(0);
                t.extend_from_slice(&u32_bytes(nodes[d].lbn, be));
                let parent = pt_index[nodes[d].parent] as u16;
                t.extend_from_slice(&u16_bytes(parent, be));
                t.extend_from_slice(id);
                if id.len() % 2 == 1 {
                    t.push(0);
                }
            }
            img[lbn0 as usize * SECTOR..lbn0 as usize * SECTOR + t.len()].copy_from_slice(&t);
        }

        // Directory extents.
        for &d in &pt_order {
            let size = nodes[d].size as usize;
            let mut data = Vec::with_capacity(size);
            let put = |r: Vec<u8>, data: &mut Vec<u8>| {
                let rem = SECTOR - data.len() % SECTOR;
                if r.len() > rem {
                    data.resize(data.len() + rem, 0);
                }
                data.extend_from_slice(&r);
            };
            put(
                dirent(
                    nodes[d].lbn,
                    nodes[d].size,
                    FLAG_DIR,
                    &dt7,
                    &[0],
                    &nodes[d].su_dot,
                ),
                &mut data,
            );
            let p = nodes[d].parent;
            put(
                dirent(
                    nodes[p].lbn,
                    nodes[p].size,
                    FLAG_DIR,
                    &dt7,
                    &[1],
                    &nodes[d].su_dd,
                ),
                &mut data,
            );
            for &c in &nodes[d].children {
                let cn = &nodes[c];
                let (flags, csize) = match cn.kind {
                    Kind::Dir => (FLAG_DIR, cn.size),
                    Kind::File => (0, cn.data.len() as u32),
                    Kind::Symlink => (0, 0),
                };
                put(
                    dirent(cn.lbn, csize, flags, &dt7, &cn.iso, &cn.su),
                    &mut data,
                );
            }
            debug_assert!(data.len() <= size);
            data.resize(size, 0);
            img[nodes[d].lbn as usize * SECTOR..nodes[d].lbn as usize * SECTOR + size]
                .copy_from_slice(&data);
        }

        // File extents.
        for n in nodes.iter().skip(1) {
            if n.kind == Kind::File && !n.data.is_empty() {
                let off = n.lbn as usize * SECTOR;
                img[off..off + n.data.len()].copy_from_slice(&n.data);
            }
        }

        write_pvd(
            &mut img,
            &volume_id(&self.volume),
            vol_blocks,
            pt_size,
            pt_l,
            pt_m,
            &dirent(nodes[0].lbn, nodes[0].size, FLAG_DIR, &dt7, &[0], &[]),
            &vd_time(self.mtime),
        );

        // Volume descriptor terminator at sector 17.
        let t = (VD_LBN + 1) * SECTOR;
        img[t] = 255;
        img[t + 1..t + 6].copy_from_slice(b"CD001");
        img[t + 6] = 1;

        Ok(img)
    }
}

/// Serialize `entries` as `(path, data)` regular files into a plain
/// level-2 image; convenience wrapper for the common case.
///
/// # Errors
///
/// Propagates [`IsoEncoder::finish`] errors.
pub fn encode(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut enc = IsoEncoder::new();
    for (name, data) in entries {
        enc.add_file(name, data);
    }
    enc.finish()
}

/// ISO9660 d-character mapping (ECMA-119 Appendix): `A-Z`, `0-9`,
/// `_`; lowercase folds to upper, everything else becomes `_`.
fn dch(b: u8) -> u8 {
    match b {
        b'a'..=b'z' => b - 32,
        b'0'..=b'9' | b'A'..=b'Z' | b'_' => b,
        _ => b'_',
    }
}

/// Mangle a path component into an ISO9660 identifier, returning
/// the identifier and the byte length of its name (stem) part —
/// used to splice dedup digits before the extension/version.
fn iso_ident(name: &str, dir: bool, level: u8) -> Result<(Vec<u8>, usize), Error> {
    let raw = name.as_bytes();
    if dir {
        let mut id: Vec<u8> = raw.iter().map(|&b| dch(b)).collect();
        id.truncate(if level == 1 { 8 } else { 30 });
        let n = id.len();
        Ok((id, n))
    } else {
        let (stem, ext) = match raw.iter().rposition(|&b| b == b'.') {
            Some(i) => (&raw[..i], &raw[i + 1..]),
            None => (raw, &raw[..0]),
        };
        let mut s: Vec<u8> = stem.iter().map(|&b| dch(b)).collect();
        let mut e: Vec<u8> = ext.iter().map(|&b| dch(b)).collect();
        if s.is_empty() {
            s.push(b'_');
        }
        if level == 1 {
            s.truncate(8);
            e.truncate(3);
        } else {
            // Level 2: name + extension ≤ 30 chars (ECMA-119 §7.5.2).
            e.truncate(29);
            s.truncate(30 - e.len());
        }
        let stem_end = s.len();
        let mut id = s;
        if !e.is_empty() {
            id.push(b'.');
            id.extend_from_slice(&e);
        }
        id.extend_from_slice(b";1");
        Ok((id, stem_end))
    }
}

/// Insert `id` into the sibling set, splicing decimal digits into
/// the stem tail on collision (`NAME.EXT;1` -> `NAM1.EXT;1`).
fn unique_ident(
    taken: &mut BTreeSet<Vec<u8>>,
    id: Vec<u8>,
    stem_end: usize,
) -> Result<Vec<u8>, Error> {
    if taken.insert(id.clone()) {
        return Ok(id);
    }
    for i in 1u32..1000 {
        let d = i.to_string().into_bytes();
        if d.len() > stem_end {
            break;
        }
        let mut c = Vec::with_capacity(id.len());
        c.extend_from_slice(&id[..stem_end - d.len()]);
        c.extend_from_slice(&d);
        c.extend_from_slice(&id[stem_end..]);
        if taken.insert(c.clone()) {
            return Ok(c);
        }
    }
    Err(Error::InvalidData("iso9660 identifier collision"))
}

/// Directory record length for `id_len` + `su_len` (base 33 bytes
/// plus the System Use alignment pad, total kept even).
fn rec_len(id_len: usize, su_len: usize) -> usize {
    let l = 33 + id_len + usize::from(id_len.is_multiple_of(2)) + su_len;
    l + l % 2
}

/// One directory record (ECMA-119 §9.1): both-endian extent and
/// size, 7-byte recording time, padding byte after even-length
/// identifiers.
fn dirent(extent: u32, size: u32, flags: u8, dt: &[u8; 7], name: &[u8], su: &[u8]) -> Vec<u8> {
    let len = rec_len(name.len(), su.len());
    debug_assert!(len <= MAX_REC, "directory record overflow");
    let mut r = Vec::with_capacity(len);
    r.push(len as u8);
    r.push(0); // extended attribute length
    r.extend_from_slice(&extent.to_le_bytes());
    r.extend_from_slice(&extent.to_be_bytes());
    r.extend_from_slice(&size.to_le_bytes());
    r.extend_from_slice(&size.to_be_bytes());
    r.extend_from_slice(dt);
    r.push(flags);
    r.push(0); // file unit size
    r.push(0); // interleave gap
    r.extend_from_slice(&1u16.to_le_bytes());
    r.extend_from_slice(&1u16.to_be_bytes());
    r.push(name.len() as u8);
    r.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        r.push(0);
    }
    r.extend_from_slice(su);
    r.resize(len, 0);
    r
}

/// SUSP `SP` marker (SUSP §5.3): check bytes `0xBE 0xEF`, no skip.
fn su_sp() -> [u8; 7] {
    *b"SP\x07\x01\xbe\xef\x00"
}

/// SUSP `ER` extension reference declaring RRIP 1.12. The id field
/// carries `RRIP_1991A`; descriptor/source strings are kept short
/// so the root `.` record stays within the 255-byte limit.
fn su_er() -> Vec<u8> {
    const ID: &[u8] = b"RRIP_1991A";
    const DES: &[u8] = b"ROCK RIDGE INTERCHANGE PROTOCOL (RRIP 1.12)";
    const SRC: &[u8] = b"IEEE P1282";
    let mut v = Vec::with_capacity(8 + ID.len() + DES.len() + SRC.len());
    v.extend_from_slice(b"ER");
    v.push((8 + ID.len() + DES.len() + SRC.len()) as u8);
    v.push(1);
    v.push(ID.len() as u8);
    v.push(DES.len() as u8);
    v.push(SRC.len() as u8);
    v.push(1); // extension version
    v.extend_from_slice(ID);
    v.extend_from_slice(DES);
    v.extend_from_slice(SRC);
    v
}

/// RRIP `PX` entry: both-endian mode, link count, uid, gid and the
/// file serial number (RRIP 1.12 §4.1.1/§4.1.3).
fn su_px(mode: u32, nlink: u32, ino: u32) -> [u8; 44] {
    let mut v = [0u8; 44];
    v[0..2].copy_from_slice(b"PX");
    v[2] = 44;
    v[3] = 1;
    for (o, x) in [(4, mode), (12, nlink), (20, 0u32), (28, 0u32), (36, ino)] {
        v[o..o + 4].copy_from_slice(&x.to_le_bytes());
        v[o + 4..o + 8].copy_from_slice(&x.to_be_bytes());
    }
    v
}

/// RRIP `TF` entry carrying only the modify time (flags bit1) in
/// the 7-byte form (RRIP 1.12 §4.1.6).
fn su_tf(dt: &[u8; 7]) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[0..2].copy_from_slice(b"TF");
    v[2] = 12;
    v[3] = 1;
    v[4] = 0x02;
    v[5..12].copy_from_slice(dt);
    v
}

/// RRIP `NM` entries for `name`, chunked with the CONTINUE flag
/// (bit0) on all but the last record (RRIP 1.12 §4.1).
fn su_nm(name: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let mut rest = name;
    loop {
        let n = rest.len().min(SU_CHUNK);
        let last = n == rest.len();
        v.extend_from_slice(b"NM");
        v.push((5 + n) as u8);
        v.push(1);
        v.push(if last { 0 } else { 1 });
        v.extend_from_slice(&rest[..n]);
        if last {
            return v;
        }
        rest = &rest[n..];
    }
}

/// RRIP `SL` records for a symlink target (RRIP 1.12 §4.1.3).
/// Components are emitted as literal path bytes — including `.`
/// and `..`, which the decoder joins like any other component —
/// with a leading `/` encoded as the root component (flags bit3).
/// Components are never split (the decoder joins components with
/// `/` unconditionally); overly long ones are an error.
fn su_sl(target: &[u8]) -> Result<Vec<u8>, Error> {
    let mut comps: Vec<(u8, &[u8])> = Vec::new();
    let mut rest = target;
    if rest.first() == Some(&b'/') {
        comps.push((0x08, &[][..]));
        rest = &rest[1..];
    }
    for c in rest.split(|&b| b == b'/') {
        if !c.is_empty() {
            if c.len() > 250 {
                return Err(Error::InvalidData("iso9660 symlink component too long"));
            }
            comps.push((0, c));
        }
    }
    if comps.is_empty() {
        comps.push((0x08, &[][..]));
    }
    let mut v = Vec::new();
    let mut body: Vec<u8> = Vec::new();
    for (flags, c) in comps {
        if body.len() + 2 + c.len() > SU_CHUNK && !body.is_empty() {
            v.extend_from_slice(b"SL");
            v.push((5 + body.len()) as u8);
            v.push(1);
            v.push(1); // CONTINUE: another SL record follows
            v.extend_from_slice(&body);
            body.clear();
        }
        body.push(flags);
        body.push(c.len() as u8);
        body.extend_from_slice(c);
    }
    v.extend_from_slice(b"SL");
    v.push((5 + body.len()) as u8);
    v.push(1);
    v.push(0);
    v.extend_from_slice(&body);
    Ok(v)
}

fn u16_bytes(v: u16, be: bool) -> [u8; 2] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

fn u32_bytes(v: u32, be: bool) -> [u8; 4] {
    if be { v.to_be_bytes() } else { v.to_le_bytes() }
}

fn put_both16(d: &mut [u8], o: usize, v: u16) {
    d[o..o + 2].copy_from_slice(&v.to_le_bytes());
    d[o + 2..o + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_both32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
    d[o + 4..o + 8].copy_from_slice(&v.to_be_bytes());
}

/// Space-pad `s` into an a/d-character descriptor field.
fn astr(field: &mut [u8], s: &[u8]) {
    field.fill(b' ');
    let n = s.len().min(field.len());
    field[..n].copy_from_slice(&s[..n]);
}

/// Mangle the volume identifier to ≤32 d-characters (`CDROM` when
/// empty), like `mkisofs -V` does.
fn volume_id(name: &str) -> Vec<u8> {
    let mut v: Vec<u8> = name.as_bytes().iter().map(|&b| dch(b)).collect();
    v.truncate(32);
    if v.is_empty() {
        v.extend_from_slice(b"CDROM");
    }
    v
}

/// Unix seconds -> civil `(year, month, day, hour, min, sec)` in
/// UTC (Howard Hinnant's days-from-civil inverse).
fn civil(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, tod / 3600, tod / 60 % 60, tod % 60)
}

/// 7-byte directory record time (ECMA-119 §9.1.5): year since
/// 1900 (clamped to the representable range), GMT timezone 0.
fn dir_time(secs: i64) -> [u8; 7] {
    let (y, mo, d, h, mi, s) = civil(secs);
    let yr = y.clamp(1900, 2155) - 1900;
    [yr as u8, mo as u8, d as u8, h as u8, mi as u8, s as u8, 0]
}

fn put_num(buf: &mut [u8], mut v: u64) {
    for b in buf.iter_mut().rev() {
        *b = b'0' + (v % 10) as u8;
        v /= 10;
    }
}

/// 17-byte volume descriptor timestamp (ECMA-119 §8.4.26.1):
/// `YYYYMMDDHHMMSSCC` ASCII digits + timezone byte (GMT).
fn vd_time(secs: i64) -> [u8; 17] {
    let (y, mo, d, h, mi, s) = civil(secs);
    let mut t = [b'0'; 17];
    put_num(&mut t[0..4], y.clamp(0, 9999) as u64);
    put_num(&mut t[4..6], mo as u64);
    put_num(&mut t[6..8], d as u64);
    put_num(&mut t[8..10], h as u64);
    put_num(&mut t[10..12], mi as u64);
    put_num(&mut t[12..14], s as u64);
    // centiseconds and timezone stay 0 digits / GMT
    t[16] = 0;
    t
}

/// Write the Primary Volume Descriptor (ECMA-119 §8.4) at sector
/// 16. The expiration timestamp is left unspecified (all `0`
/// digits) like common producers do.
#[allow(clippy::too_many_arguments)]
fn write_pvd(
    img: &mut [u8],
    volume: &[u8],
    vol_blocks: u32,
    pt_size: u32,
    pt_l: u32,
    pt_m: u32,
    root: &[u8],
    dt17: &[u8; 17],
) {
    let s = VD_LBN * SECTOR;
    let d = &mut img[s..s + SECTOR];
    d[0] = 1;
    d[1..6].copy_from_slice(b"CD001");
    d[6] = 1;
    astr(&mut d[8..40], b"ARCHIVE");
    astr(&mut d[40..72], volume);
    put_both32(d, 80, vol_blocks);
    put_both16(d, 120, 1); // volume set size
    put_both16(d, 124, 1); // volume sequence number
    put_both16(d, 128, SECTOR as u16);
    put_both32(d, 132, pt_size);
    d[140..144].copy_from_slice(&pt_l.to_le_bytes());
    d[148..152].copy_from_slice(&pt_m.to_be_bytes());
    d[156..190].copy_from_slice(&root[..34]);
    astr(&mut d[190..318], b""); // volume set id
    astr(&mut d[318..446], b""); // publisher id
    astr(&mut d[446..574], b""); // data preparer id
    astr(&mut d[574..702], b"ARCHIVE"); // application id
    astr(&mut d[702..739], b""); // copyright file id
    astr(&mut d[739..776], b""); // abstract file id
    astr(&mut d[776..813], b""); // bibliographic file id
    d[813..830].copy_from_slice(dt17); // creation
    d[830..847].copy_from_slice(dt17); // modification
    d[847..864].copy_from_slice(b"0000000000000000\x00"); // expiration: unspecified
    d[864..881].copy_from_slice(dt17); // effective
    d[881] = 1; // file structure version
}

#[cfg(test)]
mod tests {
    use super::super::decode::{self, IsoImage, IsoKind};
    use super::*;
    use crate::traits::ArchiveEntry;

    fn find<'a>(img: &'a IsoImage, path: &str) -> &'a decode::IsoEntry {
        img.entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("missing {path}"))
    }

    #[test]
    fn roundtrip_plain_iso() {
        let mut enc = IsoEncoder::new().with_volume_name("testvol");
        enc.add_file("hello.txt", b"hello iso");
        enc.add_file("one.dat", b"DATA");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.volume_id, "TESTVOL");
        assert!(!dec.has_rock_ridge);
        assert!(!dec.has_joliet);
        let names: Vec<&str> = dec.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["HELLO.TXT", "ONE.DAT"]);
        assert_eq!(find(&dec, "HELLO.TXT").data(), b"hello iso");
        assert_eq!(find(&dec, "ONE.DAT").data(), b"DATA");
        assert_eq!(find(&dec, "HELLO.TXT").kind, IsoKind::File);
        assert_eq!(find(&dec, "HELLO.TXT").mode, 0o100444);
        // volume size recorded in the PVD matches the image length
        assert_eq!(dec.volume_blocks as usize * SECTOR, img.len());
    }

    #[test]
    fn roundtrip_nested() {
        let mut enc = IsoEncoder::new();
        enc.add_file("a/b/c/deep.txt", b"deep");
        enc.add_file("a/top.txt", b"top");
        enc.add_directory("empty");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(find(&dec, "A/B/C/DEEP.TXT").data(), b"deep");
        assert_eq!(find(&dec, "A/TOP.TXT").data(), b"top");
        assert_eq!(find(&dec, "A/B").kind, IsoKind::Directory);
        assert_eq!(find(&dec, "EMPTY").kind, IsoKind::Directory);
        // '.'/'..' never surface as entries
        assert!(
            dec.entries
                .iter()
                .all(|e| e.name() != "." && !e.name().ends_with("/."))
        );
        // path table covers every directory, root first
        assert_eq!(dec.path_table.len(), 5);
        assert_eq!(dec.path_table[0].name, [0]);
        assert_eq!(dec.path_table[0].parent, 1);
    }

    #[test]
    fn roundtrip_rockridge() {
        let mut enc = IsoEncoder::new()
            .with_volume_name("rr")
            .with_rock_ridge()
            .with_mtime(1_700_000_000);
        enc.add_file("hello.txt", b"hello rock ridge");
        enc.add_file("dir with space/mixed-Case.dat", b"xyz");
        enc.add_symlink("link.txt", "hello.txt");
        enc.add_symlink("abs", "/hello.txt");
        enc.add_executable_file("run.sh", b"#!/bin/sh\n");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.volume_id, "RR");
        assert!(dec.has_rock_ridge);
        // NM names preserve case/spaces the ISO identifier cannot
        assert_eq!(find(&dec, "hello.txt").data(), b"hello rock ridge");
        assert_eq!(find(&dec, "dir with space/mixed-Case.dat").data(), b"xyz");
        assert_eq!(find(&dec, "dir with space").kind, IsoKind::Directory);
        // SL targets round-trip through entry data
        let link = find(&dec, "link.txt");
        assert_eq!(link.kind, IsoKind::Symlink);
        assert_eq!(link.data(), b"hello.txt");
        assert_eq!(find(&dec, "abs").data(), b"/hello.txt");
        // PX modes carry file type + permissions
        assert_eq!(find(&dec, "hello.txt").mode, 0o100444);
        assert_eq!(find(&dec, "run.sh").mode, 0o100555);
        assert_eq!(link.mode & 0o170000, 0o120000);
        // TF modify time / volume timestamps carry with_mtime
        assert_eq!(find(&dec, "hello.txt").mtime, 1_700_000_000);
        assert_eq!(dec.meta.creation_time, Some(1_700_000_000));
        assert_eq!(dec.meta.expiration_time, None);
        // ER extension reference lands on the root "." record
        assert!(img.windows(10).any(|w| w == b"RRIP_1991A"));
    }

    #[test]
    fn identifier_levels_and_dedup() {
        // level 1: strict 8.3 + `;1`
        let mut enc = IsoEncoder::new().with_level(1);
        enc.add_file("longfilename.txt", b"a");
        enc.add_file("readme", b"b");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        let names: Vec<&str> = dec.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["LONGFILE.TXT", "README"]);

        // level 2 keeps longer identifiers
        let mut enc = IsoEncoder::new();
        enc.add_file("longfilename.txt", b"a");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries[0].name, "LONGFILENAME.TXT");

        // mangled-name collision is disambiguated with digits
        let mut enc = IsoEncoder::new();
        enc.add_file("a.txt", b"1");
        enc.add_file("A.TXT", b"2");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 2);
        assert_ne!(dec.entries[0].name, dec.entries[1].name);
        let mut datas: Vec<&[u8]> = dec.entries.iter().map(|e| e.data()).collect();
        datas.sort_unstable();
        assert_eq!(datas, [b"1".as_slice(), b"2".as_slice()]);
    }

    #[test]
    fn path_table_l_and_m() {
        let mut enc = IsoEncoder::new();
        enc.add_file("d1/f.txt", b"x");
        enc.add_file("d2/d3/g.txt", b"y");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        // decoder walks the type-L table: root + D1 + D2 + D3
        assert_eq!(dec.path_table.len(), 4);
        assert_eq!(dec.path_table[0].name, [0]);
        let names: Vec<&[u8]> = dec.path_table[1..]
            .iter()
            .map(|e| e.name.as_slice())
            .collect();
        assert_eq!(
            names,
            [b"D1".as_slice(), b"D2".as_slice(), b"D3".as_slice()]
        );
        assert_eq!(dec.path_table[2].parent, 1);
        assert_eq!(dec.path_table[3].parent, 3);
        // type-M table mirrors the same records big-endian
        let m_lbn = u32::from_be_bytes(
            img[16 * SECTOR + 148..16 * SECTOR + 152]
                .try_into()
                .unwrap(),
        ) as usize;
        let pt_size = u32::from_le_bytes(
            img[16 * SECTOR + 132..16 * SECTOR + 136]
                .try_into()
                .unwrap(),
        ) as usize;
        let m = &img[m_lbn * SECTOR..m_lbn * SECTOR + pt_size];
        let mut pos = 0;
        let mut m_names = Vec::new();
        while pos + 8 <= m.len() && m[pos] != 0 {
            let len = m[pos] as usize;
            m_names.push(m[pos + 8..pos + 8 + len].to_vec());
            pos += 8 + len + usize::from(len % 2 == 1);
        }
        assert_eq!(
            m_names,
            dec.path_table
                .iter()
                .map(|e| e.name.clone())
                .collect::<Vec<_>>()
        );
        // each table extent names a directory whose "." record
        // points back at the same extent
        for e in &dec.path_table {
            let rec = &img[e.extent as usize * SECTOR..];
            assert_eq!(u32::from_le_bytes(rec[2..6].try_into().unwrap()), e.extent);
            assert_eq!(rec[25] & 0x02, 0x02);
            assert_eq!(rec[32], 1);
        }
    }

    #[test]
    fn empty_and_edge_files() {
        // empty volume decodes cleanly
        let img = IsoEncoder::new().finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert!(dec.entries.is_empty());

        // empty + multi-sector files
        let mut enc = IsoEncoder::new();
        enc.add_file("empty.bin", b"");
        enc.add_file("big.bin", &vec![0xABu8; 5000]);
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(find(&dec, "EMPTY.BIN").data(), b"");
        let big = find(&dec, "BIG.BIN");
        assert_eq!(big.data.len(), 5000);
        assert!(big.data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn multi_block_directory() {
        // enough entries that the root dir record area spans two
        // logical blocks
        let mut enc = IsoEncoder::new();
        for i in 0..80 {
            enc.add_file(&alloc::format!("file-{i:03}.txt"), b"x");
        }
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries.len(), 80);
        assert!(dec.entries.iter().all(|e| e.data() == b"x"));
    }

    #[test]
    fn rejects_bad_input() {
        // bad paths
        for p in ["", "/abs", "a//b", "a/./b", "a/../b", ".", ".."] {
            let mut enc = IsoEncoder::new();
            enc.add_file(p, b"x");
            assert!(enc.finish().is_err(), "path {p:?} accepted");
        }
        // duplicate leaf
        let mut enc = IsoEncoder::new();
        enc.add_file("a.txt", b"1");
        enc.add_file("a.txt", b"2");
        assert!(enc.finish().is_err());
        // file shadowed by a directory is fine, the reverse is not
        let mut enc = IsoEncoder::new();
        enc.add_file("d", b"x");
        enc.add_file("d/f", b"y");
        assert!(enc.finish().is_err());
        // symlink needs rock ridge
        let mut enc = IsoEncoder::new();
        enc.add_symlink("l", "t");
        assert!(enc.finish().is_err());
        // unsupported level
        let mut enc = IsoEncoder::new().with_level(3);
        enc.add_file("a", b"x");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn rockridge_limits() {
        // NM too long for a 255-byte record
        let mut enc = IsoEncoder::new().with_rock_ridge();
        enc.add_file(&"n".repeat(300), b"x");
        assert!(enc.finish().is_err());
        // but a long name that still fits round-trips via NM
        let long = "n".repeat(120);
        let mut enc = IsoEncoder::new().with_rock_ridge();
        enc.add_file(&long, b"x");
        let img = enc.finish().unwrap();
        let dec = decode::decode(&img).unwrap();
        assert_eq!(dec.entries[0].name, long);
        // overlong symlink component rejected
        let mut enc = IsoEncoder::new().with_rock_ridge();
        enc.add_symlink("l", &"t".repeat(300));
        assert!(enc.finish().is_err());
    }
}
