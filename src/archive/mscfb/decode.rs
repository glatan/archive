//! MS-CFB ([MS-CFB] v20210625, sections 2.1-2.6) decoding.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::{key_cmp, sort_key};
use crate::error::Error;

const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
// const FATSECT: u32 = 0xFFFF_FFFD;
// const DIFSECT: u32 = 0xFFFF_FFFC;
const MAXREGSECT: u32 = 0xFFFF_FFFA;
const NOSTREAM: u32 = 0xFFFF_FFFF;
const MAXREGSID: u32 = 0xFFFF_FFFA;

/// Directory-entry metadata ([MS-CFB] 2.6.1): the object CLSID,
/// user-defined state bits, and the creation / modification
/// FILETIMEs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CfbEntryMeta {
    /// Object CLSID (16 raw bytes). Meaningful on the root storage
    /// (2.6.2) and storage objects; usually all-zero on streams.
    pub clsid: [u8; 16],
    /// User-defined state bits.
    pub state_bits: u32,
    /// Creation time as a Windows FILETIME (100-ns intervals since
    /// 1601-01-01 UTC); zero when unset.
    pub created: u64,
    /// Last modification time as a Windows FILETIME.
    pub modified: u64,
}

/// A decoded stream entry. `name` is the storage-joined path
/// (`"Storage1/Sub/Stream"`) with UTF-16 names decoded to UTF-8.
#[derive(Debug, Clone)]
pub struct CfbEntry {
    /// Entry path within the compound file (storages joined with '/').
    pub name: String,
    /// Stream contents.
    pub data: Vec<u8>,
    /// Directory-entry metadata (CLSID, state bits, FILETIMEs).
    pub meta: CfbEntryMeta,
}

impl crate::traits::ArchiveEntry for CfbEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64le(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

struct DirEntry {
    name: String,
    obj_type: u8,
    color: u8,
    left: u32,
    right: u32,
    child: u32,
    meta: CfbEntryMeta,
    start: u32,
    size: u64,
}

struct File<'a> {
    input: &'a [u8],
    sector_size: usize,
    major: u16,
    fat: Vec<u32>,
    mini_fat: Vec<u32>,
    mini_stream: Vec<u8>,
    cutoff: u32,
    entries: Vec<DirEntry>,
}

impl<'a> File<'a> {
    fn sector(&self, n: u32) -> Result<&'a [u8], Error> {
        if n > MAXREGSECT {
            return Err(Error::InvalidData("mscfb"));
        }
        let off = (n as usize + 1)
            .checked_mul(self.sector_size)
            .ok_or(Error::UnexpectedEof)?;
        self.input
            .get(off..off + self.sector_size)
            .ok_or(Error::UnexpectedEof)
    }

    /// Follow a regular-sector chain through the FAT.
    fn chain(&self, start: u32) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut cur = start;
        while cur != ENDOFCHAIN {
            if cur > MAXREGSECT || !seen.insert(cur) {
                return Err(Error::InvalidData("mscfb"));
            }
            out.extend_from_slice(self.sector(cur)?);
            cur = *self.fat.get(cur as usize).ok_or(Error::UnexpectedEof)?;
        }
        Ok(out)
    }

    /// Follow a mini-sector chain through the mini FAT.
    fn mini_chain(&self, start: u32) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut cur = start;
        while cur != ENDOFCHAIN {
            if cur > MAXREGSECT || !seen.insert(cur) {
                return Err(Error::InvalidData("mscfb"));
            }
            let off = cur as usize * 64;
            out.extend_from_slice(
                self.mini_stream
                    .get(off..off + 64)
                    .ok_or(Error::UnexpectedEof)?,
            );
            cur = *self
                .mini_fat
                .get(cur as usize)
                .ok_or(Error::UnexpectedEof)?;
        }
        Ok(out)
    }

    fn stream_data(&self, start: u32, size: u64) -> Result<Vec<u8>, Error> {
        if self.major == 3 && size > 0x8000_0000 {
            // [MS-CFB] 2.6.1: v3 stream sizes MUST be <= 2 GiB. The high
            // dword may be garbage in older files; only reject when the
            // interpreted size would exceed the limit.
            if size > u64::from(u32::MAX) {
                return Err(Error::InvalidData("mscfb"));
            }
        }
        let size = usize::try_from(size).map_err(|_| Error::InvalidData("mscfb"))?;
        if size == 0 {
            return Ok(Vec::new());
        }
        let raw = if size < self.cutoff as usize {
            self.mini_chain(start)?
        } else {
            self.chain(start)?
        };
        raw.get(..size)
            .map(|s| s.to_vec())
            .ok_or(Error::UnexpectedEof)
    }

    /// Depth-first enumeration of a storage's child red-black tree
    /// ([MS-CFB] 2.6.4). Visits left siblings, the node, then right
    /// siblings; returns (depth-name path pieces handled by caller).
    fn walk(
        &self,
        sid: u32,
        prefix: &str,
        out: &mut Vec<CfbEntry>,
        visited: &mut BTreeSet<u32>,
        depth: usize,
    ) -> Result<(), Error> {
        if sid == NOSTREAM {
            return Ok(());
        }
        if depth > self.entries.len() || !visited.insert(sid) {
            return Err(Error::InvalidData("mscfb"));
        }
        let e = self.entries.get(sid as usize).ok_or(Error::UnexpectedEof)?;
        self.walk(e.left, prefix, out, visited, depth + 1)?;
        match e.obj_type {
            0x01 => {
                // storage object: descend into its child tree
                let mut p = String::from(prefix);
                if !p.is_empty() {
                    p.push('/');
                }
                p.push_str(&e.name);
                self.walk(e.child, &p, out, visited, depth + 1)?;
            }
            0x02 => {
                let mut p = String::from(prefix);
                if !p.is_empty() {
                    p.push('/');
                }
                p.push_str(&e.name);
                let data = self.stream_data(e.start, e.size)?;
                out.push(CfbEntry {
                    name: p,
                    data,
                    meta: e.meta,
                });
            }
            _ => {}
        }
        self.walk(e.right, prefix, out, visited, depth + 1)
    }

    /// Descend one sibling red-black tree per the [MS-CFB] 2.6.4
    /// ordering looking for `key`; returns the matching stream ID.
    /// The descent is bounded by the entry count so a malformed
    /// (cyclic) tree cannot loop forever.
    fn find_sibling(&self, mut sid: u32, key: &[u16]) -> Result<Option<u32>, Error> {
        let mut steps = 0usize;
        while sid != NOSTREAM {
            if steps >= self.entries.len() {
                return Err(Error::InvalidData("mscfb"));
            }
            steps += 1;
            let e = self.entries.get(sid as usize).ok_or(Error::UnexpectedEof)?;
            sid = match key_cmp(key, &sort_key(&e.name)) {
                Ordering::Less => e.left,
                Ordering::Greater => e.right,
                Ordering::Equal => return Ok(Some(sid)),
            };
        }
        Ok(None)
    }

    /// Resolve a '/'-separated stream path by descending each
    /// storage's sibling red-black tree under the [MS-CFB] 2.6.4
    /// ordering. The returned entry carries the on-disk (canonically
    /// cased) name.
    fn lookup(&self, path: &str) -> Result<Option<CfbEntry>, Error> {
        let comps: Vec<&str> = path.split('/').collect();
        let mut sid = self.entries[0].child;
        let mut canon = String::new();
        for (i, c) in comps.iter().enumerate() {
            if c.is_empty() {
                return Ok(None);
            }
            let Some(node) = self.find_sibling(sid, &sort_key(c))? else {
                return Ok(None);
            };
            let e = &self.entries[node as usize];
            if !canon.is_empty() {
                canon.push('/');
            }
            canon.push_str(&e.name);
            if i + 1 == comps.len() {
                // The last component must name a stream object.
                return if e.obj_type == 0x02 {
                    Ok(Some(CfbEntry {
                        name: canon,
                        data: self.stream_data(e.start, e.size)?,
                        meta: e.meta,
                    }))
                } else {
                    Ok(None)
                };
            }
            // Intermediate components must name storage objects.
            if e.obj_type != 0x01 {
                return Ok(None);
            }
            sid = e.child;
        }
        Ok(None)
    }

    /// Enforce the directory-entry invariants that `walk` tolerates
    /// ([MS-CFB] 2.6.1/2.6.4): color flags are red or black only,
    /// sibling/child IDs follow the NOSTREAM conventions for their
    /// object type, and sibling names are unique within each storage.
    /// Used by `decode_strict`.
    fn validate_directory(&self) -> Result<(), Error> {
        for e in &self.entries {
            // 2.6.1 Color Flag: only 0x00 (red) or 0x01 (black).
            if e.color > 1 {
                return Err(Error::InvalidData("mscfb"));
            }
            // 2.6.1: sibling/child IDs are a REGSID (0..=MAXREGSID) or
            // NOSTREAM; values in between are not valid, and an SID
            // must identify an actual directory entry.
            for v in [e.left, e.right, e.child] {
                if v == NOSTREAM {
                    continue;
                }
                if v > MAXREGSID || v as usize >= self.entries.len() {
                    return Err(Error::InvalidData("mscfb"));
                }
            }
            match e.obj_type {
                // Unallocated entries are all-zero except the three
                // pointers, which must be NOSTREAM (2.6.1).
                0x00 if e.left != NOSTREAM || e.right != NOSTREAM || e.child != NOSTREAM => {
                    return Err(Error::InvalidData("mscfb"));
                }
                // Stream objects cannot have children (2.6.1).
                0x02 if e.child != NOSTREAM => {
                    return Err(Error::InvalidData("mscfb"));
                }
                // The root storage object has no siblings (2.6.4).
                0x05 if e.left != NOSTREAM || e.right != NOSTREAM => {
                    return Err(Error::InvalidData("mscfb"));
                }
                _ => {}
            }
        }
        let mut visited = BTreeSet::new();
        let mut names = BTreeSet::new();
        self.validate_level(self.entries[0].child, &mut names, &mut visited)
    }

    /// Check one red-black sibling level for unique names (2.6.4),
    /// recursing into the child trees of storage objects with a fresh
    /// name set per level.
    fn validate_level(
        &self,
        sid: u32,
        names: &mut BTreeSet<Vec<u16>>,
        visited: &mut BTreeSet<u32>,
    ) -> Result<(), Error> {
        if sid == NOSTREAM {
            return Ok(());
        }
        if !visited.insert(sid) {
            return Err(Error::InvalidData("mscfb"));
        }
        let e = self.entries.get(sid as usize).ok_or(Error::UnexpectedEof)?;
        self.validate_level(e.left, names, visited)?;
        // 2.6.4: sibling names must be unique under the sorting
        // relationship, which compares uppercased UTF-16 code units.
        if !names.insert(sort_key(&e.name)) {
            return Err(Error::InvalidData("mscfb"));
        }
        if e.obj_type == 0x01 {
            let mut sub = BTreeSet::new();
            self.validate_level(e.child, &mut sub, visited)?;
        }
        self.validate_level(e.right, names, visited)
    }
}

/// Parse the header, FAT chains, mini stream, and directory array of
/// a compound file into an in-memory [File].
fn parse(input: &[u8]) -> Result<File<'_>, Error> {
    if input.len() < 512 || input[..8] != SIGNATURE {
        return Err(Error::InvalidData("mscfb"));
    }
    let major = u16le(input, 26);
    if major != 3 && major != 4 {
        return Err(Error::InvalidData("mscfb"));
    }
    if u16le(input, 28) != 0xFFFE {
        return Err(Error::InvalidData("mscfb"));
    }
    let sector_shift = u16le(input, 30);
    let expected = if major == 3 { 9 } else { 12 };
    if sector_shift != expected || u16le(input, 32) != 0x0006 {
        return Err(Error::InvalidData("mscfb"));
    }
    let sector_size = 1usize << sector_shift;
    if input.len() < 512 + sector_size && major == 4 {
        return Err(Error::InvalidData("mscfb"));
    }

    // Header fields ([MS-CFB] 2.2).
    let num_dir_sectors = u32le(input, 40);
    let num_fat_sectors = u32le(input, 44) as usize;
    let first_dir_sector = u32le(input, 48);
    let cutoff = u32le(input, 56);
    if cutoff != 0x1000 {
        return Err(Error::InvalidData("mscfb"));
    }
    let first_minifat_sector = u32le(input, 60);
    let num_minifat_sectors = u32le(input, 64) as usize;
    let first_difat_sector = u32le(input, 68);
    let num_difat_sectors = u32le(input, 72) as usize;
    if major == 3 && num_dir_sectors != 0 {
        return Err(Error::InvalidData("mscfb"));
    }

    // DIFAT: 109 in-header entries, then chained DIFAT sectors (2.5).
    let mut difat: Vec<u32> = Vec::new();
    for i in 0..109 {
        let v = u32le(input, 76 + 4 * i);
        if v != FREESECT {
            difat.push(v);
        }
    }
    let mut cur = first_difat_sector;
    let mut seen = BTreeSet::new();
    let mut difat_sector_count = 0usize;
    while cur != ENDOFCHAIN && difat_sector_count < num_difat_sectors {
        if cur > MAXREGSECT || !seen.insert(cur) {
            return Err(Error::InvalidData("mscfb"));
        }
        // DIFAT sectors are regular sectors; read via raw offset since
        // the FAT is not built yet.
        let off = (cur as usize + 1)
            .checked_mul(sector_size)
            .ok_or(Error::UnexpectedEof)?;
        let sec = input
            .get(off..off + sector_size)
            .ok_or(Error::UnexpectedEof)?;
        for i in 0..(sector_size / 4 - 1) {
            let v = u32le(sec, 4 * i);
            if v != FREESECT {
                difat.push(v);
            }
        }
        cur = u32le(sec, sector_size - 4);
        difat_sector_count += 1;
    }
    // Assembled FAT must have at least num_fat_sectors entries; extra
    // DIFAT entries are tolerated (spec: count is authoritative).
    if difat.len() < num_fat_sectors {
        return Err(Error::InvalidData("mscfb"));
    }
    difat.truncate(num_fat_sectors.max(difat.len()));

    // Build FAT array.
    let mut fat: Vec<u32> = Vec::new();
    {
        let tmp = File {
            input,
            sector_size,
            major,
            fat: Vec::new(),
            mini_fat: Vec::new(),
            mini_stream: Vec::new(),
            cutoff,
            entries: Vec::new(),
        };
        for &sec_no in &difat {
            let sec = tmp.sector(sec_no)?;
            for i in 0..sector_size / 4 {
                fat.push(u32le(sec, 4 * i));
            }
        }
    }

    let mut file = File {
        input,
        sector_size,
        major,
        fat,
        mini_fat: Vec::new(),
        mini_stream: Vec::new(),
        cutoff,
        entries: Vec::new(),
    };

    // Mini FAT chain (2.4): num_minifat_sectors regular sectors.
    if num_minifat_sectors > 0 {
        let raw = file.chain(first_minifat_sector)?;
        if raw.len() < num_minifat_sectors * sector_size {
            return Err(Error::InvalidData("mscfb"));
        }
        for i in 0..num_minifat_sectors * sector_size / 4 {
            file.mini_fat.push(u32le(&raw, 4 * i));
        }
    }

    // Directory chain (2.6): 128-byte entries.
    if first_dir_sector == ENDOFCHAIN {
        return Err(Error::InvalidData("mscfb"));
    }
    let dir_raw = file.chain(first_dir_sector)?;
    if major == 4 && dir_raw.len() != num_dir_sectors as usize * sector_size {
        return Err(Error::InvalidData("mscfb"));
    }
    for off in (0..dir_raw.len()).step_by(128) {
        let e = &dir_raw[off..off + 128];
        let obj_type = e[66];
        if obj_type > 5 || obj_type == 3 || obj_type == 4 {
            return Err(Error::InvalidData("mscfb"));
        }
        // [MS-CFB] 2.6.3: for unallocated entries the name fields are
        // undefined, so the name is only decoded for allocated objects.
        let name = if obj_type != 0 {
            let name_len = u16le(e, 64) as usize;
            if !(2..=64).contains(&name_len) || !name_len.is_multiple_of(2) {
                return Err(Error::InvalidData("mscfb"));
            }
            if e[name_len - 2] != 0 || e[name_len - 1] != 0 {
                return Err(Error::InvalidData("mscfb"));
            }
            let units: Vec<u16> = (0..name_len / 2).map(|i| u16le(e, 2 * i)).collect();
            let units = if units.last() == Some(&0) {
                &units[..units.len() - 1]
            } else {
                &units[..]
            };
            String::from_utf16(units).map_err(|_| Error::InvalidData("mscfb"))?
        } else {
            String::new()
        };
        file.entries.push(DirEntry {
            name,
            obj_type,
            color: e[67],
            left: u32le(e, 68),
            right: u32le(e, 72),
            child: u32le(e, 76),
            meta: CfbEntryMeta {
                clsid: <[u8; 16]>::try_from(&e[80..96]).unwrap(),
                state_bits: u32le(e, 96),
                created: u64le(e, 100),
                modified: u64le(e, 108),
            },
            start: u32le(e, 116),
            size: u64le(e, 120),
        });
    }
    if file.entries.is_empty() || file.entries[0].obj_type != 0x05 {
        return Err(Error::InvalidData("mscfb"));
    }

    // Mini stream = root entry's regular-sector stream.
    let root = &file.entries[0];
    if root.size > 0 {
        let ms = file.chain(root.start)?;
        let want = usize::try_from(root.size).map_err(|_| Error::InvalidData("mscfb"))?;
        file.mini_stream = ms.get(..want).ok_or(Error::UnexpectedEof)?.to_vec();
    }

    Ok(file)
}

/// Emit the stream-entry list by walking the directory tree from
/// the root storage's child pointer.
fn emit(file: &File) -> Result<Vec<CfbEntry>, Error> {
    let mut out = Vec::new();
    let mut visited = BTreeSet::new();
    visited.insert(0);
    file.walk(file.entries[0].child, "", &mut out, &mut visited, 0)?;
    Ok(out)
}

/// Decode a compound file into a flat list of stream entries.
///
/// Storage objects contribute path components only; only stream
/// objects produce entries.
pub fn decode(input: &[u8]) -> Result<Vec<CfbEntry>, Error> {
    emit(&parse(input)?)
}

/// Strict variant of [`decode`]: additionally enforces the directory
/// invariants from [MS-CFB] 2.6.1/2.6.4 that [`decode`] tolerates for
/// compatibility with non-conforming files: red/black color flags,
/// NOSTREAM conventions for sibling/child IDs by object type, and
/// unique sibling names within each storage.
pub fn decode_strict(input: &[u8]) -> Result<Vec<CfbEntry>, Error> {
    let file = parse(input)?;
    file.validate_directory()?;
    emit(&file)
}

/// Return the root storage object's directory metadata
/// ([MS-CFB] 2.6.2). The root entry is not emitted by decode; its
/// CLSID identifies the compound file's content type.
pub fn root_meta(input: &[u8]) -> Result<CfbEntryMeta, Error> {
    Ok(parse(input)?.entries[0].meta)
}

/// Compare two '/'-joined entry paths component-wise under the
/// [MS-CFB] 2.6.4 sort rule (uppercased name length first, then
/// uppercased UTF-16 code unit values).
fn path_cmp(a: &str, b: &str) -> Ordering {
    let mut ai = a.split('/');
    let mut bi = b.split('/');
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) => match key_cmp(&sort_key(x), &sort_key(y)) {
                Ordering::Equal => {}
                ord => return ord,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Decode like [`decode`], then order the entries by the [MS-CFB]
/// 2.6.4 directory sort rule applied per path component: within a
/// storage, siblings compare by uppercased name length first and then
/// by uppercased UTF-16 code unit values, and a storage's subtree is
/// listed at the storage's sibling position. Unlike [`decode`], whose
/// order reflects the on-disk red-black tree, the result is ordered
/// even when the file's directory tree is not.
pub fn decode_sorted(input: &[u8]) -> Result<Vec<CfbEntry>, Error> {
    let mut entries = decode(input)?;
    entries.sort_by(|a, b| path_cmp(&a.name, &b.name));
    Ok(entries)
}

/// Look up a single stream by '/'-separated path and return its
/// entry, or `None` when no stream matches.
///
/// Component matching follows the [MS-CFB] 2.6.4 directory ordering:
/// names compare as uppercase-mapped UTF-16 code units, so the lookup
/// is case-insensitive (`"foo.TXT"` finds `"Foo.txt"`). Resolution
/// descends each storage's sibling red-black tree, so a file whose
/// directory trees do not follow the 2.6.4 sort order may fail to
/// resolve entries that [`decode`] still enumerates.
pub fn get_stream(input: &[u8], path: &str) -> Result<Option<CfbEntry>, Error> {
    parse(input)?.lookup(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;

    /// One directory entry in the test fixture.
    struct De<'a> {
        name: &'a str,
        ty: u8,
        left: u32,
        right: u32,
        child: u32,
        start: u32,
        size: u64,
    }

    /// Complete fixture description for `build_cfb`.
    struct Fx<'a> {
        entries: &'a [De<'a>],
        fat: &'a [u32],
        /// FAT sector numbers listed in the header DIFAT.
        difat: &'a [u32],
        mini_fat: &'a [u32],
        first_dir: u32,
        minifat_sector: u32,
        root_start: u32,
        root_size: u64,
        /// (sector number, content) pairs written into the image.
        sectors: &'a [(u32, &'a [u8])],
    }

    /// Build a minimal valid v3 CFB image from a fixture description.
    /// Layout is whatever `fat`/`sectors` describe; the header DIFAT
    /// lists `difat` and the first directory sector is `first_dir`.
    fn build_cfb(fx: &Fx) -> Vec<u8> {
        let num_minifat = if fx.mini_fat.is_empty() { 0 } else { 1 };
        let n_sectors = fx.sectors.iter().map(|(n, _)| *n).max().unwrap_or(0) + 1;
        let mut f = alloc::vec![0u8; 512 + (n_sectors as usize) * 512];
        f[..8].copy_from_slice(&SIGNATURE);
        f[26..28].copy_from_slice(&3u16.to_le_bytes()); // major v3
        f[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
        f[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector shift
        f[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini sector shift
        f[44..48].copy_from_slice(&(fx.difat.len() as u32).to_le_bytes());
        f[48..52].copy_from_slice(&fx.first_dir.to_le_bytes());
        f[56..60].copy_from_slice(&0x1000u32.to_le_bytes()); // cutoff
        f[60..64].copy_from_slice(&fx.minifat_sector.to_le_bytes());
        f[64..68].copy_from_slice(&(num_minifat as u32).to_le_bytes());
        f[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        f[72..76].copy_from_slice(&0u32.to_le_bytes());
        for (i, v) in fx.difat.iter().enumerate() {
            f[76 + 4 * i..80 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        for i in fx.difat.len()..109 {
            f[76 + 4 * i..80 + 4 * i].copy_from_slice(&FREESECT.to_le_bytes());
        }
        // sector payloads first, FAT/minifat/dir written after so the
        // fixture's FAT entries are not clobbered by data writes.
        for &(n, data) in fx.sectors {
            let off = 512 + n as usize * 512;
            f[off..off + data.len()].copy_from_slice(data);
        }
        for &sec_no in fx.difat {
            let off = 512 + sec_no as usize * 512;
            for (i, v) in fx.fat.iter().enumerate() {
                f[off + 4 * i..off + 4 * i + 4].copy_from_slice(&v.to_le_bytes());
            }
            for i in fx.fat.len()..128 {
                f[off + 4 * i..off + 4 * i + 4].copy_from_slice(&FREESECT.to_le_bytes());
            }
        }
        if num_minifat > 0 {
            let off = 512 + fx.minifat_sector as usize * 512;
            for (i, v) in fx.mini_fat.iter().enumerate() {
                f[off + 4 * i..off + 4 * i + 4].copy_from_slice(&v.to_le_bytes());
            }
            for i in fx.mini_fat.len()..128 {
                f[off + 4 * i..off + 4 * i + 4].copy_from_slice(&FREESECT.to_le_bytes());
            }
        }
        for (i, e) in fx.entries.iter().enumerate() {
            let dir_off = 512 + fx.first_dir as usize * 512 + i * 128;
            let mut name16: Vec<u16> = e.name.encode_utf16().collect();
            name16.push(0);
            for (j, u) in name16.iter().enumerate() {
                f[dir_off + 2 * j..dir_off + 2 * j + 2].copy_from_slice(&u.to_le_bytes());
            }
            f[dir_off + 64..dir_off + 66]
                .copy_from_slice(&((name16.len() * 2) as u16).to_le_bytes());
            f[dir_off + 66] = e.ty;
            f[dir_off + 67] = 1; // black
            f[dir_off + 68..dir_off + 72].copy_from_slice(&e.left.to_le_bytes());
            f[dir_off + 72..dir_off + 76].copy_from_slice(&e.right.to_le_bytes());
            f[dir_off + 76..dir_off + 80].copy_from_slice(&e.child.to_le_bytes());
            f[dir_off + 116..dir_off + 120].copy_from_slice(&e.start.to_le_bytes());
            f[dir_off + 120..dir_off + 128].copy_from_slice(&e.size.to_le_bytes());
        }
        // Remaining directory slots in the first directory sector are
        // unallocated entries: all zero except the sibling/child
        // pointers, which are initialized to NOSTREAM (2.6.1).
        for off in (fx.entries.len() * 128..512).step_by(128) {
            let base = 512 + fx.first_dir as usize * 512 + off;
            f[base + 68..base + 72].copy_from_slice(&NOSTREAM.to_le_bytes());
            f[base + 72..base + 76].copy_from_slice(&NOSTREAM.to_le_bytes());
            f[base + 76..base + 80].copy_from_slice(&NOSTREAM.to_le_bytes());
        }
        // root entry (index 0) start/size override
        let r = 512 + fx.first_dir as usize * 512;
        f[r + 116..r + 120].copy_from_slice(&fx.root_start.to_le_bytes());
        f[r + 120..r + 128].copy_from_slice(&fx.root_size.to_le_bytes());
        f
    }

    /// Regular-sector stream fixture: 5000 bytes chained over FAT.
    fn big_file() -> Vec<u8> {
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "BigStream",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 2,
                size: 5000,
            },
        ];
        let mut fat = vec![FREESECT; 13];
        fat[0] = 0xFFFF_FFFD; // FATSECT
        fat[1] = ENDOFCHAIN; // directory
        for (i, v) in fat.iter_mut().enumerate().take(11).skip(2) {
            *v = i as u32 + 1;
        }
        fat[11] = ENDOFCHAIN;
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut sectors: Vec<(u32, &[u8])> = Vec::new();
        for i in 0..10usize {
            sectors.push((2 + i as u32, &data[i * 512..(i * 512 + 512).min(5000)]));
        }
        build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &[],
            first_dir: 1,
            minifat_sector: ENDOFCHAIN,
            root_start: ENDOFCHAIN,
            root_size: 0,
            sectors: &sectors,
        })
    }

    /// Mini-stream fixture: a <4096-byte stream in mini sector 0.
    fn mini_file() -> Vec<u8> {
        static DATA: &[u8] = b"hello compound mini stream world";
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "MiniStream",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 0,
                size: 32,
            },
        ];
        let mut fat = vec![FREESECT; 5];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN; // dir
        fat[2] = ENDOFCHAIN; // minifat
        fat[4] = ENDOFCHAIN; // mini stream
        let mut minifat = vec![FREESECT; 128];
        minifat[0] = ENDOFCHAIN;
        let mut ministream = alloc::vec![0u8; 512];
        ministream[..DATA.len()].copy_from_slice(DATA);
        let mfsec = alloc::vec![0u8; 512];
        let sectors: &[(u32, &[u8])] = &[(4, &ministream), (2, &mfsec)];
        build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &minifat,
            first_dir: 1,
            minifat_sector: 2,
            root_start: 4,
            root_size: 512,
            sectors,
        })
    }

    #[test]
    fn decodes_regular_sector_stream() {
        let f = big_file();
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "BigStream");
        let expect: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(out[0].data(), &expect[..]);
    }

    #[test]
    fn decodes_mini_stream() {
        let f = mini_file();
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "MiniStream");
        assert_eq!(out[0].data(), b"hello compound mini stream world");
    }

    #[test]
    fn storage_children_get_path_prefix() {
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "Storage",
                ty: 1,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 2,
                start: 0,
                size: 0,
            },
            De {
                name: "Inner",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 0,
                size: 7,
            },
        ];
        let mut fat = vec![FREESECT; 4];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN;
        fat[2] = ENDOFCHAIN; // minifat
        fat[3] = ENDOFCHAIN; // mini stream
        let mut minifat = vec![FREESECT; 128];
        minifat[0] = ENDOFCHAIN;
        let mut ms = alloc::vec![0u8; 512];
        ms[..7].copy_from_slice(b"nested!");
        let mfsec = alloc::vec![0u8; 512];
        let sectors: &[(u32, &[u8])] = &[(3, &ms), (2, &mfsec)];
        let f = build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &minifat,
            first_dir: 1,
            minifat_sector: 2,
            root_start: 3,
            root_size: 512,
            sectors,
        });
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name(), "Storage/Inner");
        assert_eq!(out[0].data(), b"nested!");
    }

    #[test]
    fn sibling_chain_enumerates_all() {
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "A",
                ty: 2,
                left: NOSTREAM,
                right: 2,
                child: NOSTREAM,
                start: 0,
                size: 3,
            },
            De {
                name: "B",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 1,
                size: 3,
            },
        ];
        let mut fat = vec![FREESECT; 4];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN;
        fat[2] = ENDOFCHAIN; // minifat
        fat[3] = ENDOFCHAIN; // mini stream
        let mut minifat = vec![FREESECT; 128];
        minifat[0] = ENDOFCHAIN;
        minifat[1] = ENDOFCHAIN;
        let mut ms = alloc::vec![0u8; 512];
        ms[0..3].copy_from_slice(b"AAA");
        ms[64..67].copy_from_slice(b"BBB");
        let mfsec = alloc::vec![0u8; 512];
        let sectors: &[(u32, &[u8])] = &[(3, &ms), (2, &mfsec)];
        let f = build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &minifat,
            first_dir: 1,
            minifat_sector: 2,
            root_start: 3,
            root_size: 512,
            sectors,
        });
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name(), "A");
        assert_eq!(out[0].data(), b"AAA");
        assert_eq!(out[1].name(), "B");
        assert_eq!(out[1].data(), b"BBB");
    }

    #[test]
    fn exposes_stream_entry_metadata() {
        let mut f = mini_file();
        // directory sector 1, entry index 1
        let e = 512 + 512 + 128;
        let clsid: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        f[e + 80..e + 96].copy_from_slice(&clsid);
        f[e + 96..e + 100].copy_from_slice(&0xAABBCCDDu32.to_le_bytes());
        f[e + 100..e + 108].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        f[e + 108..e + 116].copy_from_slice(&0x1112131415161718u64.to_le_bytes());
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].meta.clsid, clsid);
        assert_eq!(out[0].meta.state_bits, 0xAABBCCDD);
        assert_eq!(out[0].meta.created, 0x0102030405060708);
        assert_eq!(out[0].meta.modified, 0x1112131415161718);
    }

    #[test]
    fn root_meta_reads_root_entry() {
        let mut f = mini_file();
        // entry index 0 = root storage
        let e = 512 + 512;
        let clsid: [u8; 16] = [0x42; 16];
        f[e + 80..e + 96].copy_from_slice(&clsid);
        f[e + 96..e + 100].copy_from_slice(&7u32.to_le_bytes());
        f[e + 100..e + 108].copy_from_slice(&123u64.to_le_bytes());
        f[e + 108..e + 116].copy_from_slice(&456u64.to_le_bytes());
        let m = root_meta(&f).unwrap();
        assert_eq!(m.clsid, clsid);
        assert_eq!(m.state_bits, 7);
        assert_eq!(m.created, 123);
        assert_eq!(m.modified, 456);
    }

    #[test]
    fn rejects_bad_signature_and_truncation() {
        let mut f = big_file();
        f[0] = 0x00;
        assert!(decode(&f).is_err());
        let f2 = big_file();
        assert!(decode(&f2[..512]).is_err());
        assert!(decode(&f2[..f2.len() - 100]).is_err());
    }

    #[test]
    fn rejects_chain_cycle() {
        let mut f = big_file();
        // FAT sector 0: entry 2 -> 3 and 3 -> 2 (cycle)
        let off = 512;
        f[off + 8..off + 12].copy_from_slice(&3u32.to_le_bytes());
        f[off + 12..off + 16].copy_from_slice(&2u32.to_le_bytes());
        assert!(decode(&f).is_err());
    }

    #[test]
    fn rejects_unterminated_name() {
        let mut f = big_file();
        // entry 1: name length says 4 bytes but no terminating null
        let dir = 512 + 512 + 128;
        f[dir + 64..dir + 66].copy_from_slice(&4u16.to_le_bytes());
        assert!(decode(&f).is_err());
    }

    #[test]
    fn rejects_invalid_color_byte() {
        let mut f = mini_file();
        assert!(decode_strict(&f).is_ok());
        // entry 1: color flag 0x02 is neither red nor black (2.6.1)
        let e = 512 + 512 + 128;
        f[e + 67] = 2;
        assert!(decode(&f).is_ok());
        assert!(decode_strict(&f).is_err());
    }

    #[test]
    fn rejects_stream_with_child() {
        let mut f = mini_file();
        // entry 1 is a stream object; its child ID must be NOSTREAM
        let e = 512 + 512 + 128;
        f[e + 76..e + 80].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode(&f).is_ok());
        assert!(decode_strict(&f).is_err());
    }

    #[test]
    fn rejects_duplicate_sibling_names() {
        // two stream siblings with identical names under the root
        // storage violate the 2.6.4 uniqueness constraint
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "Dup",
                ty: 2,
                left: NOSTREAM,
                right: 2,
                child: NOSTREAM,
                start: 0,
                size: 3,
            },
            De {
                name: "Dup",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 1,
                size: 3,
            },
        ];
        let mut fat = vec![FREESECT; 4];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN; // dir
        fat[2] = ENDOFCHAIN; // minifat
        fat[3] = ENDOFCHAIN; // mini stream
        let mut minifat = vec![FREESECT; 128];
        minifat[0] = ENDOFCHAIN;
        minifat[1] = ENDOFCHAIN;
        let mut ms = alloc::vec![0u8; 512];
        ms[0..3].copy_from_slice(b"AAA");
        ms[64..67].copy_from_slice(b"BBB");
        let mfsec = alloc::vec![0u8; 512];
        let sectors: &[(u32, &[u8])] = &[(3, &ms), (2, &mfsec)];
        let f = build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &minifat,
            first_dir: 1,
            minifat_sector: 2,
            root_start: 3,
            root_size: 512,
            sectors,
        });
        // lenient decode still accepts; strict rejects the duplicates
        let out = decode(&f).unwrap();
        assert_eq!(out.len(), 2);
        assert!(decode_strict(&f).is_err());
    }

    /// Build a conformant image via the encoder so its sibling
    /// trees follow the 2.6.4 balanced-tree layout.
    fn encode_file(streams: &[(&str, &[u8])]) -> Vec<u8> {
        let mut enc = crate::archive::mscfb::encode::CfbEncoder::new();
        for &(p, d) in streams {
            enc.add_stream(p, d);
        }
        enc.finish().unwrap()
    }

    #[test]
    fn get_stream_resolves_sibling_tree() {
        let f = encode_file(&[
            ("Storage/Foo.txt", b"foo contents"),
            ("Storage/Bar", b"bar"),
            ("Storage/Sub/Deep", b"deep"),
            ("Top", b"top"),
        ]);
        // Exact-case lookup descends the sibling red-black trees.
        let e = get_stream(&f, "Storage/Foo.txt").unwrap().unwrap();
        assert_eq!(e.name, "Storage/Foo.txt");
        assert_eq!(e.data, b"foo contents");
        assert_eq!(
            get_stream(&f, "Storage/Sub/Deep").unwrap().unwrap().data,
            b"deep"
        );
        assert_eq!(get_stream(&f, "Top").unwrap().unwrap().data, b"top");
        // The 2.6.4 uppercase mapping makes lookup case-insensitive;
        // the returned entry keeps the on-disk casing.
        let e = get_stream(&f, "storage/foo.TXT").unwrap().unwrap();
        assert_eq!(e.name, "Storage/Foo.txt");
        assert_eq!(e.data, b"foo contents");
        assert_eq!(
            get_stream(&f, "STORAGE/SUB/DEEP").unwrap().unwrap().data,
            b"deep"
        );
    }

    #[test]
    fn get_stream_misses_unknown_and_non_stream_paths() {
        let f = encode_file(&[("Storage/Foo.txt", b"x"), ("Top", b"t")]);
        // Unknown names, storage objects, paths that continue through
        // a stream, and empty components all miss.
        assert!(get_stream(&f, "Storage/Baz").unwrap().is_none());
        assert!(get_stream(&f, "Storage").unwrap().is_none());
        assert!(get_stream(&f, "Top/Child").unwrap().is_none());
        assert!(get_stream(&f, "").unwrap().is_none());
        assert!(get_stream(&f, "Storage/Foo.txt/").unwrap().is_none());
        // Corrupt input still reports an error.
        assert!(get_stream(&f[..100], "Top").is_err());
    }

    #[test]
    fn decode_sorted_orders_by_264_sort_rule() {
        let f = encode_file(&[
            ("Storage 1/Stream Small", b"small"),
            ("Storage 1/Stream Big", b"big"),
            ("Storage 1/Deep/Nested", b"nested"),
            ("Top", b"top"),
        ]);
        // 2.6.4 order: uppercased name length first ("Top" < "Storage 1"
        // despite 'S' < 'T'), then code units; a storage's subtree is
        // listed at the storage's sibling position.
        let sorted = decode_sorted(&f).unwrap();
        let names: Vec<&str> = sorted.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Top",
                "Storage 1/Deep/Nested",
                "Storage 1/Stream Big",
                "Storage 1/Stream Small"
            ]
        );
        // The conformant file already enumerates in this order.
        let out = decode(&f).unwrap();
        let plain: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(plain, names);
    }

    #[test]
    fn decode_sorted_fixes_unsorted_tree() {
        // "b" sorts after "A" under the 2.6.4 rule ("B" > "A"), but the
        // fixture stores it in "A"'s left subtree, so in-order
        // enumeration yields "b" before "A".
        let entries: &[De] = &[
            De {
                name: "Root Entry",
                ty: 5,
                left: NOSTREAM,
                right: NOSTREAM,
                child: 1,
                start: 0,
                size: 0,
            },
            De {
                name: "A",
                ty: 2,
                left: 2,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 0,
                size: 3,
            },
            De {
                name: "b",
                ty: 2,
                left: NOSTREAM,
                right: NOSTREAM,
                child: NOSTREAM,
                start: 1,
                size: 3,
            },
        ];
        let mut fat = vec![FREESECT; 4];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN; // dir
        fat[2] = ENDOFCHAIN; // minifat
        fat[3] = ENDOFCHAIN; // mini stream
        let mut minifat = vec![FREESECT; 128];
        minifat[0] = ENDOFCHAIN;
        minifat[1] = ENDOFCHAIN;
        let mut ms = alloc::vec![0u8; 512];
        ms[0..3].copy_from_slice(b"AAA");
        ms[64..67].copy_from_slice(b"BBB");
        let mfsec = alloc::vec![0u8; 512];
        let sectors: &[(u32, &[u8])] = &[(3, &ms), (2, &mfsec)];
        let f = build_cfb(&Fx {
            entries,
            fat: &fat,
            difat: &[0],
            mini_fat: &minifat,
            first_dir: 1,
            minifat_sector: 2,
            root_start: 3,
            root_size: 512,
            sectors,
        });
        // Lenient decode keeps the on-disk tree order.
        let out = decode(&f).unwrap();
        let names: Vec<&str> = out.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["b", "A"]);
        // decode_sorted imposes the 2.6.4 order regardless.
        let sorted = decode_sorted(&f).unwrap();
        let names: Vec<&str> = sorted.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["A", "b"]);
        // Tree-descent lookup follows the 2.6.4 branches, so "b" is
        // unreachable here even though decode still enumerates it.
        assert_eq!(get_stream(&f, "A").unwrap().unwrap().data, b"AAA");
        assert!(get_stream(&f, "B").unwrap().is_none());
    }

    #[test]
    fn truncated_at_every_position() {
        // The header declares the FAT/directory layout up front, so no
        // truncated input can satisfy the sector references.
        let mut enc = crate::archive::mscfb::encode::CfbEncoder::new();
        enc.add_stream("a.txt", b"mscfb truncation sweep payload");
        enc.add_storage("dir");
        enc.add_stream("dir/b.bin", &[9u8, 8, 7, 6, 5]);
        let image = enc.finish().unwrap();
        for cut in 1..image.len() {
            assert!(decode(&image[..cut]).is_err(), "cut={cut} must not decode");
        }
    }
}
