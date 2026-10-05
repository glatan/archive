//! MS-CFB ([MS-CFB] v20210625) compound file encoding.
//!
//! [`CfbEncoder`](crate::archive::mscfb::encode::CfbEncoder) builds a compound file image from queued storage
//! and stream paths (components separated by '/'). Streams below the
//! 4096-byte mini stream cutoff ([MS-CFB] 2.2) are packed into
//! 64-byte mini sectors chained through the mini FAT inside the root
//! storage's mini stream; larger streams occupy regular FAT sector
//! chains. Sibling directory entries are linked as a balanced binary
//! tree ordered by the [MS-CFB] 2.6.4 sort rule (uppercased name
//! length first, then uppercased UTF-16 code units); all nodes are
//! colored black. Version 3 (512-byte sectors) and version 4
//! (4096-byte sectors) images are supported. Transactions, the range
//! lock sector, and CLSID/state/timestamp metadata are not emitted.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::error::Error;

const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;
const FATSECT: u32 = 0xFFFF_FFFD;
const DIFSECT: u32 = 0xFFFF_FFFC;
const NOSTREAM: u32 = 0xFFFF_FFFF;
const MAXREGSECT: u32 = 0xFFFF_FFFA;
const MAXREGSID: u32 = 0xFFFF_FFFA;
/// [MS-CFB] 2.2 mini stream cutoff: streams below this size live in
/// the mini stream.
const MINI_CUTOFF: u64 = 0x1000;
/// [MS-CFB] 2.4: mini sectors are 64 bytes.
const MINI_SECTOR: usize = 64;
/// [MS-CFB] 2.2: DIFAT entries stored in the 512-byte header.
const HEADER_DIFAT: usize = 109;
/// [MS-CFB] 2.6.1: version 3 stream size limit (2 GiB).
const V3_MAX_STREAM: u64 = 0x8000_0000;
/// [MS-CFB] 2.6.1: directory names are at most 31 UTF-16 units plus
/// the terminating NUL (name length field <= 64 bytes).
const MAX_NAME_UNITS: usize = 31;

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}

/// [MS-CFB] 2.6.4 sort key: the name uppercased as UTF-16 code units.
/// Ordering is by unit count first, then by unit values.
fn sort_key(name: &str) -> Vec<u16> {
    name.to_uppercase().encode_utf16().collect()
}

fn key_cmp(a: &[u16], b: &[u16]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Input tree node: a storage (`data: None`) or stream (`data: Some`).
struct Node {
    name: String,
    data: Option<Vec<u8>>,
    children: Vec<Node>,
}

impl Node {
    /// Insert `comps` (path components) below this storage node.
    /// Sibling names must be unique under the 2.6.4 sort key.
    fn insert(&mut self, comps: &[&str], data: Option<Vec<u8>>) -> Result<(), Error> {
        let key = sort_key(comps[0]);
        if let Some(i) = self.children.iter().position(|c| sort_key(&c.name) == key) {
            let c = &mut self.children[i];
            if c.name != comps[0] {
                return Err(Error::InvalidData("mscfb: duplicate entry name"));
            }
            if comps.len() == 1 {
                // Re-declaring an existing storage is a no-op.
                return if data.is_none() && c.data.is_none() {
                    Ok(())
                } else {
                    Err(Error::InvalidData("mscfb: duplicate entry name"))
                };
            }
            if c.data.is_some() {
                return Err(Error::InvalidData("mscfb: stream used as storage"));
            }
            return c.insert(&comps[1..], data);
        }
        if comps.len() == 1 {
            self.children.push(Node {
                name: String::from(comps[0]),
                data,
                children: Vec::new(),
            });
        } else {
            let mut n = Node {
                name: String::from(comps[0]),
                data: None,
                children: Vec::new(),
            };
            n.insert(&comps[1..], data)?;
            self.children.push(n);
        }
        Ok(())
    }
}

/// Directory entry laid out for serialization; `kids` holds child
/// stream IDs until they are sorted and linked into a balanced tree.
struct Flat {
    name: String,
    key: Vec<u16>,
    ty: u8,
    data: Option<Vec<u8>>,
    kids: Vec<u32>,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

/// Flatten the input tree into directory-entry order (preorder DFS,
/// root = stream ID 0) and return the node's stream ID.
fn flatten(n: Node, out: &mut Vec<Flat>) -> u32 {
    let sid = out.len() as u32;
    let key = sort_key(&n.name);
    out.push(Flat {
        ty: if sid == 0 {
            5
        } else if n.data.is_some() {
            2
        } else {
            1
        },
        name: n.name,
        key,
        data: n.data,
        kids: Vec::new(),
        left: NOSTREAM,
        right: NOSTREAM,
        child: NOSTREAM,
        start: 0,
        size: 0,
    });
    for c in n.children {
        let kid = flatten(c, out);
        out[sid as usize].kids.push(kid);
    }
    sid
}

/// Link `sids` (in 2.6.4 sort order) into a balanced binary tree by
/// median splitting; returns the subtree root stream ID.
fn balance(sids: &[u32], entries: &mut [Flat]) -> u32 {
    if sids.is_empty() {
        return NOSTREAM;
    }
    let mid = sids.len() / 2;
    let left = balance(&sids[..mid], entries);
    let right = balance(&sids[mid + 1..], entries);
    let e = &mut entries[sids[mid] as usize];
    e.left = left;
    e.right = right;
    sids[mid]
}

fn sector_mut(out: &mut [u8], ss: usize, n: u32) -> &mut [u8] {
    let off = ss + n as usize * ss;
    &mut out[off..off + ss]
}

/// Link `count` consecutive FAT entries starting at `start` into a
/// chain terminated by ENDOFCHAIN.
fn link(fat: &mut [u32], start: u32, count: u32) {
    for j in 0..count - 1 {
        fat[(start + j) as usize] = start + j + 1;
    }
    fat[(start + count - 1) as usize] = ENDOFCHAIN;
}

/// Compound file (MS-CFB) writer.
///
/// Paths are '/'-separated; intermediate storages are created
/// implicitly. Queued names are validated at [`finish`](Self::finish):
/// each component must be non-empty, at most 31 UTF-16 code units,
/// and unique among its siblings under the uppercase-insensitive
/// [MS-CFB] 2.6.4 sort order.
///
/// ```
/// use archive::archive::mscfb::{decode, encode::CfbEncoder};
///
/// let mut enc = CfbEncoder::new();
/// enc.add_stream("Storage/Stream", b"payload");
/// let cfb = enc.finish().unwrap();
/// let entries = decode::decode(&cfb).unwrap();
/// assert_eq!(entries[0].name, "Storage/Stream");
/// ```
pub struct CfbEncoder {
    major: u16,
    storages: Vec<String>,
    streams: Vec<(String, Vec<u8>)>,
}

impl CfbEncoder {
    /// New encoder emitting a version 3 compound file (512-byte
    /// sectors, stream sizes limited to 2 GiB).
    pub fn new() -> Self {
        Self {
            major: 3,
            storages: Vec::new(),
            streams: Vec::new(),
        }
    }

    /// New encoder emitting a version 4 compound file (4096-byte
    /// sectors, 64-bit stream sizes).
    pub fn version4() -> Self {
        Self {
            major: 4,
            storages: Vec::new(),
            streams: Vec::new(),
        }
    }

    /// Queue a storage object at `path`.
    pub fn add_storage(&mut self, path: &str) {
        self.storages.push(String::from(path));
    }

    /// Queue a stream object at `path` with `data` as its contents.
    /// Streams smaller than 4096 bytes are stored in the mini stream.
    pub fn add_stream(&mut self, path: &str, data: &[u8]) {
        self.streams.push((String::from(path), data.to_vec()));
    }

    /// Serialize the compound file image.
    ///
    /// Returns [`Error::InvalidData`] for invalid or conflicting paths,
    /// a stream over 2 GiB in a version 3 file, or an image that would
    /// exceed the [MS-CFB] sector-number space.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let v4 = self.major == 4;
        let ss: usize = if v4 { 4096 } else { 512 };
        let per_fat = ss / 4;
        let per_difat = ss / 4 - 1;

        // Directory tree from the queued paths.
        let mut root = Node {
            name: String::from("Root Entry"),
            data: None,
            children: Vec::new(),
        };
        for s in &self.storages {
            insert_path(&mut root, s, None)?;
        }
        for (p, d) in self.streams {
            if !v4 && d.len() as u64 > V3_MAX_STREAM {
                return Err(Error::InvalidData("mscfb: stream exceeds v3 size limit"));
            }
            insert_path(&mut root, &p, Some(d))?;
        }

        let mut entries: Vec<Flat> = Vec::new();
        flatten(root, &mut entries);
        if entries.len() as u64 > u64::from(MAXREGSID) + 1 {
            return Err(Error::InvalidData("mscfb: too many entries"));
        }
        // Sort each sibling level by the 2.6.4 key and link it as a
        // balanced tree.
        for i in 0..entries.len() {
            let mut kids = core::mem::take(&mut entries[i].kids);
            kids.sort_by(|&a, &b| key_cmp(&entries[a as usize].key, &entries[b as usize].key));
            entries[i].child = balance(&kids, &mut entries);
        }

        // Mini stream / mini FAT layout for sub-cutoff streams (2.4).
        let mut mini_fat: Vec<u32> = Vec::new();
        let mut mini_stream: Vec<u8> = Vec::new();
        let mut big_secs = 0usize;
        for e in entries.iter_mut().skip(1) {
            let Some(d) = &e.data else { continue };
            e.size = d.len() as u64;
            if e.size == 0 {
                e.start = ENDOFCHAIN;
            } else if e.size < MINI_CUTOFF {
                e.start = (mini_stream.len() / MINI_SECTOR) as u32;
                let n = d.len().div_ceil(MINI_SECTOR) as u32;
                for j in 0..n {
                    mini_fat.push(if j + 1 == n {
                        ENDOFCHAIN
                    } else {
                        e.start + j + 1
                    });
                }
                mini_stream.extend_from_slice(d);
                mini_stream.resize(mini_stream.len().next_multiple_of(MINI_SECTOR), 0);
            } else {
                big_secs += d.len().div_ceil(ss);
            }
        }

        // Fixed-point layout: FAT sectors describe every sector in the
        // file, including themselves and any chained DIFAT sectors.
        let dir_secs = (entries.len() * 128).div_ceil(ss);
        let minifat_secs = mini_fat.len().div_ceil(per_fat);
        let ms_secs = mini_stream.len().div_ceil(ss);
        let data_secs = dir_secs + minifat_secs + ms_secs + big_secs;
        let (mut num_fat, mut num_difat) = (0usize, 0usize);
        let total = loop {
            let t = data_secs + num_fat + num_difat;
            if t as u64 > u64::from(MAXREGSECT) + 1 {
                return Err(Error::InvalidData("mscfb: image too large"));
            }
            let need_fat = t.div_ceil(per_fat);
            let need_difat = need_fat.saturating_sub(HEADER_DIFAT).div_ceil(per_difat);
            if (need_fat, need_difat) == (num_fat, num_difat) {
                break t;
            }
            num_fat = need_fat;
            num_difat = need_difat;
        };

        // Sector assignment: directory, mini FAT, mini stream, regular
        // stream chains, FAT, DIFAT chain.
        let mut next = 0u32;
        let dir_start = next;
        next += dir_secs as u32;
        let minifat_start = if minifat_secs > 0 { next } else { ENDOFCHAIN };
        next += minifat_secs as u32;
        let ms_start = if ms_secs > 0 { next } else { ENDOFCHAIN };
        next += ms_secs as u32;
        for e in entries.iter_mut().skip(1) {
            if e.ty == 2 && e.size >= MINI_CUTOFF {
                e.start = next;
                next += e.data.as_ref().map_or(0, |d| d.len().div_ceil(ss)) as u32;
            }
        }
        let fat_start = next;
        next += num_fat as u32;
        let difat_start = if num_difat > 0 { next } else { ENDOFCHAIN };
        next += num_difat as u32;
        debug_assert_eq!(next as usize, total);

        // The root storage's stream fields describe the mini stream
        // (2.6.2).
        entries[0].start = if ms_secs > 0 { ms_start } else { ENDOFCHAIN };
        entries[0].size = mini_stream.len() as u64;

        // FAT image.
        let mut fat = alloc::vec![FREESECT; num_fat * per_fat];
        link(&mut fat, dir_start, dir_secs as u32);
        if minifat_secs > 0 {
            link(&mut fat, minifat_start, minifat_secs as u32);
        }
        if ms_secs > 0 {
            link(&mut fat, ms_start, ms_secs as u32);
        }
        for e in &entries {
            if e.ty == 2 && e.size >= MINI_CUTOFF {
                let n = e.data.as_ref().map_or(0, |d| d.len().div_ceil(ss)) as u32;
                link(&mut fat, e.start, n);
            }
        }
        for i in 0..num_fat {
            fat[fat_start as usize + i] = FATSECT;
        }
        for i in 0..num_difat {
            fat[difat_start as usize + i] = DIFSECT;
        }
        mini_fat.resize(minifat_secs * per_fat, FREESECT);

        // Directory image (2.6.1): 128-byte entries; unused slots are
        // unallocated entries with all-NOSTREAM pointers.
        let mut dir = alloc::vec![0u8; dir_secs * ss];
        for (i, e) in entries.iter().enumerate() {
            let o = i * 128;
            for (j, u) in e.name.encode_utf16().enumerate() {
                dir[o + 2 * j..o + 2 * j + 2].copy_from_slice(&u.to_le_bytes());
            }
            let name_len = (e.name.encode_utf16().count() + 1) as u16 * 2;
            dir[o + 64..o + 66].copy_from_slice(&name_len.to_le_bytes());
            dir[o + 66] = e.ty;
            dir[o + 67] = 1; // black
            dir[o + 68..o + 72].copy_from_slice(&e.left.to_le_bytes());
            dir[o + 72..o + 76].copy_from_slice(&e.right.to_le_bytes());
            dir[o + 76..o + 80].copy_from_slice(&e.child.to_le_bytes());
            dir[o + 116..o + 120].copy_from_slice(&e.start.to_le_bytes());
            dir[o + 120..o + 128].copy_from_slice(&e.size.to_le_bytes());
        }
        for o in (entries.len() * 128..dir.len()).step_by(128) {
            dir[o + 68..o + 72].copy_from_slice(&NOSTREAM.to_le_bytes());
            dir[o + 72..o + 76].copy_from_slice(&NOSTREAM.to_le_bytes());
            dir[o + 76..o + 80].copy_from_slice(&NOSTREAM.to_le_bytes());
        }

        // Header region: 512 bytes for v3; for v4 the header is still
        // 512 bytes but sector 0 begins at offset `ss` (2.2).
        let mut out = alloc::vec![0u8; ss * (1 + total)];
        out[..8].copy_from_slice(&SIGNATURE);
        put16(&mut out, 24, 0x003E); // minor version
        put16(&mut out, 26, self.major);
        put16(&mut out, 28, 0xFFFE); // byte order
        put16(&mut out, 30, if v4 { 12 } else { 9 });
        put16(&mut out, 32, 6); // mini sector shift
        put32(&mut out, 40, if v4 { dir_secs as u32 } else { 0 });
        put32(&mut out, 44, num_fat as u32);
        put32(&mut out, 48, dir_start);
        // transaction signature (offset 52) stays zero (2.2).
        put32(&mut out, 56, 0x1000);
        put32(&mut out, 60, minifat_start);
        put32(&mut out, 64, minifat_secs as u32);
        put32(&mut out, 68, difat_start);
        put32(&mut out, 72, num_difat as u32);
        for i in 0..HEADER_DIFAT {
            let v = if i < num_fat {
                fat_start + i as u32
            } else {
                FREESECT
            };
            put32(&mut out, 76 + 4 * i, v);
        }

        // Sector payloads.
        let doff = ss + dir_start as usize * ss;
        out[doff..doff + dir.len()].copy_from_slice(&dir);
        for i in 0..minifat_secs {
            let s = sector_mut(&mut out, ss, minifat_start + i as u32);
            for (j, v) in mini_fat[i * per_fat..(i + 1) * per_fat].iter().enumerate() {
                s[4 * j..4 * j + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        if ms_secs > 0 {
            mini_stream.resize(ms_secs * ss, 0);
            let off = ss + ms_start as usize * ss;
            out[off..off + mini_stream.len()].copy_from_slice(&mini_stream);
        }
        for e in &entries {
            let Some(d) = &e.data else { continue };
            if e.size < MINI_CUTOFF {
                continue;
            }
            let off = ss + e.start as usize * ss;
            out[off..off + d.len()].copy_from_slice(d);
        }
        for i in 0..num_fat {
            let s = sector_mut(&mut out, ss, fat_start + i as u32);
            for (j, v) in fat[i * per_fat..(i + 1) * per_fat].iter().enumerate() {
                s[4 * j..4 * j + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        for i in 0..num_difat {
            let s = sector_mut(&mut out, ss, difat_start + i as u32);
            for j in 0..per_difat {
                let idx = HEADER_DIFAT + i * per_difat + j;
                let v = if idx < num_fat {
                    fat_start + idx as u32
                } else {
                    FREESECT
                };
                s[4 * j..4 * j + 4].copy_from_slice(&v.to_le_bytes());
            }
            let link_next = if i + 1 < num_difat {
                difat_start + i as u32 + 1
            } else {
                ENDOFCHAIN
            };
            s[ss - 4..ss].copy_from_slice(&link_next.to_le_bytes());
        }
        Ok(out)
    }
}

impl Default for CfbEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for CfbEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_stream(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.finish()
    }
}

/// Validate path components and insert into the directory tree.
fn insert_path(root: &mut Node, path: &str, data: Option<Vec<u8>>) -> Result<(), Error> {
    let comps: Vec<&str> = path.split('/').collect();
    for c in &comps {
        if c.is_empty() || c.encode_utf16().count() > MAX_NAME_UNITS {
            return Err(Error::InvalidData("mscfb: invalid entry name"));
        }
    }
    root.insert(&comps, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::mscfb::decode::{CfbEntry, decode, decode_strict};
    use crate::traits::{ArchiveEncode, ArchiveEntry};
    use alloc::format;
    use alloc::string::ToString;

    fn entry<'a>(entries: &'a [CfbEntry], name: &str) -> &'a CfbEntry {
        entries.iter().find(|e| e.name() == name).expect("entry")
    }

    #[test]
    fn roundtrip_stream_tree() {
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = CfbEncoder::new();
        enc.add_stream("Storage 1/Stream Small", b"mini stream contents");
        enc.add_stream("Storage 1/Stream Big", &big);
        enc.add_stream("Storage 1/Deep/Nested", b"nested!");
        enc.add_stream("Top", b"top level");
        enc.add_storage("Empty Storage");
        let cfb = enc.finish().unwrap();
        for entries in [decode(&cfb).unwrap(), decode_strict(&cfb).unwrap()] {
            // In-order traversal of the balanced sibling trees yields
            // the 2.6.4 sort order at each level.
            let names: Vec<&str> = entries.iter().map(|e| e.name()).collect();
            assert_eq!(
                names,
                [
                    "Top",
                    "Storage 1/Deep/Nested",
                    "Storage 1/Stream Big",
                    "Storage 1/Stream Small"
                ]
            );
            assert_eq!(
                entry(&entries, "Storage 1/Stream Small").data(),
                b"mini stream contents"
            );
            assert_eq!(entry(&entries, "Storage 1/Stream Big").data(), &big[..]);
            assert_eq!(entry(&entries, "Storage 1/Deep/Nested").data(), b"nested!");
            assert_eq!(entry(&entries, "Top").data(), b"top level");
        }
    }

    #[test]
    fn mini_stream_roundtrip() {
        // Sizes crossing 64-byte mini sector boundaries and the 4096
        // cutoff: below cutoff uses the mini FAT, at/above the FAT.
        let sizes = [0usize, 1, 63, 64, 65, 500, 4095];
        let mut enc = CfbEncoder::new();
        for (i, &n) in sizes.iter().enumerate() {
            enc.add_stream(&format!("s{i}"), &alloc::vec![i as u8; n]);
        }
        enc.add_stream("at-cutoff", &alloc::vec![0xABu8; 4096]);
        let cfb = enc.finish().unwrap();
        let entries = decode_strict(&cfb).unwrap();
        assert_eq!(entries.len(), sizes.len() + 1);
        for (i, &n) in sizes.iter().enumerate() {
            assert_eq!(
                entry(&entries, &format!("s{i}")).data(),
                alloc::vec![i as u8; n].as_slice()
            );
        }
        assert_eq!(entry(&entries, "at-cutoff").data(), &[0xABu8; 4096]);
    }

    #[test]
    fn v4_sector_roundtrip() {
        let big: Vec<u8> = (0..9000u32).map(|i| (i % 231) as u8).collect();
        let mut enc = CfbEncoder::version4();
        enc.add_stream("A/B", b"v4 mini");
        enc.add_stream("Big", &big);
        let cfb = enc.finish().unwrap();
        assert_eq!(&cfb[..8], &SIGNATURE);
        assert_eq!(cfb.len() % 4096, 0);
        assert_eq!(u16::from_le_bytes([cfb[26], cfb[27]]), 4);
        let entries = decode_strict(&cfb).unwrap();
        assert_eq!(entry(&entries, "A/B").data(), b"v4 mini");
        assert_eq!(entry(&entries, "Big").data(), &big[..]);
    }

    #[test]
    fn difat_chain_roundtrip() {
        // >109 FAT sectors (v3: ~7 MiB of content) forces a chained
        // DIFAT sector beyond the 109 in-header entries (2.5).
        let data: Vec<u8> = (0..7_300_000u32).map(|i| (i % 251) as u8).collect();
        let mut enc = CfbEncoder::new();
        enc.add_stream("huge", &data);
        let cfb = enc.finish().unwrap();
        assert_ne!(
            u32::from_le_bytes(cfb[68..72].try_into().unwrap()),
            ENDOFCHAIN
        );
        let entries = decode(&cfb).unwrap();
        assert_eq!(entry(&entries, "huge").data(), &data[..]);
    }

    #[test]
    fn empty_file_roundtrip() {
        let cfb = CfbEncoder::new().finish().unwrap();
        assert!(decode(&cfb).unwrap().is_empty());
        assert!(decode_strict(&cfb).unwrap().is_empty());
        let mut enc = CfbEncoder::new();
        enc.add_storage("Only Storage");
        assert!(decode_strict(&enc.finish().unwrap()).unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_paths() {
        let long = "n".repeat(40);
        for bad in ["", "a//b", "/a", "a/", long.as_str()] {
            let mut enc = CfbEncoder::new();
            enc.add_stream(bad, b"x");
            assert!(enc.finish().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rejects_duplicate_names() {
        let mut enc = CfbEncoder::new();
        enc.add_stream("dup", b"1");
        enc.add_stream("dup", b"2");
        assert!(enc.finish().is_err());
        // 2.6.4: sibling names are unique under uppercase folding.
        let mut enc = CfbEncoder::new();
        enc.add_stream("UP", b"1");
        enc.add_stream("up", b"2");
        assert!(enc.finish().is_err());
        // a stream cannot act as a storage prefix
        let mut enc = CfbEncoder::new();
        enc.add_stream("a", b"x");
        enc.add_stream("a/b", b"y");
        assert!(enc.finish().is_err());
        // re-declaring a storage is a no-op
        let mut enc = CfbEncoder::new();
        enc.add_storage("s");
        enc.add_storage("s");
        enc.add_stream("s/x", b"z");
        let entries = decode_strict(&enc.finish().unwrap()).unwrap();
        assert_eq!(entry(&entries, "s/x").data(), b"z");
    }

    #[test]
    fn encode_via_trait() {
        let mut enc = CfbEncoder::new();
        ArchiveEncode::add_file(&mut enc, "a.txt", b"data");
        let cfb = ArchiveEncode::finish(enc).unwrap();
        assert_eq!(entry(&decode(&cfb).unwrap(), "a.txt").data(), b"data");
    }

    #[test]
    fn names_in_sort_order() {
        // 2.6.4: shorter (uppercased) names sort before longer ones;
        // equal lengths compare by code unit. "b" (1 unit) sorts before
        // "AA" (2 units) even though 'b' > 'A' lexicographically.
        let mut enc = CfbEncoder::new();
        enc.add_stream("b", b"one");
        enc.add_stream("AA", b"two");
        enc.add_stream("a", b"three");
        let entries = decode_strict(&enc.finish().unwrap()).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name().to_string()).collect();
        assert_eq!(names, ["a", "b", "AA"]);
    }
}
