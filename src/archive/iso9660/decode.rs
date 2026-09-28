//! ISO 9660 (ECMA-119) image decoder with Rock Ridge (IEEE P1282)
//! and Joliet supplementary volume support.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

const SECTOR: usize = 2048;
const VD_START: usize = 16 * SECTOR;
const VD_ID: &[u8; 5] = b"CD001";

const VD_TYPE_PRIMARY: u8 = 1;
const VD_TYPE_SUPPLEMENTARY: u8 = 2;
const VD_TYPE_TERMINATOR: u8 = 255;

const FLAG_DIR: u8 = 0x02;
const FLAG_MULTI_EXTENT: u8 = 0x80;

/// Entry kind derived from the directory record flags and Rock
/// Ridge `PX` mode (when present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link (Rock Ridge `SL`); `data` holds the target path.
    Symlink,
    /// Device / fifo / socket or other non-regular inode type. The
    /// payload carries the Rock Ridge mode's `S_IFMT` bits
    /// (`0` for a plain ISO9660 image).
    Other(u32),
}

/// A decoded ISO 9660 entry. `name` is the full path relative to
/// the volume root (components joined with `/`).
#[derive(Debug, Clone)]
pub struct IsoEntry {
    /// Full path without a leading slash. Rock Ridge names when the
    /// image provides them, else Joliet UCS-2 names, else ISO9660
    /// d-characters with the `;version` suffix removed.
    pub name: String,
    /// Entry kind.
    pub kind: IsoKind,
    /// Unix mode (file type + permissions). Rock Ridge `PX` mode when
    /// present; otherwise `0o040555` for directories / `0o100444`
    /// for files, matching read-only media semantics.
    pub mode: u32,
    /// Owner uid (Rock Ridge `PX`; 0 otherwise).
    pub uid: u32,
    /// Owner gid (Rock Ridge `PX`; 0 otherwise).
    pub gid: u32,
    /// Hard link count (Rock Ridge `PX`; 1 otherwise).
    pub nlink: u32,
    /// Modification time, seconds since the Unix epoch (7-byte
    /// directory record time or Rock Ridge `TF` modify time).
    pub mtime: i64,
    /// File contents or symlink target; empty for directories.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for IsoEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decoded ISO 9660 image.
#[derive(Debug)]
pub struct IsoImage {
    /// Volume identifier from the primary volume descriptor.
    pub volume_id: String,
    /// Total volume size in logical blocks.
    pub volume_blocks: u32,
    /// Whether the primary tree carries SUSP/Rock Ridge entries.
    pub has_rock_ridge: bool,
    /// Whether a Joliet supplementary volume descriptor is present.
    pub has_joliet: bool,
    /// Entries in depth-first directory order.
    pub entries: Vec<IsoEntry>,
}

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Both-endian 32-bit field (ECMA-119 §7.3.3).
fn both32(b: &[u8], o: usize) -> Result<u32, Error> {
    let lo = u32le(b, o);
    let hi = u32be(b, o + 4);
    if lo != hi {
        return Err(Error::InvalidData("iso9660 both-endian field mismatch"));
    }
    Ok(lo)
}

/// Both-endian 16-bit field.
fn both16(b: &[u8], o: usize) -> Result<u16, Error> {
    let lo = u16le(b, o);
    let hi = u16be(b, o + 2);
    if lo != hi {
        return Err(Error::InvalidData("iso9660 both-endian field mismatch"));
    }
    Ok(lo)
}

/// 7-byte directory record timestamp (ECMA-119 §9.1.5):
/// years since 1900, month, day, hour, min, sec, tz (15-min offset
/// from GMT, signed). Returns Unix seconds.
fn dec_datetime(b: &[u8], o: usize) -> i64 {
    let year = i64::from(b[o]) + 1900;
    let month = i64::from(b[o + 1]);
    let day = i64::from(b[o + 2]);
    let hour = i64::from(b[o + 3]);
    let min = i64::from(b[o + 4]);
    let sec = i64::from(b[o + 5]);
    let tz = b[o + 6] as i8 as i64;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return 0;
    }
    // days since epoch (civil from days, Howard Hinnant's algorithm)
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hour * 3600 + min * 60 + sec - tz * 900
}

/// Parsed directory record fields (ECMA-119 §9.1).
struct DirRec<'a> {
    extent: u32,
    ext_attr_len: u8,
    size: u32,
    flags: u8,
    mtime: i64,
    /// Raw file identifier bytes (`\x00` = ".", `\x01` = "..").
    name: &'a [u8],
    /// System Use field (may be empty).
    susp: &'a [u8],
}

fn parse_dirents<'a>(
    data: &'a [u8],
    blksz: usize,
    mut f: impl FnMut(DirRec<'a>) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut pos = 0usize;
    while pos < data.len() {
        // Records never cross a logical block boundary; zero bytes
        // pad out the rest of a block.
        let blk_end = (pos / blksz + 1) * blksz;
        let avail = blk_end.min(data.len());
        let len = data[pos] as usize;
        if len == 0 {
            pos = blk_end;
            continue;
        }
        if len < 34 || pos + len > avail {
            return Err(Error::InvalidData("iso9660 truncated directory record"));
        }
        let r = &data[pos..pos + len];
        let name_len = r[32] as usize;
        if 33 + name_len > len {
            return Err(Error::InvalidData("iso9660 dirent name overflow"));
        }
        let name = &r[33..33 + name_len];
        // Padding byte keeps the System Use field even-aligned.
        let susp_off = 33 + name_len + usize::from(name_len.is_multiple_of(2));
        let susp = if susp_off < len {
            &r[susp_off..]
        } else {
            &[][..]
        };
        if r[26] != 0 || r[27] != 0 {
            return Err(Error::Unsupported("iso9660 interleaved file"));
        }
        f(DirRec {
            extent: both32(r, 2)?,
            ext_attr_len: r[1],
            size: both32(r, 10)?,
            flags: r[25],
            mtime: dec_datetime(r, 18),
            name,
            susp,
        })?;
        pos += len;
    }
    Ok(())
}

/// Rock Ridge fields collected from a System Use area.
#[derive(Default)]
struct RrInfo {
    /// NM entries (possibly continued across entries with flag bit0).
    name: Vec<u8>,
    name_continue: bool,
    mode: Option<u32>,
    nlink: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// SL target path bytes, `//`-joined per component.
    symlink: Option<Vec<u8>>,
    sl_continue: bool,
    /// TF modify time.
    tf_modify: Option<i64>,
    /// ZF (zisofs) seen.
    compressed: bool,
}

fn parse_susp(img: &[u8], blksz: usize, mut area: &[u8], depth: usize) -> Result<RrInfo, Error> {
    if depth > 4 {
        return Err(Error::InvalidData("iso9660 SUSP continuation loop"));
    }
    let mut rr = RrInfo::default();
    let mut cont: Option<(u64, u64, u64)> = None;
    while area.len() >= 4 {
        let len = area[2] as usize;
        if len < 4 || len > area.len() {
            break; // padding or trailing garbage is tolerated
        }
        let e = &area[..len];
        let sig = [e[0], e[1]];
        match &sig {
            b"ST" => return Ok(rr),
            b"SP" => {
                if len < 7 || e[4] != 0xBE || e[5] != 0xEF {
                    return Err(Error::InvalidData("iso9660 bad SP entry"));
                }
                // SP payload byte 6 is the number of bytes skipped at
                // the start of subsequent system-use fields.
                let skip = e[6] as usize;
                if area.len() > len && skip > area.len() - len {
                    return Err(Error::InvalidData("iso9660 bad SP skip"));
                }
            }
            b"CE" => {
                if len < 28 {
                    return Err(Error::InvalidData("iso9660 bad CE entry"));
                }
                cont = Some((
                    u64::from(both32(e, 4)?),
                    u64::from(both32(e, 12)?),
                    u64::from(both32(e, 20)?),
                ));
            }
            b"NM" => {
                if len < 5 {
                    return Err(Error::InvalidData("iso9660 bad NM entry"));
                }
                let flags = e[4];
                if flags & 0x06 != 0 {
                    // "." / ".." pseudo names
                } else {
                    rr.name.extend_from_slice(&e[5..]);
                }
                rr.name_continue = flags & 0x01 != 0;
            }
            b"PX" => {
                if len >= 44 {
                    rr.mode = Some(both32(e, 4)?);
                    rr.nlink = Some(both32(e, 12)?);
                    rr.uid = Some(both32(e, 20)?);
                    rr.gid = Some(both32(e, 28)?);
                }
            }
            b"SL" => {
                if len < 5 {
                    return Err(Error::InvalidData("iso9660 bad SL entry"));
                }
                let sl = rr.symlink.get_or_insert_with(Vec::new);
                let mut p = 5usize;
                while p + 2 <= len {
                    let cflags = e[p];
                    let clen = e[p + 1] as usize;
                    p += 2;
                    if p + clen > len {
                        return Err(Error::InvalidData("iso9660 bad SL component"));
                    }
                    if cflags & 0x08 != 0 {
                        sl.extend_from_slice(b"/"); // root component
                    } else if cflags & 0x30 != 0 {
                        // volroot/host: record as-is
                        sl.extend_from_slice(&e[p..p + clen]);
                    } else {
                        if !sl.is_empty() && !sl.ends_with(b"/") {
                            sl.push(b'/');
                        }
                        sl.extend_from_slice(&e[p..p + clen]);
                    }
                    p += clen;
                    rr.sl_continue = cflags & 0x01 != 0;
                }
            }
            b"TF" => {
                if len < 5 {
                    return Err(Error::InvalidData("iso9660 bad TF entry"));
                }
                let tflags = e[4];
                let long = tflags & 0x80 != 0;
                let tsz = if long { 17 } else { 7 };
                let mut p = 5usize;
                let mut idx = 0;
                // bits 0..6: create, modify, access, attr, backup,
                // expire, effective — we care about modify (bit 1).
                for bit in 0..7 {
                    if tflags & (1 << bit) != 0 {
                        if p + tsz > len {
                            return Err(Error::InvalidData("iso9660 bad TF entry"));
                        }
                        if bit == 1 && !long {
                            rr.tf_modify = Some(dec_datetime(e, p));
                        }
                        // long form (17-byte ASCII timestamp) is not
                        // interpreted; dir-record time is kept.
                        p += tsz;
                        idx += 1;
                    }
                }
                let _ = idx;
            }
            b"ZF" => rr.compressed = true,
            _ => {} // PD, ER, ES, PN, RR, AS, unknown: skip
        }
        area = &area[len..];
    }
    if let Some((blk, off, clen)) = cont {
        let start = usize::try_from(blk)
            .ok()
            .and_then(|b| b.checked_mul(blksz))
            .and_then(|b| b.checked_add(off as usize))
            .ok_or(Error::InvalidData("iso9660 CE out of range"))?;
        let clen = usize::try_from(clen).map_err(|_| Error::InvalidData("iso9660 CE length"))?;
        let ca = img
            .get(
                start
                    ..start
                        .checked_add(clen)
                        .ok_or(Error::InvalidData("iso9660 CE out of range"))?,
            )
            .ok_or(Error::InvalidData("iso9660 CE out of range"))?;
        // Continuation area holds further SUSP entries; merge fields
        // (later NM/SL bytes extend earlier ones).
        let cont_rr = parse_susp(img, blksz, ca, depth + 1)?;
        if rr.name_continue || rr.name.is_empty() {
            rr.name.extend_from_slice(&cont_rr.name);
            rr.name_continue = cont_rr.name_continue;
        }
        if rr.mode.is_none() {
            rr.mode = cont_rr.mode;
        }
        if rr.nlink.is_none() {
            rr.nlink = cont_rr.nlink;
        }
        if rr.uid.is_none() {
            rr.uid = cont_rr.uid;
        }
        if rr.gid.is_none() {
            rr.gid = cont_rr.gid;
        }
        if let Some(csl) = cont_rr.symlink {
            rr.symlink
                .get_or_insert_with(Vec::new)
                .extend_from_slice(&csl);
            rr.sl_continue = cont_rr.sl_continue;
        }
        if rr.tf_modify.is_none() {
            rr.tf_modify = cont_rr.tf_modify;
        }
        rr.compressed |= cont_rr.compressed;
    }
    Ok(rr)
}

struct VolDesc {
    volume_id: String,
    volume_blocks: u32,
    logical_block_size: usize,
    root: DirRecOwned,
}

struct DirRecOwned {
    extent: u32,
    ext_attr_len: u8,
    size: u32,
    flags: u8,
    mtime: i64,
}

fn parse_vd(sec: &[u8], joliet: bool) -> Result<VolDesc, Error> {
    let expected = if joliet {
        VD_TYPE_SUPPLEMENTARY
    } else {
        VD_TYPE_PRIMARY
    };
    if sec[0] != expected || &sec[1..6] != VD_ID || sec[6] != 1 {
        return Err(Error::InvalidData("iso9660 bad volume descriptor"));
    }
    let volume_id = if joliet {
        decode_ucs2(&sec[40..72])
    } else {
        let mut vid = String::from_utf8_lossy(&sec[40..72]).into_owned();
        while vid.ends_with(' ') || vid.ends_with(' ') {
            vid.pop();
        }
        vid
    };
    let volume_blocks = both32(sec, 80)?;
    let lbs = both16(sec, 128)? as usize;
    if !lbs.is_power_of_two() || !(512..=32 * 1024).contains(&lbs) {
        return Err(Error::InvalidData("iso9660 bad logical block size"));
    }
    // Root directory record (ECMA-119 §9.1), fixed 34 bytes at 156.
    let r = &sec[156..190];
    if r[0] != 34 {
        return Err(Error::InvalidData("iso9660 bad root record"));
    }
    Ok(VolDesc {
        volume_id,
        volume_blocks,
        logical_block_size: lbs,
        root: DirRecOwned {
            extent: both32(r, 2)?,
            ext_attr_len: r[1],
            size: both32(r, 10)?,
            flags: r[25],
            mtime: dec_datetime(r, 18),
        },
    })
}

fn decode_ucs2(b: &[u8]) -> String {
    let mut s = String::new();
    let (pairs, _) = b.as_chunks::<2>();
    for pair in pairs {
        let c = u16::from_be_bytes(*pair);
        if c == 0 {
            break;
        }
        s.push(char::from_u32(u32::from(c)).unwrap_or('\u{FFFD}'));
    }
    s.trim_end().to_string()
}

/// ISO9660 file identifier -> display name: strip `;version`, map
/// `\x00`/`\x01` is handled by the caller, lowercase? Keep the
/// on-disk casing (d-characters are already uppercase per spec).
fn iso_name(raw: &[u8]) -> String {
    let mut n = raw;
    if let Some(i) = n.iter().position(|&c| c == b';') {
        n = &n[..i];
    }
    // Trailing '.' with nothing after it is stripped (e.g. "NAME.").
    if n.ends_with(b".") {
        n = &n[..n.len() - 1];
    }
    String::from_utf8_lossy(n).into_owned()
}

fn joliet_name(raw: &[u8]) -> String {
    let mut s = decode_ucs2(raw);
    if let Some(i) = s.find(';') {
        s.truncate(i);
    }
    s
}

struct Tree<'a> {
    input: &'a [u8],
    blksz: usize,
}

impl<'a> Tree<'a> {
    fn read_file(
        &self,
        extent: u32,
        ext_attr_len: u8,
        size: u32,
        flags: u8,
    ) -> Result<Vec<u8>, Error> {
        if flags & FLAG_MULTI_EXTENT != 0 {
            return Err(Error::Unsupported("iso9660 multi-extent file"));
        }
        let start = u64::from(extent)
            .checked_add(u64::from(ext_attr_len))
            .and_then(|v| v.checked_mul(self.blksz as u64))
            .ok_or(Error::InvalidData("iso9660 extent offset overflow"))?;
        let start = usize::try_from(start)
            .map_err(|_| Error::InvalidData("iso9660 extent offset overflow"))?;
        let end = start
            .checked_add(size as usize)
            .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
        Ok(self
            .input
            .get(start..end)
            .ok_or(Error::InvalidData("iso9660 extent out of range"))?
            .to_vec())
    }
}

/// Directory tree walker: carries the mutable traversal state so
/// `walk` stays small.
struct Walker<'a, 'b> {
    tree: &'b Tree<'a>,
    /// Decode file identifiers as UCS-2BE (Joliet tree).
    joliet: bool,
    /// System Use fields carry SUSP/Rock Ridge entries.
    susp_active: bool,
    /// (extent, size) of visited directories, for cycle detection.
    visited: BTreeSet<(u32, u32)>,
    entries: Vec<IsoEntry>,
    /// Set when any Rock Ridge NM name was used.
    use_rr: bool,
}

impl Walker<'_, '_> {
    /// Walk a directory tree depth-first.
    fn walk(
        &mut self,
        extent: u32,
        ext_attr_len: u8,
        size: u32,
        path: &str,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > 64 {
            return Err(Error::InvalidData("iso9660 directory nesting too deep"));
        }
        if !self.visited.insert((extent, size)) {
            return Err(Error::InvalidData("iso9660 directory cycle"));
        }
        let data = self.tree.read_file(extent, ext_attr_len, size, 0)?;
        let mut recs: Vec<(DirRecOwned, Vec<u8>, RrInfo)> = Vec::new();
        parse_dirents(&data, self.tree.blksz, |r| {
            let rr = if self.susp_active && !r.susp.is_empty() {
                parse_susp(self.tree.input, self.tree.blksz, r.susp, 0)?
            } else {
                RrInfo::default()
            };
            recs.push((
                DirRecOwned {
                    extent: r.extent,
                    ext_attr_len: r.ext_attr_len,
                    size: r.size,
                    flags: r.flags,
                    mtime: r.mtime,
                },
                r.name.to_vec(),
                rr,
            ));
            Ok(())
        })?;
        for (rec, raw_name, rr) in recs {
            // "." and ".." records carry file identifiers 0x00 / 0x01.
            if raw_name == [0] || raw_name == [1] {
                continue;
            }
            let mut base = if self.joliet {
                joliet_name(&raw_name)
            } else {
                iso_name(&raw_name)
            };
            if !rr.name.is_empty() {
                base = String::from_utf8_lossy(&rr.name).into_owned();
                self.use_rr = true;
            }
            if base.is_empty() || base.contains('/') {
                return Err(Error::InvalidData("iso9660 bad entry name"));
            }
            let cpath = if path.is_empty() {
                base.clone()
            } else {
                let mut p = String::with_capacity(path.len() + base.len() + 1);
                p.push_str(path);
                p.push('/');
                p.push_str(&base);
                p
            };
            let is_dir = rec.flags & FLAG_DIR != 0;
            let mode = rr.mode.unwrap_or(if is_dir { 0o040555 } else { 0o100444 });
            let sfmt = mode & 0o170000;
            let kind = if is_dir {
                IsoKind::Directory
            } else if sfmt == 0o120000 {
                IsoKind::Symlink
            } else if sfmt == 0o100000 || rr.mode.is_none() {
                IsoKind::File
            } else {
                IsoKind::Other(sfmt)
            };
            if rr.compressed {
                return Err(Error::Unsupported("iso9660 zisofs-compressed file"));
            }
            let entry_data = match kind {
                IsoKind::Directory => Vec::new(),
                IsoKind::Symlink => rr.symlink.clone().unwrap_or_default(),
                _ => self
                    .tree
                    .read_file(rec.extent, rec.ext_attr_len, rec.size, rec.flags)?,
            };
            let mtime = rr.tf_modify.unwrap_or(rec.mtime);
            self.entries.push(IsoEntry {
                name: cpath.clone(),
                kind,
                mode,
                uid: rr.uid.unwrap_or(0),
                gid: rr.gid.unwrap_or(0),
                nlink: rr.nlink.unwrap_or(1),
                mtime,
                data: entry_data,
            });
            if kind == IsoKind::Directory {
                self.walk(rec.extent, rec.ext_attr_len, rec.size, &cpath, depth + 1)?;
            }
        }
        Ok(())
    }
}

/// Decode an ISO 9660 image (PVD tree with Rock Ridge, falling back
/// to a Joliet supplementary tree, then plain ISO9660 names).
pub fn decode(input: &[u8]) -> Result<IsoImage, Error> {
    if input.len() < VD_START + SECTOR {
        return Err(Error::UnexpectedEof);
    }
    let mut pvd: Option<VolDesc> = None;
    let mut joliet_svd: Option<VolDesc> = None;
    let mut off = VD_START;
    loop {
        let sec = input.get(off..off + SECTOR).ok_or(Error::InvalidData(
            "iso9660 missing volume descriptor terminator",
        ))?;
        if &sec[1..6] != VD_ID {
            return Err(Error::InvalidData("iso9660 bad volume descriptor"));
        }
        match sec[0] {
            VD_TYPE_PRIMARY => {
                if pvd.is_some() {
                    return Err(Error::InvalidData("iso9660 duplicate PVD"));
                }
                pvd = Some(parse_vd(sec, false)?);
            }
            VD_TYPE_SUPPLEMENTARY => {
                // Joliet images mark the SVD with %/@, %/C or %/E
                // escape sequences (UCS-2 levels 1-3).
                let esc = &sec[88..120];
                let is_joliet = esc
                    .windows(3)
                    .any(|w| w == b"%/@" || w == b"%/C" || w == b"%/E");
                if is_joliet && joliet_svd.is_none() {
                    joliet_svd = Some(parse_vd(sec, true)?);
                }
            }
            VD_TYPE_TERMINATOR => break,
            _ => {} // boot record / partition descriptor
        }
        off += SECTOR;
    }
    let pvd = pvd.ok_or(Error::InvalidData("iso9660 missing PVD"))?;
    let tree = Tree {
        input,
        blksz: pvd.logical_block_size,
    };

    // SUSP detection: "SP" marker in the "." record of the PVD root
    // directory (SUSP 5.3).
    let mut susp_active = false;
    {
        let root_data = tree.read_file(pvd.root.extent, pvd.root.ext_attr_len, pvd.root.size, 0)?;
        if root_data.len() >= 41 && root_data[0] >= 34 {
            let r = &root_data[..root_data[0] as usize];
            let name_len = r[32] as usize;
            let susp_off = 33 + name_len + usize::from(name_len.is_multiple_of(2));
            if r[32] == 1
                && r[33] == 0
                && susp_off + 7 <= r.len()
                && &r[susp_off..susp_off + 2] == b"SP"
                && r[susp_off + 4] == 0xBE
                && r[susp_off + 5] == 0xEF
            {
                susp_active = true;
            }
        }
    }

    let mut walker = Walker {
        tree: &tree,
        joliet: false,
        susp_active,
        visited: BTreeSet::new(),
        entries: Vec::new(),
        use_rr: false,
    };
    walker.walk(pvd.root.extent, pvd.root.ext_attr_len, pvd.root.size, "", 0)?;
    let use_rr = walker.use_rr;
    let mut entries = walker.entries;

    // If Rock Ridge gave us no names at all and a Joliet tree exists,
    // re-decode via the SVD so UCS-2 names win over ISO uppercase.
    if !use_rr && let Some(svd) = &joliet_svd {
        let stree = Tree {
            input,
            blksz: svd.logical_block_size,
        };
        let mut jw = Walker {
            tree: &stree,
            joliet: true,
            susp_active,
            visited: BTreeSet::new(),
            entries: Vec::new(),
            use_rr: false,
        };
        jw.walk(svd.root.extent, svd.root.ext_attr_len, svd.root.size, "", 0)?;
        entries = jw.entries;
    }

    Ok(IsoImage {
        volume_id: pvd.volume_id,
        volume_blocks: pvd.volume_blocks,
        has_rock_ridge: use_rr,
        has_joliet: joliet_svd.is_some(),
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Minimal ISO9660 builder: 2048-byte sectors, PVD at sector 16,
    // terminator at 17, dir data + file data after.
    struct IsoBuilder {
        data: Vec<u8>,
        next_sector: u32,
    }

    impl IsoBuilder {
        fn new() -> Self {
            Self {
                data: vec![0u8; 18 * SECTOR],
                next_sector: 18,
            }
        }

        fn dirent(extent: u32, size: u32, flags: u8, name: &[u8], susp: &[u8]) -> Vec<u8> {
            let mut r = Vec::new();
            let len = 33 + name.len() + usize::from(name.len().is_multiple_of(2)) + susp.len();
            let len = len + usize::from(len % 2 == 1); // record length even
            r.push(len as u8);
            r.push(0); // ext attr
            r.extend_from_slice(&extent.to_le_bytes());
            r.extend_from_slice(&extent.to_be_bytes());
            r.extend_from_slice(&size.to_le_bytes());
            r.extend_from_slice(&size.to_be_bytes());
            r.extend_from_slice(&[120, 1, 2, 3, 4, 5, 0]); // 2020-01-02 03:04:05 GMT
            r.push(flags);
            r.push(0);
            r.push(0);
            r.extend_from_slice(&1u16.to_le_bytes());
            r.extend_from_slice(&1u16.to_be_bytes());
            r.push(name.len() as u8);
            r.extend_from_slice(name);
            if name.len().is_multiple_of(2) {
                r.push(0);
            }
            r.extend_from_slice(susp);
            while r.len() < len {
                r.push(0);
            }
            r
        }

        fn dir_block(ents: &[Vec<u8>]) -> Vec<u8> {
            let mut blk = vec![0u8; SECTOR];
            let mut pos = 0;
            for e in ents {
                blk[pos..pos + e.len()].copy_from_slice(e);
                pos += e.len();
            }
            blk
        }

        fn alloc(&mut self, bytes: &[u8]) -> u32 {
            let s = self.next_sector;
            let off = s as usize * SECTOR;
            if self.data.len() < off + SECTOR {
                self.data.resize(off + SECTOR, 0);
            }
            self.data[off..off + bytes.len()].copy_from_slice(bytes);
            self.next_sector += 1;
            s
        }

        /// Install PVD (and optional terminator) with `root` record
        /// pointing at sector of root dir.
        fn finish(mut self, root_extent: u32, root_size: u32) -> Vec<u8> {
            let p = self.next_sector; // volume size marker
            let s = 16 * SECTOR;
            self.data[s] = 1;
            self.data[s + 1..s + 6].copy_from_slice(b"CD001");
            self.data[s + 6] = 1;
            self.data[s + 40..s + 45].copy_from_slice(b"TESTV");
            self.data[s + 80..s + 84].copy_from_slice(&p.to_le_bytes());
            self.data[s + 84..s + 88].copy_from_slice(&p.to_be_bytes());
            self.data[s + 128..s + 130].copy_from_slice(&2048u16.to_le_bytes());
            self.data[s + 130..s + 132].copy_from_slice(&2048u16.to_be_bytes());
            let rec = Self::dirent(root_extent, root_size, 2, &[0], &[]);
            self.data[s + 156..s + 156 + 34].copy_from_slice(&rec[..34]);
            let t = 17 * SECTOR;
            self.data[t] = 255;
            self.data[t + 1..t + 6].copy_from_slice(b"CD001");
            self.data[t + 6] = 1;
            self.data
        }
    }

    fn plain_iso() -> Vec<u8> {
        let mut b = IsoBuilder::new();
        let hello = b.alloc(b"hello iso\n");
        let f = b.alloc(b"DATA");
        let subd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, b"ONE.DAT;1", &[]),
        ]);
        let sub = b.alloc(&subd);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(hello, 10, 0, b"HELLO.TXT;1", &[]),
            IsoBuilder::dirent(sub, SECTOR as u32, 2, b"SUB", &[]),
        ]);
        let root = b.alloc(&rootd);
        // fix "." / ".." extents in root/sub blocks
        b.finish(root, SECTOR as u32)
    }

    #[test]
    fn decode_plain_iso() {
        let img = plain_iso();
        let out = decode(&img).unwrap();
        assert_eq!(out.volume_id, "TESTV");
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["HELLO.TXT", "SUB", "SUB/ONE.DAT"]);
        assert_eq!(out.entries[0].data, b"hello iso\n");
        assert_eq!(out.entries[0].kind, IsoKind::File);
        assert_eq!(out.entries[1].kind, IsoKind::Directory);
        assert_eq!(out.entries[2].data, b"DATA");
        assert!(!out.has_rock_ridge);
        assert!(!out.has_joliet);
    }

    #[test]
    fn rejects_truncated() {
        assert!(matches!(
            decode(&vec![0u8; 1000]),
            Err(Error::UnexpectedEof)
        ));
        let img = plain_iso();
        assert!(decode(&img[..16 * SECTOR]).is_err());
    }

    #[test]
    fn rejects_bad_pvd() {
        let mut img = plain_iso();
        img[16 * SECTOR + 1] = b'X';
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rr_names_and_symlink() {
        // Build a small RR image: root ".": SP entry, file with NM+PX+SL.
        let mut b = IsoBuilder::new();
        let target = b.alloc(b"real content");
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // NM entry: sig NM, len = 5 + name length.
        let mut fsusp = Vec::new();
        let mut nm = vec![b'N', b'M', (5 + 13) as u8, 1, 0];
        nm.extend_from_slice(b"real-name.txt");
        fsusp.extend_from_slice(&nm);
        // PX entry (44 bytes)
        let mut px = vec![b'P', b'X', 44, 1];
        px.extend_from_slice(&0o100640u32.to_le_bytes());
        px.extend_from_slice(&0o100640u32.to_be_bytes());
        px.extend_from_slice(&2u32.to_le_bytes());
        px.extend_from_slice(&2u32.to_be_bytes());
        px.extend_from_slice(&500u32.to_le_bytes());
        px.extend_from_slice(&500u32.to_be_bytes());
        px.extend_from_slice(&42u32.to_le_bytes());
        px.extend_from_slice(&42u32.to_be_bytes());
        px.extend_from_slice(&9u32.to_le_bytes());
        px.extend_from_slice(&9u32.to_be_bytes());
        fsusp.extend_from_slice(&px);
        // symlink record: SL with components "hello.txt"
        let mut sl = vec![b'S', b'L', (5 + 2 + 9) as u8, 1, 0, 0, 9];
        sl.extend_from_slice(b"hello.txt");
        let link_susp = sl;
        let link_extent = b.alloc(&[]); // symlink data extent unused
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(target, 12, 0, b"REAL.TXT;1", &fsusp),
            IsoBuilder::dirent(link_extent, 0, 0, b"LINK.TXT;1", &link_susp),
        ]);
        let root = b.alloc(&rootd);
        let mut img = b.finish(root, SECTOR as u32);
        // patch "." and ".." extents in root block (first two dirents)
        for i in 0..2 {
            let base = root as usize * SECTOR
                + if i == 0 {
                    0
                } else {
                    img[root as usize * SECTOR] as usize
                };
            img[base + 2..base + 6].copy_from_slice(&root.to_le_bytes());
            img[base + 6..base + 10].copy_from_slice(&root.to_be_bytes());
            img[base + 10..base + 14].copy_from_slice(&(SECTOR as u32).to_le_bytes());
            img[base + 14..base + 18].copy_from_slice(&(SECTOR as u32).to_be_bytes());
        }
        // symlink needs mode 0o120777 via PX to be recognized
        // (add PX to link record): not present -> kind File with empty data;
        // acceptable: verify NM name + file decode.
        let out = decode(&img).unwrap();
        assert!(out.has_rock_ridge);
        assert_eq!(out.entries[0].name, "real-name.txt");
        assert_eq!(out.entries[0].mode, 0o100640);
        assert_eq!(out.entries[0].uid, 500);
        assert_eq!(out.entries[0].data, b"real content");
        assert_eq!(out.entries[1].name, "LINK.TXT");
        assert_eq!(out.entries[1].data, b"");
    }

    #[test]
    fn rr_symlink_with_px() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // SL + PX(mode=0120777)
        let mut susp = vec![b'S', b'L', 16, 1, 0, 0, 9];
        susp.extend_from_slice(b"hello.txt");
        susp.extend_from_slice(&[b'P', b'X', 44, 1]);
        susp.extend_from_slice(&0o120777u32.to_le_bytes());
        susp.extend_from_slice(&0o120777u32.to_be_bytes());
        susp.extend_from_slice(&1u32.to_le_bytes());
        susp.extend_from_slice(&1u32.to_be_bytes());
        susp.extend_from_slice(&0u32.to_le_bytes());
        susp.extend_from_slice(&0u32.to_be_bytes());
        susp.extend_from_slice(&0u32.to_le_bytes());
        susp.extend_from_slice(&0u32.to_be_bytes());
        susp.extend_from_slice(&1u32.to_le_bytes());
        susp.extend_from_slice(&1u32.to_be_bytes());
        let ext = b.alloc(&[]);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(ext, 0, 0, b"LINK.TXT;1", &susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries[0].kind, IsoKind::Symlink);
        assert_eq!(out.entries[0].data, b"hello.txt");
    }
}
