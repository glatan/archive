//! ISO 9660 (ECMA-119) image decoder with Rock Ridge (IEEE P1282)
//! and Joliet supplementary volume support.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

const SECTOR: usize = 2048;
const VD_START: usize = 16 * SECTOR;
const VD_ID: &[u8; 5] = b"CD001";

const VD_TYPE_BOOT: u8 = 0;
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

/// Content of an ISO 9660 extended attribute record (ECMA-119
/// §9.5): owner/group identification, a deny-bit permission mask,
/// the four file timestamps and record metadata. The record is
/// stored in the `ext_attr_len` logical blocks preceding the file
/// data (the first File Unit when interleaved, §6.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XaRecord {
    /// Owner identification (BP 1-4).
    pub owner_id: u16,
    /// Group identification (BP 5-8).
    pub group_id: u16,
    /// Raw 16-bit permission mask (BP 9-10, big-endian). A set bit
    /// denies the access: bits 4/6 = owner read/exec, 8/10 = group,
    /// 12/14 = other; bits 0/2 are the "system" owner class.
    pub permissions: u16,
    /// File creation date (BP 11-27, §8.4.26.1 format).
    pub creation_time: Option<i64>,
    /// File modification date (BP 28-44).
    pub modification_time: Option<i64>,
    /// File expiration date (BP 45-61); `None` = unspecified.
    pub expiration_time: Option<i64>,
    /// File effective date (BP 62-78).
    pub effective_time: Option<i64>,
    /// Record format byte (BP 79; 0 = unspecified).
    pub record_format: u8,
    /// Record attributes byte (BP 80).
    pub record_attributes: u8,
    /// Record length (BP 81-84, both-endian).
    pub record_length: u16,
    /// System identifier, padding removed (BP 85-116).
    pub system_id: String,
    /// Length of the application-use area at BP 251+ (LEN_AU).
    pub application_use_len: u16,
    /// Length of the escape sequences after the fixed part
    /// (LEN_ESC).
    pub escape_seq_len: u8,
}

/// Sparse-file encoding parameters from a Rock Ridge `SF` entry
/// (RRIP 1.12 §4.1.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrSparse {
    /// Virtual file size: SIZE HIGH << 32 | SIZE LOW (BP5-20).
    pub size: u64,
    /// Index-block table depth (BP 21).
    pub table_depth: u8,
}

/// A SUSP extension reference: `ER` fields advertise an extension
/// in use and `ES` selector fields mark the extension applying to
/// the entries that follow (SUSP 1.10 `fields.nr`; ES adds the
/// EXT_SEQ byte ahead of the shared LEN_ID/LEN_DES/LEN_SRC/EXT_VER
/// header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspExt {
    /// `ES` extension sequence number (BP 5); `None` for `ER`.
    pub sequence: Option<u8>,
    /// Extension version byte (EXT_VER).
    pub version: u8,
    /// Extension identifier bytes (EXT_ID).
    pub id: Vec<u8>,
    /// Extension descriptor bytes (EXT_DES).
    pub descriptor: Vec<u8>,
    /// Extension source bytes (EXT_SRC).
    pub source: Vec<u8>,
}

/// Apple ISO 9660 extension content (TN FL36). `AA` is the
/// current signature (BP3 = length, BP4 = SystemUseID); `BA` is
/// the old signature with no length byte (BP3 = SystemUseID, the
/// record length implied by the ID). Both decode into the same
/// variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleExt {
    /// HFS metadata (`AA` ID $02, `BA` ID $06).
    Hfs {
        /// HFS fileType (MSB-LSB).
        file_type: [u8; 4],
        /// HFS fileCreator.
        file_creator: [u8; 4],
        /// HFS finder flags (big-endian u16).
        finder_flags: u16,
    },
    /// ProDOS metadata (`AA`/`BA` ID $01).
    ProDos {
        /// ProDOS file type byte.
        file_type: u8,
        /// ProDOS aux type (LSB-MSB u16).
        aux_type: u16,
    },
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
    /// present, else the extended attribute record's permission bits
    /// (deny-bit semantics inverted to r-x), else `0o040555` for
    /// directories / `0o100444` for files, matching read-only media
    /// semantics.
    pub mode: u32,
    /// Owner uid (Rock Ridge `PX`, else the extended attribute
    /// record's owner id; 0 otherwise).
    pub uid: u32,
    /// Owner gid (Rock Ridge `PX`, else the extended attribute
    /// record's group id; 0 otherwise).
    pub gid: u32,
    /// Hard link count (Rock Ridge `PX`; 1 otherwise).
    pub nlink: u32,
    /// Device number for character/block special files (Rock Ridge
    /// `PN`, RRIP §4.1.2); `None` when no `PN` entry is present.
    /// Only meaningful when `kind` is `IsoKind::Other` with a
    /// device `S_IFMT`.
    pub dev_t: Option<u64>,
    /// Inode / file serial number (Rock Ridge `PX` BP37-44; 0 when
    /// absent). Entries sharing the value are defined as links to
    /// the same file or directory (RRIP 1.12 §4.1.3).
    pub ino: u32,
    /// Modification time, seconds since the Unix epoch (Rock Ridge
    /// `TF` modify time, else the extended attribute record's
    /// modification date, else the 7-byte directory record time).
    pub mtime: i64,
    /// Parsed extended attribute record (ECMA-119 §9.5), present
    /// when the record's Extended Attribute Length is nonzero.
    /// For multi-extent files the record of the last section is
    /// used (§6.4.6).
    pub xa: Option<XaRecord>,
    /// Sparse file parameters (Rock Ridge `SF`, RRIP §4.1.7).
    /// `data` then holds the on-disc sparse encoding (header block,
    /// index blocks and data); `size` is the virtual file size.
    pub sparse: Option<RrSparse>,
    /// SUSP `ER`/`ES` extension references found on the record.
    pub susp_ext: Vec<SuspExt>,
    /// Apple `AA`/`BA` extension records found on the record
    /// (TN FL36).
    pub apple: Vec<AppleExt>,
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

/// One record of the ISO 9660 Path Table (ECMA-119 §9.4): a
/// breadth-first index of every directory on the volume, redundant
/// with the directory-record tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTableEntry {
    /// Raw directory identifier bytes. The root directory is a
    /// single `\x00` byte.
    pub name: Vec<u8>,
    /// Extent (logical block number) of the directory.
    pub extent: u32,
    /// 1-based index of the parent record in the path table.
    pub parent: u16,
}

/// One boot catalog entry (El Torito 1.0 §2.5): the initial/default
/// entry and every section entry describe a bootable image.
#[derive(Debug, Clone)]
pub struct ElToritoEntry {
    /// Boot indicator byte is 0x88 (image marked bootable).
    pub bootable: bool,
    /// Boot media type: 0 = no emulation, 1 = 1.2M floppy,
    /// 2 = 1.44M floppy, 3 = 2.88M floppy, 4 = hard disk.
    pub media_type: u8,
    /// Load segment (0 means the default 0x07C0).
    pub load_segment: u16,
    /// System type byte (partition type for hard-disk emulation).
    pub system_type: u8,
    /// Virtual sectors to load, in 512-byte units.
    pub sector_count: u16,
    /// LBA of the boot image on the volume.
    pub load_lba: u32,
    /// Boot image contents (sector_count*512 bytes at load_lba).
    pub image: Vec<u8>,
}

/// El Torito 1.0 boot catalog decoded from a boot record volume
/// descriptor (type 0, system id "EL TORITO SPECIFICATION").
#[derive(Debug, Clone)]
pub struct ElTorito {
    /// LBA of the boot catalog sector.
    pub catalog_lba: u32,
    /// Platform id from the validation entry (0 = x86, 1 = PowerPC,
    /// 2 = Macintosh; 0xEF is used by UEFI-era images).
    pub platform: u8,
    /// Developer/vendor id string from the validation entry,
    /// trailing NUL/space padding removed.
    pub id_string: String,
    /// Catalog boot entries: index 0 is the initial/default entry.
    pub entries: Vec<ElToritoEntry>,
}

/// Textual metadata and volume timestamps carried by a primary
/// or supplementary volume descriptor (ECMA-119 §8.4.5,
/// §8.4.19-8.4.29). String fields have their trailing space/NUL
/// padding removed; on a Joliet SVD they are decoded as UCS-2BE.
/// Empty fields decode as empty strings.
#[derive(Debug, Clone, Default)]
pub struct VolumeMeta {
    /// System identifier (§8.4.5; a-characters).
    pub system_id: String,
    /// Volume set identifier (§8.4.19; d-characters).
    pub volume_set_id: String,
    /// Publisher identifier (§8.4.20; a-characters).
    pub publisher_id: String,
    /// Data preparer identifier (§8.4.21; a-characters).
    pub data_preparer_id: String,
    /// Application identifier (§8.4.22; a-characters).
    pub application_id: String,
    /// Copyright file identifier (§8.4.23; d-characters).
    pub copyright_file_id: String,
    /// Abstract file identifier (§8.4.24; d-characters).
    pub abstract_file_id: String,
    /// Bibliographic file identifier (§8.4.25; d-characters).
    pub bibliographic_file_id: String,
    /// Volume creation time (§8.4.26) as Unix seconds; `None`
    /// when the field is unspecified (all `'0'` digits, tz 0)
    /// or not parseable.
    pub creation_time: Option<i64>,
    /// Volume modification time (§8.4.27) as Unix seconds.
    pub modification_time: Option<i64>,
    /// Volume expiration time (§8.4.28) as Unix seconds; `None`
    /// means no expiration is recorded.
    pub expiration_time: Option<i64>,
    /// Volume effective time (§8.4.29) as Unix seconds.
    pub effective_time: Option<i64>,
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
    /// Type-L path table records from the primary volume descriptor
    /// (ECMA-119 §9.4), in table order. Empty when the descriptor
    /// does not reference a usable table.
    pub path_table: Vec<PathTableEntry>,
    /// El Torito boot catalogs found on boot record volume
    /// descriptors (El Torito 1.0 §2), in descriptor order. Empty for
    /// non-bootable images.
    pub el_torito: Vec<ElTorito>,
    /// Metadata strings and volume timestamps from the primary
    /// volume descriptor (ECMA-119 §8.4).
    pub meta: VolumeMeta,
    /// The same descriptor fields decoded from the Joliet
    /// supplementary volume descriptor (UCS-2BE strings), when one
    /// is present.
    pub joliet_meta: Option<VolumeMeta>,
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

/// Unix seconds for a broken-down civil time; `tz` is the signed
/// 15-minute GMT offset byte shared by both ISO9660 time formats.
fn civil_unix(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64, tz: i64) -> i64 {
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
    civil_unix(year, month, day, hour, min, sec, tz)
}

/// a/d-character descriptor field with trailing space/NUL padding
/// removed.
fn dec_str(raw: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(raw).into_owned();
    while s.ends_with(' ') || s.ends_with('\x00') {
        s.pop();
    }
    s
}

/// 17-byte volume descriptor timestamp (ECMA-119 §8.4.26.1):
/// 16 ASCII digits "YYYYMMDDHHMMSSCC" followed by a signed tz
/// byte in 15-minute units. Returns `None` when the field is
/// unspecified (all digits `'0'` and tz 0) or not parseable.
fn dec_vd_datetime(b: &[u8], o: usize) -> Option<i64> {
    let f = b.get(o..o + 17)?;
    if f[..16].iter().all(|&c| c == b'0') && f[16] == 0 {
        return None;
    }
    let field = |lo: usize, hi: usize| -> Option<i64> {
        let mut v = 0i64;
        for &c in &f[lo..hi] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + i64::from(c - b'0');
        }
        Some(v)
    };
    let year = field(0, 4)?;
    let month = field(4, 6)?;
    let day = field(6, 8)?;
    let hour = field(8, 10)?;
    let min = field(10, 12)?;
    let sec = field(12, 14)?;
    // The hundredths field is below the resolution we expose but
    // still must be digits.
    field(14, 16)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    Some(civil_unix(
        year,
        month,
        day,
        hour,
        min,
        sec,
        f[16] as i8 as i64,
    ))
}

/// Parse the fixed part of an extended attribute record
/// (ECMA-119 §9.5): 250 bytes at the start of a file section's
/// extended attribute blocks, followed by LEN_AU application-use
/// bytes and LEN_ESC escape sequences. The record version (BP 181)
/// must be 1; all 723 fields are checked for both-endian
/// agreement.
fn parse_xa(data: &[u8]) -> Result<XaRecord, Error> {
    if data.len() < 250 {
        return Err(Error::InvalidData(
            "iso9660 short extended attribute record",
        ));
    }
    if data[180] != 1 {
        return Err(Error::InvalidData("iso9660 bad extended attribute version"));
    }
    Ok(XaRecord {
        owner_id: both16(data, 0)?,
        group_id: both16(data, 4)?,
        permissions: u16be(data, 8),
        creation_time: dec_vd_datetime(data, 10),
        modification_time: dec_vd_datetime(data, 27),
        expiration_time: dec_vd_datetime(data, 44),
        effective_time: dec_vd_datetime(data, 61),
        record_format: data[78],
        record_attributes: data[79],
        record_length: both16(data, 80)?,
        system_id: dec_str(&data[84..116]),
        application_use_len: both16(data, 246)?,
        escape_seq_len: data[181],
    })
}

/// Apple `AA`/`BA` payload decode (TN FL36). `id` is the
/// SystemUseID and `p` the bytes that follow it; HFS IDs are $02
/// (`AA`) / $06 (`BA`), ProDOS is $01 in both signatures.
fn apple_ext(id: u8, p: &[u8]) -> Option<AppleExt> {
    match id {
        // HFS: fileType(4) + fileCreator(4) + finder flags(2, MSB-LSB).
        2 | 6 if p.len() >= 10 => Some(AppleExt::Hfs {
            file_type: [p[0], p[1], p[2], p[3]],
            file_creator: [p[4], p[5], p[6], p[7]],
            finder_flags: u16be(p, 8),
        }),
        // ProDOS: file type + aux type (LSB-MSB).
        1 if p.len() >= 3 => Some(AppleExt::ProDos {
            file_type: p[0],
            aux_type: u16le(p, 1),
        }),
        _ => None,
    }
}

/// Parsed directory record fields (ECMA-119 §9.1).
struct DirRec<'a> {
    extent: u32,
    ext_attr_len: u8,
    size: u32,
    flags: u8,
    /// File Unit Size in logical blocks (BP27; `0` = not
    /// interleaved).
    unit_size: u8,
    /// Interleave Gap Size in logical blocks (BP28).
    gap_size: u8,
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
        f(DirRec {
            extent: both32(r, 2)?,
            ext_attr_len: r[1],
            size: both32(r, 10)?,
            flags: r[25],
            unit_size: r[26],
            gap_size: r[27],
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
    /// ZF (zisofs) parameters, when the entry is compressed.
    zisofs: Option<ZfParams>,
    /// PN device number for char/block devices (RRIP §4.1.2).
    dev_t: Option<u64>,
    /// CL child link: logical block of the extent holding this
    /// directory's real records (RRIP §4.1.5 relocation).
    cl: Option<u32>,
    /// RE marker: this record is a relocated directory's copy in
    /// the relocation directory and is not enumerated.
    relocated: bool,
    /// PX file serial number (inode; BP37-44, RRIP §4.1.3).
    ino: Option<u32>,
    /// SF sparse file parameters (RRIP §4.1.7).
    sparse: Option<RrSparse>,
    /// SUSP `ER`/`ES` extension references.
    susp_ext: Vec<SuspExt>,
    /// Apple `AA`/`BA` extension records (TN FL36).
    apple: Vec<AppleExt>,
}

fn parse_susp(img: &[u8], blksz: usize, mut area: &[u8], depth: usize) -> Result<RrInfo, Error> {
    if depth > 4 {
        return Err(Error::InvalidData("iso9660 SUSP continuation loop"));
    }
    let mut rr = RrInfo::default();
    let mut cont: Option<(u64, u64, u64)> = None;
    while area.len() >= 4 {
        // Apple `BA` records (TN FL36, old signature) carry no
        // length byte: BP3 is the SystemUseID and the record
        // length is implied by it.
        let len = if &area[..2] == b"BA" {
            match area[2] {
                1 => 6,
                6 => 13,
                _ => break,
            }
        } else {
            area[2] as usize
        };
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
                    // File serial number (BP37-44, RRIP §4.1.3):
                    // shared values mark hard links.
                    rr.ino = Some(both32(e, 36)?);
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
            b"ZF" => {
                // zisofs transparent compression entry (16 bytes):
                // algorithm "pz" + parms (header size in 4-byte
                // words, log2 block size) + both-endian uncompressed
                // size. See zisofs_inflate for the format references.
                if len < 16 {
                    return Err(Error::InvalidData("iso9660 short ZF entry"));
                }
                if e[4] != b'p' || e[5] != b'z' {
                    return Err(Error::Unsupported("iso9660 unsupported ZF algorithm"));
                }
                rr.zisofs = Some(ZfParams {
                    header_words: e[6],
                    block_shift: e[7],
                    uncompressed_size: both32(e, 8)?,
                });
            }
            b"PN" => {
                // RRIP §4.1.2: both-endian Dev_t High then Dev_t
                // Low; the device number for char/block inodes.
                if len < 20 {
                    return Err(Error::InvalidData("iso9660 bad PN entry"));
                }
                let high = u64::from(both32(e, 4)?);
                let low = u64::from(both32(e, 12)?);
                rr.dev_t = Some(high << 32 | low);
            }
            b"CL" => {
                // RRIP §4.1.5: both-endian LBN of the extent that
                // really holds this (relocated) child directory.
                if len < 12 {
                    return Err(Error::InvalidData("iso9660 bad CL entry"));
                }
                rr.cl = Some(both32(e, 4)?);
            }
            b"RE" => rr.relocated = true,
            b"SF" => {
                // RRIP §4.1.7: both-endian SIZE HIGH and SIZE LOW
                // (the virtual file size) plus the index-block
                // table depth.
                if len < 21 {
                    return Err(Error::InvalidData("iso9660 bad SF entry"));
                }
                let hi = u64::from(both32(e, 4)?);
                let lo = u64::from(both32(e, 12)?);
                rr.sparse = Some(RrSparse {
                    size: hi << 32 | lo,
                    table_depth: e[20],
                });
            }
            b"ER" | b"ES" => {
                // SUSP ER/ES share LEN_ID + LEN_DES + LEN_SRC +
                // EXT_VER + EXT_ID/EXT_DES/EXT_SRC; ES inserts
                // EXT_SEQ at BP5.
                let es = sig == *b"ES";
                let hdrlen = if es { 9 } else { 8 };
                if len < hdrlen {
                    return Err(Error::InvalidData("iso9660 bad ER/ES entry"));
                }
                let o = if es { 5usize } else { 4 };
                let (id_len, des_len, src_len) =
                    (e[o] as usize, e[o + 1] as usize, e[o + 2] as usize);
                let body = &e[o + 4..];
                if id_len + des_len + src_len > body.len() {
                    return Err(Error::InvalidData("iso9660 bad ER/ES entry"));
                }
                rr.susp_ext.push(SuspExt {
                    sequence: if es { Some(e[4]) } else { None },
                    version: e[o + 3],
                    id: body[..id_len].to_vec(),
                    descriptor: body[id_len..id_len + des_len].to_vec(),
                    source: body[id_len + des_len..id_len + des_len + src_len].to_vec(),
                });
            }
            // PD: padding field; its contents are ignored in
            // interchange per SUSP.
            b"PD" => {}
            b"AA" => {
                // TN FL36 v2 signature: BP4 is the SystemUseID
                // (the BP3 slot is the length already consumed).
                if len >= 5
                    && let Some(a) = apple_ext(e[3], &e[4..])
                {
                    rr.apple.push(a);
                }
            }
            b"BA" => {
                // Old signature: BP3 is the SystemUseID and `len`
                // was derived from it above.
                if let Some(a) = apple_ext(e[2], &e[3..]) {
                    rr.apple.push(a);
                }
            }
            // PL (RRIP §4.1.5 parent link on `..`), RR, AS,
            // unknown: informational for a path-based walk.
            _ => {}
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
        if rr.zisofs.is_none() {
            rr.zisofs = cont_rr.zisofs;
        }
        if rr.dev_t.is_none() {
            rr.dev_t = cont_rr.dev_t;
        }
        if rr.cl.is_none() {
            rr.cl = cont_rr.cl;
        }
        rr.relocated = rr.relocated || cont_rr.relocated;
        if rr.ino.is_none() {
            rr.ino = cont_rr.ino;
        }
        if rr.sparse.is_none() {
            rr.sparse = cont_rr.sparse;
        }
        rr.susp_ext.extend(cont_rr.susp_ext);
        rr.apple.extend(cont_rr.apple);
    }
    Ok(rr)
}

struct VolDesc {
    volume_id: String,
    volume_blocks: u32,
    logical_block_size: usize,
    /// Type-L path table extent (logical block) and byte size from
    /// the volume descriptor; `0` when absent.
    path_table_extent: u32,
    path_table_size: u32,
    root: DirRecOwned,
    /// Descriptor metadata strings and volume timestamps.
    meta: VolumeMeta,
}

#[derive(Clone, Copy)]
struct DirRecOwned {
    extent: u32,
    ext_attr_len: u8,
    size: u32,
    flags: u8,
    /// File Unit Size / Interleave Gap Size (BP27/BP28).
    unit_size: u8,
    gap_size: u8,
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
    // Character fields are a/d-characters in the PVD and UCS-2BE
    // in a Joliet SVD (per the Joliet spec the SVD carries every
    // character field in the declared supplementary encoding).
    let dec_field = |raw: &[u8]| {
        if joliet {
            decode_ucs2(raw)
        } else {
            dec_str(raw)
        }
    };
    let volume_id = dec_field(&sec[40..72]);
    let volume_blocks = both32(sec, 80)?;
    let lbs = both16(sec, 128)? as usize;
    if !lbs.is_power_of_two() || !(512..=32 * 1024).contains(&lbs) {
        return Err(Error::InvalidData("iso9660 bad logical block size"));
    }
    // Path table size is a both-endian 32-bit field (ECMA-119
    // §9.4.8); the type-L table extent is little-endian (§9.4.9).
    let path_table_size = both32(sec, 132)?;
    let path_table_extent = u32le(sec, 140);
    // Root directory record (ECMA-119 §9.1), fixed 34 bytes at 156.
    let r = &sec[156..190];
    if r[0] != 34 {
        return Err(Error::InvalidData("iso9660 bad root record"));
    }
    // Descriptor metadata (ECMA-119 §8.4.5, §8.4.19-8.4.29).
    let meta = VolumeMeta {
        system_id: dec_field(&sec[8..40]),
        volume_set_id: dec_field(&sec[190..318]),
        publisher_id: dec_field(&sec[318..446]),
        data_preparer_id: dec_field(&sec[446..574]),
        application_id: dec_field(&sec[574..702]),
        copyright_file_id: dec_field(&sec[702..739]),
        abstract_file_id: dec_field(&sec[739..776]),
        bibliographic_file_id: dec_field(&sec[776..813]),
        creation_time: dec_vd_datetime(sec, 813),
        modification_time: dec_vd_datetime(sec, 830),
        expiration_time: dec_vd_datetime(sec, 847),
        effective_time: dec_vd_datetime(sec, 864),
    };
    Ok(VolDesc {
        volume_id,
        volume_blocks,
        logical_block_size: lbs,
        path_table_extent,
        path_table_size,
        root: DirRecOwned {
            extent: both32(r, 2)?,
            ext_attr_len: r[1],
            size: both32(r, 10)?,
            flags: r[25],
            unit_size: r[26],
            gap_size: r[27],
            mtime: dec_datetime(r, 18),
        },
        meta,
    })
}

/// Parse a type-L (little-endian) path table (ECMA-119 §9.4).
/// Records are `len_di(1) + ext_attr_len(1) + extent(4,LE) +
/// parent(2,LE) + dir_id(len_di)`, with dir_id padded to an even
/// length. Trailing padding or a malformed record ends the table
/// (tolerated, matching the directory-record policy).
fn parse_path_table(data: &[u8]) -> Vec<PathTableEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= data.len() {
        let len_di = data[pos] as usize;
        if len_di == 0 || pos + 8 + len_di > data.len() {
            break;
        }
        entries.push(PathTableEntry {
            name: data[pos + 8..pos + 8 + len_di].to_vec(),
            extent: u32le(data, pos + 2),
            parent: u16le(data, pos + 6),
        });
        pos += 8 + len_di + usize::from(len_di % 2 == 1);
    }
    entries
}

/// Read and parse the type-L path table referenced by a volume
/// descriptor. The table is redundant with the directory tree
/// walk, so a missing or out-of-range table yields an empty
/// vector instead of an error.
fn read_path_table(img: &[u8], vd: &VolDesc) -> Vec<PathTableEntry> {
    if vd.path_table_extent == 0 || vd.path_table_size == 0 {
        return Vec::new();
    }
    let Some(start) = u64::from(vd.path_table_extent)
        .checked_mul(vd.logical_block_size as u64)
        .and_then(|v| usize::try_from(v).ok())
    else {
        return Vec::new();
    };
    let Some(bytes) = start
        .checked_add(vd.path_table_size as usize)
        .and_then(|end| img.get(start..end))
    else {
        return Vec::new();
    };
    parse_path_table(bytes)
}

fn decode_ucs2(b: &[u8]) -> String {
    let (pairs, _) = b.as_chunks::<2>();
    // Joliet names are UCS-2BE but writers may emit UTF-16 surrogate
    // pairs for non-BMP code points; `char::decode_utf16` combines
    // them and maps lone surrogates to U+FFFD.
    let mut s = String::new();
    for r in char::decode_utf16(
        pairs
            .iter()
            .map(|p| u16::from_be_bytes(*p))
            .take_while(|&u| u != 0),
    ) {
        s.push(r.unwrap_or(char::REPLACEMENT_CHARACTER));
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
    /// Read `size` bytes starting at logical block
    /// `extent + ext_attr_len`, honoring interleaved recording
    /// (ECMA-119 §6.4.3, §9.1.7/§9.1.8): when `unit_size` is
    /// nonzero the data is stored in File Units of `unit_size`
    /// blocks separated by `gap_size` skipped blocks.
    fn read_file(&self, rec: &DirRecOwned) -> Result<Vec<u8>, Error> {
        let start = u64::from(rec.extent)
            .checked_add(u64::from(rec.ext_attr_len))
            .and_then(|v| v.checked_mul(self.blksz as u64))
            .ok_or(Error::InvalidData("iso9660 extent offset overflow"))?;
        let start = usize::try_from(start)
            .map_err(|_| Error::InvalidData("iso9660 extent offset overflow"))?;
        if rec.unit_size == 0 {
            // A nonzero gap without a File Unit is contradictory.
            if rec.gap_size != 0 {
                return Err(Error::InvalidData(
                    "iso9660 interleave gap without file unit",
                ));
            }
            let end = start
                .checked_add(rec.size as usize)
                .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
            return Ok(self
                .input
                .get(start..end)
                .ok_or(Error::InvalidData("iso9660 extent out of range"))?
                .to_vec());
        }
        let unit = usize::from(rec.unit_size) * self.blksz;
        let stride = (usize::from(rec.unit_size) + usize::from(rec.gap_size)) * self.blksz;
        let mut out = Vec::with_capacity(rec.size as usize);
        // An extended attribute record fills the whole first File
        // Unit (ECMA-119 6.4.4: ext_attr_len == unit_size), so the
        // data begins with the second File Unit, past the gap.
        let mut off = if rec.ext_attr_len != 0 {
            start
                .checked_add(usize::from(rec.gap_size) * self.blksz)
                .ok_or(Error::InvalidData("iso9660 extent out of range"))?
        } else {
            start
        };
        let mut remaining = rec.size as usize;
        while remaining > 0 {
            let want = remaining.min(unit);
            let end = off
                .checked_add(want)
                .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
            out.extend_from_slice(
                self.input
                    .get(off..end)
                    .ok_or(Error::InvalidData("iso9660 extent out of range"))?,
            );
            remaining -= want;
            off = off
                .checked_add(stride)
                .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
        }
        Ok(out)
    }

    /// Concatenate the extents of a (possibly multi-extent) file
    /// (ECMA-119 §9.1.6 bit 7 / §9.2). Single-extent files have a
    /// one-element `parts` slice.
    fn read_parts(&self, parts: &[DirRecOwned]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        for p in parts {
            out.extend_from_slice(&self.read_file(p)?);
        }
        Ok(out)
    }

    /// Read the extended attribute record preceding a file
    /// section's data (ECMA-119 §6.4, §9.1.2). The EA occupies the
    /// first `ext_attr_len` logical blocks of the extent — the
    /// first File Unit when interleaved — so the same byte range
    /// holds it in both recording modes. An all-zero EA area is
    /// reported as absent.
    fn read_xa(&self, rec: &DirRecOwned) -> Result<Option<XaRecord>, Error> {
        if rec.ext_attr_len == 0 {
            return Ok(None);
        }
        // An interleaved file section places its EA in the first
        // File Unit, so its block count must equal the File Unit
        // Size (§6.4.4).
        if rec.unit_size != 0 && rec.ext_attr_len != rec.unit_size {
            return Err(Error::InvalidData("iso9660 bad extended attribute length"));
        }
        let start = u64::from(rec.extent)
            .checked_mul(self.blksz as u64)
            .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
        let start = usize::try_from(start)
            .map_err(|_| Error::InvalidData("iso9660 extent out of range"))?;
        let len = usize::from(rec.ext_attr_len)
            .checked_mul(self.blksz)
            .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
        let data = self
            .input
            .get(
                start
                    ..start
                        .checked_add(len)
                        .ok_or(Error::InvalidData("iso9660 extent out of range"))?,
            )
            .ok_or(Error::InvalidData("iso9660 extent out of range"))?;
        if data.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        parse_xa(data).map(Some)
    }

    /// Read the `.` record of the directory at logical block
    /// `lbn` and return it as the record describing that
    /// directory. Used to resolve a Rock Ridge `CL` child link
    /// (RRIP §4.1.5), which carries only the target extent's LBN.
    fn dir_dot(&self, lbn: u32) -> Result<DirRecOwned, Error> {
        let start = u64::from(lbn)
            .checked_mul(self.blksz as u64)
            .ok_or(Error::InvalidData("iso9660 CL target out of range"))?;
        let start = usize::try_from(start)
            .map_err(|_| Error::InvalidData("iso9660 CL target out of range"))?;
        let end = start.saturating_add(self.blksz).min(self.input.len());
        let blk = self
            .input
            .get(start..end)
            .ok_or(Error::InvalidData("iso9660 CL target out of range"))?;
        let len = blk.first().copied().unwrap_or(0) as usize;
        if len < 34 || len > blk.len() {
            return Err(Error::InvalidData("iso9660 bad CL target"));
        }
        let r = &blk[..len];
        if r[32] != 1 || r[33] != 0 || r[25] & FLAG_DIR == 0 {
            return Err(Error::InvalidData("iso9660 bad CL target"));
        }
        Ok(DirRecOwned {
            extent: both32(r, 2)?,
            ext_attr_len: r[1],
            size: both32(r, 10)?,
            flags: r[25],
            unit_size: r[26],
            gap_size: r[27],
            mtime: dec_datetime(r, 18),
        })
    }
}

/// zisofs compressed file magic (H. Peter Anvin's zisofs format;
/// the same byte string is checked by Linux `fs/isofs` and
/// zisofs-tools `mkzftree`/`uncompress.c`).
const ZISOFS_MAGIC: [u8; 8] = [0x37, 0xE4, 0x53, 0x96, 0xC9, 0xDB, 0xD6, 0x07];

/// Parameters carried by a Rock Ridge `ZF` system use entry
/// (zisofs). Field names follow the zisofs spec: the `pz`
/// algorithm's `parms[0]` is the on-file header size in 4-byte
/// words and `parms[1]` is the log2 of the uncompressed block size.
#[derive(Debug, Clone, Copy)]
struct ZfParams {
    /// Block pointer table offset within the file, in 4-byte words
    /// (`parms[0]`; 4 for the current 16-byte header).
    header_words: u8,
    /// log2 of the uncompressed block size (`parms[1]`).
    block_shift: u8,
    /// Uncompressed file size (both-endian field of the ZF entry).
    uncompressed_size: u32,
}

/// Transparently decompress a zisofs `ZF`/`pz` file extent.
///
/// Layout (zisofs format by H. Peter Anvin, as implemented by
/// Linux `fs/isofs/compress.c` and zisofs-tools `mkzftree`): the
/// file starts with a 16-byte header — `ZISOFS_MAGIC` (8), the
/// uncompressed size (4, little-endian), `header_words` (1),
/// `block_shift` (1), and 2 reserved bytes — followed at byte
/// offset `header_words * 4` by a table of `nblocks + 1`
/// little-endian u32 absolute byte offsets into the file, then one
/// zlib (RFC 1950) stream per uncompressed block. A block whose
/// two pointers are equal is defined as all zeroes.
fn zisofs_inflate(data: &[u8], zf: ZfParams) -> Result<Vec<u8>, Error> {
    // "pz" requires a 32KiB block (shift 15); 64/128KiB (16/17) are
    // also defined. Other shifts are outside the profile.
    if !(15..=17).contains(&zf.block_shift) {
        return Err(Error::Unsupported("iso9660 zisofs block size"));
    }
    let block_size = 1usize << zf.block_shift;
    let usize_ = zf.uncompressed_size as usize;
    if data.len() < 16 || data[..8] != ZISOFS_MAGIC {
        return Err(Error::InvalidData("iso9660 bad zisofs header"));
    }
    // The file header repeats the ZF entry parameters; the spec
    // requires both to be consistent and correct.
    if u32le(data, 8) != zf.uncompressed_size
        || data[12] != zf.header_words
        || data[13] != zf.block_shift
    {
        return Err(Error::InvalidData("iso9660 zisofs header mismatch"));
    }
    let pt_off = usize::from(zf.header_words) * 4;
    if pt_off < 16 {
        return Err(Error::InvalidData("iso9660 bad zisofs header size"));
    }
    let nblocks = usize_.div_ceil(block_size);
    let pt_end = pt_off
        .checked_add(
            (nblocks + 1)
                .checked_mul(4)
                .ok_or(Error::InvalidData("iso9660 zisofs table overflow"))?,
        )
        .ok_or(Error::InvalidData("iso9660 zisofs table overflow"))?;
    let pt = data.get(pt_off..pt_end).ok_or(Error::InvalidData(
        "iso9660 zisofs pointer table out of range",
    ))?;

    let mut out = Vec::with_capacity(usize_);
    let mut remaining = usize_;
    for i in 0..nblocks {
        let cstart = u32le(pt, i * 4) as usize;
        let cend = u32le(pt, (i + 1) * 4) as usize;
        let csize = cend
            .checked_sub(cstart)
            .ok_or(Error::InvalidData("iso9660 zisofs pointers reversed"))?;
        if cend > data.len() {
            return Err(Error::InvalidData("iso9660 zisofs block out of range"));
        }
        let want = remaining.min(block_size);
        if csize == 0 {
            // Equal pointers: the block is all zeroes.
            out.resize(out.len() + want, 0);
        } else {
            // Sanity bound on the stored stream (mkzftree uses
            // 2 * block_size).
            if csize > 2 * block_size {
                return Err(Error::InvalidData("iso9660 zisofs block too large"));
            }
            let blk =
                crate::compress::zlib::decode::decode_bounded(&data[cstart..cend], block_size)?;
            if blk.len() < want || (remaining > block_size && blk.len() != block_size) {
                return Err(Error::InvalidData("iso9660 zisofs block size mismatch"));
            }
            out.extend_from_slice(&blk[..want]);
        }
        remaining -= want;
    }
    Ok(out)
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
    /// Walk one directory depth-first: reads the directory's own
    /// records and emits its entries. `dir` is the record
    /// holding the directory's extent (or the `.` record a
    /// Rock Ridge `CL` link resolves to).
    fn walk(&mut self, dir: &DirRecOwned, path: &str, depth: usize) -> Result<(), Error> {
        if depth > 64 {
            return Err(Error::InvalidData("iso9660 directory nesting too deep"));
        }
        if !self.visited.insert((dir.extent, dir.size)) {
            return Err(Error::InvalidData("iso9660 directory cycle"));
        }
        let data = self.tree.read_file(dir)?;
        self.scan(&data, path, depth)
    }

    /// Emit the entries of one directory's record data, recursing
    /// into child directories.
    fn scan(&mut self, data: &[u8], path: &str, depth: usize) -> Result<(), Error> {
        let mut recs: Vec<(DirRecOwned, Vec<u8>, RrInfo)> = Vec::new();
        parse_dirents(data, self.tree.blksz, |r| {
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
                    unit_size: r.unit_size,
                    gap_size: r.gap_size,
                    mtime: r.mtime,
                },
                r.name.to_vec(),
                rr,
            ));
            Ok(())
        })?;
        let mut i = 0usize;
        while i < recs.len() {
            let (rec, raw_name, rr) = &recs[i];
            // "." and ".." records carry file identifiers 0x00 / 0x01.
            if raw_name.as_slice() == [0] || raw_name.as_slice() == [1] {
                i += 1;
                continue;
            }
            // Multi-extent file (ECMA-119 §9.1.6 File Flags bit 7,
            // §9.2): consecutive records sharing one File Identifier
            // form a single file's extent list; bit 7 is clear on
            // the last record of the group.
            let mut n_ext = 1usize;
            while recs[i + n_ext - 1].0.flags & FLAG_MULTI_EXTENT != 0 {
                let Some((next, next_name, _)) = recs.get(i + n_ext) else {
                    return Err(Error::InvalidData("iso9660 unterminated multi-extent file"));
                };
                if next_name != raw_name
                    || (next.flags & !FLAG_MULTI_EXTENT) != (rec.flags & !FLAG_MULTI_EXTENT)
                    || next.unit_size != rec.unit_size
                    || next.gap_size != rec.gap_size
                {
                    return Err(Error::InvalidData("iso9660 bad multi-extent record"));
                }
                n_ext += 1;
            }
            // Rock Ridge `RE` (RRIP §4.1.5): this record is a
            // relocated directory's copy inside the relocation
            // directory; the real entry is enumerated at the
            // original path via its parent's `CL` link.
            if rr.relocated {
                i += n_ext;
                continue;
            }
            let mut base = if self.joliet {
                joliet_name(raw_name)
            } else {
                iso_name(raw_name)
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
            if is_dir && n_ext > 1 {
                // Multi-extent applies to file sections; a directory
                // is always a single extent (ECMA-119 §9.2).
                return Err(Error::InvalidData("iso9660 multi-extent directory"));
            }
            // Extended attribute record (ECMA-119 §9.5, §6.4.6):
            // the last section of a multi-extent file carries the
            // valid record.
            let xa = self.tree.read_xa(&recs[i + n_ext - 1].0)?;
            let mode = rr.mode.unwrap_or_else(|| {
                let perm = match &xa {
                    // XA permission bits deny access when set:
                    // bits 4/6 = owner r/x, 8/10 = group, 12/14 =
                    // other (§9.5.3). Write permission does not
                    // exist on a read-only medium.
                    Some(x) => {
                        let mut m = 0u32;
                        if x.permissions & 0x0010 == 0 {
                            m |= 0o400;
                        }
                        if x.permissions & 0x0040 == 0 {
                            m |= 0o100;
                        }
                        if x.permissions & 0x0100 == 0 {
                            m |= 0o040;
                        }
                        if x.permissions & 0x0400 == 0 {
                            m |= 0o010;
                        }
                        if x.permissions & 0x1000 == 0 {
                            m |= 0o004;
                        }
                        if x.permissions & 0x4000 == 0 {
                            m |= 0o001;
                        }
                        m
                    }
                    None => {
                        if is_dir {
                            0o555
                        } else {
                            0o444
                        }
                    }
                };
                (if is_dir { 0o040000 } else { 0o100000 }) | perm
            });
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
            let entry_data = match kind {
                IsoKind::Directory => Vec::new(),
                IsoKind::Symlink => rr.symlink.clone().unwrap_or_default(),
                _ => {
                    let parts: Vec<DirRecOwned> = recs[i..i + n_ext].iter().map(|t| t.0).collect();
                    let raw = self.tree.read_parts(&parts)?;
                    match rr.zisofs {
                        // zisofs `ZF`: transparent decompression.
                        Some(zf) => zisofs_inflate(&raw, zf)?,
                        None => raw,
                    }
                }
            };
            let mtime = rr
                .tf_modify
                .or_else(|| xa.as_ref().and_then(|x| x.modification_time))
                .unwrap_or(rec.mtime);
            self.entries.push(IsoEntry {
                name: cpath.clone(),
                kind,
                mode,
                uid: rr
                    .uid
                    .or_else(|| xa.as_ref().map(|x| u32::from(x.owner_id)))
                    .unwrap_or(0),
                gid: rr
                    .gid
                    .or_else(|| xa.as_ref().map(|x| u32::from(x.group_id)))
                    .unwrap_or(0),
                nlink: rr.nlink.unwrap_or(1),
                dev_t: rr.dev_t,
                ino: rr.ino.unwrap_or(0),
                mtime,
                xa,
                sparse: rr.sparse,
                susp_ext: rr.susp_ext.clone(),
                apple: rr.apple.clone(),
                data: entry_data,
            });
            if kind == IsoKind::Directory {
                let target = match rr.cl {
                    // `CL` child link (RRIP §4.1.5): the
                    // directory's real records live at the linked
                    // extent; its `.` record carries extent
                    // and size.
                    Some(lbn) => self.tree.dir_dot(lbn)?,
                    None => *rec,
                };
                self.walk(&target, &cpath, depth + 1)?;
            }
            i += n_ext;
        }
        Ok(())
    }
}

/// Parse one boot record volume descriptor. Returns None for
/// non-El-Torito boot records (other system identifiers).
fn parse_el_torito(input: &[u8], sec: &[u8]) -> Result<Option<ElTorito>, Error> {
    // Boot system identifier (BP 8-39) must be the El Torito magic.
    if !sec[7..39].starts_with(b"EL TORITO SPECIFICATION") {
        return Ok(None);
    }
    let catalog_lba = u32le(sec, 71);
    let cat_start = catalog_lba as usize * SECTOR;
    let cat = input
        .get(cat_start..cat_start + SECTOR)
        .ok_or(Error::InvalidData("iso9660 el torito catalog out of range"))?;

    // Validation entry (§2.4): header 1, key bytes 0x55/0xAA, and
    // the 16 words summing to zero.
    let v = &cat[..32];
    if v[0] != 1 || v[30] != 0x55 || v[31] != 0xAA {
        return Err(Error::InvalidData("iso9660 bad el torito validation entry"));
    }
    let sum: u32 = (0..32).step_by(2).map(|i| u32::from(u16le(v, i))).sum();
    if sum & 0xFFFF != 0 {
        return Err(Error::InvalidData("iso9660 el torito checksum mismatch"));
    }
    let platform = v[1];
    let raw_id = &v[4..28];
    let id_string = String::from_utf8_lossy(raw_id)
        .trim_end_matches([' ', '\x00'])
        .to_string();

    // Catalog boot entries start at offset 32: the initial/default
    // entry (indicator 0x88 or 0x00) followed by optional section
    // headers (0x90/0x91) and their entries.
    let mut entries = Vec::new();
    for e in cat[32..].as_chunks::<32>().0.iter() {
        // All-zero records are padding after the last catalog entry.
        if e.iter().all(|&b| b == 0) {
            break;
        }
        let ind = e[0];
        match ind {
            0x88 | 0x00 => {
                let load_lba = u32le(e, 8);
                let sector_count = u16le(e, 6);
                let img_start = load_lba as usize * SECTOR;
                let img_len = sector_count as usize * 512;
                let image = input
                    .get(img_start..img_start + img_len)
                    .ok_or(Error::InvalidData("iso9660 el torito image out of range"))?
                    .to_vec();
                entries.push(ElToritoEntry {
                    bootable: ind == 0x88,
                    media_type: e[1],
                    load_segment: u16le(e, 2),
                    system_type: e[4],
                    sector_count,
                    load_lba,
                    image,
                });
            }
            // Section headers (0x90 = more sections, 0x91 = last)
            // only mark boundaries between entry groups; skip them.
            0x90 | 0x91 => {}
            _ => break,
        }
    }
    if entries.is_empty() {
        return Err(Error::InvalidData(
            "iso9660 el torito catalog has no entries",
        ));
    }
    Ok(Some(ElTorito {
        catalog_lba,
        platform,
        id_string,
        entries,
    }))
}

/// Decode an ISO 9660 image (PVD tree with Rock Ridge, falling back
/// to a Joliet supplementary tree, then plain ISO9660 names).
pub fn decode(input: &[u8]) -> Result<IsoImage, Error> {
    if input.len() < VD_START + SECTOR {
        return Err(Error::UnexpectedEof);
    }
    let mut pvd: Option<VolDesc> = None;
    let mut joliet_svd: Option<VolDesc> = None;
    let mut el_torito = Vec::new();
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
            VD_TYPE_BOOT => {
                if let Some(et) = parse_el_torito(input, sec)? {
                    el_torito.push(et);
                }
            }
            VD_TYPE_TERMINATOR => break,
            _ => {} // partition descriptor
        }
        off += SECTOR;
    }
    let pvd = pvd.ok_or(Error::InvalidData("iso9660 missing PVD"))?;
    // Type-L path table (ECMA-119 §9.4). Contents are redundant
    // with the directory tree walk, which stays authoritative.
    let path_table = read_path_table(input, &pvd);
    let tree = Tree {
        input,
        blksz: pvd.logical_block_size,
    };

    // SUSP detection: "SP" marker in the "." record of the PVD root
    // directory (SUSP 5.3).
    let mut susp_active = false;
    {
        let root_data = tree.read_file(&pvd.root)?;
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
    walker.walk(&pvd.root, "", 0)?;
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
        jw.walk(&svd.root, "", 0)?;
        entries = jw.entries;
    }

    Ok(IsoImage {
        volume_id: pvd.volume_id,
        volume_blocks: pvd.volume_blocks,
        has_rock_ridge: use_rr,
        has_joliet: joliet_svd.is_some(),
        entries,
        path_table,
        el_torito,
        meta: pvd.meta,
        joliet_meta: joliet_svd.map(|s| s.meta),
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

        /// `dirent` with File Unit Size / Interleave Gap Size
        /// set (BP27/BP28, ECMA-119 §9.1.7/§9.1.8).
        fn dirent_ug(
            extent: u32,
            size: u32,
            flags: u8,
            unit: u8,
            gap: u8,
            name: &[u8],
            susp: &[u8],
        ) -> Vec<u8> {
            let mut r = Self::dirent(extent, size, flags, name, susp);
            r[26] = unit;
            r[27] = gap;
            r
        }

        /// `dirent` with a nonzero Extended Attribute Record
        /// Length (BP2, ECMA-119 §9.1.2).
        fn dirent_ea(
            extent: u32,
            size: u32,
            flags: u8,
            ea: u8,
            name: &[u8],
            susp: &[u8],
        ) -> Vec<u8> {
            let mut r = Self::dirent(extent, size, flags, name, susp);
            r[1] = ea;
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

        /// Allocate payload spanning as many sectors as needed.
        fn alloc_span(&mut self, bytes: &[u8]) -> u32 {
            let s = self.next_sector;
            let sectors = bytes.len().div_ceil(SECTOR).max(1);
            let off = s as usize * SECTOR;
            if self.data.len() < off + sectors * SECTOR {
                self.data.resize(off + sectors * SECTOR, 0);
            }
            self.data[off..off + bytes.len()].copy_from_slice(bytes);
            self.next_sector += sectors as u32;
            s
        }

        /// Write one volume descriptor sector (`ty` 1 = primary,
        /// 2 = Joliet supplementary). `pt` is the type-L path table
        /// `(extent, size)` to advertise in the descriptor.
        fn write_vd(
            &mut self,
            sector: usize,
            ty: u8,
            root_extent: u32,
            root_size: u32,
            pt: Option<(u32, u32)>,
        ) {
            let p = self.next_sector; // volume size marker
            let s = sector * SECTOR;
            self.data[s] = ty;
            self.data[s + 1..s + 6].copy_from_slice(b"CD001");
            self.data[s + 6] = 1;
            if ty == 2 {
                // Joliet SVD: UCS-2BE volume id + level-3 escape.
                for (i, u) in "TESTV".encode_utf16().enumerate() {
                    self.data[s + 40 + i * 2..s + 42 + i * 2].copy_from_slice(&u.to_be_bytes());
                }
                self.data[s + 88..s + 91].copy_from_slice(b"%/E");
            } else {
                self.data[s + 40..s + 45].copy_from_slice(b"TESTV");
            }
            self.data[s + 80..s + 84].copy_from_slice(&p.to_le_bytes());
            self.data[s + 84..s + 88].copy_from_slice(&p.to_be_bytes());
            self.data[s + 128..s + 130].copy_from_slice(&2048u16.to_le_bytes());
            self.data[s + 130..s + 132].copy_from_slice(&2048u16.to_be_bytes());
            if let Some((pt_extent, pt_size)) = pt {
                self.data[s + 132..s + 136].copy_from_slice(&pt_size.to_le_bytes());
                self.data[s + 136..s + 140].copy_from_slice(&pt_size.to_be_bytes());
                self.data[s + 140..s + 144].copy_from_slice(&pt_extent.to_le_bytes());
                self.data[s + 148..s + 152].copy_from_slice(&pt_extent.to_be_bytes());
            }
            let rec = Self::dirent(root_extent, root_size, 2, &[0], &[]);
            self.data[s + 156..s + 156 + 34].copy_from_slice(&rec[..34]);
        }

        /// Write a boot record volume descriptor (El Torito 1.0 §2.2)
        /// pointing at catalog_lba.
        fn write_boot_vd(&mut self, sector: usize, catalog_lba: u32) {
            let s = sector * SECTOR;
            self.data[s] = 0;
            self.data[s + 1..s + 6].copy_from_slice(b"CD001");
            self.data[s + 6] = 1;
            self.data[s + 7..s + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
            self.data[s + 71..s + 75].copy_from_slice(&catalog_lba.to_le_bytes());
        }

        /// Build a 32-byte validation entry with a valid checksum.
        fn validation_entry(platform: u8, id: &[u8]) -> [u8; 32] {
            let mut v = [0u8; 32];
            v[0] = 1;
            v[1] = platform;
            v[4..4 + id.len()].copy_from_slice(id);
            v[30] = 0x55;
            v[31] = 0xAA;
            // Checksum covers all 16 words (including the key bytes
            // as the 0xAA55 word); the checksum slot is still zero.
            let sum: u32 = (0..32)
                .step_by(2)
                .map(|i| u32::from(u16::from_le_bytes([v[i], v[i + 1]])))
                .sum();
            let fix = (0u16).wrapping_sub(sum as u16);
            v[28..30].copy_from_slice(&fix.to_le_bytes());
            v
        }

        /// Build a 32-byte boot catalog entry.
        fn boot_entry(indicator: u8, media: u8, seg: u16, count: u16, lba: u32) -> [u8; 32] {
            let mut e = [0u8; 32];
            e[0] = indicator;
            e[1] = media;
            e[2..4].copy_from_slice(&seg.to_le_bytes());
            e[6..8].copy_from_slice(&count.to_le_bytes());
            e[8..12].copy_from_slice(&lba.to_le_bytes());
            e
        }

        /// Install PVD (and terminator) with root record pointing
        /// at sector of root dir.
        fn finish(self, root_extent: u32, root_size: u32) -> Vec<u8> {
            self.finish_ext(root_extent, root_size, None, None)
        }

        /// PVD at 16, boot record at 17, terminator at 18.
        /// Caller must have set next_sector >= 19 before allocating
        /// directory/catalog/image data.
        fn finish_boot(mut self, root_extent: u32, root_size: u32, catalog_lba: u32) -> Vec<u8> {
            self.write_vd(16, 1, root_extent, root_size, None);
            self.write_boot_vd(17, catalog_lba);
            if self.data.len() < 19 * SECTOR {
                self.data.resize(19 * SECTOR, 0);
            }
            let t = 18 * SECTOR;
            self.data[t] = 255;
            self.data[t + 1..t + 6].copy_from_slice(b"CD001");
            self.data[t + 6] = 1;
            self.data
        }

        /// `finish` variant: optionally install a Joliet SVD pointing
        /// at a separate root tree, and path table fields `pt`.
        fn finish_ext(
            mut self,
            root_extent: u32,
            root_size: u32,
            joliet_root: Option<(u32, u32)>,
            pt: Option<(u32, u32)>,
        ) -> Vec<u8> {
            let mut sec = 16;
            self.write_vd(sec, 1, root_extent, root_size, pt);
            sec += 1;
            if let Some((je, js)) = joliet_root {
                self.write_vd(sec, 2, je, js, pt);
                sec += 1;
            }
            if self.data.len() < (sec + 1) * SECTOR {
                self.data.resize((sec + 1) * SECTOR, 0);
            }
            let t = sec * SECTOR;
            self.data[t] = 255;
            self.data[t + 1..t + 6].copy_from_slice(b"CD001");
            self.data[t + 6] = 1;
            self.data
        }
    }

    /// Type-L path table record (ECMA-119 §9.4): little-endian
    /// multi-byte fields, dir_id padded to an even length.
    fn path_table_record(extent: u32, parent: u16, name: &[u8]) -> Vec<u8> {
        let mut r = vec![name.len() as u8, 0];
        r.extend_from_slice(&extent.to_le_bytes());
        r.extend_from_slice(&parent.to_le_bytes());
        r.extend_from_slice(name);
        if name.len() % 2 == 1 {
            r.push(0);
        }
        r
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

    #[test]
    fn joliet_surrogate_pair_names() {
        // Joliet tree carries UCS-2BE identifiers; a surrogate pair
        // must combine into one non-BMP char and a lone surrogate
        // must decode as U+FFFD.
        let mut b = IsoBuilder::new();
        let f = b.alloc(b"DATA");
        // "A\u{20BB7}.TXT;1" — U+20BB7 is encoded as the pair D842 DFB7.
        let mut n1 = Vec::new();
        for u in "A\u{20BB7}.TXT;1".encode_utf16() {
            n1.extend_from_slice(&u.to_be_bytes());
        }
        // "B<lone lead surrogate>C.DAT;1"
        let mut n2 = Vec::new();
        for u in [
            0x0042u16, 0xD800, 0x0043, 0x002E, 0x0044, 0x0041, 0x0054, 0x003B, 0x0031,
        ] {
            n2.extend_from_slice(&u.to_be_bytes());
        }
        let jd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, &n1, &[]),
            IsoBuilder::dirent(f, 4, 0, &n2, &[]),
        ]);
        let jroot = b.alloc(&jd);
        let pd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, b"FILE.TXT;1", &[]),
        ]);
        let proot = b.alloc(&pd);
        let img = b.finish_ext(proot, SECTOR as u32, Some((jroot, SECTOR as u32)), None);
        let out = decode(&img).unwrap();
        assert!(out.has_joliet);
        assert!(!out.has_rock_ridge);
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["A\u{20BB7}.TXT", "B\u{FFFD}C.DAT"]);
    }

    /// Build a zisofs file extent: 16-byte header (magic +
    /// uncompressed size + header_words + block_shift + reserved),
    /// a block pointer table of `nblocks + 1` little-endian u32
    /// absolute offsets, then one zlib stream per non-zero block.
    /// Returns `(extent_data, zf_susp_entry)`.
    fn zisofs_payload(plain: &[u8], block_shift: u8) -> (Vec<u8>, Vec<u8>) {
        let block_size = 1usize << block_shift;
        let nblocks = plain.len().div_ceil(block_size);
        let mut blocks: Vec<Vec<u8>> = Vec::new();
        for i in 0..nblocks {
            let chunk = &plain[i * block_size..plain.len().min((i + 1) * block_size)];
            if chunk.iter().all(|&b| b == 0) {
                blocks.push(Vec::new()); // all-zero block
            } else {
                blocks.push(crate::compress::zlib::encode::encode(chunk));
            }
        }
        let mut data = Vec::new();
        data.extend_from_slice(&ZISOFS_MAGIC);
        data.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        data.push(4); // header_words: 16-byte header >> 2
        data.push(block_shift);
        data.extend_from_slice(&[0, 0]); // reserved
        let mut pos = 16 + (nblocks + 1) * 4;
        let mut ptrs = Vec::with_capacity(nblocks + 1);
        for b in &blocks {
            ptrs.push(pos as u32);
            pos += b.len();
        }
        ptrs.push(pos as u32);
        for p in ptrs {
            data.extend_from_slice(&p.to_le_bytes());
        }
        for b in &blocks {
            data.extend_from_slice(b);
        }
        // ZF system use entry: sig + len 16 + ver 1 + "pz" +
        // parms (header words, block shift) + both-endian size.
        let mut zf = vec![b'Z', b'F', 16, 1, b'p', b'z', 4, block_shift];
        zf.extend_from_slice(&(plain.len() as u32).to_le_bytes());
        zf.extend_from_slice(&(plain.len() as u32).to_be_bytes());
        (data, zf)
    }

    /// Single-file Rock Ridge image whose file extent is `data` and
    /// whose directory record carries `susp` after the `NM` name.
    fn zisofs_iso(data: &[u8], susp: &[u8]) -> Vec<u8> {
        let mut b = IsoBuilder::new();
        let f = b.alloc_span(data);
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, data.len() as u32, 0, b"FILE.BIN;1", susp),
        ]);
        let root = b.alloc(&rootd);
        b.finish(root, SECTOR as u32)
    }

    #[test]
    fn zisofs_roundtrip() {
        // Three-block file (32KiB blocks): text, all-zero, tail.
        let mut plain = vec![b'A'; 32768];
        plain.extend_from_slice(&[0; 32768]);
        plain.extend_from_slice(b"tail!");
        let (zdata, zf) = zisofs_payload(&plain, 15);
        let img = zisofs_iso(&zdata, &zf);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries.len(), 1);
        assert_eq!(out.entries[0].name, "FILE.BIN");
        assert_eq!(out.entries[0].kind, IsoKind::File);
        assert_eq!(out.entries[0].data, plain);
    }

    #[test]
    fn zisofs_small_file() {
        // Single partial block.
        let plain = b"compress me please".repeat(100);
        let (zdata, zf) = zisofs_payload(&plain, 15);
        let img = zisofs_iso(&zdata, &zf);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries[0].data, plain);
    }

    #[test]
    fn zisofs_rejects_bad_header() {
        let plain = b"hello zisofs".repeat(10);
        let (zdata, zf) = zisofs_payload(&plain, 15);
        // Corrupt the magic.
        let mut bad = zdata.clone();
        bad[0] ^= 0xFF;
        assert!(matches!(
            decode(&zisofs_iso(&bad, &zf)),
            Err(Error::InvalidData(_))
        ));
        // Uncompressed size disagrees with the ZF entry.
        let mut bad = zdata.clone();
        bad[8] ^= 0x01;
        assert!(matches!(
            decode(&zisofs_iso(&bad, &zf)),
            Err(Error::InvalidData(_))
        ));
        let mut bad = zdata.clone();
        bad[12] = 8; // header_words mismatch
        assert!(matches!(
            decode(&zisofs_iso(&bad, &zf)),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn zisofs_rejects_bad_pointers() {
        let plain = b"some content here".repeat(40);
        let (zdata, zf) = zisofs_payload(&plain, 15);
        // Pointer runs past the end of the extent.
        let mut bad = zdata.clone();
        bad[16..20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(
            decode(&zisofs_iso(&bad, &zf)),
            Err(Error::InvalidData(_))
        ));
        // Reversed pointers (end < start).
        let mut bad = zdata.clone();
        let p0 = u32::from_le_bytes([zdata[16], zdata[17], zdata[18], zdata[19]]);
        bad[20..24].copy_from_slice(&(p0 - 4).to_le_bytes());
        assert!(matches!(
            decode(&zisofs_iso(&bad, &zf)),
            Err(Error::InvalidData(_))
        ));
        // Truncated zlib stream inside the block.
        let bad = zdata[..zdata.len() - 4].to_vec();
        assert!(decode(&zisofs_iso(&bad, &zf)).is_err());
    }

    #[test]
    fn zisofs_rejects_bad_params() {
        let plain = b"parameter test".repeat(10);
        let (zdata, zf) = zisofs_payload(&plain, 15);
        // Block shift outside the defined 15..=17 profile.
        let mut bad_zf = zf.clone();
        bad_zf[7] = 14;
        assert!(matches!(
            decode(&zisofs_iso(&zdata, &bad_zf)),
            Err(Error::Unsupported(_))
        ));
        // Unknown algorithm signature (not "pz").
        let mut bad_zf = zf.clone();
        bad_zf[4] = b'x';
        assert!(matches!(
            decode(&zisofs_iso(&zdata, &bad_zf)),
            Err(Error::Unsupported(_))
        ));
        // Short ZF entry.
        let mut bad_zf = zf[..8].to_vec();
        bad_zf[2] = 8;
        assert!(matches!(
            decode(&zisofs_iso(&zdata, &bad_zf)),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn path_table_matches_tree() {
        let mut b = IsoBuilder::new();
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
            IsoBuilder::dirent(sub, SECTOR as u32, 2, b"SUB", &[]),
        ]);
        let root = b.alloc(&rootd);
        // Breadth-first table: root (self-parented), then SUB.
        let mut pt = Vec::new();
        pt.extend(path_table_record(root, 1, &[0]));
        pt.extend(path_table_record(sub, 1, b"SUB"));
        let pt_len = pt.len() as u32;
        let pt_ext = b.alloc(&pt);
        let img = b.finish_ext(root, SECTOR as u32, None, Some((pt_ext, pt_len)));
        let out = decode(&img).unwrap();
        assert_eq!(
            out.path_table,
            [
                PathTableEntry {
                    name: vec![0],
                    extent: root,
                    parent: 1,
                },
                PathTableEntry {
                    name: b"SUB".to_vec(),
                    extent: sub,
                    parent: 1,
                },
            ]
        );
        // The walked tree contains the same directory.
        let sub_e = out
            .entries
            .iter()
            .find(|e| e.name == "SUB")
            .expect("SUB entry");
        assert_eq!(sub_e.kind, IsoKind::Directory);
    }

    #[test]
    fn path_table_absent_or_bad_extent_is_tolerated() {
        // No path table fields set -> empty table, decode still ok.
        let out = decode(&plain_iso()).unwrap();
        assert!(out.path_table.is_empty());
        // Point the type-L extent past the end of the image.
        let mut img = plain_iso();
        let s = 16 * SECTOR;
        img[s + 132..s + 136].copy_from_slice(&8u32.to_le_bytes());
        img[s + 136..s + 140].copy_from_slice(&8u32.to_be_bytes());
        img[s + 140..s + 144].copy_from_slice(&0xFFFFu32.to_le_bytes());
        let out = decode(&img).unwrap();
        assert!(out.path_table.is_empty());
    }

    /// Rock Ridge `PX` entry (44 bytes): both-endian mode,
    /// nlink, uid, gid, serial.
    fn susp_px(mode: u32) -> Vec<u8> {
        let mut px = vec![b'P', b'X', 44, 1];
        for v in [mode, 1, 0, 0, 1] {
            px.extend_from_slice(&v.to_le_bytes());
            px.extend_from_slice(&v.to_be_bytes());
        }
        px
    }

    /// Rock Ridge `PN` entry (20 bytes): both-endian Dev_t
    /// High then Dev_t Low (RRIP §4.1.2).
    fn susp_pn(high: u32, low: u32) -> Vec<u8> {
        let mut pn = vec![b'P', b'N', 20, 1];
        pn.extend_from_slice(&high.to_le_bytes());
        pn.extend_from_slice(&high.to_be_bytes());
        pn.extend_from_slice(&low.to_le_bytes());
        pn.extend_from_slice(&low.to_be_bytes());
        pn
    }

    /// Rock Ridge `CL` child link (12 bytes): both-endian LBN
    /// of the relocated child directory's extent (RRIP §4.1.5).
    fn susp_cl(lbn: u32) -> Vec<u8> {
        let mut cl = vec![b'C', b'L', 12, 1];
        cl.extend_from_slice(&lbn.to_le_bytes());
        cl.extend_from_slice(&lbn.to_be_bytes());
        cl
    }

    /// Rock Ridge `PL` parent link (12 bytes): both-endian LBN
    /// of the original parent, carried by the relocated dir's `..`.
    fn susp_pl(lbn: u32) -> Vec<u8> {
        let mut pl = vec![b'P', b'L', 12, 1];
        pl.extend_from_slice(&lbn.to_le_bytes());
        pl.extend_from_slice(&lbn.to_be_bytes());
        pl
    }

    /// Rock Ridge `RE` relocated-entry marker (4 bytes).
    fn susp_re() -> Vec<u8> {
        vec![b'R', b'E', 4, 1]
    }

    /// Rock Ridge `PX` entry with a caller-chosen file serial
    /// (inode) number (44 bytes).
    fn susp_px_ino(mode: u32, ino: u32) -> Vec<u8> {
        let mut px = vec![b'P', b'X', 44, 1];
        for v in [mode, 2, 0, 0, ino] {
            px.extend_from_slice(&v.to_le_bytes());
            px.extend_from_slice(&v.to_be_bytes());
        }
        px
    }

    /// Rock Ridge `SF` sparse file entry (21 bytes, RRIP §4.1.7):
    /// both-endian SIZE HIGH + SIZE LOW + table depth.
    fn susp_sf(size: u64, depth: u8) -> Vec<u8> {
        let mut sf = vec![b'S', b'F', 21, 1];
        let hi = (size >> 32) as u32;
        let lo = size as u32;
        for v in [hi, lo] {
            sf.extend_from_slice(&v.to_le_bytes());
            sf.extend_from_slice(&v.to_be_bytes());
        }
        sf.push(depth);
        sf
    }

    /// SUSP `ES` extension selector: sequence + version +
    /// id/descriptor/source byte strings.
    fn susp_es(seq: u8, ver: u8, id: &[u8], des: &[u8], src: &[u8]) -> Vec<u8> {
        let len = 9 + id.len() + des.len() + src.len();
        let mut e = vec![
            b'E',
            b'S',
            len as u8,
            1,
            seq,
            id.len() as u8,
            des.len() as u8,
            src.len() as u8,
            ver,
        ];
        e.extend_from_slice(id);
        e.extend_from_slice(des);
        e.extend_from_slice(src);
        e
    }

    /// SUSP `PD` padding entry carrying `n` pad bytes.
    fn susp_pd(n: usize) -> Vec<u8> {
        let mut e = vec![b'P', b'D', (4 + n) as u8, 1];
        e.extend_from_slice(&vec![0u8; n]);
        e
    }

    /// Apple `AA` extension record (TN FL36 v2 signature):
    /// BP3 = length, BP4 = SystemUseID.
    fn susp_aa(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut e = vec![b'A', b'A', (4 + payload.len()) as u8, id];
        e.extend_from_slice(payload);
        e
    }

    /// Apple `BA` extension record (TN FL36 old signature): no
    /// length byte, BP3 = SystemUseID.
    fn susp_ba(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut e = vec![b'B', b'A', id];
        e.extend_from_slice(payload);
        e
    }

    /// One logical block holding an extended attribute record
    /// (ECMA-119 §9.5, 250-byte fixed part). `perms` is the
    /// deny-bit mask recorded big-endian at BP 9-10.
    fn xa_block(owner: u16, group: u16, perms: u16) -> Vec<u8> {
        let mut x = vec![0u8; SECTOR];
        for (o, v) in [(0usize, owner), (4, group), (80, 512), (246, 0)] {
            x[o..o + 2].copy_from_slice(&v.to_le_bytes());
            x[o + 2..o + 4].copy_from_slice(&v.to_be_bytes());
        }
        x[8..10].copy_from_slice(&perms.to_be_bytes());
        // modification date BP28-44: 2020-01-02 03:04:05.00 GMT
        x[27..44].copy_from_slice(b"2020010203040500\x00");
        x[84..94].copy_from_slice(b"XASYSTEMID");
        x[180] = 1; // record version
        x
    }

    /// Multi-extent file (ECMA-119 §9.1.6 File Flags bit 7, §9.2):
    /// consecutive records with the same File Identifier form one
    /// file's extent list; bit 7 is clear on the last record.
    #[test]
    fn multi_extent_file() {
        let mut b = IsoBuilder::new();
        let f = b.alloc(b"TAIL");
        let e1 = b.alloc(b"part-1 ");
        let e2 = b.alloc(b"part-2 ");
        let e3 = b.alloc(b"part-3");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(e1, 7, FLAG_MULTI_EXTENT, b"BIG.BIN;1", &[]),
            IsoBuilder::dirent(e2, 7, FLAG_MULTI_EXTENT, b"BIG.BIN;1", &[]),
            IsoBuilder::dirent(e3, 6, 0, b"BIG.BIN;1", &[]),
            // an entry after the group is still enumerated normally
            IsoBuilder::dirent(f, 4, 0, b"TAIL.TXT;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        // continuation records are not enumerated as extra entries
        assert_eq!(names, ["BIG.BIN", "TAIL.TXT"]);
        assert_eq!(out.entries[0].kind, IsoKind::File);
        assert_eq!(out.entries[0].data, b"part-1 part-2 part-3");
        assert_eq!(out.entries[1].data, b"TAIL");
    }

    #[test]
    fn multi_extent_rejects_unterminated() {
        // bit 7 set on the last record of the directory.
        let mut b = IsoBuilder::new();
        let e1 = b.alloc(b"part-1");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(e1, 6, FLAG_MULTI_EXTENT, b"BIG.BIN;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));

        // continuation record carries a different File Identifier.
        let mut b = IsoBuilder::new();
        let e1 = b.alloc(b"part-1");
        let e2 = b.alloc(b"other");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(e1, 6, FLAG_MULTI_EXTENT, b"BIG.BIN;1", &[]),
            IsoBuilder::dirent(e2, 5, 0, b"OTHER;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));

        // bit 7 on a directory record is rejected.
        let mut b = IsoBuilder::new();
        let subd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
        ]);
        let sub = b.alloc(&subd);
        let e2 = b.alloc(b"more");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(sub, SECTOR as u32, 2 | FLAG_MULTI_EXTENT, b"SUB", &[]),
            IsoBuilder::dirent(e2, 4, 2, b"SUB", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// Interleaved file (ECMA-119 §6.4.3, §9.1.7/§9.1.8): File
    /// Units of `unit_size` blocks separated by `gap_size`
    /// skipped blocks are concatenated; the last unit may be partial.
    #[test]
    fn interleaved_file() {
        let mut b = IsoBuilder::new();
        // layout: [unit0][gap][unit1][gap][unit2]
        let mut u0 = vec![0u8; SECTOR];
        u0[..4].copy_from_slice(b"blk0");
        let mut u1 = vec![0u8; SECTOR];
        u1[..4].copy_from_slice(b"blk1");
        let mut u2 = vec![0u8; SECTOR];
        u2[..5].copy_from_slice(b"blk2!");
        let mut layout = Vec::new();
        layout.extend_from_slice(&u0);
        layout.extend_from_slice(&[0xEE; SECTOR]);
        layout.extend_from_slice(&u1);
        layout.extend_from_slice(&[0xEE; SECTOR]);
        layout.extend_from_slice(&u2);
        let ext = b.alloc_span(&layout);
        // 2 full 2048-byte units + 10 bytes of the third unit.
        let size = (2 * SECTOR + 10) as u32;
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ug(ext, size, 0, 1, 1, b"INTERL.BIN;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries.len(), 1);
        let d = &out.entries[0].data;
        assert_eq!(d.len(), 2 * SECTOR + 10);
        assert_eq!(&d[..4], b"blk0");
        assert_eq!(&d[SECTOR..SECTOR + 4], b"blk1");
        assert_eq!(&d[2 * SECTOR..2 * SECTOR + 5], b"blk2!");
        // gap bytes must not leak into the file data
        assert!(!d.contains(&0xEE));
    }

    #[test]
    fn interleave_gap_without_unit_rejected() {
        // gap_size nonzero with unit_size = 0 is contradictory
        // (ECMA-119 §9.1.8 requires interleaved mode fields to be
        // consistent).
        let mut b = IsoBuilder::new();
        let f = b.alloc(b"data");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ug(f, 4, 0, 0, 1, b"BAD.BIN;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// Rock Ridge `PN` (RRIP §4.1.2): the device number of a
    /// char/block special file is exposed as `dev_t`.
    #[test]
    fn rr_pn_device() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // block device 0o060644 + PN high=1 low=0x820
        let mut susp = susp_px(0o060644);
        susp.extend_from_slice(&susp_pn(1, 0x820));
        let ext = b.alloc(&[]);
        // a plain file in the same dir reports no dev_t
        let f = b.alloc(b"plain");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(ext, 0, 0, b"DEV.BIN;1", &susp),
            IsoBuilder::dirent(f, 5, 0, b"PLAIN.TXT;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries[0].name, "DEV.BIN");
        assert_eq!(out.entries[0].kind, IsoKind::Other(0o060000));
        assert_eq!(out.entries[0].dev_t, Some((1 << 32) | 0x820));
        assert_eq!(out.entries[1].name, "PLAIN.TXT");
        assert_eq!(out.entries[1].dev_t, None);
    }

    #[test]
    fn rr_pn_rejects_short_entry() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // truncated PN (len 8 < 20)
        let susp = vec![b'P', b'N', 8, 1, 0, 0, 0, 0];
        let ext = b.alloc(&[]);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(ext, 0, 0, b"DEV.BIN;1", &susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// Rock Ridge deep-directory relocation (RRIP §4.1.5): the
    /// `CL` child link exposes the relocated directory at its
    /// original path; the `RE`-marked copy under the relocation
    /// directory is not enumerated; `PL` on its `..` is
    /// skipped.
    #[test]
    fn rr_cl_re_relocated_dir() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let f = b.alloc(b"deep!");
        // the relocated dir lives in its own extent; "." must carry
        // the real extent/size for the CL resolution.
        let deep = b.next_sector;
        let a = deep + 1; // allocated next
        let deepd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(deep, SECTOR as u32, 2, &[0], &[]),
            IsoBuilder::dirent(a, SECTOR as u32, 2, &[1], &susp_pl(a)),
            IsoBuilder::dirent(f, 5, 0, b"FILE.TXT;1", &[]),
        ]);
        assert_eq!(b.alloc(&deepd), deep);
        // parent dir: the "DEEP" record is a placeholder carrying CL.
        let ad = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(0, 0, 2, b"DEEP", &susp_cl(deep)),
        ]);
        assert_eq!(b.alloc(&ad), a);
        // relocation dir: the real record is marked RE.
        let rrd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(deep, SECTOR as u32, 2, b"DEEP", &susp_re()),
        ]);
        let rrm = b.alloc(&rrd);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(a, SECTOR as u32, 2, b"A", &[]),
            IsoBuilder::dirent(rrm, SECTOR as u32, 2, b"RR_MOVED", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let names: Vec<&str> = out.entries.iter().map(|e| e.name.as_str()).collect();
        // no double enumeration under the relocation directory
        assert_eq!(names, ["A", "A/DEEP", "A/DEEP/FILE.TXT", "RR_MOVED"]);
        assert_eq!(out.entries[1].kind, IsoKind::Directory);
        assert_eq!(out.entries[2].data, b"deep!");
    }

    #[test]
    fn rr_cl_rejects_bad_target() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // CL points past the end of the image.
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(0, 0, 2, b"DEEP", &susp_cl(0xFFFF)),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    fn el_torito_iso() -> Vec<u8> {
        let mut b = IsoBuilder::new();
        b.next_sector = 19; // VD region: 16 PVD, 17 boot, 18 term
        // Boot image: 4 virtual sectors (2048 bytes of 0xAB).
        let img_lba = b.alloc_span(&vec![0xABu8; 2048]);
        // Boot catalog sector: validation + default entry.
        let mut cat = vec![0u8; SECTOR];
        cat[..32].copy_from_slice(&IsoBuilder::validation_entry(0, b"DEVIN TEST"));
        cat[32..64].copy_from_slice(&IsoBuilder::boot_entry(0x88, 0, 0, 4, img_lba));
        let cat_lba = b.alloc(&cat);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
        ]);
        let root = b.alloc(&rootd);
        b.finish_boot(root, SECTOR as u32, cat_lba)
    }

    #[test]
    fn decodes_el_torito() {
        let img = decode(&el_torito_iso()).unwrap();
        assert_eq!(img.el_torito.len(), 1);
        let et = &img.el_torito[0];
        assert_eq!(et.platform, 0);
        assert_eq!(et.id_string, "DEVIN TEST");
        assert_eq!(et.entries.len(), 1);
        let e = &et.entries[0];
        assert!(e.bootable);
        assert_eq!(e.media_type, 0);
        assert_eq!(e.sector_count, 4);
        assert_eq!(e.image.len(), 2048);
        assert!(e.image.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn el_torito_section_entries() {
        let mut b = IsoBuilder::new();
        b.next_sector = 19;
        let img_lba = b.alloc_span(&vec![0x55u8; 512]);
        let mut cat = vec![0u8; SECTOR];
        cat[..32].copy_from_slice(&IsoBuilder::validation_entry(0xEF, b"UEFI"));
        cat[32..64].copy_from_slice(&IsoBuilder::boot_entry(0x88, 0, 0, 1, img_lba));
        cat[64] = 0x91; // last section header
        cat[96..128].copy_from_slice(&IsoBuilder::boot_entry(0x88, 0, 0, 1, img_lba));
        let cat_lba = b.alloc(&cat);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = decode(&b.finish_boot(root, SECTOR as u32, cat_lba)).unwrap();
        let et = &img.el_torito[0];
        assert_eq!(et.platform, 0xEF);
        assert_eq!(et.entries.len(), 2);
        assert_eq!(et.entries[1].image.len(), 512);
        assert!(et.entries[1].image.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn rejects_bad_el_torito_validation() {
        let mut img = el_torito_iso();
        // Break the catalog key bytes (catalog LBA is 20).
        img[20 * SECTOR + 31] = 0x00;
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_bad_el_torito_checksum() {
        let mut img = el_torito_iso();
        // Flip an id byte so the checksum word no longer balances.
        img[20 * SECTOR + 10] += 1;
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_out_of_range_el_torito_catalog() {
        let mut img = el_torito_iso();
        // Point the catalog LBA past the end of the image.
        img[17 * SECTOR + 71..17 * SECTOR + 75].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    #[test]
    fn skips_non_eltorito_boot_record() {
        let mut img = el_torito_iso();
        // Overwrite the system id so it is not an El Torito record.
        img[17 * SECTOR + 7..17 * SECTOR + 20].copy_from_slice(b"OTHER BOOT   ");
        let out = decode(&img).unwrap();
        assert!(out.el_torito.is_empty());
    }

    /// PVD metadata strings (ECMA-119 §8.4.5, §8.4.19-8.4.25):
    /// a/d-character fields are returned with trailing padding
    /// removed.
    #[test]
    fn pvd_metadata_fields() {
        let mut img = plain_iso();
        let s = 16 * SECTOR;
        img[s + 8..s + 8 + 9].copy_from_slice(b"TESTSYS 1");
        img[s + 190..s + 190 + 7].copy_from_slice(b"VOLSET1");
        img[s + 318..s + 318 + 9].copy_from_slice(b"PUBLISHER");
        img[s + 446..s + 446 + 8].copy_from_slice(b"PREPARER");
        img[s + 574..s + 574 + 11].copy_from_slice(b"MKISOFS 1.0");
        img[s + 702..s + 702 + 10].copy_from_slice(b"COPY.TXT;1");
        img[s + 739..s + 739 + 10].copy_from_slice(b"ABST.TXT;1");
        img[s + 776..s + 776 + 10].copy_from_slice(b"BIBL.TXT;1");
        let out = decode(&img).unwrap();
        let m = &out.meta;
        assert_eq!(m.system_id, "TESTSYS 1");
        assert_eq!(m.volume_set_id, "VOLSET1");
        assert_eq!(m.publisher_id, "PUBLISHER");
        assert_eq!(m.data_preparer_id, "PREPARER");
        assert_eq!(m.application_id, "MKISOFS 1.0");
        assert_eq!(m.copyright_file_id, "COPY.TXT;1");
        assert_eq!(m.abstract_file_id, "ABST.TXT;1");
        assert_eq!(m.bibliographic_file_id, "BIBL.TXT;1");
        // the builder writes no volume timestamps
        assert_eq!(m.creation_time, None);
        assert_eq!(m.modification_time, None);
        assert_eq!(m.expiration_time, None);
        assert_eq!(m.effective_time, None);
        assert!(out.joliet_meta.is_none());
    }

    /// Volume datetimes (ECMA-119 §8.4.26-8.4.29): 17-byte
    /// "YYYYMMDDHHMMSSCC" + signed 15-minute tz byte.
    #[test]
    fn pvd_volume_datetimes() {
        let mut img = plain_iso();
        let s = 16 * SECTOR;
        // creation: 2020-01-02 03:04:05.00 GMT
        img[s + 813..s + 830].copy_from_slice(b"2020010203040500\x00");
        // modification: same instant, tz +4 (local is GMT+1)
        let mut m = *b"2020010203040500\x00";
        m[16] = 4;
        img[s + 830..s + 847].copy_from_slice(&m);
        // expiration: all '0' digits + tz 0 means unspecified
        img[s + 847..s + 864].copy_from_slice(b"0000000000000000\x00");
        // effective: same instant, tz -4 (local is GMT-1)
        let mut e = *b"2020010203040500\x00";
        e[16] = (-4i8) as u8;
        img[s + 864..s + 881].copy_from_slice(&e);
        let out = decode(&img).unwrap();
        assert_eq!(out.meta.creation_time, Some(1577934245));
        assert_eq!(out.meta.modification_time, Some(1577934245 - 3600));
        assert_eq!(out.meta.expiration_time, None);
        assert_eq!(out.meta.effective_time, Some(1577934245 + 3600));
    }

    /// Datetime fields that are blank or not parseable decode as
    /// `None` rather than failing the whole image.
    #[test]
    fn unparseable_datetime_is_none() {
        let mut img = plain_iso();
        let s = 16 * SECTOR;
        // all spaces (blank field left by some writers)
        img[s + 813..s + 830].copy_from_slice(b"                 ");
        // non-digit bytes
        img[s + 830..s + 847].copy_from_slice(b"YYYYMMDDHHMMSSCC\x00");
        // out-of-range month
        img[s + 847..s + 864].copy_from_slice(b"2020130203040500\x00");
        // NUL inside the digit area
        img[s + 864..s + 881].copy_from_slice(b"20200102030405\0\0\0");
        let out = decode(&img).unwrap();
        let m = &out.meta;
        assert_eq!(m.creation_time, None);
        assert_eq!(m.modification_time, None);
        assert_eq!(m.expiration_time, None);
        assert_eq!(m.effective_time, None);
    }

    /// A Joliet SVD carries the same fields as UCS-2BE; both the
    /// PVD meta and the SVD meta are exposed.
    #[test]
    fn joliet_metadata_fields() {
        let mut b = IsoBuilder::new();
        b.next_sector = 19; // VD region: 16 PVD, 17 SVD, 18 term
        let jd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
        ]);
        let jroot = b.alloc(&jd);
        let pd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
        ]);
        let proot = b.alloc(&pd);
        let mut img = b.finish_ext(proot, SECTOR as u32, Some((jroot, SECTOR as u32)), None);
        let svd = 17 * SECTOR;
        // UCS-2BE publisher id + an ASCII volume timestamp.
        for (i, u) in "JPUB".encode_utf16().enumerate() {
            img[svd + 318 + i * 2..svd + 320 + i * 2].copy_from_slice(&u.to_be_bytes());
        }
        img[svd + 813..svd + 830].copy_from_slice(b"2020010203040500\x00");
        let pvd = 16 * SECTOR;
        img[pvd + 318..pvd + 327].copy_from_slice(b"PUBLISHER");
        let out = decode(&img).unwrap();
        assert_eq!(out.meta.publisher_id, "PUBLISHER");
        assert_eq!(out.meta.creation_time, None);
        let jm = out.joliet_meta.expect("joliet meta");
        assert_eq!(jm.publisher_id, "JPUB");
        assert_eq!(jm.creation_time, Some(1577934245));
    }

    /// Extended attribute record (ECMA-119 §9.5, §6.4): the EA
    /// blocks ahead of the file data are parsed into `IsoEntry::xa`
    /// and fold into uid/gid/mode/mtime when Rock Ridge is absent.
    #[test]
    fn xa_record_decodes() {
        let mut b = IsoBuilder::new();
        // Deny owner-read (bit4) and group-exec (bit10).
        let mut xa_file = xa_block(7, 9, 0x0410);
        xa_file.extend_from_slice(b"file data here");
        let ext = b.alloc_span(&xa_file);
        // A second file carries an XA block and a Rock Ridge PX
        // entry; the PX fields must win.
        let mut xa2 = xa_block(11, 13, 0);
        xa2.extend_from_slice(b"RR");
        let ext2 = b.alloc_span(&xa2);
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ea(ext, 14, 0, 1, b"FILE.TXT;1", &[]),
            IsoBuilder::dirent_ea(ext2, 2, 0, 1, b"RR.TXT;1", &susp_px_ino(0o100600, 77)),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let e = &out.entries[0];
        assert_eq!(e.name, "FILE.TXT");
        assert_eq!(e.data, b"file data here");
        let xa = e.xa.as_ref().expect("xa record");
        assert_eq!(xa.owner_id, 7);
        assert_eq!(xa.group_id, 9);
        assert_eq!(xa.permissions, 0x0410);
        assert_eq!(xa.modification_time, Some(1577934245));
        assert_eq!(xa.record_length, 512);
        assert_eq!(xa.system_id, "XASYSTEMID");
        // folded fallback values
        assert_eq!(e.uid, 7);
        assert_eq!(e.gid, 9);
        // owner: x only; group: r only; other: r+x
        assert_eq!(e.mode, 0o100145);
        assert_eq!(e.mtime, 1577934245);
        // Rock Ridge PX wins over XA where both exist.
        let e = &out.entries[1];
        assert_eq!(e.uid, 0);
        assert_eq!(e.mode, 0o100600);
        assert_eq!(e.ino, 77);
        assert!(e.xa.is_some());
    }

    /// Multi-extent files take the extended attribute record of
    /// their last section (ECMA-119 §6.4.6).
    #[test]
    fn xa_multi_extent_uses_last() {
        let mut b = IsoBuilder::new();
        // part 1: EA block (owner 11) then data
        let mut p1 = xa_block(11, 1, 0);
        p1.extend_from_slice(b"part-1");
        let e1 = b.alloc_span(&p1);
        // part 2: EA block (owner 22) then data
        let mut p2 = xa_block(22, 2, 0);
        p2.extend_from_slice(b"part-2");
        let e2 = b.alloc_span(&p2);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ea(e1, 6, FLAG_MULTI_EXTENT, 1, b"BIG.BIN;1", &[]),
            IsoBuilder::dirent_ea(e2, 6, 0, 1, b"BIG.BIN;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        assert_eq!(out.entries.len(), 1);
        let e = &out.entries[0];
        assert_eq!(e.data, b"part-1part-2");
        assert_eq!(e.xa.as_ref().unwrap().owner_id, 22);
        assert_eq!(e.uid, 22);
    }

    /// A both-endian field whose halves disagree is rejected
    /// (ECMA-119 §7.3.3 via §9.5).
    #[test]
    fn xa_rejects_bad_both_endian() {
        let mut b = IsoBuilder::new();
        let mut xa_file = xa_block(7, 9, 0);
        // Corrupt the group id's big-endian half (BP 6-7).
        xa_file[6] ^= 0xFF;
        xa_file.extend_from_slice(b"data");
        let ext = b.alloc_span(&xa_file);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ea(ext, 4, 0, 1, b"FILE.TXT;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// A record version other than 1 is rejected (ECMA-119 §9.5).
    #[test]
    fn xa_rejects_bad_version() {
        let mut b = IsoBuilder::new();
        let mut xa_file = xa_block(7, 9, 0);
        xa_file[180] = 2;
        xa_file.extend_from_slice(b"data");
        let ext = b.alloc_span(&xa_file);
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent_ea(ext, 4, 0, 1, b"FILE.TXT;1", &[]),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// An interleaved file stores its extended attribute record in
    /// the first File Unit (ECMA-119 §6.4.4); the EA length must
    /// equal the File Unit Size.
    #[test]
    fn xa_interleaved() {
        let mut b = IsoBuilder::new();
        // layout: [EA unit][gap][unit1][gap][unit2]
        let mut layout = xa_block(5, 6, 0x1000); // deny other-read
        layout.extend_from_slice(&[0xEE; SECTOR]);
        let mut u1 = vec![0u8; SECTOR];
        u1[..4].copy_from_slice(b"blk1");
        layout.extend_from_slice(&u1);
        layout.extend_from_slice(&[0xEE; SECTOR]);
        let mut u2 = vec![0u8; SECTOR];
        u2[..5].copy_from_slice(b"blk2!");
        layout.extend_from_slice(&u2);
        let ext = b.alloc_span(&layout);
        let size = (SECTOR + 5) as u32;
        let mut d = IsoBuilder::dirent_ea(ext, size, 0, 1, b"FILE.BIN;1", &[]);
        d[26] = 1; // File Unit Size
        d[27] = 1; // Interleave Gap Size
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            d,
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let e = &out.entries[0];
        let xa = e.xa.as_ref().expect("xa record");
        assert_eq!(xa.owner_id, 5);
        assert_eq!(e.gid, 6);
        // other-read denied -> other keeps only x.
        assert_eq!(e.mode & 0o777, 0o551);
        assert_eq!(e.data.len(), SECTOR + 5);
        assert_eq!(&e.data[..4], b"blk1");
        assert_eq!(&e.data[SECTOR..SECTOR + 5], b"blk2!");
        assert!(!e.data.contains(&0xEE));
    }

    /// Interleaved EA whose block count disagrees with the File
    /// Unit Size is rejected (ECMA-119 §6.4.4).
    #[test]
    fn xa_interleaved_bad_ea_len() {
        let mut b = IsoBuilder::new();
        let f = b.alloc(b"data");
        let mut d = IsoBuilder::dirent_ea(f, 4, 0, 1, b"BAD.BIN;1", &[]);
        d[26] = 2; // File Unit Size 2 != ext_attr_len 1
        d[27] = 1;
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], &[]),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            d,
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// Rock Ridge `SF` (RRIP §4.1.7): virtual size and table depth
    /// are exposed; the on-disc encoding stays in `data`.
    #[test]
    fn rr_sf_sparse_fields() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let mut susp = susp_px(0o100444);
        susp.extend_from_slice(&susp_sf(0x1_0000_0ABC, 2));
        let f = b.alloc(b"ENCODED");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 7, 0, b"SPARSE.BIN;1", &susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let e = &out.entries[0];
        assert_eq!(
            e.sparse,
            Some(RrSparse {
                size: 0x1_0000_0ABC,
                table_depth: 2,
            })
        );
        assert_eq!(e.data, b"ENCODED");
    }

    #[test]
    fn rr_sf_rejects_short() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let susp = vec![b'S', b'F', 8, 1, 0, 0, 0, 0];
        let f = b.alloc(b"x");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 1, 0, b"SPARSE.BIN;1", &susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        assert!(matches!(decode(&img), Err(Error::InvalidData(_))));
    }

    /// SUSP `PD` padding is skipped and `ES` extension selector
    /// fields are exposed on `IsoEntry::susp_ext`.
    #[test]
    fn susp_pd_es_parsed() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let mut susp = susp_pd(9);
        susp.extend_from_slice(&susp_es(1, 2, b"ZZZZ_199X", b"a desc", b"an.org"));
        susp.extend_from_slice(&susp_px(0o100444));
        let f = b.alloc(b"data");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, b"FILE.TXT;1", &susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let e = &out.entries[0];
        assert_eq!(e.data, b"data");
        assert_eq!(e.mode, 0o100444); // PX after PD still parsed
        assert_eq!(e.susp_ext.len(), 1);
        let x = &e.susp_ext[0];
        assert_eq!(x.sequence, Some(1));
        assert_eq!(x.version, 2);
        assert_eq!(x.id, b"ZZZZ_199X");
        assert_eq!(x.descriptor, b"a desc");
        assert_eq!(x.source, b"an.org");
    }

    /// An `ER` reference decodes through the same path with no
    /// sequence byte.
    #[test]
    fn susp_er_parsed() {
        let mut b = IsoBuilder::new();
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        let id = b"RRIP_1991A";
        let des = b"THE ROCK RIDGE INTERCHANGE PROTOCOL";
        let src = b"IEEE_P1282";
        let mut er = vec![
            b'E',
            b'R',
            (8 + id.len() + des.len() + src.len()) as u8,
            1,
            id.len() as u8,
            des.len() as u8,
            src.len() as u8,
            1,
        ];
        er.extend_from_slice(id);
        er.extend_from_slice(des);
        er.extend_from_slice(src);
        let f = b.alloc(b"data");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, b"FILE.TXT;1", &er),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        let x = &out.entries[0].susp_ext[0];
        assert_eq!(x.sequence, None);
        assert_eq!(x.id, b"RRIP_1991A");
        assert_eq!(x.descriptor, des);
        assert_eq!(x.source, b"IEEE_P1282");
    }

    /// Apple `AA` (current) and `BA` (old) signatures decode HFS
    /// and ProDOS metadata (TN FL36).
    #[test]
    fn apple_aa_ba_parsed() {
        let mut b = IsoBuilder::new();
        // Apple extensions do not use SUSP framing, but the records
        // coexist with it; include SP so the SUSP walker sees them.
        let sp = &[b'S', b'P', 7, 1, 0xBE, 0xEF, 0];
        // AA HFS (ID 2, len 14): type/creator/flags.
        let mut hfs_p = Vec::new();
        hfs_p.extend_from_slice(b"TEXT");
        hfs_p.extend_from_slice(b"ttxt");
        hfs_p.extend_from_slice(&0x8000u16.to_be_bytes());
        let mut susp = susp_aa(2, &hfs_p);
        // AA ProDOS (ID 1, len 7): file type + LE aux type.
        susp.extend_from_slice(&susp_aa(1, &[0x04, 0x34, 0x12]));
        // BA HFS (ID 6, implied len 13) on a second record.
        let mut ba_susp = susp_ba(6, &hfs_p);
        ba_susp.extend_from_slice(&susp_ba(1, &[0xB3, 0x78, 0x56]));
        let f = b.alloc(b"data");
        let g = b.alloc(b"more");
        let rootd = IsoBuilder::dir_block(&[
            IsoBuilder::dirent(0, 0, 2, &[0], sp),
            IsoBuilder::dirent(0, 0, 2, &[1], &[]),
            IsoBuilder::dirent(f, 4, 0, b"FILE.TXT;1", &susp),
            IsoBuilder::dirent(g, 4, 0, b"OLD.BIN;1", &ba_susp),
        ]);
        let root = b.alloc(&rootd);
        let img = b.finish(root, SECTOR as u32);
        let out = decode(&img).unwrap();
        assert_eq!(
            out.entries[0].apple,
            [
                AppleExt::Hfs {
                    file_type: *b"TEXT",
                    file_creator: *b"ttxt",
                    finder_flags: 0x8000,
                },
                AppleExt::ProDos {
                    file_type: 0x04,
                    aux_type: 0x1234,
                },
            ]
        );
        assert_eq!(
            out.entries[1].apple,
            [
                AppleExt::Hfs {
                    file_type: *b"TEXT",
                    file_creator: *b"ttxt",
                    finder_flags: 0x8000,
                },
                AppleExt::ProDos {
                    file_type: 0xB3,
                    aux_type: 0x5678,
                },
            ]
        );
    }
}
