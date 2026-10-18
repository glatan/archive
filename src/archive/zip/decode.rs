//! ZIP archive decoding.

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::crc32;

#[cfg(feature = "bzip2")]
use crate::compress::bzip2;
#[cfg(feature = "xz")]
use crate::compress::xz;
#[cfg(feature = "zstd")]
use crate::compress::zstd;

use super::crypto::{
    ZIP_AES_METHOD, ZipAesExtraField, decode_aes_payload, decode_traditional_payload,
    parse_aes_extra_field, parse_archive_decryption_header, parse_strong_encryption_extra,
};
use super::decode_metadata;

const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4B50;
const CENTRAL_DIRECTORY_HEADER_SIGNATURE: u32 = 0x0201_4B50;
const EOCD_SIGNATURE: u32 = 0x0605_4B50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4B50;
const ZIP64_EOCD_LOCATOR_SIGNATURE: u32 = 0x0706_4B50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4B50;
const ARCHIVE_EXTRA_DATA_RECORD_SIGNATURE: u32 = 0x0806_4B50;
const DIGITAL_SIGNATURE_SIGNATURE: u32 = 0x0505_4B50;

/// Parsed metadata for a ZIP entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipHeader {
    /// General purpose bit flag.
    pub flags: u16,
    /// Compression method (0 = store, 8 = deflate).
    pub compression_method: u16,
    /// Deflate option from bits 1-2 of the general purpose flag.
    /// 0 = Normal, 1 = Maximum, 2 = Fast, 3 = Super Fast.
    pub deflate_option: u8,
    /// DOS modification time.
    pub mod_time: u16,
    /// DOS modification date.
    pub mod_date: u16,
    /// CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Optional file comment.
    pub comment: String,
    /// Internal file attributes from the Central Directory.
    pub internal_attributes: u16,
    /// External file attributes from the Central Directory.
    pub external_attributes: u32,
    /// NTFS modification time (100-nanosecond intervals since 1601-01-01) from extra field 0x000a.
    pub ntfs_mtime: Option<u64>,
    /// NTFS access time (100-nanosecond intervals since 1601-01-01) from extra field 0x000a.
    pub ntfs_atime: Option<u64>,
    /// NTFS creation time (100-nanosecond intervals since 1601-01-01) from extra field 0x000a.
    pub ntfs_ctime: Option<u64>,
    /// Unix modification time (seconds since epoch) from extra field 0x5455.
    pub unix_mtime: Option<u32>,
    /// Unix access time (seconds since epoch) from extra field 0x5455.
    pub unix_atime: Option<u32>,
    /// Unix UID from extra field 0x000d.
    pub unix_uid: Option<u16>,
    /// Unix GID from extra field 0x000d.
    pub unix_gid: Option<u16>,
    /// Unicode path from extra field 0x7075.
    pub unicode_path: Option<String>,
    /// Unicode comment from extra field 0x6375.
    pub unicode_comment: Option<String>,
    /// Host system from version_made_by upper byte (0=DOS, 3=UNIX, etc).
    pub host_system: u8,
    /// Version needed to extract.
    pub version_needed: u16,
}

/// A single decoded ZIP entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Parsed header metadata.
    pub header: ZipHeader,
    /// Filename.
    pub name: String,
    /// File contents.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ZipEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decode a ZIP archive into memory.
pub fn decode(input: &[u8]) -> Result<Vec<ZipEntry>, Error> {
    decode_collected(input, None, None)
}

/// Visit each ZIP entry. Payload bytes are dropped when `visit` returns.
pub fn for_each_entry<F>(input: &[u8], visit: F) -> Result<(), Error>
where
    F: FnMut(ZipEntry) -> Result<(), Error>,
{
    decode_impl(input, None, None, visit)
}

fn decode_collected(
    input: &[u8],
    password: Option<&[u8]>,
    disk_map: Option<&DiskMap>,
) -> Result<Vec<ZipEntry>, Error> {
    let mut entries = Vec::new();
    decode_impl(input, password, disk_map, |entry| {
        entries.push(entry);
        Ok(())
    })?;
    Ok(entries)
}

/// Decode a ZIP archive into memory using a password for encrypted entries.
pub fn decode_with_password(input: &[u8], password: &str) -> Result<Vec<ZipEntry>, Error> {
    decode_collected(input, Some(password.as_bytes()), None)
}

/// Decode a ZIP archive into memory using a password for encrypted entries.
pub fn decode_with_password_bytes(input: &[u8], password: &[u8]) -> Result<Vec<ZipEntry>, Error> {
    decode_collected(input, Some(password), None)
}

/// Decode a split/spanned ZIP archive (`file.z01`, `file.z02`, ...,
/// `file.zip`) into a list of entries.
///
/// The segments are one logical byte stream (APPNOTE §8): the last
/// segment carries the End of Central Directory record, whose disk
/// fields must be consistent with the number of supplied parts.
/// Disk-relative offsets (entry `disk_start` + local header offset,
/// central directory disk, ZIP64 EOCD locator/record disk fields)
/// are resolved against each segment's start offset, so entries
/// stored on any disk are extracted. An optional `0x08074b50`
/// spanning signature at the start of the first segment is tolerated
/// (it is part of the byte stream offsets are relative to). So is the
/// single-segment temporary spanning marker `0x30304b50` (§8.5.4).
/// Empty parts are rejected.
pub fn decode_parts(parts: &[&[u8]]) -> Result<Vec<ZipEntry>, Error> {
    decode_parts_impl(parts, None)
}

/// [`decode_parts`] with a password for encrypted entries.
pub fn decode_parts_with_password_bytes(
    parts: &[&[u8]],
    password: &[u8],
) -> Result<Vec<ZipEntry>, Error> {
    decode_parts_impl(parts, Some(password))
}

fn decode_parts_impl(parts: &[&[u8]], password: Option<&[u8]>) -> Result<Vec<ZipEntry>, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidData("zip: empty archive part"));
    }
    let mut starts = Vec::with_capacity(parts.len());
    let mut pos = 0usize;
    for p in parts {
        starts.push(pos);
        pos += p.len();
    }
    let disk_map = DiskMap { starts };
    if parts.len() == 1 {
        return decode_collected(parts[0], password, Some(&disk_map));
    }
    let mut input = Vec::with_capacity(pos);
    for p in parts {
        input.extend_from_slice(p);
    }
    decode_collected(&input, password, Some(&disk_map))
}

/// Segment map of a split/spanned archive: `starts[d]` is the byte
/// offset where disk `d` begins inside the concatenated stream.
#[derive(Debug)]
struct DiskMap {
    starts: Vec<usize>,
}

impl DiskMap {
    /// Resolve a disk-relative offset (APPNOTE §4.4.13/§4.4.15/§4.4.16)
    /// into an absolute offset in the concatenated stream.
    fn resolve(&self, disk: u64, offset: u64) -> Result<usize, Error> {
        let disk =
            usize::try_from(disk).map_err(|_| Error::InvalidData("zip: disk index too large"))?;
        let base = self
            .starts
            .get(disk)
            .ok_or(Error::InvalidData("zip: disk index out of range"))?;
        let offset =
            usize::try_from(offset).map_err(|_| Error::Unsupported("zip: offset too large"))?;
        base.checked_add(offset)
            .ok_or(Error::InvalidData("zip: disk offset overflow"))
    }
}

fn decode_impl<F>(
    input: &[u8],
    password: Option<&[u8]>,
    disk_map: Option<&DiskMap>,
    mut visit: F,
) -> Result<(), Error>
where
    F: FnMut(ZipEntry) -> Result<(), Error>,
{
    if input.is_empty() {
        return Ok(());
    }

    let eocd_offset = find_eocd(input)?;
    let mut cursor = Cursor::new(input);
    cursor.set(eocd_offset);
    let eocd = parse_eocd(&mut cursor)?;

    // Multi-disk consistency: the EOCD sits on the last disk, so its
    // "number of this disk" equals parts-1 (APPNOTE §8, §4.4.19).
    match disk_map {
        None => {
            if eocd.disk_number != 0 || eocd.cd_disk_number != 0 {
                return Err(Error::Unsupported("zip: multi-disk archives"));
            }
        }
        Some(m) => {
            if eocd.disk_number as usize != m.starts.len() - 1
                || eocd.cd_disk_number > eocd.disk_number
            {
                return Err(Error::InvalidData("zip: disk count mismatch"));
            }
        }
    }

    // Self-extracting archive (SFX) support (APPNOTE foreword /
    // de facto): the offsets recorded in the EOCD, ZIP64 structures and
    // central directory are relative to the start of the archive proper,
    // so a prepended executable stub shifts every absolute position by
    // the stub length. For single-disk archives the stub length equals
    // the gap between the recorded end of the central directory and the
    // actual position of the structure that follows it.
    let sfx_prefix = if disk_map.is_none() {
        detect_sfx_prefix(input, eocd_offset, &eocd)?
    } else {
        0
    };

    let zip64 = if eocd.requires_zip64() {
        Some(parse_zip64_locator_and_record(
            input,
            eocd_offset,
            disk_map,
            sfx_prefix,
        )?)
    } else {
        None
    };

    let (cd_offset, cd_disk) = zip64.as_ref().map_or(
        (
            eocd.central_directory_offset as u64,
            eocd.cd_disk_number as u64,
        ),
        |z| (z.central_directory_offset, z.cd_disk_number),
    );
    let total_entries = zip64
        .as_ref()
        .map_or(eocd.total_entries as u64, |z| z.total_entries);

    // APPNOTE §4.4.15: the CD offset is relative to the start of the
    // disk on which the central directory begins. For a single-disk
    // archive carrying an SFX stub, the stub length shifts it to an
    // absolute position in the input.
    let cd_offset = match disk_map {
        Some(m) => m.resolve(cd_disk, cd_offset)?,
        None => usize::try_from(
            cd_offset
                .checked_add(sfx_prefix)
                .ok_or(Error::InvalidData("zip: central directory offset overflow"))?,
        )
        .map_err(|_| Error::Unsupported("zip: central directory offset too large"))?,
    };
    if cd_offset > input.len() {
        return Err(Error::UnexpectedEof);
    }

    // Skip Archive Extra Data Record (APPNOTE §4.3.11, signature 0x08064B50)
    // if present before the Central Directory.
    let cd_offset = skip_archive_extra_data_record(input, cd_offset)?;

    // Central Directory Encryption detection (APPNOTE §4.3.10, §7.5):
    // If the data at cd_offset does not start with a Central Directory header
    // signature (0x02014B50), an Archive Decryption Header may precede
    // encrypted CD data. CD decryption is intentionally not implemented: the
    // PKWARE strong-encryption technology is patent-encumbered (APPNOTE
    // §10.1 requires a separate license agreement; see THIRD_PARTY_NOTICES).
    reject_encrypted_central_directory(input, cd_offset, eocd_offset)?;

    let mut cursor = Cursor::new(input);
    cursor.set(cd_offset);
    let mut records = Vec::new();
    for _ in 0..total_entries {
        records.push(parse_central_directory_record(&mut cursor, disk_map)?);
    }

    // Skip Digital Signature record (APPNOTE §4.3.13, signature 0x05054B50)
    // if present after the Central Directory entries.
    if cursor.position() + 4 <= input.len()
        && read_u32_at(input, cursor.position()).is_ok_and(|sig| sig == DIGITAL_SIGNATURE_SIGNATURE)
    {
        // Digital signature: signature(4) + size_of_data(2) + signature_data(size)
        cursor.skip(4)?;
        let sig_size = cursor.read_u16()? as usize;
        cursor.skip(sig_size)?;
    }

    // Shift each entry's local header offset (recorded relative to the
    // archive start, APPNOTE §4.4.16) by the SFX stub length.
    if sfx_prefix != 0 {
        let prefix = usize::try_from(sfx_prefix)
            .map_err(|_| Error::Unsupported("zip: SFX prefix too large"))?;
        for record in &mut records {
            record.local_header_offset = record
                .local_header_offset
                .checked_add(prefix)
                .ok_or(Error::InvalidData("zip: local header offset overflow"))?;
        }
    }

    let next_offsets: Vec<usize> = records
        .iter()
        .enumerate()
        .map(|(index, _)| {
            records
                .get(index + 1)
                .map_or(cd_offset, |next| next.local_header_offset)
        })
        .collect();

    for (record, next_offset) in records.iter().zip(next_offsets) {
        visit(extract_entry(
            input,
            record,
            next_offset,
            cd_offset,
            password,
        )?)?;
    }
    Ok(())
}

/// Reject an encrypted Central Directory (APPNOTE §4.3.10, §7.5).
///
/// If the data at cd_offset does not start with a Central Directory header
/// signature (0x02014B50), an Archive Decryption Header (no signature) may
/// precede encrypted CD data. Decryption is intentionally not implemented,
/// so archives using it are reported as unsupported. Data that is neither a
/// CD header nor a plausible ADH falls through to normal CD parsing, which
/// produces a proper format error.
fn reject_encrypted_central_directory(
    input: &[u8],
    cd_offset: usize,
    eocd_offset: usize,
) -> Result<(), Error> {
    if cd_offset + 4 <= input.len()
        && read_u32_at(input, cd_offset).is_ok_and(|sig| sig == CENTRAL_DIRECTORY_HEADER_SIGNATURE)
    {
        return Ok(());
    }
    // Empty archive (0 entries): cd_offset may equal eocd_offset.
    if cd_offset >= eocd_offset {
        return Ok(());
    }

    if let Ok((adh, _)) = parse_archive_decryption_header(&input[cd_offset..]) {
        let is_known_alg = matches!(
            adh.alg_id,
            0x6601 | 0x6602 | 0x6603 | 0x6609 | 0x660E | 0x660F | 0x6610 | 0x6702 | 0x6801
        );
        if is_known_alg {
            return Err(Error::Unsupported(
                "zip: central directory encryption is not supported",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(
    mut reader: R,
) -> Result<Vec<ZipEntry>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

#[derive(Debug, Clone)]
struct CentralDirectoryRecord {
    name: String,
    comment: String,
    flags: u16,
    compression_method: u16,
    actual_compression_method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: usize,
    aes: Option<ZipAesExtraField>,
    strong_encryption: Option<super::crypto::StrongEncryptionHeader>,
    host_system: u8,
    version_needed: u16,
    internal_attributes: u16,
    external_attributes: u32,
    ntfs_mtime: Option<u64>,
    ntfs_atime: Option<u64>,
    ntfs_ctime: Option<u64>,
    unix_mtime: Option<u32>,
    unix_atime: Option<u32>,
    unix_uid: Option<u16>,
    unix_gid: Option<u16>,
    unicode_path: Option<String>,
    unicode_comment: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct EocdRecord {
    disk_number: u16,
    cd_disk_number: u16,
    total_entries: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
}

impl EocdRecord {
    const fn requires_zip64(self) -> bool {
        self.total_entries == u16::MAX || self.central_directory_offset == u32::MAX
    }
}

#[derive(Debug, Clone, Copy)]
struct Zip64Record {
    total_entries: u64,
    central_directory_offset: u64,
    cd_disk_number: u64,
}

/// Skip an Archive Extra Data Record (APPNOTE §4.3.11) if one is present
/// at `offset`. Returns the (possibly advanced) offset that points to the
/// Central Directory.
fn skip_archive_extra_data_record(input: &[u8], offset: usize) -> Result<usize, Error> {
    if offset + 4 > input.len() {
        return Ok(offset);
    }
    if read_u32_at(input, offset)? != ARCHIVE_EXTRA_DATA_RECORD_SIGNATURE {
        return Ok(offset);
    }
    // Structure: signature(4) + extra_field_length(4) + extra_field_data(variable)
    if offset + 8 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let extra_len = read_u32_at(input, offset + 4)? as usize;
    let end = offset
        .checked_add(8)
        .and_then(|v| v.checked_add(extra_len))
        .ok_or(Error::InvalidData(
            "zip: archive extra data record overflow",
        ))?;
    if end > input.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(end)
}

fn find_eocd(input: &[u8]) -> Result<usize, Error> {
    let min_len = 22usize;
    if input.len() < min_len {
        return Err(Error::UnexpectedEof);
    }
    let start = input.len().saturating_sub(65_557);
    for offset in (start..=input.len() - min_len).rev() {
        if read_u32_at(input, offset)? != EOCD_SIGNATURE {
            continue;
        }
        let comment_len = read_u16_at(input, offset + 20)? as usize;
        if offset + min_len + comment_len == input.len() {
            return Ok(offset);
        }
    }
    Err(Error::InvalidData(
        "zip: end of central directory not found",
    ))
}

/// Detect an executable stub prepended to a single-disk archive
/// (self-extracting archive, APPNOTE foreword / de facto).
///
/// The offsets recorded in the EOCD and central directory are relative
/// to the start of the archive proper (APPNOTE §4.4.15/§4.4.16), so a
/// prepended stub shifts every absolute position by the stub length.
/// That length equals the gap between the recorded end of the central
/// directory and the actual position of the record that follows it —
/// the same heuristic Python's `zipfile` uses. Returns the detected
/// prefix length in bytes (0 when the archive starts at offset 0).
fn detect_sfx_prefix(input: &[u8], eocd_offset: usize, eocd: &EocdRecord) -> Result<u64, Error> {
    if eocd.requires_zip64() {
        return detect_sfx_prefix_zip64(input, eocd_offset);
    }
    // The recorded CD offset may point at an Archive Extra Data Record
    // (APPNOTE §4.3.11) that precedes the actual central directory.
    let recorded_cd_start = usize::try_from(eocd.central_directory_offset)
        .map_err(|_| Error::Unsupported("zip: central directory offset too large"))?;
    let cd_start = if read_u32_at(input, recorded_cd_start)
        .is_ok_and(|sig| sig == ARCHIVE_EXTRA_DATA_RECORD_SIGNATURE)
    {
        skip_archive_extra_data_record(input, recorded_cd_start)?
    } else {
        recorded_cd_start
    };
    let recorded_cd_end = cd_start as u64 + eocd.central_directory_size as u64;
    let eocd_pos = eocd_offset as u64;
    if recorded_cd_end > eocd_pos {
        return Err(Error::InvalidData(
            "zip: central directory extends past EOCD",
        ));
    }
    let prefix = eocd_pos - recorded_cd_end;
    if prefix == 0 {
        return Ok(0);
    }
    // A gap between the recorded CD end and the EOCD can also be
    // trailing metadata that is not counted in the recorded CD size
    // (e.g. a digital signature record, APPNOTE §4.3.13). Only treat it
    // as an SFX stub when the shifted position actually points at the
    // start of the central directory.
    let adjusted = eocd.central_directory_offset as u64 + prefix;
    let plausible = usize::try_from(adjusted).ok().is_some_and(|pos| {
        pos == eocd_offset
            || read_u32_at(input, pos).is_ok_and(|sig| {
                sig == CENTRAL_DIRECTORY_HEADER_SIGNATURE
                    || sig == ARCHIVE_EXTRA_DATA_RECORD_SIGNATURE
            })
    });
    Ok(if plausible { prefix } else { 0 })
}

/// SFX prefix detection for ZIP64 archives. The regular EOCD carries
/// saturated (`0xFFFF`/`0xFFFFFFFF`) fields, so the ZIP64 EOCD record
/// serves as the reference point instead: its recorded offset is stored
/// in the locator immediately before the EOCD (APPNOTE §4.3.15), while
/// its actual position is the last ZIP64 EOCD signature before that
/// locator.
fn detect_sfx_prefix_zip64(input: &[u8], eocd_offset: usize) -> Result<u64, Error> {
    if eocd_offset < 20 {
        // No room for the locator; the normal path reports the error.
        return Ok(0);
    }
    let locator_offset = eocd_offset - 20;
    if read_u32_at(input, locator_offset)? != ZIP64_EOCD_LOCATOR_SIGNATURE {
        return Ok(0);
    }
    let recorded = read_u64_at(input, locator_offset + 8)?;
    if usize::try_from(recorded)
        .ok()
        .is_some_and(|pos| read_u32_at(input, pos).is_ok_and(|sig| sig == ZIP64_EOCD_SIGNATURE))
    {
        return Ok(0);
    }
    // The record is not at its recorded offset: a stub may have shifted
    // it. Scan backwards from the locator for its actual position.
    for pos in (0..locator_offset).rev() {
        if read_u32_at(input, pos)? == ZIP64_EOCD_SIGNATURE {
            let actual = pos as u64;
            if actual < recorded {
                return Err(Error::InvalidData(
                    "zip: ZIP64 EOCD record precedes its recorded offset",
                ));
            }
            return Ok(actual - recorded);
        }
    }
    // Not found; the normal path reports the error.
    Ok(0)
}

fn parse_eocd(cursor: &mut Cursor<'_>) -> Result<EocdRecord, Error> {
    let signature = cursor.read_u32()?;
    if signature != EOCD_SIGNATURE {
        return Err(Error::InvalidData("zip: invalid EOCD signature"));
    }
    let disk_number = cursor.read_u16()?;
    let cd_disk_number = cursor.read_u16()?;
    let _disk_entries = cursor.read_u16()?;
    let total_entries = cursor.read_u16()?;
    let cd_size = cursor.read_u32()?;
    let cd_offset = cursor.read_u32()?;
    let comment_len = cursor.read_u16()? as usize;
    cursor.skip(comment_len)?;
    Ok(EocdRecord {
        disk_number,
        cd_disk_number,
        total_entries,
        central_directory_size: cd_size,
        central_directory_offset: cd_offset,
    })
}

fn parse_zip64_locator_and_record(
    input: &[u8],
    eocd_offset: usize,
    disk_map: Option<&DiskMap>,
    sfx_prefix: u64,
) -> Result<Zip64Record, Error> {
    if eocd_offset < 20 {
        return Err(Error::InvalidData("zip: missing ZIP64 locator"));
    }
    let locator_offset = eocd_offset - 20;
    if read_u32_at(input, locator_offset)? != ZIP64_EOCD_LOCATOR_SIGNATURE {
        return Err(Error::InvalidData("zip: missing ZIP64 locator"));
    }
    let disk_with_record = read_u32_at(input, locator_offset + 4)?;
    let zip64_record_offset = read_u64_at(input, locator_offset + 8)?;
    let total_disks = read_u32_at(input, locator_offset + 16)?;
    match disk_map {
        None => {
            if disk_with_record != 0 || total_disks != 1 {
                return Err(Error::Unsupported("zip: multi-disk ZIP64 archives"));
            }
        }
        Some(m) => {
            if total_disks as usize != m.starts.len() || disk_with_record as usize >= m.starts.len()
            {
                return Err(Error::InvalidData("zip: disk count mismatch"));
            }
        }
    }

    // APPNOTE §4.3.15: the record offset is relative to the start of
    // the disk carrying the ZIP64 EOCD record. For a single-disk archive
    // carrying an SFX stub, the stub length shifts it to an absolute
    // position in the input.
    let record_offset = match disk_map {
        Some(m) => m.resolve(disk_with_record as u64, zip64_record_offset)?,
        None => usize::try_from(
            zip64_record_offset
                .checked_add(sfx_prefix)
                .ok_or(Error::InvalidData("zip: ZIP64 record offset overflow"))?,
        )
        .map_err(|_| Error::Unsupported("zip: ZIP64 record offset too large"))?,
    };
    if read_u32_at(input, record_offset)? != ZIP64_EOCD_SIGNATURE {
        return Err(Error::InvalidData("zip: invalid ZIP64 EOCD signature"));
    }
    let size_of_record = read_u64_at(input, record_offset + 4)?;
    let record_end = record_offset
        .checked_add(12)
        .and_then(|v| v.checked_add(size_of_record as usize))
        .ok_or(Error::InvalidData("zip: ZIP64 EOCD overflow"))?;
    if record_end > input.len() {
        return Err(Error::UnexpectedEof);
    }

    let mut cursor = Cursor::new(&input[record_offset + 12..record_end]);
    let version_made_by = cursor.read_u16()?;
    let version_needed = cursor.read_u16()?;
    let disk_number = cursor.read_u32()?;
    let cd_disk_number = cursor.read_u32()?;
    let _disk_entries = cursor.read_u64()?;
    let total_entries = cursor.read_u64()?;
    let _cd_size = cursor.read_u64()?;
    let cd_offset = cursor.read_u64()?;

    let _ = version_made_by;
    let _ = version_needed;
    match disk_map {
        None => {
            if disk_number != 0 || cd_disk_number != 0 {
                return Err(Error::Unsupported("zip: multi-disk ZIP64 archives"));
            }
        }
        Some(m) => {
            // The ZIP64 EOCD record sits on the last disk of the set.
            if disk_number as usize != m.starts.len() - 1 || cd_disk_number > disk_number {
                return Err(Error::InvalidData("zip: disk count mismatch"));
            }
        }
    }

    // ZIP64 EOCD extensible data sector (APPNOTE §4.3.14.3):
    // size_of_record covers all bytes after itself. The fixed fields above
    // consume 44 bytes; any remaining bytes form the extensible data sector.
    // We intentionally skip this sector — its contents are not needed for
    // basic archive extraction.

    Ok(Zip64Record {
        total_entries,
        central_directory_offset: cd_offset,
        cd_disk_number: cd_disk_number as u64,
    })
}

fn parse_central_directory_record(
    cursor: &mut Cursor<'_>,
    disk_map: Option<&DiskMap>,
) -> Result<CentralDirectoryRecord, Error> {
    let signature = cursor.read_u32()?;
    if signature != CENTRAL_DIRECTORY_HEADER_SIGNATURE {
        return Err(Error::InvalidData("zip: invalid central directory header"));
    }

    let version_made_by = cursor.read_u16()?;
    let version_needed = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let compression_method = cursor.read_u16()?;
    let mod_time = cursor.read_u16()?;
    let mod_date = cursor.read_u16()?;
    let crc32 = cursor.read_u32()?;
    let compressed_size_raw = cursor.read_u32()?;
    let uncompressed_size_raw = cursor.read_u32()?;
    let name_len = cursor.read_u16()? as usize;
    let extra_len = cursor.read_u16()? as usize;
    let comment_len = cursor.read_u16()? as usize;
    let disk_start_raw = cursor.read_u16()?;
    let internal_attributes = cursor.read_u16()?;
    let external_attributes = cursor.read_u32()?;
    let local_header_offset_raw = cursor.read_u32()?;

    let name = cursor.read_string(name_len, (flags & (1 << 11)) != 0)?;
    let extra = cursor.read_bytes(extra_len)?;
    let comment = cursor.read_string(comment_len, (flags & (1 << 11)) != 0)?;

    let zip64 = parse_zip64_extra(
        &extra,
        compressed_size_raw == u32::MAX,
        uncompressed_size_raw == u32::MAX,
        local_header_offset_raw == u32::MAX,
        disk_start_raw == 0xFFFF,
    )?;
    let aes = parse_aes_extra_field(&extra)?;
    if aes.is_some() && compression_method != ZIP_AES_METHOD {
        return Err(Error::InvalidData("zip: AES extra field without method 99"));
    }
    let strong_encryption = parse_strong_encryption_extra(&extra)?;

    // Parse additional extra fields
    let ntfs = parse_ntfs_extra(&extra);
    let ext_ts = parse_extended_timestamp_extra(&extra);
    let unix_extra = parse_unix_extra(&extra);
    let unicode_path = parse_unicode_path_extra(&extra);
    let unicode_comment = parse_unicode_comment_extra(&extra);

    let compressed_size = zip64.compressed_size.unwrap_or(compressed_size_raw as u64);
    let uncompressed_size = zip64
        .uncompressed_size
        .unwrap_or(uncompressed_size_raw as u64);
    let local_header_offset_u64 = zip64
        .local_header_offset
        .unwrap_or(local_header_offset_raw as u64);
    // APPNOTE §4.4.13/§4.5.3: a disk-start of 0xFFFF means the real
    // disk number is stored in the ZIP64 extra field, right after the
    // size/offset overrides.
    let disk_start = if disk_start_raw == 0xFFFF {
        zip64
            .disk_start
            .ok_or(Error::InvalidData("zip: missing ZIP64 disk start field"))?
    } else {
        disk_start_raw as u32
    };
    // APPNOTE §4.4.16: the local header offset is relative to the
    // start of the disk on which the entry begins.
    let local_header_offset = match disk_map {
        Some(m) => m.resolve(disk_start as u64, local_header_offset_u64)?,
        None => {
            if disk_start != 0 {
                return Err(Error::Unsupported("zip: multi-disk entries"));
            }
            usize::try_from(local_header_offset_u64)
                .map_err(|_| Error::Unsupported("zip: local header offset too large"))?
        }
    };
    let actual_compression_method =
        aes.map_or(compression_method, |aes| aes.actual_compression_method);

    Ok(CentralDirectoryRecord {
        name,
        comment,
        flags,
        compression_method,
        actual_compression_method,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        local_header_offset,
        aes,
        strong_encryption,
        internal_attributes,
        external_attributes,
        ntfs_mtime: ntfs.mtime,
        ntfs_atime: ntfs.atime,
        ntfs_ctime: ntfs.ctime,
        unix_mtime: ext_ts.mtime,
        unix_atime: ext_ts.atime,
        unix_uid: unix_extra.uid,
        unix_gid: unix_extra.gid,
        unicode_path,
        unicode_comment,
        host_system: (version_made_by >> 8) as u8,
        version_needed,
    })
}

fn declared_output_len(size: u64) -> Result<usize, Error> {
    crate::util::bounded::declared_output_len(size)
}

fn extract_entry(
    input: &[u8],
    record: &CentralDirectoryRecord,
    next_local_header_offset: usize,
    central_directory_offset: usize,
    password: Option<&[u8]>,
) -> Result<ZipEntry, Error> {
    let mut cursor = Cursor::new(input);
    cursor.set(record.local_header_offset);

    if cursor.read_u32()? != LOCAL_FILE_HEADER_SIGNATURE {
        return Err(Error::InvalidData("zip: invalid local file header"));
    }
    let _version_needed = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let compression_method = cursor.read_u16()?;
    let _mod_time = cursor.read_u16()?;
    let _mod_date = cursor.read_u16()?;
    let local_crc32 = cursor.read_u32()?;
    let local_compressed_size = cursor.read_u32()?;
    let local_uncompressed_size = cursor.read_u32()?;
    let name_len = cursor.read_u16()? as usize;
    let extra_len = cursor.read_u16()? as usize;
    let local_name = cursor.read_string(name_len, (flags & (1 << 11)) != 0)?;
    let local_extra = cursor.read_bytes(extra_len)?;
    let data_start = cursor.position();

    if local_name != record.name {
        return Err(Error::InvalidData("zip: local and central names differ"));
    }
    if flags != record.flags || compression_method != record.compression_method {
        return Err(Error::InvalidData("zip: local and central headers differ"));
    }

    let local_zip64 = parse_zip64_extra(
        &local_extra,
        local_compressed_size == u32::MAX,
        local_uncompressed_size == u32::MAX,
        false,
        // Local file headers carry no disk-start field (APPNOTE §4.5.3).
        false,
    )?;
    let local_aes = parse_aes_extra_field(&local_extra)?;
    if local_aes.is_some() && compression_method != ZIP_AES_METHOD {
        return Err(Error::InvalidData("zip: AES extra field without method 99"));
    }
    if local_aes != record.aes {
        return Err(Error::InvalidData(
            "zip: local and central AES metadata differ",
        ));
    }

    // Bit 13 (0x2000): Central Directory field masking (APPNOTE §4.4.4).
    // When set, the CRC-32, compressed size, and uncompressed size in the CD
    // may contain masked (zeroed) values. The real values come from the Local
    // File Header (or its ZIP64 extra field).
    let cd_masked = (record.flags & 0x2000) != 0;

    let (effective_crc32, effective_compressed_size, effective_uncompressed_size) = if cd_masked {
        // Use local file header values (with ZIP64 override if applicable)
        (
            local_crc32,
            local_zip64
                .compressed_size
                .unwrap_or(local_compressed_size as u64),
            local_zip64
                .uncompressed_size
                .unwrap_or(local_uncompressed_size as u64),
        )
    } else {
        (
            record.crc32,
            record.compressed_size,
            record.uncompressed_size,
        )
    };

    let data_end = data_start
        .checked_add(
            usize::try_from(effective_compressed_size)
                .map_err(|_| Error::Unsupported("zip: compressed size too large"))?,
        )
        .ok_or(Error::InvalidData("zip: entry data overflow"))?;
    if data_end > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let compressed = &input[data_start..data_end];

    // Bit 6: Strong encryption requires version >= 50 and encryption flag (bit 0)
    if (flags & 0x0040) != 0 {
        if record.version_needed < 50 {
            return Err(Error::InvalidData(
                "zip: strong encryption (bit 6) requires version >= 50",
            ));
        }
        if (flags & 0x0001) == 0 {
            return Err(Error::InvalidData(
                "zip: strong encryption (bit 6) requires encryption flag (bit 0)",
            ));
        }
    }

    // Bit 6: Strong Encryption (APPNOTE §7). Decryption is intentionally
    // not implemented: APPNOTE §10.1 states that implementing the
    // strong-encryption technology requires a separate license agreement
    // from PKWARE (see THIRD_PARTY_NOTICES for the patent note).
    if (flags & 0x0040) != 0 {
        let algo_name = record
            .strong_encryption
            .as_ref()
            .map_or("Unknown", |se| se.algorithm_name());
        return Err(Error::Unsupported(match algo_name {
            "AES-128" | "AES-192" | "AES-256" => "zip: strong encryption (AES) is not supported",
            _ => "zip: strong encryption is not supported",
        }));
    }

    let effective_compressed = if (flags & 0x0001) != 0 {
        let password = password.ok_or(Error::Unsupported(
            "zip: encrypted entry requires a password",
        ))?;
        if let Some(aes) = record.aes {
            decode_aes_payload(password, compressed, aes)?
        } else {
            decode_traditional_payload(
                password,
                compressed,
                effective_crc32,
                record.mod_time,
                (flags & 0x0008) != 0,
            )?
        }
    } else {
        compressed.to_vec()
    };

    let data = match record.actual_compression_method {
        0 => effective_compressed,
        1 => super::unshrink::unshrink(&effective_compressed)?,
        2 => super::expand::expand(
            &effective_compressed,
            1,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        3 => super::expand::expand(
            &effective_compressed,
            2,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        4 => super::expand::expand(
            &effective_compressed,
            3,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        5 => super::expand::expand(
            &effective_compressed,
            4,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        6 => super::implode::implode(
            &effective_compressed,
            record.flags,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        10 => super::dcl_implode::dcl_implode_decode(&effective_compressed)?,
        8 => deflate::decode::decode(&effective_compressed)?,
        9 => crate::compress::deflate64::decode::decode(&effective_compressed)?,
        #[cfg(feature = "bzip2")]
        12 => bzip2::decode::decode(&effective_compressed)?,
        #[cfg(not(feature = "bzip2"))]
        12 => {
            return Err(Error::Unsupported(
                "zip: bzip2 compression (enable bzip2 feature)",
            ));
        }
        #[cfg(any(feature = "lzip", feature = "xz", feature = "sevenz"))]
        14 => {
            // LZMA in ZIP: 4-byte header (version, prop-size) + LZMA props + stream
            if effective_compressed.len() < 4 {
                return Err(Error::InvalidData("zip: LZMA header too short"));
            }
            let prop_size =
                u16::from_le_bytes([effective_compressed[2], effective_compressed[3]]) as usize;
            if effective_compressed.len() < 4 + prop_size {
                return Err(Error::InvalidData("zip: LZMA properties truncated"));
            }
            if prop_size < 5 {
                return Err(Error::InvalidData("zip: LZMA properties too short"));
            }
            let props_bytes = &effective_compressed[4..4 + prop_size];
            let lzma_data = &effective_compressed[4 + prop_size..];
            let prop_byte = props_bytes[0];
            let lc = prop_byte % 9;
            let rem = prop_byte / 9;
            let lp = rem % 5;
            let pb = rem / 5;
            let dict_size = u32::from_le_bytes([
                props_bytes[1],
                props_bytes[2],
                props_bytes[3],
                props_bytes[4],
            ]);
            let lzma_props = crate::compress::lzma::LzmaProperties { lc, lp, pb };
            // APPNOTE §5.8.9: bit 1 of general purpose flag indicates EOS marker usage
            let uses_eos = (record.flags & (1 << 1)) != 0;
            if uses_eos {
                crate::compress::lzma::lzma_decode_with_props(lzma_data, dict_size, lzma_props)
                    .map(|(v, _)| v)?
            } else {
                crate::compress::lzma::lzma_decode_with_props_and_size(
                    lzma_data,
                    dict_size,
                    lzma_props,
                    declared_output_len(effective_uncompressed_size)?,
                )
                .map(|(v, _)| v)?
            }
        }
        #[cfg(not(any(feature = "lzip", feature = "xz", feature = "sevenz")))]
        14 => {
            return Err(Error::Unsupported(
                "zip: LZMA compression (enable lzip/xz feature)",
            ));
        }
        #[cfg(feature = "zstd")]
        93 => zstd::decode::decode(&effective_compressed)?,
        #[cfg(not(feature = "zstd"))]
        93 => {
            return Err(Error::Unsupported(
                "zip: zstd compression (enable zstd feature)",
            ));
        }
        #[cfg(feature = "xz")]
        95 => xz::decode::decode(&effective_compressed)?,
        #[cfg(not(feature = "xz"))]
        95 => {
            return Err(Error::Unsupported(
                "zip: xz compression (enable xz feature)",
            ));
        }
        #[cfg(feature = "sevenz")]
        98 => {
            // PPMd in ZIP: 2-byte params (order | mem_size_order << 8) + stream
            if effective_compressed.len() < 2 {
                return Err(Error::InvalidData("zip: PPMd header too short"));
            }
            let params = u16::from_le_bytes([effective_compressed[0], effective_compressed[1]]);
            let order = (params & 0x00FF) as u8;
            let mem_order = ((params >> 8) & 0x00FF) as u32;
            let mem_size = 1u32
                .checked_shl(mem_order)
                .ok_or(Error::InvalidData("zip: PPMd mem_size overflow"))?;
            let ppmd_data = &effective_compressed[2..];
            let props = crate::compress::ppmd::Ppmd7Properties::new(order, mem_size)?;
            crate::compress::ppmd::decode(
                ppmd_data,
                props,
                declared_output_len(effective_uncompressed_size)?,
            )?
        }
        #[cfg(not(feature = "sevenz"))]
        98 => {
            return Err(Error::Unsupported(
                "zip: PPMd compression (enable sevenz feature)",
            ));
        }
        #[cfg(feature = "cmpsc")]
        16 => crate::compress::cmpsc::decode(
            &effective_compressed,
            declared_output_len(effective_uncompressed_size)?,
        )?,
        #[cfg(not(feature = "cmpsc"))]
        16 => {
            return Err(Error::Unsupported(
                "zip: IBM z/OS CMPSC compression (method 16; enable cmpsc feature)",
            ));
        }
        _ => return Err(Error::Unsupported("zip: compression method")),
    };

    if data.len() as u64 != effective_uncompressed_size {
        return Err(Error::SizeMismatch {
            expected: effective_uncompressed_size as u32,
            actual: data.len() as u32,
        });
    }
    let actual_crc32 = crc32::crc32(&data);
    let skip_crc_check = record
        .aes
        .is_some_and(|aes| aes.vendor_version == 2 && effective_crc32 == 0);
    if !skip_crc_check && actual_crc32 != effective_crc32 {
        return Err(Error::ChecksumMismatch {
            expected: effective_crc32,
            actual: actual_crc32,
        });
    }

    if (record.flags & 0x0008) != 0 {
        let descriptor_start = data_end;
        let expected_end = next_local_header_offset.min(central_directory_offset);
        validate_data_descriptor(
            &input[descriptor_start..expected_end],
            effective_crc32,
            effective_compressed_size,
            effective_uncompressed_size,
        )?;
    } else if !cd_masked && local_crc32 != 0 && local_crc32 != effective_crc32 {
        return Err(Error::InvalidData("zip: local header CRC mismatch"));
    }

    // Parse local extra fields to merge with CD extra fields (local often has more data)
    let local_ntfs = parse_ntfs_extra(&local_extra);
    let local_ext_ts = parse_extended_timestamp_extra(&local_extra);
    let local_unix = parse_unix_extra(&local_extra);
    let local_unicode_path = parse_unicode_path_extra(&local_extra);
    let local_unicode_comment = parse_unicode_comment_extra(&local_extra);

    // Prefer local extra field values (more complete), fall back to CD values
    let deflate_option = if record.actual_compression_method == 8 {
        ((flags >> 1) & 0x03) as u8
    } else {
        0
    };

    Ok(ZipEntry {
        header: ZipHeader {
            flags,
            compression_method: record.actual_compression_method,
            deflate_option,
            mod_time: record.mod_time,
            mod_date: record.mod_date,
            crc32: effective_crc32,
            compressed_size: effective_compressed_size,
            uncompressed_size: effective_uncompressed_size,
            comment: record.comment.clone(),
            internal_attributes: record.internal_attributes,
            external_attributes: record.external_attributes,
            ntfs_mtime: local_ntfs.mtime.or(record.ntfs_mtime),
            ntfs_atime: local_ntfs.atime.or(record.ntfs_atime),
            ntfs_ctime: local_ntfs.ctime.or(record.ntfs_ctime),
            unix_mtime: local_ext_ts.mtime.or(record.unix_mtime),
            unix_atime: local_ext_ts.atime.or(record.unix_atime),
            unix_uid: local_unix.uid.or(record.unix_uid),
            unix_gid: local_unix.gid.or(record.unix_gid),
            unicode_path: local_unicode_path.or(record.unicode_path.clone()),
            unicode_comment: local_unicode_comment.or(record.unicode_comment.clone()),
            host_system: record.host_system,
            version_needed: record.version_needed,
        },
        name: record.name.clone(),
        data,
    })
}

fn validate_data_descriptor(
    descriptor: &[u8],
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
) -> Result<(), Error> {
    for has_signature in [true, false] {
        if let Ok(consumed) = parse_data_descriptor(
            descriptor,
            has_signature,
            crc32,
            compressed_size,
            uncompressed_size,
        ) && consumed == descriptor.len()
        {
            return Ok(());
        }
    }
    Err(Error::InvalidData("zip: invalid data descriptor"))
}

fn parse_data_descriptor(
    descriptor: &[u8],
    has_signature: bool,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
) -> Result<usize, Error> {
    let mut offset = 0usize;
    if has_signature {
        if descriptor.len() < 4 || read_u32_at(descriptor, 0)? != DATA_DESCRIPTOR_SIGNATURE {
            return Err(Error::InvalidData("zip: missing data descriptor signature"));
        }
        offset += 4;
    }
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        if descriptor.len() < offset + 20 {
            return Err(Error::UnexpectedEof);
        }
        if read_u32_at(descriptor, offset)? != crc32
            || read_u64_at(descriptor, offset + 4)? != compressed_size
            || read_u64_at(descriptor, offset + 12)? != uncompressed_size
        {
            return Err(Error::InvalidData("zip: data descriptor mismatch"));
        }
        Ok(offset + 20)
    } else {
        if descriptor.len() < offset + 12 {
            return Err(Error::UnexpectedEof);
        }
        if read_u32_at(descriptor, offset)? != crc32
            || read_u32_at(descriptor, offset + 4)? as u64 != compressed_size
            || read_u32_at(descriptor, offset + 8)? as u64 != uncompressed_size
        {
            return Err(Error::InvalidData("zip: data descriptor mismatch"));
        }
        Ok(offset + 12)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Zip64Extra {
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    local_header_offset: Option<u64>,
    disk_start: Option<u32>,
}

fn parse_zip64_extra(
    extra: &[u8],
    need_compressed: bool,
    need_uncompressed: bool,
    need_offset: bool,
    need_disk: bool,
) -> Result<Zip64Extra, Error> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = read_u16_at(extra, pos)?;
        let size = read_u16_at(extra, pos + 2)? as usize;
        pos += 4;
        if pos + size > extra.len() {
            return Err(Error::UnexpectedEof);
        }
        if header_id == 0x0001 {
            let mut field_pos = pos;
            let end = pos + size;
            let mut result = Zip64Extra::default();
            if need_uncompressed {
                result.uncompressed_size = Some(read_u64_at(extra, field_pos)?);
                field_pos += 8;
            }
            if need_compressed {
                result.compressed_size = Some(read_u64_at(extra, field_pos)?);
                field_pos += 8;
            }
            if need_offset {
                result.local_header_offset = Some(read_u64_at(extra, field_pos)?);
                field_pos += 8;
            }
            // Disk start number (4 bytes, APPNOTE §4.5.3). The version 1
            // record may hold only the fields the sentinels require, so a
            // record that ends before this field is tolerated here; the
            // caller treats a missing disk override as malformed.
            if need_disk && field_pos + 4 <= end {
                result.disk_start = Some(read_u32_at(extra, field_pos)?);
                field_pos += 4;
            }
            if field_pos > end {
                return Err(Error::UnexpectedEof);
            }
            return Ok(result);
        }
        pos += size;
    }
    if need_compressed || need_uncompressed || need_offset || need_disk {
        return Err(Error::InvalidData("zip: missing ZIP64 extra field"));
    }
    Ok(Zip64Extra::default())
}

// ── Extra field 0x000a: NTFS timestamps ──────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct NtfsExtra {
    mtime: Option<u64>,
    atime: Option<u64>,
    ctime: Option<u64>,
}

fn parse_ntfs_extra(extra: &[u8]) -> NtfsExtra {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let Ok(header_id) = read_u16_at(extra, pos) else {
            break;
        };
        let Ok(size) = read_u16_at(extra, pos + 2) else {
            break;
        };
        let size = size as usize;
        pos += 4;
        if pos + size > extra.len() {
            break;
        }
        if header_id == 0x000a {
            // NTFS extra field: Reserved(4) + Tag1(2) + Size1(2) + data
            let data = &extra[pos..pos + size];
            if data.len() < 8 {
                pos += size;
                continue;
            }
            // Skip Reserved (4 bytes)
            let mut attr_pos = 4usize;
            while attr_pos + 4 <= data.len() {
                let Ok(tag) = read_u16_at(data, attr_pos) else {
                    break;
                };
                let Ok(attr_size) = read_u16_at(data, attr_pos + 2) else {
                    break;
                };
                let attr_size = attr_size as usize;
                attr_pos += 4;
                if attr_pos + attr_size > data.len() {
                    break;
                }
                if tag == 0x0001 && attr_size >= 24 {
                    // Attribute tag 1: file times (mtime, atime, ctime) as u64 LE
                    let Ok(mtime) = read_u64_at(data, attr_pos) else {
                        break;
                    };
                    let Ok(atime) = read_u64_at(data, attr_pos + 8) else {
                        break;
                    };
                    let Ok(ctime) = read_u64_at(data, attr_pos + 16) else {
                        break;
                    };
                    return NtfsExtra {
                        mtime: Some(mtime),
                        atime: Some(atime),
                        ctime: Some(ctime),
                    };
                }
                attr_pos += attr_size;
            }
        }
        pos += size;
    }
    NtfsExtra::default()
}

// ── Extra field 0x5455: Extended Timestamp ────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct ExtendedTimestampExtra {
    mtime: Option<u32>,
    atime: Option<u32>,
}

/// Parse extended timestamp extra field (0x5455).
///
/// The Central Directory version typically only contains the modification time.
/// The Local File Header version may contain mtime, atime, and ctime.
/// We merge both sources.
fn parse_extended_timestamp_extra(extra: &[u8]) -> ExtendedTimestampExtra {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let Ok(header_id) = read_u16_at(extra, pos) else {
            break;
        };
        let Ok(size) = read_u16_at(extra, pos + 2) else {
            break;
        };
        let size = size as usize;
        pos += 4;
        if pos + size > extra.len() {
            break;
        }
        if header_id == 0x5455 {
            let data = &extra[pos..pos + size];
            if data.is_empty() {
                pos += size;
                continue;
            }
            let flags = data[0];
            let mut offset = 1usize;
            let mut result = ExtendedTimestampExtra::default();
            if flags & 0x01 != 0 && offset + 4 <= data.len() {
                result.mtime = Some(u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]));
                offset += 4;
            }
            if flags & 0x02 != 0 && offset + 4 <= data.len() {
                result.atime = Some(u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]));
            }
            return result;
        }
        pos += size;
    }
    ExtendedTimestampExtra::default()
}

// ── Extra field 0x000d: UNIX extra field ─────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
struct UnixExtra {
    uid: Option<u16>,
    gid: Option<u16>,
}

fn parse_unix_extra(extra: &[u8]) -> UnixExtra {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let Ok(header_id) = read_u16_at(extra, pos) else {
            break;
        };
        let Ok(size) = read_u16_at(extra, pos + 2) else {
            break;
        };
        let size = size as usize;
        pos += 4;
        if pos + size > extra.len() {
            break;
        }
        if header_id == 0x000d {
            // UNIX extra: AcTime(4) + ModTime(4) + UID(2) + GID(2)
            let data = &extra[pos..pos + size];
            if data.len() >= 12 {
                let uid = u16::from_le_bytes([data[8], data[9]]);
                let gid = u16::from_le_bytes([data[10], data[11]]);
                return UnixExtra {
                    uid: Some(uid),
                    gid: Some(gid),
                };
            }
        }
        pos += size;
    }
    UnixExtra::default()
}

// ── Extra field 0x7075: Unicode Path ─────────────────────────────────────

fn parse_unicode_path_extra(extra: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let Ok(header_id) = read_u16_at(extra, pos) else {
            break;
        };
        let Ok(size) = read_u16_at(extra, pos + 2) else {
            break;
        };
        let size = size as usize;
        pos += 4;
        if pos + size > extra.len() {
            break;
        }
        if header_id == 0x7075 {
            // Version(1) + NameCRC32(4) + UnicodeName(rest)
            let data = &extra[pos..pos + size];
            if data.len() >= 5 {
                // version must be 1
                if data[0] == 1 {
                    // skip CRC32 of the name field (4 bytes)
                    if let Ok(name) = core::str::from_utf8(&data[5..]) {
                        return Some(String::from(name));
                    }
                }
            }
        }
        pos += size;
    }
    None
}

// ── Extra field 0x6375: Unicode Comment ───────────────────────────────────

fn parse_unicode_comment_extra(extra: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let Ok(header_id) = read_u16_at(extra, pos) else {
            break;
        };
        let Ok(size) = read_u16_at(extra, pos + 2) else {
            break;
        };
        let size = size as usize;
        pos += 4;
        if pos + size > extra.len() {
            break;
        }
        if header_id == 0x6375 {
            // Version(1) + ComCRC32(4) + UnicodeComment(rest)
            let data = &extra[pos..pos + size];
            if data.len() >= 5
                && data[0] == 1
                && let Ok(comment) = core::str::from_utf8(&data[5..])
            {
                return Some(String::from(comment));
            }
        }
        pos += size;
    }
    None
}

// ── Extra field 0x0007: AV Info (APPNOTE §4.6.2) ─────────────────────────
// ── Extra field 0x0008: Extended Language Encoding (APPNOTE §4.6.3) ──────
//
// These optional extra field IDs are recognised by the specification but carry
// no data that affects normal extraction. The extra-field iteration loops
// above (parse_zip64_extra, parse_ntfs_extra, etc.) already skip unknown
// header IDs, so archives containing 0x0007 or 0x0008 entries are handled
// correctly without any special-case code.

fn read_u16_at(input: &[u8], offset: usize) -> Result<u16, Error> {
    if offset + 2 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u16::from_le_bytes([input[offset], input[offset + 1]]))
}

fn read_u32_at(input: &[u8], offset: usize) -> Result<u32, Error> {
    if offset + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ]))
}

fn read_u64_at(input: &[u8], offset: usize) -> Result<u64, Error> {
    if offset + 8 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ]))
}

struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    const fn set(&mut self, pos: usize) {
        self.pos = pos;
    }

    const fn position(&self) -> usize {
        self.pos
    }

    const fn skip(&mut self, len: usize) -> Result<(), Error> {
        if self.pos + len > self.input.len() {
            return Err(Error::UnexpectedEof);
        }
        self.pos += len;
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let value = read_u16_at(self.input, self.pos)?;
        self.pos += 2;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let value = read_u32_at(self.input, self.pos)?;
        self.pos += 4;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let value = read_u64_at(self.input, self.pos)?;
        self.pos += 8;
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        if self.pos + len > self.input.len() {
            return Err(Error::UnexpectedEof);
        }
        let bytes = self.input[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(bytes)
    }

    fn read_string(&mut self, len: usize, utf8: bool) -> Result<String, Error> {
        let bytes = self.read_bytes(len)?;
        decode_metadata(&bytes, utf8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::deflate::encode::{self, Level};

    #[test]
    fn for_each_entry_stops_when_visit_fails() {
        let mut encoder = crate::archive::zip::encode::ZipEncoder::new();
        encoder.add_file("a.txt", b"aaa");
        encoder.add_file("b.txt", b"bbb");
        let archive = encoder.finish().unwrap();
        let mut seen = Vec::new();
        let err = for_each_entry(&archive, |entry| {
            seen.push(entry.name);
            Err(Error::InvalidData("stop"))
        });
        assert!(err.is_err());
        assert_eq!(seen, ["a.txt"]);
    }

    #[test]
    fn test_decode_empty_input() {
        assert!(decode(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_decode_store_single_file() {
        let archive = build_test_zip("hello.txt", b"hello", 0, false, false, true);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn test_decode_deflate_single_file() {
        let archive = build_test_zip("hello.txt", b"hello hello hello", 8, false, false, true);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, b"hello hello hello");
    }

    #[test]
    fn test_decode_with_data_descriptor_signature() {
        let archive = build_test_zip("dd.txt", b"descriptor", 8, true, false, true);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, b"descriptor");
    }

    #[test]
    fn test_decode_with_data_descriptor_no_signature() {
        let archive = build_test_zip("dd.txt", b"descriptor", 8, true, false, false);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, b"descriptor");
    }

    #[test]
    fn test_cd_bit13_masking_falls_back_to_local_header() {
        // Bit 13 (0x2000): the CD carries masked (zeroed) CRC-32 and sizes;
        // the real values are taken from the Local File Header.
        let data = b"masked central directory fields";
        let mut archive = build_test_zip("masked.txt", data, 0, false, false, false);
        archive[6] = 0x00;
        archive[7] = 0x20;
        let cd_sig = CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes();
        let cd_off = archive.windows(4).position(|w| w == cd_sig).unwrap();
        archive[cd_off + 8] = 0x00;
        archive[cd_off + 9] = 0x20;
        archive[cd_off + 16..cd_off + 28].fill(0);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].name, "masked.txt");
        assert_eq!(entries[0].data, data);
    }

    #[cfg(feature = "cmpsc")]
    #[test]
    fn test_decode_cmpsc_method16_roundtrip() {
        let payload = b"cmpsc method 16 payload payload payload";
        let archive = build_test_zip("cmpsc.bin", payload, 16, false, false, false);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "cmpsc.bin");
        assert_eq!(entries[0].header.compression_method, 16);
        assert_eq!(entries[0].data, payload);
    }

    #[cfg(feature = "cmpsc")]
    #[test]
    fn test_decode_cmpsc_method16_corrupt_rejected() {
        let name = "cmpsc.bin";
        let mut archive = build_test_zip(name, b"payload", 16, false, false, false);
        // The compressed payload starts right after the fixed 30-byte local
        // header and the file name; its first byte is the method-16
        // container version, which must be 1.
        let payload_pos = 30 + name.len();
        assert_eq!(archive[payload_pos], 1);
        archive[payload_pos] = 0;
        assert!(matches!(decode(&archive), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_zip64_sizes_and_offsets() {
        let archive = build_test_zip("zip64.txt", b"zip64", 0, false, true, true);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].name, "zip64.txt");
        assert_eq!(entries[0].data, b"zip64");
    }

    #[test]
    fn decodes_sfx_prefixed_archive() {
        // Self-extracting archive: an executable stub is prepended to the
        // ZIP payload, shifting every recorded offset by the stub length.
        let archive = build_test_zip("sfx.txt", b"self extracting", 8, false, false, true);
        let mut sfx = b"#!/bin/sh\necho stub\n".to_vec();
        sfx.extend_from_slice(&archive);
        let entries = decode(&sfx).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sfx.txt");
        assert_eq!(entries[0].data, b"self extracting");
    }

    #[test]
    fn sfx_prefix_via_zip64() {
        // Same stub detection through the ZIP64 EOCD locator/record:
        // the record is located by scanning back from the locator.
        let archive = build_test_zip("sfx64.txt", b"zip64 sfx", 0, false, true, true);
        let mut sfx = vec![0xAA; 512];
        sfx.extend_from_slice(&archive);
        let entries = decode(&sfx).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sfx64.txt");
        assert_eq!(entries[0].data, b"zip64 sfx");
    }

    #[test]
    fn test_bad_data_descriptor_rejected() {
        let mut archive = build_test_zip("bad.txt", b"payload", 0, true, false, true);
        let dd_pos = archive
            .windows(4)
            .position(|window| window == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
            .unwrap();
        archive[dd_pos + 4] ^= 0xFF;
        assert!(matches!(decode(&archive), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_cp437_name_and_comment() {
        let archive = build_test_zip_raw_metadata(
            b"\x84.txt",
            b"data",
            0,
            false,
            false,
            true,
            0,
            b"\x94 comment",
        );
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].name, "ä.txt");
        assert_eq!(entries[0].header.comment, "ö comment");
    }

    #[test]
    fn test_decode_with_eocd_comment_backward_search() {
        let mut archive = build_test_zip("commented.txt", b"data", 0, false, false, true);
        let comment = b"zip comment";
        let comment_len_pos = archive.len() - 2;
        archive[comment_len_pos..].copy_from_slice(&(comment.len() as u16).to_le_bytes());
        archive.extend_from_slice(comment);

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "commented.txt");
        assert_eq!(entries[0].data, b"data");
    }

    #[test]
    fn test_decode_invalid_utf8_metadata_rejected() {
        let archive =
            build_test_zip_raw_metadata(b"\xFF.txt", b"data", 0, false, false, true, 1 << 11, b"");
        assert!(matches!(decode(&archive), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_decode_encrypted_entry_rejected() {
        let mut archive = build_test_zip("secret.txt", b"data", 0, false, false, true);
        archive[6] |= 0x01;
        let cd_offset = archive
            .windows(4)
            .position(|window| window == CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes())
            .unwrap();
        archive[cd_offset + 8] |= 0x01;

        assert!(matches!(
            decode(&archive),
            Err(Error::Unsupported(
                "zip: encrypted entry requires a password"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_rejected_aes() {
        // bit 6 (strong encryption) + extra field 0x0017 with AES-256 info.
        // Decryption is intentionally not implemented (APPNOTE §10.1).
        let archive = build_strong_encryption_zip(0x6610, 256);
        assert!(matches!(
            decode(&archive),
            Err(Error::Unsupported(
                "zip: strong encryption (AES) is not supported"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_rejected_other_algorithms() {
        for (alg_id, bitlen) in [(0x6601, 64u16), (0x6603, 168), (0x6801, 128), (0x0000, 0)] {
            let archive = build_strong_encryption_zip(alg_id, bitlen);
            assert!(matches!(
                decode(&archive),
                Err(Error::Unsupported(
                    "zip: strong encryption is not supported"
                ))
            ));
        }
    }

    /// Build a synthetic ZIP whose central directory region opens with an
    /// Archive Decryption Header (APPNOTE §4.3.10) instead of CD records:
    /// the signature of Central Directory Encryption.
    fn build_adh_cd_zip() -> Vec<u8> {
        let archive = build_test_zip("a.txt", b"hi", 0, false, false, false);
        let eocd_pos = archive.len() - 22;
        let cd_offset =
            u32::from_le_bytes(archive[eocd_pos + 16..eocd_pos + 20].try_into().unwrap()) as usize;

        // Archive Decryption Header (no signature): format=2, alg=AES-256,
        // bitlen=256, flags=password, ErdSize=8 + ERD, Reserved1, VSize=0, VCRC32.
        let mut adh = Vec::new();
        adh.extend_from_slice(&2u16.to_le_bytes());
        adh.extend_from_slice(&0x6610u16.to_le_bytes());
        adh.extend_from_slice(&256u16.to_le_bytes());
        adh.extend_from_slice(&0x0001u16.to_le_bytes());
        adh.extend_from_slice(&8u16.to_le_bytes());
        adh.extend_from_slice(&[0xAA; 8]);
        adh.extend_from_slice(&0u32.to_le_bytes());
        adh.extend_from_slice(&0u16.to_le_bytes());
        adh.extend_from_slice(&0x12345678u32.to_le_bytes());

        let mut out = archive[..cd_offset].to_vec();
        out.extend_from_slice(&adh);
        out.extend_from_slice(&archive[cd_offset..eocd_pos]); // "encrypted" CD bytes
        let mut eocd = archive[eocd_pos..].to_vec();
        let new_cd_size = (out.len() - cd_offset) as u32;
        eocd[12..16].copy_from_slice(&new_cd_size.to_le_bytes());
        eocd[16..20].copy_from_slice(&(cd_offset as u32).to_le_bytes());
        out.extend_from_slice(&eocd);
        out
    }

    #[test]
    fn test_central_directory_encryption_rejected() {
        let archive = build_adh_cd_zip();
        assert!(matches!(
            decode(&archive),
            Err(Error::Unsupported(
                "zip: central directory encryption is not supported"
            ))
        ));
    }

    /// Build a synthetic ZIP archive with Strong Encryption (bit 6) set.
    ///
    /// The file data contains a fabricated strong encryption data header so the
    /// decoder can parse the AlgID from the file data. The Central Directory
    /// extra field includes 0x0017 with the same algorithm info.
    fn build_strong_encryption_zip(alg_id: u16, bitlen: u16) -> Vec<u8> {
        let name = b"secret.txt";
        let plaintext = b"hello";
        let crc = crc32::crc32(plaintext);

        // Build a fake strong encryption data header as the "compressed" data.
        let mut file_data = Vec::new();
        // IVSize (2B) = 16
        file_data.extend_from_slice(&16u16.to_le_bytes());
        // IV (16B)
        file_data.extend_from_slice(&[0xAA; 16]);
        // Size (4B)
        file_data.extend_from_slice(&50u32.to_le_bytes());
        // Format (2B) = 2
        file_data.extend_from_slice(&2u16.to_le_bytes());
        // AlgID (2B)
        file_data.extend_from_slice(&alg_id.to_le_bytes());
        // Bitlen (2B)
        file_data.extend_from_slice(&bitlen.to_le_bytes());
        // Flags (2B) = 0x0001 (password)
        file_data.extend_from_slice(&0x0001u16.to_le_bytes());
        // ErdSize (2B) = 0
        file_data.extend_from_slice(&0u16.to_le_bytes());
        // Reserved1 (4B)
        file_data.extend_from_slice(&0u32.to_le_bytes());
        // VSize (2B) = 0
        file_data.extend_from_slice(&0u16.to_le_bytes());
        // VCRC32 (4B)
        file_data.extend_from_slice(&0u32.to_le_bytes());
        // Some fake encrypted payload
        file_data.extend_from_slice(plaintext);

        // bit 0 (encrypted) + bit 6 (strong encryption) = 0x0041
        let flags: u16 = 0x0041;

        // Build extra field 0x0017 for Central Directory
        let mut cd_extra = Vec::new();
        cd_extra.extend_from_slice(&0x0017u16.to_le_bytes());
        cd_extra.extend_from_slice(&8u16.to_le_bytes()); // data size
        cd_extra.extend_from_slice(&2u16.to_le_bytes()); // Format = 2
        cd_extra.extend_from_slice(&alg_id.to_le_bytes());
        cd_extra.extend_from_slice(&bitlen.to_le_bytes());
        cd_extra.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags = password

        // Local File Header (no 0x0017 extra in local; that's normal per spec)
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&50u16.to_le_bytes()); // version needed (5.0 for strong enc)
        local.extend_from_slice(&flags.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // compressed size
        local.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // uncompressed size
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // local extra field length = 0
        local.extend_from_slice(name);
        local.extend_from_slice(&file_data);

        let central_offset = local.len();

        // Central Directory Header
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&50u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&50u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&flags.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(file_data.len() as u32).to_le_bytes()); // compressed size
        cd.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // uncompressed size
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes()); // extra field length
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment length
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal file attributes
        cd.extend_from_slice(&0u32.to_le_bytes()); // external file attributes
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        cd.extend_from_slice(name);
        cd.extend_from_slice(&cd_extra);

        let mut archive = local;
        archive.extend_from_slice(&cd);

        // EOCD
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // disk number
        archive.extend_from_slice(&0u16.to_le_bytes()); // CD disk number
        archive.extend_from_slice(&1u16.to_le_bytes()); // disk entries
        archive.extend_from_slice(&1u16.to_le_bytes()); // total entries
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // CD size
        archive.extend_from_slice(&(central_offset as u32).to_le_bytes()); // CD offset
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length

        archive
    }

    #[test]
    fn test_archive_extra_data_record_skipped() {
        // Build a normal ZIP, then insert an Archive Extra Data Record
        // (APPNOTE §4.3.11) between the local file data and the Central
        // Directory. The decoder must skip it and still decode correctly.
        let name = b"hello.txt";
        let data = b"hello";
        let crc = crc32::crc32(data);
        let compressed = data.to_vec();

        // -- Local File Header + data --
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&0u16.to_le_bytes()); // flags
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local.extend_from_slice(name);
        local.extend_from_slice(&compressed);

        // -- Archive Extra Data Record --
        let aerd_extra = b"some extra data";
        let mut aerd = Vec::new();
        aerd.extend_from_slice(&ARCHIVE_EXTRA_DATA_RECORD_SIGNATURE.to_le_bytes());
        aerd.extend_from_slice(&(aerd_extra.len() as u32).to_le_bytes());
        aerd.extend_from_slice(aerd_extra);

        // CD offset now points to after the AERD, but EOCD records
        // the position of the AERD (the decoder should skip over it).
        let aerd_offset = local.len();

        // -- Central Directory --
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        cd.extend_from_slice(name);

        // -- EOCD (points cd_offset at the AERD, not the real CD) --
        let mut archive = local;
        archive.extend_from_slice(&aerd);
        archive.extend_from_slice(&cd);
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // disk number
        archive.extend_from_slice(&0u16.to_le_bytes()); // cd disk number
        archive.extend_from_slice(&1u16.to_le_bytes()); // disk entries
        archive.extend_from_slice(&1u16.to_le_bytes()); // total entries
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // cd size
        // Point cd_offset at the AERD so the skip logic is exercised.
        archive.extend_from_slice(&(aerd_offset as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn test_digital_signature_skipped() {
        // Build a normal ZIP, then insert a Digital Signature record
        // (APPNOTE §4.3.13) between the Central Directory and the EOCD.
        // The decoder must skip it and still find the EOCD correctly.
        let name = b"hello.txt";
        let data = b"hello";
        let crc = crc32::crc32(data);
        let compressed = data.to_vec();

        // -- Local File Header + data --
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&0u16.to_le_bytes()); // flags
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local.extend_from_slice(name);
        local.extend_from_slice(&compressed);

        let central_offset = local.len();

        // -- Central Directory --
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        cd.extend_from_slice(name);

        // -- Digital Signature record --
        let sig_data = b"fake signature data";
        let mut digsig = Vec::new();
        digsig.extend_from_slice(&DIGITAL_SIGNATURE_SIGNATURE.to_le_bytes());
        digsig.extend_from_slice(&(sig_data.len() as u16).to_le_bytes());
        digsig.extend_from_slice(sig_data);

        // -- Assemble archive --
        let mut archive = local;
        archive.extend_from_slice(&cd);
        archive.extend_from_slice(&digsig);
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // disk number
        archive.extend_from_slice(&0u16.to_le_bytes()); // cd disk number
        archive.extend_from_slice(&1u16.to_le_bytes()); // disk entries
        archive.extend_from_slice(&1u16.to_le_bytes()); // total entries
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // cd size
        archive.extend_from_slice(&(central_offset as u32).to_le_bytes()); // cd offset
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    fn build_test_zip(
        name: &str,
        data: &[u8],
        method: u16,
        use_descriptor: bool,
        use_zip64: bool,
        descriptor_signature: bool,
    ) -> Vec<u8> {
        build_test_zip_raw_metadata(
            name.as_bytes(),
            data,
            method,
            use_descriptor,
            use_zip64,
            descriptor_signature,
            0,
            b"",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_zip_raw_metadata(
        name: &[u8],
        data: &[u8],
        method: u16,
        use_descriptor: bool,
        use_zip64: bool,
        descriptor_signature: bool,
        extra_flags: u16,
        comment: &[u8],
    ) -> Vec<u8> {
        let compressed = match method {
            0 => data.to_vec(),
            8 => encode::encode(data, Level::Default),
            #[cfg(feature = "cmpsc")]
            16 => crate::compress::cmpsc::encode(data),
            _ => unreachable!(),
        };
        let crc = crc32::crc32(data);
        let flags: u16 = if use_descriptor { 0x0008 } else { 0 } | extra_flags;
        let mut local_extra = Vec::new();
        if use_zip64 {
            local_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            local_extra.extend_from_slice(&16u16.to_le_bytes());
            local_extra.extend_from_slice(&(data.len() as u64).to_le_bytes());
            local_extra.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        }

        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&flags.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&(if use_descriptor { 0 } else { crc }).to_le_bytes());
        local.extend_from_slice(
            &(if use_zip64 {
                u32::MAX
            } else {
                compressed.len() as u32
            })
            .to_le_bytes(),
        );
        local.extend_from_slice(
            &(if use_zip64 {
                u32::MAX
            } else {
                data.len() as u32
            })
            .to_le_bytes(),
        );
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&local_extra);
        local.extend_from_slice(&compressed);

        if use_descriptor {
            if descriptor_signature {
                local.extend_from_slice(&DATA_DESCRIPTOR_SIGNATURE.to_le_bytes());
            }
            local.extend_from_slice(&crc.to_le_bytes());
            if use_zip64 {
                local.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
                local.extend_from_slice(&(data.len() as u64).to_le_bytes());
            } else {
                local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            }
        }

        let central_offset = local.len();
        let mut cd_extra = Vec::new();
        if use_zip64 {
            cd_extra.extend_from_slice(&0x0001u16.to_le_bytes());
            cd_extra.extend_from_slice(&24u16.to_le_bytes());
            cd_extra.extend_from_slice(&(data.len() as u64).to_le_bytes());
            cd_extra.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
            cd_extra.extend_from_slice(&0u64.to_le_bytes());
        }

        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&flags.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(
            &(if use_zip64 {
                u32::MAX
            } else {
                compressed.len() as u32
            })
            .to_le_bytes(),
        );
        cd.extend_from_slice(
            &(if use_zip64 {
                u32::MAX
            } else {
                data.len() as u32
            })
            .to_le_bytes(),
        );
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&(if use_zip64 { u32::MAX } else { 0 }).to_le_bytes());
        cd.extend_from_slice(name);
        cd.extend_from_slice(&cd_extra);
        cd.extend_from_slice(comment);

        let mut archive = local;
        archive.extend_from_slice(&cd);

        if use_zip64 {
            let zip64_eocd_offset = archive.len();
            archive.extend_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
            archive.extend_from_slice(&44u64.to_le_bytes());
            archive.extend_from_slice(&45u16.to_le_bytes());
            archive.extend_from_slice(&45u16.to_le_bytes());
            archive.extend_from_slice(&0u32.to_le_bytes());
            archive.extend_from_slice(&0u32.to_le_bytes());
            archive.extend_from_slice(&1u64.to_le_bytes());
            archive.extend_from_slice(&1u64.to_le_bytes());
            archive.extend_from_slice(&(cd.len() as u64).to_le_bytes());
            archive.extend_from_slice(&(central_offset as u64).to_le_bytes());

            archive.extend_from_slice(&ZIP64_EOCD_LOCATOR_SIGNATURE.to_le_bytes());
            archive.extend_from_slice(&0u32.to_le_bytes());
            archive.extend_from_slice(&(zip64_eocd_offset as u64).to_le_bytes());
            archive.extend_from_slice(&1u32.to_le_bytes());
        }

        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&(if use_zip64 { u16::MAX } else { 1 }).to_le_bytes());
        archive.extend_from_slice(&(if use_zip64 { u16::MAX } else { 1 }).to_le_bytes());
        archive
            .extend_from_slice(&(if use_zip64 { u32::MAX } else { cd.len() as u32 }).to_le_bytes());
        archive.extend_from_slice(
            &(if use_zip64 {
                u32::MAX
            } else {
                central_offset as u32
            })
            .to_le_bytes(),
        );
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive
    }

    fn zip64_with_uncompressed(method: u16, compressed: &[u8], uncompressed: u64) -> Vec<u8> {
        let name = b"a.txt";
        let mut local_extra = Vec::new();
        local_extra.extend_from_slice(&0x0001u16.to_le_bytes());
        local_extra.extend_from_slice(&16u16.to_le_bytes());
        local_extra.extend_from_slice(&uncompressed.to_le_bytes());
        local_extra.extend_from_slice(&(compressed.len() as u64).to_le_bytes());

        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&45u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u32.to_le_bytes());
        local.extend_from_slice(&u32::MAX.to_le_bytes());
        local.extend_from_slice(&u32::MAX.to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&local_extra);
        local.extend_from_slice(compressed);

        let central_offset = local.len();
        let mut cd_extra = Vec::new();
        cd_extra.extend_from_slice(&0x0001u16.to_le_bytes());
        cd_extra.extend_from_slice(&24u16.to_le_bytes());
        cd_extra.extend_from_slice(&uncompressed.to_le_bytes());
        cd_extra.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        cd_extra.extend_from_slice(&0u64.to_le_bytes());

        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&45u16.to_le_bytes());
        cd.extend_from_slice(&45u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&method.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&u32::MAX.to_le_bytes());
        cd.extend_from_slice(&u32::MAX.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&u32::MAX.to_le_bytes());
        cd.extend_from_slice(name);
        cd.extend_from_slice(&cd_extra);

        let mut archive = local;
        archive.extend_from_slice(&cd);
        let zip64_eocd_offset = archive.len();
        archive.extend_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&44u64.to_le_bytes());
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&45u16.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&1u64.to_le_bytes());
        archive.extend_from_slice(&1u64.to_le_bytes());
        archive.extend_from_slice(&(cd.len() as u64).to_le_bytes());
        archive.extend_from_slice(&(central_offset as u64).to_le_bytes());
        archive.extend_from_slice(&ZIP64_EOCD_LOCATOR_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u32.to_le_bytes());
        archive.extend_from_slice(&(zip64_eocd_offset as u64).to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&u16::MAX.to_le_bytes());
        archive.extend_from_slice(&u16::MAX.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&u32::MAX.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive
    }

    #[test]
    fn test_declared_uncompressed_size_above_limit_is_rejected() {
        let mut cases = vec![
            (2u16, Vec::new()),
            (3, Vec::new()),
            (4, Vec::new()),
            (5, Vec::new()),
            (6, Vec::new()),
        ];
        #[cfg(any(feature = "lzip", feature = "xz", feature = "sevenz"))]
        cases.push((14, vec![0, 0, 5, 0, 0x5D, 0, 0, 0, 1]));
        #[cfg(feature = "cmpsc")]
        cases.push((16, Vec::new()));
        #[cfg(feature = "sevenz")]
        cases.push((98, vec![6, 20]));
        for (method, compressed) in cases {
            let archive = zip64_with_uncompressed(method, &compressed, 1 << 40);
            assert!(
                matches!(decode(&archive), Err(Error::OutputLimitExceeded { .. })),
                "method {method}"
            );
        }
    }

    #[cfg(feature = "sevenz")]
    #[test]
    fn test_ppmd_method_rejects_mem_order_above_decode_limit() {
        let name = b"a.txt";
        let compressed = [0x06, 0x1D];
        let crc = crc32::crc32(&[]);
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&98u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        local.extend_from_slice(&0u32.to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(name);
        local.extend_from_slice(&compressed);
        let central_offset = local.len() as u32;
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&98u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(name);
        let mut archive = local;
        archive.extend_from_slice(&cd);
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        archive.extend_from_slice(&central_offset.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            decode(&archive).unwrap_err(),
            Error::Unsupported("ppmd: memory size exceeds decode limit")
        );
    }

    #[test]
    fn test_archive_entry_trait() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("hello.txt", b"Hello!");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
    }

    #[test]
    fn test_archive_codec_decode_roundtrip() {
        use crate::archive::zip::{ZipArchiveEncoder, ZipCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ZipArchiveEncoder::new();
        encoder.add_file("hello.txt", b"Hello!");
        encoder.add_file("world.txt", b"World!");
        let archive = <ZipArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ZipCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
        assert_eq!(entries[1].name(), "world.txt");
        assert_eq!(entries[1].data(), b"World!");
    }

    #[test]
    fn test_archive_entry_empty_data() {
        use crate::archive::zip::{ZipArchiveEncoder, ZipCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ZipArchiveEncoder::new();
        encoder.add_file("empty.txt", b"");
        let archive = <ZipArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ZipCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "empty.txt");
        assert_eq!(entries[0].data(), b"");
    }

    #[test]
    fn test_archive_multiple_entries() {
        use crate::archive::zip::{ZipArchiveEncoder, ZipCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ZipArchiveEncoder::new();
        for i in 0..12 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            encoder.add_file(&name, data.as_bytes());
        }
        let archive = <ZipArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ZipCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 12);
        for (i, entry) in entries.iter().enumerate() {
            let expected_name = alloc::format!("file_{i}.txt");
            let expected_data = alloc::format!("Content of file {i}");
            assert_eq!(entry.name(), expected_name);
            assert_eq!(entry.data(), expected_data.as_bytes());
        }
    }
    /// Locate the EOCD record and patch its disk fields as if the
    /// archive were split so that the EOCD sits on `disks` and the
    /// central directory starts on `cd_disk` (field values only;
    /// stored offsets are not touched).
    fn patch_eocd_disks(archive: &mut [u8], disks: u16, cd_disk: u16) {
        let pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .expect("EOCD not found");
        archive[pos + 4..pos + 6].copy_from_slice(&disks.to_le_bytes());
        archive[pos + 6..pos + 8].copy_from_slice(&cd_disk.to_le_bytes());
    }

    /// Locate the EOCD and patch both its disk fields and the stored
    /// CD offset as if the central directory began on `cd_disk` at
    /// disk-relative offset `cd_offset` (APPNOTE §4.4.15).
    fn patch_eocd_split(archive: &mut [u8], disks: u16, cd_disk: u16, cd_offset: u32) {
        let pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .expect("EOCD not found");
        archive[pos + 4..pos + 6].copy_from_slice(&disks.to_le_bytes());
        archive[pos + 6..pos + 8].copy_from_slice(&cd_disk.to_le_bytes());
        archive[pos + 16..pos + 20].copy_from_slice(&cd_offset.to_le_bytes());
    }

    /// Return `(disk_start_pos, lh_offset_pos)` for each central
    /// directory record, starting at `cd_off`.
    fn cd_record_positions(archive: &[u8], cd_off: usize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut p = cd_off;
        while archive[p..p + 4] == [0x50, 0x4b, 0x01, 0x02] {
            out.push((p + 34, p + 42));
            let name_len = u16::from_le_bytes(archive[p + 28..p + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(archive[p + 30..p + 32].try_into().unwrap()) as usize;
            let com_len = u16::from_le_bytes(archive[p + 32..p + 34].try_into().unwrap()) as usize;
            p += 46 + name_len + extra_len + com_len;
        }
        out
    }

    /// Stored absolute CD offset read from the EOCD.
    fn eocd_cd_offset(archive: &[u8]) -> usize {
        let pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .expect("EOCD not found");
        u32::from_le_bytes(archive[pos + 16..pos + 20].try_into().unwrap()) as usize
    }

    #[test]
    fn split_parts_roundtrip() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"aaaa");
        enc.add_file("dir/b.bin", &[0x55; 3000]);
        enc.add_file("c.txt", b"cccc");
        let mut archive = enc.finish().unwrap();
        // EOCD sits on the last disk; the CD starts on the last disk
        // too for this small archive, so its stored offset is
        // relative to the start of disk 2 (APPNOTE §4.4.15).
        let a = archive.len() / 3;
        let bnd = 2 * archive.len() / 3;
        let cd_off = eocd_cd_offset(&archive);
        let (cd_disk, cd_rel) = if cd_off >= bnd {
            (2u16, (cd_off - bnd) as u32)
        } else if cd_off >= a {
            (1u16, (cd_off - a) as u32)
        } else {
            (0u16, cd_off as u32)
        };
        patch_eocd_split(&mut archive, 2, cd_disk, cd_rel);
        let parts = [&archive[..a], &archive[a..bnd], &archive[bnd..]];
        let entries = decode_parts(&parts).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name(), "a.txt");
        assert_eq!(entries[0].data(), b"aaaa");
        assert_eq!(entries[1].data(), vec![0x55; 3000]);
        // The same bytes still look multi-disk to decode().
        assert!(matches!(decode(&archive), Err(Error::Unsupported(_))));
    }

    #[test]
    fn split_parts_disk_count_mismatch() {
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"data");
        let mut archive = enc.finish().unwrap();
        patch_eocd_disks(&mut archive, 4, 0);
        let mid = archive.len() / 2;
        let parts = [&archive[..mid], &archive[mid..]];
        assert!(matches!(decode_parts(&parts), Err(Error::InvalidData(_))));
    }

    #[test]
    fn split_parts_rejects_empty_and_accepts_single() {
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"data");
        let archive = enc.finish().unwrap();
        assert!(matches!(decode_parts(&[]), Err(Error::InvalidData(_))));
        assert!(matches!(
            decode_parts(&[&archive[..10], &[]]),
            Err(Error::InvalidData(_))
        ));
        assert_eq!(decode_parts(&[&archive]).unwrap().len(), 1);
        // Single part may still carry disk 0 fields (unsplit archive).
        let mut multi = archive.clone();
        patch_eocd_disks(&mut multi, 0, 0);
        assert_eq!(decode_parts(&[&multi]).unwrap().len(), 1);
    }

    #[test]
    fn split_parts_spanning_signature_tolerated() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"payload");
        enc.add_file("b.txt", b"other");
        let archive = enc.finish().unwrap();
        // PKZIP spanning archives prepend the 0x08074b50 signature as
        // the first 4 bytes of segment 1; every stored absolute offset
        // (CD local-header offsets, EOCD cd_offset) counts those bytes.
        let eocd_pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .unwrap();
        let cd_off =
            u32::from_le_bytes(archive[eocd_pos + 16..eocd_pos + 20].try_into().unwrap()) as usize;
        // Collect each CD record's local_header_offset position.
        let mut lh_offs = Vec::new();
        let mut p = cd_off;
        while archive[p..p + 4] == [0x50, 0x4b, 0x01, 0x02] {
            lh_offs.push(p + 42);
            let name_len = u16::from_le_bytes(archive[p + 28..p + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(archive[p + 30..p + 32].try_into().unwrap()) as usize;
            let com_len = u16::from_le_bytes(archive[p + 32..p + 34].try_into().unwrap()) as usize;
            p += 46 + name_len + extra_len + com_len;
        }

        let mut with_sig = Vec::with_capacity(archive.len() + 4);
        with_sig.extend_from_slice(&[0x50, 0x4b, 0x07, 0x08]);
        with_sig.extend_from_slice(&archive);
        // Shift every stored absolute offset by 4.
        for pos in lh_offs {
            let pos = pos + 4; // record itself moved
            let old = u32::from_le_bytes(with_sig[pos..pos + 4].try_into().unwrap());
            with_sig[pos..pos + 4].copy_from_slice(&(old + 4).to_le_bytes());
        }
        let eocd_pos = eocd_pos + 4;
        let mid = with_sig.len() / 2;
        // The stored CD offset is relative to the disk it starts on
        // (APPNOTE §4.4.15): pick the disk actually containing it.
        let old_cd = u32::from_le_bytes(with_sig[eocd_pos + 16..eocd_pos + 20].try_into().unwrap())
            as usize
            + 4;
        let (cd_disk, cd_rel) = if old_cd >= mid {
            (1u16, (old_cd - mid) as u32)
        } else {
            (0u16, old_cd as u32)
        };
        with_sig[eocd_pos + 16..eocd_pos + 20].copy_from_slice(&cd_rel.to_le_bytes());
        patch_eocd_disks(&mut with_sig, 1, cd_disk);
        let entries = decode_parts(&[&with_sig[..mid], &with_sig[mid..]]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"payload");
        assert_eq!(entries[1].data(), b"other");
    }

    #[test]
    fn split_parts_temporary_spanning_marker_tolerated() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"payload");
        enc.add_file("b.txt", b"other");
        let archive = enc.finish().unwrap();

        // APPNOTE 8.5.4: when spanning is begun but a single segment
        // turns out to be enough, the 0x08074b50 spanning signature
        // that opened segment 1 is rewritten as the temporary
        // spanning marker 0x30304b50. The marker occupies the first
        // four bytes of the stream, so every stored absolute offset
        // counts it.
        let eocd_pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .unwrap();
        let cd_off =
            u32::from_le_bytes(archive[eocd_pos + 16..eocd_pos + 20].try_into().unwrap()) as usize;
        // Collect each CD record local_header_offset position.
        let mut lh_offs = Vec::new();
        let mut p = cd_off;
        while archive[p..p + 4] == [0x50, 0x4b, 0x01, 0x02] {
            lh_offs.push(p + 42);
            let name_len = u16::from_le_bytes(archive[p + 28..p + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(archive[p + 30..p + 32].try_into().unwrap()) as usize;
            let com_len = u16::from_le_bytes(archive[p + 32..p + 34].try_into().unwrap()) as usize;
            p += 46 + name_len + extra_len + com_len;
        }

        let mut with_marker = Vec::with_capacity(archive.len() + 4);
        with_marker.extend_from_slice(&[0x50, 0x4b, 0x30, 0x30]);
        with_marker.extend_from_slice(&archive);
        // Shift every stored absolute offset by the marker length.
        for pos in lh_offs {
            let pos = pos + 4;
            let old = u32::from_le_bytes(with_marker[pos..pos + 4].try_into().unwrap());
            with_marker[pos..pos + 4].copy_from_slice(&(old + 4).to_le_bytes());
        }
        let eocd_pos = eocd_pos + 4;
        let old_cd = u32::from_le_bytes(
            with_marker[eocd_pos + 16..eocd_pos + 20]
                .try_into()
                .unwrap(),
        );
        with_marker[eocd_pos + 16..eocd_pos + 20].copy_from_slice(&(old_cd + 4).to_le_bytes());

        // A single segment with the marker is not actually split:
        // both the parts API and plain decode accept it.
        let entries = decode_parts(&[&with_marker]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"payload");
        assert_eq!(entries[1].data(), b"other");
        let entries = decode(&with_marker).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"payload");
    }

    #[test]
    fn split_parts_real_disk_offsets() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file("a.txt", b"payload-a");
        enc.add_file("b.txt", b"payload-b");
        let mut archive = enc.finish().unwrap();

        let cd_off = eocd_cd_offset(&archive);
        let recs = cd_record_positions(&archive, cd_off);
        assert_eq!(recs.len(), 2);
        // b.txt's local header is the first byte of disk 1: its
        // stored offset becomes 0 relative to that disk, and the CD
        // record's disk-start field becomes 1 (APPNOTE §4.4.13/§4.4.16).
        let split =
            u32::from_le_bytes(archive[recs[1].1..recs[1].1 + 4].try_into().unwrap()) as usize;
        archive[recs[1].1..recs[1].1 + 4].copy_from_slice(&0u32.to_le_bytes());
        archive[recs[1].0..recs[1].0 + 2].copy_from_slice(&1u16.to_le_bytes());
        // CD itself begins on disk 1 (it follows b.txt's data), so
        // the EOCD cd_offset is relative to the start of disk 1.
        let cd_rel = (cd_off - split) as u32;
        patch_eocd_split(&mut archive, 1, 1, cd_rel);

        let parts = [&archive[..split], &archive[split..]];
        let entries = decode_parts(&parts).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"payload-a");
        assert_eq!(entries[1].data(), b"payload-b");
        // The same bytes still look multi-disk to decode().
        assert!(matches!(decode(&archive), Err(Error::Unsupported(_))));
    }

    #[test]
    fn split_parts_zip64_multidisk() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::zip::encode::ZipEncoder::new();
        enc.add_file_with_options(
            "a.txt",
            b"payload",
            &crate::archive::zip::encode::ZipEntryOptions {
                force_zip64: true,
                ..Default::default()
            },
        );
        let mut archive = enc.finish().unwrap();

        // Locate the ZIP64 EOCD locator (last 20 bytes before EOCD)
        // and the ZIP64 EOCD record it points at.
        let eocd_pos = archive
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x05, 0x06])
            .unwrap();
        let locator = eocd_pos - 20;
        assert_eq!(archive[locator..locator + 4], [0x50, 0x4b, 0x06, 0x07]);
        let rec_off =
            u64::from_le_bytes(archive[locator + 8..locator + 16].try_into().unwrap()) as usize;
        assert_eq!(archive[rec_off..rec_off + 4], [0x50, 0x4b, 0x06, 0x06]);

        // Split so the central directory begins on disk 1: find the
        // first central-directory header signature.
        let mut cd_pos = 0usize;
        while archive[cd_pos..cd_pos + 4] != [0x50, 0x4b, 0x01, 0x02] {
            cd_pos += 1;
            assert!(cd_pos < rec_off);
        }
        let split = cd_pos;

        // Entry stays on disk 0 (absolute offset == disk-0-relative).
        // CD on disk 1: ZIP64 record's cd_disk/cd_offset become
        // disk-1-relative; locator's record offset too; EOCD mirrors it.
        let cd_rel = 0u64; // CD starts at the first byte of disk 1
        archive[rec_off + 16..rec_off + 20].copy_from_slice(&1u32.to_le_bytes()); // disk_number
        archive[rec_off + 20..rec_off + 24].copy_from_slice(&1u32.to_le_bytes()); // cd_disk
        archive[rec_off + 48..rec_off + 56].copy_from_slice(&cd_rel.to_le_bytes());
        archive[locator + 4..locator + 8].copy_from_slice(&1u32.to_le_bytes()); // disk_with_record
        archive[locator + 8..locator + 16]
            .copy_from_slice(&((rec_off - split) as u64).to_le_bytes());
        archive[locator + 16..locator + 20].copy_from_slice(&2u32.to_le_bytes()); // total_disks
        patch_eocd_split(&mut archive, 1, 1, 0);

        let parts = [&archive[..split], &archive[split..]];
        let entries = decode_parts(&parts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data(), b"payload");
        assert!(matches!(decode(&archive), Err(Error::Unsupported(_))));
    }

    // --- ZIP64 disk-start override tests (§4.4.13, §4.5.3) ---

    /// ZIP64 extra field (tag 0x0001) holding only the disk start
    /// number. The size/offset fields would precede it but are absent
    /// here because their sentinels are not set (APPNOTE §4.5.3).
    /// `None` emits the tag with a zero-length body (no disk field).
    fn zip64_disk_extra(disk: Option<u32>) -> Vec<u8> {
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x0001u16.to_le_bytes());
        match disk {
            Some(d) => {
                extra.extend_from_slice(&4u16.to_le_bytes());
                extra.extend_from_slice(&d.to_le_bytes());
            }
            None => extra.extend_from_slice(&0u16.to_le_bytes()),
        }
        extra
    }

    /// Build a single-file (stored) archive whose Central Directory
    /// record uses the 0xFFFF disk-start sentinel; `cd_extra` becomes
    /// the record's extra field verbatim. When `disk0_len` is non-zero
    /// the archive is laid out as a 2-disk set: `disk0_len` filler bytes
    /// form disk 0, the local header sits at disk-1-relative offset 0,
    /// the CD follows it on disk 1, and the EOCD records the entry/CD
    /// disks accordingly (APPNOTE §8, §4.4.15/§4.4.16).
    fn build_disk_start_override_zip(cd_extra: &[u8], disk0_len: usize) -> Vec<u8> {
        let name = b"disk.txt";
        let data = b"payload";
        let crc = crc32::crc32(data);
        let multi = disk0_len > 0;
        let last_disk: u16 = if multi { 1 } else { 0 };

        // Disk-1-relative content: local file header + stored data.
        let mut disk1 = Vec::new();
        disk1.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        disk1.extend_from_slice(&20u16.to_le_bytes());
        disk1.extend_from_slice(&0u16.to_le_bytes()); // flags
        disk1.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        disk1.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        disk1.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        disk1.extend_from_slice(&crc.to_le_bytes());
        disk1.extend_from_slice(&(data.len() as u32).to_le_bytes());
        disk1.extend_from_slice(&(data.len() as u32).to_le_bytes());
        disk1.extend_from_slice(&(name.len() as u16).to_le_bytes());
        disk1.extend_from_slice(&0u16.to_le_bytes()); // local extra len
        disk1.extend_from_slice(name);
        disk1.extend_from_slice(data);

        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0xFFFFu16.to_le_bytes()); // disk start sentinel
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        // Local header offset, relative to the entry's disk (§4.4.16):
        // 0 in both layouts (start of disk 1, or start of the archive).
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(name);
        cd.extend_from_slice(cd_extra);

        let mut archive = vec![0xAA; disk0_len];
        archive.extend_from_slice(&disk1);
        archive.extend_from_slice(&cd);

        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&last_disk.to_le_bytes()); // disk number
        archive.extend_from_slice(&last_disk.to_le_bytes()); // cd disk number
        archive.extend_from_slice(&1u16.to_le_bytes()); // disk entries
        archive.extend_from_slice(&1u16.to_le_bytes()); // total entries
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        // CD offset relative to its disk (§4.4.15): the CD follows the
        // entry data on disk 1, or sits at disk1.len() on a single disk.
        archive.extend_from_slice(&(disk1.len() as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length
        archive
    }

    #[test]
    fn test_zip64_disk_start_override() {
        // disk_start = 0xFFFF sentinel; the real disk number (0) comes
        // from the ZIP64 extra field (APPNOTE §4.4.13/§4.5.3).
        let archive = build_disk_start_override_zip(&zip64_disk_extra(Some(0)), 0);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "disk.txt");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_zip64_disk_start_override_missing_field() {
        // Sentinel set but no ZIP64 extra field at all.
        let archive = build_disk_start_override_zip(&[], 0);
        assert!(matches!(decode(&archive), Err(Error::InvalidData(_))));
        // ZIP64 extra present but too short to hold the disk field.
        let archive = build_disk_start_override_zip(&zip64_disk_extra(None), 0);
        assert!(matches!(decode(&archive), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_zip64_disk_start_override_multidisk() {
        // The override resolves to a non-zero disk: without a disk map
        // this is a real multi-disk entry and stays Unsupported.
        let archive = build_disk_start_override_zip(&zip64_disk_extra(Some(1)), 0);
        assert!(matches!(
            decode(&archive),
            Err(Error::Unsupported("zip: multi-disk entries"))
        ));

        // Same override on a 2-disk layout: decode_parts resolves the
        // disk-1-relative offset through the segment map.
        let archive = build_disk_start_override_zip(&zip64_disk_extra(Some(1)), 16);
        assert!(matches!(decode(&archive), Err(Error::Unsupported(_))));
        let entries = decode_parts(&[&archive[..16], &archive[16..]]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "disk.txt");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_decode_truncated_at_every_position() {
        // Every proper prefix of a valid archive must fail: the EOCD
        // record sits at the end, so no truncated input can locate a
        // complete central directory.
        let archive = build_test_zip("t.txt", b"truncation sweep payload", 8, false, false, false);
        for cut in 1..archive.len() {
            assert!(
                decode(&archive[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }
}
