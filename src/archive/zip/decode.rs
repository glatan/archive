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
    decrypt_central_directory, decrypt_strong_encryption, parse_aes_extra_field,
    parse_archive_decryption_header, parse_strong_encryption_data_header,
    parse_strong_encryption_extra,
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
    decode_impl(input, None)
}

/// Decode a ZIP archive into memory using a password for encrypted entries.
pub fn decode_with_password(input: &[u8], password: &str) -> Result<Vec<ZipEntry>, Error> {
    decode_impl(input, Some(password.as_bytes()))
}

/// Decode a ZIP archive into memory using a password for encrypted entries.
pub fn decode_with_password_bytes(input: &[u8], password: &[u8]) -> Result<Vec<ZipEntry>, Error> {
    decode_impl(input, Some(password))
}

fn decode_impl(input: &[u8], password: Option<&[u8]>) -> Result<Vec<ZipEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let eocd_offset = find_eocd(input)?;
    let mut cursor = Cursor::new(input);
    cursor.set(eocd_offset);
    let eocd = parse_eocd(&mut cursor)?;

    let zip64 = if eocd.requires_zip64() {
        Some(parse_zip64_locator_and_record(input, eocd_offset)?)
    } else {
        None
    };

    let cd_offset = zip64
        .as_ref()
        .map_or(eocd.central_directory_offset as u64, |z| {
            z.central_directory_offset
        });
    let total_entries = zip64
        .as_ref()
        .map_or(eocd.total_entries as u64, |z| z.total_entries);

    let cd_offset = usize::try_from(cd_offset)
        .map_err(|_| Error::Unsupported("zip: central directory offset too large"))?;
    if cd_offset > input.len() {
        return Err(Error::UnexpectedEof);
    }

    // Skip Archive Extra Data Record (APPNOTE §4.3.11, signature 0x08064B50)
    // if present before the Central Directory.
    let cd_offset = skip_archive_extra_data_record(input, cd_offset)?;

    // Central Directory Encryption detection (APPNOTE §4.3.10, §7.5):
    // If the data at cd_offset does not start with a Central Directory header
    // signature (0x02014B50), the Central Directory may be encrypted. In that
    // case, an Archive Decryption Header (no signature) precedes the encrypted
    // CD data. We parse the ADH, decrypt the CD, and then parse entries from
    // the decrypted buffer.
    let (cd_data, cd_is_encrypted) =
        detect_and_decrypt_cd(input, cd_offset, eocd_offset, password)?;

    let (records, effective_cd_offset) = if cd_is_encrypted {
        // Parse CD entries from the decrypted buffer
        let mut cursor = Cursor::new(&cd_data);
        let mut records = Vec::new();
        for _ in 0..total_entries {
            records.push(parse_central_directory_record(&mut cursor)?);
        }
        // When CD is decrypted, there's no meaningful "cd_offset" in the original
        // input for determining entry boundaries. Use eocd_offset as the fallback
        // boundary for the last entry.
        (records, eocd_offset)
    } else {
        let mut cursor = Cursor::new(input);
        cursor.set(cd_offset);
        let mut records = Vec::new();
        for _ in 0..total_entries {
            records.push(parse_central_directory_record(&mut cursor)?);
        }

        // Skip Digital Signature record (APPNOTE §4.3.13, signature 0x05054B50)
        // if present after the Central Directory entries.
        if cursor.position() + 4 <= input.len()
            && read_u32_at(input, cursor.position())
                .is_ok_and(|sig| sig == DIGITAL_SIGNATURE_SIGNATURE)
        {
            // Digital signature: signature(4) + size_of_data(2) + signature_data(size)
            cursor.skip(4)?;
            let sig_size = cursor.read_u16()? as usize;
            cursor.skip(sig_size)?;
        }
        (records, cd_offset)
    };

    let next_offsets: Vec<usize> = records
        .iter()
        .enumerate()
        .map(|(index, _)| {
            records
                .get(index + 1)
                .map_or(effective_cd_offset, |next| next.local_header_offset)
        })
        .collect();

    let mut entries = Vec::with_capacity(records.len());
    for (record, next_offset) in records.iter().zip(next_offsets) {
        entries.push(extract_entry(
            input,
            record,
            next_offset,
            effective_cd_offset,
            password,
        )?);
    }
    Ok(entries)
}

/// Detect Central Directory Encryption and decrypt if needed (APPNOTE §4.3.10, §7.5).
///
/// Returns `(cd_data, is_encrypted)`:
/// - If not encrypted: `cd_data` is empty (caller should use original input at cd_offset)
/// - If encrypted: `cd_data` is the decrypted Central Directory bytes
fn detect_and_decrypt_cd(
    input: &[u8],
    cd_offset: usize,
    eocd_offset: usize,
    password: Option<&[u8]>,
) -> Result<(Vec<u8>, bool), Error> {
    // Check if the data at cd_offset starts with a Central Directory header signature.
    // If it does, no CD encryption is in effect.
    if cd_offset + 4 <= input.len()
        && read_u32_at(input, cd_offset).is_ok_and(|sig| sig == CENTRAL_DIRECTORY_HEADER_SIGNATURE)
    {
        return Ok((Vec::new(), false));
    }

    // Also check for empty archive (0 entries) where cd_offset may equal eocd_offset.
    if cd_offset >= eocd_offset {
        return Ok((Vec::new(), false));
    }

    // The data at cd_offset is not a CD header. Try to parse an Archive Decryption Header.
    let adh_data = &input[cd_offset..];
    let (adh, adh_size) = match parse_archive_decryption_header(adh_data) {
        Ok(result) => result,
        Err(_) => {
            // Could not parse as ADH either. This might just be corrupt data.
            // Return not-encrypted and let normal CD parsing produce a proper error.
            return Ok((Vec::new(), false));
        }
    };

    // Validate that the parsed ADH looks reasonable (known algorithm ID)
    let is_known_alg = matches!(
        adh.alg_id,
        0x6601 | 0x6602 | 0x6603 | 0x6609 | 0x660E | 0x660F | 0x6610 | 0x6702 | 0x6801
    );
    if !is_known_alg {
        // Unknown algorithm or the data isn't really an ADH.
        // Let normal parsing handle it (will likely produce a clear error).
        return Ok((Vec::new(), false));
    }

    // We have a valid Archive Decryption Header. Require a password.
    let password = password.ok_or(Error::Unsupported(
        "zip: central directory is encrypted; password required",
    ))?;

    // The encrypted CD data follows the Archive Decryption Header
    let encrypted_start = cd_offset + adh_size;
    if encrypted_start >= eocd_offset {
        return Err(Error::InvalidData(
            "zip: archive decryption header extends past EOCD",
        ));
    }

    // The encrypted CD extends from after the ADH to before the ZIP64 EOCD / EOCD structures.
    // We use eocd_offset as the boundary (ZIP64 EOCD Locator is right before EOCD,
    // and ZIP64 EOCD Record is before that, but the encrypted CD should end before those).
    let encrypted_cd = &input[encrypted_start..eocd_offset];

    let decrypted = decrypt_central_directory(password, encrypted_cd, &adh)?;
    Ok((decrypted, true))
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
    total_entries: u16,
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

fn parse_eocd(cursor: &mut Cursor<'_>) -> Result<EocdRecord, Error> {
    let signature = cursor.read_u32()?;
    if signature != EOCD_SIGNATURE {
        return Err(Error::InvalidData("zip: invalid EOCD signature"));
    }
    let disk_number = cursor.read_u16()?;
    let cd_disk_number = cursor.read_u16()?;
    let _disk_entries = cursor.read_u16()?;
    let total_entries = cursor.read_u16()?;
    let _cd_size = cursor.read_u32()?;
    let cd_offset = cursor.read_u32()?;
    let comment_len = cursor.read_u16()? as usize;
    cursor.skip(comment_len)?;
    if disk_number != 0 || cd_disk_number != 0 {
        return Err(Error::Unsupported("zip: multi-disk archives"));
    }
    Ok(EocdRecord {
        total_entries,
        central_directory_offset: cd_offset,
    })
}

fn parse_zip64_locator_and_record(input: &[u8], eocd_offset: usize) -> Result<Zip64Record, Error> {
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
    if disk_with_record != 0 || total_disks != 1 {
        return Err(Error::Unsupported("zip: multi-disk ZIP64 archives"));
    }

    let record_offset = usize::try_from(zip64_record_offset)
        .map_err(|_| Error::Unsupported("zip: ZIP64 record offset too large"))?;
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
    if disk_number != 0 || cd_disk_number != 0 {
        return Err(Error::Unsupported("zip: multi-disk ZIP64 archives"));
    }

    // ZIP64 EOCD extensible data sector (APPNOTE §4.3.14.3):
    // size_of_record covers all bytes after itself. The fixed fields above
    // consume 44 bytes; any remaining bytes form the extensible data sector.
    // We intentionally skip this sector — its contents are not needed for
    // basic archive extraction.

    Ok(Zip64Record {
        total_entries,
        central_directory_offset: cd_offset,
    })
}

fn parse_central_directory_record(
    cursor: &mut Cursor<'_>,
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
    let disk_start = cursor.read_u16()?;
    let internal_attributes = cursor.read_u16()?;
    let external_attributes = cursor.read_u32()?;
    let local_header_offset_raw = cursor.read_u32()?;
    if disk_start != 0 {
        return Err(Error::Unsupported("zip: multi-disk entries"));
    }

    let name = cursor.read_string(name_len, (flags & (1 << 11)) != 0)?;
    let extra = cursor.read_bytes(extra_len)?;
    let comment = cursor.read_string(comment_len, (flags & (1 << 11)) != 0)?;

    let zip64 = parse_zip64_extra(
        &extra,
        compressed_size_raw == u32::MAX,
        uncompressed_size_raw == u32::MAX,
        local_header_offset_raw == u32::MAX,
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
    let local_header_offset = usize::try_from(local_header_offset_u64)
        .map_err(|_| Error::Unsupported("zip: local header offset too large"))?;
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

    // Bit 6: Strong Encryption (APPNOTE §7)
    if (flags & 0x0040) != 0 {
        let data_header = parse_strong_encryption_data_header(compressed);

        // Check if this is an algorithm we can decrypt (or identify for errors)
        let alg_id = match &data_header {
            Ok(dh) => Some(dh.alg_id),
            Err(_) => record.strong_encryption.as_ref().map(|se| se.alg_id),
        };

        // Supported algorithms: AES, DES, 3DES, RC2, RC4
        let is_supported = alg_id.is_some_and(|id| {
            matches!(
                id,
                0x6601 | 0x6602 | 0x6603 | 0x6609 | 0x660E | 0x660F | 0x6610 | 0x6702 | 0x6801
            )
        });

        if is_supported {
            let algo_name = alg_id.map_or("Unknown", |id| match id {
                0x6601 => "DES",
                0x6602 | 0x6702 => "RC2",
                0x6603 => "3DES 168",
                0x6609 => "3DES 112",
                0x660E => "AES-128",
                0x660F => "AES-192",
                0x6610 => "AES-256",
                0x6801 => "RC4",
                _ => "Unknown",
            });
            let password = password.ok_or(match algo_name {
                "AES-128" | "AES-192" | "AES-256" => {
                    Error::Unsupported("zip: strong encryption (AES) requires password")
                }
                _ => Error::Unsupported("zip: strong encryption requires password"),
            })?;
            let dh = data_header.map_err(|_| {
                Error::InvalidData("zip: strong encryption data header parse failed")
            })?;
            let decrypted = decrypt_strong_encryption(password, &dh)?;
            // Decompress the decrypted data through the normal method dispatch
            let data = match record.actual_compression_method {
                0 => decrypted,
                8 => deflate::decode::decode(&decrypted)?,
                _ => {
                    return Err(Error::Unsupported(
                        "zip: compression method with strong encryption",
                    ));
                }
            };
            if data.len() as u64 != effective_uncompressed_size {
                return Err(Error::SizeMismatch {
                    expected: effective_uncompressed_size as u32,
                    actual: data.len() as u32,
                });
            }
            let actual_crc32 = crc32::crc32(&data);
            if actual_crc32 != effective_crc32 {
                return Err(Error::ChecksumMismatch {
                    expected: effective_crc32,
                    actual: actual_crc32,
                });
            }
            let local_extra = &[];
            let local_ntfs = parse_ntfs_extra(local_extra);
            let local_ext_ts = parse_extended_timestamp_extra(local_extra);
            let local_unix = parse_unix_extra(local_extra);
            let local_unicode_path = parse_unicode_path_extra(local_extra);
            let local_unicode_comment = parse_unicode_comment_extra(local_extra);
            return Ok(ZipEntry {
                header: ZipHeader {
                    flags,
                    compression_method: record.actual_compression_method,
                    deflate_option: 0,
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
            });
        }

        // Unsupported algorithms: Blowfish, Twofish, unknown
        let algo_name = if let Ok(dh) = &data_header {
            dh.algorithm_name()
        } else if let Some(ref se) = record.strong_encryption {
            se.algorithm_name()
        } else {
            "Unknown"
        };
        return Err(match algo_name {
            "Blowfish" => Error::Unsupported("zip: strong encryption (Blowfish)"),
            "Twofish" => Error::Unsupported("zip: strong encryption (Twofish)"),
            _ => Error::Unsupported("zip: strong encryption (unknown algorithm)"),
        });
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
        2 => super::expand::expand(&effective_compressed, 1)?,
        3 => super::expand::expand(&effective_compressed, 2)?,
        4 => super::expand::expand(&effective_compressed, 3)?,
        5 => super::expand::expand(&effective_compressed, 4)?,
        6 => super::implode::implode(
            &effective_compressed,
            record.flags,
            effective_uncompressed_size as usize,
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
                    effective_uncompressed_size as usize,
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
            crate::compress::ppmd::decode(ppmd_data, props, effective_uncompressed_size as usize)?
        }
        #[cfg(not(feature = "sevenz"))]
        98 => {
            return Err(Error::Unsupported(
                "zip: PPMd compression (enable sevenz feature)",
            ));
        }
        16 => {
            return Err(Error::Unsupported(
                "zip: IBM z/OS CMPSC compression (method 16)",
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
}

fn parse_zip64_extra(
    extra: &[u8],
    need_compressed: bool,
    need_uncompressed: bool,
    need_offset: bool,
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
            }
            if field_pos > end {
                return Err(Error::UnexpectedEof);
            }
            return Ok(result);
        }
        pos += size;
    }
    if need_compressed || need_uncompressed || need_offset {
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
    fn test_decode_zip64_sizes_and_offsets() {
        let archive = build_test_zip("zip64.txt", b"zip64", 0, false, true, true);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].name, "zip64.txt");
        assert_eq!(entries[0].data, b"zip64");
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
    fn test_strong_encryption_header_parsed() {
        // Build a ZIP where bit 6 (strong encryption) is set and extra field 0x0017
        // contains AES-256 algorithm info. Without a password, AES strong encryption
        // should return a password-required error.
        let archive = build_strong_encryption_zip(0x6610, 256, "AES-256");
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption (AES) requires password"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_header_parsed_3des() {
        // 3DES is now supported; without a password it requires one
        let archive = build_strong_encryption_zip(0x6603, 168, "3DES 168");
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption requires password"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_header_parsed_des() {
        // DES is now supported; without a password it requires one
        let archive = build_strong_encryption_zip(0x6601, 64, "DES");
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption requires password"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_header_parsed_rc4() {
        // RC4 is now supported; without a password it requires one
        let archive = build_strong_encryption_zip(0x6801, 128, "RC4");
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption requires password"
            ))
        ));
    }

    #[test]
    fn test_strong_encryption_header_parsed_unknown() {
        let archive = build_strong_encryption_zip(0x0000, 0, "Unknown");
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption (unknown algorithm)"
            ))
        ));
    }

    /// Build a synthetic ZIP archive with Strong Encryption (bit 6) set.
    ///
    /// The file data contains a fabricated strong encryption data header so the
    /// decoder can parse the AlgID from the file data. The Central Directory
    /// extra field includes 0x0017 with the same algorithm info.
    fn build_strong_encryption_zip(alg_id: u16, bitlen: u16, _expected_name: &str) -> Vec<u8> {
        let name = b"secret.txt";
        let plaintext = b"hello";
        let crc = crc32::crc32(plaintext);

        // Build a fake strong encryption data header as the "compressed" data.
        // This allows parse_strong_encryption_data_header to identify the algorithm.
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

    /// Build a synthetic ZIP archive with Strong Encryption (bit 6) and AES
    /// that can actually be decrypted with the given password.
    fn build_decryptable_strong_encryption_zip(
        password: &[u8],
        plaintext: &[u8],
        alg_id: u16,
        key_size: usize,
    ) -> Vec<u8> {
        use crate::archive::zip::crypto::{
            apply_pkcs7_padding, encrypt_aes_cbc_by_key_size, pbkdf2_hmac_sha1,
        };
        use crate::util::sha1::{Sha1, sha1};

        let name = b"secret.txt";
        let crc = crc32::crc32(plaintext);

        // Use a deterministic IV
        let iv = [0x11u8; 16];

        // Step 1: Derive master key
        let master_key = pbkdf2_hmac_sha1(password, &iv, 1000, key_size);

        // Step 2: Encrypt ERD
        let erd_plain = b"random_erd_data_for_test_padding!"; // 32 bytes
        let erd_padded = apply_pkcs7_padding(erd_plain);
        let erd_encrypted = encrypt_aes_cbc_by_key_size(&master_key, &erd_padded, &iv).unwrap();

        // Step 3: Derive session key
        let erd_hash = sha1(erd_plain);
        let session_key = if key_size <= 20 {
            erd_hash[..key_size].to_vec()
        } else {
            let mut key_material = alloc::vec::Vec::with_capacity(key_size);
            key_material.extend_from_slice(&erd_hash);
            let mut counter = 1u8;
            while key_material.len() < key_size {
                let mut hasher = Sha1::new();
                hasher.update(erd_plain.as_slice());
                hasher.update(&[counter]);
                let extra = hasher.finish();
                key_material.extend_from_slice(&extra);
                counter = counter.wrapping_add(1);
            }
            key_material.truncate(key_size);
            key_material
        };

        // Step 4: Encrypt file data (Store, no compression)
        let data_iv = [0x22u8; 16];
        let padded_plaintext = apply_pkcs7_padding(plaintext);
        let encrypted_body =
            encrypt_aes_cbc_by_key_size(&session_key, &padded_plaintext, &data_iv).unwrap();

        // Build strong encryption data header as the "compressed" data
        let mut file_data = Vec::new();
        // IVSize (2B)
        file_data.extend_from_slice(&16u16.to_le_bytes());
        // IV (16B)
        file_data.extend_from_slice(&iv);
        // Size (4B)
        file_data.extend_from_slice(&50u32.to_le_bytes());
        // Format (2B)
        file_data.extend_from_slice(&2u16.to_le_bytes());
        // AlgID (2B)
        file_data.extend_from_slice(&alg_id.to_le_bytes());
        // Bitlen (2B)
        file_data.extend_from_slice(&((key_size * 8) as u16).to_le_bytes());
        // Flags (2B) = 0x0001 (password)
        file_data.extend_from_slice(&0x0001u16.to_le_bytes());
        // ErdSize (2B)
        file_data.extend_from_slice(&(erd_encrypted.len() as u16).to_le_bytes());
        // ErdData
        file_data.extend_from_slice(&erd_encrypted);
        // Reserved1 (4B)
        file_data.extend_from_slice(&0u32.to_le_bytes());
        // VSize (2B) = 0
        file_data.extend_from_slice(&0u16.to_le_bytes());
        // VCRC32 (4B)
        file_data.extend_from_slice(&0u32.to_le_bytes());
        // Encrypted data: data_iv + encrypted_body
        file_data.extend_from_slice(&data_iv);
        file_data.extend_from_slice(&encrypted_body);

        // bit 0 (encrypted) + bit 6 (strong encryption) = 0x0041
        let flags: u16 = 0x0041;

        // Build extra field 0x0017 for Central Directory
        let mut cd_extra = Vec::new();
        cd_extra.extend_from_slice(&0x0017u16.to_le_bytes());
        cd_extra.extend_from_slice(&8u16.to_le_bytes());
        cd_extra.extend_from_slice(&2u16.to_le_bytes()); // Format
        cd_extra.extend_from_slice(&alg_id.to_le_bytes());
        cd_extra.extend_from_slice(&((key_size * 8) as u16).to_le_bytes());
        cd_extra.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags = password

        // Local File Header
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&50u16.to_le_bytes()); // version needed
        local.extend_from_slice(&flags.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        local.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
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
        cd.extend_from_slice(&(file_data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(cd_extra.len() as u16).to_le_bytes());
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
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(central_offset as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());

        archive
    }

    #[test]
    fn test_strong_encryption_aes256_full_decode() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-256!";
        let archive = build_decryptable_strong_encryption_zip(password, plaintext, 0x6610, 32);
        let entries = decode_with_password_bytes(&archive, password).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, plaintext);
    }

    #[test]
    fn test_strong_encryption_aes192_full_decode() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-192!";
        let archive = build_decryptable_strong_encryption_zip(password, plaintext, 0x660F, 24);
        let entries = decode_with_password_bytes(&archive, password).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, plaintext);
    }

    #[test]
    fn test_strong_encryption_aes128_full_decode() {
        let password = b"strong_password";
        let plaintext = b"Hello, Strong Encryption AES-128!";
        let archive = build_decryptable_strong_encryption_zip(password, plaintext, 0x660E, 16);
        let entries = decode_with_password_bytes(&archive, password).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, plaintext);
    }

    #[test]
    fn test_strong_encryption_wrong_password() {
        let password = b"correct_password";
        let plaintext = b"secret data";
        let archive = build_decryptable_strong_encryption_zip(password, plaintext, 0x6610, 32);
        let result = decode_with_password_bytes(&archive, b"wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_strong_encryption_no_password() {
        let password = b"password";
        let plaintext = b"data";
        let archive = build_decryptable_strong_encryption_zip(password, plaintext, 0x6610, 32);
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: strong encryption (AES) requires password"
            ))
        ));
    }

    // --- Central Directory Encryption tests (§4.3.10, §7.5) ---

    /// Build a synthetic ZIP archive with an encrypted Central Directory.
    ///
    /// The archive contains one file entry. The Central Directory is encrypted
    /// using AES-256 Strong Encryption. An Archive Decryption Header precedes
    /// the encrypted CD data block, which is structured as a Strong Encryption
    /// Data Header (same format as per-file encryption).
    fn build_cd_encrypted_zip(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
        use crate::archive::zip::crypto::{
            apply_pkcs7_padding, encrypt_aes_cbc_by_key_size, pbkdf2_hmac_sha1,
        };
        use crate::util::sha1::{Sha1, sha1};

        let name = b"hello.txt";
        let crc = crc32::crc32(plaintext);
        let compressed = plaintext.to_vec(); // Store method

        // --- Local File Header + file data ---
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&62u16.to_le_bytes()); // version needed (6.2 for CD encryption)
        local.extend_from_slice(&0u16.to_le_bytes()); // flags (no per-file encryption)
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0x1234u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0x5678u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local.extend_from_slice(name);
        local.extend_from_slice(&compressed);

        let central_offset = local.len();

        // --- Build the Central Directory (plaintext, to be encrypted) ---
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&62u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&62u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes()); // flags
        cd.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        cd.extend_from_slice(&0x1234u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0x5678u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        cd.extend_from_slice(name);

        // --- Encrypt the Central Directory using the Strong Encryption protocol ---
        let key_size = 32usize; // AES-256
        let alg_id: u16 = 0x6610;

        // Use deterministic IV for testing
        let iv = [0x33u8; 16];
        let master_key = pbkdf2_hmac_sha1(password, &iv, 1000, key_size);

        // Create ERD (Encrypted Random Data)
        let erd_plain = b"random_erd_data_for_test_padding!"; // 32 bytes
        let erd_padded = apply_pkcs7_padding(erd_plain);
        let erd_encrypted = encrypt_aes_cbc_by_key_size(&master_key, &erd_padded, &iv).unwrap();

        // Derive session key from decrypted ERD via SHA-1
        let erd_hash = sha1(erd_plain);
        let mut key_material = alloc::vec::Vec::with_capacity(key_size);
        key_material.extend_from_slice(&erd_hash);
        let mut counter = 1u8;
        while key_material.len() < key_size {
            let mut hasher = Sha1::new();
            hasher.update(erd_plain.as_slice());
            hasher.update(&[counter]);
            let extra = hasher.finish();
            key_material.extend_from_slice(&extra);
            counter = counter.wrapping_add(1);
        }
        key_material.truncate(key_size);
        let session_key = key_material;

        // Encrypt the CD with AES-CBC using session key
        let data_iv = [0x44u8; 16];
        let cd_padded = apply_pkcs7_padding(&cd);
        let encrypted_cd_body =
            encrypt_aes_cbc_by_key_size(&session_key, &cd_padded, &data_iv).unwrap();

        // --- Build the Archive Decryption Header (§4.3.10) ---
        // This is the metadata header that identifies the algorithm.
        let mut adh = Vec::new();
        adh.extend_from_slice(&2u16.to_le_bytes()); // Format
        adh.extend_from_slice(&alg_id.to_le_bytes()); // AlgID
        adh.extend_from_slice(&((key_size * 8) as u16).to_le_bytes()); // Bitlen
        adh.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags = password
        adh.extend_from_slice(&0u16.to_le_bytes()); // ErdSize = 0 (not used in ADH)
        adh.extend_from_slice(&0u32.to_le_bytes()); // Reserved1
        adh.extend_from_slice(&0u16.to_le_bytes()); // VSize = 0
        adh.extend_from_slice(&0u32.to_le_bytes()); // VCRC32

        // --- Build the encrypted CD block in Strong Encryption Data Header format ---
        // This follows the ADH and contains the actual encrypted data.
        let mut encrypted_block = Vec::new();
        // IVSize (2B) + IV
        encrypted_block.extend_from_slice(&(iv.len() as u16).to_le_bytes());
        encrypted_block.extend_from_slice(&iv);
        // Size (4B) + Format (2B) + AlgID (2B) + Bitlen (2B) + Flags (2B)
        encrypted_block.extend_from_slice(&50u32.to_le_bytes()); // Size (arbitrary)
        encrypted_block.extend_from_slice(&2u16.to_le_bytes()); // Format
        encrypted_block.extend_from_slice(&alg_id.to_le_bytes());
        encrypted_block.extend_from_slice(&((key_size * 8) as u16).to_le_bytes());
        encrypted_block.extend_from_slice(&0x0001u16.to_le_bytes()); // Flags = password
        // ErdSize + ErdData
        encrypted_block.extend_from_slice(&(erd_encrypted.len() as u16).to_le_bytes());
        encrypted_block.extend_from_slice(&erd_encrypted);
        // Reserved1 (4B) + VSize (2B) + VCRC32 (4B)
        encrypted_block.extend_from_slice(&0u32.to_le_bytes());
        encrypted_block.extend_from_slice(&0u16.to_le_bytes());
        encrypted_block.extend_from_slice(&0u32.to_le_bytes());
        // Encrypted CD payload: data_iv + encrypted_body
        encrypted_block.extend_from_slice(&data_iv);
        encrypted_block.extend_from_slice(&encrypted_cd_body);

        // --- Assemble archive ---
        // The EOCD cd_offset should point to the ADH (which is before the encrypted CD block).
        let adh_offset = central_offset;
        let mut archive = local;
        archive.extend_from_slice(&adh);
        archive.extend_from_slice(&encrypted_block);

        // EOCD
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes()); // disk number
        archive.extend_from_slice(&0u16.to_le_bytes()); // cd disk number
        archive.extend_from_slice(&1u16.to_le_bytes()); // disk entries
        archive.extend_from_slice(&1u16.to_le_bytes()); // total entries
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes()); // cd size (original)
        archive.extend_from_slice(&(adh_offset as u32).to_le_bytes()); // cd offset (points to ADH)
        archive.extend_from_slice(&0u16.to_le_bytes()); // comment length

        archive
    }

    #[test]
    fn test_cd_encryption_aes256_decode() {
        let password = b"cd_encryption_password";
        let plaintext = b"Hello, CD Encryption!";
        let archive = build_cd_encrypted_zip(password, plaintext);
        let entries = decode_with_password_bytes(&archive, password).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, plaintext);
    }

    #[test]
    fn test_cd_encryption_no_password() {
        let password = b"cd_encryption_password";
        let plaintext = b"Hello, CD Encryption!";
        let archive = build_cd_encrypted_zip(password, plaintext);
        let result = decode(&archive);
        assert!(matches!(
            result,
            Err(Error::Unsupported(
                "zip: central directory is encrypted; password required"
            ))
        ));
    }

    #[test]
    fn test_cd_encryption_wrong_password() {
        let password = b"correct_password";
        let plaintext = b"secret";
        let archive = build_cd_encrypted_zip(password, plaintext);
        let result = decode_with_password_bytes(&archive, b"wrong_password");
        assert!(result.is_err());
    }

    // --- Bit 13 (CD field masking) tests (§4.4.4) ---

    /// Build a synthetic ZIP archive with bit 13 set, where the CD entry has
    /// zeroed CRC-32/sizes and the real values are in the Local File Header.
    fn build_bit13_masked_zip(plaintext: &[u8]) -> Vec<u8> {
        let name = b"masked.txt";
        let crc = crc32::crc32(plaintext);
        let compressed = plaintext.to_vec(); // Store

        // --- Local File Header + file data ---
        // Local header has the REAL values
        let flags: u16 = 0x2000; // bit 13 set
        let mut local = Vec::new();
        local.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&flags.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        local.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        local.extend_from_slice(&crc.to_le_bytes()); // Real CRC
        local.extend_from_slice(&(compressed.len() as u32).to_le_bytes()); // Real compressed
        local.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // Real uncompressed
        local.extend_from_slice(&(name.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra len
        local.extend_from_slice(name);
        local.extend_from_slice(&compressed);

        let central_offset = local.len();

        // --- Central Directory Header ---
        // CD entry has MASKED (zeroed) CRC-32/sizes
        let mut cd = Vec::new();
        cd.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&flags.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // method = Store
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        cd.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        cd.extend_from_slice(&0u32.to_le_bytes()); // CRC = 0 (MASKED)
        cd.extend_from_slice(&0u32.to_le_bytes()); // compressed = 0 (MASKED)
        cd.extend_from_slice(&0u32.to_le_bytes()); // uncompressed = 0 (MASKED)
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra len
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk start
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        cd.extend_from_slice(name);

        let mut archive = local;
        archive.extend_from_slice(&cd);

        // EOCD
        archive.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&1u16.to_le_bytes());
        archive.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(central_offset as u32).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());

        archive
    }

    #[test]
    fn test_cd_encryption_bit13_masking() {
        let plaintext = b"Bit 13 masked data";
        let archive = build_bit13_masked_zip(plaintext);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "masked.txt");
        assert_eq!(entries[0].data, plaintext);
        // Verify the effective values were resolved from the local header
        assert_eq!(entries[0].header.crc32, crc32::crc32(plaintext));
        assert_eq!(entries[0].header.compressed_size, plaintext.len() as u64);
        assert_eq!(entries[0].header.uncompressed_size, plaintext.len() as u64);
    }

    #[test]
    fn test_cd_encryption_bit13_masking_empty_file() {
        let plaintext = b"";
        let archive = build_bit13_masked_zip(plaintext);
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"");
        assert_eq!(entries[0].header.crc32, crc32::crc32(b""));
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
}
