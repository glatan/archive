//! ZIP archive encoding.
//!
//! [`ZipEncoder`] assembles a whole archive in memory ([`ZipEncoder::finish`])
//! or emits it as split/spanned (multi-disk) segments
//! ([`ZipEncoder::finish_parts`]); [`ZipStreamWriter`] streams an archive to a
//! `std::io::Write` sink without a final assembly buffer.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::crc32;

use super::crypto::{
    ZIP_AES_METHOD, ZipAesExtraField, append_aes_extra_field, encode_aes_payload,
    encode_traditional_payload,
};
use super::decode::{ZipEntry, ZipHeader};
use super::encode_metadata;

pub use super::crypto::ZipAesStrength;

const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4B50;
const CENTRAL_DIRECTORY_HEADER_SIGNATURE: u32 = 0x0201_4B50;
const EOCD_SIGNATURE: u32 = 0x0605_4B50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4B50;
const ZIP64_EOCD_LOCATOR_SIGNATURE: u32 = 0x0706_4B50;
const ZIP64_EXTRA_FIELD_ID: u16 = 0x0001;
const NTFS_EXTRA_FIELD_ID: u16 = 0x000a;
const EXTENDED_TIMESTAMP_EXTRA_FIELD_ID: u16 = 0x5455;
const UNIX_EXTRA_FIELD_ID: u16 = 0x000d;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4B50;
const DATA_DESCRIPTOR_FLAG: u16 = 1 << 3;
const UTF8_FLAG: u16 = 1 << 11;
const ZIP_VERSION_DEFAULT: u16 = 20;
const ZIP_VERSION_ZIP64: u16 = 45;
const ZIP_VERSION_BZIP2: u16 = 46;

/// ZIP compression method for newly encoded entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZipCompression {
    /// Store the entry without compression.
    Store,
    /// Compress the entry with Deflate.
    #[default]
    Deflate,
    /// Compress the entry with bzip2.
    Bzip2,
    /// Compress the entry with LZMA.
    Lzma,
    /// Compress the entry with Zstandard.
    Zstd,
    /// Compress the entry with xz.
    Xz,
    /// Compress the entry with PPMd.
    Ppmd,
    /// Compress the entry with the legacy Shrinking method (method 1).
    Shrunk,
    /// Compress the entry with the legacy Reducing method, with the given
    /// compression factor 1-4 (methods 2-5).
    Reduce(u8),
    /// Compress the entry with the legacy Imploding method (method 6),
    /// using an 8 KiB dictionary and three Shannon-Fano trees.
    Implode,
    /// Compress the entry with Deflate64 (method 9).
    Deflate64,
    /// Compress the entry with PKWARE DCL Implode (method 10), emitting a
    /// literal-only stream: one 9-bit literal per input byte and no
    /// back-references, so the output does not reduce the data.
    DclImplode,
    /// Compress the entry with IBM z/OS CMPSC (method 16), emitting an
    /// alphabet-only (uncompressed) CMPSC stream. Requires the `cmpsc`
    /// feature; the stream carries one index symbol per input byte and does
    /// not reduce the data, mirroring the LZXD uncompressed-encoder precedent.
    Cmpsc,
}

/// Metadata for an encoded ZIP entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntryOptions {
    /// DOS modification time.
    pub mod_time: u16,
    /// DOS modification date.
    pub mod_date: u16,
    /// Optional file comment.
    pub comment: String,
    /// Mark the filename/comment fields as UTF-8.
    ///
    /// When `false`, metadata is encoded as CP437 per the traditional ZIP
    /// convention, and values outside CP437 are rejected.
    pub utf8: bool,
    /// Compression method used for the entry.
    pub compression: ZipCompression,
    /// Emit a post-data descriptor and leave CRC/sizes out of the local header.
    pub use_data_descriptor: bool,
    /// Force ZIP64 metadata even when sizes are below 4 GiB.
    pub force_zip64: bool,
    /// Internal file attributes (written to Central Directory).
    pub internal_attributes: u16,
    /// External file attributes (written to Central Directory).
    pub external_attributes: u32,
    /// NTFS modification time (100-nanosecond intervals since 1601-01-01).
    pub ntfs_mtime: Option<u64>,
    /// NTFS access time (100-nanosecond intervals since 1601-01-01).
    pub ntfs_atime: Option<u64>,
    /// NTFS creation time (100-nanosecond intervals since 1601-01-01).
    pub ntfs_ctime: Option<u64>,
    /// Unix modification time (seconds since epoch).
    pub unix_mtime: Option<u32>,
    /// Unix access time (seconds since epoch).
    pub unix_atime: Option<u32>,
    /// Unix UID.
    pub unix_uid: Option<u16>,
    /// Unix GID.
    pub unix_gid: Option<u16>,
    /// Unicode path (written as extra field 0x7075).
    pub unicode_path: Option<String>,
    /// Unicode comment (written as extra field 0x6375).
    pub unicode_comment: Option<String>,
}

impl Default for ZipEntryOptions {
    fn default() -> Self {
        Self {
            mod_time: 0,
            mod_date: 0,
            comment: String::new(),
            utf8: true,
            compression: ZipCompression::Deflate,
            use_data_descriptor: false,
            force_zip64: false,
            internal_attributes: 0,
            external_attributes: 0,
            ntfs_mtime: None,
            ntfs_atime: None,
            ntfs_ctime: None,
            unix_mtime: None,
            unix_atime: None,
            unix_uid: None,
            unix_gid: None,
            unicode_path: None,
            unicode_comment: None,
        }
    }
}

/// Options controlling the segment layout produced by
/// [`ZipEncoder::finish_parts_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZipSplitOptions {
    /// Place the whole central directory (and the end-of-archive tail)
    /// on the last segment.
    ///
    /// When `false` the tail may occupy its own trailing segment with the
    /// central directory ending on an earlier disk. That layout is legal
    /// per APPNOTE §8 but is rejected by readers that require the central
    /// directory to begin on the last disk (e.g. Info-ZIP `unzip`'s
    /// multi-disk handling). Enabling this option keeps `cd_disk ==
    /// this_disk`, at the cost of requiring the central directory plus
    /// tail to fit within one segment.
    pub central_directory_on_last_segment: bool,
}

/// Builder for creating ZIP archives.
#[derive(Debug, Default)]
pub struct ZipEncoder {
    entries: Vec<PendingEntry>,
    password: Option<Vec<u8>>,
    encryption: ZipEncryptionMode,
    archive_comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZipEncryptionMode {
    Aes(ZipAesStrength),
    Traditional,
}

impl Default for ZipEncryptionMode {
    fn default() -> Self {
        Self::Aes(ZipAesStrength::Aes256)
    }
}

#[derive(Debug)]
struct PendingEntry {
    name: String,
    data: Vec<u8>,
    options: ZipEntryOptions,
}

#[derive(Debug)]
struct EncodedEntry {
    name_bytes: Vec<u8>,
    comment_bytes: Vec<u8>,
    flags: u16,
    mod_time: u16,
    mod_date: u16,
    compression_method: u16,
    crc32: u32,
    stored_crc32: u32,
    compressed_data: Vec<u8>,
    uncompressed_size: u64,
    use_data_descriptor: bool,
    force_zip64: bool,
    /// Offset of the local file header, relative to the start of the disk
    /// that carries it (`disk_start`). Equal to the absolute offset for
    /// single-disk archives.
    local_header_offset: u64,
    /// Number of the disk on which this entry's local header starts
    /// (0 for single-disk archives).
    disk_start: u16,
    aes: Option<ZipAesExtraField>,
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

/// Streaming ZIP writer for unknown-size entries.
///
/// This writer emits local headers up front and always finalizes entries with
/// data descriptors. Stored entries are written directly as bytes are read.
/// Deflated entries currently buffer only the active entry until compression
/// completes, but the archive as a whole is still streamed without a final
/// assembly buffer.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct ZipStreamWriter<W: std::io::Write> {
    writer: W,
    entries: Vec<StreamedEntry>,
    bytes_written: u64,
}

#[cfg(feature = "std")]
#[derive(Debug)]
struct StreamedEntry {
    name_bytes: Vec<u8>,
    comment_bytes: Vec<u8>,
    flags: u16,
    mod_time: u16,
    mod_date: u16,
    compression_method: u16,
    crc32: u32,
    stored_crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    use_data_descriptor: bool,
    force_zip64: bool,
    local_header_offset: u64,
    aes: Option<ZipAesExtraField>,
}

impl ZipEncoder {
    /// Create a new ZIP encoder.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            password: None,
            encryption: ZipEncryptionMode::Aes(ZipAesStrength::Aes256),
            archive_comment: String::new(),
        }
    }

    /// Set the archive-level comment written in the End of Central Directory record.
    pub fn set_archive_comment(&mut self, comment: &str) {
        self.archive_comment = comment.to_string();
    }

    /// Encrypt subsequently added entries with WinZip AES.
    ///
    /// Defaults to AES-256 strength.
    pub fn set_password(&mut self, password: &str) {
        self.set_password_bytes(password.as_bytes());
    }

    /// Encrypt subsequently added entries with WinZip AES.
    ///
    /// Defaults to AES-256 strength.
    pub fn set_password_bytes(&mut self, password: &[u8]) {
        self.password = Some(password.to_vec());
        self.encryption = ZipEncryptionMode::Aes(ZipAesStrength::Aes256);
    }

    /// Encrypt subsequently added entries with the selected WinZip AES strength.
    pub fn set_password_with_aes_strength(&mut self, password: &str, strength: ZipAesStrength) {
        self.set_password_bytes_with_aes_strength(password.as_bytes(), strength);
    }

    /// Encrypt subsequently added entries with the selected WinZip AES strength.
    pub fn set_password_bytes_with_aes_strength(
        &mut self,
        password: &[u8],
        strength: ZipAesStrength,
    ) {
        self.password = Some(password.to_vec());
        self.encryption = ZipEncryptionMode::Aes(strength);
    }

    /// Encrypt subsequently added entries with traditional PKZIP encryption.
    pub fn set_traditional_password(&mut self, password: &str) {
        self.set_traditional_password_bytes(password.as_bytes());
    }

    /// Encrypt subsequently added entries with traditional PKZIP encryption.
    pub fn set_traditional_password_bytes(&mut self, password: &[u8]) {
        self.password = Some(password.to_vec());
        self.encryption = ZipEncryptionMode::Traditional;
    }

    /// Add a file entry using default options (Deflate).
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_options(name, data, &ZipEntryOptions::default());
    }

    /// Add a stored file entry.
    pub fn add_file_stored(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_options(
            name,
            data,
            &ZipEntryOptions {
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
    }

    /// Add a file entry with explicit metadata.
    pub fn add_file_with_options(&mut self, name: &str, data: &[u8], options: &ZipEntryOptions) {
        self.entries.push(PendingEntry {
            name: name.to_string(),
            data: data.to_vec(),
            options: options.clone(),
        });
    }

    /// Add an entry previously decoded from another ZIP archive.
    pub fn add_entry(&mut self, entry: &ZipEntry) {
        self.entries.push(PendingEntry {
            name: entry.name.clone(),
            data: entry.data.clone(),
            options: ZipEntryOptions::from(&entry.header),
        });
    }

    /// Finish the archive and return its serialized bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let prepared = PreparedArchive::new(self)?;

        let mut output = Vec::with_capacity(
            usize::try_from(prepared.total_size)
                .map_err(|_| Error::Unsupported("zip: archive too large"))?,
        );

        for entry in &prepared.entries {
            write_local_file_header(&mut output, entry)?;
        }
        for entry in &prepared.entries {
            write_central_directory_record(&mut output, entry)?;
        }
        write_end_of_central_directory(
            &mut output,
            prepared.entries.len() as u64,
            prepared.central_directory_size,
            prepared.central_directory_offset,
            prepared.needs_zip64_archive,
            &prepared.archive_comment_bytes,
            EocdDiskLayout::single_disk(prepared.entries.len() as u64),
        )?;
        Ok(output)
    }

    /// Finish the archive as a split/spanned (multi-disk) archive: a
    /// sequence of byte segments of at most `max_segment_size` bytes each,
    /// suitable for [`super::decode::decode_parts`] or for writing out as
    /// `.z01`, `.z02`, ..., `.zip` files (the naming is the caller's
    /// responsibility, APPNOTE §8.3).
    ///
    /// The segments form one logical byte stream (§8). Records are never
    /// cut at a segment boundary: the atomic units are each local file
    /// header with its name and extra field, each data descriptor, each
    /// central directory record, and the end-of-archive tail (the ZIP64
    /// EOCD record, its locator and the EOCD stay together on the last
    /// disk, §4.3.15). Only compressed entry data may be split across
    /// segments. Per-entry disk-start and disk-relative local header
    /// offsets, the central-directory disk fields and the EOCD/ZIP64 disk
    /// fields are filled in accordingly.
    ///
    /// Returns [`Error::InvalidData`] when `max_segment_size` is zero or an
    /// atomic record does not fit in a single segment, and
    /// [`Error::Unsupported`] when more than 65535 segments would be
    /// produced (the 16-bit disk fields cannot express more). A result of
    /// one segment is byte-identical to [`finish`](Self::finish).
    pub fn finish_parts(self, max_segment_size: usize) -> Result<Vec<Vec<u8>>, Error> {
        self.finish_parts_with(max_segment_size, &ZipSplitOptions::default())
    }

    /// Like [`finish_parts`](Self::finish_parts) with explicit segment
    /// layout options. See [`ZipSplitOptions`] for the available knobs.
    pub fn finish_parts_with(
        self,
        max_segment_size: usize,
        options: &ZipSplitOptions,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if max_segment_size == 0 {
            return Err(Error::InvalidData("zip: segment size too small"));
        }
        let mut prepared = PreparedArchive::new(self)?;
        let plan = plan_split(
            &prepared.entries,
            prepared.needs_zip64_archive,
            prepared.archive_comment_bytes.len(),
            max_segment_size as u64,
            options.central_directory_on_last_segment,
        )?;

        // Resolve each entry's disk placement into its header fields. A
        // disk-relative offset never exceeds the absolute offset it
        // replaces, and pinning `force_zip64` where the absolute offset
        // already required ZIP64 keeps the emitted record sizes identical
        // to the ones the plan was computed from.
        for (entry, &(disk, rel_offset)) in
            prepared.entries.iter_mut().zip(plan.entry_headers.iter())
        {
            if needs_zip64_entry(entry) {
                entry.force_zip64 = true;
            }
            entry.disk_start = u16::try_from(disk)
                .map_err(|_| Error::Unsupported("zip: too many archive parts"))?;
            entry.local_header_offset = rel_offset;
        }

        let mut output = Vec::with_capacity(
            usize::try_from(plan.total_size)
                .map_err(|_| Error::Unsupported("zip: archive too large"))?,
        );
        for entry in &prepared.entries {
            write_local_file_header(&mut output, entry)?;
        }
        let central_directory_start = output.len() as u64;
        for entry in &prepared.entries {
            write_central_directory_record(&mut output, entry)?;
        }
        let central_directory_size = output.len() as u64 - central_directory_start;
        let last_disk = plan.part_starts.len() as u64 - 1;
        write_end_of_central_directory(
            &mut output,
            prepared.entries.len() as u64,
            central_directory_size,
            plan.cd_offset,
            prepared.needs_zip64_archive,
            &prepared.archive_comment_bytes,
            EocdDiskLayout {
                this_disk: last_disk as u16,
                cd_disk: plan.cd_disk as u16,
                entries_this_disk: plan.entries_on_last_disk,
                disk_base: plan.part_starts[plan.part_starts.len() - 1],
                total_disks: plan.part_starts.len() as u64,
            },
        )?;
        debug_assert_eq!(output.len() as u64, plan.total_size);

        let mut parts = Vec::with_capacity(plan.part_starts.len());
        for (index, &start) in plan.part_starts.iter().enumerate() {
            let end = plan
                .part_starts
                .get(index + 1)
                .copied()
                .unwrap_or(plan.total_size);
            parts.push(output[start as usize..end as usize].to_vec());
        }
        Ok(parts)
    }

    /// Finish the archive and write it to a stream without assembling the final bytes first.
    #[cfg(feature = "std")]
    pub fn finish_to<W: std::io::Write>(self, mut writer: W) -> std::io::Result<usize> {
        let prepared = PreparedArchive::new(self)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
        let mut written = 0usize;
        let mut record = Vec::new();

        for entry in &prepared.entries {
            record.clear();
            write_local_file_header(&mut record, entry).map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
            })?;
            writer.write_all(&record)?;
            written += record.len();
        }
        for entry in &prepared.entries {
            record.clear();
            write_central_directory_record(&mut record, entry).map_err(|err| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
            })?;
            writer.write_all(&record)?;
            written += record.len();
        }
        record.clear();
        write_end_of_central_directory(
            &mut record,
            prepared.entries.len() as u64,
            prepared.central_directory_size,
            prepared.central_directory_offset,
            prepared.needs_zip64_archive,
            &prepared.archive_comment_bytes,
            EocdDiskLayout::single_disk(prepared.entries.len() as u64),
        )
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
        writer.write_all(&record)?;
        written += record.len();

        Ok(written)
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> ZipStreamWriter<W> {
    /// Create a new streaming ZIP writer.
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            entries: Vec::new(),
            bytes_written: 0,
        }
    }

    /// Return the number of bytes emitted so far.
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a file entry from a reader without requiring the size up front.
    ///
    /// This API always emits a data descriptor for the entry, regardless of
    /// `options.use_data_descriptor`.
    pub fn write_file_from_reader<R: std::io::Read>(
        &mut self,
        name: &str,
        mut reader: R,
        options: &ZipEntryOptions,
    ) -> std::io::Result<()> {
        validate_name(name).map_err(io_invalid_data)?;
        validate_comment(&options.comment).map_err(io_invalid_data)?;

        let mut stream_options = options.clone();
        stream_options.use_data_descriptor = true;

        let name_bytes = encode_metadata(name, stream_options.utf8).map_err(io_invalid_data)?;
        let comment_bytes = encode_metadata(&stream_options.comment, stream_options.utf8)
            .map_err(io_invalid_data)?;
        let local_header_offset = self.bytes_written;

        let header = StreamedEntry {
            name_bytes: name_bytes.clone(),
            comment_bytes: comment_bytes.clone(),
            flags: entry_flags(&stream_options),
            mod_time: stream_options.mod_time,
            mod_date: stream_options.mod_date,
            compression_method: compression_method_id(stream_options.compression),
            crc32: 0,
            stored_crc32: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            use_data_descriptor: true,
            force_zip64: stream_options.force_zip64,
            local_header_offset,
            aes: None,
        };

        let mut record = Vec::new();
        write_streamed_local_file_header(&mut record, &header).map_err(io_invalid_data)?;
        self.writer.write_all(&record)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(record.len() as u64)
            .ok_or_else(|| std::io::Error::other("zip: archive too large"))?;

        let mut crc = crc32::Crc32::new();
        let mut uncompressed_size = 0u64;
        // Streaming writer: buffer all input, compress with compress_data()
        let compressed_size = {
            let mut plain = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let chunk = &buffer[..read];
                crc.update(chunk);
                uncompressed_size = uncompressed_size
                    .checked_add(read as u64)
                    .ok_or_else(|| std::io::Error::other("zip: entry too large"))?;
                plain.extend_from_slice(chunk);
            }
            let (_method, compressed) =
                compress_data(&plain, stream_options.compression).map_err(io_invalid_data)?;
            let compressed_size = compressed.len() as u64;
            self.writer.write_all(&compressed)?;
            self.bytes_written = self
                .bytes_written
                .checked_add(compressed_size)
                .ok_or_else(|| std::io::Error::other("zip: archive too large"))?;
            compressed_size
        };

        let entry = StreamedEntry {
            name_bytes,
            comment_bytes,
            flags: header.flags,
            mod_time: header.mod_time,
            mod_date: header.mod_date,
            compression_method: header.compression_method,
            crc32: crc.finish(),
            stored_crc32: crc.finish(),
            compressed_size,
            uncompressed_size,
            use_data_descriptor: true,
            force_zip64: header.force_zip64,
            local_header_offset,
            aes: None,
        };

        record.clear();
        write_streamed_data_descriptor(&mut record, &entry);
        self.writer.write_all(&record)?;
        self.bytes_written = self
            .bytes_written
            .checked_add(record.len() as u64)
            .ok_or_else(|| std::io::Error::other("zip: archive too large"))?;
        self.entries.push(entry);
        Ok(())
    }

    /// Finish the archive, write the central directory, and return the sink.
    pub fn finish(mut self) -> std::io::Result<W> {
        let central_directory_offset = self.bytes_written;
        let central_directory_size = self.entries.iter().try_fold(0u64, |acc, entry| {
            acc.checked_add(streamed_central_directory_record_len(entry))
                .ok_or_else(|| std::io::Error::other("zip: archive too large"))
        })?;
        let needs_zip64_archive = self.entries.iter().any(streamed_needs_zip64_entry)
            || central_directory_offset > u32::MAX as u64
            || central_directory_size > u32::MAX as u64
            || self.entries.len() > u16::MAX as usize;

        let mut record = Vec::new();
        for entry in &self.entries {
            record.clear();
            write_streamed_central_directory_record(&mut record, entry).map_err(io_invalid_data)?;
            self.writer.write_all(&record)?;
            self.bytes_written = self
                .bytes_written
                .checked_add(record.len() as u64)
                .ok_or_else(|| std::io::Error::other("zip: archive too large"))?;
        }

        record.clear();
        write_end_of_central_directory(
            &mut record,
            self.entries.len() as u64,
            central_directory_size,
            central_directory_offset,
            needs_zip64_archive,
            &[], // streaming writer has no archive comment
            EocdDiskLayout::single_disk(self.entries.len() as u64),
        )
        .map_err(io_invalid_data)?;
        self.writer.write_all(&record)?;
        Ok(self.writer)
    }
}

struct PreparedArchive {
    entries: Vec<EncodedEntry>,
    central_directory_offset: u64,
    central_directory_size: u64,
    needs_zip64_archive: bool,
    total_size: u64,
    archive_comment_bytes: Vec<u8>,
}

impl PreparedArchive {
    fn new(encoder: ZipEncoder) -> Result<Self, Error> {
        let ZipEncoder {
            entries: pending,
            password,
            encryption,
            archive_comment,
        } = encoder;
        let archive_comment_bytes = archive_comment.into_bytes();
        let mut entries = Vec::with_capacity(pending.len());
        for entry in pending {
            validate_name(&entry.name)?;
            validate_comment(&entry.options.comment)?;
            let name_bytes = encode_metadata(&entry.name, entry.options.utf8)?;
            let comment_bytes = encode_metadata(&entry.options.comment, entry.options.utf8)?;
            let mut flags = entry_flags(&entry.options);
            let (actual_compression_method, mut compressed_data) =
                compress_data(&entry.data, entry.options.compression)?;
            let crc32 = crc32::crc32(&entry.data);
            let mut compression_method = actual_compression_method;
            let mut aes = None;
            if let Some(password) = password.as_deref() {
                let mut seed = Vec::with_capacity(name_bytes.len() + 16);
                seed.extend_from_slice(&name_bytes);
                seed.extend_from_slice(&crc32.to_le_bytes());
                seed.extend_from_slice(&(entry.data.len() as u64).to_le_bytes());
                match encryption {
                    ZipEncryptionMode::Aes(aes_strength) => {
                        let encoded = encode_aes_payload(
                            password,
                            &compressed_data,
                            actual_compression_method,
                            &seed,
                            aes_strength,
                        )?;
                        compressed_data = encoded.payload;
                        compression_method = ZIP_AES_METHOD;
                        flags |= 1;
                        aes = Some(encoded.extra);
                    }
                    ZipEncryptionMode::Traditional => {
                        compressed_data = encode_traditional_payload(
                            password,
                            &compressed_data,
                            crc32,
                            entry.options.mod_time,
                            entry.options.use_data_descriptor,
                            &seed,
                        )?;
                        flags |= 1;
                    }
                }
            }
            entries.push(EncodedEntry {
                name_bytes,
                comment_bytes,
                flags,
                mod_time: entry.options.mod_time,
                mod_date: entry.options.mod_date,
                compression_method,
                crc32,
                stored_crc32: crc32,
                compressed_data,
                uncompressed_size: entry.data.len() as u64,
                use_data_descriptor: entry.options.use_data_descriptor,
                force_zip64: entry.options.force_zip64,
                local_header_offset: 0,
                disk_start: 0,
                aes,
                internal_attributes: entry.options.internal_attributes,
                external_attributes: entry.options.external_attributes,
                ntfs_mtime: entry.options.ntfs_mtime,
                ntfs_atime: entry.options.ntfs_atime,
                ntfs_ctime: entry.options.ntfs_ctime,
                unix_mtime: entry.options.unix_mtime,
                unix_atime: entry.options.unix_atime,
                unix_uid: entry.options.unix_uid,
                unix_gid: entry.options.unix_gid,
                unicode_path: entry.options.unicode_path.clone(),
                unicode_comment: entry.options.unicode_comment.clone(),
            });
        }

        let mut local_offset = 0u64;
        for entry in &mut entries {
            entry.local_header_offset = local_offset;
            local_offset = local_offset
                .checked_add(local_record_len(entry))
                .ok_or(Error::Unsupported("zip: archive too large"))?;
        }

        let central_directory_offset = local_offset;
        let central_directory_size = entries.iter().try_fold(0u64, |acc, entry| {
            acc.checked_add(central_directory_record_len(entry))
                .ok_or(Error::Unsupported("zip: archive too large"))
        })?;

        let needs_zip64_archive = entries.iter().any(needs_zip64_entry)
            || central_directory_offset > u32::MAX as u64
            || central_directory_size > u32::MAX as u64
            || entries.len() > u16::MAX as usize;
        let tail_size = if needs_zip64_archive { 98u64 } else { 22u64 };
        let total_size = central_directory_offset
            .checked_add(central_directory_size)
            .and_then(|v| v.checked_add(tail_size))
            .and_then(|v| v.checked_add(archive_comment_bytes.len() as u64))
            .ok_or(Error::Unsupported("zip: archive too large"))?;

        Ok(Self {
            entries,
            central_directory_offset,
            central_directory_size,
            needs_zip64_archive,
            total_size,
            archive_comment_bytes,
        })
    }
}

/// Layout of a split/spanned archive produced by [`plan_split`].
struct SplitPlan {
    /// Absolute stream offset at which each segment (disk) begins.
    /// Always starts at 0 and is strictly increasing.
    part_starts: Vec<u64>,
    /// `(disk index, disk-relative offset)` of each entry's local file
    /// header, in entry order.
    entry_headers: Vec<(u64, u64)>,
    /// Disk on which the first central directory record begins.
    cd_disk: u64,
    /// Disk-relative offset of the central directory's first record.
    cd_offset: u64,
    /// Central directory records that start on the last disk (the disk
    /// carrying the EOCD).
    entries_on_last_disk: u64,
    /// Total length of the emitted stream.
    total_size: u64,
}

/// Place an atomic record of `len` bytes at `pos`, opening a new segment
/// when it would straddle the `max` boundary. Returns the record's start
/// offset. Every push to `part_starts` is followed by at least one byte
/// of content, so no empty segment is produced.
fn place_atomic_record(
    part_starts: &mut Vec<u64>,
    disk_base: &mut u64,
    pos: &mut u64,
    len: u64,
    max: u64,
) -> Result<u64, Error> {
    if len > max {
        return Err(Error::InvalidData("zip: segment size too small"));
    }
    if *pos - *disk_base + len > max {
        // Does not fit in the remainder of the current segment; the new
        // segment starts at the record boundary (`pos > *disk_base`
        // always holds here because `len <= max`).
        part_starts.push(*pos);
        *disk_base = *pos;
    }
    let start = *pos;
    *pos += len;
    Ok(start)
}

/// Compute the segment boundaries of a split archive (APPNOTE §8),
/// filling each segment greedily up to `max` bytes.
///
/// Local file headers (including name and extra field), data
/// descriptors, central directory records and the end-of-archive tail
/// (ZIP64 EOCD + locator + EOCD, kept together per §4.3.15) are atomic:
/// they never straddle a segment boundary. Compressed entry data is the
/// only unit that may be split mid-stream.
fn plan_split(
    entries: &[EncodedEntry],
    needs_zip64_archive: bool,
    archive_comment_len: usize,
    max: u64,
    cd_on_last_segment: bool,
) -> Result<SplitPlan, Error> {
    let mut plan = SplitPlan {
        part_starts: vec![0],
        entry_headers: Vec::with_capacity(entries.len()),
        cd_disk: 0,
        cd_offset: 0,
        entries_on_last_disk: 0,
        total_size: 0,
    };
    let mut disk_base = 0u64;
    let mut pos = 0u64;

    for entry in entries {
        // Local file header + name + extra: atomic.
        let head = 30 + entry.name_bytes.len() as u64 + local_extra_field(entry).len() as u64;
        let start =
            place_atomic_record(&mut plan.part_starts, &mut disk_base, &mut pos, head, max)?;
        plan.entry_headers
            .push((plan.part_starts.len() as u64 - 1, start - disk_base));

        // Compressed data: splittable at any byte boundary.
        let mut remaining = entry.compressed_data.len() as u64;
        while remaining > 0 {
            let space = max - (pos - disk_base);
            if space == 0 {
                plan.part_starts.push(pos);
                disk_base = pos;
                continue;
            }
            let take = remaining.min(space);
            pos += take;
            remaining -= take;
        }

        // Data descriptor: atomic.
        let descriptor = data_descriptor_len(entry);
        if descriptor > 0 {
            place_atomic_record(
                &mut plan.part_starts,
                &mut disk_base,
                &mut pos,
                descriptor,
                max,
            )?;
        }
    }

    // End-of-archive tail: ZIP64 EOCD record + ZIP64 EOCD locator + EOCD
    // must reside on the same (last) disk (APPNOTE §4.3.15).
    let tail = if needs_zip64_archive { 76 } else { 0 } + 22 + archive_comment_len as u64;

    if cd_on_last_segment {
        // The whole central directory and the tail form one atomic unit
        // so that the CD begins on the last disk (cd_disk == this_disk),
        // the layout readers such as Info-ZIP unzip require for
        // multi-disk archives.
        let cd_total = entries
            .iter()
            .map(central_directory_record_len)
            .sum::<u64>()
            + tail;
        let start = place_atomic_record(
            &mut plan.part_starts,
            &mut disk_base,
            &mut pos,
            cd_total,
            max,
        )?;
        plan.cd_disk = plan.part_starts.len() as u64 - 1;
        plan.cd_offset = start - disk_base;
        plan.entries_on_last_disk = entries.len() as u64;
    } else {
        let mut cd_record_disks = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            let len = central_directory_record_len(entry);
            let start =
                place_atomic_record(&mut plan.part_starts, &mut disk_base, &mut pos, len, max)?;
            if index == 0 {
                plan.cd_disk = plan.part_starts.len() as u64 - 1;
                plan.cd_offset = start - disk_base;
            }
            cd_record_disks.push(plan.part_starts.len() as u64 - 1);
        }
        place_atomic_record(&mut plan.part_starts, &mut disk_base, &mut pos, tail, max)?;
        let last_disk = plan.part_starts.len() as u64 - 1;
        plan.entries_on_last_disk = cd_record_disks
            .iter()
            .filter(|&&disk| disk == last_disk)
            .count() as u64;
    }

    if plan.part_starts.len() > 0xFFFF {
        // Disk indexes are 16-bit; 0xFFFF is the ZIP64-extra sentinel.
        return Err(Error::Unsupported("zip: too many archive parts"));
    }
    plan.total_size = pos;
    Ok(plan)
}

impl From<&ZipHeader> for ZipEntryOptions {
    fn from(header: &ZipHeader) -> Self {
        Self {
            mod_time: header.mod_time,
            mod_date: header.mod_date,
            comment: header.comment.clone(),
            utf8: (header.flags & UTF8_FLAG) != 0,
            compression: match header.compression_method {
                0 => ZipCompression::Store,
                8 => ZipCompression::Deflate,
                12 => ZipCompression::Bzip2,
                14 => ZipCompression::Lzma,
                93 => ZipCompression::Zstd,
                95 => ZipCompression::Xz,
                98 => ZipCompression::Ppmd,
                10 => ZipCompression::DclImplode,
                16 => ZipCompression::Cmpsc,
                _ => ZipCompression::Store,
            },
            use_data_descriptor: (header.flags & DATA_DESCRIPTOR_FLAG) != 0,
            force_zip64: false,
            internal_attributes: header.internal_attributes,
            external_attributes: header.external_attributes,
            ntfs_mtime: header.ntfs_mtime,
            ntfs_atime: header.ntfs_atime,
            ntfs_ctime: header.ntfs_ctime,
            unix_mtime: header.unix_mtime,
            unix_atime: header.unix_atime,
            unix_uid: header.unix_uid,
            unix_gid: header.unix_gid,
            unicode_path: header.unicode_path.clone(),
            unicode_comment: header.unicode_comment.clone(),
        }
    }
}

const fn entry_flags(options: &ZipEntryOptions) -> u16 {
    let mut flags = 0u16;
    if options.utf8 {
        flags |= UTF8_FLAG;
    }
    if options.use_data_descriptor {
        flags |= DATA_DESCRIPTOR_FLAG;
    }
    if let ZipCompression::Implode = options.compression {
        // Bit 1: 8 KiB dictionary, bit 2: three Shannon-Fano trees.
        flags |= 0x0006;
    }
    flags
}

fn compress_data(data: &[u8], compression: ZipCompression) -> Result<(u16, Vec<u8>), Error> {
    match compression {
        ZipCompression::Store => Ok((0, data.to_vec())),
        ZipCompression::Deflate => Ok((
            8,
            deflate::encode::encode(data, deflate::encode::Level::Default),
        )),
        ZipCompression::Bzip2 => {
            #[cfg(feature = "bzip2")]
            {
                Ok((12, crate::compress::bzip2::encode::encode(data)))
            }
            #[cfg(not(feature = "bzip2"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: bzip2 compression (enable bzip2 feature)",
                ))
            }
        }
        ZipCompression::Lzma => {
            #[cfg(any(feature = "lzip", feature = "xz", feature = "sevenz"))]
            {
                // LZMA in ZIP: version(2) + prop_size(2) + props(5) + lzma_stream
                let dict_size = 1u32 << 16; // 64 KB
                let encoded = crate::compress::lzma::lzma_encode(data, dict_size);
                let lc: u8 = 3;
                let lp: u8 = 0;
                let pb: u8 = 2;
                let prop_byte = lc + lp * 9 + pb * 45;
                let mut out = Vec::with_capacity(4 + 5 + encoded.len());
                // version = 2, property size = 5
                out.extend_from_slice(&2u16.to_le_bytes());
                out.extend_from_slice(&5u16.to_le_bytes());
                out.push(prop_byte);
                out.extend_from_slice(&dict_size.to_le_bytes());
                out.extend_from_slice(&encoded);
                Ok((14, out))
            }
            #[cfg(not(any(feature = "lzip", feature = "xz", feature = "sevenz")))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: LZMA compression (enable lzip/xz feature)",
                ))
            }
        }
        ZipCompression::Zstd => {
            #[cfg(feature = "zstd")]
            {
                Ok((93, crate::compress::zstd::encode::encode(data)))
            }
            #[cfg(not(feature = "zstd"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: zstd compression (enable zstd feature)",
                ))
            }
        }
        ZipCompression::Xz => {
            #[cfg(feature = "xz")]
            {
                Ok((95, crate::compress::xz::encode::encode(data)))
            }
            #[cfg(not(feature = "xz"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: xz compression (enable xz feature)",
                ))
            }
        }
        ZipCompression::Shrunk => Ok((1, super::unshrink::shrink(data))),
        ZipCompression::Reduce(factor) => {
            if !(1..=4).contains(&factor) {
                return Err(Error::InvalidData("zip: reduce factor must be 1-4"));
            }
            Ok((factor as u16 + 1, super::expand::reduce(data, factor)))
        }
        ZipCompression::Implode => Ok((6, super::implode::implode_encode(data, true, true))),
        ZipCompression::Deflate64 => Ok((9, crate::compress::deflate64::encode::encode(data))),
        ZipCompression::DclImplode => Ok((10, super::dcl_implode::dcl_implode_encode(data))),
        ZipCompression::Ppmd => {
            #[cfg(feature = "sevenz")]
            {
                let order: u8 = 6;
                let mem_order: u8 = 20; // 1 MB
                let mem_size = 1u32 << mem_order;
                let props = crate::compress::ppmd::Ppmd7Properties::new(order, mem_size)?;
                let encoded = crate::compress::ppmd::encode(data, props, false)?;
                let params = (order as u16) | ((mem_order as u16) << 8);
                let mut out = Vec::with_capacity(2 + encoded.len());
                out.extend_from_slice(&params.to_le_bytes());
                out.extend_from_slice(&encoded);
                Ok((98, out))
            }
            #[cfg(not(feature = "sevenz"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: PPMd compression (enable sevenz feature)",
                ))
            }
        }
        ZipCompression::Cmpsc => {
            #[cfg(feature = "cmpsc")]
            {
                Ok((16, crate::compress::cmpsc::encode(data)))
            }
            #[cfg(not(feature = "cmpsc"))]
            {
                let _ = data;
                Err(Error::Unsupported(
                    "zip: IBM z/OS CMPSC compression (method 16; enable cmpsc feature)",
                ))
            }
        }
    }
}

/// Return the ZIP method ID for a compression variant.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
const fn compression_method_id(compression: ZipCompression) -> u16 {
    match compression {
        ZipCompression::Store => 0,
        ZipCompression::Deflate => 8,
        ZipCompression::Bzip2 => 12,
        ZipCompression::Lzma => 14,
        ZipCompression::Zstd => 93,
        ZipCompression::Xz => 95,
        ZipCompression::Ppmd => 98,
        ZipCompression::Shrunk => 1,
        ZipCompression::Reduce(factor) => factor as u16 + 1,
        ZipCompression::Implode => 6,
        ZipCompression::Deflate64 => 9,
        ZipCompression::DclImplode => 10,
        ZipCompression::Cmpsc => 16,
    }
}

/// Compute the minimum version needed to extract, based on features used.
fn compute_version_needed(compression: ZipCompression, zip64: bool, aes: bool) -> u16 {
    let mut version = ZIP_VERSION_DEFAULT;
    if aes {
        version = version.max(51);
    }
    if zip64 {
        version = version.max(ZIP_VERSION_ZIP64);
    }
    match compression {
        ZipCompression::Bzip2 => version = version.max(ZIP_VERSION_BZIP2),
        ZipCompression::Lzma | ZipCompression::Ppmd => version = version.max(63),
        ZipCompression::Deflate64 => version = version.max(21),
        // APPNOTE §4.4.3.2: DCL Implode needs version 2.5.
        ZipCompression::DclImplode => version = version.max(25),
        _ => {}
    }
    version
}

/// Return the version-made-by field.
/// Upper byte = host OS (3 = Unix, 0 = DOS/FAT).
fn version_made_by(zip64: bool, compression: ZipCompression, aes: bool) -> u16 {
    let version = compute_version_needed(compression, zip64, aes);
    #[cfg(unix)]
    let host_byte: u16 = 3 << 8; // Unix
    #[cfg(not(unix))]
    let host_byte: u16 = 0; // DOS
    host_byte | version
}

fn write_local_file_header(output: &mut Vec<u8>, entry: &EncodedEntry) -> Result<(), Error> {
    let zip64 = needs_zip64_entry(entry) && !entry.use_data_descriptor;
    let extra = local_extra_field(entry);

    output.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
    output.extend_from_slice(
        &compute_version_needed(entry_compression(entry), zip64, entry.aes.is_some()).to_le_bytes(),
    );
    output.extend_from_slice(&entry.flags.to_le_bytes());
    output.extend_from_slice(&entry.compression_method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    if entry.use_data_descriptor {
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
    } else if zip64 {
        output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
        output.extend_from_slice(&(entry.compressed_data.len() as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
    output.extend_from_slice(
        &u16_len(entry.name_bytes.len(), "zip: file name too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&u16_len(extra.len(), "zip: extra field too large")?.to_le_bytes());
    output.extend_from_slice(&entry.name_bytes);
    output.extend_from_slice(&extra);
    output.extend_from_slice(&entry.compressed_data);
    if entry.use_data_descriptor {
        write_data_descriptor(output, entry);
    }
    Ok(())
}

fn write_central_directory_record(output: &mut Vec<u8>, entry: &EncodedEntry) -> Result<(), Error> {
    let zip64 = needs_zip64_entry(entry);
    let extra = central_extra_field(entry);
    let compression = entry_compression(entry);

    output.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
    output
        .extend_from_slice(&version_made_by(zip64, compression, entry.aes.is_some()).to_le_bytes());
    output.extend_from_slice(
        &compute_version_needed(compression, zip64, entry.aes.is_some()).to_le_bytes(),
    );
    output.extend_from_slice(&entry.flags.to_le_bytes());
    output.extend_from_slice(&entry.compression_method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
    if zip64 {
        output.extend_from_slice(&u32::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.compressed_data.len() as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
    output.extend_from_slice(
        &u16_len(entry.name_bytes.len(), "zip: file name too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&u16_len(extra.len(), "zip: extra field too large")?.to_le_bytes());
    output.extend_from_slice(
        &u16_len(entry.comment_bytes.len(), "zip: comment too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&entry.disk_start.to_le_bytes()); // disk number start
    output.extend_from_slice(&entry.internal_attributes.to_le_bytes());
    output.extend_from_slice(&entry.external_attributes.to_le_bytes());
    if zip64 {
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.local_header_offset as u32).to_le_bytes());
    }
    output.extend_from_slice(&entry.name_bytes);
    output.extend_from_slice(&extra);
    output.extend_from_slice(&entry.comment_bytes);
    Ok(())
}

/// Map an encoded entry's compression_method back to ZipCompression for version calc.
/// Resolve the effective compression method; for AES entries the real
/// method lives in the AES extra field.
fn method_compression(method: u16, aes: Option<&ZipAesExtraField>) -> ZipCompression {
    let method = aes.map_or(method, |a| a.actual_compression_method);
    match method {
        0 => ZipCompression::Store,
        8 => ZipCompression::Deflate,
        12 => ZipCompression::Bzip2,
        14 => ZipCompression::Lzma,
        93 => ZipCompression::Zstd,
        95 => ZipCompression::Xz,
        98 => ZipCompression::Ppmd,
        10 => ZipCompression::DclImplode,
        16 => ZipCompression::Cmpsc,
        _ => ZipCompression::Store,
    }
}

fn entry_compression(entry: &EncodedEntry) -> ZipCompression {
    method_compression(entry.compression_method, entry.aes.as_ref())
}

#[cfg(feature = "std")]
fn streamed_compression(entry: &StreamedEntry) -> ZipCompression {
    method_compression(entry.compression_method, entry.aes.as_ref())
}

/// Disk-placement fields of the end-of-archive tail (EOCD, plus ZIP64
/// EOCD and locator when emitted). For a single-disk archive every field
/// takes its default (all disks 0, one disk total).
#[derive(Debug, Clone, Copy)]
struct EocdDiskLayout {
    /// Number of the disk carrying the EOCD record (the last disk).
    this_disk: u16,
    /// Number of the disk on which the central directory starts.
    cd_disk: u16,
    /// Number of central directory entries stored on `this_disk`.
    entries_this_disk: u64,
    /// Absolute offset in the output stream where `this_disk` begins.
    disk_base: u64,
    /// Total number of disks in the archive set.
    total_disks: u64,
}

impl EocdDiskLayout {
    /// Disk fields for a single-disk archive.
    const fn single_disk(total_entries: u64) -> Self {
        Self {
            this_disk: 0,
            cd_disk: 0,
            entries_this_disk: total_entries,
            disk_base: 0,
            total_disks: 1,
        }
    }
}

fn write_end_of_central_directory(
    output: &mut Vec<u8>,
    total_entries: u64,
    central_directory_size: u64,
    central_directory_offset: u64,
    zip64: bool,
    archive_comment: &[u8],
    disk: EocdDiskLayout,
) -> Result<(), Error> {
    if zip64 {
        // The ZIP64 EOCD record and its locator always sit on the last disk
        // (APPNOTE §4.3.15); the locator offset is relative to that disk.
        let zip64_eocd_offset = output.len() as u64 - disk.disk_base;
        output.extend_from_slice(&ZIP64_EOCD_SIGNATURE.to_le_bytes());
        output.extend_from_slice(&44u64.to_le_bytes());
        output.extend_from_slice(&ZIP_VERSION_ZIP64.to_le_bytes());
        output.extend_from_slice(&ZIP_VERSION_ZIP64.to_le_bytes());
        output.extend_from_slice(&(disk.this_disk as u32).to_le_bytes());
        output.extend_from_slice(&(disk.cd_disk as u32).to_le_bytes());
        output.extend_from_slice(&disk.entries_this_disk.to_le_bytes());
        output.extend_from_slice(&total_entries.to_le_bytes());
        output.extend_from_slice(&central_directory_size.to_le_bytes());
        output.extend_from_slice(&central_directory_offset.to_le_bytes());

        output.extend_from_slice(&ZIP64_EOCD_LOCATOR_SIGNATURE.to_le_bytes());
        output.extend_from_slice(&(disk.this_disk as u32).to_le_bytes());
        output.extend_from_slice(&zip64_eocd_offset.to_le_bytes());
        output.extend_from_slice(&(disk.total_disks as u32).to_le_bytes());
    }

    let comment_len = u16::try_from(archive_comment.len())
        .map_err(|_| Error::Unsupported("zip: archive comment too long"))?;

    output.extend_from_slice(&EOCD_SIGNATURE.to_le_bytes());
    output.extend_from_slice(&disk.this_disk.to_le_bytes());
    output.extend_from_slice(&disk.cd_disk.to_le_bytes());
    if zip64 {
        output.extend_from_slice(&u16::MAX.to_le_bytes());
        output.extend_from_slice(&u16::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        let disk_entries = u16::try_from(disk.entries_this_disk)
            .map_err(|_| Error::Unsupported("zip: too many entries"))?;
        let entry_count = u16::try_from(total_entries)
            .map_err(|_| Error::Unsupported("zip: too many entries"))?;
        output.extend_from_slice(&disk_entries.to_le_bytes());
        output.extend_from_slice(&entry_count.to_le_bytes());
        output.extend_from_slice(
            &u32::try_from(central_directory_size)
                .map_err(|_| Error::Unsupported("zip: central directory too large"))?
                .to_le_bytes(),
        );
        output.extend_from_slice(
            &u32::try_from(central_directory_offset)
                .map_err(|_| Error::Unsupported("zip: central directory offset too large"))?
                .to_le_bytes(),
        );
    }
    output.extend_from_slice(&comment_len.to_le_bytes());
    output.extend_from_slice(archive_comment);
    Ok(())
}

fn local_record_len(entry: &EncodedEntry) -> u64 {
    30 + entry.name_bytes.len() as u64
        + local_extra_field(entry).len() as u64
        + entry.compressed_data.len() as u64
        + data_descriptor_len(entry)
}

fn central_directory_record_len(entry: &EncodedEntry) -> u64 {
    46 + entry.name_bytes.len() as u64
        + central_extra_field(entry).len() as u64
        + entry.comment_bytes.len() as u64
}

fn local_extra_field(entry: &EncodedEntry) -> Vec<u8> {
    let mut extra = Vec::new();
    if needs_zip64_entry(entry) && !entry.use_data_descriptor {
        extra.reserve(20);
        extra.extend_from_slice(&ZIP64_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&16u16.to_le_bytes());
        extra.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
        extra.extend_from_slice(&(entry.compressed_data.len() as u64).to_le_bytes());
    }
    if let Some(aes) = entry.aes {
        append_aes_extra_field(&mut extra, aes);
    }
    append_timestamp_extra_fields(&mut extra, entry);
    extra
}

const fn data_descriptor_len(entry: &EncodedEntry) -> u64 {
    if !entry.use_data_descriptor {
        return 0;
    }
    if needs_zip64_entry(entry) { 24 } else { 16 }
}

fn write_data_descriptor(output: &mut Vec<u8>, entry: &EncodedEntry) {
    output.extend_from_slice(&DATA_DESCRIPTOR_SIGNATURE.to_le_bytes());
    output.extend_from_slice(&entry.crc32.to_le_bytes());
    if needs_zip64_entry(entry) {
        output.extend_from_slice(&(entry.compressed_data.len() as u64).to_le_bytes());
        output.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.compressed_data.len() as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
}

#[cfg(feature = "std")]
fn write_streamed_local_file_header(
    output: &mut Vec<u8>,
    entry: &StreamedEntry,
) -> Result<(), Error> {
    let zip64 = streamed_needs_zip64_entry(entry) && !entry.use_data_descriptor;
    let extra = streamed_local_extra_field(entry);

    output.extend_from_slice(&LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
    output.extend_from_slice(
        &compute_version_needed(streamed_compression(entry), zip64, entry.aes.is_some())
            .to_le_bytes(),
    );
    output.extend_from_slice(&entry.flags.to_le_bytes());
    output.extend_from_slice(&entry.compression_method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    if entry.use_data_descriptor {
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
    } else if zip64 {
        output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
        output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
    output.extend_from_slice(
        &u16_len(entry.name_bytes.len(), "zip: file name too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&u16_len(extra.len(), "zip: extra field too large")?.to_le_bytes());
    output.extend_from_slice(&entry.name_bytes);
    output.extend_from_slice(&extra);
    Ok(())
}

#[cfg(feature = "std")]
fn write_streamed_central_directory_record(
    output: &mut Vec<u8>,
    entry: &StreamedEntry,
) -> Result<(), Error> {
    let zip64 = streamed_needs_zip64_entry(entry);
    let extra = streamed_central_extra_field(entry);

    output.extend_from_slice(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes());
    output.extend_from_slice(
        &version_made_by(zip64, streamed_compression(entry), entry.aes.is_some()).to_le_bytes(),
    );
    output.extend_from_slice(
        &compute_version_needed(streamed_compression(entry), zip64, entry.aes.is_some())
            .to_le_bytes(),
    );
    output.extend_from_slice(&entry.flags.to_le_bytes());
    output.extend_from_slice(&entry.compression_method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    output.extend_from_slice(&entry.stored_crc32.to_le_bytes());
    if zip64 {
        output.extend_from_slice(&u32::MAX.to_le_bytes());
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
    output.extend_from_slice(
        &u16_len(entry.name_bytes.len(), "zip: file name too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&u16_len(extra.len(), "zip: extra field too large")?.to_le_bytes());
    output.extend_from_slice(
        &u16_len(entry.comment_bytes.len(), "zip: comment too long")?.to_le_bytes(),
    );
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    if zip64 {
        output.extend_from_slice(&u32::MAX.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.local_header_offset as u32).to_le_bytes());
    }
    output.extend_from_slice(&entry.name_bytes);
    output.extend_from_slice(&extra);
    output.extend_from_slice(&entry.comment_bytes);
    Ok(())
}

#[cfg(feature = "std")]
fn streamed_local_extra_field(entry: &StreamedEntry) -> Vec<u8> {
    let mut extra = Vec::new();
    if streamed_needs_zip64_entry(entry) && !entry.use_data_descriptor {
        extra.reserve(20);
        extra.extend_from_slice(&ZIP64_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&16u16.to_le_bytes());
        extra.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
        extra.extend_from_slice(&entry.compressed_size.to_le_bytes());
    }
    if let Some(aes) = entry.aes {
        append_aes_extra_field(&mut extra, aes);
    }
    extra
}

#[cfg(feature = "std")]
fn write_streamed_data_descriptor(output: &mut Vec<u8>, entry: &StreamedEntry) {
    output.extend_from_slice(&DATA_DESCRIPTOR_SIGNATURE.to_le_bytes());
    output.extend_from_slice(&entry.crc32.to_le_bytes());
    if streamed_needs_zip64_entry(entry) {
        output.extend_from_slice(&entry.compressed_size.to_le_bytes());
        output.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
    } else {
        output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
        output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    }
}

#[cfg(feature = "std")]
fn streamed_central_extra_field(entry: &StreamedEntry) -> Vec<u8> {
    let mut extra = Vec::new();
    if streamed_needs_zip64_entry(entry) {
        extra.reserve(28);
        extra.extend_from_slice(&ZIP64_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&24u16.to_le_bytes());
        extra.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
        extra.extend_from_slice(&entry.compressed_size.to_le_bytes());
        extra.extend_from_slice(&entry.local_header_offset.to_le_bytes());
    }
    if let Some(aes) = entry.aes {
        append_aes_extra_field(&mut extra, aes);
    }
    extra
}

#[cfg(feature = "std")]
fn streamed_central_directory_record_len(entry: &StreamedEntry) -> u64 {
    46 + entry.name_bytes.len() as u64
        + streamed_central_extra_field(entry).len() as u64
        + entry.comment_bytes.len() as u64
}

#[cfg(feature = "std")]
const fn streamed_needs_zip64_entry(entry: &StreamedEntry) -> bool {
    entry.force_zip64
        || entry.uncompressed_size > u32::MAX as u64
        || entry.compressed_size > u32::MAX as u64
        || entry.local_header_offset > u32::MAX as u64
}

#[cfg(feature = "std")]
fn io_invalid_data(err: Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string())
}

fn central_extra_field(entry: &EncodedEntry) -> Vec<u8> {
    let mut extra = Vec::new();
    if needs_zip64_entry(entry) {
        extra.reserve(28);
        extra.extend_from_slice(&ZIP64_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&24u16.to_le_bytes());
        extra.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
        extra.extend_from_slice(&(entry.compressed_data.len() as u64).to_le_bytes());
        extra.extend_from_slice(&entry.local_header_offset.to_le_bytes());
    }
    if let Some(aes) = entry.aes {
        append_aes_extra_field(&mut extra, aes);
    }
    append_timestamp_extra_fields(&mut extra, entry);
    extra
}

/// Append NTFS, extended timestamp, and UNIX extra fields when the entry has them set.
fn append_timestamp_extra_fields(extra: &mut Vec<u8>, entry: &EncodedEntry) {
    // NTFS extra field (0x000a)
    if entry.ntfs_mtime.is_some() || entry.ntfs_atime.is_some() || entry.ntfs_ctime.is_some() {
        let mtime = entry.ntfs_mtime.unwrap_or(0);
        let atime = entry.ntfs_atime.unwrap_or(0);
        let ctime = entry.ntfs_ctime.unwrap_or(0);
        // Header: id(2) + size(2)
        // Data: Reserved(4) + Tag(2) + TagSize(2) + Mtime(8) + Atime(8) + Ctime(8)
        let data_size: u16 = 4 + 2 + 2 + 24; // = 32
        extra.extend_from_slice(&NTFS_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&data_size.to_le_bytes());
        extra.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        extra.extend_from_slice(&0x0001u16.to_le_bytes()); // Tag = 1 (file times)
        extra.extend_from_slice(&24u16.to_le_bytes()); // Tag data size
        extra.extend_from_slice(&mtime.to_le_bytes());
        extra.extend_from_slice(&atime.to_le_bytes());
        extra.extend_from_slice(&ctime.to_le_bytes());
    }

    // Extended timestamp (0x5455)
    if entry.unix_mtime.is_some() || entry.unix_atime.is_some() {
        let mut flags: u8 = 0;
        let mut payload = Vec::new();
        if let Some(mtime) = entry.unix_mtime {
            flags |= 0x01;
            payload.extend_from_slice(&mtime.to_le_bytes());
        }
        if let Some(atime) = entry.unix_atime {
            flags |= 0x02;
            payload.extend_from_slice(&atime.to_le_bytes());
        }
        let data_size = (1 + payload.len()) as u16;
        extra.extend_from_slice(&EXTENDED_TIMESTAMP_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&data_size.to_le_bytes());
        extra.push(flags);
        extra.extend_from_slice(&payload);
    }

    // UNIX extra field (0x000d)
    if entry.unix_uid.is_some() || entry.unix_gid.is_some() {
        let uid = entry.unix_uid.unwrap_or(0);
        let gid = entry.unix_gid.unwrap_or(0);
        // Data: AcTime(4) + ModTime(4) + UID(2) + GID(2) = 12
        let data_size: u16 = 12;
        extra.extend_from_slice(&UNIX_EXTRA_FIELD_ID.to_le_bytes());
        extra.extend_from_slice(&data_size.to_le_bytes());
        extra.extend_from_slice(&entry.unix_atime.unwrap_or(0).to_le_bytes());
        extra.extend_from_slice(&entry.unix_mtime.unwrap_or(0).to_le_bytes());
        extra.extend_from_slice(&uid.to_le_bytes());
        extra.extend_from_slice(&gid.to_le_bytes());
    }

    // Unicode Path extra field (0x7075)
    if let Some(ref upath) = entry.unicode_path {
        let upath_bytes = upath.as_bytes();
        let name_crc = crate::util::crc32::crc32(&entry.name_bytes);
        let data_size = (1 + 4 + upath_bytes.len()) as u16; // version(1) + crc32(4) + path
        extra.extend_from_slice(&0x7075u16.to_le_bytes());
        extra.extend_from_slice(&data_size.to_le_bytes());
        extra.push(1); // Version
        extra.extend_from_slice(&name_crc.to_le_bytes());
        extra.extend_from_slice(upath_bytes);
    }

    // Unicode Comment extra field (0x6375)
    if let Some(ref ucomment) = entry.unicode_comment {
        let ucomment_bytes = ucomment.as_bytes();
        let comment_crc = crate::util::crc32::crc32(&entry.comment_bytes);
        let data_size = (1 + 4 + ucomment_bytes.len()) as u16;
        extra.extend_from_slice(&0x6375u16.to_le_bytes());
        extra.extend_from_slice(&data_size.to_le_bytes());
        extra.push(1); // Version
        extra.extend_from_slice(&comment_crc.to_le_bytes());
        extra.extend_from_slice(ucomment_bytes);
    }
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidData("zip: empty file name"));
    }
    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidData("zip: NUL in file name"));
    }
    if name.contains('\\') {
        return Err(Error::InvalidData("zip: backslash in file name"));
    }
    if name.starts_with('/') {
        return Err(Error::InvalidData("zip: absolute path in file name"));
    }
    // Reject drive letters like "C:" or "c:"
    if name.len() >= 2 && name.as_bytes()[0].is_ascii_alphabetic() && name.as_bytes()[1] == b':' {
        return Err(Error::InvalidData("zip: drive letter in file name"));
    }
    // Reject ../ traversal
    for component in name.split('/') {
        if component == ".." {
            return Err(Error::InvalidData("zip: path traversal in file name"));
        }
    }
    Ok(())
}

fn validate_comment(comment: &str) -> Result<(), Error> {
    if comment.as_bytes().contains(&0) {
        return Err(Error::InvalidData("zip: NUL in file comment"));
    }
    Ok(())
}

const fn needs_zip64_entry(entry: &EncodedEntry) -> bool {
    entry.force_zip64
        || entry.uncompressed_size > u32::MAX as u64
        || entry.compressed_data.len() as u64 > u32::MAX as u64
        || entry.local_header_offset > u32::MAX as u64
}

fn u16_len(len: usize, error: &'static str) -> Result<u16, Error> {
    u16::try_from(len).map_err(|_| Error::Unsupported(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::zip::decode;

    #[test]
    fn test_roundtrip_empty_archive() {
        let archive = ZipEncoder::new().finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_roundtrip_store_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("hello.txt", b"Hello ZIP");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].header.compression_method, 0);
        assert_eq!(entries[0].data, b"Hello ZIP");
    }

    #[test]
    fn test_roundtrip_deflate_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("hello.txt", b"Hello ZIP deflate");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].header.compression_method, 8);
        assert_eq!(entries[0].data, b"Hello ZIP deflate");
    }

    #[test]
    fn test_roundtrip_multiple_entries_and_comment() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("one.txt", b"one");
        encoder.add_file_with_options(
            "two.txt",
            b"two",
            &ZipEntryOptions {
                comment: "comment".into(),
                utf8: true,
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"one");
        assert_eq!(entries[1].data, b"two");
        assert_eq!(entries[1].header.comment, "comment");
    }

    #[test]
    fn test_force_zip64_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "zip64.txt",
            b"zip64 payload",
            &ZipEntryOptions {
                force_zip64: true,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        assert!(
            archive
                .windows(4)
                .any(|window| window == ZIP64_EOCD_SIGNATURE.to_le_bytes())
        );
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "zip64.txt");
        assert_eq!(entries[0].data, b"zip64 payload");
        assert_eq!(entries[0].header.uncompressed_size, 13);
    }

    #[test]
    fn test_roundtrip_data_descriptor_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "descriptor.txt",
            b"descriptor payload",
            &ZipEntryOptions {
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        assert!(
            archive
                .windows(4)
                .any(|window| window == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
        );
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "descriptor.txt");
        assert_eq!(entries[0].data, b"descriptor payload");
        assert_ne!(entries[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
    }

    #[test]
    fn test_ascii_entry_can_clear_utf8_flag() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "plain.txt",
            b"plain payload",
            &ZipEntryOptions {
                utf8: false,
                comment: "ascii".into(),
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].data, b"plain payload");
        assert_eq!(entries[0].header.flags & UTF8_FLAG, 0);
    }

    #[test]
    fn test_roundtrip_aes_encrypted_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.set_password("secret");
        encoder.add_file("secret.txt", b"top secret");
        let archive = encoder.finish().unwrap();

        assert!(
            archive
                .windows(2)
                .any(|window| window == ZIP_AES_METHOD.to_le_bytes())
        );
        assert!(matches!(
            decode::decode(&archive),
            Err(Error::Unsupported(
                "zip: encrypted entry requires a password"
            ))
        ));

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, b"top secret");
        assert_eq!(entries[0].header.compression_method, 8);
        assert_ne!(entries[0].header.flags & 1, 0);
    }

    #[test]
    fn test_roundtrip_aes_encrypted_with_data_descriptor() {
        let mut encoder = ZipEncoder::new();
        encoder.set_password("secret");
        encoder.add_file_with_options(
            "secret.txt",
            b"aes descriptor payload",
            &ZipEntryOptions {
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();

        assert!(
            archive
                .windows(4)
                .any(|window| window == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
        );

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, b"aes descriptor payload");
        assert_eq!(entries[0].header.compression_method, 8);
        assert_ne!(entries[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
        assert_ne!(entries[0].header.flags & 1, 0);
    }

    #[test]
    fn test_roundtrip_aes_wrong_password_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.set_password("secret");
        encoder.add_file_stored("secret.txt", b"payload");
        let archive = encoder.finish().unwrap();

        assert!(matches!(
            decode::decode_with_password(&archive, "wrong"),
            Err(Error::InvalidData("zip: invalid AES password"))
        ));
    }

    #[test]
    fn test_roundtrip_aes128_encrypted_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.set_password_with_aes_strength("secret", ZipAesStrength::Aes128);
        encoder.add_file("secret.txt", b"top secret");
        let archive = encoder.finish().unwrap();

        assert!(archive.windows(11).any(|window| {
            window
                == [
                    0x01, 0x99, 0x07, 0x00, 0x01, 0x00, b'A', b'E', 0x01, 0x08, 0x00,
                ]
        }));

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"top secret");
        assert_eq!(entries[0].header.compression_method, 8);
    }

    #[test]
    fn test_roundtrip_aes192_encrypted_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.set_password_with_aes_strength("secret", ZipAesStrength::Aes192);
        encoder.add_file_stored("secret.txt", b"payload");
        let archive = encoder.finish().unwrap();

        assert!(archive.windows(11).any(|window| {
            window
                == [
                    0x01, 0x99, 0x07, 0x00, 0x01, 0x00, b'A', b'E', 0x02, 0x00, 0x00,
                ]
        }));

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"payload");
        assert_eq!(entries[0].header.compression_method, 0);
    }

    #[test]
    fn test_roundtrip_traditional_encrypted_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.set_traditional_password("secret");
        encoder.add_file("secret.txt", b"top secret traditional");
        let archive = encoder.finish().unwrap();

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, b"top secret traditional");
        assert_eq!(entries[0].header.compression_method, 8);
    }

    #[test]
    fn test_roundtrip_traditional_encrypted_with_data_descriptor() {
        let mut encoder = ZipEncoder::new();
        encoder.set_traditional_password("secret");
        encoder.add_file_with_options(
            "secret.txt",
            b"traditional descriptor payload",
            &ZipEntryOptions {
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();

        assert!(
            archive
                .windows(4)
                .any(|window| window == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
        );

        let entries = decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, b"traditional descriptor payload");
        assert_eq!(entries[0].header.compression_method, 8);
        assert_ne!(entries[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
        assert_ne!(entries[0].header.flags & 1, 0);
    }

    #[test]
    fn test_roundtrip_traditional_wrong_password_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.set_traditional_password("secret");
        encoder.add_file_stored("secret.txt", b"payload");
        let archive = encoder.finish().unwrap();

        assert!(matches!(
            decode::decode_with_password(&archive, "wrong"),
            Err(Error::InvalidData("zip: invalid traditional password"))
        ));
    }

    #[test]
    fn test_cp437_entry_without_utf8_flag_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "ä.txt",
            b"payload",
            &ZipEntryOptions {
                utf8: false,
                comment: "ö comment".into(),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        assert!(archive.windows(5).any(|window| window == b"\x84.txt"));
        assert!(archive.windows(9).any(|window| window == b"\x94 comment"));
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].name, "ä.txt");
        assert_eq!(entries[0].header.comment, "ö comment");
        assert_eq!(entries[0].header.flags & UTF8_FLAG, 0);
    }

    #[test]
    fn test_add_decoded_entry_preserves_metadata() {
        let mut source = ZipEncoder::new();
        source.add_file_with_options(
            "source.txt",
            b"payload",
            &ZipEntryOptions {
                comment: "copied".into(),
                compression: ZipCompression::Store,
                mod_time: 0x1234,
                mod_date: 0x5678,
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        let source_archive = source.finish().unwrap();
        let decoded = decode::decode(&source_archive).unwrap();

        let mut target = ZipEncoder::new();
        target.add_entry(&decoded[0]);
        let target_archive = target.finish().unwrap();
        let roundtrip = decode::decode(&target_archive).unwrap();

        assert_eq!(roundtrip[0].name, "source.txt");
        assert_eq!(roundtrip[0].header.comment, "copied");
        assert_eq!(roundtrip[0].header.mod_time, 0x1234);
        assert_eq!(roundtrip[0].header.mod_date, 0x5678);
        assert_ne!(roundtrip[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
        assert_eq!(roundtrip[0].data, b"payload");
    }

    #[test]
    fn test_empty_name_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("", b"data");
        assert!(matches!(encoder.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_non_cp437_without_utf8_flag_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "こんにちは.txt",
            b"data",
            &ZipEntryOptions {
                utf8: false,
                ..ZipEntryOptions::default()
            },
        );
        assert!(matches!(encoder.finish(), Err(Error::InvalidData(_))));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_stream_writer_store_roundtrip_with_data_descriptor() {
        use std::io::Cursor;

        let mut writer = ZipStreamWriter::new(Vec::new());
        writer
            .write_file_from_reader(
                "streamed.txt",
                Cursor::new(b"streamed store payload".as_slice()),
                &ZipEntryOptions {
                    compression: ZipCompression::Store,
                    comment: "streamed".into(),
                    use_data_descriptor: false,
                    ..ZipEntryOptions::default()
                },
            )
            .unwrap();
        let archive = writer.finish().unwrap();

        assert!(
            archive
                .windows(4)
                .any(|window| window == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
        );

        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "streamed.txt");
        assert_eq!(entries[0].data, b"streamed store payload");
        assert_eq!(entries[0].header.comment, "streamed");
        assert_ne!(entries[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
        assert_eq!(entries[0].header.compression_method, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_stream_writer_deflate_and_multiple_entries_roundtrip() {
        use std::io::Cursor;

        let mut writer = ZipStreamWriter::new(Vec::new());
        writer
            .write_file_from_reader(
                "alpha.txt",
                Cursor::new(b"alpha alpha alpha alpha".as_slice()),
                &ZipEntryOptions::default(),
            )
            .unwrap();
        writer
            .write_file_from_reader(
                "beta.bin",
                Cursor::new([0x10, 0x20, 0x30, 0x40]),
                &ZipEntryOptions {
                    compression: ZipCompression::Store,
                    ..ZipEntryOptions::default()
                },
            )
            .unwrap();
        let archive = writer.finish().unwrap();

        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha.txt");
        assert_eq!(entries[0].data, b"alpha alpha alpha alpha");
        assert_eq!(entries[0].header.compression_method, 8);
        assert_ne!(entries[0].header.flags & DATA_DESCRIPTOR_FLAG, 0);
        assert_eq!(entries[1].name, "beta.bin");
        assert_eq!(entries[1].data, [0x10, 0x20, 0x30, 0x40]);
        assert_eq!(entries[1].header.compression_method, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_streamed_central_version_made_by() {
        use std::io::Cursor;

        let mut writer = ZipStreamWriter::new(Vec::new());
        writer
            .write_file_from_reader(
                "streamed.txt",
                Cursor::new(b"streamed payload".as_slice()),
                &ZipEntryOptions {
                    compression: ZipCompression::Store,
                    ..ZipEntryOptions::default()
                },
            )
            .unwrap();
        let archive = writer.finish().unwrap();

        // Streamed central directory record (APPNOTE 4.3.12):
        // version_made_by packs the host OS byte (upper half) with
        // the spec version (lower half); version_needed is the
        // minimum extract version (Store needs only the 2.0 default).
        let cd = archive
            .windows(4)
            .position(|w| w == CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes())
            .unwrap();
        let made_by = u16::from_le_bytes(archive[cd + 4..cd + 6].try_into().unwrap());
        let needed = u16::from_le_bytes(archive[cd + 6..cd + 8].try_into().unwrap());
        let host: u16 = if cfg!(unix) { 3 } else { 0 };
        assert_eq!(made_by >> 8, host);
        assert_eq!(made_by & 0x00FF, ZIP_VERSION_DEFAULT);
        assert_eq!(needed, ZIP_VERSION_DEFAULT);

        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].header.host_system, host as u8);
        assert_eq!(entries[0].header.version_needed, ZIP_VERSION_DEFAULT);
    }

    #[cfg(feature = "bzip2")]
    #[test]
    fn test_roundtrip_bzip2_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "bzip2.txt",
            b"Hello bzip2 in ZIP Hello bzip2 in ZIP",
            &ZipEntryOptions {
                compression: ZipCompression::Bzip2,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bzip2.txt");
        assert_eq!(entries[0].header.compression_method, 12);
        assert_eq!(entries[0].data, b"Hello bzip2 in ZIP Hello bzip2 in ZIP");
    }

    #[cfg(feature = "bzip2")]
    #[test]
    fn test_bzip2_version_needed_in_local_and_central() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "bzip2.txt",
            b"bzip2 version needed payload",
            &ZipEntryOptions {
                compression: ZipCompression::Bzip2,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();

        // Local file header: version_needed follows the signature
        // (APPNOTE 4.3.7). Bzip2 requires at least version 4.6 (46).
        assert_eq!(archive[0..4], LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes());
        let lfh_version = u16::from_le_bytes(archive[4..6].try_into().unwrap());
        assert_eq!(lfh_version, ZIP_VERSION_BZIP2);

        // Central directory record: version_needed sits at offset +6,
        // after the signature and version_made_by (APPNOTE 4.3.12).
        let cd = archive
            .windows(4)
            .position(|w| w == CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes())
            .unwrap();
        let cd_version = u16::from_le_bytes(archive[cd + 6..cd + 8].try_into().unwrap());
        assert_eq!(cd_version, ZIP_VERSION_BZIP2);

        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].header.version_needed, ZIP_VERSION_BZIP2);
        assert_eq!(entries[0].header.compression_method, 12);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn test_roundtrip_zstd_single_file() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "zstd.txt",
            b"Hello zstd in ZIP Hello zstd in ZIP",
            &ZipEntryOptions {
                compression: ZipCompression::Zstd,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "zstd.txt");
        assert_eq!(entries[0].header.compression_method, 93);
        assert_eq!(entries[0].data, b"Hello zstd in ZIP Hello zstd in ZIP");
    }

    #[test]
    fn test_attributes_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "attrs.txt",
            b"attributes",
            &ZipEntryOptions {
                internal_attributes: 0x0001,
                external_attributes: 0o100644 << 16,
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.internal_attributes, 0x0001);
        assert_eq!(entries[0].header.external_attributes, 0o100644 << 16);
    }

    #[test]
    fn test_ntfs_timestamp_roundtrip() {
        let mtime: u64 = 132_500_000_000_000_000;
        let atime: u64 = 132_500_000_100_000_000;
        let ctime: u64 = 132_500_000_200_000_000;
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "timestamps.txt",
            b"time",
            &ZipEntryOptions {
                ntfs_mtime: Some(mtime),
                ntfs_atime: Some(atime),
                ntfs_ctime: Some(ctime),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.ntfs_mtime, Some(mtime));
        assert_eq!(entries[0].header.ntfs_atime, Some(atime));
        assert_eq!(entries[0].header.ntfs_ctime, Some(ctime));
    }

    #[test]
    fn test_path_validation_backslash_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("foo\\bar.txt", b"data");
        assert!(matches!(
            encoder.finish(),
            Err(Error::InvalidData("zip: backslash in file name"))
        ));
    }

    #[test]
    fn test_path_validation_drive_letter_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("C:file.txt", b"data");
        assert!(matches!(
            encoder.finish(),
            Err(Error::InvalidData("zip: drive letter in file name"))
        ));
    }

    #[test]
    fn test_path_validation_leading_slash_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("/absolute.txt", b"data");
        assert!(matches!(
            encoder.finish(),
            Err(Error::InvalidData("zip: absolute path in file name"))
        ));
    }

    #[test]
    fn test_path_validation_traversal_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("../escape.txt", b"data");
        assert!(matches!(
            encoder.finish(),
            Err(Error::InvalidData("zip: path traversal in file name"))
        ));
    }

    #[test]
    fn test_path_validation_nested_traversal_rejected() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("foo/../../../etc/passwd", b"data");
        assert!(matches!(
            encoder.finish(),
            Err(Error::InvalidData("zip: path traversal in file name"))
        ));
    }

    #[test]
    fn test_archive_comment_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.set_archive_comment("archive level comment");
        encoder.add_file_stored("file.txt", b"payload");
        let archive = encoder.finish().unwrap();
        // Verify the comment is in the binary
        assert!(
            archive
                .windows(b"archive level comment".len())
                .any(|w| w == b"archive level comment")
        );
        // Verify we can still decode the archive
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_unix_timestamp_roundtrip() {
        let mtime: u32 = 1_700_000_000;
        let atime: u32 = 1_700_000_100;
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "unix_ts.txt",
            b"unix",
            &ZipEntryOptions {
                unix_mtime: Some(mtime),
                unix_atime: Some(atime),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].header.unix_mtime, Some(mtime));
        assert_eq!(entries[0].header.unix_atime, Some(atime));
    }

    #[test]
    fn test_unix_uid_gid_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "unix_ids.txt",
            b"ids",
            &ZipEntryOptions {
                unix_uid: Some(1000),
                unix_gid: Some(100),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].header.unix_uid, Some(1000));
        assert_eq!(entries[0].header.unix_gid, Some(100));
    }

    #[test]
    fn test_unicode_comment_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "unicode_comment.txt",
            b"comment",
            &ZipEntryOptions {
                unicode_comment: Some("コメント".into()),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(
            entries[0].header.unicode_comment.as_deref(),
            Some("コメント")
        );
    }

    #[test]
    fn test_unix_extra_field_times() {
        // 0x000d carries real atime/mtime (not placeholders) when set.
        let mtime: u32 = 1_700_000_000;
        let atime: u32 = 1_700_000_100;
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "unix_times.txt",
            b"times",
            &ZipEntryOptions {
                unix_mtime: Some(mtime),
                unix_atime: Some(atime),
                unix_uid: Some(1),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        // Locate the 0x000d extra field and check its payload.
        let needle = 0x000du16.to_le_bytes();
        let pos = archive
            .windows(2)
            .position(|w| w == needle)
            .expect("0x000d extra field");
        assert_eq!(
            u32::from_le_bytes(archive[pos + 4..pos + 8].try_into().unwrap()),
            atime
        );
        assert_eq!(
            u32::from_le_bytes(archive[pos + 8..pos + 12].try_into().unwrap()),
            mtime
        );
        assert_eq!(
            u16::from_le_bytes(archive[pos + 12..pos + 14].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn test_reencode_preserves_extra_fields() {
        // decode -> ZipEntryOptions::from(&ZipHeader) -> encode keeps every
        // recognised extra field.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "meta.txt",
            b"meta",
            &ZipEntryOptions {
                ntfs_mtime: Some(132_500_000_000_000_000),
                ntfs_atime: Some(132_500_000_100_000_000),
                ntfs_ctime: Some(132_500_000_200_000_000),
                unix_mtime: Some(1_700_000_000),
                unix_atime: Some(1_700_000_100),
                unix_uid: Some(1000),
                unix_gid: Some(100),
                unicode_path: Some("unicode/パス.txt".into()),
                unicode_comment: Some("コメント".into()),
                compression: ZipCompression::Store,
                ..ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let first = decode::decode(&archive).unwrap();
        let header = &first[0].header;

        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            &first[0].name,
            &first[0].data,
            &ZipEntryOptions::from(header),
        );
        let second = decode::decode(&encoder.finish().unwrap()).unwrap();
        let h = &second[0].header;
        assert_eq!(h.ntfs_mtime, header.ntfs_mtime);
        assert_eq!(h.ntfs_atime, header.ntfs_atime);
        assert_eq!(h.ntfs_ctime, header.ntfs_ctime);
        assert_eq!(h.unix_mtime, header.unix_mtime);
        assert_eq!(h.unix_atime, header.unix_atime);
        assert_eq!(h.unix_uid, header.unix_uid);
        assert_eq!(h.unix_gid, header.unix_gid);
        assert_eq!(h.unicode_path, header.unicode_path);
        assert_eq!(h.unicode_comment, header.unicode_comment);
    }

    // --- Split/spanned (multi-disk) emit via `finish_parts` (APPNOTE 8) ---

    /// Parse the concatenated stream and return the atomic record
    /// ranges ([start, end)) that must not straddle a segment boundary.
    fn collect_record_ranges(stream: &[u8]) -> Vec<(usize, usize)> {
        let mut atomics = Vec::new();
        let mut pos = 0usize;
        // Local file headers until the central directory.
        while stream[pos..pos + 4] == LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes() {
            let flags = u16::from_le_bytes(stream[pos + 6..pos + 8].try_into().unwrap());
            let name_len =
                u16::from_le_bytes(stream[pos + 26..pos + 28].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(stream[pos + 28..pos + 30].try_into().unwrap()) as usize;
            atomics.push((pos, pos + 30 + name_len + extra_len));
            let data_start = pos + 30 + name_len + extra_len;
            if flags & DATA_DESCRIPTOR_FLAG != 0 {
                // Sizes are not in the local header; scan forward for the
                // data descriptor signature emitted by our writer (test
                // payloads never contain it).
                let dd = stream[data_start..]
                    .windows(4)
                    .position(|w| w == DATA_DESCRIPTOR_SIGNATURE.to_le_bytes())
                    .map(|i| data_start + i)
                    .unwrap();
                atomics.push((dd, dd + 16));
                pos = dd + 16;
            } else {
                let csize =
                    u32::from_le_bytes(stream[pos + 18..pos + 22].try_into().unwrap()) as usize;
                pos = data_start + csize;
            }
        }
        // Central directory records.
        while stream[pos..pos + 4] == CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes() {
            let name_len =
                u16::from_le_bytes(stream[pos + 28..pos + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(stream[pos + 30..pos + 32].try_into().unwrap()) as usize;
            let comment_len =
                u16::from_le_bytes(stream[pos + 32..pos + 34].try_into().unwrap()) as usize;
            let end = pos + 46 + name_len + extra_len + comment_len;
            atomics.push((pos, end));
            pos = end;
        }
        // Tail block (ZIP64 EOCD + locator + EOCD) is atomic.
        atomics.push((pos, stream.len()));
        atomics
    }

    #[test]
    fn test_finish_parts_roundtrip() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file("a.txt", b"aaaa");
        encoder.add_file_stored("dir/b.bin", &[0x55; 300]);
        encoder.add_file_with_options(
            "c.txt",
            b"cccc",
            &ZipEntryOptions {
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        let parts = encoder.finish_parts(160).unwrap();
        assert!(parts.len() > 1);
        assert!(
            parts
                .iter()
                .all(|part| !part.is_empty() && part.len() <= 160)
        );

        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let entries = decode::decode_parts(&slices).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].data, b"aaaa");
        assert_eq!(entries[1].name, "dir/b.bin");
        assert_eq!(entries[1].data, vec![0x55; 300]);
        assert_eq!(entries[2].name, "c.txt");
        assert_eq!(entries[2].data, b"cccc");
    }

    #[test]
    fn test_finish_parts_roundtrip_zip64() {
        // ZIP64 tail (EOCD record + locator + EOCD) stays atomic on the
        // last disk.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_with_options(
            "a.txt",
            b"zip64 payload",
            &ZipEntryOptions {
                force_zip64: true,
                ..ZipEntryOptions::default()
            },
        );
        encoder.add_file_stored("b.bin", &[0x33; 200]);
        let parts = encoder.finish_parts(120).unwrap();
        assert!(parts.len() > 1);
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let entries = decode::decode_parts(&slices).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"zip64 payload");
        assert_eq!(entries[1].data, vec![0x33; 200]);
    }

    #[test]
    fn test_finish_parts_records_not_split() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("a.txt", &[0x41; 100]);
        encoder.add_file_with_options(
            "b.txt",
            &[0x42; 50],
            &ZipEntryOptions {
                use_data_descriptor: true,
                ..ZipEntryOptions::default()
            },
        );
        encoder.add_file_stored("c.txt", &[0x43; 80]);
        let parts = encoder.finish_parts(120).unwrap();
        assert!(parts.len() > 1);

        let stream: Vec<u8> = parts.concat();
        let atomics = collect_record_ranges(&stream);
        let mut boundary = 0usize;
        for part in &parts[..parts.len() - 1] {
            boundary += part.len();
            // The boundary may fall inside a splittable data range but
            // must never land strictly inside an atomic record.
            for &(start, end) in &atomics {
                assert!(
                    !(start < boundary && boundary < end),
                    "segment boundary {boundary} splits atomic record {start}..{end}"
                );
            }
        }
    }

    #[test]
    fn test_finish_parts_disk_fields() {
        // Two stored entries; a 150-byte segment cap puts the local
        // header of b.txt at the start of disk 1.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("a.txt", &[0x41; 100]);
        encoder.add_file_stored("b.txt", &[0x42; 100]);
        let parts = encoder.finish_parts(150).unwrap();
        assert!(parts.len() > 1);

        let stream: Vec<u8> = parts.concat();
        // Segment start offsets in the concatenated stream.
        let mut starts = Vec::with_capacity(parts.len());
        let mut off = 0usize;
        for part in &parts {
            starts.push(off);
            off += part.len();
        }

        // EOCD disk fields.
        let eocd = stream
            .windows(4)
            .rposition(|w| w == EOCD_SIGNATURE.to_le_bytes())
            .unwrap();
        let this_disk = u16::from_le_bytes(stream[eocd + 4..eocd + 6].try_into().unwrap()) as usize;
        let cd_disk = u16::from_le_bytes(stream[eocd + 6..eocd + 8].try_into().unwrap()) as usize;
        let disk_entries =
            u16::from_le_bytes(stream[eocd + 8..eocd + 10].try_into().unwrap()) as usize;
        let total = u16::from_le_bytes(stream[eocd + 10..eocd + 12].try_into().unwrap());
        let cd_offset =
            u32::from_le_bytes(stream[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        assert_eq!(this_disk, parts.len() - 1);
        assert_eq!(total, 2);
        let cd_abs = starts[cd_disk] + cd_offset;
        assert_eq!(
            stream[cd_abs..cd_abs + 4],
            CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes()
        );

        // Each central directory record: disk number start (+34) and the
        // local header offset (+42) are disk-relative.
        let mut cd_pos = cd_abs;
        let mut count_on_last = 0usize;
        for _ in 0..2 {
            let disk_start =
                u16::from_le_bytes(stream[cd_pos + 34..cd_pos + 36].try_into().unwrap()) as usize;
            let lh_off =
                u32::from_le_bytes(stream[cd_pos + 42..cd_pos + 46].try_into().unwrap()) as usize;
            let lh_abs = starts[disk_start] + lh_off;
            assert_eq!(
                stream[lh_abs..lh_abs + 4],
                LOCAL_FILE_HEADER_SIGNATURE.to_le_bytes()
            );
            // EOCD disk-entries counts CD records residing on the last disk.
            if cd_pos >= starts[this_disk] {
                count_on_last += 1;
            }
            let name_len =
                u16::from_le_bytes(stream[cd_pos + 28..cd_pos + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(stream[cd_pos + 30..cd_pos + 32].try_into().unwrap()) as usize;
            let com_len =
                u16::from_le_bytes(stream[cd_pos + 32..cd_pos + 34].try_into().unwrap()) as usize;
            cd_pos += 46 + name_len + extra_len + com_len;
        }
        assert_eq!(disk_entries, count_on_last);
    }

    #[test]
    fn test_finish_parts_cd_on_last_segment() {
        let a_payload = vec![0x41u8; 400];
        let b_payload = b"deflated payload deflated payload".to_vec();
        let build = || {
            let mut encoder = ZipEncoder::new();
            encoder.add_file_stored("a.bin", &a_payload);
            encoder.add_file("b.txt", &b_payload);
            encoder
        };

        // Default: the greedy plan leaves the EOCD tail alone on the
        // last segment (cd_disk < this_disk).
        let parts = build().finish_parts(300).unwrap();
        assert!(parts.len() > 1);
        assert!(
            parts
                .last()
                .unwrap()
                .starts_with(&EOCD_SIGNATURE.to_le_bytes())
        );

        // Compat: the whole central directory and tail move to the last
        // segment so that cd_disk == this_disk.
        let parts = build()
            .finish_parts_with(
                300,
                &ZipSplitOptions {
                    central_directory_on_last_segment: true,
                },
            )
            .unwrap();
        assert!(parts.len() > 1);
        let last = parts.last().unwrap();
        assert!(last.starts_with(&CENTRAL_DIRECTORY_HEADER_SIGNATURE.to_le_bytes()));
        let eocd = last.len() - 22;
        let this_disk = u16::from_le_bytes(last[eocd + 4..eocd + 6].try_into().unwrap()) as usize;
        let cd_disk = u16::from_le_bytes(last[eocd + 6..eocd + 8].try_into().unwrap()) as usize;
        let disk_entries = u16::from_le_bytes(last[eocd + 8..eocd + 10].try_into().unwrap());
        assert_eq!(this_disk, parts.len() - 1);
        assert_eq!(cd_disk, this_disk);
        assert_eq!(disk_entries, 2);

        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let entries = decode::decode_parts(&slices).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.bin");
        assert_eq!(entries[0].data, a_payload);
        assert_eq!(entries[1].name, "b.txt");
        assert_eq!(entries[1].data, b_payload);
    }

    #[test]
    fn test_finish_parts_cd_on_last_segment_too_small() {
        // The whole CD + tail cannot fit in one segment: rejected rather
        // than silently emitting an incompatible layout.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("a.txt", b"data");
        assert!(matches!(
            encoder.finish_parts_with(
                40,
                &ZipSplitOptions {
                    central_directory_on_last_segment: true,
                },
            ),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn test_finish_parts_single_segment() {
        // A generous segment size produces one segment identical to
        // finish(): all disk fields stay zero.
        let mut encoder = ZipEncoder::new();
        encoder.add_file("a.txt", b"aaaa");
        encoder.add_file_stored("b.bin", &[0x77; 500]);
        let single = encoder.finish().unwrap();

        let mut encoder = ZipEncoder::new();
        encoder.add_file("a.txt", b"aaaa");
        encoder.add_file_stored("b.bin", &[0x77; 500]);
        let parts = encoder.finish_parts(1_048_576).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], single);
    }

    #[test]
    fn test_finish_parts_data_spans_disks() {
        // A stored entry larger than the segment cap is cut mid-data.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("big.bin", &[0x5A; 400]);
        let parts = encoder.finish_parts(120).unwrap();
        assert!(parts.len() >= 4);
        // The first boundary lands strictly inside the compressed data
        // (head = 30-byte local header + 7-byte name).
        let head_len = 30 + "big.bin".len();
        assert!(parts[0].len() > head_len);
        assert!(parts[0].len() < head_len + 400);

        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let entries = decode::decode_parts(&slices).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, vec![0x5A; 400]);
    }

    #[test]
    fn test_finish_parts_too_small() {
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("a.txt", b"data");
        assert!(matches!(
            encoder.finish_parts(0),
            Err(Error::InvalidData(_))
        ));
        // A local file header (30 + 5 bytes) cannot fit in 10 bytes.
        let mut encoder = ZipEncoder::new();
        encoder.add_file_stored("a.txt", b"data");
        assert!(matches!(
            encoder.finish_parts(10),
            Err(Error::InvalidData(_))
        ));
    }
}
