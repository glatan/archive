//! tar archive encoding (UStar format with GNU or PAX extension headers).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

use super::header::{BLOCK_SIZE, FileType};

/// Extension format for handling metadata that exceeds UStar limits.
///
/// [`TarFormat::Gnu`] uses GNU-specific extension headers (LongName/LongLink)
/// and binary size encoding. [`TarFormat::Pax`] uses POSIX.1-2001 PAX extended
/// headers, which can represent long paths, nanosecond timestamps, large
/// uid/gid values, and the metadata keys currently emitted by this encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarFormat {
    /// GNU extensions (LongName/LongLink headers, binary size encoding).
    Gnu,
    /// POSIX.1-2001 PAX extended headers.
    Pax,
}

/// Builder for creating tar archives.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode, decode};
///
/// let mut enc = encode::TarEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// enc.add_directory("subdir/", 0o755);
/// let tar = enc.finish();
/// let entries = decode::decode(&tar).unwrap();
/// assert_eq!(entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct TarEncoder {
    data: Vec<u8>,
    format: TarFormat,
}

/// Metadata for a tar entry to be written.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode::TarEntryOptions, header::FileType};
///
/// let opts = TarEntryOptions {
///     name: "link.txt".into(),
///     file_type: FileType::SymLink,
///     link_name: "target.txt".into(),
///     ..Default::default()
/// };
/// ```
#[derive(Clone)]
pub struct TarEntryOptions {
    /// File path within the archive.
    pub name: String,
    /// File mode / permissions (e.g. `0o644`).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Modification time as Unix timestamp.
    ///
    /// In PAX mode this may be negative for pre-1970 timestamps.
    pub mtime: i64,
    /// Entry type (regular file, directory, symlink, etc.).
    pub file_type: FileType,
    /// Link target path (for hard links and symlinks).
    pub link_name: String,
    /// Owner user name.
    ///
    /// Values longer than 32 bytes are preserved via a PAX `uname` attribute
    /// when the encoder is in [`TarFormat::Pax`] mode.
    pub uname: String,
    /// Owner group name.
    ///
    /// Values longer than 32 bytes are preserved via a PAX `gname` attribute
    /// when the encoder is in [`TarFormat::Pax`] mode.
    pub gname: String,
    /// Device major number (for character/block devices).
    pub devmajor: u32,
    /// Device minor number (for character/block devices).
    pub devminor: u32,
    /// Modification time nanosecond fraction (0–999_999_999).
    ///
    /// Emitted as a PAX `mtime` attribute when non-zero and the encoder
    /// is in [`TarFormat::Pax`] mode.
    pub mtime_nsec: u32,
    /// Access time as Unix timestamp (seconds).
    ///
    /// Emitted as a PAX `atime` attribute when non-zero.
    pub atime: i64,
    /// Access time nanosecond fraction (0–999_999_999).
    pub atime_nsec: u32,
    /// Status-change time as Unix timestamp (seconds).
    ///
    /// Emitted as a PAX `ctime` attribute when non-zero.
    pub ctime: i64,
    /// Status-change time nanosecond fraction (0–999_999_999).
    pub ctime_nsec: u32,
    /// PAX `charset` keyword value.
    ///
    /// Emitted as a PAX `charset` attribute when `Some` and the encoder
    /// is in [`TarFormat::Pax`] mode.
    pub pax_charset: Option<String>,
    /// PAX `comment` keyword value.
    ///
    /// Emitted as a PAX `comment` attribute when `Some` and the encoder
    /// is in [`TarFormat::Pax`] mode.
    pub pax_comment: Option<String>,
    /// PAX `hdrcharset` keyword value.
    ///
    /// Emitted as a PAX `hdrcharset` attribute when `Some` and the encoder
    /// is in [`TarFormat::Pax`] mode.
    pub pax_hdrcharset: Option<String>,
}

impl Default for TarEntryOptions {
    fn default() -> Self {
        Self {
            name: String::new(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            file_type: FileType::Regular,
            link_name: String::new(),
            uname: String::new(),
            gname: String::new(),
            devmajor: 0,
            devminor: 0,
            mtime_nsec: 0,
            atime: 0,
            atime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            pax_charset: None,
            pax_comment: None,
            pax_hdrcharset: None,
        }
    }
}

impl Default for TarEncoder {
    /// Returns a GNU-format encoder (same as [`TarEncoder::new`]).
    fn default() -> Self {
        Self::new()
    }
}

impl TarEncoder {
    /// Create a new empty tar archive builder.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::encode::TarEncoder;
    /// let enc = TarEncoder::new();
    /// let tar = enc.finish();
    /// assert!(!tar.is_empty()); // contains EOF blocks
    /// ```
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            format: TarFormat::Gnu,
        }
    }

    /// Create a new tar archive builder using PAX extended headers.
    ///
    /// In PAX mode, long filenames and link names are stored as PAX `path`
    /// and `linkpath` attributes instead of GNU LongName/LongLink headers.
    /// Nanosecond and negative timestamps (`mtime_nsec`, `atime`, `ctime`) in
    /// [`TarEntryOptions`] are emitted as PAX time attributes.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::{encode::TarEncoder, decode};
    ///
    /// let mut enc = TarEncoder::new_pax();
    /// enc.add_file("hello.txt", b"Hello!");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.name, "hello.txt");
    /// ```
    pub const fn new_pax() -> Self {
        Self {
            data: Vec::new(),
            format: TarFormat::Pax,
        }
    }

    /// Return the extension format this encoder uses.
    pub const fn format(&self) -> TarFormat {
        self.format
    }

    /// Add a regular file entry.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::{encode, decode};
    /// let mut enc = encode::TarEncoder::new();
    /// enc.add_file("hello.txt", b"Hello!");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].data, b"Hello!");
    /// ```
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_options(
            data,
            &TarEntryOptions {
                name: String::from(name),
                ..Default::default()
            },
        );
    }

    /// Add a sparse regular file using GNU PAX sparse v0.1 metadata.
    ///
    /// `data` must contain the concatenated non-hole segments described by
    /// `sparse_map`, and `real_size` is the logical file size after holes are
    /// expanded.
    pub fn add_sparse_file(
        &mut self,
        name: &str,
        data: &[u8],
        sparse_map: &[(u64, u64)],
        real_size: u64,
    ) -> Result<(), Error> {
        self.add_sparse_file_with_options(
            data,
            &TarEntryOptions {
                name: String::from(name),
                ..Default::default()
            },
            sparse_map,
            real_size,
        )
    }

    /// Add a directory entry.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::{encode, decode};
    /// let mut enc = encode::TarEncoder::new();
    /// enc.add_directory("mydir/", 0o755);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.name, "mydir/");
    /// ```
    pub fn add_directory(&mut self, name: &str, mode: u32) {
        self.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: String::from(name),
                mode,
                file_type: FileType::Directory,
                ..Default::default()
            },
        );
    }

    /// Add an entry with full options.
    ///
    /// Long filenames (> 100 bytes) are automatically handled via UStar prefix
    /// splitting or GNU long name extension headers.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::{encode::{TarEncoder, TarEntryOptions}, decode, header::FileType};
    /// let mut enc = TarEncoder::new();
    /// enc.add_file_with_options(b"target", &TarEntryOptions {
    ///     name: "link".into(),
    ///     file_type: FileType::SymLink,
    ///     link_name: "target".into(),
    ///     ..Default::default()
    /// });
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.link_name, "target");
    /// ```
    pub fn add_file_with_options(&mut self, data: &[u8], opts: &TarEntryOptions) {
        // Extension entries (GNU LongName/LongLink, PAX headers) are written
        // verbatim — they must not themselves trigger further extensions.
        let is_extension = matches!(
            opts.file_type,
            FileType::GnuLongName
                | FileType::GnuLongLink
                | FileType::PaxHeader
                | FileType::PaxGlobalHeader
        );

        let mut ustar_prefix = String::new();
        let mut header_name = opts.name.clone();
        let mut header_link = opts.link_name.clone();
        let mut header_uname = truncate_to(&opts.uname, 32);
        let mut header_gname = truncate_to(&opts.gname, 32);

        if !is_extension {
            match self.format {
                TarFormat::Gnu => {
                    // B-3: Try UStar prefix split for long names (101-255 bytes).
                    let mut needs_gnu_longname = false;
                    if opts.name.len() > 100 {
                        if let Some((prefix, name)) = try_ustar_split(&opts.name) {
                            ustar_prefix = String::from(prefix);
                            header_name = String::from(name);
                        } else {
                            needs_gnu_longname = true;
                        }
                    }
                    if needs_gnu_longname {
                        let mut name_bytes = Vec::from(opts.name.as_bytes());
                        name_bytes.push(0);
                        self.add_file_with_options(
                            &name_bytes,
                            &TarEntryOptions {
                                name: String::from("././@LongLink"),
                                file_type: FileType::GnuLongName,
                                ..Default::default()
                            },
                        );
                    }
                    if opts.link_name.len() > 100 {
                        let mut link_bytes = Vec::from(opts.link_name.as_bytes());
                        link_bytes.push(0);
                        self.add_file_with_options(
                            &link_bytes,
                            &TarEntryOptions {
                                name: String::from("././@LongLink"),
                                file_type: FileType::GnuLongLink,
                                ..Default::default()
                            },
                        );
                    }
                }
                TarFormat::Pax => {
                    let pax_data = build_pax_data(opts, data.len(), true);
                    if !pax_data.is_empty() {
                        let pax_name = pax_header_name(&opts.name);
                        self.add_file_with_options(
                            &pax_data,
                            &TarEntryOptions {
                                name: pax_name,
                                file_type: FileType::PaxHeader,
                                ..Default::default()
                            },
                        );
                    }
                    // Truncate base header values for backward compatibility;
                    // PAX-aware readers use the extended attributes instead.
                    if opts.name.len() > 100 {
                        header_name = truncate_to(&opts.name, 100);
                    }
                    if opts.link_name.len() > 100 {
                        header_link = truncate_to(&opts.link_name, 100);
                    }
                    if opts.uname.len() > 32 {
                        header_uname = truncate_to(&opts.uname, 32);
                    }
                    if opts.gname.len() > 32 {
                        header_gname = truncate_to(&opts.gname, 32);
                    }
                }
            }
        }

        let mut header = [0u8; BLOCK_SIZE];

        // Name (100 bytes)
        write_string(&mut header[0..100], &header_name);
        // Mode (8 bytes, octal)
        write_octal(&mut header[100..108], opts.mode as u64, 7);
        // UID (8 bytes)
        write_octal(&mut header[108..116], opts.uid as u64, 7);
        // GID (8 bytes)
        write_octal(&mut header[116..124], opts.gid as u64, 7);
        // Size (12 bytes)
        // Regular files, GNU extensions, and PAX headers carry data.
        // Symlinks, hardlinks, directories, etc. have size 0.
        let size = match opts.file_type {
            FileType::Regular
            | FileType::GnuSparse
            | FileType::GnuLongName
            | FileType::GnuLongLink
            | FileType::PaxHeader
            | FileType::PaxGlobalHeader => data.len() as u64,
            _ => 0,
        };
        // B-5: Use binary encoding for sizes >= 8GB (0x200000000)
        write_size(&mut header[124..136], size);
        // Mtime (12 bytes). Negative values are represented via PAX only.
        write_octal(&mut header[136..148], opts.mtime.max(0) as u64, 11);
        // Checksum placeholder - spaces (8 bytes)
        header[148..156].copy_from_slice(b"        ");
        // Type flag (1 byte)
        header[156] = match opts.file_type {
            FileType::Regular => b'0',
            FileType::HardLink => b'1',
            FileType::SymLink => b'2',
            FileType::CharDevice => b'3',
            FileType::BlockDevice => b'4',
            FileType::Directory => b'5',
            FileType::Fifo => b'6',
            FileType::Contiguous => b'7',
            FileType::PaxHeader => b'x',
            FileType::PaxGlobalHeader => b'g',
            FileType::GnuLongName => b'L',
            FileType::GnuLongLink => b'K',
            FileType::GnuSparse => b'S',
            FileType::Other(b) => b,
        };
        // Link name (100 bytes)
        write_string(&mut header[157..257], &header_link);
        // UStar magic + version
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // B-4: uname (32 bytes at offset 265) and gname (32 bytes at offset 297)
        write_string(&mut header[265..297], &header_uname);
        write_string(&mut header[297..329], &header_gname);
        // devmajor (8 bytes at offset 329) and devminor (8 bytes at offset 337)
        write_octal(&mut header[329..337], opts.devmajor as u64, 7);
        write_octal(&mut header[337..345], opts.devminor as u64, 7);
        // B-3: UStar prefix field (155 bytes at offset 345)
        if !ustar_prefix.is_empty() {
            write_string(&mut header[345..500], &ustar_prefix);
        }

        // Compute checksum
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write_octal(&mut header[148..155], checksum as u64, 6);
        header[155] = b' ';

        self.data.extend_from_slice(&header);

        // Write data blocks
        if size > 0 {
            self.data.extend_from_slice(data);
            // Pad to 512-byte boundary
            let remainder = data.len() % BLOCK_SIZE;
            if remainder != 0 {
                let padding = BLOCK_SIZE - remainder;
                self.data.resize(self.data.len() + padding, 0);
            }
        }
    }

    /// Add a sparse regular file with full metadata control.
    pub fn add_sparse_file_with_options(
        &mut self,
        data: &[u8],
        opts: &TarEntryOptions,
        sparse_map: &[(u64, u64)],
        real_size: u64,
    ) -> Result<(), Error> {
        if self.format != TarFormat::Pax {
            return Err(Error::Unsupported("tar: sparse files require PAX format"));
        }
        if opts.file_type != FileType::Regular {
            return Err(Error::Unsupported(
                "tar: sparse encoding only supports regular files",
            ));
        }
        validate_sparse_layout(data, sparse_map, real_size)?;

        let mut pax_data = build_pax_data(opts, data.len(), false);
        pax_data.extend_from_slice(&build_sparse_pax_data(&opts.name, sparse_map, real_size));
        let pax_name = pax_header_name(&opts.name);
        self.add_file_with_options(
            &pax_data,
            &TarEntryOptions {
                name: pax_name,
                file_type: FileType::PaxHeader,
                ..Default::default()
            },
        );

        let mut sparse_opts = opts.clone();
        sparse_opts.name = sparse_placeholder_name(&opts.name);
        self.add_file_with_options(data, &sparse_opts);
        Ok(())
    }

    /// Finalize the archive by writing two 512-byte zero blocks (EOF marker)
    /// and return the complete tar data.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::encode::TarEncoder;
    /// let mut enc = TarEncoder::new();
    /// enc.add_file("a.txt", b"data");
    /// let tar = enc.finish();
    /// assert!(tar.len() > 512); // at least one header block + EOF
    /// ```
    pub fn finish(mut self) -> Vec<u8> {
        // Two 512-byte zero blocks mark end of archive
        self.data.resize(self.data.len() + BLOCK_SIZE * 2, 0);
        self.data
    }

    /// Finalize the archive and write it to a writer.
    ///
    /// Returns the number of bytes written.
    ///
    /// This method does not panic.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the underlying writer fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::encode::TarEncoder;
    ///
    /// let mut enc = TarEncoder::new();
    /// enc.add_file("a.txt", b"content");
    /// let mut buf = Vec::new();
    /// let len = enc.finish_to(&mut buf).unwrap();
    /// assert_eq!(buf.len(), len);
    /// ```
    #[cfg(feature = "std")]
    pub fn finish_to<W: std::io::Write>(self, mut writer: W) -> std::io::Result<usize> {
        let data = self.finish();
        writer.write_all(&data)?;
        Ok(data.len())
    }
}

/// Write a string into a fixed-width header field, truncating if necessary.
pub(crate) fn write_string(field: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(field.len());
    field[..len].copy_from_slice(&bytes[..len]);
}

/// Write a value as zero-padded octal ASCII into a fixed-width header field.
pub(crate) fn write_octal(field: &mut [u8], value: u64, width: usize) {
    let s = alloc::format!("{value:0>width$o}");
    let bytes = s.as_bytes();
    let len = bytes.len().min(field.len());
    field[..len].copy_from_slice(&bytes[..len]);
}

/// B-5: Write a size value to the 12-byte size field.
/// For values < 0x200000000 (8GB), use standard octal encoding.
/// For values >= 8GB, use GNU binary encoding (high bit set, big-endian).
pub(crate) fn write_size(field: &mut [u8], value: u64) {
    const MAX_OCTAL_SIZE: u64 = 0x1_FFFF_FFFF; // max value fitting in 11 octal digits
    if value <= MAX_OCTAL_SIZE {
        write_octal(field, value, 11);
    } else {
        // GNU binary encoding: first byte has high bit set, remaining 11 bytes
        // are big-endian value. A u64 fits in 8 bytes, so bytes 1..4 are zero.
        field[0] = 0x80;
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;
        // Store value in bytes 4..12 as big-endian (8 bytes for u64)
        for i in 0..8 {
            field[11 - i] = (value >> (i * 8)) as u8;
        }
    }
}

/// Try to split a path into UStar prefix (<=155 bytes) and name (<=100 bytes) at a '/' boundary.
///
/// Returns `Some((prefix, name))` if a valid split exists, `None` otherwise.
/// Tries each `/` from right to left to find the rightmost valid split point.
fn try_ustar_split(path: &str) -> Option<(&str, &str)> {
    // Try each '/' from right to left to find a valid split
    for (i, _) in path.rmatch_indices('/') {
        let prefix = &path[..i];
        let name = &path[i + 1..];
        if !name.is_empty() && name.len() <= 100 && prefix.len() <= 155 {
            return Some((prefix, name));
        }
    }
    None
}

/// Build the PAX extended header data for an entry.
///
/// Returns an empty `Vec` when no PAX attributes are needed (i.e. everything
/// fits within the base UStar header fields).
fn build_pax_data(opts: &TarEntryOptions, data_len: usize, include_path: bool) -> Vec<u8> {
    let mut pax = Vec::new();

    // Path — only when it cannot fit in the 100-byte UStar name field.
    if include_path && opts.name.len() > 100 {
        pax.extend_from_slice(&format_pax_record("path", &opts.name));
    }

    // Link path
    if opts.link_name.len() > 100 {
        pax.extend_from_slice(&format_pax_record("linkpath", &opts.link_name));
    }

    // mtime with nanosecond precision
    if opts.mtime < 0 || opts.mtime_nsec > 0 {
        pax.extend_from_slice(&format_pax_record(
            "mtime",
            &format_pax_time(opts.mtime, opts.mtime_nsec),
        ));
    }

    // atime
    if opts.atime != 0 || opts.atime_nsec > 0 {
        pax.extend_from_slice(&format_pax_record(
            "atime",
            &format_pax_time(opts.atime, opts.atime_nsec),
        ));
    }

    // ctime
    if opts.ctime != 0 || opts.ctime_nsec > 0 {
        pax.extend_from_slice(&format_pax_record(
            "ctime",
            &format_pax_time(opts.ctime, opts.ctime_nsec),
        ));
    }

    // uid/gid — only when they overflow 7 octal digits (max 2_097_151).
    const MAX_OCTAL_ID: u32 = 0o7_777_777;
    const MAX_OCTAL_MODE: u32 = 0o7_777_777;
    if opts.mode > MAX_OCTAL_MODE {
        pax.extend_from_slice(&format_pax_record(
            "mode",
            &alloc::format!("{:o}", opts.mode),
        ));
    }
    if opts.uid > MAX_OCTAL_ID {
        pax.extend_from_slice(&format_pax_record("uid", &alloc::format!("{}", opts.uid)));
    }
    if opts.gid > MAX_OCTAL_ID {
        pax.extend_from_slice(&format_pax_record("gid", &alloc::format!("{}", opts.gid)));
    }
    if opts.uname.len() > 32 {
        pax.extend_from_slice(&format_pax_record("uname", &opts.uname));
    }
    if opts.gname.len() > 32 {
        pax.extend_from_slice(&format_pax_record("gname", &opts.gname));
    }

    // size — only when it overflows 11 octal digits (max ~8 GB).
    const MAX_OCTAL_SIZE: u64 = 0x1_FFFF_FFFF;
    if (data_len as u64) > MAX_OCTAL_SIZE {
        pax.extend_from_slice(&format_pax_record("size", &alloc::format!("{data_len}")));
    }

    // PAX charset / comment / hdrcharset keywords
    if let Some(ref charset) = opts.pax_charset {
        pax.extend_from_slice(&format_pax_record("charset", charset));
    }
    if let Some(ref comment) = opts.pax_comment {
        pax.extend_from_slice(&format_pax_record("comment", comment));
    }
    if let Some(ref hdrcharset) = opts.pax_hdrcharset {
        pax.extend_from_slice(&format_pax_record("hdrcharset", hdrcharset));
    }

    pax
}

fn build_sparse_pax_data(name: &str, sparse_map: &[(u64, u64)], real_size: u64) -> Vec<u8> {
    let mut pax = Vec::new();
    pax.extend_from_slice(&format_pax_record("GNU.sparse.name", name));
    pax.extend_from_slice(&format_pax_record(
        "GNU.sparse.size",
        &alloc::format!("{real_size}"),
    ));
    pax.extend_from_slice(&format_pax_record(
        "GNU.sparse.realsize",
        &alloc::format!("{real_size}"),
    ));
    pax.extend_from_slice(&format_pax_record(
        "GNU.sparse.numblocks",
        &alloc::format!("{}", sparse_map.len()),
    ));
    let map = sparse_map
        .iter()
        .flat_map(|(offset, length)| [alloc::format!("{offset}"), alloc::format!("{length}")])
        .collect::<Vec<_>>()
        .join(",");
    pax.extend_from_slice(&format_pax_record("GNU.sparse.map", &map));
    pax
}

fn validate_sparse_layout(
    data: &[u8],
    sparse_map: &[(u64, u64)],
    real_size: u64,
) -> Result<(), Error> {
    if sparse_map.is_empty() {
        return Err(Error::InvalidData("tar: sparse map cannot be empty"));
    }

    let mut total_len = 0u64;
    let mut prev_end = 0u64;
    for (index, (offset, length)) in sparse_map.iter().copied().enumerate() {
        if length == 0 {
            return Err(Error::InvalidData(
                "tar: sparse extent length cannot be zero",
            ));
        }
        if index > 0 && offset < prev_end {
            return Err(Error::InvalidData(
                "tar: sparse extents must be ordered and non-overlapping",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or(Error::InvalidData("tar: sparse extent overflow"))?;
        if end > real_size {
            return Err(Error::InvalidData(
                "tar: sparse extent exceeds logical size",
            ));
        }
        prev_end = end;
        total_len = total_len
            .checked_add(length)
            .ok_or(Error::InvalidData("tar: sparse data length overflow"))?;
    }

    if total_len != data.len() as u64 {
        return Err(Error::InvalidData("tar: sparse data length mismatch"));
    }

    Ok(())
}

/// Format a single PAX record: `"{len} {key}={value}\n"`.
///
/// The length field includes itself, the separating space, the key, the `=`,
/// the value, and the trailing newline.
fn format_pax_record(key: &str, value: &str) -> Vec<u8> {
    // "rest" = everything except the decimal length field itself.
    let rest = 1 + key.len() + 1 + value.len() + 1; // space + key + '=' + value + '\n'
    let mut total = rest + 1; // start assuming 1 digit
    loop {
        let new_total = rest + decimal_digits(total);
        if new_total == total {
            break;
        }
        total = new_total;
    }
    alloc::format!("{total} {key}={value}\n").into_bytes()
}

/// Format a PAX time value as `"secs"` or `"secs.frac"`.
///
/// Trailing zeros in the fractional part are trimmed.
fn format_pax_time(secs: i64, nsec: u32) -> String {
    let total_nanos = (secs as i128) * 1_000_000_000i128 + (nsec as i128);
    if total_nanos % 1_000_000_000i128 == 0 {
        alloc::format!("{}", total_nanos / 1_000_000_000i128)
    } else {
        let negative = total_nanos < 0;
        let abs_nanos = total_nanos.abs();
        let whole = abs_nanos / 1_000_000_000i128;
        let frac = alloc::format!("{:09}", (abs_nanos % 1_000_000_000i128) as u32);
        let trimmed = frac.trim_end_matches('0');
        if negative {
            alloc::format!("-{whole}.{trimmed}")
        } else {
            alloc::format!("{whole}.{trimmed}")
        }
    }
}

/// Number of decimal digits needed to represent `n`.
const fn decimal_digits(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut count = 0;
    let mut v = n;
    while v > 0 {
        count += 1;
        v /= 10;
    }
    count
}

/// Generate a conventional PAX extended-header entry name.
///
/// Follows the GNU tar convention: `PaxHeaders.0/{basename}`.
fn pax_header_name(name: &str) -> String {
    let basename = name.rsplit('/').next().unwrap_or(name);
    let truncated = truncate_to(basename, 80);
    alloc::format!("PaxHeaders.0/{truncated}")
}

fn sparse_placeholder_name(name: &str) -> String {
    let basename = name.rsplit('/').next().unwrap_or(name);
    match name.rsplit_once('/') {
        Some((dir, _)) => alloc::format!("{dir}/GNUSparseFile.0/{basename}"),
        None => alloc::format!("GNUSparseFile.0/{basename}"),
    }
}

/// Truncate a UTF-8 string to at most `max_bytes` bytes without splitting a
/// multi-byte character.
fn truncate_to(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return String::from(s);
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    String::from(&s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::tar::decode;

    #[test]
    fn test_roundtrip_single_file() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"Hello, tar!");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, tar!");
    }

    #[test]
    fn test_roundtrip_multiple_files() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("a.txt", b"Content A");
        encoder.add_file("b.txt", b"Content B");
        encoder.add_file("empty.txt", b"");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, b"Content A");
        assert_eq!(entries[1].data, b"Content B");
        assert_eq!(entries[2].data, b"");
    }

    #[test]
    fn test_roundtrip_directory() {
        let mut encoder = TarEncoder::new();
        encoder.add_directory("mydir/", 0o755);
        encoder.add_file("mydir/file.txt", b"nested content");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.file_type, FileType::Directory);
        assert_eq!(entries[1].data, b"nested content");
    }

    // Phase 4: Special types

    #[test]
    fn test_roundtrip_hardlink() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("original.txt", b"real content");
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("hardlink.txt"),
                file_type: FileType::HardLink,
                link_name: alloc::string::String::from("original.txt"),
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.file_type, FileType::Regular);
        assert_eq!(entries[0].data, b"real content");
        assert_eq!(entries[1].header.file_type, FileType::HardLink);
        assert_eq!(entries[1].header.link_name, "original.txt");
        assert_eq!(entries[1].data.len(), 0);
    }

    #[test]
    fn test_roundtrip_symlink() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("link.txt"),
                file_type: FileType::SymLink,
                link_name: alloc::string::String::from("target.txt"),
                ..Default::default()
            },
        );
        encoder.add_file("target.txt", b"real content");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].header.file_type, FileType::SymLink);
        assert_eq!(entries[0].header.link_name, "target.txt");
        assert_eq!(entries[0].data.len(), 0);
        assert_eq!(entries[1].data, b"real content");
    }

    #[test]
    fn test_roundtrip_fifo() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("my_fifo"),
                mode: 0o644,
                file_type: FileType::Fifo,
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::Fifo);
        assert_eq!(entries[0].header.name, "my_fifo");
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn test_roundtrip_char_device() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("null"),
                mode: 0o666,
                file_type: FileType::CharDevice,
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::CharDevice);
    }

    #[test]
    fn test_roundtrip_block_device() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("sda"),
                mode: 0o660,
                file_type: FileType::BlockDevice,
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::BlockDevice);
    }

    #[test]
    fn test_roundtrip_long_name() {
        let long_name = "a/".repeat(60) + "file.txt"; // 124 chars, > 100
        let mut encoder = TarEncoder::new();
        encoder.add_file(&long_name, b"long name content");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].data, b"long name content");
    }

    #[test]
    fn test_roundtrip_long_link_name() {
        let long_link = "b/".repeat(60) + "target.txt"; // > 100 chars
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from("mylink"),
                file_type: FileType::SymLink,
                link_name: alloc::string::String::from(long_link.as_str()),
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::SymLink);
        assert_eq!(entries[0].header.link_name, long_link);
    }

    #[test]
    fn test_roundtrip_long_name_and_link() {
        let long_name = "c/".repeat(60) + "link.txt"; // > 100 chars
        let long_link = "d/".repeat(60) + "target.txt"; // > 100 chars
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: alloc::string::String::from(long_name.as_str()),
                file_type: FileType::SymLink,
                link_name: alloc::string::String::from(long_link.as_str()),
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].header.link_name, long_link);
        assert_eq!(entries[0].header.file_type, FileType::SymLink);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_finish_to() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"Hello, tar!");
        let mut output = Vec::new();
        let len = encoder.finish_to(&mut output).unwrap();
        assert_eq!(len, output.len());
        let entries = decode::decode(&output).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, tar!");
    }

    #[test]
    fn test_empty_archive() {
        let encoder = TarEncoder::new();
        let data = encoder.finish();
        // Empty archive: just two 512-byte zero blocks (EOF marker)
        assert_eq!(data.len(), 1024);
        assert!(data.iter().all(|&b| b == 0));
        let entries = decode::decode(&data).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_file_exactly_512_bytes() {
        // File data is exactly one tar block (512 bytes) — no padding needed
        let data = vec![b'X'; 512];
        let mut encoder = TarEncoder::new();
        encoder.add_file("block.bin", &data);
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, data);
    }

    #[test]
    fn test_file_511_bytes_padding() {
        // File data 511 bytes — needs 1 byte of padding to reach 512
        let data = vec![b'Y'; 511];
        let mut encoder = TarEncoder::new();
        encoder.add_file("pad.bin", &data);
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, data);
    }

    #[test]
    fn test_filename_exactly_100_bytes() {
        // Name exactly 100 bytes — at the UStar limit, no GNU long name needed
        let name = "a".repeat(100);
        let mut encoder = TarEncoder::new();
        encoder.add_file(&name, b"data");
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, name);
    }

    #[test]
    fn test_filename_101_bytes_triggers_gnu_longname() {
        // Name 101 bytes — exceeds UStar limit, requires GNU long name extension
        let name = "b".repeat(101);
        let mut encoder = TarEncoder::new();
        encoder.add_file(&name, b"data");
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, name);
    }

    #[test]
    fn test_empty_file() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("empty.txt", b"");
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "empty.txt");
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn test_large_file_multi_block() {
        // Large file spanning multiple 512-byte blocks
        let data = vec![0x42; 2000];
        let mut encoder = TarEncoder::new();
        encoder.add_file("large.bin", &data);
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, data);
    }

    // B-3: UStar prefix field support

    #[test]
    fn test_ustar_prefix_split() {
        // Build a path >100 chars that can be split at '/' into prefix (<=155) and name (<=100).
        // "some/deeply/nested/directory/structure/" is the prefix part,
        // and the filename is short enough.
        let dir = "a_long_directory_name_for_testing/";
        // Repeat to make prefix portion; ensure total > 100 but splittable
        let long_path = alloc::format!("{dir}{dir}{dir}file.txt");
        assert!(long_path.len() > 100, "path should exceed 100 bytes");
        assert!(
            long_path.len() <= 255,
            "path should fit in UStar prefix+name"
        );

        let mut encoder = TarEncoder::new();
        encoder.add_file(&long_path, b"ustar prefix test");
        let tar = encoder.finish();

        // Verify no GNU LongName entry was emitted: the archive should have
        // exactly 1 entry (the file itself), not 2 (LongName + file).
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_path);
        assert_eq!(entries[0].data, b"ustar prefix test");

        // Also verify the raw header uses the prefix field (bytes 345-500)
        // by checking it's non-zero.
        let prefix_field = &tar[345..500];
        assert!(
            prefix_field.iter().any(|&b| b != 0),
            "UStar prefix field should be populated"
        );
    }

    #[test]
    fn test_ustar_prefix_fallback_to_gnu_longname() {
        // A path >100 bytes with no '/' at all cannot use UStar prefix,
        // so it must fall back to GNU LongName.
        let name = "b".repeat(120);
        let mut encoder = TarEncoder::new();
        encoder.add_file(&name, b"data");
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, name);
    }

    // B-4: uname/gname write support

    #[test]
    fn test_uname_gname_roundtrip() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            b"hello",
            &TarEntryOptions {
                name: String::from("test.txt"),
                uname: String::from("testuser"),
                gname: String::from("testgroup"),
                ..Default::default()
            },
        );
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.uname, "testuser");
        assert_eq!(entries[0].header.gname, "testgroup");
        assert_eq!(entries[0].data, b"hello");
    }

    // B-5: Binary size encoding for files > 8GB

    #[test]
    fn test_binary_size_encoding_roundtrip() {
        // We can't create an actual 8GB+ file in a test, so we test the
        // encoding/decoding at the header level by manually constructing
        // a header with a large size using write_size and parsing it back.
        use crate::archive::tar::header::TarHeader;

        let large_size: u64 = 0x2_0000_0000; // 8 GiB
        let mut header = [0u8; BLOCK_SIZE];

        // Name
        header[0..8].copy_from_slice(b"big.file");
        // Mode
        write_octal(&mut header[100..108], 0o644, 7);
        // UID
        write_octal(&mut header[108..116], 0, 7);
        // GID
        write_octal(&mut header[116..124], 0, 7);
        // Size - use binary encoding
        write_size(&mut header[124..136], large_size);
        // Mtime
        write_octal(&mut header[136..148], 0, 11);
        // Checksum placeholder
        header[148..156].copy_from_slice(b"        ");
        // Type flag - regular file
        header[156] = b'0';
        // UStar magic
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // Compute checksum
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write_octal(&mut header[148..155], checksum as u64, 6);
        header[155] = b' ';

        // Parse the header back
        let parsed = TarHeader::parse(&header).unwrap();
        assert_eq!(parsed.size, large_size);
        assert_eq!(parsed.name, "big.file");

        // Also test a much larger size
        let huge_size: u64 = 0x100_0000_0000; // 1 TiB
        write_size(&mut header[124..136], huge_size);
        // Recompute checksum
        header[148..156].copy_from_slice(b"        ");
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write_octal(&mut header[148..155], checksum as u64, 6);
        header[155] = b' ';

        let parsed2 = TarHeader::parse(&header).unwrap();
        assert_eq!(parsed2.size, huge_size);
    }

    #[test]
    fn test_try_ustar_split_boundaries() {
        // No slash → None
        assert!(try_ustar_split(&"a".repeat(120)).is_none());

        // Slash at the very end → name is empty → skip, None
        assert!(try_ustar_split(&format!("{}/", "a".repeat(100))).is_none());

        // prefix exactly 155 chars, name exactly 100 chars → valid split
        let prefix = "a".repeat(155);
        let name = "b".repeat(100);
        let path = format!("{prefix}/{name}");
        assert_eq!(path.len(), 256);
        let result = try_ustar_split(&path);
        assert!(result.is_some());
        let (p, n) = result.unwrap();
        assert_eq!(p, prefix);
        assert_eq!(n, name);

        // prefix 156 chars, name 100 chars → prefix too long, no valid split
        let path2 = format!("{}/{name}", "a".repeat(156));
        assert!(try_ustar_split(&path2).is_none());

        // prefix 155, name 101 → name too long, try earlier slash
        // "aaa.../bbb.../ccc" with multiple slashes
        let part1 = "a".repeat(80);
        let part2 = "b".repeat(74);
        let file = "c".repeat(101);
        let path3 = format!("{part1}/{part2}/{file}");
        // first try: prefix="aaa.../bbb..." (155), name="ccc"(101) → name too long
        // second try: prefix="aaa..."(80), name="bbb.../ccc"(176) → name too long
        // → None
        assert!(try_ustar_split(&path3).is_none());

        // Multiple slashes: should find the rightmost valid split
        let dir = "dir"; // 3
        let path4 = format!("{dir}/{dir}/{}", "f".repeat(95));
        // "dir/dir/fff..." total = 3+1+3+1+95 = 103
        // rightmost '/': prefix="dir/dir"(7), name="fff..."(95) → valid
        let result4 = try_ustar_split(&path4);
        assert!(result4.is_some());
        let (p4, n4) = result4.unwrap();
        assert_eq!(p4, "dir/dir");
        assert_eq!(n4.len(), 95);
    }

    #[test]
    fn test_ustar_prefix_roundtrip_with_deep_nesting() {
        // Deeply nested path that uses prefix field
        let path = "aaa/bbb/ccc/ddd/eee/fff/ggg/hhh/iii/jjj/kkk/lll/mmm/nnn/ooo/ppp/qqq/rrr/sss/ttt/uuu/vvv/www/xxx/file.dat";
        assert!(path.len() > 100);
        assert!(path.len() <= 255);

        let mut encoder = TarEncoder::new();
        encoder.add_file(path, b"deep nesting");
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, path);
        assert_eq!(entries[0].data, b"deep nesting");
    }

    // C-5 #34: large file (>64KB) roundtrip
    #[test]
    fn test_roundtrip_large_file() {
        let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
        let mut encoder = TarEncoder::new();
        encoder.add_file("large.bin", &data);
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "large.bin");
        assert_eq!(entries[0].data, data);
    }

    // C-5 #37: Default impl equivalence
    #[test]
    fn test_default_equals_new() {
        let from_new = TarEncoder::new().finish();
        let from_default = TarEncoder::default().finish();
        assert_eq!(from_new, from_default);
    }

    #[test]
    fn test_mode_uid_gid_roundtrip() {
        let mut encoder = TarEncoder::new();
        encoder.add_file_with_options(
            b"payload",
            &TarEntryOptions {
                name: String::from("owned.txt"),
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                ..Default::default()
            },
        );
        let tar = encoder.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mode, 0o644);
        assert_eq!(entries[0].header.uid, 1000);
        assert_eq!(entries[0].header.gid, 1000);
    }

    #[test]
    fn test_binary_size_8gb_boundary() {
        // Test encoding a file with size exactly at the 8GB boundary (0x200000000).
        // This value exceeds the maximum 11-octal-digit range, so the encoder must
        // use GNU binary encoding. We construct the header manually (no actual 8GB
        // of data) and verify it round-trips through the parser.
        use crate::archive::tar::header::TarHeader;

        let boundary_size: u64 = 0x2_0000_0000; // exactly 8 GiB
        let mut header = [0u8; BLOCK_SIZE];

        // Name
        header[0..9].copy_from_slice(b"8gig.file");
        // Mode
        write_octal(&mut header[100..108], 0o644, 7);
        // UID
        write_octal(&mut header[108..116], 0, 7);
        // GID
        write_octal(&mut header[116..124], 0, 7);
        // Size — should trigger binary encoding
        write_size(&mut header[124..136], boundary_size);
        // Verify the binary flag is set (high bit of first byte)
        assert_eq!(
            header[124] & 0x80,
            0x80,
            "8GB boundary should use binary encoding"
        );
        // Mtime
        write_octal(&mut header[136..148], 0, 11);
        // Checksum placeholder
        header[148..156].copy_from_slice(b"        ");
        // Type flag — regular file
        header[156] = b'0';
        // UStar magic
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        // Compute and write checksum
        let checksum: u32 = header.iter().map(|&b| b as u32).sum();
        write_octal(&mut header[148..155], checksum as u64, 6);
        header[155] = b' ';

        // Parse back and verify
        let parsed = TarHeader::parse(&header).unwrap();
        assert_eq!(parsed.size, boundary_size);
        assert_eq!(parsed.name, "8gig.file");
    }

    #[test]
    fn test_devmajor_devminor_roundtrip() {
        let mut enc = TarEncoder::new();
        enc.add_file_with_options(
            b"",
            &TarEntryOptions {
                name: "null".into(),
                file_type: FileType::CharDevice,
                devmajor: 1,
                devminor: 3,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = super::super::decode::decode(&tar).unwrap();
        assert_eq!(entries[0].header.devmajor, 1);
        assert_eq!(entries[0].header.devminor, 3);
    }

    // ── PAX format tests ────────────────────────────────────────────

    /// When all metadata fits within UStar limits, a PAX-mode encoder
    /// produces a standard UStar archive with no PAX extended headers.
    #[test]
    fn test_pax_roundtrip_simple() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file("hello.txt", b"Hello, PAX!");
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "hello.txt");
        assert_eq!(entries[0].data, b"Hello, PAX!");
    }

    /// A filename exceeding 100 bytes with no `/` (no valid UStar prefix
    /// split) is stored via a PAX `path` attribute and round-trips correctly.
    #[test]
    fn test_pax_long_name() {
        let long_name = "x".repeat(150);
        let mut enc = TarEncoder::new_pax();
        enc.add_file(&long_name, b"pax long name");
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].data, b"pax long name");
    }

    /// A symlink target exceeding 100 bytes is stored via a PAX `linkpath`
    /// attribute.
    #[test]
    fn test_pax_long_link() {
        let long_target = "y".repeat(120);
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: "link.txt".into(),
                file_type: FileType::SymLink,
                link_name: long_target.clone(),
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.link_name, long_target);
    }

    /// Both the filename and the link target exceed 100 bytes; the PAX
    /// extended header carries `path` and `linkpath` attributes together.
    #[test]
    fn test_pax_long_name_and_link() {
        let long_name = "n".repeat(130);
        let long_link = "l".repeat(140);
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            &[],
            &TarEntryOptions {
                name: long_name.clone(),
                file_type: FileType::SymLink,
                link_name: long_link.clone(),
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].header.link_name, long_link);
    }

    /// Non-zero `mtime_nsec` in `TarEntryOptions` emits a PAX `mtime`
    /// attribute with sub-second precision that round-trips through the
    /// decoder.
    #[test]
    fn test_pax_mtime_nanoseconds() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"data",
            &TarEntryOptions {
                name: "ns.txt".into(),
                mtime: 1_700_000_000,
                mtime_nsec: 123_456_789,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, 1_700_000_000);
        assert_eq!(entries[0].header.mtime_nsec, 123_456_789);
    }

    /// Non-zero `atime` / `ctime` in `TarEntryOptions` emit PAX `atime`
    /// and `ctime` attributes with nanosecond fractions.
    #[test]
    fn test_pax_atime_ctime() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"data",
            &TarEntryOptions {
                name: "times.txt".into(),
                mtime: 1_000_000_000,
                atime: 1_000_000_100,
                atime_nsec: 500_000_000,
                ctime: 1_000_000_200,
                ctime_nsec: 750_000_000,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.atime, 1_000_000_100);
        assert_eq!(entries[0].header.atime_nsec, 500_000_000);
        assert_eq!(entries[0].header.ctime, 1_000_000_200);
        assert_eq!(entries[0].header.ctime_nsec, 750_000_000);
    }

    /// Multiple files in one PAX-mode archive — only those with long names
    /// get PAX headers; short-named entries are plain UStar.
    #[test]
    fn test_pax_multiple_files() {
        let mut enc = TarEncoder::new_pax();
        let long_a = "a".repeat(110);
        enc.add_file(&long_a, b"AAA");
        enc.add_file("short.txt", b"BBB");
        let long_c = "c".repeat(105);
        enc.add_file(&long_c, b"CCC");
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].header.name, long_a);
        assert_eq!(entries[0].data, b"AAA");
        assert_eq!(entries[1].header.name, "short.txt");
        assert_eq!(entries[1].data, b"BBB");
        assert_eq!(entries[2].header.name, long_c);
        assert_eq!(entries[2].data, b"CCC");
    }

    #[test]
    fn test_pax_sparse_roundtrip() {
        let mut enc = TarEncoder::new_pax();
        enc.add_sparse_file("sparse.bin", b"HELLOWORLD", &[(0, 5), (2048, 5)], 4096)
            .unwrap();
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "sparse.bin");
        assert_eq!(entries[0].header.size, 4096);
        assert_eq!(entries[0].header.sparse_map, vec![(0, 5), (2048, 5)]);
        assert_eq!(entries[0].data, b"HELLOWORLD");
    }

    #[test]
    fn test_pax_sparse_requires_pax_mode() {
        let mut enc = TarEncoder::new();
        let err = enc
            .add_sparse_file("sparse.bin", b"HELLO", &[(0, 5)], 4096)
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }

    #[test]
    fn test_pax_sparse_rejects_invalid_layout() {
        let mut enc = TarEncoder::new_pax();
        let err = enc
            .add_sparse_file("sparse.bin", b"HELLO", &[(0, 3), (2, 2)], 4096)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidData(_)));
    }

    /// `TarEncoder::format()` returns the format chosen at construction time.
    #[test]
    fn test_pax_format_accessor() {
        let gnu = TarEncoder::new();
        assert_eq!(gnu.format(), TarFormat::Gnu);
        let pax = TarEncoder::new_pax();
        assert_eq!(pax.format(), TarFormat::Pax);
    }

    // ── PAX record / time formatting ─────────────────────────────────

    /// `format_pax_record` produces the self-referencing `"{len} {key}={value}\n"`
    /// encoding required by POSIX.1-2001.
    #[test]
    fn test_format_pax_record() {
        let rec = format_pax_record("path", "foo");
        assert_eq!(rec, b"12 path=foo\n");

        // "16 linkpath=bar\n" = 16 bytes
        let rec2 = format_pax_record("linkpath", "bar");
        assert_eq!(rec2, b"16 linkpath=bar\n");

        // Edge case: total length crosses a decimal digit boundary.
        // key="k", value="v" (1+1 bytes) → rest = 1+1+1+1+1 = 5
        // total = 5 + 1 = 6 → decimal_digits(6) = 1 → 5+1 = 6 ✓
        let rec3 = format_pax_record("k", "v");
        assert_eq!(rec3, b"6 k=v\n");

        // key="k", value="vvvvvv" (6 bytes) → rest = 1+1+1+6+1 = 10
        // total = 10+2 = 12 → decimal_digits(12) = 2 → 10+2 = 12 ✓
        let rec4 = format_pax_record("k", "vvvvvv");
        assert_eq!(rec4, b"12 k=vvvvvv\n");
    }

    /// When the content length plus a 1-digit prefix would equal 10, the
    /// prefix becomes 2 digits and the total jumps to 11 — verify the
    /// iterative length calculation converges correctly.
    #[test]
    fn test_format_pax_record_digit_boundary() {
        let rec = format_pax_record("ab", "cdef");
        assert_eq!(rec, b"11 ab=cdef\n");
        assert_eq!(rec.len(), 11);
    }

    /// `format_pax_time` omits the fractional part for whole-second values,
    /// and trims trailing zeros from nanosecond fractions.
    #[test]
    fn test_format_pax_time() {
        assert_eq!(format_pax_time(1234567890, 0), "1234567890");
        assert_eq!(
            format_pax_time(1234567890, 123_456_789),
            "1234567890.123456789"
        );
        assert_eq!(format_pax_time(1234567890, 100_000_000), "1234567890.1");
        assert_eq!(format_pax_time(0, 1), "0.000000001");
        assert_eq!(format_pax_time(-1, 0), "-1");
        assert_eq!(format_pax_time(-2, 500_000_000), "-1.5");
    }

    /// A PAX-mode encoder handles directory entries (no data, type `'5'`)
    /// without emitting spurious PAX headers.
    #[test]
    fn test_pax_directory() {
        let mut enc = TarEncoder::new_pax();
        enc.add_directory("mydir/", 0o755);
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.file_type, FileType::Directory);
        assert_eq!(entries[0].header.name, "mydir/");
    }

    #[test]
    fn test_pax_mode_overflow_roundtrip() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"mode overflow",
            &TarEntryOptions {
                name: "overflow-mode.txt".into(),
                mode: 0o12_345_670,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mode, 0o12_345_670);
    }

    #[test]
    fn test_pax_long_uname_gname_roundtrip() {
        let long_uname = "owner-name-".repeat(4);
        let long_gname = "group-name-".repeat(4);
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"owner metadata",
            &TarEntryOptions {
                name: "owners.txt".into(),
                uname: long_uname.clone(),
                gname: long_gname.clone(),
                ..Default::default()
            },
        );
        let tar = enc.finish();
        assert!(
            tar.windows(b" uname=".len()).any(|w| w == b" uname="),
            "PAX header should contain uname record"
        );
        assert!(
            tar.windows(b" gname=".len()).any(|w| w == b" gname="),
            "PAX header should contain gname record"
        );
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.uname, long_uname);
        assert_eq!(entries[0].header.gname, long_gname);
    }

    /// A single PAX extended header can carry both `path` and time attributes
    /// (`mtime` with nsec, `atime`) simultaneously.
    #[test]
    fn test_pax_combined_long_name_and_timestamps() {
        let long_name = "z".repeat(200);
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"combo",
            &TarEntryOptions {
                name: long_name.clone(),
                mtime: 1_600_000_000,
                mtime_nsec: 999_999_999,
                atime: 1_600_000_001,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, long_name);
        assert_eq!(entries[0].header.mtime, 1_600_000_000);
        assert_eq!(entries[0].header.mtime_nsec, 999_999_999);
        assert_eq!(entries[0].header.atime, 1_600_000_001);
        assert_eq!(entries[0].data, b"combo");
    }

    #[test]
    fn test_pax_negative_mtime_roundtrip() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"pre-epoch",
            &TarEntryOptions {
                name: "negative-time.txt".into(),
                mtime: -86_400,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, -86_400);
        assert_eq!(entries[0].header.mtime_nsec, 0);
    }

    #[test]
    fn test_pax_negative_fractional_mtime_roundtrip() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"fractional pre-epoch",
            &TarEntryOptions {
                name: "negative-frac.txt".into(),
                mtime: -2,
                mtime_nsec: 500_000_000,
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.mtime, -2);
        assert_eq!(entries[0].header.mtime_nsec, 500_000_000);
    }

    #[test]
    fn test_pax_charset_comment_hdrcharset_roundtrip() {
        let mut enc = TarEncoder::new_pax();
        enc.add_file_with_options(
            b"charset test data",
            &TarEntryOptions {
                name: "charset.txt".into(),
                pax_charset: Some("ISO-LATIN-1".into()),
                pax_comment: Some("test comment".into()),
                pax_hdrcharset: Some("BINARY".into()),
                ..Default::default()
            },
        );
        let tar = enc.finish();
        let entries = decode::decode(&tar).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.name, "charset.txt");
        assert_eq!(
            entries[0].header.pax_charset.as_deref(),
            Some("ISO-LATIN-1")
        );
        assert_eq!(
            entries[0].header.pax_comment.as_deref(),
            Some("test comment")
        );
        assert_eq!(entries[0].header.pax_hdrcharset.as_deref(), Some("BINARY"));
        assert_eq!(entries[0].data, b"charset test data");
    }
}
