//! cpio archive encoding (`odc`, SVR4 `newc`, `newcrc`, and `bin` formats).

use alloc::vec::Vec;

use super::header::{BIN_HEADER_SIZE, BIN_MAGIC, CpioFormat, S_IFDIR, S_IFLNK, S_IFSOCK, align_to};

/// Builder for creating cpio archives (`odc`, SVR4 `newc`, `newcrc`, and `bin` formats).
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode, decode};
///
/// let mut enc = encode::CpioEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// enc.add_directory("subdir", 0o755);
/// let cpio = enc.finish();
/// let entries = decode::decode(&cpio).unwrap();
/// assert_eq!(entries.len(), 2);
/// ```
#[derive(Debug)]
pub struct CpioEncoder {
    data: Vec<u8>,
    ino_counter: u32,
    format: CpioFormat,
    /// When set, the next entry will use this inode number instead of auto-increment.
    custom_ino: Option<u32>,
}

/// Metadata for a cpio entry.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::encode::CpioEntryOptions;
///
/// let opts = CpioEntryOptions {
///     mode: 0o100755,
///     mtime: 1700000000,
///     ..Default::default()
/// };
/// ```
pub struct CpioEntryOptions {
    /// File mode and permissions (e.g. `0o100644` for a regular file).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Modification time as Unix timestamp.
    pub mtime: u32,
}

impl Default for CpioEntryOptions {
    fn default() -> Self {
        Self {
            mode: 0o100644, // regular file
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
        }
    }
}

impl Default for CpioEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CpioEncoder {
    /// Create a new encoder that produces "newc" (070701) format without checksums.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::encode::CpioEncoder;
    /// let enc = CpioEncoder::new();
    /// let cpio = enc.finish();
    /// assert!(!cpio.is_empty()); // contains TRAILER!!!
    /// ```
    pub const fn new() -> Self {
        Self {
            data: Vec::new(),
            ino_counter: 1,
            format: CpioFormat::Newc,
            custom_ino: None,
        }
    }

    /// Create a new encoder that produces "newcrc" (070702) format with checksums.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::encode::CpioEncoder;
    ///
    /// let enc = CpioEncoder::new_crc();
    /// let cpio = enc.finish();
    /// assert!(!cpio.is_empty()); // contains TRAILER!!!
    /// ```
    ///
    /// This method does not panic.
    pub const fn new_crc() -> Self {
        Self {
            data: Vec::new(),
            ino_counter: 1,
            format: CpioFormat::Newcrc,
            custom_ino: None,
        }
    }

    /// Create a new encoder that produces portable ASCII `odc` (070707) format.
    pub const fn new_odc() -> Self {
        Self {
            data: Vec::new(),
            ino_counter: 1,
            format: CpioFormat::Odc,
            custom_ino: None,
        }
    }

    /// Create a new encoder that produces SVR4 binary `bin` (070707 u16) format.
    ///
    /// 16-bit fields are written little-endian; 32-bit fields are written as
    /// two u16s, most significant word first (FreeBSD cpio(5), "New Binary
    /// Format"). Entries are padded to even offsets and the archive is padded
    /// to a 512-byte boundary.
    pub const fn new_bin() -> Self {
        Self {
            data: Vec::new(),
            ino_counter: 1,
            format: CpioFormat::Bin,
            custom_ino: None,
        }
    }

    /// Set the inode number for the next entry. After the entry is written,
    /// the custom inode is cleared and auto-increment resumes.
    ///
    /// This also advances the auto-increment counter past the given value
    /// if it is >= the current counter, to avoid collisions.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.set_next_ino(42);
    /// enc.add_file("a.txt", b"data");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.ino, 42);
    /// ```
    pub const fn set_next_ino(&mut self, ino: u32) {
        self.custom_ino = Some(ino);
    }

    /// Allocate the next inode number, using custom_ino if set.
    const fn next_ino(&mut self) -> u32 {
        if let Some(ino) = self.custom_ino.take() {
            // Advance counter past the custom value to avoid future collisions
            if ino >= self.ino_counter {
                self.ino_counter = ino + 1;
            }
            ino
        } else {
            let ino = self.ino_counter;
            self.ino_counter += 1;
            ino
        }
    }

    /// Add a regular file entry.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_file("hello.txt", b"Hello!");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].data, b"Hello!");
    /// ```
    pub fn add_file(&mut self, name: &str, file_data: &[u8]) {
        self.add_file_with_options(name, file_data, &CpioEntryOptions::default());
    }

    /// Add a hardlink entry.
    ///
    /// In SVR4 newc format, hardlinks are entries that share the same inode number.
    /// The first entry with data carries the file content; subsequent entries with
    /// the same inode have filesize=0. The `target_ino` must match the inode of a
    /// previously added file (use [`CpioEncoder::set_next_ino`] to control inode assignment).
    ///
    /// This writes a zero-length regular file entry with the given inode and nlink=2.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.set_next_ino(100);
    /// enc.add_file("original.txt", b"data");
    /// enc.add_hardlink("link.txt", 100);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.ino, entries[1].header.ino);
    /// ```
    pub fn add_hardlink(&mut self, name: &str, target_ino: u32) {
        // Override the next ino to use the target's inode
        self.custom_ino = Some(target_ino);
        self.add_file_with_options(
            name,
            &[],
            &CpioEntryOptions {
                mode: 0o100644,
                nlink: 2,
                ..Default::default()
            },
        );
    }

    /// Add a symlink entry. The `target` is stored as the file data.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_symlink("link.txt", "target.txt");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].symlink_target(), Some("target.txt"));
    /// ```
    pub fn add_symlink(&mut self, name: &str, target: &str) {
        self.add_file_with_options(
            name,
            target.as_bytes(),
            &CpioEntryOptions {
                mode: S_IFLNK | 0o777,
                ..Default::default()
            },
        );
    }

    /// Add a directory entry.
    ///
    /// The `mode` is OR'd with [`S_IFDIR`] automatically.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_directory("mydir", 0o755);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert!(entries[0].header.is_directory());
    /// ```
    pub fn add_directory(&mut self, name: &str, mode: u32) {
        self.add_file_with_options(
            name,
            &[],
            &CpioEntryOptions {
                mode: S_IFDIR | (mode & 0o7777),
                nlink: 2,
                ..Default::default()
            },
        );
    }

    /// Add a socket entry.
    ///
    /// The `mode` is OR'd with [`S_IFSOCK`] automatically.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_socket("my.sock", 0o755);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert!(entries[0].header.is_socket());
    /// ```
    pub fn add_socket(&mut self, name: &str, mode: u32) {
        self.add_file_with_options(
            name,
            &[],
            &CpioEntryOptions {
                mode: S_IFSOCK | (mode & 0o7777),
                nlink: 1,
                ..Default::default()
            },
        );
    }

    /// Add a device file entry (character or block device).
    ///
    /// The `mode` should include the file type bits (e.g.
    /// [`S_IFCHR`](super::header::S_IFCHR) or [`S_IFBLK`](super::header::S_IFBLK)).
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode, header::S_IFCHR};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_device("null", S_IFCHR | 0o666, 1, 3);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.rdevmajor, 1);
    /// ```
    pub fn add_device(&mut self, name: &str, mode: u32, rdevmajor: u32, rdevminor: u32) {
        let ino = self.next_ino();

        let name_with_nul = name.len() + 1;
        self.data.extend_from_slice(&build_header(
            self.format,
            &HeaderFields {
                ino,
                mode,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdevmajor,
                rdevminor,
                mtime: 0,
                filesize: 0,
                namesize: name_with_nul as u32,
                check: 0,
            },
        ));

        self.data.extend_from_slice(name.as_bytes());
        self.data.push(0);

        pad_name_if_needed(&mut self.data, self.format);
        // No file data for device files
    }

    /// Add an entry with custom options.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode::{CpioEncoder, CpioEntryOptions}, decode};
    /// let mut enc = CpioEncoder::new();
    /// enc.add_file_with_options("test.txt", b"data", &CpioEntryOptions {
    ///     mode: 0o100755,
    ///     ..Default::default()
    /// });
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.mode, 0o100755);
    /// ```
    pub fn add_file_with_options(&mut self, name: &str, file_data: &[u8], opts: &CpioEntryOptions) {
        let ino = self.next_ino();

        let name_with_nul = name.len() + 1;

        // Compute CRC (sum of all data bytes, mod 2^32) for newcrc format
        let check: u32 = if self.format.is_crc() {
            file_data
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
        } else {
            0
        };

        self.data.extend_from_slice(&build_header(
            self.format,
            &HeaderFields {
                ino,
                mode: opts.mode,
                uid: opts.uid,
                gid: opts.gid,
                nlink: opts.nlink,
                rdevmajor: 0,
                rdevminor: 0,
                mtime: opts.mtime,
                filesize: file_data.len() as u32,
                namesize: name_with_nul as u32,
                check,
            },
        ));

        self.data.extend_from_slice(name.as_bytes());
        self.data.push(0);

        pad_name_if_needed(&mut self.data, self.format);

        self.data.extend_from_slice(file_data);

        pad_data_if_needed(&mut self.data, self.format);
    }

    /// Finalize the archive by writing the TRAILER!!! entry and return the
    /// complete cpio data.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::encode::CpioEncoder;
    /// let mut enc = CpioEncoder::new();
    /// enc.add_file("a.txt", b"data");
    /// let cpio = enc.finish();
    /// assert!(!cpio.is_empty());
    /// ```
    pub fn finish(mut self) -> Vec<u8> {
        let name = "TRAILER!!!";
        let name_with_nul = name.len() + 1;
        self.data.extend_from_slice(&build_header(
            self.format,
            &HeaderFields {
                ino: 0,
                mode: 0,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdevmajor: 0,
                rdevminor: 0,
                mtime: 0,
                filesize: 0,
                namesize: name_with_nul as u32,
                check: 0,
            },
        ));
        self.data.extend_from_slice(name.as_bytes());
        self.data.push(0);

        pad_name_if_needed(&mut self.data, self.format);

        if self.format != CpioFormat::Odc {
            // Pad archive to 512-byte boundary (convention)
            let current = self.data.len();
            let padded = (current + 511) & !511;
            self.data.resize(padded, 0);
        }

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
    /// use archive::archive::cpio::encode::CpioEncoder;
    ///
    /// let mut enc = CpioEncoder::new();
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

fn pad_name_if_needed(data: &mut Vec<u8>, format: CpioFormat) {
    let padded = align_to(data.len(), format.alignment());
    data.resize(padded, 0);
}

fn pad_data_if_needed(data: &mut Vec<u8>, format: CpioFormat) {
    let padded = align_to(data.len(), format.alignment());
    data.resize(padded, 0);
}

/// Field values used to construct a cpio entry header.
struct HeaderFields {
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    rdevmajor: u32,
    rdevminor: u32,
    mtime: u32,
    filesize: u32,
    namesize: u32,
    check: u32,
}

/// Serialize a cpio header for `format`. `dev`/`devminor` are always 0
/// (matching the previous encoder behavior).
fn build_header(format: CpioFormat, f: &HeaderFields) -> Vec<u8> {
    match format {
        CpioFormat::Odc => build_odc_header(
            f.ino & 0o777777,
            f.mode & 0o777777,
            f.uid & 0o777777,
            f.gid & 0o777777,
            f.nlink & 0o777777,
            combine_device(f.rdevmajor, f.rdevminor),
            f.mtime,
            f.namesize,
            f.filesize,
        )
        .into_bytes(),
        CpioFormat::Newc | CpioFormat::Newcrc => {
            let magic: &str = if format.is_crc() { "070702" } else { "070701" };
            alloc::format!(
                "{magic}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 00000000\
                 00000000\
                 {:08X}\
                 {:08X}\
                 {:08X}\
                 {:08X}",
                f.ino,
                f.mode,
                f.uid,
                f.gid,
                f.nlink,
                f.mtime,
                f.filesize,
                f.rdevmajor,
                f.rdevminor,
                f.namesize,
                f.check,
            )
            .into_bytes()
        }
        CpioFormat::Bin => build_bin_header(f),
    }
}

/// Serialize a SVR4 binary ("bin") header: thirteen u16 fields,
/// little-endian, with 32-bit fields stored as two u16s (most significant
/// word first).
fn build_bin_header(f: &HeaderFields) -> Vec<u8> {
    let rdev = combine_device(f.rdevmajor, f.rdevminor);
    let mut header = Vec::with_capacity(BIN_HEADER_SIZE);
    for v in [
        BIN_MAGIC,
        0, // dev
        f.ino as u16,
        f.mode as u16,
        f.uid as u16,
        f.gid as u16,
        f.nlink as u16,
        rdev as u16,
        (f.mtime >> 16) as u16,
        f.mtime as u16,
        f.namesize as u16,
        (f.filesize >> 16) as u16,
        f.filesize as u16,
    ] {
        header.extend_from_slice(&v.to_le_bytes());
    }
    header
}

const fn combine_device(major: u32, minor: u32) -> u32 {
    ((major & 0xFF) << 8) | (minor & 0xFF)
}

#[allow(clippy::too_many_arguments)]
fn build_odc_header(
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    rdev: u32,
    mtime: u32,
    namesize: u32,
    filesize: u32,
) -> alloc::string::String {
    alloc::format!(
        "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
        0u32,
        ino,
        mode,
        uid,
        gid,
        nlink,
        rdev,
        mtime,
        namesize,
        filesize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::cpio::decode;

    #[test]
    fn test_roundtrip_single_file() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("test.txt", b"Hello, cpio!");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, cpio!");
    }

    #[test]
    fn test_roundtrip_multiple_files() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("a.txt", b"AAA");
        encoder.add_file("b.txt", b"BBB");
        encoder.add_file("empty.txt", b"");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].data, b"AAA");
        assert_eq!(entries[1].name, "b.txt");
        assert_eq!(entries[1].data, b"BBB");
        assert_eq!(entries[2].name, "empty.txt");
        assert_eq!(entries[2].data, b"");
    }

    #[test]
    fn test_roundtrip_symlink() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("target.txt", b"real content");
        encoder.add_symlink("link.txt", "target.txt");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "target.txt");
        assert!(!entries[0].header.is_symlink());
        assert_eq!(entries[1].name, "link.txt");
        assert!(entries[1].header.is_symlink());
        assert_eq!(entries[1].symlink_target(), Some("target.txt"));
    }

    #[test]
    fn test_roundtrip_directory() {
        let mut encoder = CpioEncoder::new();
        encoder.add_directory("mydir", 0o755);
        encoder.add_file("mydir/file.txt", b"nested");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].header.is_directory());
        assert_eq!(entries[0].name, "mydir");
        assert_eq!(entries[1].data, b"nested");
    }

    #[test]
    fn test_roundtrip_crc_format() {
        let mut encoder = CpioEncoder::new_crc();
        encoder.add_file("hello.txt", b"Hello!");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].header.is_crc);
        assert_eq!(entries[0].data, b"Hello!");
        // Verify CRC was stored correctly
        let expected_crc: u32 = b"Hello!".iter().map(|&b| b as u32).sum();
        assert_eq!(entries[0].header.check, expected_crc);
    }

    #[test]
    fn test_roundtrip_odc_format() {
        let mut encoder = CpioEncoder::new_odc();
        encoder.add_file("hello.txt", b"Hello!");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"Hello!");
        assert_eq!(entries[0].header.format, CpioFormat::Odc);
        assert_eq!(&archive[..6], b"070707");
    }

    #[test]
    fn test_odc_has_no_512_padding() {
        let encoder = CpioEncoder::new_odc();
        let archive = encoder.finish();
        assert_eq!(archive.len(), 87);
        assert!(!archive.ends_with(&[0; 16]));
    }

    #[test]
    fn test_crc_mismatch_detected() {
        let mut encoder = CpioEncoder::new_crc();
        encoder.add_file("test.txt", b"data");
        let mut archive = encoder.finish();
        // Corrupt the file data (but not the CRC in the header)
        // Find the data after the first header+name alignment
        // Header is 110 bytes, name "test.txt\0" is 9 bytes, aligned to 120
        let data_offset = 120; // 110 + 9 = 119, aligned to 120
        archive[data_offset] ^= 0xFF; // corrupt first byte
        let result = decode::decode(&archive);
        assert!(matches!(
            result,
            Err(crate::error::Error::ChecksumMismatch { .. })
        ));
    }

    // Phase 4: Many files

    #[test]
    fn test_roundtrip_many_files() {
        let mut encoder = CpioEncoder::new();
        for i in 0..10 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            encoder.add_file(&name, data.as_bytes());
        }
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 10);
        for (i, entry) in entries.iter().enumerate().take(10) {
            assert_eq!(entry.name, alloc::format!("file_{i}.txt"));
            assert_eq!(entry.data, alloc::format!("Content of file {i}").as_bytes());
        }
    }

    #[test]
    fn test_roundtrip_device() {
        use crate::archive::cpio::header::{S_IFBLK, S_IFCHR};

        let mut encoder = CpioEncoder::new();
        encoder.add_device("null", S_IFCHR | 0o666, 1, 3);
        encoder.add_device("sda", S_IFBLK | 0o660, 8, 0);
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].name, "null");
        assert_eq!(entries[0].header.file_type(), S_IFCHR);
        assert_eq!(entries[0].header.rdevmajor, 1);
        assert_eq!(entries[0].header.rdevminor, 3);

        assert_eq!(entries[1].name, "sda");
        assert_eq!(entries[1].header.file_type(), S_IFBLK);
        assert_eq!(entries[1].header.rdevmajor, 8);
        assert_eq!(entries[1].header.rdevminor, 0);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_finish_to() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("test.txt", b"Hello, cpio!");
        let mut output = Vec::new();
        let len = encoder.finish_to(&mut output).unwrap();
        assert_eq!(len, output.len());
        let entries = decode::decode(&output).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, cpio!");
    }

    #[test]
    fn test_roundtrip_crc_empty_file() {
        // Empty file has check=0, should still validate in newcrc format
        let mut encoder = CpioEncoder::new_crc();
        encoder.add_file("empty.txt", b"");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.check, 0);
        assert!(entries[0].header.is_crc);
    }

    #[test]
    fn test_roundtrip_empty_archive() {
        let encoder = CpioEncoder::new();
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_roundtrip_hardlink() {
        let mut encoder = CpioEncoder::new();
        // Add the "original" file with a known inode and nlink=2
        encoder.set_next_ino(42);
        encoder.add_file_with_options(
            "original.txt",
            b"shared content",
            &CpioEntryOptions {
                nlink: 2,
                ..Default::default()
            },
        );
        // Add a hardlink referencing the same inode
        encoder.add_hardlink("link.txt", 42);
        let archive = encoder.finish();

        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);

        // Both should share the same inode number
        assert_eq!(entries[0].header.ino, 42);
        assert_eq!(entries[1].header.ino, 42);

        // Original has the data
        assert_eq!(entries[0].name, "original.txt");
        assert_eq!(entries[0].data, b"shared content");
        assert_eq!(entries[0].header.nlink, 2);

        // Hardlink has zero-length data
        assert_eq!(entries[1].name, "link.txt");
        assert_eq!(entries[1].data, b"");
        assert_eq!(entries[1].header.nlink, 2);
    }

    #[test]
    fn test_custom_ino() {
        let mut encoder = CpioEncoder::new();

        // Set custom inode for first file
        encoder.set_next_ino(100);
        encoder.add_file("first.txt", b"first");

        // Second file gets auto-increment (should be 101)
        encoder.add_file("second.txt", b"second");

        // Set another custom inode
        encoder.set_next_ino(500);
        encoder.add_file("third.txt", b"third");

        // Next auto-increment should be 501
        encoder.add_file("fourth.txt", b"fourth");

        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 4);

        assert_eq!(entries[0].header.ino, 100);
        assert_eq!(entries[0].name, "first.txt");

        assert_eq!(entries[1].header.ino, 101);
        assert_eq!(entries[1].name, "second.txt");

        assert_eq!(entries[2].header.ino, 500);
        assert_eq!(entries[2].name, "third.txt");

        assert_eq!(entries[3].header.ino, 501);
        assert_eq!(entries[3].name, "fourth.txt");
    }

    // C-5 #35: large file (>64KB) roundtrip
    #[test]
    fn test_roundtrip_large_file() {
        let data: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
        let mut encoder = CpioEncoder::new();
        encoder.add_file("large.bin", &data);
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "large.bin");
        assert_eq!(entries[0].data, data);
    }

    // C-5 #38: Default impl equivalence
    #[test]
    fn test_default_equals_new() {
        let from_new = CpioEncoder::new().finish();
        let from_default = CpioEncoder::default().finish();
        assert_eq!(from_new, from_default);
    }

    #[test]
    fn test_fifo_roundtrip() {
        use crate::archive::cpio::header::S_IFIFO;

        let mut encoder = CpioEncoder::new();
        encoder.add_file_with_options(
            "my_fifo",
            &[],
            &CpioEntryOptions {
                mode: S_IFIFO | 0o644,
                ..Default::default()
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "my_fifo");
        assert_eq!(entries[0].header.file_type(), S_IFIFO);
        assert_eq!(entries[0].header.mode, S_IFIFO | 0o644);
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn test_long_filename_roundtrip() {
        // Create a filename of exactly 256 bytes
        let long_name = "a".repeat(256);
        assert_eq!(long_name.len(), 256);

        let mut encoder = CpioEncoder::new();
        encoder.add_file(&long_name, b"content");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, long_name);
        assert_eq!(entries[0].data, b"content");
    }

    #[test]
    fn test_max_field_values() {
        let mut encoder = CpioEncoder::new();
        // Use a very large inode number
        encoder.set_next_ino(u32::MAX - 1);
        encoder.add_file_with_options(
            "max_fields.txt",
            b"data",
            &CpioEntryOptions {
                mode: 0o100644,
                uid: u32::MAX,
                gid: u32::MAX,
                nlink: u32::MAX,
                mtime: u32::MAX,
            },
        );
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.ino, u32::MAX - 1);
        assert_eq!(entries[0].header.uid, u32::MAX);
        assert_eq!(entries[0].header.gid, u32::MAX);
        assert_eq!(entries[0].header.nlink, u32::MAX);
        assert_eq!(entries[0].header.mtime, u32::MAX);
        assert_eq!(entries[0].data, b"data");
    }

    #[test]
    fn test_socket_roundtrip() {
        let mut encoder = CpioEncoder::new();
        encoder.add_socket("my.sock", 0o755);
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "my.sock");
        assert!(entries[0].header.is_socket());
        assert_eq!(
            entries[0].header.file_type(),
            crate::archive::cpio::header::S_IFSOCK
        );
        assert_eq!(
            entries[0].header.mode,
            crate::archive::cpio::header::S_IFSOCK | 0o755
        );
        assert!(entries[0].data.is_empty());
    }

    #[test]
    fn test_newc_check_field_zero() {
        // In newc (070701) format, the check field should always be "00000000"
        let mut encoder = CpioEncoder::new();
        encoder.add_file("file1.txt", b"hello world");
        encoder.add_file("file2.txt", b"\xff\xfe\xfd");
        let archive = encoder.finish();

        // Walk through the archive verifying each header's check field
        let mut pos = 0;
        let mut found_headers = 0;
        while pos + 110 <= archive.len() {
            let magic = &archive[pos..pos + 6];
            if magic != b"070701" {
                break;
            }
            // Check field is at offset 102..110 in the header
            let check_field = &archive[pos + 102..pos + 110];
            assert_eq!(
                check_field, b"00000000",
                "check field at header offset {pos} should be 00000000"
            );
            found_headers += 1;

            // Parse the header to advance past this entry
            let (header, header_total) =
                crate::archive::cpio::header::CpioHeader::parse(&archive[pos..]).unwrap();
            let data_start = pos + header_total;
            let data_size = header.filesize as usize;
            pos = crate::archive::cpio::header::align_to(data_start + data_size, 4);
        }
        // Should have found the 2 file headers + 1 TRAILER header = 3
        assert_eq!(found_headers, 3);
    }

    #[test]
    fn test_bin_roundtrip_single_file() {
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("test.txt", b"bin payload");
        let archive = encoder.finish();
        // Binary magic: u16 070707 little-endian
        assert_eq!(&archive[0..2], &[0xC7, 0x71]);
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].data, b"bin payload");
        assert_eq!(
            entries[0].header.format,
            crate::archive::cpio::header::CpioFormat::Bin
        );
    }

    #[test]
    fn test_bin_roundtrip_multiple_files() {
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("a.txt", b"AAA");
        encoder.add_file("b.txt", b"BBBBB");
        encoder.add_file("empty.txt", b"");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, b"AAA");
        assert_eq!(entries[1].data, b"BBBBB");
        assert_eq!(entries[2].data, b"");
    }

    #[test]
    fn test_bin_even_alignment() {
        // "odd.bin" has namesize 8 (even), data 1 byte -> one pad byte after data.
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("odd.bin", b"x");
        let archive = encoder.finish();
        // header (26) + name (8) = 34, data at 34..35, pad at 35, next header at 36
        let (h, total) = crate::archive::cpio::header::CpioHeader::parse(&archive).unwrap();
        assert_eq!(h.filesize, 1);
        assert_eq!(total, 34);
        assert_eq!(archive[35], 0);
        // next entry (TRAILER) starts at even offset 36
        assert_eq!(&archive[36..38], &[0xC7, 0x71]);
    }

    #[test]
    fn test_bin_odd_namesize_padding() {
        // name "ab" -> namesize 3 (odd) -> 1 pad byte after name
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("ab", b"dd");
        let archive = encoder.finish();
        let (h, total) = crate::archive::cpio::header::CpioHeader::parse(&archive).unwrap();
        assert_eq!(h.namesize, 3);
        assert_eq!(total, 26 + 4); // name padded to even
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].name, "ab");
        assert_eq!(entries[0].data, b"dd");
    }

    #[test]
    fn test_bin_symlink_roundtrip() {
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_symlink("link.txt", "target.txt");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert!(entries[0].header.is_symlink());
        assert_eq!(entries[0].symlink_target(), Some("target.txt"));
    }

    #[test]
    fn test_bin_device_roundtrip() {
        use crate::archive::cpio::header::S_IFCHR;
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_device("null", S_IFCHR | 0o666, 1, 3);
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].header.rdevmajor, 1);
        assert_eq!(entries[0].header.rdevminor, 3);
    }

    #[test]
    fn test_bin_big_endian_decode() {
        // Same archive bytes with all u16 fields byte-swapped (BE variant).
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("be.txt", b"BE!");
        let le = encoder.finish();
        // Swap each u16 in the 26-byte headers only (names and data are bytes).
        let mut be = le.clone();
        let mut pos = 0;
        while pos + 26 <= be.len() && be[pos] == 0xC7 && be[pos + 1] == 0x71 {
            for i in 0..13 {
                be.swap(pos + 2 * i, pos + 2 * i + 1);
            }
            let namesize = u16::from_be_bytes([be[pos + 20], be[pos + 21]]) as usize;
            let filesize = ((u16::from_be_bytes([be[pos + 22], be[pos + 23]]) as usize) << 16)
                | u16::from_be_bytes([be[pos + 24], be[pos + 25]]) as usize;
            let name_end = pos + 26 + ((namesize + 1) & !1);
            pos = name_end + ((filesize + 1) & !1);
        }
        let entries = decode::decode(&be).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "be.txt");
        assert_eq!(entries[0].data, b"BE!");
        assert_eq!(
            entries[0].header.format,
            crate::archive::cpio::header::CpioFormat::Bin
        );
    }

    #[test]
    fn test_bin_trailer_and_512_padding() {
        let mut encoder = CpioEncoder::new_bin();
        encoder.add_file("a", b"");
        let archive = encoder.finish();
        assert_eq!(archive.len() % 512, 0);
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
