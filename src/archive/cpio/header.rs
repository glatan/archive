//! cpio header parsing (`odc`, SVR4 `newc`, `newcrc`, and `bin` formats).

use crate::error::Error;

/// Magic number for SVR4 "newc" cpio format.
pub(crate) const NEWC_MAGIC: &[u8; 6] = b"070701";

/// Magic number for SVR4 "newcrc" cpio format (with CRC).
pub(crate) const NEWCRC_MAGIC: &[u8; 6] = b"070702";

/// Magic number for POSIX/SUSv2 portable ASCII "odc" cpio format.
pub(crate) const ODC_MAGIC: &[u8; 6] = b"070707";

/// Magic number for SVR4 binary "bin" cpio format (u16 field, octal 070707).
pub(crate) const BIN_MAGIC: u16 = 0o070707;

/// Size of the newc header in bytes.
pub(crate) const HEADER_SIZE: usize = 110;

/// Size of the odc header in bytes.
pub(crate) const ODC_HEADER_SIZE: usize = 76;

/// Size of the binary header in bytes (thirteen u16 fields).
pub(crate) const BIN_HEADER_SIZE: usize = 26;

// Unix file type mode bits
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// FIFO (named pipe).
pub const S_IFIFO: u32 = 0o010000;
/// Socket.
pub const S_IFSOCK: u32 = 0o140000;
/// Mask for file type bits.
pub const S_IFMT: u32 = 0o170000;

/// Supported cpio header format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioFormat {
    /// POSIX portable ASCII format with octal fields and no per-entry padding.
    Odc,
    /// SVR4 new ASCII format with hexadecimal fields.
    Newc,
    /// SVR4 CRC variant with hexadecimal fields and checksum.
    Newcrc,
    /// SVR4 binary format with 16-bit fields and 2-byte alignment.
    Bin,
}

impl CpioFormat {
    /// Fixed header size.
    pub(crate) const fn header_size(self) -> usize {
        match self {
            Self::Odc => ODC_HEADER_SIZE,
            Self::Newc | Self::Newcrc => HEADER_SIZE,
            Self::Bin => BIN_HEADER_SIZE,
        }
    }

    /// Byte alignment applied after each entry's name and file data.
    ///
    /// `odc` has no padding, `bin` pads to even offsets, and `newc`/`newcrc`
    /// pad to 4-byte boundaries.
    pub(crate) const fn alignment(self) -> usize {
        match self {
            Self::Odc => 1,
            Self::Bin => 2,
            Self::Newc | Self::Newcrc => 4,
        }
    }

    /// Whether this format carries a checksum field.
    pub const fn is_crc(self) -> bool {
        matches!(self, Self::Newcrc)
    }
}

/// Parsed cpio header (SVR4 "newc" / "newcrc" format).
///
/// Contains metadata extracted from a 110-byte cpio header.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode, decode};
/// let mut enc = encode::CpioEncoder::new();
/// enc.add_file("test.txt", b"data");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries[0].header.filesize, 4);
/// ```
#[derive(Debug, Clone)]
pub struct CpioHeader {
    /// Inode number.
    pub ino: u32,
    /// File mode and permissions.
    pub mode: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Modification time.
    pub mtime: u32,
    /// File size.
    pub filesize: u32,
    /// Device major number (of the file's device).
    pub devmajor: u32,
    /// Device minor number.
    pub devminor: u32,
    /// Device major number (for special files).
    pub rdevmajor: u32,
    /// Device minor number (for special files).
    pub rdevminor: u32,
    /// Length of the filename (including null terminator).
    pub namesize: u32,
    /// Checksum (0 for "newc", sum of data bytes for "newcrc").
    pub check: u32,
    /// Whether this entry uses the CRC format ("070702").
    pub is_crc: bool,
    /// Header format used by this entry.
    pub format: CpioFormat,
}

impl CpioHeader {
    /// Returns the file type bits extracted from the mode field (masked with [`S_IFMT`]).
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode, header::S_IFREG};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_file("a.txt", b"");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert_eq!(entries[0].header.file_type(), S_IFREG);
    /// ```
    pub const fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }

    /// Returns true if this entry is a symlink.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_symlink("link", "target");
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert!(entries[0].header.is_symlink());
    /// ```
    pub const fn is_symlink(&self) -> bool {
        self.file_type() == S_IFLNK
    }

    /// Returns true if this entry is a directory.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_directory("dir", 0o755);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert!(entries[0].header.is_directory());
    /// ```
    pub const fn is_directory(&self) -> bool {
        self.file_type() == S_IFDIR
    }

    /// Returns true if this entry is a socket.
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
    pub const fn is_socket(&self) -> bool {
        self.file_type() == S_IFSOCK
    }

    /// Parse a cpio header from the given data.
    ///
    /// Returns the header and the total number of bytes consumed
    /// (header + filename + padding). Supports both "newc" (070701) and
    /// "newcrc" (070702) formats.
    ///
    /// This method does not panic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if data is shorter than 110 bytes,
    /// [`Error::InvalidData`] for unrecognized magic numbers or malformed hex fields.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode, decode, header::CpioHeader};
    /// let mut enc = encode::CpioEncoder::new();
    /// enc.add_file("test.txt", b"data");
    /// let cpio = enc.finish();
    /// let (header, _consumed) = CpioHeader::parse(&cpio).unwrap();
    /// assert_eq!(header.filesize, 4);
    /// ```
    pub fn parse(data: &[u8]) -> Result<(Self, usize), Error> {
        if data.len() < 6 {
            return Err(Error::UnexpectedEof);
        }

        // The binary format stores the magic as a u16 whose byte order is
        // determined by observing the magic itself (FreeBSD cpio(5), "New
        // Binary Format").
        let bin_le = if data[0..2] == BIN_MAGIC.to_le_bytes() {
            Some(true)
        } else if data[0..2] == BIN_MAGIC.to_be_bytes() {
            Some(false)
        } else {
            None
        };

        let format = if bin_le.is_some() {
            CpioFormat::Bin
        } else if &data[0..6] == NEWC_MAGIC {
            CpioFormat::Newc
        } else if &data[0..6] == NEWCRC_MAGIC {
            CpioFormat::Newcrc
        } else if &data[0..6] == ODC_MAGIC {
            CpioFormat::Odc
        } else {
            return Err(Error::InvalidData("invalid cpio magic number"));
        };

        if data.len() < format.header_size() {
            return Err(Error::UnexpectedEof);
        }

        let header = match format {
            CpioFormat::Bin => {
                let little = bin_le == Some(true);
                let u16_at = |i: usize| -> u16 {
                    let b = [data[i], data[i + 1]];
                    if little {
                        u16::from_le_bytes(b)
                    } else {
                        u16::from_be_bytes(b)
                    }
                };
                // 32-bit fields are stored as two u16s, most significant
                // word first.
                let u32_at =
                    |i: usize| -> u32 { (u32::from(u16_at(i)) << 16) | u32::from(u16_at(i + 2)) };
                let dev = u32::from(u16_at(2));
                let rdev = u32::from(u16_at(14));
                CpioHeader {
                    ino: u32::from(u16_at(4)),
                    mode: u32::from(u16_at(6)),
                    uid: u32::from(u16_at(8)),
                    gid: u32::from(u16_at(10)),
                    nlink: u32::from(u16_at(12)),
                    mtime: u32_at(16),
                    filesize: u32_at(22),
                    devmajor: (dev >> 8) & 0xFF,
                    devminor: dev & 0xFF,
                    rdevmajor: (rdev >> 8) & 0xFF,
                    rdevminor: rdev & 0xFF,
                    namesize: u32::from(u16_at(20)),
                    check: 0,
                    is_crc: false,
                    format,
                }
            }
            CpioFormat::Odc => {
                let dev = parse_octal_field(&data[6..12])?;
                let rdev = parse_octal_field(&data[42..48])?;
                CpioHeader {
                    ino: parse_octal_field(&data[12..18])?,
                    mode: parse_octal_field(&data[18..24])?,
                    uid: parse_octal_field(&data[24..30])?,
                    gid: parse_octal_field(&data[30..36])?,
                    nlink: parse_octal_field(&data[36..42])?,
                    mtime: parse_octal_field(&data[48..59])?,
                    filesize: parse_octal_field(&data[65..76])?,
                    devmajor: dev,
                    devminor: 0,
                    rdevmajor: (rdev >> 8) & 0xFF,
                    rdevminor: rdev & 0xFF,
                    namesize: parse_octal_field(&data[59..65])?,
                    check: 0,
                    is_crc: false,
                    format,
                }
            }
            CpioFormat::Newc | CpioFormat::Newcrc => CpioHeader {
                ino: parse_hex_field(&data[6..14])?,
                mode: parse_hex_field(&data[14..22])?,
                uid: parse_hex_field(&data[22..30])?,
                gid: parse_hex_field(&data[30..38])?,
                nlink: parse_hex_field(&data[38..46])?,
                mtime: parse_hex_field(&data[46..54])?,
                filesize: parse_hex_field(&data[54..62])?,
                devmajor: parse_hex_field(&data[62..70])?,
                devminor: parse_hex_field(&data[70..78])?,
                rdevmajor: parse_hex_field(&data[78..86])?,
                rdevminor: parse_hex_field(&data[86..94])?,
                namesize: parse_hex_field(&data[94..102])?,
                check: parse_hex_field(&data[102..110])?,
                is_crc: format.is_crc(),
                format,
            },
        };

        if header.namesize == 0 {
            return Err(Error::InvalidData(
                "cpio namesize must include a null terminator",
            ));
        }

        // Total consumed: header + filename, plus name padding.
        let name_offset = format.header_size();
        let name_end = name_offset + header.namesize as usize;
        let total = align_to(name_end, format.alignment());

        Ok((header, total))
    }
}

/// Parse an 8-character hexadecimal ASCII field.
fn parse_hex_field(field: &[u8]) -> Result<u32, Error> {
    let s = core::str::from_utf8(field)
        .map_err(|_| Error::InvalidData("invalid UTF-8 in cpio header field"))?;
    u32::from_str_radix(s, 16).map_err(|_| Error::InvalidData("invalid hex field in cpio header"))
}

/// Parse a fixed-width octal ASCII field.
fn parse_octal_field(field: &[u8]) -> Result<u32, Error> {
    let s = core::str::from_utf8(field)
        .map_err(|_| Error::InvalidData("invalid UTF-8 in cpio header field"))?;
    u32::from_str_radix(s, 8).map_err(|_| Error::InvalidData("invalid octal field in cpio header"))
}

/// Round up to the next `boundary`-byte boundary.
pub(crate) const fn align_to(n: usize, boundary: usize) -> usize {
    (n + boundary - 1) & !(boundary - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_field() {
        assert_eq!(parse_hex_field(b"00000000").unwrap(), 0);
        assert_eq!(parse_hex_field(b"000000FF").unwrap(), 255);
        assert_eq!(parse_hex_field(b"DEADBEEF").unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_parse_octal_field() {
        assert_eq!(parse_octal_field(b"000000").unwrap(), 0);
        assert_eq!(parse_octal_field(b"000377").unwrap(), 255);
        assert_eq!(parse_octal_field(b"777777").unwrap(), 0o777777);
    }

    #[test]
    fn test_align_to() {
        assert_eq!(align_to(0, 4), 0);
        assert_eq!(align_to(1, 4), 4);
        assert_eq!(align_to(4, 4), 4);
        assert_eq!(align_to(5, 4), 8);
        assert_eq!(align_to(110, 4), 112);
        assert_eq!(align_to(3, 2), 4);
        assert_eq!(align_to(4, 2), 4);
        assert_eq!(align_to(5, 1), 5);
    }

    // Phase 1: Error detection

    #[test]
    fn test_invalid_cpio_magic() {
        // "070703" is not a valid magic (valid is "070701" or "070702")
        let mut data = [0u8; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070703");
        for b in &mut data[6..HEADER_SIZE] {
            *b = b'0';
        }
        let result = CpioHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_cpio_header_too_short() {
        let data = [0u8; 5];
        let result = CpioHeader::parse(&data);
        assert!(matches!(result, Err(Error::UnexpectedEof)));
    }

    #[test]
    fn test_cpio_newcrc_magic_accepted() {
        // "070702" (newcrc) should be accepted
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070702");
        // namesize must be at least 1 for null terminator
        data[94..102].copy_from_slice(b"00000001");
        let result = CpioHeader::parse(&data);
        assert!(result.is_ok());
        let (header, _) = result.unwrap();
        assert!(header.is_crc);
    }

    #[test]
    fn test_cpio_newc_magic_accepted() {
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070701");
        data[94..102].copy_from_slice(b"00000001");
        let result = CpioHeader::parse(&data);
        assert!(result.is_ok());
        let (header, _) = result.unwrap();
        assert_eq!(header.format, CpioFormat::Newc);
        assert!(!header.is_crc);
    }

    #[test]
    fn test_cpio_odc_magic_accepted() {
        let mut data = [b'0'; ODC_HEADER_SIZE];
        data[0..6].copy_from_slice(b"070707");
        data[59..65].copy_from_slice(b"000001");
        let result = CpioHeader::parse(&data);
        assert!(result.is_ok());
        let (header, consumed) = result.unwrap();
        assert_eq!(header.format, CpioFormat::Odc);
        assert!(!header.is_crc);
        assert_eq!(consumed, ODC_HEADER_SIZE + 1);
    }

    #[test]
    fn test_cpio_file_type_helpers() {
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070701");
        data[94..102].copy_from_slice(b"00000001");

        // Regular file: S_IFREG | 0644 = 0o100644 = 0x81A4
        data[14..22].copy_from_slice(b"000081A4");
        let (h, _) = CpioHeader::parse(&data).unwrap();
        assert_eq!(h.file_type(), S_IFREG);
        assert!(!h.is_symlink());
        assert!(!h.is_directory());

        // Symlink: S_IFLNK | 0777 = 0o120777 = 0xA1FF
        data[14..22].copy_from_slice(b"0000A1FF");
        let (h, _) = CpioHeader::parse(&data).unwrap();
        assert_eq!(h.file_type(), S_IFLNK);
        assert!(h.is_symlink());

        // Directory: S_IFDIR | 0755 = 0o040755 = 0x41ED
        data[14..22].copy_from_slice(b"000041ED");
        let (h, _) = CpioHeader::parse(&data).unwrap();
        assert_eq!(h.file_type(), S_IFDIR);
        assert!(h.is_directory());
    }

    #[test]
    fn test_invalid_hex_field() {
        // A header with invalid hex characters in a field
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070701");
        data[94..102].copy_from_slice(b"00000001");
        // Corrupt the ino field with non-hex chars
        data[6..14].copy_from_slice(b"0000GGGG");
        let result = CpioHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_parse_hex_field_lowercase() {
        // parse_hex_field should handle lowercase hex digits (a-f) just as
        // well as uppercase, since u32::from_str_radix(s, 16) accepts both.
        assert_eq!(parse_hex_field(b"0000000a").unwrap(), 10);
        assert_eq!(parse_hex_field(b"000000ff").unwrap(), 255);
        assert_eq!(parse_hex_field(b"deadbeef").unwrap(), 0xDEADBEEF);
        assert_eq!(parse_hex_field(b"abcdef01").unwrap(), 0xABCDEF01);

        // Also verify a full header with lowercase hex fields parses correctly.
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070701");
        // mode: 0x000081a4 in lowercase
        data[14..22].copy_from_slice(b"000081a4");
        // namesize: 1 (null terminator only)
        data[94..102].copy_from_slice(b"00000001");
        let (header, _) = CpioHeader::parse(&data).unwrap();
        assert_eq!(header.mode, 0x000081A4);
    }

    #[test]
    fn test_invalid_octal_field() {
        let mut data = [b'0'; ODC_HEADER_SIZE];
        data[0..6].copy_from_slice(b"070707");
        data[12..18].copy_from_slice(b"00000x");
        data[59..65].copy_from_slice(b"000001");
        let result = CpioHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_cpio_namesize_zero() {
        let mut data = [b'0'; HEADER_SIZE];
        data[0..6].copy_from_slice(b"070701");
        data[94..102].copy_from_slice(b"00000000"); // namesize = 0
        let result = CpioHeader::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    fn bin_header(fields: &[(usize, u16)], little: bool) -> Vec<u8> {
        let mut h = vec![0u8; BIN_HEADER_SIZE];
        let magic = if little {
            BIN_MAGIC.to_le_bytes()
        } else {
            BIN_MAGIC.to_be_bytes()
        };
        h[0..2].copy_from_slice(&magic);
        for (off, v) in fields {
            let b = if little {
                v.to_le_bytes()
            } else {
                v.to_be_bytes()
            };
            h[*off..*off + 2].copy_from_slice(&b);
        }
        h
    }

    #[test]
    fn test_cpio_bin_parse_le() {
        // namesize=1, mode S_IFREG|0644, mtime 0x0001_0002, filesize 0x0003_0004
        let h = bin_header(
            &[
                (4, 7),
                (6, 0o100644),
                (8, 1000),
                (10, 100),
                (12, 1),
                (16, 1),
                (18, 2),
                (20, 1),
                (22, 3),
                (24, 4),
            ],
            true,
        );
        let (header, consumed) = CpioHeader::parse(&h).unwrap();
        assert_eq!(header.format, CpioFormat::Bin);
        assert_eq!(header.ino, 7);
        assert_eq!(header.mode, 0o100644);
        assert_eq!(header.file_type(), S_IFREG);
        assert_eq!(header.uid, 1000);
        assert_eq!(header.gid, 100);
        assert_eq!(header.nlink, 1);
        assert_eq!(header.mtime, 0x0001_0002);
        assert_eq!(header.filesize, 0x0003_0004);
        assert_eq!(header.namesize, 1);
        assert!(!header.is_crc);
        assert_eq!(consumed, BIN_HEADER_SIZE + 2); // name + even pad
    }

    #[test]
    fn test_cpio_bin_parse_be() {
        // Same header byte-swapped per u16 field: big-endian variant.
        let h = bin_header(
            &[
                (4, 7),
                (6, 0o100644),
                (16, 1),
                (18, 2),
                (20, 1),
                (22, 3),
                (24, 4),
            ],
            false,
        );
        assert_eq!(&h[0..2], &[0x71, 0xC7]);
        let (header, _) = CpioHeader::parse(&h).unwrap();
        assert_eq!(header.format, CpioFormat::Bin);
        assert_eq!(header.ino, 7);
        assert_eq!(header.mtime, 0x0001_0002);
        assert_eq!(header.filesize, 0x0003_0004);
    }

    #[test]
    fn test_cpio_bin_dev_rdev_split() {
        // dev=0x0308 -> major 3 minor 8; rdev=0x0103 -> major 1 minor 3
        let h = bin_header(&[(2, 0x0308), (14, 0x0103), (20, 1)], true);
        let (header, _) = CpioHeader::parse(&h).unwrap();
        assert_eq!(header.devmajor, 3);
        assert_eq!(header.devminor, 8);
        assert_eq!(header.rdevmajor, 1);
        assert_eq!(header.rdevminor, 3);
    }
}
