//! tar header parsing (UStar 512-byte blocks).

use alloc::vec::Vec;

use crate::error::Error;

/// Size of a tar header/block in bytes.
pub const BLOCK_SIZE: usize = 512;

/// Tar file type indicator from the typeflag field.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::header::FileType;
///
/// let ft = FileType::Regular;
/// assert_ne!(ft, FileType::Directory);
/// ```
///
/// This type does not panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file (typeflag `'0'` or `'\0'`).
    Regular,
    /// Hard link (typeflag `'1'`).
    HardLink,
    /// Symbolic link (typeflag `'2'`).
    SymLink,
    /// Character device (typeflag `'3'`).
    CharDevice,
    /// Block device (typeflag `'4'`).
    BlockDevice,
    /// Directory (typeflag `'5'`).
    Directory,
    /// FIFO / named pipe (typeflag `'6'`).
    Fifo,
    /// Contiguous file (typeflag `'7'`).
    Contiguous,
    /// Extended header (PAX).
    PaxHeader,
    /// Global extended header (PAX).
    PaxGlobalHeader,
    /// GNU long name.
    GnuLongName,
    /// GNU long link.
    GnuLongLink,
    /// GNU sparse file (typeflag `'S'`).
    GnuSparse,
    /// Other/unknown type.
    Other(u8),
}

impl FileType {
    /// Parse a file type from the tar type flag byte.
    const fn from_byte(b: u8) -> Self {
        match b {
            0 | b'0' => FileType::Regular,
            b'1' => FileType::HardLink,
            b'2' => FileType::SymLink,
            b'3' => FileType::CharDevice,
            b'4' => FileType::BlockDevice,
            b'5' => FileType::Directory,
            b'6' => FileType::Fifo,
            b'7' => FileType::Contiguous,
            b'x' => FileType::PaxHeader,
            b'g' => FileType::PaxGlobalHeader,
            b'L' => FileType::GnuLongName,
            b'K' => FileType::GnuLongLink,
            b'S' => FileType::GnuSparse,
            other => FileType::Other(other),
        }
    }
}

/// Parsed tar header (UStar format).
///
/// Contains metadata extracted from a 512-byte tar header block.
///
/// This type does not panic.
///
/// # Examples
///
/// ```
/// use archive::archive::tar::{encode, decode};
///
/// let mut enc = encode::TarEncoder::new();
/// enc.add_file("test.txt", b"data");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries[0].header.name, "test.txt");
/// assert_eq!(entries[0].header.size, 4);
/// ```
#[derive(Debug, Clone)]
pub struct TarHeader {
    /// File name (up to 100 bytes, or prefix + name for UStar).
    pub name: alloc::string::String,
    /// File mode (octal).
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Modification time (Unix timestamp, seconds).
    ///
    /// PAX attributes may set this to a negative value for pre-1970 timestamps.
    pub mtime: i64,
    /// Modification time nanosecond fraction (0-999_999_999).
    ///
    /// Populated from PAX `mtime` attribute when it contains a decimal point
    /// (e.g., `"1234567890.123456789"`). Zero if no fractional part is present.
    pub mtime_nsec: u32,
    /// Access time (Unix timestamp, seconds). Populated from PAX `atime` attribute.
    pub atime: i64,
    /// Access time nanosecond fraction (0-999_999_999).
    pub atime_nsec: u32,
    /// Status change time (Unix timestamp, seconds). Populated from PAX `ctime` attribute.
    pub ctime: i64,
    /// Status change time nanosecond fraction (0-999_999_999).
    pub ctime_nsec: u32,
    /// File type.
    pub file_type: FileType,
    /// Link target name.
    pub link_name: alloc::string::String,
    /// Owner user name.
    pub uname: alloc::string::String,
    /// Owner group name.
    pub gname: alloc::string::String,
    /// Device major number (for character/block devices).
    pub devmajor: u32,
    /// Device minor number (for character/block devices).
    pub devminor: u32,
    /// Sparse file extents as `(offset, length)` pairs.
    ///
    /// When present, `data` in the decoded entry contains the condensed payload
    /// (concatenated non-hole segments) and `size` stores the logical file size.
    pub sparse_map: Vec<(u64, u64)>,
    /// PAX `charset` keyword value.
    pub pax_charset: Option<alloc::string::String>,
    /// PAX `comment` keyword value.
    pub pax_comment: Option<alloc::string::String>,
    /// PAX `hdrcharset` keyword value.
    pub pax_hdrcharset: Option<alloc::string::String>,
    /// Whether the GNU sparse header has an extended sparse header following.
    pub(crate) _gnu_sparse_extended: bool,
    /// The on-tape data size for GNU sparse files.
    pub(crate) _gnu_sparse_data_size: u64,
}

impl TarHeader {
    /// Parse a tar header from a 512-byte block.
    ///
    /// This method does not panic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidData`] for zero blocks (EOF marker) or
    /// checksum mismatches.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::tar::{encode, decode, header::{BLOCK_SIZE, TarHeader}};
    ///
    /// let mut enc = encode::TarEncoder::new();
    /// enc.add_file("a.txt", b"hello");
    /// let tar = enc.finish();
    /// let block: &[u8; BLOCK_SIZE] = tar[..BLOCK_SIZE].try_into().unwrap();
    /// let header = TarHeader::parse(block).unwrap();
    /// assert_eq!(header.name, "a.txt");
    /// ```
    pub fn parse(block: &[u8; BLOCK_SIZE]) -> Result<Self, Error> {
        // Check if this is a zero block (EOF marker)
        if block.iter().all(|&b| b == 0) {
            return Err(Error::InvalidData("zero block"));
        }

        // Verify checksum
        verify_checksum(block)?;

        let name_raw = parse_str(&block[0..100]);
        let mode = parse_octal(&block[100..108])?;
        let uid = parse_octal(&block[108..116])?;
        let gid = parse_octal(&block[116..124])?;
        let size = parse_octal_u64(&block[124..136])?;
        let mtime = i64::try_from(parse_octal_u64(&block[136..148])?)
            .map_err(|_| Error::InvalidData("mtime out of range"))?;
        let file_type = FileType::from_byte(block[156]);
        let link_name = parse_str(&block[157..257]);

        // Check for UStar format
        // The POSIX.1-2001 spec requires version "00" (bytes 263-264), but many
        // tar implementations write non-standard versions (e.g., spaces or other
        // values), so we accept any version for compatibility.
        let is_ustar = &block[257..263] == b"ustar\0" || &block[257..263] == b"ustar ";
        let prefix = if is_ustar {
            parse_str(&block[345..500])
        } else {
            alloc::string::String::new()
        };
        let uname = if is_ustar {
            parse_str(&block[265..297])
        } else {
            alloc::string::String::new()
        };
        let gname = if is_ustar {
            parse_str(&block[297..329])
        } else {
            alloc::string::String::new()
        };
        let devmajor = if is_ustar {
            parse_octal(&block[329..337]).unwrap_or(0)
        } else {
            0
        };
        let devminor = if is_ustar {
            parse_octal(&block[337..345]).unwrap_or(0)
        } else {
            0
        };

        // Combine prefix and name for UStar
        let name = if !prefix.is_empty() {
            alloc::format!("{prefix}/{name_raw}")
        } else {
            name_raw
        };

        // Handle GNU sparse (typeflag 'S')
        let mut sparse_map = Vec::new();
        let mut gnu_sparse_extended = false;
        let mut gnu_sparse_data_size = 0u64;
        let mut final_size = size;

        if file_type == FileType::GnuSparse {
            // Parse 4 sparse entries from header bytes 386-481
            // Each entry: 12 bytes offset (octal) + 12 bytes numbytes (octal)
            sparse_map = parse_gnu_sparse_entries(&block[386..482]);
            // isextended flag at byte 482
            gnu_sparse_extended = block[482] != 0;
            // realsize from bytes 483-494 (12 bytes, octal)
            let realsize = parse_octal_u64(&block[483..495])?;
            // The on-tape data size is the original 'size' field
            gnu_sparse_data_size = size;
            // The logical file size is realsize
            final_size = realsize;
        }

        Ok(TarHeader {
            name,
            mode,
            uid,
            gid,
            size: final_size,
            mtime,
            mtime_nsec: 0,
            atime: 0,
            atime_nsec: 0,
            ctime: 0,
            ctime_nsec: 0,
            file_type,
            link_name,
            uname,
            gname,
            devmajor,
            devminor,
            sparse_map,
            pax_charset: None,
            pax_comment: None,
            pax_hdrcharset: None,
            _gnu_sparse_extended: gnu_sparse_extended,
            _gnu_sparse_data_size: gnu_sparse_data_size,
        })
    }
}

/// Verify the tar header checksum.
fn verify_checksum(block: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
    let stored = parse_octal(&block[148..156])?;

    // Calculate checksum: sum of all bytes, treating checksum field as spaces
    let mut sum = 0u32;
    for (i, &byte) in block.iter().enumerate() {
        if (148..156).contains(&i) {
            sum += b' ' as u32;
        } else {
            sum += byte as u32;
        }
    }

    if sum != stored {
        // Also try signed checksum (some old implementations)
        let mut signed_sum = 0i32;
        for (i, &byte) in block.iter().enumerate() {
            if (148..156).contains(&i) {
                signed_sum += b' ' as i32;
            } else {
                signed_sum += (byte as i8) as i32;
            }
        }
        if signed_sum as u32 != stored {
            return Err(Error::ChecksumMismatch {
                expected: stored,
                actual: sum,
            });
        }
    }

    Ok(())
}

/// Parse a null-terminated or space-padded string from a tar field.
fn parse_str(field: &[u8]) -> alloc::string::String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let s = &field[..end];
    // Trim trailing spaces
    let trimmed = match s.iter().rposition(|&b| b != b' ') {
        Some(pos) => &s[..=pos],
        None => &[],
    };
    alloc::string::String::from_utf8_lossy(trimmed).into_owned()
}

/// Parse an octal ASCII number field (u32).
fn parse_octal(field: &[u8]) -> Result<u32, Error> {
    parse_octal_u64(field).map(|v| v as u32)
}

/// Parse GNU sparse entries from a 96-byte region (4 entries, 24 bytes each).
///
/// Each entry is 12 bytes of octal offset followed by 12 bytes of octal numbytes.
/// Entries with both offset and numbytes equal to zero are skipped.
fn parse_gnu_sparse_entries(data: &[u8]) -> Vec<(u64, u64)> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i + 24 <= data.len() {
        let offset = parse_octal_u64(&data[i..i + 12]).unwrap_or(0);
        let numbytes = parse_octal_u64(&data[i + 12..i + 24]).unwrap_or(0);
        if offset == 0 && numbytes == 0 {
            i += 24;
            continue;
        }
        entries.push((offset, numbytes));
        i += 24;
    }
    entries
}

/// Parse an octal ASCII number field (u64).
fn parse_octal_u64(field: &[u8]) -> Result<u64, Error> {
    // Handle binary encoding (base-256) for large values
    if !field.is_empty() && field[0] & 0x80 != 0 {
        // Binary encoding: big-endian, first bit is sign
        let mut value = 0u64;
        for &b in &field[1..] {
            value = (value << 8) | b as u64;
        }
        return Ok(value);
    }

    let s = parse_str(field);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(&s, 8).map_err(|_| Error::InvalidData("invalid octal field in tar header"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::tar::encode::TarEncoder;

    fn first_header_block(archive: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block.copy_from_slice(&archive[..BLOCK_SIZE]);
        block
    }

    #[test]
    fn test_parse_octal() {
        assert_eq!(parse_octal(b"000644 \0").unwrap(), 0o644);
        assert_eq!(parse_octal(b"0000000\0").unwrap(), 0);
        assert_eq!(parse_octal_u64(b"00000000123\0").unwrap(), 0o123);
    }

    #[test]
    fn test_parse_str() {
        assert_eq!(parse_str(b"hello\0\0\0"), "hello");
        assert_eq!(parse_str(b"hello   "), "hello");
        assert_eq!(parse_str(b"\0\0\0"), "");
    }

    #[test]
    fn test_file_type() {
        assert_eq!(FileType::from_byte(b'0'), FileType::Regular);
        assert_eq!(FileType::from_byte(0), FileType::Regular);
        assert_eq!(FileType::from_byte(b'1'), FileType::HardLink);
        assert_eq!(FileType::from_byte(b'2'), FileType::SymLink);
        assert_eq!(FileType::from_byte(b'3'), FileType::CharDevice);
        assert_eq!(FileType::from_byte(b'4'), FileType::BlockDevice);
        assert_eq!(FileType::from_byte(b'5'), FileType::Directory);
        assert_eq!(FileType::from_byte(b'6'), FileType::Fifo);
        assert_eq!(FileType::from_byte(b'x'), FileType::PaxHeader);
        assert_eq!(FileType::from_byte(b'g'), FileType::PaxGlobalHeader);
        assert_eq!(FileType::from_byte(b'L'), FileType::GnuLongName);
        assert_eq!(FileType::from_byte(b'K'), FileType::GnuLongLink);
        assert_eq!(FileType::from_byte(b'7'), FileType::Contiguous);
        assert_eq!(FileType::from_byte(b'S'), FileType::GnuSparse);
        assert_eq!(FileType::from_byte(b'9'), FileType::Other(b'9'));
    }

    // Phase 1: Error detection

    #[test]
    fn test_tar_header_checksum_mismatch() {
        // Build a valid header using TarEncoder, then corrupt data
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"data");
        let archive = encoder.finish();
        // Get the first 512-byte block (header)
        let mut block = first_header_block(&archive);
        // Corrupt the name field (changes actual checksum but stored remains)
        block[0] = b'X';
        block[1] = b'Y';
        block[2] = b'Z';
        let result = TarHeader::parse(&block);
        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_tar_header_parse_direct() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"data");
        let archive = encoder.finish();
        let block = first_header_block(&archive);

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.name, "test.txt");
        assert_eq!(header.size, 4);
        assert_eq!(header.file_type, FileType::Regular);
    }

    #[test]
    fn test_tar_header_signed_checksum_fallback() {
        let mut encoder = TarEncoder::new();
        encoder.add_file("café.txt", b"data");
        let archive = encoder.finish();
        let mut block = first_header_block(&archive);

        let signed_sum: i32 = block
            .iter()
            .enumerate()
            .map(|(i, &byte)| {
                if (148..156).contains(&i) {
                    b' ' as i32
                } else {
                    (byte as i8) as i32
                }
            })
            .sum();
        block[148..156].fill(0);
        let encoded = alloc::format!("{signed_sum:06o}\0 ");
        block[148..156].copy_from_slice(encoded.as_bytes());

        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.name, "café.txt");
        assert_eq!(header.size, 4);
    }

    #[test]
    fn test_tar_header_ustar_prefix_parse_direct() {
        let long_path = format!("{}/{}", "dir".repeat(30), "nested-file.txt");
        let mut encoder = TarEncoder::new();
        encoder.add_file(&long_path, b"payload");
        let archive = encoder.finish();
        let block = first_header_block(&archive);

        assert_eq!(&block[257..263], b"ustar\0");
        let header = TarHeader::parse(&block).unwrap();
        assert_eq!(header.name, long_path);
        assert_eq!(header.size, 7);
    }

    // Phase 4: Binary size encoding

    #[test]
    fn test_binary_size_encoding() {
        // Binary encoding: first byte has bit 7 set, rest is big-endian value
        let mut field = [0u8; 12];
        field[0] = 0x80; // binary flag
        field[11] = 42; // value = 42
        let size = parse_octal_u64(&field).unwrap();
        assert_eq!(size, 42);

        // Larger value
        let mut field2 = [0u8; 12];
        field2[0] = 0x80;
        // Encode 0x1_0000_0000 (4GB+) in big-endian in bytes 1..12
        field2[7] = 0x01;
        let size2 = parse_octal_u64(&field2).unwrap();
        assert_eq!(size2, 0x01_0000_0000);
    }

    #[test]
    fn test_owner_group_names() {
        use crate::archive::tar::decode;
        use crate::archive::tar::encode::TarEncoder;

        let mut encoder = TarEncoder::new();
        encoder.add_file("test.txt", b"hello");
        let archive = encoder.finish();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].header.uname, "");
        assert_eq!(entries[0].header.gname, "");
    }
}
