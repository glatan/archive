//! cpio archive decoding (`odc`, SVR4 `newc`, and `newcrc` formats).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

use super::header::{CpioHeader, align4};

/// A single entry in a cpio archive.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode, decode};
///
/// let mut enc = encode::CpioEncoder::new();
/// enc.add_file("hello.txt", b"Hello!");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries[0].name, "hello.txt");
/// assert_eq!(entries[0].data, b"Hello!");
/// ```
#[derive(Debug, Clone)]
pub struct CpioEntry {
    /// Parsed header metadata.
    pub header: CpioHeader,
    /// Filename.
    pub name: String,
    /// File data. For symlinks, this contains the link target path.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for CpioEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl CpioEntry {
    /// Returns `true` if this entry is a hard link (nlink > 1 and data is empty).
    ///
    /// In cpio archives, hard links share the same inode number. The first
    /// entry with that inode carries the file data, while subsequent entries
    /// (the hard links) have empty data.
    ///
    /// This method does not panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use archive::archive::cpio::{encode::{CpioEncoder, CpioEntryOptions}, decode};
    /// let mut enc = CpioEncoder::new();
    /// enc.set_next_ino(10);
    /// enc.add_file_with_options("original.txt", b"data", &CpioEntryOptions {
    ///     nlink: 2,
    ///     ..Default::default()
    /// });
    /// enc.add_hardlink("link.txt", 10);
    /// let entries = decode::decode(&enc.finish()).unwrap();
    /// assert!(!entries[0].is_hard_link()); // has data
    /// assert!(entries[1].is_hard_link());  // nlink > 1 and empty data
    /// ```
    pub const fn is_hard_link(&self) -> bool {
        self.header.nlink > 1 && self.data.is_empty()
    }

    /// For symlink entries, returns the link target path.
    ///
    /// Returns `None` for non-symlink entries or if the target is not valid UTF-8.
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
    /// assert_eq!(entries[0].symlink_target(), Some("target"));
    /// ```
    pub fn symlink_target(&self) -> Option<&str> {
        if self.header.is_symlink() {
            core::str::from_utf8(&self.data).ok()
        } else {
            None
        }
    }
}

/// Group entries by inode + device, returning only groups with more than one entry.
///
/// Each group is a `Vec` of indices into the input slice. Within each group,
/// the first index is the entry carrying the file data (the "original"),
/// and subsequent indices are hard links.
///
/// Uses [`alloc::collections::BTreeMap`] for `no_std` compatibility.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode::{CpioEncoder, CpioEntryOptions}, decode};
///
/// let mut enc = CpioEncoder::new();
/// enc.set_next_ino(5);
/// enc.add_file_with_options("original.txt", b"data", &CpioEntryOptions {
///     nlink: 2,
///     ..Default::default()
/// });
/// enc.add_hardlink("link.txt", 5);
/// enc.add_file("other.txt", b"other");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// let groups = decode::find_hard_link_groups(&entries);
/// assert_eq!(groups.len(), 1);
/// assert_eq!(groups[0], vec![0, 1]);
/// ```
pub fn find_hard_link_groups(entries: &[CpioEntry]) -> Vec<Vec<usize>> {
    let mut map: BTreeMap<(u32, u32, u32), Vec<usize>> = BTreeMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        let key = (
            entry.header.ino,
            entry.header.devmajor,
            entry.header.devminor,
        );
        map.entry(key).or_default().push(idx);
    }
    map.into_values().filter(|group| group.len() > 1).collect()
}

/// Trailer filename that marks the end of the cpio archive.
const TRAILER: &str = "TRAILER!!!";

/// Decode a cpio archive (`odc`, SVR4 `newc`, or `newcrc`) from a byte slice.
///
/// For "newcrc" (070702) entries, verifies the checksum against the data.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode, decode};
///
/// let mut enc = encode::CpioEncoder::new();
/// enc.add_file("a.txt", b"aaa");
/// let entries = decode::decode(&enc.finish()).unwrap();
/// assert_eq!(entries.len(), 1);
/// ```
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] if the archive is truncated,
/// [`Error::InvalidData`] for bad magic numbers or CRC mismatches.
pub fn decode(input: &[u8]) -> Result<Vec<CpioEntry>, Error> {
    let mut entries = Vec::new();
    let mut pos = 0;
    let mut saw_trailer = false;

    loop {
        if pos >= input.len() {
            break;
        }

        let (header, header_total) = CpioHeader::parse(&input[pos..])?;

        // Extract filename (namesize includes null terminator)
        let name_start = pos + header.format.header_size();
        let name_len = header.namesize as usize;
        if name_start + name_len > input.len() {
            return Err(Error::UnexpectedEof);
        }
        if input[name_start + name_len - 1] != 0 {
            return Err(Error::InvalidData(
                "cpio namesize must include a trailing null terminator",
            ));
        }
        // Strip null terminator
        let name_end = name_start + name_len - 1;
        let name = String::from_utf8_lossy(&input[name_start..name_end]).into_owned();

        // Check for trailer
        if name == TRAILER {
            saw_trailer = true;
            break;
        }

        // File data starts after header + name (aligned to 4 bytes)
        let data_start = pos + header_total;
        let data_size = header.filesize as usize;
        if data_start + data_size > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let data = input[data_start..data_start + data_size].to_vec();

        // Verify CRC for newcrc (070702) format
        if header.is_crc {
            let actual: u32 = data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            if actual != header.check {
                return Err(Error::ChecksumMismatch {
                    expected: header.check,
                    actual,
                });
            }
        } else if header.check != 0 {
            return Err(Error::InvalidData("cpio newc check field must be zero"));
        }

        // Next entry starts after data. Only newc/newcrc use 4-byte padding.
        pos = if header.format.uses_align4() {
            align4(data_start + data_size)
        } else {
            data_start + data_size
        };

        entries.push(CpioEntry { header, name, data });
    }

    if !entries.is_empty() && !saw_trailer {
        return Err(Error::InvalidData("cpio archive missing TRAILER!!! entry"));
    }

    Ok(entries)
}

/// Decode a cpio archive from a [`std::io::Read`] source.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if reading from the source fails, or if the data is malformed.
///
/// # Examples
///
/// ```
/// use archive::archive::cpio::{encode, decode};
///
/// let mut enc = encode::CpioEncoder::new();
/// enc.add_file("a.txt", b"data");
/// let cpio = enc.finish();
/// let entries = decode::decode_reader(cpio.as_slice()).unwrap();
/// assert_eq!(entries.len(), 1);
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(
    mut reader: R,
) -> Result<Vec<CpioEntry>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::cpio::encode::CpioEncoder;

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("test.txt", b"Hello, cpio!");
        let archive = encoder.finish();
        let cursor = std::io::Cursor::new(&archive);
        let entries = decode_reader(cursor).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "test.txt");
        assert_eq!(entries[0].data, b"Hello, cpio!");
    }

    // C-5 #31: empty input
    #[test]
    fn test_decode_empty_input() {
        let entries = decode(&[]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_entry_order_preserved() {
        let names = ["echo", "alpha", "zulu", "mike", "bravo"];
        let mut encoder = CpioEncoder::new();
        for &name in &names {
            let filename = alloc::format!("{name}.txt");
            let content = alloc::format!("content of {name}");
            encoder.add_file(&filename, content.as_bytes());
        }
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 5);
        for (i, &name) in names.iter().enumerate() {
            let expected_name = alloc::format!("{name}.txt");
            assert_eq!(
                entries[i].name, expected_name,
                "entry {i} should be {expected_name}, got {}",
                entries[i].name
            );
            let expected_content = alloc::format!("content of {name}");
            assert_eq!(entries[i].data, expected_content.as_bytes());
        }
    }

    #[test]
    fn test_newc_nonzero_check_rejected() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("test.txt", b"Hello, cpio!");
        let mut archive = encoder.finish();
        archive[102..110].copy_from_slice(b"00000001");

        let err = decode(&archive).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidData("cpio newc check field must be zero")
        ));
    }

    #[test]
    fn test_missing_trailer_rejected() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("test.txt", b"Hello, cpio!");
        let archive = encoder.finish();

        let (header, header_total) =
            crate::archive::cpio::header::CpioHeader::parse(&archive).unwrap();
        let entry_end = align4(header_total + header.filesize as usize);
        let truncated = &archive[..entry_end];
        let err = decode(truncated).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidData("cpio archive missing TRAILER!!! entry")
        ));
    }

    #[test]
    fn test_decode_trailer_only_archive() {
        let archive = CpioEncoder::new().finish();
        let entries = decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_decode_manual_odc_archive() {
        let mut archive = Vec::new();
        archive.extend_from_slice(
            alloc::format!(
                "{}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                "070707",
                0u32,
                1u32,
                0o100644u32,
                0u32,
                0u32,
                1u32,
                0u32,
                0u32,
                11u32,
                5u32
            )
            .as_bytes(),
        );
        archive.extend_from_slice(b"sample.txt\0");
        archive.extend_from_slice(b"hello");
        archive.extend_from_slice(
            alloc::format!(
                "{}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                "070707",
                0u32,
                0u32,
                0u32,
                0u32,
                0u32,
                1u32,
                0u32,
                0u32,
                11u32,
                0u32
            )
            .as_bytes(),
        );
        archive.extend_from_slice(b"TRAILER!!!\0");

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sample.txt");
        assert_eq!(entries[0].data, b"hello");
        assert_eq!(
            entries[0].header.format,
            crate::archive::cpio::header::CpioFormat::Odc
        );
    }

    #[test]
    fn test_decode_odc_without_newc_padding() {
        let mut encoder = CpioEncoder::new_odc();
        encoder.add_file("a", b"1");
        encoder.add_file("bbb", b"22");
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[0].data, b"1");
        assert_eq!(entries[1].name, "bbb");
        assert_eq!(entries[1].data, b"22");
    }

    #[test]
    fn test_is_hard_link() {
        let mut encoder = CpioEncoder::new();
        encoder.set_next_ino(10);
        encoder.add_file_with_options(
            "original.txt",
            b"shared data",
            &crate::archive::cpio::encode::CpioEntryOptions {
                nlink: 2,
                ..Default::default()
            },
        );
        encoder.add_hardlink("link.txt", 10);
        // A regular file (nlink=1) should not be a hard link
        encoder.add_file("regular.txt", b"solo");
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();

        assert_eq!(entries.len(), 3);
        // Original has data, so is_hard_link() returns false even though nlink > 1
        assert!(
            !entries[0].is_hard_link(),
            "original with data is not a hard link"
        );
        // Hard link entry: nlink > 1 and data is empty
        assert!(
            entries[1].is_hard_link(),
            "entry with nlink > 1 and empty data is a hard link"
        );
        // Regular file: nlink == 1
        assert!(
            !entries[2].is_hard_link(),
            "regular file (nlink=1) is not a hard link"
        );
    }

    #[test]
    fn test_find_hard_link_groups() {
        let mut encoder = CpioEncoder::new();
        // Group A: inode 20, two entries
        encoder.set_next_ino(20);
        encoder.add_file_with_options(
            "a_orig.txt",
            b"group a data",
            &crate::archive::cpio::encode::CpioEntryOptions {
                nlink: 2,
                ..Default::default()
            },
        );
        encoder.add_hardlink("a_link.txt", 20);
        // Unrelated file
        encoder.add_file("solo.txt", b"alone");
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();

        let groups = find_hard_link_groups(&entries);
        assert_eq!(groups.len(), 1, "expected exactly one hard link group");
        // The group must contain exactly indices 0 and 1
        let mut group = groups[0].clone();
        group.sort_unstable();
        assert_eq!(group, vec![0, 1]);
    }

    #[test]
    fn test_find_hard_link_groups_no_links() {
        let mut encoder = CpioEncoder::new();
        encoder.add_file("a.txt", b"aaa");
        encoder.add_file("b.txt", b"bbb");
        encoder.add_file("c.txt", b"ccc");
        let archive = encoder.finish();
        let entries = decode(&archive).unwrap();

        let groups = find_hard_link_groups(&entries);
        assert!(
            groups.is_empty(),
            "no hard link groups expected for regular files"
        );
    }

    #[test]
    fn test_archive_entry_trait() {
        use crate::traits::ArchiveEntry;
        let mut enc = CpioEncoder::new();
        enc.add_file("hello.txt", b"Hello!");
        let entries = decode(&enc.finish()).unwrap();
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
    }

    #[test]
    fn test_archive_codec_decode_roundtrip() {
        use crate::archive::cpio::{CpioArchiveEncoder, CpioCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = CpioArchiveEncoder::new();
        encoder.add_file("hello.txt", b"Hello!");
        encoder.add_file("world.txt", b"World!");
        let archive = <CpioArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = CpioCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
        assert_eq!(entries[1].name(), "world.txt");
        assert_eq!(entries[1].data(), b"World!");
    }

    #[test]
    fn test_archive_entry_empty_data() {
        use crate::archive::cpio::{CpioArchiveEncoder, CpioCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = CpioArchiveEncoder::new();
        encoder.add_file("empty.txt", b"");
        let archive = <CpioArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = CpioCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "empty.txt");
        assert_eq!(entries[0].data(), b"");
    }

    #[test]
    fn test_archive_multiple_entries() {
        use crate::archive::cpio::{CpioArchiveEncoder, CpioCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = CpioArchiveEncoder::new();
        for i in 0..12 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            encoder.add_file(&name, data.as_bytes());
        }
        let archive = <CpioArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = CpioCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 12);
        for (i, entry) in entries.iter().enumerate() {
            let expected_name = alloc::format!("file_{i}.txt");
            let expected_data = alloc::format!("Content of file {i}");
            assert_eq!(entry.name(), expected_name);
            assert_eq!(entry.data(), expected_data.as_bytes());
        }
    }

    #[test]
    fn test_missing_name_null_terminator_rejected() {
        let mut archive = Vec::new();
        archive.extend_from_slice(b"070701");
        archive.extend_from_slice(b"00000001");
        archive.extend_from_slice(b"000081A4");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000001");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"00000004");
        archive.extend_from_slice(b"00000000");
        archive.extend_from_slice(b"bad!");

        let err = decode(&archive).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidData(msg) if msg.contains("trailing null terminator")
        ));
    }
}
