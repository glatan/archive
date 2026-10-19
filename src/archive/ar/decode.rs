//! `ar` archive decoding (GNU and BSD dialects).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

const GLOBAL_MAGIC: &[u8; 8] = b"!<arch>\n";
const THIN_MAGIC: &[u8] = b"!<thin>\n";
const HEADER_LEN: usize = 60;

/// Parsed metadata for a single `ar` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArHeader {
    /// Modification time.
    pub mtime: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File mode (octal).
    pub mode: u32,
    /// Data size after dialect-specific name handling.
    pub size: u64,
}

/// A single `ar` archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArEntry {
    /// Parsed entry metadata.
    pub header: ArHeader,
    /// Archive filename.
    pub name: String,
    /// Entry payload.
    pub data: Vec<u8>,
    /// `true` when this entry came from a thin archive (`!<thin>\n` magic).
    /// Thin-archive regular members carry no inline payload; `data` will be
    /// empty and the caller is expected to read the file from disk.
    pub is_thin: bool,
}

impl crate::traits::ArchiveEntry for ArEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decode an `ar` archive from a byte slice.
pub fn decode(input: &[u8]) -> Result<Vec<ArEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() < GLOBAL_MAGIC.len() {
        return Err(Error::UnexpectedEof);
    }

    let is_thin = input.starts_with(THIN_MAGIC);
    if !is_thin && &input[..GLOBAL_MAGIC.len()] != GLOBAL_MAGIC {
        return Err(Error::InvalidData("ar: invalid global header"));
    }

    let mut pos = GLOBAL_MAGIC.len();
    let mut entries = Vec::new();
    let mut gnu_string_table: Option<Vec<u8>> = None;

    while pos < input.len() {
        if pos + HEADER_LEN > input.len() {
            return Err(Error::UnexpectedEof);
        }

        let header = &input[pos..pos + HEADER_LEN];
        pos += HEADER_LEN;

        if &header[58..60] != b"`\n" {
            return Err(Error::InvalidData("ar: invalid file header trailer"));
        }

        let identifier = parse_identifier(&header[..16])?;
        let mtime = parse_decimal_field(&header[16..28])?;
        let uid = parse_decimal_field(&header[28..34])? as u32;
        let gid = parse_decimal_field(&header[34..40])? as u32;
        let mode = parse_octal_field(&header[40..48])? as u32;
        let raw_size = parse_decimal_field(&header[48..58])? as usize;

        let special = identifier == "/"
            || identifier == "/SYM64/"
            || identifier == "__.SYMDEF"
            || identifier == "__.SYMDEF SORTED"
            || identifier == "//";
        // In a thin archive a regular member's data is not stored in the
        // archive; the header size field records the real file size but no
        // payload bytes (or padding) follow the header. Special members such
        // as the `//` string table and `/` symbol table still carry data.
        let stored_size = if is_thin && !special { 0 } else { raw_size };

        if pos + stored_size > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let payload = &input[pos..pos + stored_size];
        pos += stored_size;

        if stored_size % 2 == 1 {
            if pos >= input.len() {
                return Err(Error::UnexpectedEof);
            }
            if input[pos] != b'\n' {
                return Err(Error::InvalidData("ar: invalid entry padding"));
            }
            pos += 1;
        }

        if identifier == "/"
            || identifier == "/SYM64/"
            || identifier == "__.SYMDEF"
            || identifier == "__.SYMDEF SORTED"
        {
            continue;
        }
        if identifier == "//" {
            gnu_string_table = Some(payload.to_vec());
            continue;
        }

        let (name, data) = if let Some(rest) = identifier.strip_prefix("#1/") {
            let name_len = parse_decimal_str(rest)? as usize;
            if name_len > payload.len() {
                return Err(Error::InvalidData("ar: BSD long name exceeds entry size"));
            }
            let entry_data = if is_thin {
                Vec::new()
            } else {
                payload[name_len..].to_vec()
            };
            (
                String::from_utf8_lossy(&payload[..name_len]).into_owned(),
                entry_data,
            )
        } else if let Some(rest) = identifier.strip_prefix('/') {
            if !rest.is_empty() && rest.as_bytes().iter().all(u8::is_ascii_digit) {
                let table = gnu_string_table
                    .as_deref()
                    .ok_or(Error::InvalidData("ar: missing GNU string table"))?;
                let offset = parse_decimal_str(rest)? as usize;
                let entry_data = if is_thin {
                    Vec::new()
                } else {
                    payload.to_vec()
                };
                (resolve_gnu_name(table, offset)?, entry_data)
            } else {
                let entry_data = if is_thin {
                    Vec::new()
                } else {
                    payload.to_vec()
                };
                (normalize_short_name(&identifier), entry_data)
            }
        } else {
            let entry_data = if is_thin {
                Vec::new()
            } else {
                payload.to_vec()
            };
            (normalize_short_name(&identifier), entry_data)
        };

        entries.push(ArEntry {
            header: ArHeader {
                mtime,
                uid,
                gid,
                mode,
                size: if is_thin {
                    raw_size as u64
                } else {
                    data.len() as u64
                },
            },
            name,
            data,
            is_thin,
        });
    }

    Ok(entries)
}

#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> Result<Vec<ArEntry>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

fn parse_identifier(field: &[u8]) -> Result<String, Error> {
    let trimmed = trim_ascii_spaces(field);
    if trimmed.is_empty() {
        return Err(Error::InvalidData("ar: empty file identifier"));
    }
    Ok(String::from_utf8_lossy(trimmed).into_owned())
}

fn normalize_short_name(name: &str) -> String {
    if name.ends_with('/') && name != "/" && name != "//" {
        name[..name.len() - 1].to_string()
    } else {
        name.to_string()
    }
}

fn resolve_gnu_name(table: &[u8], offset: usize) -> Result<String, Error> {
    if offset >= table.len() {
        return Err(Error::InvalidData("ar: GNU name offset out of range"));
    }
    let slice = &table[offset..];
    let mut end = None;
    for i in 0..slice.len() {
        if slice[i] == b'\n' && i > 0 && slice[i - 1] == b'/' {
            end = Some(i - 1);
            break;
        }
    }
    let end = end.unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
}

fn parse_decimal_field(field: &[u8]) -> Result<u64, Error> {
    let trimmed = trim_ascii_spaces(field);
    if trimmed.is_empty() {
        return Ok(0);
    }
    let value = core::str::from_utf8(trimmed)
        .map_err(|_| Error::InvalidData("ar: invalid decimal field"))?;
    parse_decimal_str(value)
}

fn parse_decimal_str(value: &str) -> Result<u64, Error> {
    value
        .parse::<u64>()
        .map_err(|_| Error::InvalidData("ar: invalid decimal field"))
}

fn parse_octal_field(field: &[u8]) -> Result<u64, Error> {
    let trimmed = trim_ascii_spaces(field);
    if trimmed.is_empty() {
        return Ok(0);
    }
    let value =
        core::str::from_utf8(trimmed).map_err(|_| Error::InvalidData("ar: invalid octal field"))?;
    u64::from_str_radix(value, 8).map_err(|_| Error::InvalidData("ar: invalid octal field"))
}

fn trim_ascii_spaces(field: &[u8]) -> &[u8] {
    let mut end = field.len();
    while end > 0 && field[end - 1] == b' ' {
        end -= 1;
    }
    &field[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_header(buf: &mut Vec<u8>, name: &str, size: usize) {
        let mut field = [b' '; HEADER_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        field[16..28].copy_from_slice(b"0           ");
        field[28..34].copy_from_slice(b"0     ");
        field[34..40].copy_from_slice(b"0     ");
        field[40..48].copy_from_slice(b"100644  ");
        let size_str = alloc::format!("{size}");
        field[48..48 + size_str.len()].copy_from_slice(size_str.as_bytes());
        field[58..60].copy_from_slice(b"`\n");
        buf.extend_from_slice(&field);
    }

    #[test]
    fn test_decode_empty_input() {
        assert!(decode(&[]).unwrap().is_empty());
    }

    #[test]
    fn test_decode_short_gnu_archive() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);
        push_header(&mut archive, "hello.txt/", 5);
        archive.extend_from_slice(b"hello");
        archive.push(b'\n');

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn test_decode_gnu_string_table() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);

        let table = b"very_long_filename.txt/\n";
        push_header(&mut archive, "//", table.len());
        archive.extend_from_slice(table);

        push_header(&mut archive, "/0", 4);
        archive.extend_from_slice(b"data");

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "very_long_filename.txt");
        assert_eq!(entries[0].data, b"data");
    }

    #[test]
    fn test_decode_bsd_long_name() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);

        let name = b"this_is_a_long_name.txt";
        let data = b"payload";
        push_header(&mut archive, "#1/23", name.len() + data.len());
        archive.extend_from_slice(name);
        archive.extend_from_slice(data);

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "this_is_a_long_name.txt");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_decode_odd_sized_entry_padding() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);

        push_header(&mut archive, "odd.txt/", 3);
        archive.extend_from_slice(b"abc");
        archive.push(b'\n');

        push_header(&mut archive, "next.txt/", 2);
        archive.extend_from_slice(b"de");

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "odd.txt");
        assert_eq!(entries[0].data, b"abc");
        assert_eq!(entries[1].name, "next.txt");
        assert_eq!(entries[1].data, b"de");
    }

    #[test]
    fn test_decode_missing_string_table_rejected() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);
        push_header(&mut archive, "/42", 1);
        archive.push(b'x');
        archive.push(b'\n');

        let result = decode(&archive);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_sym64_symbol_table_skipped() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);

        // Add a /SYM64/ symbol table entry — should be skipped.
        let sym_data = b"fake_sym64_data!";
        push_header(&mut archive, "/SYM64/", sym_data.len());
        archive.extend_from_slice(sym_data);

        // Add a regular entry that should be returned.
        push_header(&mut archive, "real.txt/", 4);
        archive.extend_from_slice(b"data");

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "real.txt");
        assert_eq!(entries[0].data, b"data");
    }

    #[test]
    fn test_thin_archive_decode() {
        let mut archive = Vec::new();
        archive.extend_from_slice(THIN_MAGIC);

        // A regular member in a thin archive: the header records the real
        // file size but no payload bytes follow the header.
        push_header(&mut archive, "foo.o/", 6);
        push_header(&mut archive, "bar.o/", 4);

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "foo.o");
        assert!(entries[0].is_thin);
        assert!(entries[0].data.is_empty());
        // size should reflect the original member size from the header.
        assert_eq!(entries[0].header.size, 6);
        assert_eq!(entries[1].name, "bar.o");
        assert_eq!(entries[1].header.size, 4);
    }

    #[test]
    fn test_regular_archive_not_thin() {
        let mut archive = Vec::new();
        archive.extend_from_slice(GLOBAL_MAGIC);

        push_header(&mut archive, "bar.o/", 4);
        archive.extend_from_slice(b"DATA");

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bar.o");
        assert!(!entries[0].is_thin);
        assert_eq!(entries[0].data, b"DATA");
    }

    #[test]
    fn test_archive_entry_trait() {
        use crate::traits::ArchiveEntry;
        let mut enc = crate::archive::ar::encode::ArEncoder::new();
        enc.add_file("hello.txt", b"Hello!");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
    }

    #[test]
    fn test_archive_codec_decode_roundtrip() {
        use crate::archive::ar::{ArArchiveEncoder, ArCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ArArchiveEncoder::new();
        encoder.add_file("hello.txt", b"Hello!");
        encoder.add_file("world.txt", b"World!");
        let archive = <ArArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ArCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"Hello!");
        assert_eq!(entries[1].name(), "world.txt");
        assert_eq!(entries[1].data(), b"World!");
    }

    #[test]
    fn test_archive_entry_empty_data() {
        use crate::archive::ar::{ArArchiveEncoder, ArCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ArArchiveEncoder::new();
        encoder.add_file("empty.txt", b"");
        let archive = <ArArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ArCodec;
        let entries = codec.decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "empty.txt");
        assert_eq!(entries[0].data(), b"");
    }

    #[test]
    fn test_archive_multiple_entries() {
        use crate::archive::ar::{ArArchiveEncoder, ArCodec};
        use crate::traits::{ArchiveDecode, ArchiveEncode, ArchiveEntry};

        let mut encoder = ArArchiveEncoder::new();
        for i in 0..12 {
            let name = alloc::format!("file_{i}.txt");
            let data = alloc::format!("Content of file {i}");
            encoder.add_file(&name, data.as_bytes());
        }
        let archive = <ArArchiveEncoder as ArchiveEncode>::finish(encoder).unwrap();

        let codec = ArCodec;
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
    fn test_decode_truncated_prefix_invariant() {
        // ar has no archive terminator, so a cut at a member boundary
        // (or right after the global header) decodes to a valid prefix
        // of the entries; every other cut must fail. Invariant:
        // decode(prefix) is Err or a prefix of the full entry list.
        let mut encoder = crate::archive::ar::encode::ArEncoder::new();
        encoder.add_file("t.txt", b"ar truncation sweep payload");
        encoder.add_file("odd.bin", b"odd-sized");
        encoder.add_file("third", b"3");
        let archive = encoder.finish().unwrap();
        let full = decode(&archive).unwrap();
        for cut in 0..archive.len() {
            if let Ok(prefix) = decode(&archive[..cut]) {
                assert!(
                    prefix.len() <= full.len()
                        && full
                            .iter()
                            .zip(prefix.iter())
                            .all(|(a, b)| a.name == b.name && a.data == b.data),
                    "cut={cut}: entries must be a prefix of the full list"
                );
            }
        }
    }
}
