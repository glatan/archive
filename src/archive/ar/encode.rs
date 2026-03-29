//! `ar` archive encoding (GNU and BSD dialects).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

use super::decode::ArEntry;

const GLOBAL_MAGIC: &[u8; 8] = b"!<arch>\n";

/// ar filename encoding dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ArDialect {
    /// GNU `ar` long-name table (`//` + `/offset`) dialect.
    #[default]
    Gnu,
    /// BSD `ar` `#1/<len>` long-name dialect.
    Bsd,
}

/// Metadata for an encoded `ar` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArEntryOptions {
    /// Modification time.
    pub mtime: u64,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// File mode (octal).
    pub mode: u32,
}

impl Default for ArEntryOptions {
    fn default() -> Self {
        Self {
            mtime: 0,
            uid: 0,
            gid: 0,
            mode: 0o100644,
        }
    }
}

/// Builder for creating `ar` archives.
#[derive(Debug, Default)]
pub struct ArEncoder {
    entries: Vec<PendingEntry>,
    dialect: ArDialect,
}

#[derive(Debug)]
struct PendingEntry {
    name: String,
    data: Vec<u8>,
    options: ArEntryOptions,
}

impl ArEncoder {
    /// Create a GNU-dialect encoder.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            dialect: ArDialect::Gnu,
        }
    }

    /// Create a BSD-dialect encoder.
    pub const fn new_bsd() -> Self {
        Self {
            entries: Vec::new(),
            dialect: ArDialect::Bsd,
        }
    }

    /// Return the dialect used by this encoder.
    pub const fn dialect(&self) -> ArDialect {
        self.dialect
    }

    /// Add a regular file entry with default metadata.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_options(name, data, &ArEntryOptions::default());
    }

    /// Add a regular file entry with explicit metadata.
    pub fn add_file_with_options(&mut self, name: &str, data: &[u8], options: &ArEntryOptions) {
        self.entries.push(PendingEntry {
            name: name.to_string(),
            data: data.to_vec(),
            options: options.clone(),
        });
    }

    /// Add an entry previously decoded from another archive.
    pub fn add_entry(&mut self, entry: &ArEntry) {
        self.entries.push(PendingEntry {
            name: entry.name.clone(),
            data: entry.data.clone(),
            options: ArEntryOptions {
                mtime: entry.header.mtime,
                uid: entry.header.uid,
                gid: entry.header.gid,
                mode: entry.header.mode,
            },
        });
    }

    /// Finish the archive and return its serialized bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        output.extend_from_slice(GLOBAL_MAGIC);
        match self.dialect {
            ArDialect::Gnu => encode_gnu_entries(&mut output, &self.entries)?,
            ArDialect::Bsd => encode_bsd_entries(&mut output, &self.entries)?,
        }
        Ok(output)
    }
}

fn encode_gnu_entries(output: &mut Vec<u8>, entries: &[PendingEntry]) -> Result<(), Error> {
    let mut string_table = Vec::new();
    let mut offsets = Vec::with_capacity(entries.len());

    for entry in entries {
        validate_name(&entry.name)?;
        if requires_gnu_long_name(&entry.name) {
            let offset = string_table.len();
            string_table.extend_from_slice(entry.name.as_bytes());
            string_table.extend_from_slice(b"/\n");
            offsets.push(Some(offset));
        } else {
            offsets.push(None);
        }
    }

    if !string_table.is_empty() {
        write_header(output, "//", 0, 0, 0, 0, string_table.len())?;
        output.extend_from_slice(&string_table);
        if string_table.len() % 2 == 1 {
            output.push(b'\n');
        }
    }

    for (entry, offset) in entries.iter().zip(offsets) {
        let identifier = if let Some(offset) = offset {
            alloc::format!("/{offset}")
        } else {
            alloc::format!("{}/", entry.name)
        };
        write_header(
            output,
            &identifier,
            entry.options.mtime,
            entry.options.uid,
            entry.options.gid,
            entry.options.mode,
            entry.data.len(),
        )?;
        output.extend_from_slice(&entry.data);
        if entry.data.len() % 2 == 1 {
            output.push(b'\n');
        }
    }

    Ok(())
}

fn encode_bsd_entries(output: &mut Vec<u8>, entries: &[PendingEntry]) -> Result<(), Error> {
    for entry in entries {
        validate_name(&entry.name)?;
        let use_long = requires_bsd_long_name(&entry.name);
        let encoded_size = if use_long {
            entry.name.len() + entry.data.len()
        } else {
            entry.data.len()
        };
        let identifier = if use_long {
            alloc::format!("#1/{}", entry.name.len())
        } else {
            entry.name.clone()
        };

        write_header(
            output,
            &identifier,
            entry.options.mtime,
            entry.options.uid,
            entry.options.gid,
            entry.options.mode,
            encoded_size,
        )?;
        if use_long {
            output.extend_from_slice(entry.name.as_bytes());
        }
        output.extend_from_slice(&entry.data);
        if encoded_size % 2 == 1 {
            output.push(b'\n');
        }
    }
    Ok(())
}

fn write_header(
    output: &mut Vec<u8>,
    identifier: &str,
    mtime: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: usize,
) -> Result<(), Error> {
    write_field(output, identifier, 16)?;
    write_field(output, &alloc::format!("{mtime}"), 12)?;
    write_field(output, &alloc::format!("{uid}"), 6)?;
    write_field(output, &alloc::format!("{gid}"), 6)?;
    write_field(output, &alloc::format!("{mode:o}"), 8)?;
    write_field(output, &alloc::format!("{size}"), 10)?;
    output.extend_from_slice(b"`\n");
    Ok(())
}

fn write_field(output: &mut Vec<u8>, value: &str, width: usize) -> Result<(), Error> {
    if value.len() > width {
        return Err(Error::InvalidData("ar: field width overflow"));
    }
    output.extend_from_slice(value.as_bytes());
    output.extend(core::iter::repeat_n(b' ', width - value.len()));
    Ok(())
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidData("ar: empty file name"));
    }
    if name.contains('\n') {
        return Err(Error::InvalidData("ar: newline in file name"));
    }
    Ok(())
}

fn requires_gnu_long_name(name: &str) -> bool {
    name.len() > 15 || name.contains(' ')
}

fn requires_bsd_long_name(name: &str) -> bool {
    name.len() >= 16 || name.contains(' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ar::decode;

    #[test]
    fn test_roundtrip_gnu_short_name() {
        let mut encoder = ArEncoder::new();
        encoder.add_file("hello.txt", b"Hello!");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"Hello!");
    }

    #[test]
    fn test_roundtrip_gnu_long_name() {
        let mut encoder = ArEncoder::new();
        encoder.add_file("very long filename.txt", b"abc");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].name, "very long filename.txt");
        assert_eq!(entries[0].data, b"abc");
    }

    #[test]
    fn test_roundtrip_bsd_long_name() {
        let mut encoder = ArEncoder::new_bsd();
        encoder.add_file("this_is_a_long_name.txt", b"payload");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].name, "this_is_a_long_name.txt");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_roundtrip_bsd_exact_16_byte_name() {
        let mut encoder = ArEncoder::new_bsd();
        encoder.add_file("sixteen_byte_nam", b"payload");
        let archive = encoder.finish().unwrap();
        let entries = decode::decode(&archive).unwrap();
        assert_eq!(entries[0].name, "sixteen_byte_nam");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn test_empty_name_rejected() {
        let mut encoder = ArEncoder::new();
        encoder.add_file("", b"x");
        let result = encoder.finish();
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }
}
