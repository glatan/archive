//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{MARKER, NAME_LEN};

/// Encoder for method-2 (stored) ARC archives.
pub struct ArcEncoder {
    out: Vec<u8>,
}

impl ArcEncoder {
    pub fn new() -> Self {
        ArcEncoder { out: Vec::new() }
    }

    /// Add a stored file entry. `name` must be a flat file name (no
    /// path separators, no NUL) of at most 12 bytes. `date`/`time` are
    /// DOS-format fields written verbatim (0 = unset).
    pub fn add_file(&mut self, name: &str, data: &[u8], date: u16, time: u16) -> Result<(), Error> {
        if name.is_empty()
            || name.len() > NAME_LEN - 1
            || name.contains('\0')
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Error::InvalidData("arc: bad filename"));
        }
        self.out.push(MARKER);
        self.out.push(2);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        self.out.extend_from_slice(&field);
        self.out
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&date.to_le_bytes());
        self.out.extend_from_slice(&time.to_le_bytes());
        self.out
            .extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        self.out
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.out.extend_from_slice(data);
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(&[MARKER, 0]);
        self.out
    }
}

impl Default for ArcEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a method-2 ARC archive from `(name, data)` pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut e = ArcEncoder::new();
    for (name, data) in files {
        e.add_file(name, data, 0, 0)?;
    }
    Ok(e.finish())
}
