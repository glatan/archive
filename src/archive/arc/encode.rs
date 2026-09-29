//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{MARKER, NAME_LEN};

/// Encoder for method-1 (obsolete unpacked), method-2 (stored) and
/// method-3 (packed/RLE90) ARC archives.
pub struct ArcEncoder {
    out: Vec<u8>,
}

impl ArcEncoder {
    pub fn new() -> Self {
        ArcEncoder { out: Vec::new() }
    }

    /// Add a stored (method-2) file entry. `name` must be a flat file
    /// name (no path separators, no NUL) of at most 12 bytes.
    /// `date`/`time` are DOS-format fields written verbatim (0 =
    /// unset).
    pub fn add_file(&mut self, name: &str, data: &[u8], date: u16, time: u16) -> Result<(), Error> {
        self.add_file_with_method(name, data, date, time, 2)
    }

    /// Add a file entry with an explicit method byte. Supported
    /// methods: `1` (obsolete unpacked — the record carries no
    /// date/time/CRC-16/length fields), `2` (stored) and `3`
    /// (packed/RLE90). Any other method is rejected with
    /// [`Error::Unsupported`]. `date`/`time` are ignored
    /// for method 1.
    pub fn add_file_with_method(
        &mut self,
        name: &str,
        data: &[u8],
        date: u16,
        time: u16,
        method: u8,
    ) -> Result<(), Error> {
        if name.is_empty()
            || name.len() > NAME_LEN - 1
            || name.contains('\0')
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Error::InvalidData("arc: bad filename"));
        }
        if method == 0 || method > 3 {
            return Err(Error::Unsupported("arc: unsupported method"));
        }
        self.out.push(MARKER);
        self.out.push(method);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        self.out.extend_from_slice(&field);
        self.out
            .extend_from_slice(&(data.len() as u32).to_le_bytes());
        if method == 1 {
            // Obsolete unpacked member: raw data follows the size
            // directly, with no date/time/CRC-16/length fields.
            self.out.extend_from_slice(data);
            return Ok(());
        }
        self.out.extend_from_slice(&date.to_le_bytes());
        self.out.extend_from_slice(&time.to_le_bytes());
        // The CRC-16 covers the uncompressed data.
        self.out
            .extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        let packed;
        let body: &[u8] = if method == 3 {
            packed = super::rle90::encode(data);
            &packed
        } else {
            data
        };
        self.out
            .extend_from_slice(&(body.len() as u32).to_le_bytes());
        self.out.extend_from_slice(body);
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
