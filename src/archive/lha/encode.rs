//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

/// Encoder for header-level-0 `-lh0-` (stored) archives.
pub struct LhaEncoder {
    out: Vec<u8>,
}

impl LhaEncoder {
    pub fn new() -> Self {
        LhaEncoder { out: Vec::new() }
    }

    /// Add a stored file entry. `name` must be 1-255 bytes of UTF-8 and
    /// contain no NUL. `mtime` is written verbatim as the DOS-format
    /// timestamp field (0 is a valid "unset" value).
    pub fn add_file(&mut self, name: &str, data: &[u8], mtime: u32) -> Result<(), Error> {
        if name.is_empty() || name.len() > 255 || name.contains('\0') {
            return Err(Error::InvalidData("lha: bad filename"));
        }
        // hdr_size counts method..crc16 inclusive.
        let hsize = 5 + 4 + 4 + 4 + 1 + 1 + 1 + name.len() + 2;
        if hsize > u8::MAX as usize {
            return Err(Error::InvalidData("lha: header too large"));
        }
        let mut hdr = Vec::with_capacity(hsize + 2);
        hdr.push(hsize as u8);
        hdr.push(0); // checksum placeholder
        hdr.extend_from_slice(b"-lh0-");
        hdr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(data.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&mtime.to_le_bytes());
        hdr.push(0x20); // attribute
        hdr.push(0); // level 0
        hdr.push(name.len() as u8);
        hdr.extend_from_slice(name.as_bytes());
        hdr.extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        hdr[1] = hdr[2..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(data);
        Ok(())
    }

    /// Add a `-lhd-` directory marker (no payload).
    pub fn add_dir(&mut self, name: &str, mtime: u32) -> Result<(), Error> {
        if name.is_empty() || name.len() > 255 || name.contains('\0') {
            return Err(Error::InvalidData("lha: bad filename"));
        }
        let hsize = 5 + 4 + 4 + 4 + 1 + 1 + 1 + name.len() + 2;
        let mut hdr = Vec::with_capacity(hsize + 2);
        hdr.push(hsize as u8);
        hdr.push(0);
        hdr.extend_from_slice(b"-lhd-");
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&mtime.to_le_bytes());
        hdr.push(0x20);
        hdr.push(0);
        hdr.push(name.len() as u8);
        hdr.extend_from_slice(name.as_bytes());
        hdr.extend_from_slice(&0u16.to_le_bytes());
        hdr[1] = hdr[2..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        self.out.extend_from_slice(&hdr);
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out.push(0); // end-of-archive mark
        self.out
    }
}

impl Default for LhaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a level-0 `-lh0-` archive from `(name, data)` pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut e = LhaEncoder::new();
    for (name, data) in files {
        e.add_file(name, data, 0)?;
    }
    Ok(e.finish())
}
