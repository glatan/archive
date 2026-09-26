//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{BASIC_HDR_SIZE, SIG};

/// Encoder for method-0 (stored) ARJ archives.
pub struct ArjEncoder {
    out: Vec<u8>,
    main_written: bool,
}

impl ArjEncoder {
    pub fn new() -> Self {
        ArjEncoder {
            out: Vec::new(),
            main_written: false,
        }
    }

    fn write_header(&mut self, fixed: &[u8; BASIC_HDR_SIZE], name: &str, comment: &str) {
        let mut body = Vec::new();
        body.extend_from_slice(fixed);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(comment.as_bytes());
        body.push(0);
        self.out.extend_from_slice(&SIG);
        self.out
            .extend_from_slice(&(body.len() as u16).to_le_bytes());
        self.out.extend_from_slice(&body);
        self.out
            .extend_from_slice(&crate::util::crc32::crc32(&body).to_le_bytes());
        self.out.extend_from_slice(&0u16.to_le_bytes()); // no ext header
    }

    fn ensure_main(&mut self) {
        if self.main_written {
            return;
        }
        self.main_written = true;
        let mut fixed = [0u8; BASIC_HDR_SIZE];
        fixed[0] = BASIC_HDR_SIZE as u8; // first_hdr_size
        fixed[1] = 10; // archiver version (ARJ 2.x)
        fixed[2] = 1; // min version to extract
        fixed[3] = 2; // host OS: unix
        fixed[4] = 0x10; // flags: backup-type (per spec, plain archives use 0x10)
        // fixed[5] file_type for main header = 0; time fields 0.
        self.write_header(&fixed, "", "");
    }

    /// Add a stored (method 0) file entry. `mtime` is written verbatim
    /// as the DOS-format timestamp (0 = unset).
    pub fn add_file(&mut self, name: &str, data: &[u8], mtime: u32) -> Result<(), Error> {
        if name.is_empty() || name.contains('\0') || name.len() > u16::MAX as usize - BASIC_HDR_SIZE
        {
            return Err(Error::InvalidData("arj: bad filename"));
        }
        self.ensure_main();
        let mut fixed = [0u8; BASIC_HDR_SIZE];
        fixed[0] = BASIC_HDR_SIZE as u8;
        fixed[1] = 10;
        fixed[2] = 1;
        fixed[3] = 2;
        fixed[4] = 0x10;
        fixed[5] = 0; // method 0: stored
        fixed[6] = 0; // file type: binary
        fixed[8..12].copy_from_slice(&mtime.to_le_bytes());
        fixed[12..16].copy_from_slice(&crate::util::crc32::crc32(data).to_le_bytes());
        fixed[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
        fixed[20..24].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.write_header(&fixed, name, "");
        self.out.extend_from_slice(data);
        Ok(())
    }

    /// Add a directory entry (file type 3, method 0, no payload).
    pub fn add_dir(&mut self, name: &str, mtime: u32) -> Result<(), Error> {
        if name.is_empty() || name.contains('\0') {
            return Err(Error::InvalidData("arj: bad filename"));
        }
        self.ensure_main();
        let mut fixed = [0u8; BASIC_HDR_SIZE];
        fixed[0] = BASIC_HDR_SIZE as u8;
        fixed[1] = 10;
        fixed[2] = 1;
        fixed[3] = 2;
        fixed[4] = 0x10;
        fixed[6] = 3; // directory
        fixed[8..12].copy_from_slice(&mtime.to_le_bytes());
        self.write_header(&fixed, name, "");
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.ensure_main();
        self.out.extend_from_slice(&SIG);
        self.out.extend_from_slice(&0u16.to_le_bytes()); // end of archive
        self.out
    }
}

impl Default for ArjEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a method-0 ARJ archive from `(name, data)` pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut e = ArjEncoder::new();
    for (name, data) in files {
        e.add_file(name, data, 0)?;
    }
    Ok(e.finish())
}
