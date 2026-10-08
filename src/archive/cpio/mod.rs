//! cpio archive format (`odc`, SVR4 `newc`, `newcrc`, and `bin`).
//!
//! Supports portable ASCII `odc` (070707), `newc` (070701), `newcrc` (070702), and binary `bin`.
//! The encoder can produce archives with regular files, symlinks, directories,
//! device files, sockets, and hardlinks.

use alloc::vec::Vec;

use crate::error::Error;

/// cpio archive decoding.
pub mod decode;
/// cpio archive encoding.
pub mod encode;
/// cpio header parsing.
pub mod header;

/// Codec struct for trait-based cpio decode operations.
pub struct CpioCodec;

impl crate::traits::ArchiveDecode for CpioCodec {
    type Entry = decode::CpioEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}

/// Encoder struct for trait-based cpio encode operations.
pub struct CpioArchiveEncoder {
    inner: encode::CpioEncoder,
}

impl CpioArchiveEncoder {
    /// Create a new trait-based cpio encoder (newc format).
    pub const fn new() -> Self {
        Self {
            inner: encode::CpioEncoder::new(),
        }
    }
}

impl Default for CpioArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for CpioArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.inner.finish())
    }
}
