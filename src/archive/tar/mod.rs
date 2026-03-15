//! tar archive format.
//!
//! Supports UStar format with both GNU and PAX extension modes:
//!
//! - **GNU mode** (`TarFormat::Gnu`, the default): handles long
//!   filenames via UStar prefix splitting or GNU LongName/LongLink extension
//!   headers, and uses binary size encoding for files larger than 8 GB.
//!
//! - **PAX mode** (`TarFormat::Pax`): uses POSIX.1-2001 extended
//!   headers for long paths, signed nanosecond timestamps (`mtime`, `atime`, `ctime`),
//!   large uid/gid values, and GNU sparse metadata (`GNU.sparse.*`).
//!
//! The decoder automatically recognises GNU and PAX extensions regardless of
//! which mode the encoder uses.

use alloc::vec::Vec;

use crate::error::Error;

/// tar archive decoding.
pub mod decode;
/// tar archive encoding.
pub mod encode;
/// tar header parsing (UStar 512-byte blocks).
pub mod header;

/// Codec struct for trait-based tar decode operations.
pub struct TarCodec;

impl crate::traits::ArchiveDecode for TarCodec {
    type Entry = decode::TarEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}

/// Encoder struct for trait-based tar encode operations.
pub struct TarArchiveEncoder {
    inner: encode::TarEncoder,
}

impl TarArchiveEncoder {
    /// Create a new trait-based tar encoder (GNU mode).
    pub const fn new() -> Self {
        Self {
            inner: encode::TarEncoder::new(),
        }
    }
}

impl Default for TarArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for TarArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.inner.finish())
    }
}
