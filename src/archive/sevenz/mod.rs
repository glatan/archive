//! 7z archive support.
//!
//! Current scope covers a baseline interoperable subset:
//! - plain and encoded next-header parsing
//! - multi-folder decode for supported single-output folder DAGs
//! - password-based 7zAES decode for supported single-output folders and encoded headers
//! - LZMA2, raw LZMA, PPMdH, and Brotli decoding, plus Copy / x86 BCJ / BCJ2 / Delta /
//!   PowerPC BCJ / ARM BCJ / ARM Thumb BCJ / SPARC BCJ / ARM64 BCJ / RISC-V BCJ filters
//! - BCJ2 encode and decode for supported single-output DAG layouts
//! - bounded archive writing with one or two linear solid folders and
//!   Copy / LZMA / LZMA2 / PPMdH / Brotli compression
//! - BCJ2 four-stream write support, all single-stream BCJ architecture filters for encode
//! - timestamp (ctime/atime/mtime) parsing and writing
//! - linear 7zAES file-content write and encoded-header write for the current writer subset
//!
//! For the current supported method surface, upstream interfaces are single-stream
//! except for fixed 4-input `BCJ2`; nonstandard multi-input / multi-output arity
//! declarations are rejected explicitly rather than assigned invented semantics.

use alloc::vec::Vec;

use crate::error::Error;

mod bcj2;

/// 7z archive decoding.
pub mod decode;
/// 7z archive encoding.
pub mod encode;

/// Codec struct for trait-based 7z decode operations.
pub struct SevenZCodec;

impl crate::traits::ArchiveDecode for SevenZCodec {
    type Entry = decode::SevenZEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}

/// Encoder struct for trait-based 7z encode operations.
pub struct SevenZArchiveEncoder {
    inner: encode::SevenZEncoder,
}

impl SevenZArchiveEncoder {
    /// Create a new trait-based 7z encoder (LZMA2).
    pub const fn new() -> Self {
        Self {
            inner: encode::SevenZEncoder::new(),
        }
    }
}

impl Default for SevenZArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for SevenZArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.inner.finish()
    }
}
