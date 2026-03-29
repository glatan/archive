//! `ar` archive format support.
//!
//! Implements the common GNU and BSD variants of the Unix `ar` container,
//! including GNU string tables (`//` + `/offset`) and BSD long names
//! (`#1/<len>`). Symbol-table metadata entries are recognised and skipped
//! by the decoder.

use alloc::vec::Vec;

use crate::error::Error;

/// `ar` archive decoding.
pub mod decode;
/// `ar` archive encoding.
pub mod encode;

/// Codec struct for trait-based ar decode operations.
pub struct ArCodec;

impl crate::traits::ArchiveDecode for ArCodec {
    type Entry = decode::ArEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}

/// Encoder struct for trait-based ar encode operations.
pub struct ArArchiveEncoder {
    inner: encode::ArEncoder,
}

impl ArArchiveEncoder {
    /// Create a new trait-based ar encoder (GNU dialect).
    pub const fn new() -> Self {
        Self {
            inner: encode::ArEncoder::new(),
        }
    }
}

impl Default for ArArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for ArArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.inner.finish()
    }
}
