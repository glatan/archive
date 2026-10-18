//! Common traits for compression and archive operations.
//!
//! These traits provide a uniform interface across all formats.
//! Existing free functions remain unchanged; these traits are an
//! additional abstraction layer for generic programming.
//!
//! # Compression traits
//!
//! [`Decode`](crate::traits::Decode) and [`Encode`](crate::traits::Encode) abstract over compression codecs.
//! Each format provides a zero-sized codec struct (e.g. `Bzip2Codec`)
//! that implements these traits by delegating to the existing free functions.
//!
//! ```
//! # #[cfg(feature = "bzip2")] {
//! use archive::traits::{Decode, Encode};
//! use archive::compress::bzip2::Bzip2Codec;
//!
//! let codec = Bzip2Codec;
//! let data = b"hello world hello world hello world";
//! let compressed = codec.encode(data, &()).unwrap();
//! let decoded = codec.decode(&compressed, None).unwrap();
//! assert_eq!(decoded, data);
//! # }
//! ```
//!
//! # Archive traits
//!
//! [`ArchiveEntry`](crate::traits::ArchiveEntry) provides uniform read access to entry name and data.
//! [`ArchiveDecode`](crate::traits::ArchiveDecode) and [`ArchiveEncode`](crate::traits::ArchiveEncode) abstract over archive containers.
//!
//! # Decompression bomb protection
//!
//! [`Decode::decode`](crate::traits::Decode::decode) accepts an optional `max_output` parameter.
//! When `Some(n)`, the decoder returns [`Error::OutputLimitExceeded`]
//! if the decompressed output would exceed `n` bytes.
//!
//! [`Error::OutputLimitExceeded`]: crate::error::Error::OutputLimitExceeded

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// Decode compressed data from a byte slice.
///
/// Every compression codec struct implements this trait.
/// Pass `max_output: Some(n)` to enforce an output size limit
/// (decompression bomb protection). `n` counts only the bytes this
/// call appends.
pub trait Decode {
    /// Append the decompressed bytes of `input` to `output`.
    ///
    /// `max_output` is the maximum number of bytes this call may append.
    /// Bytes already in `output` do not count. `Some(n)` yields
    /// [`Error::OutputLimitExceeded`] when the decompressed size would
    /// exceed `n`. On error, `output` is left as it was when this call
    /// started.
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error>;

    /// Decode `input`, optionally limiting output to `max_output` bytes.
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        self.decode_into(input, &mut output, max_output)?;
        Ok(output)
    }
}

/// Encode data into a compressed byte stream.
///
/// The associated `Options` type allows format-specific configuration.
/// Formats with no options use `Options = ()`.
pub trait Encode {
    /// Format-specific encoding options. Use `()` for formats with no options.
    type Options;

    /// Append the compressed bytes of `input` to `output`.
    fn encode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        options: &Self::Options,
    ) -> Result<(), Error>;

    /// Encode `input` with the given options.
    fn encode(&self, input: &[u8], options: &Self::Options) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        self.encode_into(input, &mut output, options)?;
        Ok(output)
    }
}

/// Read-only access to an archive entry's name and data.
///
/// Implemented by all archive entry types (`TarEntry`, `ZipEntry`, etc.).
pub trait ArchiveEntry {
    /// Entry name or path within the archive.
    fn name(&self) -> &str;

    /// Entry payload bytes.
    fn data(&self) -> &[u8];
}

/// Decode an archive from bytes, yielding typed entries.
pub trait ArchiveDecode {
    /// The entry type produced by this decoder.
    type Entry: ArchiveEntry;

    /// Decode an archive, returning its entries.
    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error>;

    /// Visit each entry. The default collects every entry, then walks them.
    ///
    /// Formats that override this build one entry, pass it to `visit`, and
    /// drop it before the next, so peak memory is one payload rather than
    /// the whole archive.
    fn for_each_entry<F>(&self, input: &[u8], mut visit: F) -> Result<(), Error>
    where
        F: FnMut(Self::Entry) -> Result<(), Error>,
    {
        for entry in self.decode(input)? {
            visit(entry)?;
        }
        Ok(())
    }
}

/// Build and finalize an archive from file entries.
pub trait ArchiveEncode {
    /// Add a file entry to the archive being built.
    fn add_file(&mut self, name: &str, data: &[u8]);

    /// Finalize and return the archive bytes.
    fn finish(self) -> Result<Vec<u8>, Error>;
}

/// Metadata accessor for archive entries that carry a filename as `String`.
///
/// This blanket-style helper is not a trait — each entry type implements
/// `ArchiveEntry` directly. This module exists only for trait definitions.
impl ArchiveEntry for (String, Vec<u8>) {
    fn name(&self) -> &str {
        &self.0
    }
    fn data(&self) -> &[u8] {
        &self.1
    }
}
