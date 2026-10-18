//! `std::io` adapter traits for compression codecs.
//!
//! These traits are only available with the `std` feature enabled.
//! They provide [`std::io::Read`] / [`std::io::Write`] based interfaces
//! complementing the in-memory [`Decode`](crate::traits::Decode) /
//! [`Encode`](crate::traits::Encode) traits.

use alloc::vec::Vec;

/// Decode from a [`std::io::Read`] source.
///
/// Implementations read the source to the end and then decode that
/// slice. gzip, xz, zstd, and lz4 are framed, but their parsers index
/// a contiguous buffer and the bit reader cannot resume on a longer
/// slice. A streaming reader would have to reimplement those parsers.
pub trait DecodeReader {
    /// Read all bytes from `reader`, decode, and return the result.
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>>;
}

/// Encode to a [`std::io::Write`] sink.
pub trait EncodeWriter {
    /// Format-specific encoding options.
    type Options;

    /// Encode `input` with `options` and write the result to `writer`.
    /// Returns the number of bytes written.
    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        options: &Self::Options,
        writer: W,
    ) -> std::io::Result<usize>;
}
