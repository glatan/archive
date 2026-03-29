//! gzip compression ([RFC 1952]).
//!
//! Wraps DEFLATE streams with gzip headers and trailers that carry metadata
//! (filename, comment, timestamp) and integrity checks (CRC32, original size).
//! Supports multi-member streams and all header flags (FEXTRA, FNAME, FCOMMENT, FHCRC).
//!
//! [RFC 1952]: https://datatracker.ietf.org/doc/html/rfc1952

/// gzip decompression with checksum verification.
pub mod decode;
/// gzip compression with configurable header options.
pub mod encode;
/// gzip header parsing.
pub mod header;

use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for gzip compression/decompression via trait interface.
pub struct GzipCodec;

impl Decode for GzipCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for GzipCodec {
    type Options = deflate::encode::Level;

    fn encode(&self, input: &[u8], options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input, *options))
    }
}

#[cfg(feature = "std")]
use crate::traits_io::{DecodeReader, EncodeWriter};

#[cfg(feature = "std")]
impl DecodeReader for GzipCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader).map_err(Into::into)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for GzipCodec {
    type Options = deflate::encode::Level;

    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        options: &Self::Options,
        writer: W,
    ) -> std::io::Result<usize> {
        encode::encode_writer(input, *options, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gzip_codec_roundtrip() {
        let codec = GzipCodec;
        let data = b"hello gzip codec roundtrip test data";
        let compressed = codec
            .encode(data, &deflate::encode::Level::Default)
            .unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_gzip_codec_reader_writer_roundtrip() {
        let codec = GzipCodec;
        let data = b"hello gzip reader/writer roundtrip";
        let mut buf = Vec::new();
        codec
            .encode_writer(data, &deflate::encode::Level::Default, &mut buf)
            .unwrap();
        let decompressed = codec.decode_reader(buf.as_slice()).unwrap();
        assert_eq!(decompressed, data);
    }
}
