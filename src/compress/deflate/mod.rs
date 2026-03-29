//! DEFLATE compression ([RFC 1951]).
//!
//! Provides raw DEFLATE stream encoding and decoding without any framing
//! (no gzip or zlib headers). The encoder supports three compression levels:
//! no compression (stored blocks), fast (fixed Huffman), and default (dynamic Huffman with LZ77).
//!
//! [RFC 1951]: https://datatracker.ietf.org/doc/html/rfc1951

/// DEFLATE decompression (inflate).
pub mod decode;
/// DEFLATE compression.
pub mod encode;
pub(crate) mod tables;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for DEFLATE compression/decompression via trait interface.
pub struct DeflateCodec;

impl Decode for DeflateCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for DeflateCodec {
    type Options = encode::Level;

    fn encode(&self, input: &[u8], options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input, *options))
    }
}

#[cfg(feature = "std")]
use crate::traits_io::{DecodeReader, EncodeWriter};

#[cfg(feature = "std")]
impl DecodeReader for DeflateCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader).map_err(Into::into)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for DeflateCodec {
    type Options = encode::Level;

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
    fn test_deflate_codec_roundtrip() {
        let codec = DeflateCodec;
        let data = b"hello deflate codec roundtrip test data";
        let compressed = codec.encode(data, &encode::Level::Default).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_deflate_codec_reader_writer_roundtrip() {
        let codec = DeflateCodec;
        let data = b"hello deflate reader/writer roundtrip";
        let mut buf = Vec::new();
        codec
            .encode_writer(data, &encode::Level::Default, &mut buf)
            .unwrap();
        let decompressed = codec.decode_reader(buf.as_slice()).unwrap();
        assert_eq!(decompressed, data);
    }
}
