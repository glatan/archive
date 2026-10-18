//! bzip2 compression and decompression.
//!
//! Implements the bzip2 block-sorting compression format using
//! Burrows-Wheeler Transform (BWT), Move-To-Front (MTF),
//! Run-Length Encoding (RLE), and Huffman coding.

/// bzip2 decompression with CRC32 verification.
pub mod decode;

/// bzip2 compression.
pub mod encode;

/// MSB-first bit-level I/O for bzip2 streams.
pub(crate) mod bitstream;
/// Burrows-Wheeler Transform (forward and inverse).
pub(crate) mod bwt;
/// bzip2-style CRC-32 (big-endian / non-reflected).
pub(crate) mod crc32;
/// Canonical Huffman coding for bzip2.
pub(crate) mod huffman;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for bzip2 compression/decompression via trait interface.
pub struct Bzip2Codec;

impl Decode for Bzip2Codec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for Bzip2Codec {
    type Options = ();

    fn encode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        _options: &Self::Options,
    ) -> Result<(), Error> {
        crate::compress::move_into(output, encode::encode(input));
        Ok(())
    }
}

#[cfg(feature = "std")]
use crate::traits_io::{DecodeReader, EncodeWriter};

#[cfg(feature = "std")]
impl DecodeReader for Bzip2Codec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for Bzip2Codec {
    type Options = ();

    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        _options: &Self::Options,
        writer: W,
    ) -> std::io::Result<usize> {
        encode::encode_writer(input, writer)
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn test_bzip2_codec_roundtrip() {
        let codec = Bzip2Codec;
        let data = b"hello bzip2 codec roundtrip test data";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_bzip2_codec_reader_writer_roundtrip() {
        let codec = Bzip2Codec;
        let data = b"hello bzip2 reader/writer roundtrip";
        let mut buf = Vec::new();
        codec.encode_writer(data, &(), &mut buf).unwrap();
        let decompressed = codec.decode_reader(buf.as_slice()).unwrap();
        assert_eq!(decompressed, data);
    }
}
