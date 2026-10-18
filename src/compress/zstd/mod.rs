//! Zstandard (zstd) compression ([RFC 8878]).
//!
//! Supports multi-frame decoding, dictionary-based decoding, and XXH64
//! content checksums. The public encoder emits Raw/RLE/Compressed blocks plus
//! frame-level checksum and optional dictionary ID metadata; compressed blocks
//! use the shared LZ77 + predefined-FSE/Huffman path when that beats raw output.
//!
//! [RFC 8878]: https://datatracker.ietf.org/doc/html/rfc8878

/// zstd decompression with optional dictionary support.
pub mod decode;
/// zstd compression with optional dictionary support.
pub mod encode;
/// Zstd frame header and block header parsing.
pub(crate) mod frame;
/// Finite State Entropy (FSE) table decoding and encoding.
pub(crate) mod fse;
/// Huffman literal compression and decompression.
pub(crate) mod huff;
/// Zstandard Seekable Format (multi-frame + seek table).
pub mod seekable;
/// Zstd sequence decoding and execution.
pub(crate) mod sequences;
/// zstd dictionary training.
pub mod train;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for Zstandard compression via trait-based API.
pub struct ZstdCodec;

impl Decode for ZstdCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for ZstdCodec {
    type Options = encode::EncodeOptions;

    fn encode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        options: &Self::Options,
    ) -> Result<(), Error> {
        crate::compress::move_into(output, encode::encode_with_options(input, options));
        Ok(())
    }
}

#[cfg(feature = "std")]
use crate::traits_io::{DecodeReader, EncodeWriter};

#[cfg(feature = "std")]
impl DecodeReader for ZstdCodec {
    fn decode_reader<R: std::io::Read>(&self, mut reader: R) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        decode::decode(&buf).map_err(Into::into)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for ZstdCodec {
    type Options = encode::EncodeOptions;

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
mod tests {
    use super::*;

    #[test]
    fn test_zstd_codec_roundtrip() {
        let codec = ZstdCodec;
        let data = b"hello zstd hello zstd hello zstd";
        let compressed = codec
            .encode(data, &encode::EncodeOptions::default())
            .unwrap();
        let decoded = Decode::decode(&codec, &compressed, None).unwrap();
        assert_eq!(decoded, data);
    }
}
