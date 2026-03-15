//! LZ4 compression and decompression ([LZ4 frame format]).
//!
//! Implements the LZ4 frame format with support for independent/dependent
//! blocks, content size, content checksum, block checksum, dictionary IDs,
//! and block max sizes (64KB-4MB).
//!
//! [LZ4 frame format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
//!
//! # Examples
//!
//! ## Encode
//!
//! ```
//! use archive::compress::lz4::encode;
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! assert!(compressed.len() > 0);
//! ```
//!
//! ## Decode
//!
//! ```
//! use archive::compress::lz4::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// LZ4 decompression (frame format).
pub mod decode;

/// LZ4 compression (frame format).
pub mod encode;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for LZ4 compression via trait-based API.
pub struct Lz4Codec;

impl Decode for Lz4Codec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for Lz4Codec {
    type Options = ();

    fn encode(&self, input: &[u8], _options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input))
    }
}

#[cfg(feature = "std")]
use crate::traits_io::{DecodeReader, EncodeWriter};

#[cfg(feature = "std")]
impl DecodeReader for Lz4Codec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for Lz4Codec {
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
mod tests {
    use super::*;

    #[test]
    fn test_lz4_codec_roundtrip() {
        let codec = Lz4Codec;
        let data = b"hello lz4 hello lz4 hello lz4";
        let compressed = codec.encode(data, &()).unwrap();
        let decoded = Decode::decode(&codec, &compressed, None).unwrap();
        assert_eq!(decoded, data);
    }
}
