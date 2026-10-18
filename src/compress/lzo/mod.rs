//! LZO compression and decompression (lzop format).
//!
//! Implements LZO1X-1 compression wrapped in the lzop file format
//! with Adler-32 data checksums.
//!
//! # Examples
//!
//! ## Encode
//!
//! ```
//! use archive::compress::lzo::encode;
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! assert!(!compressed.is_empty());
//! ```
//!
//! ## Decode
//!
//! ```
//! use archive::compress::lzo::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// LZO decompression (lzop format).
pub mod decode;

/// LZO compression (lzop format).
pub mod encode;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for LZO compression via trait-based API.
pub struct LzoCodec;

impl Decode for LzoCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for LzoCodec {
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
impl DecodeReader for LzoCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl EncodeWriter for LzoCodec {
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
    fn test_lzo_codec_roundtrip() {
        let codec = LzoCodec;
        let data = b"hello lzo hello lzo hello lzo";
        let compressed = codec.encode(data, &()).unwrap();
        let decoded = Decode::decode(&codec, &compressed, None).unwrap();
        assert_eq!(decoded, data);
    }
}
