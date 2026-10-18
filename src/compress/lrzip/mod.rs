//! lrzip (Long Range ZIP) compression and decompression.
//!
//! lrzip uses rzip-style long-range redundancy reduction followed by
//! a configurable backend compression (LZMA, bzip2, LZO, zlib, ZPAQ,
//! or none).
//!
//! This implementation reuses the crate's shared long-range match finder while
//! encoding/decoding the lrzip-specific token stream and bounded `.lrz`
//! container layout. Current system-tool coverage confirms crate decode of
//! simple and match-rich LZMA-authored archives plus crate encode consumed by
//! system `lrzip -d` across the supported backend matrix. Full upstream
//! outer-container parity beyond the documented subset is still not claimed.
//!
//! # Examples
//!
//! ## Encode
//!
//! ```
//! use archive::compress::lrzip::encode;
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! assert!(!compressed.is_empty());
//! ```
//!
//! ## Decode
//!
//! ```
//! use archive::compress::lrzip::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// lrzip decompression.
pub mod decode;

/// lrzip compression.
pub mod encode;

// ── Codec struct & trait impls ──────────────────────────────────

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for lrzip compression and decompression.
///
/// The `Options` type is [`encode::CompressionType`], selecting the backend
/// compressor (LZMA, bzip2, LZO, zlib, ZPAQ, or none).
pub struct LrzipCodec;

impl Decode for LrzipCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for LrzipCodec {
    type Options = encode::CompressionType;

    fn encode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        options: &Self::Options,
    ) -> Result<(), Error> {
        crate::compress::move_into(output, encode::encode_with(input, *options));
        Ok(())
    }
}

#[cfg(feature = "std")]
impl crate::traits_io::DecodeReader for LrzipCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl crate::traits_io::EncodeWriter for LrzipCodec {
    type Options = encode::CompressionType;

    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        options: &Self::Options,
        mut writer: W,
    ) -> std::io::Result<usize> {
        let encoded = encode::encode_with(input, *options);
        writer.write_all(&encoded)?;
        Ok(encoded.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decode, Encode};

    #[test]
    fn lrzip_codec_roundtrip() {
        let codec = LrzipCodec;
        let data = b"Hello, lrzip codec trait roundtrip!";
        let compressed = codec.encode(data, &encode::CompressionType::Lzma).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn lrzip_codec_reader_writer_roundtrip() {
        use crate::traits_io::{DecodeReader, EncodeWriter};

        let codec = LrzipCodec;
        let data = b"lrzip reader/writer roundtrip";
        let mut compressed = Vec::new();
        codec
            .encode_writer(data, &encode::CompressionType::Lzma, &mut compressed)
            .unwrap();
        let decompressed = codec.decode_reader(&compressed[..]).unwrap();
        assert_eq!(decompressed, data);
    }
}
