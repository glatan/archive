//! xz compression and decompression.
//!
//! Implements the [xz file format](https://tukaani.org/xz/xz-file-format.txt)
//! using LZMA2 compression with xz stream/block integrity checks and the crate's
//! supported standard pre-LZMA2 filters (x86 / PowerPC / IA64 / SPARC / ARM /
//! ARM-Thumb / ARM64 / RISC-V BCJ, plus Delta). Custom/unknown pre-LZMA2
//! filter IDs are preserved on parse and can be applied when a matching
//! `FilterRegistry` entry is supplied via the registry-aware encode/decode
//! APIs, including the reader adapters. `FilterRegistry::register_passthrough()`
//! provides an identity codec for application-defined custom IDs when a caller
//! wants to roundtrip a known marker without transforming bytes; otherwise
//! unregistered custom IDs still fail later as explicit unsupported-filter
//! errors instead of being rejected as malformed headers.
//!
//! # Examples
//!
//! ```
//! use archive::compress::xz::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// xz stream decoder.
pub mod decode;

/// xz stream encoder.
pub mod encode;

/// xz block filter definitions shared by the encoder and decoder.
pub mod filters;

/// Custom filter registry types shared by xz encode/decode paths.
pub mod registry;

/// Compatibility shim re-exporting the shared `compress::lzma2` codec.
pub(crate) mod lzma2;

pub use registry::{FilterCodec, FilterRegistry, MIN_CUSTOM_FILTER_ID};

// ── Codec struct & trait impls ──────────────────────────────────

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for xz compression and decompression.
pub struct XzCodec;

impl Decode for XzCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for XzCodec {
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
impl crate::traits_io::DecodeReader for XzCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl crate::traits_io::EncodeWriter for XzCodec {
    type Options = ();

    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        _options: &Self::Options,
        mut writer: W,
    ) -> std::io::Result<usize> {
        let encoded = encode::encode(input);
        writer.write_all(&encoded)?;
        Ok(encoded.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decode, Encode};

    #[test]
    fn xz_codec_roundtrip() {
        let codec = XzCodec;
        let data = b"Hello, xz codec trait roundtrip!";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn xz_codec_reader_roundtrip() {
        use crate::traits_io::{DecodeReader, EncodeWriter};

        let codec = XzCodec;
        let data = b"xz reader/writer roundtrip";
        let mut compressed = Vec::new();
        codec.encode_writer(data, &(), &mut compressed).unwrap();
        let decompressed = codec.decode_reader(&compressed[..]).unwrap();
        assert_eq!(decompressed, data);
    }
}
