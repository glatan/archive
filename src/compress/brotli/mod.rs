//! Brotli compression support.
//!
//! Current scope covers Brotli decode plus a public encoder:
//! - stream window header parsing
//! - final empty stream marker
//! - uncompressed, metadata, and compressed metablocks
//! - single- and multi-block-type metablocks
//! - context-map parsing and LSB6/MSB6/UTF8/Signed literal context selection
//! - static dictionary references and default transforms
//! - default compressed-stream command / distance semantics
//! - uncompressed Brotli stream emission
//! - literal-only compressed metablock emission for repeated short patterns and
//!   other low-cardinality payloads (up to 4 distinct literal symbols)
//! - metadata metablock emission (`encode_with_metadata`)
//! - LZ77 hash-table matching engine (32K entries, 4-byte min match)
//! - static dictionary match fallback
//! - distance encoding (NPOSTFIX=0, NDIRECT=0)
//! - complex prefix code writing (RFC 7932 section 4.2)
//! - multi-block-type literal splitting (2 types)
//! - context modeling with LSB6 and 2 context groups

/// Brotli decoding.
pub mod decode;

/// Brotli encoding.
#[allow(
    dead_code,
    clippy::manual_find,
    clippy::manual_range_contains,
    clippy::collapsible_if,
    clippy::type_complexity
)]
pub mod encode;

mod dictionary;
mod huffman;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for Brotli compression via trait-based API.
pub struct BrotliCodec;

impl Decode for BrotliCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for BrotliCodec {
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
use crate::traits_io::EncodeWriter;

#[cfg(feature = "std")]
impl EncodeWriter for BrotliCodec {
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
    fn test_brotli_codec_roundtrip() {
        let codec = BrotliCodec;
        let data = b"hello brotli hello brotli hello brotli";
        let compressed = codec.encode(data, &()).unwrap();
        let decoded = Decode::decode(&codec, &compressed, None).unwrap();
        assert_eq!(decoded, data);
    }
}
