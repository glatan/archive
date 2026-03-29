//! Snappy compression and decompression.
//!
//! Supports both the raw Snappy block format and the framed stream format.
//! The default `encode::encode` / `decode::decode` entry points operate on the
//! framed format and expose raw helpers for interoperability testing.

/// Snappy decoding.
pub mod decode;

/// Snappy encoding.
pub mod encode;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for Snappy compression via trait-based API.
pub struct SnappyCodec;

impl Decode for SnappyCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for SnappyCodec {
    type Options = ();

    fn encode(&self, input: &[u8], _options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snappy_codec_roundtrip() {
        let codec = SnappyCodec;
        let data = b"hello snappy hello snappy hello snappy";
        let compressed = codec.encode(data, &()).unwrap();
        let decoded = Decode::decode(&codec, &compressed, None).unwrap();
        assert_eq!(decoded, data);
    }
}
