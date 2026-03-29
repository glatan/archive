//! lzip compression and decompression.
//!
//! Implements the lzip compressed data format, which uses LZMA
//! (Lempel-Ziv-Markov chain Algorithm) with fixed parameters
//! (lc=3, lp=0, pb=2) and a simple framing format.

/// lzip decompression with CRC-32 verification.
pub mod decode;

/// lzip compression.
pub mod encode;

/// Compatibility shim re-exporting the shared `compress::lzma` codec.
pub(crate) mod lzma;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for lzip compression/decompression via trait interface.
pub struct LzipCodec;

impl Decode for LzipCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for LzipCodec {
    type Options = ();

    fn encode(&self, input: &[u8], _options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lzip_codec_roundtrip() {
        let codec = LzipCodec;
        let data = b"hello lzip codec roundtrip test data";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }
}
