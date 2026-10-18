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

/// Maximum uncompressed data size per member: 16 EiB - 1 (2^64 - 1).
/// The 8-byte trailer field always covers this range (lzip manual ch.5).
const MAX_DATA_SIZE: u64 = u64::MAX;

/// Maximum member size: 2 PiB (lzip manual ch.5).
const MAX_MEMBER_SIZE: u64 = 0x8_0000_0000_0000;

/// Zero-sized codec for lzip compression/decompression via trait interface.
pub struct LzipCodec;

impl Decode for LzipCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for LzipCodec {
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
