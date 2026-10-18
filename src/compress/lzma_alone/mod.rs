//! LZMA-Alone `.lzma` compression and decompression.
//!
//! Implements the `.lzma` file format: a 13-byte header followed by a raw
//! LZMA stream. The header stores the LZMA properties byte, the dictionary
//! size as a 32-bit little-endian integer, and the uncompressed size as a
//! 64-bit little-endian integer (`0xFFFF_FFFF_FFFF_FFFF` when unknown).
//!
//! Base specification: `lzma-file-format.txt` (XZ documentation, public
//! domain). The shared LZMA codec lives in [`crate::compress::lzma`].

/// LZMA-Alone `.lzma` decompression.
pub mod decode;

/// LZMA-Alone `.lzma` compression.
pub mod encode;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for LZMA-Alone `.lzma` compression and decompression.
pub struct LzmaAloneCodec;

impl Decode for LzmaAloneCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for LzmaAloneCodec {
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
    fn test_lzma_alone_codec_roundtrip() {
        let codec = LzmaAloneCodec;
        let data = b"hello lzma-alone codec roundtrip test data";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }
}
