//! rzip (`.rz`) compression and decompression.
//!
//! This module implements the upstream `rzip.samba.org` container shape:
//! a 24-byte `RZIP` header followed by chunk-local two-stream data.
//!
//! The long-range matching token layer is also shared with the crate's
//! `lrzip` implementation. The current encoder is validated against system
//! `rzip -d` for direct text, binary, and level-1 multi-chunk payloads within
//! the documented container/token subset.

use crate::util::crc32::Crc32;

/// rzip encoding.
pub mod encode;

/// rzip decoding.
pub mod decode;

pub(crate) fn legacy_crc32(data: &[u8]) -> u32 {
    let mut crc = Crc32::from_raw(0);
    crc.update(data);
    crc.finish_raw()
}

// ── Codec struct & trait impls ──────────────────────────────────

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for rzip compression and decompression.
pub struct RzipCodec;

impl Decode for RzipCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for RzipCodec {
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
    use crate::traits::{Decode, Encode};

    #[test]
    fn rzip_codec_roundtrip() {
        let codec = RzipCodec;
        let data = b"Hello, rzip codec trait roundtrip!";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }
}
