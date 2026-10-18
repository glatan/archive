//! zlib compression and decompression ([RFC 1950]).
//!
//! zlib wraps a raw DEFLATE stream with a 2-byte header and a 4-byte
//! Adler-32 checksum trailer.
//!
//! [RFC 1950]: https://datatracker.ietf.org/doc/html/rfc1950
//!
//! # Examples
//!
//! ```
//! use archive::compress::zlib::{decode, encode};
//!
//! let data = b"Hello, zlib!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// zlib decompression.
pub mod decode;

/// zlib compression.
pub mod encode;

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for zlib compression/decompression via trait interface.
pub struct ZlibCodec;

impl Decode for ZlibCodec {
    fn decode_into(
        &self,
        input: &[u8],
        output: &mut Vec<u8>,
        max_output: Option<usize>,
    ) -> Result<(), Error> {
        decode::decode_into(input, output, max_output)
    }
}

impl Encode for ZlibCodec {
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
    fn test_zlib_codec_roundtrip() {
        let codec = ZlibCodec;
        let data = b"hello zlib codec roundtrip test data";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }
}
