//! LZW compression and decompression (Unix compress `.Z` format).
//!
//! Implements the Lempel-Ziv-Welch algorithm as used by the Unix `compress`
//! utility. The format uses variable-width codes (9-16 bits) packed LSB-first,
//! with an optional clear code (256) to reset the dictionary.
//!
//! # Format details
//!
//! - 3-byte header: magic `0x1F 0x9D`, then flags byte
//! - Flags byte: bits 0-4 = max code bits (9-16), bit 7 = block mode (clear code enabled)
//! - Codes start at 9 bits wide and grow as the dictionary fills
//! - Code 256 is the clear code (when block mode is enabled)
//! - First data byte is emitted as a literal (not a code pair)

/// Returns true when the encoder should widen the next emitted code.
pub(crate) const fn should_bump_encode_code_width(
    next_code: u32,
    code_bits: u32,
    max_bits: u32,
) -> bool {
    code_bits < max_bits && next_code > (1 << code_bits)
}

/// Returns true when the decoder should widen the next code it reads.
///
/// The decoder reconstructs dictionary entries one step behind the encoder,
/// so its boundary check is intentionally one code earlier than the encoder's.
pub(crate) const fn should_bump_decode_code_width(
    next_code: u32,
    code_bits: u32,
    max_bits: u32,
) -> bool {
    code_bits < max_bits && next_code >= (1 << code_bits)
}

/// LZW decompression (Unix compress `.Z` format).
pub mod decode;

/// LZW compression (Unix compress `.Z` format).
pub mod encode;

// ── Codec struct & trait impls ──────────────────────────────────

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for LZW (Unix compress `.Z`) compression and decompression.
pub struct LzwCodec;

impl Decode for LzwCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for LzwCodec {
    type Options = ();

    fn encode(&self, input: &[u8], _options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input))
    }
}

#[cfg(feature = "std")]
impl crate::traits_io::DecodeReader for LzwCodec {
    fn decode_reader<R: std::io::Read>(&self, reader: R) -> std::io::Result<Vec<u8>> {
        decode::decode_reader(reader)
    }
}

#[cfg(feature = "std")]
impl crate::traits_io::EncodeWriter for LzwCodec {
    type Options = ();

    fn encode_writer<W: std::io::Write>(
        &self,
        input: &[u8],
        _options: &Self::Options,
        mut writer: W,
    ) -> std::io::Result<usize> {
        encode::encode_writer(input, &mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decode, Encode};

    #[test]
    fn lzw_codec_roundtrip() {
        let codec = LzwCodec;
        let data = b"Hello, LZW codec trait roundtrip!";
        let compressed = codec.encode(data, &()).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "std")]
    #[test]
    fn lzw_codec_reader_writer_roundtrip() {
        use crate::traits_io::{DecodeReader, EncodeWriter};

        let codec = LzwCodec;
        let data = b"LZW reader/writer roundtrip";
        let mut compressed = Vec::new();
        codec.encode_writer(data, &(), &mut compressed).unwrap();
        let decompressed = codec.decode_reader(&compressed[..]).unwrap();
        assert_eq!(decompressed, data);
    }
}
