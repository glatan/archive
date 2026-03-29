//! ZPAQ compression and decompression.
//!
//! ZPAQ uses context-mixing compression with an arithmetic coder,
//! a ZPAQL virtual machine for context computation, and a predictor
//! composed of multiple component types (CM, ICM, MATCH, ISSE, SSE,
//! MIX, MIX2, AVG).
//!
//! This module implements the low-level, single-payload ZPAQ codec. The public
//! encoder exposes the crate's validated built-in model levels `1..=3` plus a
//! validated `encode::CustomModel` surface, while the decoder accepts any
//! upstream level byte whose parsed model/header is otherwise valid. The
//! current bounded acceptance corpus covers all supported predictor component
//! types, bounded size sweeps, deeper component chains, and mixed HCOMP program
//! shapes. Known component-layout truncation and unsupported/truncated HCOMP
//! bytecode are rejected before payload decode, and unknown component types are
//! rejected instead of being treated as no-op components. HCOMP programs that
//! exhaust the VM cycle limit are also rejected explicitly.
//!
//! It is suitable as a compression backend (for example inside `lrzip`), but it
//! is not the crate's multi-entry archive layer with filename/comment metadata APIs.
//! For multi-entry archive-style use, prefer [`crate::archive::zpaq`].
//!
//! # Examples
//!
//! ```
//! use archive::compress::zpaq::{decode, encode};
//!
//! let data = b"Hello, ZPAQ!";
//! let compressed = encode::encode(data, 1);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! ```

/// ZPAQ encoding (public API).
pub mod encode;

/// ZPAQ decoding (public API).
pub mod decode;

/// ZPAQL virtual machine.
pub(crate) mod zpaql;

/// Context-mixing predictor with 9 component types.
pub(crate) mod predictor;

/// Arithmetic encoder and decoder.
pub(crate) mod arithmetic;

/// Predefined model configurations for levels 1-3.
pub(crate) mod models;

// ── Codec struct & trait impls ──────────────────────────────────

use alloc::vec::Vec;

use crate::error::Error;
use crate::traits::{Decode, Encode};

/// Zero-sized codec for ZPAQ compression and decompression.
///
/// The `Options` type is `u32`, representing the compression level (1-3).
pub struct ZpaqCodec;

impl Decode for ZpaqCodec {
    fn decode(&self, input: &[u8], max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match max_output {
            Some(limit) => decode::decode_bounded(input, limit),
            None => decode::decode(input),
        }
    }
}

impl Encode for ZpaqCodec {
    type Options = u32;

    fn encode(&self, input: &[u8], options: &Self::Options) -> Result<Vec<u8>, Error> {
        Ok(encode::encode(input, *options))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{Decode, Encode};

    #[test]
    fn zpaq_codec_roundtrip() {
        let codec = ZpaqCodec;
        let data = b"Hello, ZPAQ codec trait roundtrip!";
        let compressed = codec.encode(data, &1).unwrap();
        let decompressed = codec.decode(&compressed, None).unwrap();
        assert_eq!(decompressed, data);
    }
}
