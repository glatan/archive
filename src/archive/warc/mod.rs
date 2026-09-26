//! WARC (Web ARChive, `.warc`) format support.
//!
//! Read-only decoder for WARC 1.0 / 1.1 record streams (ISO 28500,
//! IIPC specification). Each record is exposed as an entry named by
//! its `WARC-Target-URI` (or `WARC-Record-ID` when absent); the entry
//! data is the record block. `.warc.gz` files are per-record gzip
//! members — decompress with [`crate::compress::gzip`] first.
//! Payload semantics (HTTP header parsing, record segmentation
//! reassembly, digest verification) and writing are intentionally out
//! of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// WARC archive decoding.
pub mod decode;

/// Codec struct for trait-based WARC decode operations.
pub struct WarcCodec;

impl crate::traits::ArchiveDecode for WarcCodec {
    type Entry = decode::WarcEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
