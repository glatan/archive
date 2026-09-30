//! WARC (Web ARChive, `.warc`) format support.
//!
//! Decoder and encoder for WARC 1.0 / 1.1 record streams (ISO 28500,
//! IIPC specification). Each record is exposed as an entry named by
//! its `WARC-Target-URI` (or `WARC-Record-ID` when absent); the entry
//! data is the record block. `.warc.gz` files are per-record gzip
//! members — decompress with [`crate::compress::gzip`] first.
//! The encoder emits records with the mandatory fields plus a SHA-1
//! `WARC-Block-Digest` (and `WARC-Payload-Digest` when the caller
//! supplies the payload bytes). On decode, `sha1` digests are
//! verified: `WARC-Block-Digest` always, and `WARC-Payload-Digest`
//! when the payload is known to be the whole record block. Per-record
//! field/type constraints and Clause 7 segmentation structure (segment
//! ordering, `WARC-Segment-Total-Length`) are validated on decode.
//! Clause 7 segmented series can be reassembled with
//! [`decode::join`], and `WARC-Concurrent-To` capture
//! groups resolved with [`decode::concurrent_groups`]. Payload
//! semantics beyond that (HTTP message parsing inside blocks)
//! are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// WARC archive decoding.
pub mod decode;

/// WARC record stream encoding.
pub mod encode;

/// Codec struct for trait-based WARC decode operations.
pub struct WarcCodec;

impl crate::traits::ArchiveDecode for WarcCodec {
    type Entry = decode::WarcEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
