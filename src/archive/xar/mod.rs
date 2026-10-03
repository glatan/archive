//! XAR (eXtensible ARchive) format support.
//!
//! Implements the format described by the upstream xar project's
//! `xarformat` document: a fixed binary header (`xar!` magic,
//! version, compressed/uncompressed TOC lengths, checksum algorithm),
//! a zlib-compressed XML table of contents, and a heap region holding
//! the TOC checksum followed by per-file data runs (stored or
//! `application/x-gzip` = zlib-compressed).
//!
//! Decode verifies the header TOC checksum (none/SHA-1/MD5 and
//! `cksum_alg=3` names "sha1"/"md5"), the uncompressed TOC length, and
//! each file's `extracted-checksum` when it uses sha1/md5. Extended
//! attributes (`<ea>`), signatures, and encoding styles beyond
//! none/gzip/bzip2/xz/lzma are out of scope.

use alloc::vec::Vec;

mod xml;

pub mod decode;
pub mod encode;

/// Codec struct for trait-based XAR decode operations.
pub struct XarCodec;

impl crate::traits::ArchiveDecode for XarCodec {
    type Entry = decode::XarEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, crate::error::Error> {
        decode::decode(input)
    }
}
