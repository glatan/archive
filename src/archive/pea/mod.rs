//! PEA (Pack, Encrypt, Authenticate) archive read support.
//!
//! Decoder for the PEA 1.x file format as implemented by PeaZip's
//! `pea`/`unpea` backend (reference source `pea.pas`/`pea_utils.pas`,
//! snapshots in `docs/spec/sources/`): a 10-byte archive header
//! (`$EA`, version/revision, volume/object control algorithms), a
//! `POD` stream header naming the compression scheme (PCOMPRESS0
//! store, PCOMPRESS1-3 chunked zlib-deflate over 1 MiB blocks), a
//! sequence of file/directory objects, and an `EOA` trigger followed
//! by stream and volume integrity tags.
//!
//! Integrity tags (Adler-32, CRC-32, CRC-64, MD5, SHA-1, SHA-256) are
//! verified when the algorithm is one this crate implements; other
//! hash algorithms are parsed and skipped unverified. Authenticated-
//! encryption streams (EAX/Twofish/Serpent/HMAC and cascades) and
//! multi-volume spanning are intentionally out of scope, as is
//! writing PEA files.

use crate::error::Error;

/// PEA archive decoding.
pub mod decode;

/// Codec struct for trait-based PEA decode operations.
pub struct PeaCodec;

impl crate::traits::ArchiveDecode for PeaCodec {
    type Entry = decode::PeaEntry;

    fn decode(&self, input: &[u8]) -> Result<alloc::vec::Vec<Self::Entry>, Error> {
        decode::decode(input).map(|img| img.entries)
    }
}
