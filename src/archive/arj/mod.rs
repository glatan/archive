//! ARJ archive read and store-method write support.
//!
//! Reference: ARJ technical note ("arj tekninen" / ARJ file format
//! description published with ARJ 2.x). Supported scope:
//!
//! - reading: ARJ 2.x basic headers, method 0 (`stored`) and
//!   file-type 3 (directory) / 4 (volume label) entries. Compressed
//!   methods 1-4 and entries flagged as garbled (password-protected,
//!   flag bit 0x01) are rejected with [`Error::Unsupported`];
//! - writing: method-0 binary file entries only.
//!
//! Layout: each header starts with the two-byte signature `0x60 0xEA`
//! followed by a `u16le` header size (0 = end of archive). The basic
//! header is a fixed 30-byte block, then a NUL-terminated filename,
//! a NUL-terminated comment, and a `u32le` CRC-32 of the header bytes
//! starting at `first_hdr_size`. File data follows the header CRC (and
//! any extended header block, which is skipped). The main (first)
//! header describes the archive itself and carries no data.

use alloc::vec::Vec;

use crate::error::Error;

/// ARJ archive decoding.
pub mod decode;
/// ARJ store-method encoding.
pub mod encode;

/// Codec struct for trait-based ARJ decode operations.
pub struct ArjCodec;

impl crate::traits::ArchiveDecode for ArjCodec {
    type Entry = decode::ArjEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
