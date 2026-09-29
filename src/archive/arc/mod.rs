//! SEA ARC (`.arc`) archive read and store-method write support.
//!
//! Reference: the ARC file format description published by System
//! Enhancement Associates (arc specification / wotsit "arc" entry).
//! Supported scope:
//!
//! - reading: method 1 (obsolete unpacked, no CRC), method 2
//!   (stored) and method 3 (packed/RLE90). Methods 4 (squeezed),
//!   5-8 (crunched / non-ASCII crunched / crushed / distilled) and
//!   any higher method are rejected with [`Error::Unsupported`];
//! - writing: method 1 (obsolete unpacked), method 2 (stored) and
//!   method 3 (packed/RLE90) entries.
//!
//! Layout: each member starts with `0x1A` and a method byte; method 0
//! marks end of archive. Method-1 records are
//! `[name 13B][size u32le][data]`; methods >= 2 use
//! `[name 13B][size u32le][date u16le][time u16le][crc16 u16le]
//! [length u32le][data]` where `size` is the uncompressed size and
//! `length` is the stored data size (equal for method 2; the RLE90
//! packed size for method 3). The CRC-16 covers the uncompressed
//! data. ARC has no directory entries and names are flat,
//! NUL-padded, at most 12 characters plus a terminator byte.

use alloc::vec::Vec;

use crate::error::Error;

/// ARC archive decoding.
pub mod decode;
/// ARC store/RLE90-method encoding.
pub mod encode;

/// RLE90 packing used by method-3 (packed) members.
mod rle90;

/// Codec struct for trait-based ARC decode operations.
pub struct ArcCodec;

impl crate::traits::ArchiveDecode for ArcCodec {
    type Entry = decode::ArcEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
