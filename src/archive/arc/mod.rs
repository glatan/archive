//! SEA ARC (`.arc`) archive read and store-method write support.
//!
//! Reference: the ARC file format description published by System
//! Enhancement Associates (arc specification / wotsit "arc" entry).
//! Supported scope:
//!
//! - reading: method 1 (obsolete unpacked, no CRC) and method 2
//!   (stored). Methods 3 (packed/RLE), 4 (squeezed), 5-8 (crunched /
//!   non-ASCII crunched / crushed / distilled) and any higher method
//!   are rejected with [`Error::Unsupported`];
//! - writing: method 2 (stored) entries only.
//!
//! Layout: each member starts with `0x1A` and a method byte; method 0
//! marks end of archive. Method-1 records are
//! `[name 13B][size u32le][data]`; methods >= 2 use
//! `[name 13B][size u32le][date u16le][time u16le][crc16 u16le]
//! [length u32le][data]` where `size` is the uncompressed size and
//! `length` is the stored data size (equal for method 2). ARC has no
//! directory entries and names are flat, NUL-padded, at most 12
//! characters plus a terminator byte.

use alloc::vec::Vec;

use crate::error::Error;

/// ARC archive decoding.
pub mod decode;
/// ARC store-method encoding.
pub mod encode;

/// Codec struct for trait-based ARC decode operations.
pub struct ArcCodec;

impl crate::traits::ArchiveDecode for ArcCodec {
    type Entry = decode::ArcEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
