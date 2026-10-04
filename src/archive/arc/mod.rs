//! SEA ARC (`.arc`) archive read and write support.
//!
//! Reference: the ARC file format description published by System
//! Enhancement Associates (arc specification / wotsit "arc" entry).
//! Compression method internals follow the de-facto reference
//! implementations: methods 5-7/0xa/0xb (`crunch`, `crush`, `distill`)
//! are ported from the newtua_dos transliterations of XADMaster
//! handlers, `squeeze` is adapted from compcol's MIT-licensed
//! `arc_squeeze`, and methods 8/9 share the crate's `compress::lzw`
//! core (de facto reference: ncompress `compress42.c`, public
//! domain/Unlicense). nomarch and hyc-arc are used only as
//! test-time oracles, not as implementation references.
//! Supported scope:
//!
//! - reading: method 1 (obsolete unpacked), method 2
//!   (stored), method 3 (packed/RLE90), method 4 (squeezed = RLE90 +
//!   static Huffman), method 5 (crunched, obsolete — quadratic-hash
//!   LZW), method 6 (crunched = quadratic-hash LZW + RLE90), method 7
//!   (crunched = multiplicative-hash LZW + RLE90), method 8 (crunched
//!   = dynamic LZW + RLE90), method 9 (squashed = dynamic LZW), method
//!   0x0a (crushed = adaptive LZW + RLE90) and method 0x0b (distilled =
//!   LZSS + header Huffman). ARC 6.0+ informational/control items
//!   (methods 20-39) are parsed and skipped without producing entries;
//!   methods 12-19 and 40+ are rejected with [`Error::Unsupported`];
//! - writing: methods 1-0x0b entries.
//!
//! Layout: each member starts with `0x1A` and a method byte; method 0
//! marks end of archive. Method-1 records are
//! `[name 13B][size u32le][date u16le][time u16le][crc16 u16le]
//! [data]` — the regular header minus the original-length field;
//! methods >= 2 use
//! `[name 13B][length u32le][date u16le][time u16le][crc16 u16le]
//! [size u32le][data]` where `length` is the stored (compressed) data
//! size and `size` is the original uncompressed size (equal for method
//! 2; for method 3 `length` is the RLE90 packed size). The CRC-16
//! covers the uncompressed
//! data. ARC has no directory entries and names are flat,
//! NUL-padded, at most 12 characters plus a terminator byte.

use alloc::vec::Vec;

use crate::error::Error;

/// ARC archive decoding.
pub mod decode;
/// ARC member encoding.
pub mod encode;

/// Methods 5/6/7 (crunched) codec: fixed 12-bit hash-table LZW.
mod bits;
mod crunch;
/// Method-0x0a (crushed) codec: adaptive LZW with usage-based
/// replacement.
mod crush;
/// Method-0x0b (distilled) codec: LZSS with a header-supplied Huffman
/// code.
mod distill;
/// RLE90 packing used by method-3 (packed) members and as a stage of
/// methods 4 (squeezed), 6/7 (crunched), 8 (crunched) and 0x0a
/// (crushed).
mod rle90;
/// Method-4 (squeezed) codec: static Huffman over an RLE90 stream.
mod squeeze;

/// Codec struct for trait-based ARC decode operations.
pub struct ArcCodec;

impl crate::traits::ArchiveDecode for ArcCodec {
    type Entry = decode::ArcEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
