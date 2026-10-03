//! ARJ archive read and write support.
//!
//! Reference: ARJ technical note (ARJ 2.x file format description).
//! Supported scope:
//!
//! - reading: ARJ 2.x headers, method 0 (stored), methods 1-3
//!   (LZH-static, 15-bit window) and method 4 ("fastest" LZSS),
//!   file-type 3 (directory) / 4 (volume label) entries, garbled
//!   (password XOR, flag 0x01) entries via the `decode_with_password*`
//!   functions, and multi-volume archives via `decode_parts`
//!   (flag 0x04 split files reassembled across volume buffers; with
//!   `std`, `decode::volume_paths` enumerates the `.arj`/`.aNN`
//!   sibling volumes automatically). Other methods and the
//!   security-envelope features are rejected
//!   with [`Error::Unsupported`];
//! - writing: stored (method 0), methods 1-3 (LZH-static, one shared
//!   15-bit-window wire format) and method-4 "fastest" LZSS file
//!   entries (ArjEncoder::with_method, falling back to stored when
//!   compression does not shrink the input), garbled (password XOR)
//!   entries via ArjEncoder::with_password, directory entries, and
//!   multi-volume output via ArjEncoder::finish_parts.
//!
//! Layout: each header starts with the two-byte signature `0x60 0xEA`
//! followed by a `u16le` header size (0 = end of archive). The basic
//! header is a 28-30 byte fixed block, then a NUL-terminated filename,
//! a NUL-terminated comment, and a `u32le` CRC-32 of the header bytes
//! starting at `first_hdr_size`. File data follows the header CRC (and
//! any extended header block, which is skipped). The main (first)
//! header describes the archive itself and carries no data.

use alloc::vec::Vec;

use crate::error::Error;

/// ARJ archive decoding.
pub mod decode;
/// ARJ encoding (stored and compressed methods).
pub mod encode;
mod method4;

/// Codec struct for trait-based ARJ decode operations.
pub struct ArjCodec;

impl crate::traits::ArchiveDecode for ArjCodec {
    type Entry = decode::ArjEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
