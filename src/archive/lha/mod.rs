//! LHA / LZH archive read/write support.
//!
//! Reference: lha header documentation ("apphead"/lzh_note) as used by
//! the original LHA and GNU `lha`. Supported scope:
//!
//! - header levels 0, 1, 2, and 3 for reading;
//! - methods `-lh0-` (stored), `-lhd-` (directory marker, no data),
//!   `-lh1-` (adaptive Huffman, 4 KiB ring), `-lh2-` (dynamic Huffman,
//!   8 KiB ring), `-lh3-` (static Huffman "st0", 8 KiB ring),
//!   `-lh4-` through `-lh7-` (static Huffman "st1", 16/64/128 KiB
//!   rings), LArc `-lzs-`/`-lz4-`/`-lz5-`, and PMarc
//!   `-pm0-`/`-pm1-`/`-pm2-`; `-lz4-` and `-pm0-` are stored
//!   variants. Every other method (`-lhx-`, ...) is rejected with
//!   [Error::Unsupported];
//! - writing emits `-lh0-`/`-lhd-` entries at header level 0, 1, 2, or 3
//!   (`LhaEncoder::with_level`), or `-lz4-`/`-pm0-` stored-alias and
//!   static-Huffman `-lh4-`/`-lh5-`/`-lh6-`/`-lh7-` file entries via
//!   `LhaEncoder::with_method`, or LArc `-lzs-`/`-lz5-` LZSS file
//!   entries (falling back to `-lh0-` when compression does not
//!   shrink the input). Level 0 requires the whole filename to fit
//!   in one byte
//!   (at most 255 bytes); levels 1/2/3 carry the name through
//!   extended headers.
//!
//! Layout (level 0):
//! [hdr_size u8][checksum u8][method 5B][packed u32le][orig u32le]
//!  [dos time u32le][attr u8][level u8][name_len u8][name][crc16 u16le]
//!  [data]. hdr_size counts bytes from method through crc16;
//!  checksum is the byte sum of that range. Level 1 replaces the
//!  trailing fields with crc16 u16le + OS id + extended headers;
//!  level 2 uses a u16 size field, no checksum, crc16 + OS id +
//!  extended headers (filename in extension block 0x01); level 3
//!  uses a 32-byte base header with u32 sizes and u32-sized
//!  extended headers. The archive is terminated by a zero header-size
//!  field.

use alloc::vec::Vec;

use crate::error::Error;

/// LHA archive decoding.
pub mod decode;
/// LHA archive encoding.
pub mod encode;
mod larc;
mod larc_enc;
mod lzh_dyn;
mod lzh_st0;
mod lzhuf;
mod pmarc;

/// Codec struct for trait-based LHA decode operations.
pub struct LhaCodec;

impl crate::traits::ArchiveDecode for LhaCodec {
    type Entry = decode::LhaEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
