//! LHA / LZH archive read and store-method write support.
//!
//! Reference: lha header documentation ("apphead"/lzh_note) as used by
//! the original LHA and GNU `lha`. Supported scope:
//!
//! - header levels 0, 1, and 2 for reading;
//! - methods `-lh0-` (stored) and `-lhd-` (directory marker, no data);
//!   every other method (`-lh1-`, `-lh5-`, `-lh6-`, `-lh7-`, `-lzs-`,
//!   `-lz4-`, `-pm0-`, `-pm2-`, ...) is rejected with
//!   [`Error::Unsupported`];
//! - writing emits header level 0 `-lh0-` entries only (file names must
//!   fit in one byte, i.e. at most 255 bytes, and be non-empty).
//!
//! Layout (level 0):
//! `[hdr_size u8][checksum u8][method 5B][packed u32le][orig u32le]
//!  [dos time u32le][attr u8][level u8][name_len u8][name][crc16 u16le]
//!  [data]`. `hdr_size` counts bytes from `method` through `crc16`;
//! `checksum` is the byte sum of that range. Level 1 replaces the
//! trailing fields with `crc16 u16le + OS id + extended headers`;
//! level 2 uses a `u16` size field, no checksum, `crc16 + OS id +
//! extended headers` (filename in extension block 0x01). The archive is
//! terminated by a zero header-size field.

use alloc::vec::Vec;

use crate::error::Error;

/// LHA archive decoding.
pub mod decode;
/// LHA store-method encoding.
pub mod encode;

/// Codec struct for trait-based LHA decode operations.
pub struct LhaCodec;

impl crate::traits::ArchiveDecode for LhaCodec {
    type Entry = decode::LhaEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
