//! Microsoft Cabinet (`.cab`, MSCAB) archive format support.
//!
//! Reader and single-cabinet writer for the cabinet container defined
//! in [MS-CAB]. Supports the `tcompTYPE_NONE` (stored),
//! `tcompTYPE_MSZIP` and `tcompTYPE_LZX` compression types,
//! including MSZIP history carried between `CFDATA` blocks within
//! a folder, contiguous LZX streams across `CFDATA` blocks (and
//! across cabinet members for continued folders), files spanning
//! consecutive folders, and `FLAG_RESERVE_PRESENT` reserved areas
//! (skipped on read, zero-filled on write). `decode_parts` reads
//! multi-cabinet sets (iCabinet/setID validated, folder fragments and
//! split CFDATA blocks reassembled across members). Quantum folders and
//! multi-cabinet writing are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// Microsoft Cabinet archive decoding.
pub mod decode;
pub mod encode;

/// Codec struct for trait-based MSCAB decode operations.
pub struct MscabCodec;

impl crate::traits::ArchiveDecode for MscabCodec {
    type Entry = decode::MscabEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }
}
