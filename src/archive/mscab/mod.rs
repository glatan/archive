//! Microsoft Cabinet (`.cab`, MSCAB) archive format support.
//!
//! Read-only decoder for the cabinet container defined in [MS-CAB].
//! Supports the `tcompTYPE_NONE` (stored) and `tcompTYPE_MSZIP`
//! compression types, including MSZIP history carried between `CFDATA`
//! blocks within a folder and files spanning consecutive folders.
//! Quantum and LZX folders, multi-cabinet sets, and cabinet writing
//! are intentionally out of scope.

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
