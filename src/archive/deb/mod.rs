//! Debian binary package (`.deb`) support.
//!
//! A `.deb` package is an `ar` archive with a fixed member layout defined by
//! the deb(5) specification: `debian-binary` (format version line, e.g.
//! "2.0"), `control.tar.<ext>` (package metadata), and `data.tar.<ext>`
//! (payload). This module validates the member layout and exposes the tar
//! members either raw or decompressed through the crate's existing codecs.
//!
//! This module is read-only: `.deb` writing is intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// `.deb` package decoding.
pub mod decode;

pub use decode::{DebCompression, DebMember, DebMemberKind, DebPackage, decode};

/// Codec struct for trait-based `.deb` member decode operations.
pub struct DebCodec;

impl crate::traits::ArchiveDecode for DebCodec {
    type Entry = decode::DebMember;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input).map(|package| package.members)
    }
}
