//! RPM package (`.rpm`) support.
//!
//! An `.rpm` package consists of a 96-byte Lead, a Signature section, a
//! Header section (both using the RPM "header structure" key-value format
//! defined by the rpm.org file format documentation), and a compressed
//! payload. The payload is a cpio `newc` archive for v4 packages, or the
//! RPM-specific stripped cpio variant (magic `07070X`, file index only) for
//! v6 packages and v4 packages containing files >= 4 GB.
//!
//! This module is read-only: `.rpm` writing and cryptographic signature
//! verification are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// `.rpm` package decoding.
pub mod decode;

pub use decode::{
    RpmCompression, RpmHeaderSection, RpmLead, RpmPackage, RpmPackageType, RpmPayloadEntry,
    RpmTagEntry, RpmTagType, decode,
};

/// Codec struct for trait-based `.rpm` decode operations.
pub struct RpmCodec;

impl crate::traits::ArchiveDecode for RpmCodec {
    type Entry = decode::RpmPayloadEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)?.payload_entries()
    }
}
