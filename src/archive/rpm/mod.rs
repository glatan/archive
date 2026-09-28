//! RPM package (`.rpm`) support.
//!
//! An `.rpm` package consists of a 96-byte Lead, a Signature section, a
//! Header section (both using the RPM "header structure" key-value format
//! defined by the rpm.org file format documentation), and a compressed
//! payload. The payload is a cpio `newc` archive for v4 packages, or the
//! RPM-specific stripped cpio variant (magic `07070X`, file index only) for
//! v6 packages and v4 packages containing files >= 4 GB.
//!
//! [`decode`] reads Lead/Signature/Header plus gzip/bzip2/lzma/xz/zstd/
//! uncompressed `newc` or stripped payloads. [`encode`] writes packages
//! (`newc` payload, all six compressors). Cryptographic signature
//! verification and stripped-payload writing are intentionally out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// `.rpm` package decoding.
pub mod decode;

/// `.rpm` package encoding.
pub mod encode;

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
