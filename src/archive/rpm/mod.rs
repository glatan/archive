//! RPM package (`.rpm`) support.
//!
//! An `.rpm` package consists of a 96-byte Lead, a Signature section, a
//! Header section (both using the RPM "header structure" key-value format
//! defined by the rpm.org file format documentation), and a compressed
//! payload. The payload is a cpio `newc` archive for v4 packages, or the
//! RPM-specific stripped cpio variant (magic `07070X`, file index only) for
//! v6 packages and v4 packages containing files exceeding the 32-bit
//! `FILESIZES` range.
//!
//! [`decode`] reads Lead/Signature/Header plus gzip/bzip2/lzma/xz/zstd/
//! uncompressed `newc` or stripped payloads. [`encode`] writes packages
//! (`newc` or stripped `07070X` payload, all six compressors);
//! [`encode::RpmEncoder::v6`] emits the v6 required tag set
//! (`RPMTAG_RPMFORMAT`/`ENCODING`, payload SHA-256/SHA-512 digest and
//! size tags, Signature `SHA256`/`RESERVED`, file digests and MIME
//! tags for `add_file` packages). OpenPGP signature verification is
//! intentionally out of scope; digest tags can be checked opt-in via
//! RpmPackage::verify_digests.

use alloc::vec::Vec;

use crate::error::Error;

/// `.rpm` package decoding.
pub mod decode;

/// `.rpm` package encoding.
pub mod encode;

pub use decode::{
    RpmCompression, RpmDigestAlgorithm, RpmDigestCheck, RpmDigestTarget, RpmHeaderSection, RpmLead,
    RpmPackage, RpmPackageType, RpmPayloadEntry, RpmTagEntry, RpmTagType, decode,
};

/// Codec struct for trait-based `.rpm` decode operations.
pub struct RpmCodec;

impl crate::traits::ArchiveDecode for RpmCodec {
    type Entry = decode::RpmPayloadEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)?.payload_entries()
    }
}
