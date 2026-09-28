//! `.rpm` package encoding (rpm.org package format).
//!
//! Emits the full container: 96-byte Lead + Signature header section
//! (with the `HEADERSIGNATURES` 62 immutable region) + 8-byte-aligned
//! padding + Header section (with the `HEADERIMMUTABLE` 63 region) +
//! compressed `newc` cpio payload.
//!
//! Tag data is serialized big-endian with per-type alignment padding
//! inside the data store (INT16 → 2, INT32 → 4, INT64 → 8), index
//! entries sorted by tag. The immutable-region trailer is written in
//! the offset-0 layout also produced by rpm-style generators and
//! accepted by libarchive (the region tag is the first index entry
//! and its BIN data is a 16-byte `[tag, type 7, offset 0, count 16]`
//! trailer).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::archive::cpio;
use crate::archive::rpm::decode::{RpmCompression, RpmPackageType};
use crate::compress::{bzip2, deflate, gzip, lzma_alone, xz, zstd};
use crate::error::Error;

const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
const LEAD_SIZE: usize = 96;
const SIG_REGION_TAG: u32 = 62;
const HDR_REGION_TAG: u32 = 63;
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_ARCH: u32 = 1022;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;

/// A typed value for one RPM header tag.
#[derive(Debug, Clone)]
pub enum RpmTagValue {
    /// CHAR (type 1).
    Char(u8),
    /// INT8 (type 2) — element list.
    Int8(Vec<u8>),
    /// INT16 (type 3) — element list, 2-byte aligned.
    Int16(Vec<u16>),
    /// INT32 (type 4) — element list, 4-byte aligned.
    Int32(Vec<i32>),
    /// INT64 (type 5) — element list, 8-byte aligned.
    Int64(Vec<i64>),
    /// STRING (type 6) — NUL-terminated, exactly one value.
    Str(String),
    /// BIN (type 7) — opaque blob.
    Bin(Vec<u8>),
    /// STRING_ARRAY (type 8) — NUL-separated list.
    StrArray(Vec<String>),
    /// I18NSTRING (type 9) — NUL-separated list.
    I18nString(Vec<String>),
}

impl RpmTagValue {
    /// Header-structure type code (1-9 per format_header.html).
    fn type_code(&self) -> u32 {
        match self {
            Self::Char(_) => 1,
            Self::Int8(_) => 2,
            Self::Int16(_) => 3,
            Self::Int32(_) => 4,
            Self::Int64(_) => 5,
            Self::Str(_) => 6,
            Self::Bin(_) => 7,
            Self::StrArray(_) => 8,
            Self::I18nString(_) => 9,
        }
    }

    fn count(&self) -> u32 {
        match self {
            Self::Char(_) => 1,
            Self::Int8(v) => v.len() as u32,
            Self::Int16(v) => v.len() as u32,
            Self::Int32(v) => v.len() as u32,
            Self::Int64(v) => v.len() as u32,
            Self::Str(_) => 1,
            Self::Bin(v) => v.len() as u32,
            Self::StrArray(v) | Self::I18nString(v) => v.len() as u32,
        }
    }

    /// Alignment of the element type inside the data store.
    fn align(&self) -> usize {
        match self {
            Self::Int16(_) => 2,
            Self::Int32(_) => 4,
            Self::Int64(_) => 8,
            _ => 1,
        }
    }

    fn emit(&self, out: &mut Vec<u8>) {
        match self {
            Self::Char(v) => out.push(*v),
            Self::Int8(v) => out.extend_from_slice(v),
            Self::Int16(v) => {
                for x in v {
                    out.extend_from_slice(&x.to_be_bytes());
                }
            }
            Self::Int32(v) => {
                for x in v {
                    out.extend_from_slice(&x.to_be_bytes());
                }
            }
            Self::Int64(v) => {
                for x in v {
                    out.extend_from_slice(&x.to_be_bytes());
                }
            }
            Self::Str(s) => {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            Self::Bin(v) => out.extend_from_slice(v),
            Self::StrArray(v) | Self::I18nString(v) => {
                for s in v {
                    out.extend_from_slice(s.as_bytes());
                    out.push(0);
                }
            }
        }
    }
}

/// Encoder for `.rpm` packages.
///
/// The Lead fields other than magic/version/type/name are historical
/// and default to zero (rpm ignores them). The payload is a `newc`
/// cpio archive built from [`add_file`](Self::add_file), or raw
/// payload bytes via [`set_payload`](Self::set_payload).
pub struct RpmEncoder {
    major: u8,
    minor: u8,
    package_type: RpmPackageType,
    archnum: u16,
    osnum: u16,
    lead_name: String,
    sig_tags: Vec<(u32, RpmTagValue)>,
    header_tags: Vec<(u32, RpmTagValue)>,
    compression: RpmCompression,
    files: Vec<(String, Vec<u8>)>,
    payload: Option<Vec<u8>>,
}

impl RpmEncoder {
    /// New encoder: format major 4, binary package, gzip payload.
    pub fn new() -> Self {
        RpmEncoder {
            major: 4,
            minor: 0,
            package_type: RpmPackageType::Binary,
            archnum: 0,
            osnum: 0,
            lead_name: String::new(),
            sig_tags: Vec::new(),
            header_tags: Vec::new(),
            compression: RpmCompression::Gzip,
            files: Vec::new(),
            payload: None,
        }
    }

    /// Lead format major/minor (e.g. 3.0 or 4.0).
    pub fn major_minor(mut self, major: u8, minor: u8) -> Self {
        self.major = major;
        self.minor = minor;
        self
    }

    /// Lead package type (binary or source).
    pub fn package_type(mut self, t: RpmPackageType) -> Self {
        self.package_type = t;
        self
    }

    /// Lead `name-version-release` string (truncated at 66 bytes).
    pub fn lead_name(mut self, name: &str) -> Result<Self, Error> {
        if name.len() > 66 || name.contains('\0') {
            return Err(Error::InvalidData("rpm: bad lead name"));
        }
        self.lead_name = name.to_string();
        Ok(self)
    }

    /// Lead historical arch/os numbers (informational only).
    pub fn lead_numbers(mut self, archnum: u16, osnum: u16) -> Self {
        self.archnum = archnum;
        self.osnum = osnum;
        self
    }

    /// `RPMTAG_NAME` (tag 1000).
    pub fn name(mut self, name: &str) -> Self {
        self.upsert_tag(TAG_NAME, RpmTagValue::Str(name.to_string()));
        self
    }

    /// `RPMTAG_VERSION` (tag 1001).
    pub fn version(mut self, v: &str) -> Self {
        self.upsert_tag(TAG_VERSION, RpmTagValue::Str(v.to_string()));
        self
    }

    /// `RPMTAG_RELEASE` (tag 1002).
    pub fn release(mut self, r: &str) -> Self {
        self.upsert_tag(TAG_RELEASE, RpmTagValue::Str(r.to_string()));
        self
    }

    /// `RPMTAG_ARCH` (tag 1022).
    pub fn arch(mut self, a: &str) -> Self {
        self.upsert_tag(TAG_ARCH, RpmTagValue::Str(a.to_string()));
        self
    }

    /// Add or replace a Header tag. Region tags (62/63) and
    /// `RPMTAG_PAYLOADCOMPRESSOR` (1125) are managed by the encoder
    /// and rejected here.
    pub fn header_tag(mut self, tag: u32, value: RpmTagValue) -> Result<Self, Error> {
        if tag == SIG_REGION_TAG || tag == HDR_REGION_TAG || tag == TAG_PAYLOADCOMPRESSOR {
            return Err(Error::InvalidData("rpm: tag managed by encoder"));
        }
        self.upsert_tag(tag, value);
        Ok(self)
    }

    /// Add or replace a Signature-section tag. The region tag (62) is
    /// managed by the encoder.
    pub fn signature_tag(mut self, tag: u32, value: RpmTagValue) -> Result<Self, Error> {
        if tag == SIG_REGION_TAG || tag == HDR_REGION_TAG {
            return Err(Error::InvalidData("rpm: tag managed by encoder"));
        }
        self.sig_tags.retain(|(t, _)| *t != tag);
        self.sig_tags.push((tag, value));
        Ok(self)
    }

    /// Payload compressor (`RPMTAG_PAYLOADCOMPRESSOR`, default gzip).
    pub fn compression(mut self, c: RpmCompression) -> Self {
        self.compression = c;
        self
    }

    /// Add a payload file (encoded into `newc` cpio).
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.files.push((name.to_string(), data.to_vec()));
    }

    /// Supply ready-made cpio payload bytes instead of file lists.
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = Some(payload);
    }

    fn upsert_tag(&mut self, tag: u32, value: RpmTagValue) {
        self.header_tags.retain(|(t, _)| *t != tag);
        self.header_tags.push((tag, value));
    }

    /// Emit the `.rpm` bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        // Lead
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        out.push(self.major);
        out.push(self.minor);
        out.extend_from_slice(
            &(match self.package_type {
                RpmPackageType::Binary => 0u16,
                RpmPackageType::Source => 1u16,
            })
            .to_be_bytes(),
        );
        out.extend_from_slice(&self.archnum.to_be_bytes());
        let mut name = [0u8; 66];
        name[..self.lead_name.len()].copy_from_slice(self.lead_name.as_bytes());
        out.extend_from_slice(&name);
        out.extend_from_slice(&self.osnum.to_be_bytes());
        out.extend_from_slice(&5u16.to_be_bytes()); // signature_type: header-style
        out.resize(LEAD_SIZE, 0);

        // Signature header: region tag + caller tags.
        let mut sig_tags = self.sig_tags;
        sig_tags.push((
            SIG_REGION_TAG,
            RpmTagValue::Bin(region_trailer(SIG_REGION_TAG)),
        ));
        out.extend_from_slice(&build_header(&sig_tags));
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }

        // Header: region tag + compressor + caller tags.
        let mut header_tags = self.header_tags;
        header_tags.push((
            HDR_REGION_TAG,
            RpmTagValue::Bin(region_trailer(HDR_REGION_TAG)),
        ));
        header_tags.push((
            TAG_PAYLOADCOMPRESSOR,
            RpmTagValue::Str(compressor_name(self.compression).to_string()),
        ));
        out.extend_from_slice(&build_header(&header_tags));

        // Payload.
        let payload = match self.payload {
            Some(p) => p,
            None => build_cpio(&self.files),
        };
        out.extend_from_slice(&compress(&payload, self.compression)?);
        Ok(out)
    }
}

impl Default for RpmEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// 16-byte immutable-region BIN trailer `[tag, type 7, offset 0, 16]`.
fn region_trailer(tag: u32) -> Vec<u8> {
    let mut t = Vec::with_capacity(16);
    t.extend_from_slice(&tag.to_be_bytes());
    t.extend_from_slice(&7u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&16u32.to_be_bytes());
    t
}

/// Build one header structure: magic + counts + sorted index + data
/// store with per-type alignment padding.
fn build_header(tags: &[(u32, RpmTagValue)]) -> Vec<u8> {
    let mut sorted: Vec<&(u32, RpmTagValue)> = tags.iter().collect();
    sorted.sort_by_key(|(t, _)| *t);
    let nindex = sorted.len() as u32;

    let mut index = Vec::with_capacity(sorted.len() * 16);
    let mut data = Vec::new();
    for (tag, value) in sorted {
        while !data.len().is_multiple_of(value.align()) {
            data.push(0);
        }
        index.extend_from_slice(&tag.to_be_bytes());
        index.extend_from_slice(&value.type_code().to_be_bytes());
        index.extend_from_slice(&(data.len() as u32).to_be_bytes());
        index.extend_from_slice(&value.count().to_be_bytes());
        value.emit(&mut data);
    }

    let mut out = Vec::with_capacity(16 + index.len() + data.len());
    out.extend_from_slice(&HEADER_MAGIC);
    out.extend_from_slice(&nindex.to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&index);
    out.extend_from_slice(&data);
    out
}

fn compressor_name(c: RpmCompression) -> &'static str {
    match c {
        RpmCompression::Gzip => "gzip",
        RpmCompression::Bzip2 => "bzip2",
        RpmCompression::Lzma => "lzma",
        RpmCompression::Xz => "xz",
        RpmCompression::Zstd => "zstd",
        RpmCompression::None => "none",
    }
}

fn compress(data: &[u8], c: RpmCompression) -> Result<Vec<u8>, Error> {
    Ok(match c {
        RpmCompression::None => data.to_vec(),
        RpmCompression::Gzip => gzip::encode::encode(data, deflate::encode::Level::Default),
        RpmCompression::Bzip2 => bzip2::encode::encode(data),
        RpmCompression::Lzma => lzma_alone::encode::encode(data),
        RpmCompression::Xz => xz::encode::encode(data),
        RpmCompression::Zstd => zstd::encode::encode(data),
    })
}

fn build_cpio(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut enc = cpio::encode::CpioEncoder::new();
    for (name, data) in files {
        enc.add_file(name, data);
    }
    enc.finish()
}

/// Convenience: build a gzip `.rpm` from `name-version-release`
/// metadata and a payload file list.
pub fn encode(
    nvr: &str,
    name: &str,
    version: &str,
    release: &str,
    files: &[(&str, &[u8])],
) -> Result<Vec<u8>, Error> {
    let mut enc = RpmEncoder::new()
        .lead_name(nvr)?
        .name(name)
        .version(version)
        .release(release);
    for (n, d) in files {
        enc.add_file(n, d);
    }
    enc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::rpm::decode;

    fn basic() -> RpmEncoder {
        let mut enc = RpmEncoder::new()
            .lead_name("demo-1.0-1")
            .unwrap()
            .name("demo")
            .version("1.0")
            .release("1");
        enc.add_file("./usr/bin/demo", b"#!/bin/sh\n");
        enc
    }

    #[test]
    fn roundtrip_gzip() {
        let pkg = decode::decode(&basic().finish().unwrap()).unwrap();
        assert_eq!(pkg.lead.name, "demo-1.0-1");
        assert_eq!(pkg.lead.major, 4);
        assert_eq!(pkg.name().unwrap().unwrap(), "demo");
        assert_eq!(pkg.version().unwrap().unwrap(), "1.0");
        assert_eq!(pkg.payload_compressor().unwrap(), RpmCompression::Gzip);
        let entries = pkg.payload_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "./usr/bin/demo");
        assert_eq!(entries[0].data, b"#!/bin/sh\n");
    }

    #[test]
    fn roundtrip_all_compressions() {
        for c in [
            RpmCompression::None,
            RpmCompression::Gzip,
            RpmCompression::Bzip2,
            RpmCompression::Lzma,
            RpmCompression::Xz,
            RpmCompression::Zstd,
        ] {
            let mut enc = basic().compression(c);
            enc.add_file("./f", b"payload");
            let pkg = decode::decode(&enc.finish().unwrap())
                .unwrap_or_else(|e| panic!("decode {c:?}: {e}"));
            assert_eq!(pkg.payload_compressor().unwrap(), c, "{c:?}");
            let entries = pkg.payload_entries().unwrap();
            assert_eq!(entries.last().unwrap().data, b"payload", "{c:?}");
        }
    }

    #[test]
    fn typed_tags_roundtrip() {
        let mut enc = basic();
        enc = enc
            .header_tag(1028, RpmTagValue::Int32(alloc::vec![11, 22]))
            .unwrap()
            .header_tag(5008, RpmTagValue::Int64(alloc::vec![123456789012]))
            .unwrap()
            .header_tag(
                1117,
                RpmTagValue::StrArray(alloc::vec!["a".into(), "b".into()]),
            )
            .unwrap()
            .header_tag(9999, RpmTagValue::Bin(alloc::vec![1, 2, 3]))
            .unwrap()
            .signature_tag(269, RpmTagValue::Str("sig".into()))
            .unwrap();
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(
            pkg.header.get_i32s(1028).unwrap().unwrap(),
            alloc::vec![11, 22]
        );
        assert_eq!(
            pkg.header.get_i64s(5008).unwrap().unwrap(),
            alloc::vec![123456789012]
        );
        assert_eq!(
            pkg.header.get_strings(1117).unwrap().unwrap(),
            alloc::vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(pkg.header.get_bin(9999).unwrap().unwrap(), &[1u8, 2, 3]);
        assert_eq!(pkg.signature.get_string(269).unwrap().unwrap(), "sig");
        // Region tags are the first index entries.
        assert_eq!(pkg.signature.entries[0].tag, SIG_REGION_TAG);
        assert_eq!(pkg.header.entries[0].tag, HDR_REGION_TAG);
        // Index entries sorted by tag.
        let tags: alloc::vec::Vec<u32> = pkg.header.entries.iter().map(|e| e.tag).collect();
        assert!(tags.windows(2).all(|w| w[0] < w[1]), "{tags:?}");
    }

    #[test]
    fn managed_tags_rejected() {
        for t in [SIG_REGION_TAG, HDR_REGION_TAG, TAG_PAYLOADCOMPRESSOR] {
            assert!(basic().header_tag(t, RpmTagValue::Str("x".into())).is_err());
        }
        assert!(
            basic()
                .signature_tag(SIG_REGION_TAG, RpmTagValue::Str("x".into()))
                .is_err()
        );
    }

    #[test]
    fn lead_variants() {
        let pkg = decode::decode(
            &RpmEncoder::new()
                .major_minor(3, 0)
                .package_type(RpmPackageType::Source)
                .lead_numbers(1, 1)
                .finish()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(pkg.lead.major, 3);
        assert_eq!(pkg.lead.package_type, RpmPackageType::Source);
        assert_eq!(pkg.lead.archnum, 1);
        assert_eq!(pkg.lead.osnum, 1);
        assert_eq!(pkg.lead.signature_type, 5);

        assert!(RpmEncoder::new().lead_name(&"x".repeat(67)).is_err());
        assert!(RpmEncoder::new().lead_name("a\0b").is_err());
    }

    #[test]
    fn convenience_encode() {
        let pkg = decode::decode(
            &encode(
                "demo-2.0-3",
                "demo",
                "2.0",
                "3",
                &[("./usr/bin/demo", b"run")],
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(pkg.lead.name, "demo-2.0-3");
        assert_eq!(pkg.name().unwrap().unwrap(), "demo");
        assert_eq!(pkg.release().unwrap().unwrap(), "3");
    }
}
