//! `.rpm` package encoding (rpm.org package format).
//!
//! Emits the full container: 96-byte Lead + Signature header section
//! (with the `HEADERSIGNATURES` 62 immutable region) + 8-byte-aligned
//! padding + Header section (with the `HEADERIMMUTABLE` 63 region) +
//! compressed `newc` cpio payload. [`RpmEncoder::stripped_payload`]
//! emits rpm's own stripped `07070X` cpio variant instead, with the
//! file list carried by header tags.
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
use crate::util::{sha256, sha512};

const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
const LEAD_SIZE: usize = 96;
const SIG_REGION_TAG: u32 = 62;
const HDR_REGION_TAG: u32 = 63;
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_ARCH: u32 = 1022;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TAG_FILESIZES: u32 = 1028;
const TAG_FILEDIGESTS: u32 = 1035;
const TAG_DIRINDEXES: u32 = 1116;
const TAG_BASENAMES: u32 = 1117;
const TAG_DIRNAMES: u32 = 1118;
const TAG_LONGFILESIZES: u32 = 5008;
const TAG_FILEDIGESTALGO: u32 = 5011;
const TAG_ENCODING: u32 = 5062;
const TAG_PAYLOADSHA256: u32 = 5092;
const TAG_PAYLOADSHA256ALT: u32 = 5097;
const TAG_PAYLOADSIZE: u32 = 5112;
const TAG_PAYLOADSIZEALT: u32 = 5113;
const TAG_RPMFORMAT: u32 = 5114;
const TAG_FILEMIMEINDEX: u32 = 5115;
const TAG_MIMEDICT: u32 = 5116;
const TAG_PAYLOADSHA512: u32 = 5121;
const TAG_PAYLOADSHA512ALT: u32 = 5122;
const SIGTAG_SHA256_V6: u32 = 272;
const SIGTAG_RESERVED: u32 = 999;

/// PGPHASHALGO_SHA256 (rpm.org rpmtag.h digest algorithm numbering).
const HASHALGO_SHA256: i32 = 8;
/// Zeroed space reservation emitted as Signature tag 999 (RESERVED)
/// on v6 packages, for signatures appended after the fact.
const V6_SIG_RESERVED_BYTES: usize = 4096;
/// Header tags the v6 emit path computes itself.
const V6_MANAGED_HEADER_TAGS: &[u32] = &[
    TAG_FILEDIGESTS,
    TAG_FILEDIGESTALGO,
    TAG_ENCODING,
    TAG_PAYLOADSHA256,
    TAG_PAYLOADSHA256ALT,
    TAG_PAYLOADSIZE,
    TAG_PAYLOADSIZEALT,
    TAG_RPMFORMAT,
    TAG_FILEMIMEINDEX,
    TAG_MIMEDICT,
    TAG_PAYLOADSHA512,
    TAG_PAYLOADSHA512ALT,
];

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
    stripped: bool,
    v6: bool,
    mime_types: Vec<String>,
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
            stripped: false,
            v6: false,
            mime_types: Vec::new(),
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
    /// and rejected here. In [`v6`](Self::v6) mode the v6 required
    /// tag set is computed by the encoder as well.
    pub fn header_tag(mut self, tag: u32, value: RpmTagValue) -> Result<Self, Error> {
        if tag == SIG_REGION_TAG || tag == HDR_REGION_TAG || tag == TAG_PAYLOADCOMPRESSOR {
            return Err(Error::InvalidData("rpm: tag managed by encoder"));
        }
        if self.v6 && V6_MANAGED_HEADER_TAGS.contains(&tag) {
            return Err(Error::InvalidData("rpm: tag managed by encoder"));
        }
        self.upsert_tag(tag, value);
        Ok(self)
    }

    /// Add or replace a Signature-section tag. The region tag (62) is
    /// managed by the encoder. In [`v6`](Self::v6) mode only the
    /// cryptographic-content tags permitted by format_v6.html are
    /// accepted (267/268, 274, 276/277, 278, 279); the SHA256 (272)
    /// and RESERVED (999) tags are emitted by the encoder, and v4
    /// signature tags as well as tags above 999 are rejected.
    pub fn signature_tag(mut self, tag: u32, value: RpmTagValue) -> Result<Self, Error> {
        if tag == SIG_REGION_TAG || tag == HDR_REGION_TAG {
            return Err(Error::InvalidData("rpm: tag managed by encoder"));
        }
        if self.v6 {
            if tag == SIGTAG_SHA256_V6 || tag == SIGTAG_RESERVED {
                return Err(Error::InvalidData("rpm: tag managed by encoder"));
            }
            if !v6_sig_tag_allowed(tag) {
                return Err(Error::InvalidData(
                    "rpm: signature tag not permitted in v6 package",
                ));
            }
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

    /// Emit a stripped `07070X` payload (rpm's own cpio variant used
    /// for v6 packages and v4 packages with files >2 GiB) instead of
    /// `newc`. Stripped entries carry no names or sizes: the header
    /// file-list tags `BASENAMES` / `DIRNAMES` / `DIRINDEXES` /
    /// `FILESIZES` (or `LONGFILESIZES` for major >= 6 / large files)
    /// are emitted automatically and override caller-set values.
    /// Ignored when `set_payload` supplies raw payload bytes.
    pub fn stripped_payload(mut self) -> Self {
        self.stripped = true;
        self
    }

    /// Emit a v6 package (format_v6.html). The Lead version field
    /// stays 4 (backwards compatibility: v6 is identified by
    /// `RPMTAG_RPMFORMAT` = 6 in the Header, not the Lead) and the
    /// Lead OS/arch numbers are forced to zero, so this overrides
    /// [`major_minor`](Self::major_minor) and
    /// [`lead_numbers`](Self::lead_numbers). The stripped `07070X`
    /// payload is implied.
    ///
    /// The encoder then emits the v6 required tag set automatically
    /// (caller-set values are overridden): `RPMTAG_RPMFORMAT` (5114),
    /// `RPMTAG_ENCODING` (5062, "utf-8"), `RPMTAG_PAYLOADSHA256`/
    /// `SHA256ALT` (5092/5097), `RPMTAG_PAYLOADSHA512`/`ALT`
    /// (5121/5122), `RPMTAG_PAYLOADSIZE`/`ALT` (5112/5113, INT64), and
    /// in the Signature `SHA256` (272, hex digest of the Header blob)
    /// plus `RESERVED` (999, zeroed BIN, always the last tag). For
    /// packages built via [`add_file`](Self::add_file) the file-scoped
    /// tags are emitted as well: `RPMTAG_FILEDIGESTALGO` (5011,
    /// SHA-256), per-file `RPMTAG_FILEDIGESTS` (1035), `RPMTAG_MIMEDICT`
    /// (5116) and `RPMTAG_FILEMIMEINDEX` (5115). With
    /// [`set_payload`](Self::set_payload) there is no file list, so
    /// the file-scoped tags are omitted while the payload-level digest
    /// and size tags are still emitted.
    ///
    /// The v4 `RPMTAG_PAYLOADDIGESTALGO` (5093) selector is obsolete in
    /// v6 and is not emitted; the SHA-3 tags (Signature 279, Header
    /// 5123/5124) are intentionally out of scope.
    pub fn v6(mut self) -> Self {
        self.v6 = true;
        self.stripped = true;
        self
    }

    /// Per-file MIME types for the v6 `RPMTAG_MIMEDICT` (5116) /
    /// `RPMTAG_FILEMIMEINDEX` (5115) tags, parallel to
    /// [`add_file`](Self::add_file) call order. The encoder builds the
    /// deduplicated MIME dictionary and the per-file index into it.
    /// Files without a corresponding entry (or all files when this is
    /// not called) fall back to `application/octet-stream`. Only used
    /// in [`v6`](Self::v6) mode; ignored otherwise.
    pub fn mime_types(mut self, types: &[&str]) -> Self {
        self.mime_types = types.iter().map(|s| (*s).to_string()).collect();
        self
    }

    fn upsert_tag(&mut self, tag: u32, value: RpmTagValue) {
        self.header_tags.retain(|(t, _)| *t != tag);
        self.header_tags.push((tag, value));
    }

    /// Emit the `.rpm` bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        // In v6 mode the Signature may only carry the cryptographic
        // content tags listed by format_v6.html; a tag queued before
        // v6() was enabled is caught here.
        if self.v6 {
            for &(tag, _) in &self.sig_tags {
                if !v6_sig_tag_allowed(tag) {
                    return Err(Error::InvalidData(
                        "rpm: signature tag not permitted in v6 package",
                    ));
                }
            }
        }

        // Payload first: the v6 payload digest/size tags and the v6
        // Signature SHA256 are computed over the final payload/header
        // bytes, so compression precedes the section builds.
        let caller_payload = self.payload.is_some();
        let stripped = (self.stripped || self.v6) && !caller_payload;
        let payload = match self.payload {
            Some(p) => p,
            None if stripped => build_stripped(&self.files),
            None => build_cpio(&self.files),
        };
        let compressed = compress(&payload, self.compression)?;

        // Header: region tag + compressor + caller tags. Stripped/v6
        // file-list tags and the v6 required tag set are managed by
        // the encoder and override caller-set values.
        let mut header_tags = self.header_tags;
        if stripped {
            for (t, v) in file_list_tags(&self.files, self.v6 || self.major >= 6) {
                header_tags.retain(|(x, _)| *x != t);
                header_tags.push((t, v));
            }
        }
        if self.v6 {
            for (t, v) in v6_header_tags(
                &self.files,
                &self.mime_types,
                &payload,
                &compressed,
                !caller_payload,
            ) {
                header_tags.retain(|(x, _)| *x != t);
                header_tags.push((t, v));
            }
        }
        header_tags.push((
            HDR_REGION_TAG,
            RpmTagValue::Bin(region_trailer(HDR_REGION_TAG)),
        ));
        header_tags.push((
            TAG_PAYLOADCOMPRESSOR,
            RpmTagValue::Str(compressor_name(self.compression).to_string()),
        ));
        let header_blob = build_header(&header_tags);

        // Signature header: region tag + caller tags (+ the v6 SHA256
        // digest of the Header blob and the RESERVED space
        // reservation).
        let mut sig_tags = self.sig_tags;
        if self.v6 {
            sig_tags.push((
                SIGTAG_SHA256_V6,
                RpmTagValue::Str(hex_lower(&sha256::sha256(&header_blob))),
            ));
            sig_tags.push((
                SIGTAG_RESERVED,
                RpmTagValue::Bin(alloc::vec![0; V6_SIG_RESERVED_BYTES]),
            ));
        }
        sig_tags.push((
            SIG_REGION_TAG,
            RpmTagValue::Bin(region_trailer(SIG_REGION_TAG)),
        ));
        let sig_blob = build_header(&sig_tags);

        // Lead. v6 packages keep version 4 and zeroed OS/arch numbers
        // for backwards compatibility (format_v6.html).
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
        let (major, minor, archnum, osnum) = if self.v6 {
            (4, 0, 0, 0)
        } else {
            (self.major, self.minor, self.archnum, self.osnum)
        };
        out.push(major);
        out.push(minor);
        out.extend_from_slice(
            &(match self.package_type {
                RpmPackageType::Binary => 0u16,
                RpmPackageType::Source => 1u16,
            })
            .to_be_bytes(),
        );
        out.extend_from_slice(&archnum.to_be_bytes());
        let mut name = [0u8; 66];
        name[..self.lead_name.len()].copy_from_slice(self.lead_name.as_bytes());
        out.extend_from_slice(&name);
        out.extend_from_slice(&osnum.to_be_bytes());
        out.extend_from_slice(&5u16.to_be_bytes()); // signature_type: header-style
        out.resize(LEAD_SIZE, 0);

        out.extend_from_slice(&sig_blob);
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        out.extend_from_slice(&header_blob);
        out.extend_from_slice(&compressed);
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

/// Signature tags a caller may set on a v6 package: the
/// cryptographic-content tags of format_v6.html (legacy RSA/DSA,
/// FILESIGNATURES, VERITYSIGNATURES/ALGO, OPENPGP, SHA3_256). The
/// region tag (62), SHA256 (272) and RESERVED (999) are emitted by
/// the encoder; tags above 999 and the v4 digest/size tags are
/// illegal in a v6 Signature.
fn v6_sig_tag_allowed(tag: u32) -> bool {
    matches!(tag, 267 | 268 | 274 | 276 | 277 | 278 | 279)
}

/// Lowercase hex encoding for STRING digest tags.
fn hex_lower(bytes: &[u8]) -> String {
    use alloc::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The v6 required Header tag set (format_v6.html): RPMFORMAT,
/// ENCODING, and the payload digest/size pairs computed over the
/// stored (compressed) and uncompressed payload bytes. When the
/// package is built from `add_file` entries (`file_tags`), the
/// file-scoped tags are emitted as well: FILEDIGESTALGO + per-file
/// SHA-256 FILEDIGESTS and the MIME dictionary/index pair.
fn v6_header_tags(
    files: &[(String, Vec<u8>)],
    mime_types: &[String],
    payload: &[u8],
    compressed: &[u8],
    file_tags: bool,
) -> Vec<(u32, RpmTagValue)> {
    let mut tags = alloc::vec![
        (TAG_RPMFORMAT, RpmTagValue::Int32(alloc::vec![6])),
        (TAG_ENCODING, RpmTagValue::Str("utf-8".to_string())),
        (
            TAG_PAYLOADSHA256,
            RpmTagValue::StrArray(alloc::vec![hex_lower(&sha256::sha256(compressed))]),
        ),
        (
            TAG_PAYLOADSHA256ALT,
            RpmTagValue::StrArray(alloc::vec![hex_lower(&sha256::sha256(payload))]),
        ),
        (
            TAG_PAYLOADSHA512,
            RpmTagValue::StrArray(alloc::vec![hex_lower(&sha512::sha512(compressed))]),
        ),
        (
            TAG_PAYLOADSHA512ALT,
            RpmTagValue::StrArray(alloc::vec![hex_lower(&sha512::sha512(payload))]),
        ),
        (
            TAG_PAYLOADSIZE,
            RpmTagValue::Int64(alloc::vec![compressed.len() as i64]),
        ),
        (
            TAG_PAYLOADSIZEALT,
            RpmTagValue::Int64(alloc::vec![payload.len() as i64]),
        ),
    ];
    if file_tags {
        tags.push((
            TAG_FILEDIGESTALGO,
            RpmTagValue::Int32(alloc::vec![HASHALGO_SHA256]),
        ));
        tags.push((
            TAG_FILEDIGESTS,
            RpmTagValue::StrArray(
                files
                    .iter()
                    .map(|(_, data)| hex_lower(&sha256::sha256(data)))
                    .collect(),
            ),
        ));
        // MIMEDICT: deduplicated MIME dictionary; FILEMIMEINDEX:
        // per-file index into it. Missing entries fall back to the
        // generic binary type.
        let mut dict: Vec<String> = Vec::new();
        let mut index = Vec::with_capacity(files.len());
        for i in 0..files.len() {
            let mime = mime_types
                .get(i)
                .map(String::as_str)
                .unwrap_or("application/octet-stream");
            let di = match dict.iter().position(|d| d == mime) {
                Some(i) => i,
                None => {
                    dict.push(mime.to_string());
                    dict.len() - 1
                }
            };
            index.push(di as i32);
        }
        tags.push((TAG_MIMEDICT, RpmTagValue::StrArray(dict)));
        tags.push((TAG_FILEMIMEINDEX, RpmTagValue::Int32(index)));
    }
    tags
}

/// Header file-list tags for a stripped payload: per-file basename,
/// deduplicated dirname list (trailing `/` retained), per-file dir
/// index, and file sizes (`LONGFILESIZES` when `long`, i.e. for v6 /
/// >2 GiB files).
fn file_list_tags(files: &[(String, Vec<u8>)], long: bool) -> Vec<(u32, RpmTagValue)> {
    let mut dirs: Vec<String> = Vec::new();
    let mut dir_index = Vec::with_capacity(files.len());
    let mut basenames = Vec::with_capacity(files.len());
    for (name, _) in files {
        let (dir, base) = match name.rfind('/') {
            Some(i) => (&name[..=i], &name[i + 1..]),
            None => ("", name.as_str()),
        };
        let di = match dirs.iter().position(|d| d == dir) {
            Some(i) => i,
            None => {
                dirs.push(dir.to_string());
                dirs.len() - 1
            }
        };
        dir_index.push(di as i32);
        basenames.push(base.to_string());
    }
    let mut tags = vec![
        (TAG_BASENAMES, RpmTagValue::StrArray(basenames)),
        (TAG_DIRNAMES, RpmTagValue::StrArray(dirs)),
        (TAG_DIRINDEXES, RpmTagValue::Int32(dir_index)),
    ];
    if long || files.iter().any(|(_, d)| d.len() > i32::MAX as usize) {
        tags.push((
            TAG_LONGFILESIZES,
            RpmTagValue::Int64(files.iter().map(|(_, d)| d.len() as i64).collect()),
        ));
    } else {
        tags.push((
            TAG_FILESIZES,
            RpmTagValue::Int32(files.iter().map(|(_, d)| d.len() as i32).collect()),
        ));
    }
    tags
}

/// Stripped `07070X` payload: 4-aligned `07070X` + 8-hex-digit file
/// index + raw file data, terminated by the regular newc
/// `TRAILER!!!` entry (an empty cpio archive).
fn build_stripped(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (fx, (_, data)) in files.iter().enumerate() {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(b"07070X");
        out.extend_from_slice(alloc::format!("{fx:08x}").as_bytes());
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
    }
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    out.extend_from_slice(&cpio::encode::CpioEncoder::new().finish());
    out
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

    #[test]
    fn stripped_roundtrip() {
        let mut enc = basic().stripped_payload();
        enc.add_file("usr/share/doc/readme.txt", b"docs");
        enc.add_file("top_level.txt", b"no dir");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        let entries = pkg.payload_entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, "./usr/bin/demo");
        assert_eq!(entries[0].file_index, Some(0));
        assert_eq!(entries[0].data, b"#!/bin/sh\n");
        assert_eq!(entries[1].name, "usr/share/doc/readme.txt");
        assert_eq!(entries[1].file_index, Some(1));
        assert_eq!(entries[2].name, "top_level.txt");
        assert_eq!(entries[2].data, b"no dir");
    }

    #[test]
    fn stripped_v6_uses_longfilesizes() {
        let enc = basic().stripped_payload().major_minor(6, 0);
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        // v6 path emits LONGFILESIZES; decoder resolves it.
        let entries = pkg.payload_entries().unwrap();
        assert_eq!(entries[0].data, b"#!/bin/sh\n");
    }

    #[test]
    fn stripped_payload_bytes_layout() {
        // Raw (uncompressed) payload should contain aligned 07070X
        // records terminated by the newc TRAILER!!! entry.
        let mut enc = RpmEncoder::new()
            .compression(RpmCompression::None)
            .stripped_payload();
        enc.add_file("a/b.txt", b"xy");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        let raw = pkg.payload().unwrap();
        assert!(raw.starts_with(b"07070X"));
        assert!(raw.windows(10).any(|w| w == b"TRAILER!!!"));
    }

    fn v6() -> RpmEncoder {
        let mut enc = basic().v6();
        enc.add_file("etc/demo.conf", b"key=value\n");
        enc
    }

    #[test]
    fn v6_roundtrip() {
        let bytes = v6().finish().unwrap();
        let pkg = decode::decode(&bytes).unwrap();
        // Lead stays at version 4 for backwards compatibility; v6 is
        // identified by RPMTAG_RPMFORMAT.
        assert_eq!(pkg.lead.major, 4);
        assert_eq!(pkg.lead.minor, 0);
        assert_eq!(pkg.lead.archnum, 0);
        assert_eq!(pkg.lead.osnum, 0);
        assert_eq!(pkg.header.get_i32s(TAG_RPMFORMAT).unwrap().unwrap(), [6]);
        assert_eq!(
            pkg.header.get_string(TAG_ENCODING).unwrap().unwrap(),
            "utf-8"
        );
        assert_eq!(
            pkg.header.get_i32s(TAG_FILEDIGESTALGO).unwrap().unwrap(),
            [HASHALGO_SHA256]
        );
        // Per-file SHA-256 digests.
        let digests = pkg.header.get_strings(TAG_FILEDIGESTS).unwrap().unwrap();
        assert_eq!(digests.len(), 2);
        assert_eq!(digests[0], hex_lower(&sha256::sha256(b"#!/bin/sh\n")));
        // Payload digest/size pairs.
        for tag in [
            TAG_PAYLOADSHA256,
            TAG_PAYLOADSHA256ALT,
            TAG_PAYLOADSHA512,
            TAG_PAYLOADSHA512ALT,
        ] {
            assert_eq!(
                pkg.header.get_strings(tag).unwrap().unwrap().len(),
                1,
                "tag {tag}"
            );
        }
        assert_eq!(
            pkg.header.get_i64s(TAG_PAYLOADSIZE).unwrap().unwrap().len(),
            1
        );
        assert_eq!(
            pkg.header
                .get_i64s(TAG_PAYLOADSIZEALT)
                .unwrap()
                .unwrap()
                .len(),
            1
        );
        // Payload digests verify (5092/5097 default to SHA-256 on v6;
        // 5121/5122 are SHA-512).
        let checks = pkg.verify_digests().unwrap();
        assert!(checks.iter().all(|c| c.matches()), "{checks:?}");
        for tag in [
            SIGTAG_SHA256_V6,
            TAG_PAYLOADSHA256,
            TAG_PAYLOADSHA256ALT,
            TAG_PAYLOADSHA512,
            TAG_PAYLOADSHA512ALT,
        ] {
            assert!(checks.iter().any(|c| c.tag == tag), "tag {tag}");
        }
        // Signature carries only region + SHA256 + RESERVED; RESERVED
        // is the last tag and all zeros.
        let sig_tags: alloc::vec::Vec<u32> = pkg.signature.entries.iter().map(|e| e.tag).collect();
        assert_eq!(
            sig_tags,
            [SIG_REGION_TAG, SIGTAG_SHA256_V6, SIGTAG_RESERVED]
        );
        let reserved = pkg.signature.get_bin(SIGTAG_RESERVED).unwrap().unwrap();
        assert!(reserved.iter().all(|&b| b == 0));
        // Stripped payload with the v6 file list.
        let entries = pkg.payload_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "./usr/bin/demo");
        assert_eq!(entries[0].data, b"#!/bin/sh\n");
        assert_eq!(entries[1].name, "etc/demo.conf");
        assert!(pkg.header.find(TAG_LONGFILESIZES).is_some());
        assert!(pkg.header.find(TAG_FILESIZES).is_none());
        // No v4 PAYLOADDIGESTALGO selector and no SHA-3 tags.
        assert!(pkg.header.find(5093).is_none());
        for tag in [279u32, 5123, 5124] {
            assert!(pkg.header.find(tag).is_none());
            assert!(pkg.signature.find(tag).is_none());
        }
    }

    #[test]
    fn v6_mime_dict() {
        // MIME entries are parallel to add_file order; the dictionary
        // is deduplicated and FILEMIMEINDEX points into it.
        let mut enc = basic()
            .v6()
            .mime_types(&["text/plain", "text/plain", "application/x-conf"]);
        enc.add_file("etc/a.conf", b"a=1\n");
        enc.add_file("etc/b.bin", b"\x00\x01");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(
            pkg.header.get_strings(TAG_MIMEDICT).unwrap().unwrap(),
            alloc::vec!["text/plain", "application/x-conf"]
        );
        assert_eq!(
            pkg.header.get_i32s(TAG_FILEMIMEINDEX).unwrap().unwrap(),
            [0, 0, 1]
        );

        // Missing entries and an unset mime_types fall back to
        // application/octet-stream.
        let pkg = decode::decode(&v6().finish().unwrap()).unwrap();
        assert_eq!(
            pkg.header.get_strings(TAG_MIMEDICT).unwrap().unwrap(),
            alloc::vec!["application/octet-stream"]
        );
        assert_eq!(
            pkg.header.get_i32s(TAG_FILEMIMEINDEX).unwrap().unwrap(),
            [0, 0]
        );
    }

    #[test]
    fn v6_signature_tag_rejected() {
        // v4 signature tags and tags >999 are illegal in a v6
        // Signature; SHA256 (272) and RESERVED (999) are managed.
        for tag in [269u32, 273, 1000, 1004, 1007] {
            assert!(
                basic()
                    .v6()
                    .signature_tag(tag, RpmTagValue::Str("x".into()))
                    .is_err(),
                "tag {tag}"
            );
        }
        for tag in [SIGTAG_SHA256_V6, SIGTAG_RESERVED] {
            assert!(
                basic()
                    .v6()
                    .signature_tag(tag, RpmTagValue::Str("x".into()))
                    .is_err(),
                "tag {tag}"
            );
        }
        // A tag queued before v6() is enabled is rejected at finish().
        let enc = basic()
            .signature_tag(269, RpmTagValue::Str("sig".into()))
            .unwrap()
            .v6();
        assert!(enc.finish().is_err());
        // Permitted cryptographic-content tags still work.
        let pkg = decode::decode(
            &v6()
                .signature_tag(274, RpmTagValue::StrArray(alloc::vec!["sig".into()]))
                .unwrap()
                .finish()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            pkg.signature.get_strings(274).unwrap().unwrap(),
            alloc::vec!["sig".to_string()]
        );
    }

    #[test]
    fn v6_managed_header_tags_rejected() {
        for &tag in V6_MANAGED_HEADER_TAGS {
            assert!(
                basic()
                    .v6()
                    .header_tag(tag, RpmTagValue::Str("x".into()))
                    .is_err(),
                "tag {tag}"
            );
        }
        // A tag queued before v6() is enabled is overridden by the
        // encoder's value at finish().
        let mut enc = basic()
            .header_tag(TAG_ENCODING, RpmTagValue::Str("latin1".into()))
            .unwrap()
            .v6();
        enc.add_file("f.bin", b"x");
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(
            pkg.header.get_string(TAG_ENCODING).unwrap().unwrap(),
            "utf-8"
        );
    }

    #[test]
    fn v6_set_payload_skips_file_tags() {
        // Raw payload bytes: payload-level digest/size tags are still
        // emitted, but the file-scoped tags have no file list to cover.
        let mut enc = basic().v6();
        enc.set_payload(build_cpio(&enc.files));
        let pkg = decode::decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(pkg.header.get_i32s(TAG_RPMFORMAT).unwrap().unwrap(), [6]);
        assert!(pkg.header.find(TAG_PAYLOADSHA256).is_some());
        assert!(pkg.header.find(TAG_PAYLOADSIZE).is_some());
        assert!(pkg.header.find(TAG_FILEDIGESTS).is_none());
        assert!(pkg.header.find(TAG_MIMEDICT).is_none());
        let entries = pkg.payload_entries().unwrap();
        assert_eq!(entries[0].data, b"#!/bin/sh\n");
    }
}
