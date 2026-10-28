//! `.rpm` package decoding (read-only).
//!
//! Layout per the rpm.org file format documentation:
//!
//! 1. Lead — 96 bytes: `ED AB EE DB` magic, format version, package type,
//!    package name, OS/arch numbers, signature type, reserved.
//! 2. Signature — an RPM "header structure" whose first tag is 62
//!    (`RPMTAG_HEADERSIGNATURES`), padded to an 8-byte boundary.
//! 3. Header — a header structure whose first tag is 63
//!    (`RPMTAG_HEADERIMMUTABLE`).
//! 4. Payload — compressed cpio. v4 packages use `newc` (`070701`); v6
//!    packages and v4 packages with files >= 4 GB use the stripped cpio
//!    variant (`07070X` + 8-hex-digit file index), where file sizes and
//!    names come from the header's file list tags.
//!
//! Signature verification and package-manager semantics (install scripts,
//! dependencies, file classification) are intentionally out of scope.
//! Digest tags (Signature MD5/SHA1/SHA256, Header PAYLOADDIGEST family)
//! can be checked opt-in via RpmPackage::verify_digests.

use alloc::string::String;
use alloc::vec::Vec;

use crate::archive::cpio;
use crate::compress::{bzip2, gzip, lzma_alone, xz, zstd};
use crate::error::Error;
use crate::util::{md5, sha1, sha256, sha512};

const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const LEAD_SIZE: usize = 96;
const HEADER_MAGIC: [u8; 8] = [0x8E, 0xAD, 0xE8, 0x01, 0x00, 0x00, 0x00, 0x00];
const HEADER_INTRO_SIZE: usize = 16;
const INDEX_ENTRY_SIZE: usize = 16;
const SIG_REGION_TAG: u32 = 62;
const HDR_REGION_TAG: u32 = 63;
const STRIPPED_MAGIC: &[u8; 6] = b"07070X";
const STRIPPED_ENTRY_SIZE: usize = 14;
const STRIPPED_TRAILER: u32 = u32::MAX;
const NEWC_MAGIC: &[u8; 6] = b"070701";
const NEWCRC_MAGIC: &[u8; 6] = b"070702";
const CPIO_TRAILER: &str = "TRAILER!!!";

// Header tags (rpm.org rpmtag.h).
const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_ARCH: u32 = 1022;
const TAG_FILESIZES: u32 = 1028;
const TAG_FILEMODES: u32 = 1030;
const TAG_DIRINDEXES: u32 = 1116;
const TAG_BASENAMES: u32 = 1117;
const TAG_DIRNAMES: u32 = 1118;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TAG_LONGFILESIZES: u32 = 5008;

// Digest tags (rpm.org rpmtag.h / format_v6.html). The Signature digests
// cover the header blob (+ payload for MD5); the Header PAYLOADDIGEST
// family covers the payload with the algorithm named by
// PAYLOADDIGESTALGO (1=MD5, 2=SHA-1, 8=SHA-256, 10=SHA-512).
const SIGTAG_SHA1: u32 = 269;
const SIGTAG_SHA256_V6: u32 = 272;
const SIGTAG_SHA256_V4: u32 = 273;
const SIGTAG_MD5: u32 = 1004;
const TAG_PAYLOADDIGEST: u32 = 5092;
const TAG_PAYLOADDIGESTALGO: u32 = 5093;
const TAG_PAYLOADDIGESTALT: u32 = 5097;
const TAG_RPMFORMAT: u32 = 5114;
const TAG_PAYLOADSHA512: u32 = 5121;
const TAG_PAYLOADSHA512ALT: u32 = 5122;

/// Package type from the Lead (`type` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmPackageType {
    /// Binary package (type 0).
    Binary,
    /// Source package (type 1).
    Source,
}

/// Parsed Lead (96-byte prefix identifying the file as an RPM package).
///
/// The Lead fields other than the magic are historical and not used by RPM
/// itself; they are preserved for inspection only.
#[derive(Debug, Clone)]
pub struct RpmLead {
    /// RPM file format major version (3 for v3/v4 packages, 4 for v6).
    pub major: u8,
    /// RPM file format minor version.
    pub minor: u8,
    /// Package type.
    pub package_type: RpmPackageType,
    /// Architecture number (historical; the real arch lives in the Header).
    pub archnum: u16,
    /// Package `name-version-release` string (NUL-padded, 66 bytes).
    pub name: String,
    /// OS number (historical).
    pub osnum: u16,
    /// Signature type (5 indicates header-style signatures).
    pub signature_type: u16,
}

/// Tag value data type (RPM header structure type codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmTagType {
    /// CHAR (1).
    Char,
    /// INT8 (2).
    Int8,
    /// INT16 (3).
    Int16,
    /// INT32 (4).
    Int32,
    /// INT64 (5).
    Int64,
    /// STRING (6) — NUL-terminated string, count must be 1.
    String,
    /// BIN (7) — binary blob.
    Bin,
    /// STRING_ARRAY (8).
    StringArray,
    /// I18NSTRING (9).
    I18nString,
}

impl RpmTagType {
    fn from_raw(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Char),
            2 => Some(Self::Int8),
            3 => Some(Self::Int16),
            4 => Some(Self::Int32),
            5 => Some(Self::Int64),
            6 => Some(Self::String),
            7 => Some(Self::Bin),
            8 => Some(Self::StringArray),
            9 => Some(Self::I18nString),
            _ => None,
        }
    }
}

/// A single index entry of an RPM header structure.
#[derive(Debug, Clone, Copy)]
pub struct RpmTagEntry {
    /// Tag identifier.
    pub tag: u32,
    /// Data type code.
    pub tag_type: u32,
    /// Byte offset into the section's data store.
    pub offset: u32,
    /// Number of values.
    pub count: u32,
}

impl RpmTagEntry {
    /// The typed variant of [`Self::tag_type`], if recognized.
    pub fn data_type(&self) -> Option<RpmTagType> {
        RpmTagType::from_raw(self.tag_type)
    }
}

/// A parsed RPM header structure (used for both Signature and Header).
#[derive(Debug, Clone)]
pub struct RpmHeaderSection {
    /// Index entries, sorted by tag (unsorted or duplicate-tag input
    /// is rejected).
    pub entries: Vec<RpmTagEntry>,
    /// Raw data store bytes.
    pub data: Vec<u8>,
}

impl RpmHeaderSection {
    /// Find the index entry for `tag`.
    pub fn find(&self, tag: u32) -> Option<&RpmTagEntry> {
        self.entries.iter().find(|entry| entry.tag == tag)
    }

    /// Slice of the data store covered by `entry`, bounds-checked.
    fn entry_bytes(&self, entry: &RpmTagEntry, len: usize) -> Result<&[u8], Error> {
        let start = entry.offset as usize;
        let end = start
            .checked_add(len)
            .ok_or(Error::InvalidData("rpm: tag data offset overflow"))?;
        if end > self.data.len() {
            return Err(Error::InvalidData("rpm: tag data out of bounds"));
        }
        Ok(&self.data[start..end])
    }

    /// Raw bytes of a BIN tag (also works for CHAR/INT8 blobs).
    pub fn get_bin(&self, tag: u32) -> Option<Result<&[u8], Error>> {
        self.find(tag)
            .map(|entry| self.entry_bytes(entry, entry.count as usize))
    }

    /// First NUL-terminated string of a STRING / STRING_ARRAY / I18NSTRING
    /// tag. Non-UTF8 content is converted with `String::from_utf8_lossy`.
    pub fn get_string(&self, tag: u32) -> Option<Result<String, Error>> {
        self.get_strings(tag).map(|r| {
            r.map(|mut v| {
                if v.is_empty() {
                    String::new()
                } else {
                    v.remove(0)
                }
            })
        })
    }

    /// All strings of a STRING_ARRAY / I18NSTRING tag (or the single string
    /// of a STRING tag).
    pub fn get_strings(&self, tag: u32) -> Option<Result<Vec<String>, Error>> {
        let entry = self.find(tag)?;
        let data_type = entry.data_type()?;
        match data_type {
            RpmTagType::String | RpmTagType::StringArray | RpmTagType::I18nString => {}
            _ => {
                return Some(Err(Error::InvalidData("rpm: tag is not a string type")));
            }
        }
        let mut offset = entry.offset as usize;
        let mut strings = Vec::with_capacity(entry.count as usize);
        let result = (|| {
            for _ in 0..entry.count {
                let rest = self
                    .data
                    .get(offset..)
                    .ok_or(Error::InvalidData("rpm: string offset out of bounds"))?;
                let end = rest
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Error::InvalidData("rpm: unterminated string"))?;
                strings.push(String::from_utf8_lossy(&rest[..end]).into_owned());
                offset += end + 1;
            }
            Ok(())
        })();
        Some(result.map(|()| strings))
    }

    /// All values of an INT32 tag.
    pub fn get_i32s(&self, tag: u32) -> Option<Result<Vec<i32>, Error>> {
        let entry = self.find(tag)?;
        if entry.data_type() != Some(RpmTagType::Int32) {
            return Some(Err(Error::InvalidData("rpm: tag is not INT32")));
        }
        Some(
            self.entry_bytes(entry, 4 * entry.count as usize)
                .map(|bytes| {
                    bytes
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| i32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                        .collect()
                }),
        )
    }

    /// All values of an INT64 tag.
    pub fn get_i64s(&self, tag: u32) -> Option<Result<Vec<i64>, Error>> {
        let entry = self.find(tag)?;
        if entry.data_type() != Some(RpmTagType::Int64) {
            return Some(Err(Error::InvalidData("rpm: tag is not INT64")));
        }
        Some(
            self.entry_bytes(entry, 8 * entry.count as usize)
                .map(|bytes| {
                    bytes
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| {
                            i64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])
                        })
                        .collect()
                }),
        )
    }
}

/// Payload compression named by `RPMTAG_PAYLOADCOMPRESSOR` (tag 1125).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmCompression {
    /// Uncompressed cpio payload.
    None,
    /// gzip payload (the rpm default).
    Gzip,
    /// bzip2 payload.
    Bzip2,
    /// LZMA-Alone payload.
    Lzma,
    /// xz payload.
    Xz,
    /// zstd payload.
    Zstd,
}

/// A file extracted from the package payload.
#[derive(Debug, Clone)]
pub struct RpmPayloadEntry {
    /// Resolved path. For `newc` payloads this is the cpio filename; for
    /// stripped payloads it is `dirnames[dirindexes[fx]] + basenames[fx]`
    /// when those header tags are present, otherwise `fx` formatted as a
    /// hex index.
    pub name: String,
    /// File index into the header file list (stripped cpio payloads only).
    pub file_index: Option<u32>,
    /// File content. For symlinks this is the link target.
    pub data: Vec<u8>,
    /// True when the payload entry is a directory.
    pub is_dir: bool,
}

impl crate::traits::ArchiveEntry for RpmPayloadEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Digest algorithm used by a package digest tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmDigestAlgorithm {
    /// MD5 (RPMSIGTAG_MD5, RPMTAG_PAYLOADDIGESTALGO 1).
    Md5,
    /// SHA-1 (RPMSIGTAG_SHA1, RPMTAG_PAYLOADDIGESTALGO 2).
    Sha1,
    /// SHA-256 (RPMSIGTAG_SHA256, RPMTAG_PAYLOADDIGESTALGO 8).
    Sha256,
    /// SHA-512 (RPMTAG_PAYLOADDIGESTALGO 10).
    Sha512,
}

/// Byte range a package digest tag is computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpmDigestTarget {
    /// The Header section blob.
    Header,
    /// The Header blob followed by the stored payload bytes.
    HeaderAndPayload,
    /// The stored (compressed) payload bytes.
    PayloadCompressed,
    /// The decompressed payload bytes.
    PayloadUncompressed,
}

/// Outcome of checking one digest tag against the package bytes.
#[derive(Debug, Clone)]
pub struct RpmDigestCheck {
    /// Tag the stored digest was read from.
    pub tag: u32,
    /// Digest algorithm the tag uses.
    pub algorithm: RpmDigestAlgorithm,
    /// Byte range the digest covers.
    pub target: RpmDigestTarget,
    /// Digest value stored in the tag.
    pub expected: Vec<u8>,
    /// Digest recomputed over the covered bytes.
    pub actual: Vec<u8>,
}

impl RpmDigestCheck {
    /// Whether the stored digest equals the recomputed one.
    pub fn matches(&self) -> bool {
        self.expected == self.actual
    }
}

/// A decoded `.rpm` package.
#[derive(Debug, Clone)]
pub struct RpmPackage {
    /// Parsed Lead fields.
    pub lead: RpmLead,
    /// Signature header structure.
    pub signature: RpmHeaderSection,
    /// Main header structure.
    pub header: RpmHeaderSection,
    header_raw: Vec<u8>,
    payload_compressed: Vec<u8>,
}

impl RpmPackage {
    /// Package name (`RPMTAG_NAME`, tag 1000) if present.
    pub fn name(&self) -> Option<Result<String, Error>> {
        self.header.get_string(TAG_NAME)
    }

    /// Package version (`RPMTAG_VERSION`, tag 1001) if present.
    pub fn version(&self) -> Option<Result<String, Error>> {
        self.header.get_string(TAG_VERSION)
    }

    /// Package release (`RPMTAG_RELEASE`, tag 1002) if present.
    pub fn release(&self) -> Option<Result<String, Error>> {
        self.header.get_string(TAG_RELEASE)
    }

    /// Package architecture (`RPMTAG_ARCH`, tag 1022) if present.
    pub fn arch(&self) -> Option<Result<String, Error>> {
        self.header.get_string(TAG_ARCH)
    }

    /// Payload compression from `RPMTAG_PAYLOADCOMPRESSOR` (tag 1125).
    /// Defaults to gzip when the tag is absent, matching rpm behavior.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] for unrecognized compressor names.
    pub fn payload_compressor(&self) -> Result<RpmCompression, Error> {
        let Some(result) = self.header.get_string(TAG_PAYLOADCOMPRESSOR) else {
            return Ok(RpmCompression::Gzip);
        };
        let name = result?;
        match name.as_str() {
            "gzip" => Ok(RpmCompression::Gzip),
            "bzip2" => Ok(RpmCompression::Bzip2),
            "lzma" => Ok(RpmCompression::Lzma),
            "xz" => Ok(RpmCompression::Xz),
            "zstd" => Ok(RpmCompression::Zstd),
            "none" | "" => Ok(RpmCompression::None),
            _ => Err(Error::Unsupported("rpm: unsupported payload compressor")),
        }
    }

    /// Verify the digest tags carried by the Signature and Header
    /// sections against the package bytes. Returns one RpmDigestCheck
    /// per digest tag found (empty when the package carries none).
    /// Verification is opt-in: decode never checks digests.
    ///
    /// Covered tags (rpm.org rpmtag.h, format_v6.html):
    ///
    /// - Signature 1004 (RPMSIGTAG_MD5, BIN): MD5 over header + payload.
    /// - Signature 269 (RPMSIGTAG_SHA1, STRING hex): SHA-1 over the
    ///   header blob.
    /// - Signature 272/273 (RPMSIGTAG_SHA256, STRING hex): SHA-256 over
    ///   the header blob (272 is the v6 numbering, 273 the v4 one).
    /// - Header 5092 (RPMTAG_PAYLOADDIGEST, STRING_ARRAY hex): digest
    ///   over the stored (compressed) payload.
    /// - Header 5097 (RPMTAG_PAYLOADDIGESTALT): digest over the
    ///   decompressed payload. The algorithm for both comes from
    ///   RPMTAG_PAYLOADDIGESTALGO (5093). On v6 packages
    ///   (RPMTAG_RPMFORMAT 5114 = 6) these tags are
    ///   RPMTAG_PAYLOADSHA256[/ALT]: SHA-256 without the obsolete
    ///   5093 selector.
    /// - Header 5121/5122 (RPMTAG_PAYLOADSHA512[/ALT], v6): SHA-512
    ///   over the compressed / decompressed payload.
    ///
    /// OpenPGP signature verification remains out of scope.
    ///
    /// # Errors
    ///
    /// Returns Error::InvalidData for malformed digest tags (bad hex or
    /// PAYLOADDIGEST without PAYLOADDIGESTALGO on non-v6 packages),
    /// Error::Unsupported for digest algorithms without an
    /// implementation, and payload decompression errors for the ALT
    /// tags.
    pub fn verify_digests(&self) -> Result<Vec<RpmDigestCheck>, Error> {
        let mut checks = Vec::new();

        if let Some(result) = self.signature.get_bin(SIGTAG_MD5) {
            let mut hasher = md5::Md5::new();
            hasher.update(&self.header_raw);
            hasher.update(&self.payload_compressed);
            checks.push(RpmDigestCheck {
                tag: SIGTAG_MD5,
                algorithm: RpmDigestAlgorithm::Md5,
                target: RpmDigestTarget::HeaderAndPayload,
                expected: result?.to_vec(),
                actual: hasher.finish().to_vec(),
            });
        }
        for (tag, algorithm) in [
            (SIGTAG_SHA1, RpmDigestAlgorithm::Sha1),
            (SIGTAG_SHA256_V6, RpmDigestAlgorithm::Sha256),
            (SIGTAG_SHA256_V4, RpmDigestAlgorithm::Sha256),
        ] {
            let Some(result) = self.signature.get_string(tag) else {
                continue;
            };
            let expected = parse_hex_digest(&result?)?;
            let actual = match algorithm {
                RpmDigestAlgorithm::Sha1 => sha1::sha1(&self.header_raw).to_vec(),
                _ => sha256::sha256(&self.header_raw).to_vec(),
            };
            checks.push(RpmDigestCheck {
                tag,
                algorithm,
                target: RpmDigestTarget::Header,
                expected,
                actual,
            });
        }

        // v6 packages mark themselves with RPMTAG_RPMFORMAT (5114) = 6;
        // there, tags 5092/5097 are RPMTAG_PAYLOADSHA256[/ALT] and need
        // no PAYLOADDIGESTALGO selector (obsolete in v6).
        let rpmformat = match self.header.get_i32s(TAG_RPMFORMAT) {
            Some(result) => result?.first().copied(),
            None => None,
        };
        let is_v6 = rpmformat == Some(6);

        if self.header.find(TAG_PAYLOADDIGEST).is_some()
            || self.header.find(TAG_PAYLOADDIGESTALT).is_some()
        {
            let algorithm = match self.header.get_i32s(TAG_PAYLOADDIGESTALGO) {
                Some(result) => match result?.first() {
                    Some(&1) => RpmDigestAlgorithm::Md5,
                    Some(&2) => RpmDigestAlgorithm::Sha1,
                    Some(&8) => RpmDigestAlgorithm::Sha256,
                    Some(&10) => RpmDigestAlgorithm::Sha512,
                    _ => {
                        return Err(Error::Unsupported(
                            "rpm: unsupported payload digest algorithm",
                        ));
                    }
                },
                None if is_v6 => RpmDigestAlgorithm::Sha256,
                None => {
                    return Err(Error::InvalidData(
                        "rpm: PAYLOADDIGEST without PAYLOADDIGESTALGO",
                    ));
                }
            };
            if let Some(result) = self.header.get_strings(TAG_PAYLOADDIGEST) {
                let actual = digest_of(algorithm, &self.payload_compressed);
                for string in result? {
                    checks.push(RpmDigestCheck {
                        tag: TAG_PAYLOADDIGEST,
                        algorithm,
                        target: RpmDigestTarget::PayloadCompressed,
                        expected: parse_hex_digest(&string)?,
                        actual: actual.clone(),
                    });
                }
            }
            if let Some(result) = self.header.get_strings(TAG_PAYLOADDIGESTALT) {
                let actual = digest_of(algorithm, &self.payload()?);
                for string in result? {
                    checks.push(RpmDigestCheck {
                        tag: TAG_PAYLOADDIGESTALT,
                        algorithm,
                        target: RpmDigestTarget::PayloadUncompressed,
                        expected: parse_hex_digest(&string)?,
                        actual: actual.clone(),
                    });
                }
            }
        }

        // v6 per-algorithm payload digests (5121 compressed /
        // 5122 uncompressed); SHA-3 tags 5123/5124 are not covered.
        for (tag, target) in [
            (TAG_PAYLOADSHA512, RpmDigestTarget::PayloadCompressed),
            (TAG_PAYLOADSHA512ALT, RpmDigestTarget::PayloadUncompressed),
        ] {
            let Some(result) = self.header.get_strings(tag) else {
                continue;
            };
            let data = match target {
                RpmDigestTarget::PayloadCompressed => self.payload_compressed.clone(),
                _ => self.payload()?,
            };
            let actual = sha512::sha512(&data).to_vec();
            for string in result? {
                checks.push(RpmDigestCheck {
                    tag,
                    algorithm: RpmDigestAlgorithm::Sha512,
                    target,
                    expected: parse_hex_digest(&string)?,
                    actual: actual.clone(),
                });
            }
        }
        Ok(checks)
    }

    /// Decompressed cpio payload bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload compressor is unsupported or the
    /// compressed data is corrupt.
    pub fn payload(&self) -> Result<Vec<u8>, Error> {
        self.decompress_payload(None)
    }

    /// Bounded variant of [`Self::payload`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputLimitExceeded`] when the decompressed payload
    /// exceeds `max_output` bytes.
    pub fn payload_bounded(&self, max_output: usize) -> Result<Vec<u8>, Error> {
        self.decompress_payload(Some(max_output))
    }

    fn decompress_payload(&self, max_output: Option<usize>) -> Result<Vec<u8>, Error> {
        match self.payload_compressor()? {
            RpmCompression::None => {
                if let Some(limit) = max_output
                    && self.payload_compressed.len() > limit
                {
                    return Err(Error::OutputLimitExceeded { limit });
                }
                Ok(self.payload_compressed.clone())
            }
            RpmCompression::Gzip => bounded(&self.payload_compressed, max_output, |d, l| {
                gzip::decode::decode_bounded(d, l)
            }),
            RpmCompression::Bzip2 => bounded(&self.payload_compressed, max_output, |d, l| {
                bzip2::decode::decode_bounded(d, l)
            }),
            RpmCompression::Lzma => bounded(&self.payload_compressed, max_output, |d, l| {
                lzma_alone::decode::decode_bounded(d, l)
            }),
            RpmCompression::Xz => bounded(&self.payload_compressed, max_output, |d, l| {
                xz::decode::decode_bounded(d, l)
            }),
            RpmCompression::Zstd => bounded(&self.payload_compressed, max_output, |d, l| {
                zstd::decode::decode_bounded(d, l)
            }),
        }
    }

    /// Files contained in the payload.
    ///
    /// `newc` payloads are decoded through the crate's cpio decoder.
    /// Stripped payloads (`07070X`) are decoded against the header's file
    /// list (`RPMTAG_LONGFILESIZES` / `RPMTAG_FILESIZES` for sizes, and
    /// `RPMTAG_BASENAMES` / `RPMTAG_DIRNAMES` / `RPMTAG_DIRINDEXES` for
    /// names).
    ///
    /// # Errors
    ///
    /// Returns an error if the payload is corrupt or the stripped payload
    /// references file-list tags that are missing or inconsistent.
    pub fn payload_entries(&self) -> Result<Vec<RpmPayloadEntry>, Error> {
        self.payload_entries_internal(None)
    }

    /// Bounded variant of [`Self::payload_entries`].
    pub fn payload_entries_bounded(
        &self,
        max_output: usize,
    ) -> Result<Vec<RpmPayloadEntry>, Error> {
        self.payload_entries_internal(Some(max_output))
    }

    fn payload_entries_internal(
        &self,
        max_output: Option<usize>,
    ) -> Result<Vec<RpmPayloadEntry>, Error> {
        let payload = match max_output {
            Some(limit) => self.payload_bounded(limit)?,
            None => self.payload()?,
        };
        if payload.starts_with(STRIPPED_MAGIC) {
            self.decode_stripped_payload(&payload)
        } else if payload.starts_with(NEWC_MAGIC) || payload.starts_with(NEWCRC_MAGIC) {
            cpio::decode::decode(&payload).map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| RpmPayloadEntry {
                        is_dir: entry.header.is_directory(),
                        name: entry.name,
                        file_index: None,
                        data: entry.data,
                    })
                    .collect()
            })
        } else {
            Err(Error::InvalidData("rpm: unrecognized payload format"))
        }
    }

    /// Decode a stripped cpio payload (`07070X` records).
    fn decode_stripped_payload(&self, payload: &[u8]) -> Result<Vec<RpmPayloadEntry>, Error> {
        let file_sizes = self.file_sizes()?;
        let file_modes = self
            .header
            .get_bin(TAG_FILEMODES)
            .transpose()?
            .map(|bytes| {
                bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>()
            });
        let basenames = self.header.get_strings(TAG_BASENAMES).transpose()?;
        let dirnames = self.header.get_strings(TAG_DIRNAMES).transpose()?;
        let dirindexes = self.header.get_i32s(TAG_DIRINDEXES).transpose()?;

        let mut entries = Vec::new();
        let mut pos = 0usize;
        loop {
            pos = align4(pos);
            let entry_end = pos
                .checked_add(STRIPPED_ENTRY_SIZE)
                .ok_or(Error::UnexpectedEof)?;
            if entry_end > payload.len() {
                return Err(Error::UnexpectedEof);
            }
            let magic_end = pos.checked_add(6).ok_or(Error::UnexpectedEof)?;
            let magic = &payload[pos..magic_end];
            if magic == NEWC_MAGIC || magic == NEWCRC_MAGIC {
                // rpm terminates stripped archives with a regular newc
                // "TRAILER!!!" entry; reject anything else. The newc
                // header is longer than the stripped entry, so validate
                // its own range first.
                let newc_end = pos.checked_add(110).ok_or(Error::UnexpectedEof)?;
                if newc_end > payload.len() {
                    return Err(Error::UnexpectedEof);
                }
                let name_len_pos = pos.checked_add(94).ok_or(Error::UnexpectedEof)?;
                let name_len = parse_hex_u32(&payload[name_len_pos..name_len_pos + 8])? as usize;
                let name_start = pos.checked_add(110).ok_or(Error::UnexpectedEof)?;
                let name_end = name_start
                    .checked_add(name_len)
                    .ok_or(Error::InvalidData("rpm: name length overflow"))?;
                if name_end > payload.len() {
                    return Err(Error::UnexpectedEof);
                }
                let name_text_end = name_end
                    .checked_sub(1)
                    .ok_or(Error::InvalidData("rpm: empty newc entry name"))?;
                let name = String::from_utf8_lossy(&payload[name_start..name_text_end]);
                if name == CPIO_TRAILER {
                    break;
                }
                return Err(Error::InvalidData(
                    "rpm: unexpected newc entry in stripped payload",
                ));
            }
            if magic != STRIPPED_MAGIC {
                return Err(Error::InvalidData("rpm: bad stripped cpio magic"));
            }
            let fx_pos = pos.checked_add(6).ok_or(Error::UnexpectedEof)?;
            let fx = parse_hex_u32(&payload[fx_pos..fx_pos + 8])?;
            pos = align4(entry_end);
            if fx == STRIPPED_TRAILER {
                break;
            }
            let size = file_sizes
                .get(fx as usize)
                .copied()
                .ok_or(Error::InvalidData("rpm: file index out of range"))?;
            let size =
                usize::try_from(size).map_err(|_| Error::InvalidData("rpm: negative file size"))?;
            let data_end = pos.checked_add(size).ok_or(Error::UnexpectedEof)?;
            if data_end > payload.len() {
                return Err(Error::UnexpectedEof);
            }
            let data = payload[pos..data_end].to_vec();
            pos = data_end;
            let name = resolve_stripped_name(
                fx,
                basenames.as_deref(),
                dirnames.as_deref(),
                dirindexes.as_deref(),
            );
            let is_dir = file_modes
                .as_ref()
                .and_then(|modes| modes.get(fx as usize))
                .map_or_else(|| name.ends_with('/'), |mode| mode & 0o170000 == 0o040000);
            entries.push(RpmPayloadEntry {
                name,
                file_index: Some(fx),
                data,
                is_dir,
            });
        }
        Ok(entries)
    }

    /// Per-file sizes from `RPMTAG_LONGFILESIZES` (v6) or `RPMTAG_FILESIZES`.
    fn file_sizes(&self) -> Result<Vec<i64>, Error> {
        if let Some(result) = self.header.get_i64s(TAG_LONGFILESIZES) {
            return result;
        }
        match self.header.get_i32s(TAG_FILESIZES) {
            Some(result) => result.map(|sizes| sizes.iter().map(|&s| i64::from(s)).collect()),
            None => Err(Error::InvalidData(
                "rpm: stripped payload requires FILESIZES or LONGFILESIZES tag",
            )),
        }
    }
}

fn resolve_stripped_name(
    fx: u32,
    basenames: Option<&[String]>,
    dirnames: Option<&[String]>,
    dirindexes: Option<&[i32]>,
) -> String {
    let i = fx as usize;
    match (basenames, dirnames, dirindexes) {
        (Some(base), Some(dirs), Some(idx)) => {
            match (base.get(i), idx.get(i).and_then(|&d| dirs.get(d as usize))) {
                (Some(name), Some(dir)) => alloc::format!("{dir}{name}"),
                _ => alloc::format!("{i:08x}"),
            }
        }
        (Some(base), _, _) => base
            .get(i)
            .cloned()
            .unwrap_or_else(|| alloc::format!("{i:08x}")),
        _ => alloc::format!("{i:08x}"),
    }
}

const fn align4(offset: usize) -> usize {
    offset.div_ceil(4) * 4
}

fn bounded(
    data: &[u8],
    max_output: Option<usize>,
    decode: impl Fn(&[u8], usize) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    decode(data, max_output.unwrap_or(usize::MAX))
}

fn parse_hex_u32(bytes: &[u8]) -> Result<u32, Error> {
    let mut value = 0u32;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(Error::InvalidData("rpm: invalid hex digit")),
        };
        value = value << 4 | u32::from(digit);
    }
    Ok(value)
}

/// Digest of data for a payload-digest algorithm.
fn digest_of(algorithm: RpmDigestAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        RpmDigestAlgorithm::Md5 => md5::md5(data).to_vec(),
        RpmDigestAlgorithm::Sha1 => sha1::sha1(data).to_vec(),
        RpmDigestAlgorithm::Sha256 => sha256::sha256(data).to_vec(),
        RpmDigestAlgorithm::Sha512 => sha512::sha512(data).to_vec(),
    }
}

/// Decode a hex STRING digest tag value into bytes.
fn parse_hex_digest(string: &str) -> Result<Vec<u8>, Error> {
    let bytes = string.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidData("rpm: odd-length digest hex"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        out.push(parse_hex_u32(pair)? as u8);
    }
    Ok(out)
}

fn read_u16_be(input: &[u8], pos: usize) -> u16 {
    u16::from_be_bytes([input[pos], input[pos + 1]])
}

fn read_u32_be(input: &[u8], pos: usize) -> Result<u32, Error> {
    if pos + 4 > input.len() {
        return Err(Error::UnexpectedEof);
    }
    Ok(u32::from_be_bytes([
        input[pos],
        input[pos + 1],
        input[pos + 2],
        input[pos + 3],
    ]))
}

/// Decode a `.rpm` package (Lead, Signature, Header, compressed payload).
///
/// Signature tags are parsed but cryptographic verification is
/// intentionally out of scope.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] for structural violations and
/// [`Error::UnexpectedEof`] for truncated input.
///
/// # Examples
///
/// ```no_run
/// use archive::archive::rpm;
///
/// let bytes = std::fs::read("package.rpm").unwrap();
/// let package = rpm::decode::decode(&bytes).unwrap();
/// for entry in package.payload_entries().unwrap() {
///     println!("{}: {} bytes", entry.name, entry.data.len());
/// }
/// ```
pub fn decode(input: &[u8]) -> Result<RpmPackage, Error> {
    if input.len() < LEAD_SIZE {
        return Err(Error::UnexpectedEof);
    }
    if input[..4] != LEAD_MAGIC {
        return Err(Error::InvalidData("rpm: bad lead magic"));
    }
    let major = input[4];
    let minor = input[5];
    let raw_type = read_u16_be(input, 6);
    let package_type = match raw_type {
        0 => RpmPackageType::Binary,
        1 => RpmPackageType::Source,
        _ => return Err(Error::InvalidData("rpm: unknown package type")),
    };
    let archnum = read_u16_be(input, 8);
    let name_raw = &input[10..76];
    let name_len = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    let name = String::from_utf8_lossy(&name_raw[..name_len]).into_owned();
    let osnum = read_u16_be(input, 76);
    let signature_type = read_u16_be(input, 78);

    let (signature, sig_end) = parse_header_section(input, LEAD_SIZE, SIG_REGION_TAG)?;
    let signature_end = sig_end + (8 - sig_end % 8) % 8;
    if signature_end > input.len() {
        return Err(Error::UnexpectedEof);
    }

    let (header, header_end) = parse_header_section(input, signature_end, HDR_REGION_TAG)?;

    Ok(RpmPackage {
        lead: RpmLead {
            major,
            minor,
            package_type,
            archnum,
            name,
            osnum,
            signature_type,
        },
        signature,
        header,
        header_raw: input[signature_end..header_end].to_vec(),
        payload_compressed: input[header_end..].to_vec(),
    })
}

/// Parse one RPM header structure at `offset`; returns the section and the
/// offset just past its data store (before signature padding).
fn parse_header_section(
    input: &[u8],
    offset: usize,
    region_tag: u32,
) -> Result<(RpmHeaderSection, usize), Error> {
    if offset + HEADER_INTRO_SIZE > input.len() {
        return Err(Error::UnexpectedEof);
    }
    if input[offset..offset + 8] != HEADER_MAGIC {
        return Err(Error::InvalidData("rpm: bad header magic"));
    }
    let nindex = read_u32_be(input, offset + 8)? as usize;
    let hsize = read_u32_be(input, offset + 12)? as usize;

    let index_len = nindex
        .checked_mul(INDEX_ENTRY_SIZE)
        .ok_or(Error::InvalidData("rpm: index size overflow"))?;
    let index_end = offset + HEADER_INTRO_SIZE + index_len;
    if index_end > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let data_end = index_end
        .checked_add(hsize)
        .ok_or(Error::InvalidData("rpm: header size overflow"))?;
    if data_end > input.len() {
        return Err(Error::UnexpectedEof);
    }

    let mut entries: Vec<RpmTagEntry> = Vec::with_capacity(nindex);
    for i in 0..nindex {
        let base = offset + HEADER_INTRO_SIZE + i * INDEX_ENTRY_SIZE;
        let entry = RpmTagEntry {
            tag: read_u32_be(input, base)?,
            tag_type: read_u32_be(input, base + 4)?,
            offset: read_u32_be(input, base + 8)?,
            count: read_u32_be(input, base + 12)?,
        };
        if entry.data_type().is_none() {
            return Err(Error::InvalidData("rpm: unknown tag type"));
        }
        if entry.data_type() == Some(RpmTagType::String) && entry.count != 1 {
            return Err(Error::InvalidData("rpm: STRING tag with count != 1"));
        }
        // Index entries are sorted by tag number with no duplicates
        // (format_header.html).
        if let Some(prev) = entries.last()
            && entry.tag <= prev.tag
        {
            return Err(Error::InvalidData(if entry.tag == prev.tag {
                "rpm: duplicate index tag"
            } else {
                "rpm: index entries not sorted by tag"
            }));
        }
        entries.push(entry);
    }

    // Immutable region check: the first tag must be the region tag.
    if entries.first().map(|e| e.tag) != Some(region_tag) {
        return Err(Error::InvalidData("rpm: missing immutable region tag"));
    }

    let data = &input[index_end..data_end];

    // In offset order, the bytes between one entry's data end and the
    // next entry's start are alignment padding, which must be all zero
    // (format_header.html).
    let mut by_offset: Vec<&RpmTagEntry> = entries.iter().collect();
    by_offset.sort_by_key(|entry| entry.offset);
    let mut filled = 0usize;
    for entry in by_offset {
        let (start, end) = tag_data_extent(entry, data)?;
        if start < filled {
            return Err(Error::InvalidData("rpm: overlapping tag data"));
        }
        if data[filled..start].iter().any(|&b| b != 0) {
            return Err(Error::InvalidData("rpm: non-zero data store padding"));
        }
        filled = end;
    }

    Ok((
        RpmHeaderSection {
            entries,
            data: data.to_vec(),
        },
        data_end,
    ))
}

/// Byte range `[start, end)` covered by `entry`'s data inside the
/// section's data store. String-typed extents are measured by walking
/// the NUL terminators.
fn tag_data_extent(entry: &RpmTagEntry, data: &[u8]) -> Result<(usize, usize), Error> {
    let start = entry.offset as usize;
    if start > data.len() {
        return Err(Error::InvalidData("rpm: tag data out of bounds"));
    }
    let data_type = entry
        .data_type()
        .ok_or(Error::InvalidData("rpm: unknown tag type"))?;
    let elem: u64 = match data_type {
        RpmTagType::Char | RpmTagType::Int8 | RpmTagType::Bin => 1,
        RpmTagType::Int16 => 2,
        RpmTagType::Int32 => 4,
        RpmTagType::Int64 => 8,
        RpmTagType::String | RpmTagType::StringArray | RpmTagType::I18nString => {
            let mut pos = start;
            for _ in 0..entry.count {
                let nul = data[pos..]
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(Error::InvalidData("rpm: unterminated string"))?;
                pos += nul + 1;
            }
            return Ok((start, pos));
        }
    };
    let end = start as u64 + elem * u64::from(entry.count);
    if end > data.len() as u64 {
        return Err(Error::InvalidData("rpm: tag data out of bounds"));
    }
    Ok((start, end as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Minimal header-structure builder for tests.
    fn build_header(tags: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut data = Vec::new();
        for &(tag, ty, bytes) in tags {
            // Align integer types to their natural boundaries.
            let align = match ty {
                3 => 2,
                4 => 4,
                5 => 8,
                _ => 1,
            };
            while data.len() % align != 0 {
                data.push(0);
            }
            let count = match ty {
                // CHAR / BIN / INT8: element count is the byte length.
                1 | 2 | 7 => bytes.len() as u32,
                3 => (bytes.len() / 2) as u32,
                4 => (bytes.len() / 4) as u32,
                5 => (bytes.len() / 8) as u32,
                // STRING / I18NSTRING hold a single string per entry.
                6 | 9 => 1,
                // STRING_ARRAY: one element per NUL terminator.
                8 => bytes.iter().filter(|&&b| b == 0).count() as u32,
                _ => 1,
            };
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&ty.to_be_bytes());
            index.extend_from_slice(&(data.len() as u32).to_be_bytes());
            index.extend_from_slice(&count.to_be_bytes());
            data.extend_from_slice(bytes);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC);
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&data);
        out
    }

    /// 16-byte BIN region trailer embedded in a section's data store.
    fn region_trailer(tag: u32) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&tag.to_be_bytes());
        t.extend_from_slice(&7u32.to_be_bytes());
        t.extend_from_slice(&0u32.to_be_bytes());
        t.extend_from_slice(&16u32.to_be_bytes());
        t
    }

    /// Minimal .rpm fixture: lead + signature + header + payload bytes.
    fn build_rpm(payload: &[u8], compressor: Option<&str>) -> Vec<u8> {
        let mut lead = vec![0u8; LEAD_SIZE];
        lead[..4].copy_from_slice(&LEAD_MAGIC);
        lead[4] = 4;
        lead[6..8].copy_from_slice(&0u16.to_be_bytes());
        let name = b"test-1.0-1";
        lead[10..10 + name.len()].copy_from_slice(name);
        lead[76..78].copy_from_slice(&1u16.to_be_bytes());
        lead[78..80].copy_from_slice(&5u16.to_be_bytes());

        let mut sig = build_header(&[(SIG_REGION_TAG, 7, &region_trailer(SIG_REGION_TAG))]);
        while !sig.len().is_multiple_of(8) {
            sig.push(0);
        }

        let compressor = compressor.unwrap_or("gzip\0");
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, b"test\0"),
            (TAG_PAYLOADCOMPRESSOR, 6, compressor.as_bytes()),
        ]);

        let mut rpm = lead;
        rpm.extend_from_slice(&sig);
        rpm.extend_from_slice(&header);
        rpm.extend_from_slice(payload);
        rpm
    }

    fn cpio_payload(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut enc = cpio::encode::CpioEncoder::new();
        for (name, data) in files {
            enc.add_file(name, data);
        }
        enc.finish()
    }

    #[test]
    fn decodes_uncompressed_newc_payload() {
        let payload = cpio_payload(&[("hello.txt", b"hi")]);
        let rpm = build_rpm(&payload, Some("none\0"));
        let package = decode(&rpm).unwrap();
        assert_eq!(package.lead.name, "test-1.0-1");
        assert_eq!(package.name().unwrap().unwrap(), "test");
        assert_eq!(package.payload_compressor().unwrap(), RpmCompression::None);
        let entries = package.payload_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].data, b"hi");
    }

    #[test]
    fn rejects_unrecognized_payload_compressor() {
        // spec/rpm 要件14: an unrecognized compressor name is Unsupported.
        let rpm = build_rpm(&[], Some("bogus-compressor\0"));
        let package = decode(&rpm).unwrap();
        assert!(matches!(
            package.payload_compressor(),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_bad_lead_magic() {
        let mut rpm = build_rpm(&[], Some("none\0"));
        rpm[0] = 0;
        assert!(decode(&rpm).is_err());
    }

    #[test]
    fn rejects_unknown_package_type() {
        let mut rpm = build_rpm(&[], Some("none\0"));
        rpm[6] = 0;
        rpm[7] = 9;
        assert!(decode(&rpm).is_err());
    }

    #[test]
    fn rejects_missing_region_tags() {
        // Header without a leading region tag.
        let bad = build_header(&[(TAG_NAME, 6, b"x\0")]);
        let mut rpm = vec![0u8; LEAD_SIZE];
        rpm[..4].copy_from_slice(&LEAD_MAGIC);
        rpm[6..8].copy_from_slice(&0u16.to_be_bytes());
        rpm.extend_from_slice(&bad);
        assert!(decode(&rpm).is_err());
    }

    #[test]
    fn parses_stripped_payload() {
        // Two-file stripped payload: fx 0 and fx 1, then trailer.
        let mut payload = Vec::new();
        payload.extend_from_slice(STRIPPED_MAGIC);
        payload.extend_from_slice(b"00000000");
        payload.extend_from_slice(&[0; 2]); // pad to 4
        payload.extend_from_slice(b"AAAA");
        payload.extend_from_slice(STRIPPED_MAGIC);
        payload.extend_from_slice(b"00000001");
        payload.extend_from_slice(&[0; 2]);
        payload.extend_from_slice(b"BBB");
        // trailer: stripped header with fx = ffffffff (pad pos 39 -> 40)
        payload.push(0);
        payload.extend_from_slice(STRIPPED_MAGIC);
        payload.extend_from_slice(b"ffffffff");

        let rpm = {
            let mut lead = vec![0u8; LEAD_SIZE];
            lead[..4].copy_from_slice(&LEAD_MAGIC);
            lead[6..8].copy_from_slice(&0u16.to_be_bytes());
            let mut sig = build_header(&[(SIG_REGION_TAG, 7, &region_trailer(SIG_REGION_TAG))]);
            while !sig.len().is_multiple_of(8) {
                sig.push(0);
            }
            let mut sizes = Vec::new();
            sizes.extend_from_slice(&4i64.to_be_bytes());
            sizes.extend_from_slice(&3i64.to_be_bytes());
            let header = build_header(&[
                (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
                (TAG_BASENAMES, 8, b"a.bin\0b.bin\0"),
                (TAG_PAYLOADCOMPRESSOR, 6, b"none\0"),
                (TAG_LONGFILESIZES, 5, &sizes),
            ]);
            let mut rpm = lead;
            rpm.extend_from_slice(&sig);
            rpm.extend_from_slice(&header);
            rpm.extend_from_slice(&payload);
            rpm
        };
        let package = decode(&rpm).unwrap();
        let entries = package.payload_entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"AAAA");
        assert_eq!(entries[1].data, b"BBB");
        assert_eq!(entries[0].file_index, Some(0));
        assert_eq!(entries[0].name, "a.bin");
        assert_eq!(entries[1].name, "b.bin");
    }

    #[test]
    fn rejects_stripped_payload_without_sizes() {
        let mut payload = Vec::new();
        payload.extend_from_slice(STRIPPED_MAGIC);
        payload.extend_from_slice(b"00000000");
        let mut rpm = vec![0u8; LEAD_SIZE];
        rpm[..4].copy_from_slice(&LEAD_MAGIC);
        rpm[6..8].copy_from_slice(&0u16.to_be_bytes());
        let mut sig = build_header(&[(SIG_REGION_TAG, 7, &region_trailer(SIG_REGION_TAG))]);
        while !sig.len().is_multiple_of(8) {
            sig.push(0);
        }
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_PAYLOADCOMPRESSOR, 6, b"none\0"),
        ]);
        rpm.extend_from_slice(&sig);
        rpm.extend_from_slice(&header);
        rpm.extend_from_slice(&payload);
        let package = decode(&rpm).unwrap();
        assert!(package.payload_entries().is_err());
    }

    #[test]
    fn rejects_unsorted_index_entries() {
        // spec/rpm 要件12a: index entries are sorted by tag number.
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_PAYLOADCOMPRESSOR, 6, b"none\0"),
            (TAG_NAME, 6, b"x\0"),
        ]);
        assert!(matches!(
            parse_header_section(&header, 0, HDR_REGION_TAG),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn rejects_duplicate_tag() {
        // spec/rpm 要件12a: duplicate tags are rejected.
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, b"a\0"),
            (TAG_NAME, 6, b"b\0"),
        ]);
        assert!(matches!(
            parse_header_section(&header, 0, HDR_REGION_TAG),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn rejects_nonzero_store_padding() {
        // spec/rpm 要件12b: alignment padding in the data store must
        // be zero. Here the INT32 tag forces 2 padding bytes after the
        // 2-byte "x\0" string.
        let mut header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, b"x\0"),                   // data[16..18]
            (TAG_FILESIZES, 4, &1i32.to_be_bytes()), // aligned to 20
        ]);
        let data_start = HEADER_INTRO_SIZE + 3 * INDEX_ENTRY_SIZE;
        header[data_start + 18] = 0xff;
        assert!(matches!(
            parse_header_section(&header, 0, HDR_REGION_TAG),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn accepts_aligned_zero_padding() {
        // spec/rpm 要件12b: zero alignment padding is accepted.
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, b"x\0"),
            (TAG_FILESIZES, 4, &1i32.to_be_bytes()),
        ]);
        let (section, _) = parse_header_section(&header, 0, HDR_REGION_TAG).unwrap();
        assert_eq!(section.get_i32s(TAG_FILESIZES).unwrap().unwrap(), [1]);
    }

    #[test]
    fn tag_type_accessors_validate_types() {
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, b"pkg\0"),
            (TAG_FILESIZES, 4, &12i32.to_be_bytes()),
        ]);
        let (section, _) = parse_header_section(&header, 0, HDR_REGION_TAG).unwrap();
        assert_eq!(section.get_string(TAG_NAME).unwrap().unwrap(), "pkg");
        assert_eq!(section.get_i32s(TAG_FILESIZES).unwrap().unwrap(), [12]);
        assert!(section.get_i32s(TAG_NAME).unwrap().is_err());
        assert!(section.get_string(TAG_ARCH).is_none());
    }

    /// NUL-terminated STRING-tag bytes.
    fn nul_str(bytes: &[u8]) -> Vec<u8> {
        let mut v = bytes.to_vec();
        v.push(0);
        v
    }

    /// Lowercase hex encoding for STRING digest tags.
    fn hex_of(bytes: &[u8]) -> Vec<u8> {
        use alloc::fmt::Write;
        let mut out = String::new();
        for b in bytes {
            write!(out, "{:02x}", b).unwrap();
        }
        out.into_bytes()
    }

    /// .rpm with matching digest tags in the Signature and Header.
    fn signed_rpm(payload: &[u8]) -> Vec<u8> {
        let paydigest = nul_str(&hex_of(&sha256::sha256(payload)));
        let name = nul_str(b"test");
        let none = nul_str(b"none");
        let header = build_header(&[
            (HDR_REGION_TAG, 7, &region_trailer(HDR_REGION_TAG)),
            (TAG_NAME, 6, &name),
            (TAG_PAYLOADCOMPRESSOR, 6, &none),
            (TAG_PAYLOADDIGEST, 8, &paydigest),
            (TAG_PAYLOADDIGESTALGO, 4, &8i32.to_be_bytes()),
            (TAG_PAYLOADDIGESTALT, 8, &paydigest),
        ]);
        let mut hasher = md5::Md5::new();
        hasher.update(&header);
        hasher.update(payload);
        let md5_sum = hasher.finish();
        let sha1_hex = nul_str(&hex_of(&sha1::sha1(&header)));
        let sha256_hex = nul_str(&hex_of(&sha256::sha256(&header)));
        let sig = build_header(&[
            (SIG_REGION_TAG, 7, &region_trailer(SIG_REGION_TAG)),
            (SIGTAG_SHA1, 6, &sha1_hex),
            (SIGTAG_SHA256_V4, 6, &sha256_hex),
            (SIGTAG_MD5, 7, &md5_sum),
        ]);
        let mut rpm = vec![0u8; LEAD_SIZE];
        rpm[..4].copy_from_slice(&LEAD_MAGIC);
        rpm[4] = 4;
        rpm[6..8].copy_from_slice(&0u16.to_be_bytes());
        rpm.extend_from_slice(&sig);
        while !rpm.len().is_multiple_of(8) {
            rpm.push(0);
        }
        rpm.extend_from_slice(&header);
        rpm.extend_from_slice(payload);
        rpm
    }

    #[test]
    fn verifies_md5_sha1_digests() {
        let payload = cpio_payload(&[("hello.txt", b"hi")]);
        let rpm = signed_rpm(&payload);
        let package = decode(&rpm).unwrap();
        let checks = package.verify_digests().unwrap();
        assert_eq!(checks.len(), 5);
        assert!(checks.iter().all(RpmDigestCheck::matches));
        let md5_check = checks.iter().find(|c| c.tag == SIGTAG_MD5).unwrap();
        assert_eq!(md5_check.target, RpmDigestTarget::HeaderAndPayload);
        assert!(checks.iter().any(|c| c.tag == SIGTAG_SHA1));
        assert!(checks.iter().any(|c| c.tag == SIGTAG_SHA256_V4));
        let stored = checks.iter().find(|c| c.tag == TAG_PAYLOADDIGEST).unwrap();
        assert_eq!(stored.target, RpmDigestTarget::PayloadCompressed);
        let alt = checks
            .iter()
            .find(|c| c.tag == TAG_PAYLOADDIGESTALT)
            .unwrap();
        assert_eq!(alt.target, RpmDigestTarget::PayloadUncompressed);
    }

    #[test]
    fn rejects_tampered_payload_digest() {
        let payload = cpio_payload(&[("hello.txt", b"hi")]);
        let mut rpm = signed_rpm(&payload);
        let last = rpm.len() - 1;
        rpm[last] ^= 0x01;
        let package = decode(&rpm).unwrap();
        let checks = package.verify_digests().unwrap();
        assert!(
            !checks
                .iter()
                .find(|c| c.tag == SIGTAG_MD5)
                .unwrap()
                .matches()
        );
        assert!(
            !checks
                .iter()
                .find(|c| c.tag == TAG_PAYLOADDIGEST)
                .unwrap()
                .matches()
        );
        // Header digests still match.
        assert!(
            checks
                .iter()
                .find(|c| c.tag == SIGTAG_SHA256_V4)
                .unwrap()
                .matches()
        );
    }

    #[test]
    fn detects_tampered_header_digest() {
        let payload = cpio_payload(&[("hello.txt", b"hi")]);
        let mut rpm = signed_rpm(&payload);
        let pos = rpm.windows(4).position(|w| w == b"test").unwrap();
        rpm[pos] = 0x75;
        let package = decode(&rpm).unwrap();
        let checks = package.verify_digests().unwrap();
        assert!(
            !checks
                .iter()
                .find(|c| c.tag == SIGTAG_SHA1)
                .unwrap()
                .matches()
        );
        assert!(
            !checks
                .iter()
                .find(|c| c.tag == SIGTAG_SHA256_V4)
                .unwrap()
                .matches()
        );
        assert!(
            !checks
                .iter()
                .find(|c| c.tag == SIGTAG_MD5)
                .unwrap()
                .matches()
        );
        // Payload digests still match.
        assert!(
            checks
                .iter()
                .find(|c| c.tag == TAG_PAYLOADDIGEST)
                .unwrap()
                .matches()
        );
    }
}
