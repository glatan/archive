//! `.deb` package decoding (read-only).
//!
//! Member layout per deb(5):
//!
//! 1. `debian-binary` — text; the first line is the format version ("2.0").
//! 2. `control.tar` or `control.tar.<ext>` — package metadata.
//! 3. `data.tar` or `data.tar.<ext>` — the installed payload.
//!
//! Additional members may follow `data.tar*`; members inserted between the
//! required members are accepted only with a leading `_` in the name, which
//! deb(5) reserves for safely-ignorable members. Both are preserved with
//! kind [`DebMemberKind::Other`]. Recognized member compressions are
//! uncompressed tar, gzip, xz, zstd, bzip2, LZMA-Alone, and Unix compress
//! (`.Z`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::archive::ar::decode::ArHeader;
use crate::archive::tar::decode::TarEntry;
use crate::archive::{ar, tar};
use crate::compress::{bzip2, gzip, lzma_alone, lzw, xz, zstd};
use crate::error::Error;

const DEBIAN_BINARY: &str = "debian-binary";
const CONTROL_PREFIX: &str = "control.tar";
const DATA_PREFIX: &str = "data.tar";

/// Compression applied to a `control.tar.*` / `data.tar.*` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebCompression {
    /// Uncompressed `control.tar` / `data.tar`.
    None,
    /// `*.tar.gz` (gzip).
    Gzip,
    /// `*.tar.xz` (xz).
    Xz,
    /// `*.tar.zst` (zstd).
    Zstd,
    /// `*.tar.bz2` (bzip2).
    Bzip2,
    /// `*.tar.lzma` (LZMA-Alone).
    Lzma,
    /// `*.tar.Z` (Unix compress / LZW).
    Lzw,
}

impl DebCompression {
    /// Member-name suffix for this compression ("" for uncompressed).
    pub const fn extension(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Gzip => ".gz",
            Self::Xz => ".xz",
            Self::Zstd => ".zst",
            Self::Bzip2 => ".bz2",
            Self::Lzma => ".lzma",
            Self::Lzw => ".Z",
        }
    }
}

/// Classification of an `ar` member inside a `.deb` package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebMemberKind {
    /// `debian-binary` — the format-version member.
    DebianBinary,
    /// `control.tar*` — package metadata.
    Control,
    /// `data.tar*` — installed payload.
    Data,
    /// Any other member (e.g. signatures such as `_gpgorigin`).
    Other,
}

/// A single `ar` member of a `.deb` package.
#[derive(Debug, Clone)]
pub struct DebMember {
    /// Parsed `ar` entry metadata.
    pub header: ArHeader,
    /// Member name (e.g. `debian-binary`, `control.tar.xz`).
    pub name: String,
    /// Role of the member inside the package.
    pub kind: DebMemberKind,
    /// Compression of the tar member; `None` for non-tar members.
    pub compression: Option<DebCompression>,
    /// Raw member payload (compressed for tar members).
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for DebMember {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A decoded `.deb` package.
#[derive(Debug, Clone)]
pub struct DebPackage {
    /// Format version from the first line of `debian-binary` (e.g. "2.0").
    pub version: String,
    /// All members in archive order.
    pub members: Vec<DebMember>,
}

impl DebPackage {
    /// Look up a member by exact name.
    pub fn member(&self, name: &str) -> Option<&DebMember> {
        self.members.iter().find(|member| member.name == name)
    }

    /// The `control.tar*` member.
    pub fn control_member(&self) -> Option<&DebMember> {
        self.members
            .iter()
            .find(|member| member.kind == DebMemberKind::Control)
    }

    /// The `data.tar*` member.
    pub fn data_member(&self) -> Option<&DebMember> {
        self.members
            .iter()
            .find(|member| member.kind == DebMemberKind::Data)
    }

    /// Decompress the `control.tar*` member, returning raw tar bytes.
    pub fn control_tar(&self) -> Result<Vec<u8>, Error> {
        self.tar_payload(DebMemberKind::Control, None)
    }

    /// Decompress the `data.tar*` member, returning raw tar bytes.
    pub fn data_tar(&self) -> Result<Vec<u8>, Error> {
        self.tar_payload(DebMemberKind::Data, None)
    }

    /// Bounded variant of [`DebPackage::control_tar`].
    pub fn control_tar_bounded(&self, max_output: usize) -> Result<Vec<u8>, Error> {
        self.tar_payload(DebMemberKind::Control, Some(max_output))
    }

    /// Bounded variant of [`DebPackage::data_tar`].
    pub fn data_tar_bounded(&self, max_output: usize) -> Result<Vec<u8>, Error> {
        self.tar_payload(DebMemberKind::Data, Some(max_output))
    }

    /// Decode the `control.tar*` member into tar entries.
    pub fn control_entries(&self) -> Result<Vec<TarEntry>, Error> {
        tar::decode::decode(&self.control_tar()?)
    }

    /// Decode the `data.tar*` member into tar entries.
    pub fn data_entries(&self) -> Result<Vec<TarEntry>, Error> {
        tar::decode::decode(&self.data_tar()?)
    }

    /// Bounded variant of [`DebPackage::control_entries`].
    pub fn control_entries_bounded(&self, max_output: usize) -> Result<Vec<TarEntry>, Error> {
        tar::decode::decode(&self.control_tar_bounded(max_output)?)
    }

    /// Bounded variant of [`DebPackage::data_entries`].
    pub fn data_entries_bounded(&self, max_output: usize) -> Result<Vec<TarEntry>, Error> {
        tar::decode::decode(&self.data_tar_bounded(max_output)?)
    }

    fn tar_payload(
        &self,
        kind: DebMemberKind,
        max_output: Option<usize>,
    ) -> Result<Vec<u8>, Error> {
        let member = self
            .members
            .iter()
            .find(|member| member.kind == kind)
            .ok_or(Error::InvalidData("deb: missing tar member"))?;
        decompress_member(member, max_output)
    }
}

/// Decode a `.deb` package from a byte slice.
///
/// Validates that the input is a non-thin `ar` archive whose required members
/// occur in the deb(5) canonical order — `debian-binary`, `control.tar*`,
/// `data.tar*` — that exactly one `control.tar*` and one `data.tar*` member
/// are present, and that each tar member uses a recognized compression
/// suffix. A member inserted between the required members is accepted only
/// when its name starts with `_`, which deb(5) reserves for members that can
/// be safely ignored; additional members after `data.tar*` are kept as
/// [`DebMemberKind::Other`].
///
/// # Errors
///
/// Returns [`Error::InvalidData`] for malformed package structure and
/// [`Error::UnexpectedEof`] for truncated `ar` input.
pub fn decode(input: &[u8]) -> Result<DebPackage, Error> {
    let entries = ar::decode::decode(input)?;
    if entries.iter().any(|entry| entry.is_thin) {
        return Err(Error::InvalidData("deb: thin archives are not packages"));
    }
    let first = entries
        .first()
        .ok_or(Error::InvalidData("deb: missing debian-binary member"))?;
    if first.name != DEBIAN_BINARY {
        return Err(Error::InvalidData("deb: first member is not debian-binary"));
    }
    let version = parse_version(&first.data)?;

    let mut members = Vec::with_capacity(entries.len());
    let mut have_control = false;
    let mut have_data = false;
    for (index, entry) in entries.into_iter().enumerate() {
        let kind = classify_member(&entry.name);
        let compression = match kind {
            DebMemberKind::Control | DebMemberKind::Data => Some(member_compression(&entry.name)?),
            DebMemberKind::DebianBinary | DebMemberKind::Other => None,
        };
        match kind {
            DebMemberKind::DebianBinary => {
                if index != 0 {
                    return Err(Error::InvalidData("deb: duplicate debian-binary member"));
                }
            }
            DebMemberKind::Control => {
                if have_control {
                    return Err(Error::InvalidData("deb: duplicate control member"));
                }
                have_control = true;
            }
            DebMemberKind::Data => {
                if have_data {
                    return Err(Error::InvalidData("deb: duplicate data member"));
                }
                if !have_control {
                    return Err(Error::InvalidData("deb: data member before control member"));
                }
                have_data = true;
            }
            DebMemberKind::Other => {
                // deb(5): members inserted between the required members are
                // named with a leading '_' so they can be safely ignored;
                // anything else in that position cannot be safely ignored.
                // Members after data.tar are ignored unconditionally.
                if !have_data && !entry.name.starts_with('_') {
                    return Err(Error::InvalidData(
                        "deb: unexpected member between required members",
                    ));
                }
            }
        }
        members.push(DebMember {
            header: entry.header,
            name: entry.name,
            kind,
            compression,
            data: entry.data,
        });
    }
    if !have_control {
        return Err(Error::InvalidData("deb: missing control.tar member"));
    }
    if !have_data {
        return Err(Error::InvalidData("deb: missing data.tar member"));
    }
    Ok(DebPackage { version, members })
}

/// Decompress a `control.tar*` / `data.tar*` member payload.
pub fn decompress_member(member: &DebMember, max_output: Option<usize>) -> Result<Vec<u8>, Error> {
    match member.compression {
        None | Some(DebCompression::None) => {
            if let Some(limit) = max_output
                && member.data.len() > limit
            {
                return Err(Error::OutputLimitExceeded { limit });
            }
            Ok(member.data.clone())
        }
        Some(DebCompression::Gzip) => decode_bounded(
            &member.data,
            max_output,
            gzip::decode::decode,
            gzip::decode::decode_bounded,
        ),
        Some(DebCompression::Xz) => decode_bounded(
            &member.data,
            max_output,
            xz::decode::decode,
            xz::decode::decode_bounded,
        ),
        Some(DebCompression::Zstd) => decode_bounded(
            &member.data,
            max_output,
            zstd::decode::decode,
            zstd::decode::decode_bounded,
        ),
        Some(DebCompression::Bzip2) => decode_bounded(
            &member.data,
            max_output,
            bzip2::decode::decode,
            bzip2::decode::decode_bounded,
        ),
        Some(DebCompression::Lzma) => decode_bounded(
            &member.data,
            max_output,
            lzma_alone::decode::decode,
            lzma_alone::decode::decode_bounded,
        ),
        Some(DebCompression::Lzw) => decode_bounded(
            &member.data,
            max_output,
            lzw::decode::decode,
            lzw::decode::decode_bounded,
        ),
    }
}

fn decode_bounded(
    input: &[u8],
    max_output: Option<usize>,
    decode: fn(&[u8]) -> Result<Vec<u8>, Error>,
    decode_bounded: fn(&[u8], usize) -> Result<Vec<u8>, Error>,
) -> Result<Vec<u8>, Error> {
    match max_output {
        Some(limit) => decode_bounded(input, limit),
        None => decode(input),
    }
}

fn classify_member(name: &str) -> DebMemberKind {
    if name == DEBIAN_BINARY {
        DebMemberKind::DebianBinary
    } else if name == CONTROL_PREFIX || name.starts_with("control.tar.") {
        DebMemberKind::Control
    } else if name == DATA_PREFIX || name.starts_with("data.tar.") {
        DebMemberKind::Data
    } else {
        DebMemberKind::Other
    }
}

fn member_compression(name: &str) -> Result<DebCompression, Error> {
    let suffix = name
        .strip_prefix(CONTROL_PREFIX)
        .or_else(|| name.strip_prefix(DATA_PREFIX))
        .ok_or(Error::InvalidData("deb: not a tar member"))?;
    match suffix {
        "" => Ok(DebCompression::None),
        ".gz" => Ok(DebCompression::Gzip),
        ".xz" => Ok(DebCompression::Xz),
        ".zst" => Ok(DebCompression::Zstd),
        ".bz2" => Ok(DebCompression::Bzip2),
        ".lzma" => Ok(DebCompression::Lzma),
        ".Z" => Ok(DebCompression::Lzw),
        _ => Err(Error::Unsupported(
            "deb: unrecognized tar member compression",
        )),
    }
}

fn parse_version(data: &[u8]) -> Result<String, Error> {
    let line = data
        .split(|&byte| byte == b'\n')
        .next()
        .ok_or(Error::InvalidData("deb: empty debian-binary member"))?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = core::str::from_utf8(line)
        .map_err(|_| Error::InvalidData("deb: debian-binary is not UTF-8"))?;
    let valid = !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && text.contains('.');
    // deb(5): if the major number has changed, an incompatible change
    // has been made and the program should stop.
    if !valid || !text.starts_with("2.") {
        return Err(Error::InvalidData("deb: malformed format version"));
    }
    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_deb(control: &[u8], data: &[u8]) -> Vec<u8> {
        build_deb_named("control.tar", control, "data.tar", data)
    }

    fn build_deb_named(
        control_name: &str,
        control: &[u8],
        data_name: &str,
        data: &[u8],
    ) -> Vec<u8> {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file(control_name, control);
        enc.add_file(data_name, data);
        enc.finish().unwrap()
    }

    fn tar_with_file(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut enc = tar::encode::TarEncoder::new();
        enc.add_file(name, payload);
        enc.finish()
    }

    #[test]
    fn decodes_minimal_package() {
        let deb = build_deb(
            &tar_with_file("./control", b"x"),
            &tar_with_file("./a", b"a"),
        );
        let package = decode(&deb).unwrap();
        assert_eq!(package.version, "2.0");
        assert_eq!(package.members.len(), 3);
        assert_eq!(package.members[0].kind, DebMemberKind::DebianBinary);
        assert_eq!(package.members[1].kind, DebMemberKind::Control);
        assert_eq!(package.members[2].kind, DebMemberKind::Data);
        assert_eq!(package.members[1].compression, Some(DebCompression::None));
        let entries = package.data_entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"a");
    }

    #[test]
    fn rejects_non_ar_input() {
        assert!(decode(b"not an ar").is_err());
    }

    #[test]
    fn rejects_thin_archive() {
        let mut deb = build_deb(
            &tar_with_file("./control", b"x"),
            &tar_with_file("./a", b"a"),
        );
        deb[..8].copy_from_slice(b"!<thin>\n");
        assert!(decode(&deb).is_err());
    }

    #[test]
    fn rejects_missing_debian_binary() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_debian_binary_not_first() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file("control.tar", b"c");
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("data.tar", b"d");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_major_version_change() {
        // deb(5): a changed major number means an incompatible format.
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"3.0\n");
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        assert!(decode(&enc.finish().unwrap()).is_err());
    }

    #[test]
    fn rejects_duplicate_control_member() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("control.tar", b"a");
        enc.add_file("control.tar.gz", b"b");
        enc.add_file("data.tar", b"d");
        assert!(decode(&enc.finish().unwrap()).is_err());
    }

    #[test]
    fn rejects_missing_control_and_data() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_unknown_member_compression() {
        let deb = build_deb_named("control.tar.lz4", b"c", "data.tar", b"d");
        assert!(decode(&deb).is_err());
    }

    #[test]
    fn rejects_name_prefix_lookalikes() {
        let deb = build_deb_named("control.tarball", b"c", "data.tar", b"d");
        let package = decode(&deb);
        assert!(package.is_err());
    }

    #[test]
    fn rejects_duplicate_data_member() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        enc.add_file("data.tar.gz", b"e");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_data_before_control() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("data.tar", b"d");
        enc.add_file("control.tar", b"c");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn rejects_member_between_required() {
        // A member without a leading '_' inserted between the required
        // members cannot be safely ignored per deb(5).
        for extra_at in [1usize, 2] {
            let mut enc = ar::encode::ArEncoder::new();
            enc.add_file(DEBIAN_BINARY, b"2.0\n");
            if extra_at == 1 {
                enc.add_file("signature", b"sig");
            }
            enc.add_file("control.tar", b"c");
            if extra_at == 2 {
                enc.add_file("signature", b"sig");
            }
            enc.add_file("data.tar", b"d");
            let input = enc.finish().unwrap();
            assert!(decode(&input).is_err(), "extra member at {extra_at}");
        }
        // A second debian-binary member is also out of order.
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        let input = enc.finish().unwrap();
        assert!(decode(&input).is_err());
    }

    #[test]
    fn keeps_ignorable_member_between_required() {
        // deb(5): '_' members inserted between the required members are
        // safely ignorable, e.g. signature members.
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("_gpgorigin", b"sig");
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        let input = enc.finish().unwrap();
        let package = decode(&input).unwrap();
        assert_eq!(package.members.len(), 4);
        assert_eq!(package.members[1].kind, DebMemberKind::Other);
        assert_eq!(package.members[1].name, "_gpgorigin");
        assert_eq!(package.members[2].kind, DebMemberKind::Control);
        assert_eq!(package.members[3].kind, DebMemberKind::Data);
    }

    #[test]
    fn keeps_extra_members() {
        let mut enc = ar::encode::ArEncoder::new();
        enc.add_file(DEBIAN_BINARY, b"2.0\n");
        enc.add_file("control.tar", b"c");
        enc.add_file("data.tar", b"d");
        enc.add_file("_gpgorigin", b"sig");
        let input = enc.finish().unwrap();
        let package = decode(&input).unwrap();
        assert_eq!(package.members[3].kind, DebMemberKind::Other);
        assert_eq!(package.member("_gpgorigin").unwrap().data, b"sig");
    }

    #[test]
    fn parses_version_line() {
        assert_eq!(parse_version(b"2.0\n").unwrap(), "2.0");
        assert_eq!(parse_version(b"2.0").unwrap(), "2.0");
        assert_eq!(parse_version(b"2.1\r\nmore\n").unwrap(), "2.1");
        assert!(parse_version(b"2\n").is_err());
        assert!(parse_version(b"x.y\n").is_err());
        assert!(parse_version(b"").is_err());
    }

    #[test]
    fn decompresses_gzip_member() {
        let tar_bytes = tar_with_file("./usr/bin/x", b"payload");
        let gz = gzip::encode::encode(&tar_bytes, crate::compress::deflate::encode::Level::Default);
        let deb = build_deb_named("control.tar", b"c", "data.tar.gz", &gz);
        let package = decode(&deb).unwrap();
        let entries = package.data_entries().unwrap();
        assert_eq!(entries[0].header.name, "./usr/bin/x");
        assert_eq!(entries[0].data, b"payload");
    }

    #[test]
    fn bounded_decode_enforces_limit() {
        let tar_bytes = tar_with_file("./a", b"payload-data");
        let gz = gzip::encode::encode(&tar_bytes, crate::compress::deflate::encode::Level::Default);
        let deb = build_deb_named("control.tar", b"c", "data.tar.gz", &gz);
        let package = decode(&deb).unwrap();
        assert!(package.data_tar_bounded(64).is_err());
        assert_eq!(package.data_tar_bounded(usize::MAX).unwrap(), tar_bytes);
    }
}
