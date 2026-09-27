use clap::ValueEnum;

use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum Format {
    Tar,
    Cpio,
    Ar,
    Deb,
    Rpm,
    Squashfs,
    Mscab,
    Zim,
    Mtree,
    Warc,
    Lha,
    Arj,
    Arc,
    Zpaq,
    Zip,
    #[value(name = "7z")]
    SevenZ,
    Gzip,
    Zstd,
    #[value(name = "zstd-seekable")]
    ZstdSeekable,
    Bzip2,
    Lzip,
    #[value(name = "lzma")]
    LzmaAlone,
    Lzw,
    Lz4,
    Lzo,
    Lrzip,
    Rzip,
    Zlib,
    Snappy,
    Brotli,
    Deflate,
    Xz,
    Xpress,
    #[value(name = "xpress-huff")]
    XpressHuff,
    Lznt1,
    Lzf,
    Fastlz,
    Lzrw1,
    Lzrw1a,
    Lzrw2,
    Lzrw3,
    Lzrw3a,
    Lzsa,
    Zx0,
    Zx1,
    Zx2,
    Zx5,
    Vcdiff,
    Mppc,
    Lzs,
    Lzxd,
    Cmpsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ArchiveFormat {
    Tar,
    Cpio,
    Ar,
    Zpaq,
    Zip,
    #[value(name = "7z")]
    SevenZ,
    Lha,
    Arj,
    Arc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompressionFormat {
    Gzip,
    Zstd,
    #[value(name = "zstd-seekable")]
    ZstdSeekable,
    Bzip2,
    Lzip,
    #[value(name = "lzma")]
    LzmaAlone,
    Lzw,
    Lz4,
    Lzo,
    Lrzip,
    Rzip,
    Zlib,
    Snappy,
    Brotli,
    Deflate,
    Xz,
    Zpaq,
    Xpress,
    #[value(name = "xpress-huff")]
    XpressHuff,
    Lznt1,
    Lzf,
    Fastlz,
    Lzrw1,
    Lzrw1a,
    Lzrw2,
    Lzrw3,
    Lzrw3a,
    Lzsa,
    Lzsa2,
    Zx0,
    Zx1,
    Zx2,
    Zx5,
    Vcdiff,
    Mppc,
    Lzs,
    Lzxd,
    Cmpsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum ContentKind {
    Archive,
    Compression,
}

impl core::fmt::Display for Format {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Tar => "tar",
            Self::Cpio => "cpio",
            Self::Ar => "ar",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Squashfs => "squashfs",
            Self::Mscab => "mscab",
            Self::Zim => "zim",
            Self::Mtree => "mtree",
            Self::Warc => "warc",
            Self::Lha => "lha",
            Self::Arj => "arj",
            Self::Arc => "arc",
            Self::Zpaq => "zpaq",
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
            Self::ZstdSeekable => "zstd-seekable",
            Self::Bzip2 => "bzip2",
            Self::Lzip => "lzip",
            Self::LzmaAlone => "lzma",
            Self::Lzw => "lzw",
            Self::Lz4 => "lz4",
            Self::Lzo => "lzo",
            Self::Lrzip => "lrzip",
            Self::Rzip => "rzip",
            Self::Zlib => "zlib",
            Self::Snappy => "snappy",
            Self::Brotli => "brotli",
            Self::Deflate => "deflate",
            Self::Xz => "xz",
            Self::Xpress => "xpress",
            Self::XpressHuff => "xpress-huff",
            Self::Lznt1 => "lznt1",
            Self::Lzf => "lzf",
            Self::Fastlz => "fastlz",
            Self::Lzrw1 => "lzrw1",
            Self::Lzrw1a => "lzrw1a",
            Self::Lzrw2 => "lzrw2",
            Self::Lzrw3 => "lzrw3",
            Self::Lzrw3a => "lzrw3a",
            Self::Lzsa => "lzsa",
            Self::Zx0 => "zx0",
            Self::Zx1 => "zx1",
            Self::Zx2 => "zx2",
            Self::Zx5 => "zx5",
            Self::Vcdiff => "vcdiff",
            Self::Mppc => "mppc",
            Self::Lzs => "lzs",
            Self::Lzxd => "lzxd",
            Self::Cmpsc => "cmpsc",
        };
        f.write_str(name)
    }
}

impl core::fmt::Display for ContentKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Archive => f.write_str("archive"),
            Self::Compression => f.write_str("compression"),
        }
    }
}

impl From<ArchiveFormat> for Format {
    fn from(format: ArchiveFormat) -> Self {
        match format {
            ArchiveFormat::Tar => Self::Tar,
            ArchiveFormat::Cpio => Self::Cpio,
            ArchiveFormat::Ar => Self::Ar,
            ArchiveFormat::Zpaq => Self::Zpaq,
            ArchiveFormat::Zip => Self::Zip,
            ArchiveFormat::SevenZ => Self::SevenZ,
            ArchiveFormat::Lha => Self::Lha,
            ArchiveFormat::Arj => Self::Arj,
            ArchiveFormat::Arc => Self::Arc,
        }
    }
}

impl From<CompressionFormat> for Format {
    fn from(format: CompressionFormat) -> Self {
        match format {
            CompressionFormat::Gzip => Self::Gzip,
            CompressionFormat::Zstd => Self::Zstd,
            CompressionFormat::ZstdSeekable => Self::ZstdSeekable,
            CompressionFormat::Bzip2 => Self::Bzip2,
            CompressionFormat::Lzip => Self::Lzip,
            CompressionFormat::LzmaAlone => Self::LzmaAlone,
            CompressionFormat::Lzw => Self::Lzw,
            CompressionFormat::Lz4 => Self::Lz4,
            CompressionFormat::Lzo => Self::Lzo,
            CompressionFormat::Lrzip => Self::Lrzip,
            CompressionFormat::Rzip => Self::Rzip,
            CompressionFormat::Zlib => Self::Zlib,
            CompressionFormat::Snappy => Self::Snappy,
            CompressionFormat::Brotli => Self::Brotli,
            CompressionFormat::Deflate => Self::Deflate,
            CompressionFormat::Xz => Self::Xz,
            CompressionFormat::Zpaq => Self::Zpaq,
            CompressionFormat::Xpress => Self::Xpress,
            CompressionFormat::XpressHuff => Self::XpressHuff,
            CompressionFormat::Lznt1 => Self::Lznt1,
            CompressionFormat::Lzf => Self::Lzf,
            CompressionFormat::Fastlz => Self::Fastlz,
            CompressionFormat::Lzrw1 => Self::Lzrw1,
            CompressionFormat::Lzrw1a => Self::Lzrw1a,
            CompressionFormat::Lzrw2 => Self::Lzrw2,
            CompressionFormat::Lzrw3 => Self::Lzrw3,
            CompressionFormat::Lzrw3a => Self::Lzrw3a,
            CompressionFormat::Lzsa | CompressionFormat::Lzsa2 => Self::Lzsa,
            CompressionFormat::Zx0 => Self::Zx0,
            CompressionFormat::Zx1 => Self::Zx1,
            CompressionFormat::Zx2 => Self::Zx2,
            CompressionFormat::Zx5 => Self::Zx5,
            CompressionFormat::Vcdiff => Self::Vcdiff,
            CompressionFormat::Mppc => Self::Mppc,
            CompressionFormat::Lzs => Self::Lzs,
            CompressionFormat::Lzxd => Self::Lzxd,
            CompressionFormat::Cmpsc => Self::Cmpsc,
        }
    }
}

pub fn choose_format(input: &[u8], override_format: Option<Format>) -> Result<Format, CliError> {
    override_format
        .or_else(|| detect_format(input))
        .ok_or_else(|| {
            CliError::Detect("could not auto-detect format; retry with --format".to_owned())
        })
}

pub fn detect_format(input: &[u8]) -> Option<Format> {
    if input.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(Format::SevenZ);
    }
    if input.starts_with(b"PK\x03\x04")
        || input.starts_with(b"PK\x05\x06")
        || input.starts_with(b"PK\x07\x08")
    {
        return Some(Format::Zip);
    }
    if input.starts_with(&[0x1F, 0x8B]) {
        return Some(Format::Gzip);
    }
    if input.starts_with(b"BZh") {
        return Some(Format::Bzip2);
    }
    if input.starts_with(b"LZIP") {
        return Some(Format::Lzip);
    }
    if input.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(Format::Xz);
    }
    if input.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Format::Zstd);
    }
    if input.starts_with(&[0xD6, 0xC3, 0xC4]) {
        return Some(Format::Vcdiff);
    }
    if input.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        return Some(Format::Lz4);
    }
    if input.starts_with(&[0x89, 0x4C, 0x5A, 0x4F, 0x00, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(Format::Lzo);
    }
    if input.starts_with(b"LRZI") {
        return Some(Format::Lrzip);
    }
    if input.starts_with(b"RZIP") {
        return Some(Format::Rzip);
    }
    if input.starts_with(&[0x1F, 0x9D]) {
        return Some(Format::Lzw);
    }
    if input.starts_with(&[0x60, 0xEA]) {
        return Some(Format::Arj);
    }
    if input.len() >= 2 && input[0] == 0x1A && (1..=8).contains(&input[1]) {
        return Some(Format::Arc);
    }
    if input.len() >= 21
        && input[2] == b'-'
        && input[3] == b'l'
        && input[6] == b'-'
        && input[20] <= 2
    {
        return Some(Format::Lha);
    }
    if input.starts_with(b"!<arch>\ndebian-binary") {
        return Some(Format::Deb);
    }
    if input.starts_with(&[0xED, 0xAB, 0xEE, 0xDB]) {
        return Some(Format::Rpm);
    }
    if input.starts_with(b"hsqs") {
        return Some(Format::Squashfs);
    }
    if input.starts_with(b"MSCF") {
        return Some(Format::Mscab);
    }
    if input.len() >= 4 && u32::from_le_bytes(input[..4].try_into().unwrap()) == 0x044D_495A {
        return Some(Format::Zim);
    }
    if input.starts_with(b"#mtree") {
        return Some(Format::Mtree);
    }
    if input.starts_with(b"WARC/1.0\r\n") || input.starts_with(b"WARC/1.1\r\n") {
        return Some(Format::Warc);
    }
    if input.starts_with(b"!<arch>\n") {
        return Some(Format::Ar);
    }
    if input.starts_with(b"070701") || input.starts_with(b"070702") || input.starts_with(b"070707")
    {
        return Some(Format::Cpio);
    }
    if input.len() >= 3
        && input[0] == 0x7b
        && input[1] == 0x9e
        && input[2] & 0x1f == 0
        && input[2] >> 5 <= 1
    {
        return Some(Format::Lzsa);
    }
    if input.starts_with(b"zPQ") {
        return Some(Format::Zpaq);
    }
    if input.len() >= 262 && &input[257..262] == b"ustar" {
        return Some(Format::Tar);
    }
    if looks_like_zlib(input) {
        return Some(Format::Zlib);
    }
    None
}

fn looks_like_zlib(input: &[u8]) -> bool {
    if input.len() < 2 {
        return false;
    }
    let cmf = input[0];
    let flg = input[1];
    (cmf & 0x0F) == 8 && ((u16::from(cmf) << 8) | u16::from(flg)) % 31 == 0
}

pub fn scope_notes(format: Format) -> Vec<String> {
    match format {
        Format::Rzip => vec![
            "encode output is validated for crate roundtrip plus documented direct `system rzip -d` interop cases; full parity is still not claimed".to_owned(),
        ],
        Format::Lrzip => vec![
            "current interop scope is the documented supported backend subset".to_owned(),
        ],
        Format::Zip => vec![
            "encrypted write with data descriptors is intentionally not exposed by the CLI".to_owned(),
        ],
        Format::SevenZ => vec![
            "7z write support is intentionally limited to the current baseline one-folder subset".to_owned(),
        ],
        Format::Deb => vec![
            "deb extraction unpacks the data.tar payload; use --format ar for raw member access".to_owned(),
        ],
        Format::Rpm => vec![
            "rpm support is read-only; header signatures and payload digests are parsed but not verified".to_owned(),
        ],
        Format::Squashfs => vec![
            "squashfs support is read-only; LZMA1-compressed images are unsupported".to_owned(),
        ],
        Format::Mscab => vec![
            "mscab support is read-only; Quantum/LZX folders and multi-cabinet sets are unsupported".to_owned(),
        ],
        Format::Zim => vec![
            "zim support is read-only; entry names include the ZIM namespace prefix".to_owned(),
        ],
        Format::Mtree => vec![
            "mtree is a manifest format; entries carry metadata only, no file content".to_owned(),
        ],
        Format::Warc => vec![
            "warc support is read-only; .warc.gz must be decompressed as gzip first".to_owned(),
        ],
        Format::Lha => vec![
            "lha support covers stored (-lh0-/-lhd-) entries only; LZH-compressed methods are rejected".to_owned(),
        ],
        Format::Arj => vec![
            "arj support covers method-0 (stored) entries only; compressed/encrypted entries are rejected".to_owned(),
        ],
        Format::Arc => vec![
            "arc support covers stored methods (1/2) only; packed/squeezed/crunched members are rejected".to_owned(),
        ],
        Format::Xpress | Format::XpressHuff | Format::Lznt1 => vec![
            "MS-XCA streams carry no container header or magic; --format is required".to_owned(),
        ],
        Format::Lzf => vec![
            "lzf streams carry no container header or magic; --format is required".to_owned(),
        ],
        Format::Fastlz => vec![
            "fastlz streams carry no container header or magic; --format is required".to_owned(),
        ],
        Format::Zx0 => vec![
            "zx0 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Zx1 => vec![
            "zx1 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Zx2 => vec![
            "zx2 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Zx5 => vec![
            "zx5 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Mppc => vec![
            "mppc packets carry no magic; --format is required".to_owned(),
        ],
        Format::Lzs => vec![
            "lzs streams carry no magic; --format is required".to_owned(),
        ],
        Format::ZstdSeekable => vec![
            "zstd-seekable streams auto-detect as zstd; selecting this format requires and validates the seek table".to_owned(),
        ],
        Format::Lzrw1 => vec![
            "lzrw1 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Lzrw1a => vec![
            "lzrw1a streams carry no magic; --format is required".to_owned(),
        ],
        Format::Lzrw2 => vec![
            "lzrw2 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Lzrw3 => vec![
            "lzrw3 streams carry no magic; --format is required".to_owned(),
        ],
        Format::Lzrw3a => vec![
            "lzrw3a streams carry no magic; --format is required".to_owned(),
        ],
        Format::Lzxd => vec![
            "lzxd streams carry no magic; --format is required (decoding assumes the maximum window size)".to_owned(),
        ],
        Format::Cmpsc => vec![
            "cmpsc streams carry no magic; --format is required (payload must be an APPNOTE method-16 stream)".to_owned(),
        ],
        _ => Vec::new(),
    }
}

pub const fn checksum_verified_by_default(format: Format) -> bool {
    matches!(
        format,
        Format::Tar
            | Format::Cpio
            | Format::Ar
            | Format::Deb
            | Format::Zpaq
            | Format::Lha
            | Format::Arj
            | Format::Arc
            | Format::Zip
            | Format::SevenZ
            | Format::Gzip
            | Format::Zstd
            | Format::Bzip2
            | Format::Lzip
            | Format::Lz4
            | Format::Lzo
            | Format::Lrzip
            | Format::Rzip
            | Format::Zlib
            | Format::Xz
    )
}

#[cfg(test)]
mod tests {
    use super::{Format, detect_format};

    #[test]
    fn detect_gzip() {
        assert_eq!(detect_format(&[0x1F, 0x8B, 0x08, 0x00]), Some(Format::Gzip));
    }

    #[test]
    fn detect_zip() {
        assert_eq!(detect_format(b"PK\x03\x04rest"), Some(Format::Zip));
    }

    #[test]
    fn detect_sevenz() {
        assert_eq!(
            detect_format(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4]),
            Some(Format::SevenZ)
        );
    }

    #[test]
    fn detect_tar() {
        let mut data = vec![0u8; 512];
        data[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect_format(&data), Some(Format::Tar));
    }

    #[test]
    fn detect_zlib() {
        assert_eq!(detect_format(&[0x78, 0x9C, 0, 0]), Some(Format::Zlib));
    }

    #[test]
    fn detect_deb() {
        assert_eq!(
            detect_format(b"!<arch>\ndebian-binary/   rest"),
            Some(Format::Deb)
        );
    }

    #[test]
    fn detect_rpm() {
        assert_eq!(
            detect_format(&[0xED, 0xAB, 0xEE, 0xDB, 4, 0]),
            Some(Format::Rpm)
        );
    }

    #[test]
    fn detect_squashfs() {
        assert_eq!(detect_format(b"hsqsrest"), Some(Format::Squashfs));
    }

    #[test]
    fn detect_mscab() {
        assert_eq!(detect_format(b"MSCFrest"), Some(Format::Mscab));
    }

    #[test]
    fn detect_zim() {
        let mut d = vec![0u8; 8];
        d[..4].copy_from_slice(&0x044D_495Au32.to_le_bytes());
        assert_eq!(detect_format(&d), Some(Format::Zim));
    }

    #[test]
    fn detect_mtree() {
        assert_eq!(detect_format(b"#mtree\n/set"), Some(Format::Mtree));
    }

    #[test]
    fn detect_warc() {
        assert_eq!(detect_format(b"WARC/1.1\r\nrest"), Some(Format::Warc));
    }

    #[test]
    fn detect_plain_ar_not_deb() {
        assert_eq!(
            detect_format(b"!<arch>\nfile.o/         rest"),
            Some(Format::Ar)
        );
    }

    #[test]
    fn detect_lzsa() {
        // 7b 9e magic; traits byte selects the block level (v1 or v2).
        assert_eq!(detect_format(&[0x7B, 0x9E, 0x00]), Some(Format::Lzsa));
        assert_eq!(detect_format(&[0x7B, 0x9E, 0x20]), Some(Format::Lzsa));
        assert_eq!(detect_format(&[0x7B, 0x9D, 0x00]), None);
        // traits byte must have reserved bits clear and version <= 1.
        assert_eq!(detect_format(&[0x7B, 0x9E, 0x01]), None);
        assert_eq!(detect_format(&[0x7B, 0x9E, 0x40]), None);
        // magic alone without a traits byte is not a stream.
        assert_eq!(detect_format(&[0x7B, 0x9E]), None);
    }

    #[test]
    fn detect_lha() {
        // "-l?-" signature at offset 2 and level byte <= 2 at offset 20.
        let mut d = *b"xx-lh0-.............\x00.";
        assert_eq!(detect_format(&d), Some(Format::Lha));
        d[20] = 3; // level 3 is out of range
        assert_eq!(detect_format(&d), None);
    }

    #[test]
    fn detect_arj() {
        assert_eq!(detect_format(&[0x60, 0xEA, 0x00]), Some(Format::Arj));
    }

    #[test]
    fn detect_arc() {
        assert_eq!(detect_format(&[0x1A, 0x01]), Some(Format::Arc));
        assert_eq!(detect_format(&[0x1A, 0x08]), Some(Format::Arc));
        assert_eq!(detect_format(&[0x1A, 0x09]), None);
    }
}
