use clap::ValueEnum;

use crate::error::CliError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[cfg_attr(feature = "json", derive(serde::Serialize))]
pub enum Format {
    Tar,
    Cpio,
    Ar,
    Zpaq,
    Zip,
    #[value(name = "7z")]
    SevenZ,
    Gzip,
    Zstd,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CompressionFormat {
    Gzip,
    Zstd,
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
            Self::Zpaq => "zpaq",
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
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
        }
    }
}

impl From<CompressionFormat> for Format {
    fn from(format: CompressionFormat) -> Self {
        match format {
            CompressionFormat::Gzip => Self::Gzip,
            CompressionFormat::Zstd => Self::Zstd,
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
    if input.starts_with(b"!<arch>\n") {
        return Some(Format::Ar);
    }
    if input.starts_with(b"070701") || input.starts_with(b"070702") || input.starts_with(b"070707")
    {
        return Some(Format::Cpio);
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
        _ => Vec::new(),
    }
}

pub const fn checksum_verified_by_default(format: Format) -> bool {
    matches!(
        format,
        Format::Tar
            | Format::Cpio
            | Format::Ar
            | Format::Zpaq
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
}
