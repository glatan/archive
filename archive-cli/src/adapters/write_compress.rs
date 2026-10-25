use std::fs;
use std::path::Path;

use ::archive::compress;

use crate::args::CompressCommand;
use crate::detect::CompressionFormat;
use crate::error::CliError;

pub fn compress_input(command: CompressCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let input = fs::read(&command.input)?;
    let encoded = compress_bytes(
        command.format,
        &input,
        command.level,
        command.backend.as_deref(),
    )?;
    fs::write(&command.output, encoded)?;
    Ok(())
}

/// Encode `input` with the same dispatch used by `archive compress`.
///
/// The benchmark helper calls this directly so that in-process timings use
/// the production codec dispatch, not a benchmark-only copy.
pub fn compress_bytes(
    format: CompressionFormat,
    input: &[u8],
    level: Option<u8>,
    backend: Option<&str>,
) -> Result<Vec<u8>, CliError> {
    let encoded = match format {
        CompressionFormat::Gzip => compress::gzip::encode::encode(input, map_deflate_level(level)?),
        CompressionFormat::Deflate => {
            compress::deflate::encode::encode(input, map_deflate_level(level)?)
        }
        CompressionFormat::Bzip2 => {
            if let Some(level) = level {
                if !(1..=9).contains(&level) {
                    return Err(CliError::Detect(
                        "bzip2 --level must be in the range 1..=9".to_owned(),
                    ));
                }
                compress::bzip2::encode::encode_with_level(input, level)
            } else {
                compress::bzip2::encode::encode(input)
            }
        }
        CompressionFormat::Rzip => {
            if let Some(level) = level {
                if !(1..=9).contains(&level) {
                    return Err(CliError::Detect(
                        "rzip --level must be in the range 1..=9".to_owned(),
                    ));
                }
                compress::rzip::encode::encode_with_level(input, level)
            } else {
                compress::rzip::encode::encode(input)
            }
        }
        CompressionFormat::Lzw => {
            if let Some(level) = level {
                if !(9..=16).contains(&level) {
                    return Err(CliError::Detect(
                        "lzw --level must be in the range 9..=16".to_owned(),
                    ));
                }
                compress::lzw::encode::encode_with_options(input, level)
            } else {
                compress::lzw::encode::encode(input)
            }
        }
        CompressionFormat::Zpaq => {
            let level = level.unwrap_or(1);
            if !(1..=3).contains(&level) {
                return Err(CliError::Detect(
                    "zpaq --level must be in the range 1..=3".to_owned(),
                ));
            }
            compress::zpaq::encode::encode(input, u32::from(level))
        }
        CompressionFormat::Lrzip => {
            if level.is_some() {
                return Err(CliError::Unsupported(
                    "lrzip: --level is not exposed by this CLI; use --backend only".to_owned(),
                ));
            }
            let backend = match backend.unwrap_or("lzma") {
                "none" => compress::lrzip::encode::CompressionType::None,
                "bzip2" => compress::lrzip::encode::CompressionType::Bzip2,
                "lzo" => compress::lrzip::encode::CompressionType::Lzo,
                "lzma" => compress::lrzip::encode::CompressionType::Lzma,
                "gzip" => compress::lrzip::encode::CompressionType::Gzip,
                "zpaq" => compress::lrzip::encode::CompressionType::Zpaq,
                other => {
                    return Err(CliError::Detect(format!(
                        "unsupported lrzip backend `{other}`; expected one of: none, bzip2, lzo, lzma, gzip, zpaq"
                    )));
                }
            };
            compress::lrzip::encode::encode_with(input, backend)
        }
        CompressionFormat::Zstd => {
            reject_unexpected_level(level, "zstd")?;
            reject_unexpected_backend(backend, "zstd")?;
            compress::zstd::encode::encode(input)
        }
        CompressionFormat::ZstdSeekable => {
            reject_unexpected_level(level, "zstd-seekable")?;
            reject_unexpected_backend(backend, "zstd-seekable")?;
            compress::zstd::seekable::encode(input, compress::zstd::seekable::DEFAULT_FRAME_SIZE)
        }
        CompressionFormat::Lzip => {
            reject_unexpected_level(level, "lzip")?;
            reject_unexpected_backend(backend, "lzip")?;
            compress::lzip::encode::encode(input)
        }
        CompressionFormat::LzmaAlone => {
            reject_unexpected_level(level, "lzma")?;
            reject_unexpected_backend(backend, "lzma")?;
            compress::lzma_alone::encode::encode(input)
        }
        CompressionFormat::Lz4 => {
            reject_unexpected_level(level, "lz4")?;
            reject_unexpected_backend(backend, "lz4")?;
            compress::lz4::encode::encode(input)
        }
        CompressionFormat::Lzo => {
            reject_unexpected_level(level, "lzo")?;
            reject_unexpected_backend(backend, "lzo")?;
            compress::lzo::encode::encode(input)
        }
        CompressionFormat::Zlib => {
            reject_unexpected_level(level, "zlib")?;
            reject_unexpected_backend(backend, "zlib")?;
            compress::zlib::encode::encode(input)
        }
        CompressionFormat::Snappy => {
            reject_unexpected_level(level, "snappy")?;
            reject_unexpected_backend(backend, "snappy")?;
            compress::snappy::encode::encode(input)
        }
        CompressionFormat::Brotli => {
            reject_unexpected_level(level, "brotli")?;
            reject_unexpected_backend(backend, "brotli")?;
            compress::brotli::encode::encode(input)
        }
        CompressionFormat::Xz => {
            reject_unexpected_level(level, "xz")?;
            reject_unexpected_backend(backend, "xz")?;
            compress::xz::encode::encode(input)
        }
        CompressionFormat::Xpress => {
            reject_unexpected_level(level, "xpress")?;
            reject_unexpected_backend(backend, "xpress")?;
            compress::xca::lz77::encode(input)
        }
        CompressionFormat::XpressHuff => {
            reject_unexpected_level(level, "xpress-huff")?;
            reject_unexpected_backend(backend, "xpress-huff")?;
            compress::xca::huffman::encode(input)
        }
        CompressionFormat::Lznt1 => {
            reject_unexpected_level(level, "lznt1")?;
            reject_unexpected_backend(backend, "lznt1")?;
            compress::xca::lznt1::encode(input)
        }
        CompressionFormat::Lzf => {
            reject_unexpected_level(level, "lzf")?;
            reject_unexpected_backend(backend, "lzf")?;
            compress::lzf::encode(input)
        }
        CompressionFormat::Fastlz => {
            reject_unexpected_level(level, "fastlz")?;
            reject_unexpected_backend(backend, "fastlz")?;
            compress::fastlz::encode(input)
        }
        CompressionFormat::Lzrw1 => {
            reject_unexpected_level(level, "lzrw1")?;
            reject_unexpected_backend(backend, "lzrw1")?;
            compress::lzrw1::encode(input)
        }
        CompressionFormat::Lzrw1a => {
            reject_unexpected_level(level, "lzrw1a")?;
            reject_unexpected_backend(backend, "lzrw1a")?;
            compress::lzrw1a::encode(input)
        }
        CompressionFormat::Lzrw2 => {
            reject_unexpected_level(level, "lzrw2")?;
            reject_unexpected_backend(backend, "lzrw2")?;
            compress::lzrw2::encode(input)
        }
        CompressionFormat::Lzrw3 => {
            reject_unexpected_level(level, "lzrw3")?;
            reject_unexpected_backend(backend, "lzrw3")?;
            compress::lzrw3::encode(input)
        }
        CompressionFormat::Lzrw3a => {
            reject_unexpected_level(level, "lzrw3a")?;
            reject_unexpected_backend(backend, "lzrw3a")?;
            compress::lzrw3a::encode(input)
        }
        CompressionFormat::Lzsa => {
            reject_unexpected_level(level, "lzsa")?;
            reject_unexpected_backend(backend, "lzsa")?;
            compress::lzsa::encode(input)
        }
        CompressionFormat::Lzsa2 => {
            reject_unexpected_level(level, "lzsa2")?;
            reject_unexpected_backend(backend, "lzsa2")?;
            compress::lzsa::encode_lzsa2(input)
        }
        CompressionFormat::Zx0 => {
            reject_unexpected_level(level, "zx0")?;
            reject_unexpected_backend(backend, "zx0")?;
            compress::zx0::encode(input)
        }
        CompressionFormat::Zx1 => {
            reject_unexpected_level(level, "zx1")?;
            reject_unexpected_backend(backend, "zx1")?;
            compress::zx1::encode(input)
        }
        CompressionFormat::Zx2 => {
            reject_unexpected_level(level, "zx2")?;
            reject_unexpected_backend(backend, "zx2")?;
            compress::zx2::encode(input)
        }
        CompressionFormat::Zx5 => {
            reject_unexpected_level(level, "zx5")?;
            reject_unexpected_backend(backend, "zx5")?;
            compress::zx5::encode(input)
        }
        CompressionFormat::Zx0b => {
            reject_unexpected_level(level, "zx0b")?;
            reject_unexpected_backend(backend, "zx0b")?;
            compress::zx0::encode_backwards(input)
        }
        CompressionFormat::Zx1b => {
            reject_unexpected_level(level, "zx1b")?;
            reject_unexpected_backend(backend, "zx1b")?;
            compress::zx1::encode_backwards(input)
        }
        CompressionFormat::Zx2b => {
            reject_unexpected_level(level, "zx2b")?;
            reject_unexpected_backend(backend, "zx2b")?;
            compress::zx2::encode_backwards(input)
        }
        CompressionFormat::Zx5b => {
            reject_unexpected_level(level, "zx5b")?;
            reject_unexpected_backend(backend, "zx5b")?;
            compress::zx5::encode_backwards(input)
        }
        CompressionFormat::Vcdiff => {
            reject_unexpected_level(level, "vcdiff")?;
            reject_unexpected_backend(backend, "vcdiff")?;
            compress::vcdiff::encode(input)
        }
        CompressionFormat::Mppc => {
            reject_unexpected_level(level, "mppc")?;
            reject_unexpected_backend(backend, "mppc")?;
            compress::mppc::encode(input)
                .map_err(|error| CliError::from_archive_error(error, false))?
        }
        CompressionFormat::Lzs => {
            reject_unexpected_level(level, "lzs")?;
            reject_unexpected_backend(backend, "lzs")?;
            compress::lzs::encode(input)
                .map_err(|error| CliError::from_archive_error(error, false))?
        }
        CompressionFormat::Lzxd => {
            reject_unexpected_level(level, "lzxd")?;
            reject_unexpected_backend(backend, "lzxd")?;
            compress::lzxd::encode(input)
        }
        CompressionFormat::Cmpsc => {
            reject_unexpected_level(level, "cmpsc")?;
            reject_unexpected_backend(backend, "cmpsc")?;
            compress::cmpsc::encode(input)
        }
    };
    Ok(encoded)
}

fn map_deflate_level(level: Option<u8>) -> Result<compress::deflate::encode::Level, CliError> {
    match level.unwrap_or(6) {
        0 => Ok(compress::deflate::encode::Level::NoCompression),
        1..=3 => Ok(compress::deflate::encode::Level::Fast),
        4..=9 => Ok(compress::deflate::encode::Level::Default),
        other => Err(CliError::Detect(format!(
            "deflate/gzip --level must be in the range 0..=9, got {other}"
        ))),
    }
}

fn reject_unexpected_level(level: Option<u8>, format: &str) -> Result<(), CliError> {
    if level.is_some() {
        Err(CliError::Unsupported(format!(
            "{format}: --level is not exposed by this CLI for the current writer surface"
        )))
    } else {
        Ok(())
    }
}

fn reject_unexpected_backend(backend: Option<&str>, format: &str) -> Result<(), CliError> {
    if backend.is_some() {
        Err(CliError::Unsupported(format!(
            "{format}: --backend is only supported for lrzip"
        )))
    } else {
        Ok(())
    }
}

fn ensure_output_absent(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        return Err(CliError::Detect(format!(
            "refusing to overwrite existing output {}; choose a new path",
            path.display()
        )));
    }
    Ok(())
}
