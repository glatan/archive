use std::fs;
use std::path::Path;

use ::archive::compress;

use crate::args::CompressCommand;
use crate::detect::CompressionFormat;
use crate::error::CliError;

pub fn compress_input(command: CompressCommand) -> Result<(), CliError> {
    ensure_output_absent(&command.output)?;
    let input = fs::read(&command.input)?;
    let encoded = match command.format {
        CompressionFormat::Gzip => {
            compress::gzip::encode::encode(&input, map_deflate_level(command.level)?)
        }
        CompressionFormat::Deflate => {
            compress::deflate::encode::encode(&input, map_deflate_level(command.level)?)
        }
        CompressionFormat::Bzip2 => {
            if let Some(level) = command.level {
                if !(1..=9).contains(&level) {
                    return Err(CliError::Detect(
                        "bzip2 --level must be in the range 1..=9".to_owned(),
                    ));
                }
                compress::bzip2::encode::encode_with_level(&input, level)
            } else {
                compress::bzip2::encode::encode(&input)
            }
        }
        CompressionFormat::Rzip => {
            if let Some(level) = command.level {
                if !(1..=9).contains(&level) {
                    return Err(CliError::Detect(
                        "rzip --level must be in the range 1..=9".to_owned(),
                    ));
                }
                compress::rzip::encode::encode_with_level(&input, level)
            } else {
                compress::rzip::encode::encode(&input)
            }
        }
        CompressionFormat::Lzw => {
            if let Some(level) = command.level {
                if !(9..=16).contains(&level) {
                    return Err(CliError::Detect(
                        "lzw --level must be in the range 9..=16".to_owned(),
                    ));
                }
                compress::lzw::encode::encode_with_options(&input, level)
            } else {
                compress::lzw::encode::encode(&input)
            }
        }
        CompressionFormat::Zpaq => {
            let level = command.level.unwrap_or(1);
            if !(1..=3).contains(&level) {
                return Err(CliError::Detect(
                    "zpaq --level must be in the range 1..=3".to_owned(),
                ));
            }
            compress::zpaq::encode::encode(&input, u32::from(level))
        }
        CompressionFormat::Lrzip => {
            if command.level.is_some() {
                return Err(CliError::Unsupported(
                    "lrzip: --level is not exposed by this CLI; use --backend only".to_owned(),
                ));
            }
            let backend = match command.backend.as_deref().unwrap_or("lzma") {
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
            compress::lrzip::encode::encode_with(&input, backend)
        }
        CompressionFormat::Zstd => {
            reject_unexpected_level(command.level, "zstd")?;
            reject_unexpected_backend(command.backend.as_deref(), "zstd")?;
            compress::zstd::encode::encode(&input)
        }
        CompressionFormat::Lzip => {
            reject_unexpected_level(command.level, "lzip")?;
            reject_unexpected_backend(command.backend.as_deref(), "lzip")?;
            compress::lzip::encode::encode(&input)
        }
        CompressionFormat::Lz4 => {
            reject_unexpected_level(command.level, "lz4")?;
            reject_unexpected_backend(command.backend.as_deref(), "lz4")?;
            compress::lz4::encode::encode(&input)
        }
        CompressionFormat::Lzo => {
            reject_unexpected_level(command.level, "lzo")?;
            reject_unexpected_backend(command.backend.as_deref(), "lzo")?;
            compress::lzo::encode::encode(&input)
        }
        CompressionFormat::Zlib => {
            reject_unexpected_level(command.level, "zlib")?;
            reject_unexpected_backend(command.backend.as_deref(), "zlib")?;
            compress::zlib::encode::encode(&input)
        }
        CompressionFormat::Snappy => {
            reject_unexpected_level(command.level, "snappy")?;
            reject_unexpected_backend(command.backend.as_deref(), "snappy")?;
            compress::snappy::encode::encode(&input)
        }
        CompressionFormat::Brotli => {
            reject_unexpected_level(command.level, "brotli")?;
            reject_unexpected_backend(command.backend.as_deref(), "brotli")?;
            compress::brotli::encode::encode(&input)
        }
        CompressionFormat::Xz => {
            reject_unexpected_level(command.level, "xz")?;
            reject_unexpected_backend(command.backend.as_deref(), "xz")?;
            compress::xz::encode::encode(&input)
        }
    };
    fs::write(&command.output, encoded)?;
    Ok(())
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
