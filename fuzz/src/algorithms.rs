//! Algorithm registry — maps algorithm names to encode/decode functions.
//!
//! Each [`Algorithm`] variant corresponds to a compression format or archive
//! format supported by the `archive` crate. The [`encode_with`] and
//! [`decode_with`] functions dispatch to the appropriate library calls.
//!
//! Archive formats (tar, cpio) are wrapped so they present the same
//! `&[u8] → Vec<u8>` interface as compression: a single file named
//! `"fuzz_test"` is packed/unpacked as the archive payload.

use archive::archive::{ar, cpio, sevenz, tar, zip};
use archive::compress::*;
use archive::error::Error;
use std::fmt;

/// Compression algorithm or archive format under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Deflate,
    Gzip,
    GzipFast,
    GzipStore,
    Zstd,
    ZstdFast,
    ZstdBest,
    ZstdNoChecksum,
    Bzip2,
    Bzip2Fast,
    Bzip2Best,
    Lzip,
    LzipFast,
    LzipBest,
    LzmaAlone,
    Xz,
    XzFast,
    XzBest,
    Lzw,
    LzwBits9,
    Lz4,
    Lz4Fast,
    Lz4Best,
    Lz4SmallBlock,
    Lzo,
    LzoFast,
    LzoBest,
    LrzipLzma,
    LrzipBzip2,
    LrzipGzip,
    LrzipLzo,
    LrzipNone,
    LrzipZpaq,
    Brotli,
    BrotliFast,
    BrotliBest,
    Snappy,
    Rzip,
    Zlib,
    Zpaq,
    ZpaqLevel2,
    ZpaqLevel3,
    Ar,
    ArBsd,
    Zip,
    ZipStore,
    ZipBzip2,
    ZipZstd,
    SevenZ,
    SevenZCopy,
    SevenZLzma,
    SevenZPpmd,
    TarGnu,
    TarUstar,
    TarPax,
    Cpio,
    CpioCrc,
}

impl Algorithm {
    /// Every algorithm variant, in the order they appear in `--algorithm all`.
    pub const ALL: &[Algorithm] = &[
        Algorithm::Deflate,
        Algorithm::Gzip,
        Algorithm::GzipFast,
        Algorithm::GzipStore,
        Algorithm::Zstd,
        Algorithm::ZstdFast,
        Algorithm::ZstdBest,
        Algorithm::ZstdNoChecksum,
        Algorithm::Bzip2,
        Algorithm::Bzip2Fast,
        Algorithm::Bzip2Best,
        Algorithm::Lzip,
        Algorithm::LzipFast,
        Algorithm::LzipBest,
        Algorithm::LzmaAlone,
        Algorithm::Xz,
        Algorithm::XzFast,
        Algorithm::XzBest,
        Algorithm::Lzw,
        Algorithm::LzwBits9,
        Algorithm::Lz4,
        Algorithm::Lz4Fast,
        Algorithm::Lz4Best,
        Algorithm::Lz4SmallBlock,
        Algorithm::Lzo,
        Algorithm::LzoFast,
        Algorithm::LzoBest,
        Algorithm::LrzipLzma,
        Algorithm::LrzipBzip2,
        Algorithm::LrzipGzip,
        Algorithm::LrzipLzo,
        Algorithm::LrzipNone,
        Algorithm::LrzipZpaq,
        Algorithm::Brotli,
        Algorithm::BrotliFast,
        Algorithm::BrotliBest,
        Algorithm::Snappy,
        Algorithm::Rzip,
        Algorithm::Zlib,
        Algorithm::Zpaq,
        Algorithm::ZpaqLevel2,
        Algorithm::ZpaqLevel3,
        Algorithm::Ar,
        Algorithm::ArBsd,
        Algorithm::Zip,
        Algorithm::ZipStore,
        Algorithm::ZipBzip2,
        Algorithm::ZipZstd,
        Algorithm::SevenZ,
        Algorithm::SevenZCopy,
        Algorithm::SevenZLzma,
        Algorithm::SevenZPpmd,
        Algorithm::TarGnu,
        Algorithm::TarUstar,
        Algorithm::TarPax,
        Algorithm::Cpio,
        Algorithm::CpioCrc,
    ];

    /// CLI-facing name used in `--algorithm` and log output.
    pub const fn name(self) -> &'static str {
        match self {
            Algorithm::Deflate => "deflate",
            Algorithm::Gzip => "gzip",
            Algorithm::GzipFast => "gzip-fast",
            Algorithm::GzipStore => "gzip-store",
            Algorithm::Zstd => "zstd",
            Algorithm::ZstdFast => "zstd-fast",
            Algorithm::ZstdBest => "zstd-best",
            Algorithm::ZstdNoChecksum => "zstd-nochecksum",
            Algorithm::Bzip2 => "bzip2",
            Algorithm::Bzip2Fast => "bzip2-fast",
            Algorithm::Bzip2Best => "bzip2-best",
            Algorithm::Lzip => "lzip",
            Algorithm::LzipFast => "lzip-fast",
            Algorithm::LzipBest => "lzip-best",
            Algorithm::LzmaAlone => "lzma",
            Algorithm::Xz => "xz",
            Algorithm::XzFast => "xz-fast",
            Algorithm::XzBest => "xz-best",
            Algorithm::Lzw => "lzw",
            Algorithm::LzwBits9 => "lzw-bits9",
            Algorithm::Lz4 => "lz4",
            Algorithm::Lz4Fast => "lz4-fast",
            Algorithm::Lz4Best => "lz4-best",
            Algorithm::Lz4SmallBlock => "lz4-small-block",
            Algorithm::Lzo => "lzo",
            Algorithm::LzoFast => "lzo-fast",
            Algorithm::LzoBest => "lzo-best",
            Algorithm::LrzipLzma => "lrzip-lzma",
            Algorithm::LrzipBzip2 => "lrzip-bzip2",
            Algorithm::LrzipGzip => "lrzip-gzip",
            Algorithm::LrzipLzo => "lrzip-lzo",
            Algorithm::LrzipNone => "lrzip-none",
            Algorithm::LrzipZpaq => "lrzip-zpaq",
            Algorithm::Brotli => "brotli",
            Algorithm::BrotliFast => "brotli-fast",
            Algorithm::BrotliBest => "brotli-best",
            Algorithm::Snappy => "snappy",
            Algorithm::Rzip => "rzip",
            Algorithm::Zlib => "zlib",
            Algorithm::Zpaq => "zpaq",
            Algorithm::ZpaqLevel2 => "zpaq-level2",
            Algorithm::ZpaqLevel3 => "zpaq-level3",
            Algorithm::Ar => "ar",
            Algorithm::ArBsd => "ar-bsd",
            Algorithm::Zip => "zip",
            Algorithm::ZipStore => "zip-store",
            Algorithm::ZipBzip2 => "zip-bzip2",
            Algorithm::ZipZstd => "zip-zstd",
            Algorithm::SevenZ => "7z",
            Algorithm::SevenZCopy => "7z-copy",
            Algorithm::SevenZLzma => "7z-lzma",
            Algorithm::SevenZPpmd => "7z-ppmd",
            Algorithm::TarGnu => "tar-gnu",
            Algorithm::TarUstar => "tar-ustar",
            Algorithm::TarPax => "tar-pax",
            Algorithm::Cpio => "cpio",
            Algorithm::CpioCrc => "cpio-crc",
        }
    }

    /// Parse a CLI name back into an [`Algorithm`]. Returns `None` for unknown names.
    pub fn from_name(name: &str) -> Option<Algorithm> {
        match name {
            "deflate" => Some(Algorithm::Deflate),
            "gzip" => Some(Algorithm::Gzip),
            "gzip-fast" => Some(Algorithm::GzipFast),
            "gzip-store" => Some(Algorithm::GzipStore),
            "zstd" => Some(Algorithm::Zstd),
            "zstd-fast" => Some(Algorithm::ZstdFast),
            "zstd-best" => Some(Algorithm::ZstdBest),
            "zstd-nochecksum" => Some(Algorithm::ZstdNoChecksum),
            "bzip2" => Some(Algorithm::Bzip2),
            "bzip2-fast" => Some(Algorithm::Bzip2Fast),
            "bzip2-best" => Some(Algorithm::Bzip2Best),
            "lzip" => Some(Algorithm::Lzip),
            "lzip-fast" => Some(Algorithm::LzipFast),
            "lzip-best" => Some(Algorithm::LzipBest),
            "lzma" | "lzma-alone" => Some(Algorithm::LzmaAlone),
            "xz" => Some(Algorithm::Xz),
            "xz-fast" => Some(Algorithm::XzFast),
            "xz-best" => Some(Algorithm::XzBest),
            "lzw" => Some(Algorithm::Lzw),
            "lzw-bits9" => Some(Algorithm::LzwBits9),
            "lz4" => Some(Algorithm::Lz4),
            "lz4-fast" => Some(Algorithm::Lz4Fast),
            "lz4-best" => Some(Algorithm::Lz4Best),
            "lz4-small-block" => Some(Algorithm::Lz4SmallBlock),
            "lzo" => Some(Algorithm::Lzo),
            "lzo-fast" => Some(Algorithm::LzoFast),
            "lzo-best" => Some(Algorithm::LzoBest),
            "lrzip" | "lrzip-lzma" => Some(Algorithm::LrzipLzma),
            "lrzip-bzip2" => Some(Algorithm::LrzipBzip2),
            "lrzip-gzip" => Some(Algorithm::LrzipGzip),
            "lrzip-lzo" => Some(Algorithm::LrzipLzo),
            "lrzip-none" => Some(Algorithm::LrzipNone),
            "lrzip-zpaq" => Some(Algorithm::LrzipZpaq),
            "brotli" => Some(Algorithm::Brotli),
            "brotli-fast" => Some(Algorithm::BrotliFast),
            "brotli-best" => Some(Algorithm::BrotliBest),
            "snappy" => Some(Algorithm::Snappy),
            "rzip" => Some(Algorithm::Rzip),
            "zlib" => Some(Algorithm::Zlib),
            "zpaq" => Some(Algorithm::Zpaq),
            "zpaq-level2" => Some(Algorithm::ZpaqLevel2),
            "zpaq-level3" => Some(Algorithm::ZpaqLevel3),
            "ar" | "ar-gnu" => Some(Algorithm::Ar),
            "ar-bsd" => Some(Algorithm::ArBsd),
            "zip" => Some(Algorithm::Zip),
            "zip-store" => Some(Algorithm::ZipStore),
            "zip-bzip2" => Some(Algorithm::ZipBzip2),
            "zip-zstd" => Some(Algorithm::ZipZstd),
            "7z" | "sevenz" => Some(Algorithm::SevenZ),
            "7z-copy" => Some(Algorithm::SevenZCopy),
            "7z-lzma" => Some(Algorithm::SevenZLzma),
            "7z-ppmd" => Some(Algorithm::SevenZPpmd),
            "tar" | "tar-gnu" => Some(Algorithm::TarGnu),
            "tar-ustar" => Some(Algorithm::TarUstar),
            "tar-pax" => Some(Algorithm::TarPax),
            "cpio" => Some(Algorithm::Cpio),
            "cpio-crc" => Some(Algorithm::CpioCrc),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Encode `data` using the specified algorithm, returning the compressed/archived bytes.
pub fn encode_with(algo: Algorithm, data: &[u8]) -> Vec<u8> {
    match algo {
        Algorithm::Deflate => deflate::encode::encode(data, deflate::encode::Level::Default),
        Algorithm::Gzip => gzip::encode::encode(data, deflate::encode::Level::Default),
        Algorithm::GzipFast => gzip::encode::encode(data, deflate::encode::Level::Fast),
        Algorithm::GzipStore => gzip::encode::encode(data, deflate::encode::Level::NoCompression),
        Algorithm::Zstd | Algorithm::ZstdFast | Algorithm::ZstdBest => zstd::encode::encode(data),
        Algorithm::ZstdNoChecksum => zstd::encode::encode_with_options(
            data,
            &zstd::encode::EncodeOptions { checksum: false },
        ),
        Algorithm::Bzip2 => bzip2::encode::encode(data),
        Algorithm::Bzip2Fast => bzip2::encode::encode_with_level(data, 1),
        Algorithm::Bzip2Best => bzip2::encode::encode_with_level(data, 9),
        Algorithm::Lzip | Algorithm::LzipFast | Algorithm::LzipBest => lzip::encode::encode(data),
        Algorithm::LzmaAlone => lzma_alone::encode::encode(data),
        Algorithm::Xz | Algorithm::XzFast | Algorithm::XzBest => xz::encode::encode(data),
        Algorithm::Lzw | Algorithm::LzwBits9 => lzw::encode::encode(data),
        Algorithm::Lz4 | Algorithm::Lz4Fast | Algorithm::Lz4Best => lz4::encode::encode(data),
        Algorithm::Lz4SmallBlock => {
            lz4::encode::encode_with_options(data, lz4::encode::BlockMaxSize::KB64, true)
        }
        Algorithm::Lzo | Algorithm::LzoFast | Algorithm::LzoBest => lzo::encode::encode(data),
        Algorithm::LrzipLzma => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::Lzma)
        }
        Algorithm::LrzipBzip2 => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::Bzip2)
        }
        Algorithm::LrzipGzip => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::Gzip)
        }
        Algorithm::LrzipLzo => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::Lzo)
        }
        Algorithm::LrzipNone => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::None)
        }
        Algorithm::LrzipZpaq => {
            lrzip::encode::encode_with(data, lrzip::encode::CompressionType::Zpaq)
        }
        Algorithm::Brotli | Algorithm::BrotliFast | Algorithm::BrotliBest => {
            brotli::encode::encode(data)
        }
        Algorithm::Snappy => snappy::encode::encode(data),
        Algorithm::Rzip => rzip::encode::encode(data),
        Algorithm::Zlib => zlib::encode::encode(data),
        Algorithm::Zpaq => zpaq::encode::encode(data, 1),
        Algorithm::ZpaqLevel2 => zpaq::encode::encode(data, 2),
        Algorithm::ZpaqLevel3 => zpaq::encode::encode(data, 3),
        Algorithm::Ar => {
            let mut enc = ar::encode::ArEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("ar encode should succeed")
        }
        Algorithm::ArBsd => {
            let mut enc = ar::encode::ArEncoder::new_bsd();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("ar bsd encode should succeed")
        }
        Algorithm::Zip => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("zip encode should succeed")
        }
        Algorithm::ZipStore => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file_with_options(
                "fuzz_test",
                data,
                &zip::encode::ZipEntryOptions {
                    compression: zip::encode::ZipCompression::Store,
                    ..Default::default()
                },
            );
            enc.finish().expect("zip-store encode should succeed")
        }
        Algorithm::ZipBzip2 => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file_with_options(
                "fuzz_test",
                data,
                &zip::encode::ZipEntryOptions {
                    compression: zip::encode::ZipCompression::Bzip2,
                    ..Default::default()
                },
            );
            enc.finish().expect("zip-bzip2 encode should succeed")
        }
        Algorithm::ZipZstd => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file_with_options(
                "fuzz_test",
                data,
                &zip::encode::ZipEntryOptions {
                    compression: zip::encode::ZipCompression::Zstd,
                    ..Default::default()
                },
            );
            enc.finish().expect("zip-zstd encode should succeed")
        }
        Algorithm::SevenZ => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z encode should succeed")
        }
        Algorithm::SevenZCopy => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.set_method(sevenz::encode::SevenZMethod::Copy);
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z-copy encode should succeed")
        }
        Algorithm::SevenZLzma => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.set_method(sevenz::encode::SevenZMethod::Lzma { dict_size: 1 << 23 });
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z-lzma encode should succeed")
        }
        Algorithm::SevenZPpmd => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.set_method(sevenz::encode::SevenZMethod::Ppmd {
                order: 6,
                mem_size: 1 << 20,
            });
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z-ppmd encode should succeed")
        }
        Algorithm::TarGnu => {
            let mut enc = tar::encode::TarEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::TarUstar => {
            // Pure UStar: short name keeps output within base UStar limits.
            let mut enc = tar::encode::TarEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::TarPax => {
            let mut enc = tar::encode::TarEncoder::new_pax();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::Cpio => {
            let mut enc = cpio::encode::CpioEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::CpioCrc => {
            let mut enc = cpio::encode::CpioEncoder::new_crc();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
    }
}

/// Decode `data` using the specified algorithm, returning the original bytes.
pub fn decode_with(algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    match algo {
        Algorithm::Deflate => deflate::decode::decode(data),
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => gzip::decode::decode(data),
        Algorithm::Zstd | Algorithm::ZstdFast | Algorithm::ZstdBest | Algorithm::ZstdNoChecksum => {
            zstd::decode::decode(data)
        }
        Algorithm::Bzip2 | Algorithm::Bzip2Fast | Algorithm::Bzip2Best => {
            bzip2::decode::decode(data)
        }
        Algorithm::Lzip | Algorithm::LzipFast | Algorithm::LzipBest => lzip::decode::decode(data),
        Algorithm::LzmaAlone => lzma_alone::decode::decode(data),
        Algorithm::Xz | Algorithm::XzFast | Algorithm::XzBest => xz::decode::decode(data),
        Algorithm::Lzw | Algorithm::LzwBits9 => lzw::decode::decode(data),
        Algorithm::Lz4 | Algorithm::Lz4Fast | Algorithm::Lz4Best | Algorithm::Lz4SmallBlock => {
            lz4::decode::decode(data)
        }
        Algorithm::Lzo | Algorithm::LzoFast | Algorithm::LzoBest => lzo::decode::decode(data),
        Algorithm::LrzipLzma
        | Algorithm::LrzipBzip2
        | Algorithm::LrzipGzip
        | Algorithm::LrzipLzo
        | Algorithm::LrzipNone
        | Algorithm::LrzipZpaq => lrzip::decode::decode(data),
        Algorithm::Brotli | Algorithm::BrotliFast | Algorithm::BrotliBest => {
            brotli::decode::decode(data)
        }
        Algorithm::Snappy => snappy::decode::decode(data),
        Algorithm::Rzip => rzip::decode::decode(data),
        Algorithm::Zlib => zlib::decode::decode(data),
        Algorithm::Zpaq | Algorithm::ZpaqLevel2 | Algorithm::ZpaqLevel3 => {
            zpaq::decode::decode(data)
        }
        Algorithm::Ar | Algorithm::ArBsd => {
            let entries = ar::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Zip | Algorithm::ZipStore | Algorithm::ZipBzip2 | Algorithm::ZipZstd => {
            let entries = zip::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::SevenZ
        | Algorithm::SevenZCopy
        | Algorithm::SevenZLzma
        | Algorithm::SevenZPpmd => {
            let entries = sevenz::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::TarGnu | Algorithm::TarUstar | Algorithm::TarPax => {
            let entries = tar::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Cpio | Algorithm::CpioCrc => {
            let entries = cpio::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
    }
}

pub const fn special_case_labels(algo: Algorithm) -> &'static [&'static str] {
    match algo {
        Algorithm::Ar => &["gnu-long-name"],
        Algorithm::ArBsd => &["bsd-long-name"],
        Algorithm::TarGnu => &["gnu-long-name"],
        Algorithm::TarPax => &["pax-metadata"],
        Algorithm::Cpio => &["newc-metadata"],
        Algorithm::CpioCrc => &["newcrc-metadata"],
        Algorithm::Zip => &["stored-comment", "cp437-comment", "aes256", "traditional"],
        Algorithm::SevenZ => &[
            "copy-method",
            "ppmd",
            "encrypted",
            "encoded-header",
            "encrypted-header",
        ],
        _ => &[],
    }
}

pub fn run_special_case(algo: Algorithm, label: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match (algo, label) {
        (Algorithm::Ar, "gnu-long-name") => {
            let mut encoder = ar::encode::ArEncoder::new();
            let options = ar::encode::ArEntryOptions {
                mtime: 1_700_000_000,
                uid: 1000,
                gid: 1000,
                mode: 0o100755,
            };
            encoder.add_file_with_options(
                "very_long_fuzz_entry_name_for_gnu_archive.txt",
                data,
                &options,
            );
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = ar::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].name != "very_long_fuzz_entry_name_for_gnu_archive.txt" {
                return Err("ar special case lost GNU long filename".to_string());
            }
            if entries[0].header.mode != 0o100755 {
                return Err("ar special case lost mode".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::ArBsd, "bsd-long-name") => {
            let mut encoder = ar::encode::ArEncoder::new_bsd();
            let options = ar::encode::ArEntryOptions {
                mtime: 7,
                uid: 1,
                gid: 2,
                mode: 0o100640,
            };
            encoder.add_file_with_options(
                "very_long_fuzz_entry_name_for_bsd_archive.txt",
                data,
                &options,
            );
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = ar::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].name != "very_long_fuzz_entry_name_for_bsd_archive.txt" {
                return Err("ar special case lost BSD long filename".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::TarGnu, "gnu-long-name") => {
            let mut encoder = tar::encode::TarEncoder::new();
            let options = tar::encode::TarEntryOptions {
                name: "very/long/path/for/gnu/tar/fuzz/entry/name.txt".to_string(),
                ..Default::default()
            };
            encoder.add_file_with_options(data, &options);
            let archive = encoder.finish();
            let entries = tar::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].header.name != "very/long/path/for/gnu/tar/fuzz/entry/name.txt" {
                return Err("tar GNU special case lost long path".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::TarPax, "pax-metadata") => {
            let mut encoder = tar::encode::TarEncoder::new_pax();
            let options = tar::encode::TarEntryOptions {
                name: "deep/path/for/pax/fuzz/entry.txt".to_string(),
                mode: 0o755,
                mtime: -123,
                mtime_nsec: 42,
                atime: 5,
                atime_nsec: 7,
                ctime: 9,
                ctime_nsec: 11,
                uname: "very-long-user-name-for-pax".to_string(),
                gname: "very-long-group-name-for-pax".to_string(),
                ..Default::default()
            };
            encoder.add_file_with_options(data, &options);
            let archive = encoder.finish();
            let entries = tar::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].header.name != "deep/path/for/pax/fuzz/entry.txt" {
                return Err("tar PAX special case lost path".to_string());
            }
            if entries[0].header.mode != 0o755 {
                return Err("tar PAX special case lost mode".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::Cpio, "newc-metadata") => {
            let mut encoder = cpio::encode::CpioEncoder::new();
            let options = cpio::encode::CpioEntryOptions {
                mode: 0o100755,
                uid: 100,
                gid: 200,
                nlink: 1,
                mtime: u32::MAX,
            };
            encoder.add_file_with_options("deep/newc/metadata/file.txt", data, &options);
            let archive = encoder.finish();
            let entries = cpio::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].name != "deep/newc/metadata/file.txt" {
                return Err("cpio newc special case lost path".to_string());
            }
            if entries[0].header.mode != 0o100755 {
                return Err("cpio newc special case lost mode".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::CpioCrc, "newcrc-metadata") => {
            let mut encoder = cpio::encode::CpioEncoder::new_crc();
            let options = cpio::encode::CpioEntryOptions {
                mode: 0o100640,
                uid: 1,
                gid: 2,
                nlink: 1,
                mtime: 1234567890,
            };
            encoder.add_file_with_options("deep/newcrc/metadata/file.txt", data, &options);
            let archive = encoder.finish();
            let entries = cpio::decode::decode(&archive).map_err(|e| e.to_string())?;
            if !entries[0].header.is_crc {
                return Err("cpio newcrc special case lost crc format".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::Zip, "stored-comment") => {
            let mut encoder = zip::encode::ZipEncoder::new();
            encoder.add_file_with_options(
                "fuzz_test",
                data,
                &zip::encode::ZipEntryOptions {
                    comment: "stored".to_string(),
                    compression: zip::encode::ZipCompression::Store,
                    ..Default::default()
                },
            );
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = zip::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].header.comment != "stored" {
                return Err("zip stored comment special case lost comment".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::Zip, "cp437-comment") => {
            let mut encoder = zip::encode::ZipEncoder::new();
            encoder.add_file_with_options(
                "fuzz_test",
                data,
                &zip::encode::ZipEntryOptions {
                    comment: "ö comment".to_string(),
                    utf8: false,
                    compression: zip::encode::ZipCompression::Store,
                    ..Default::default()
                },
            );
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = zip::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries[0].header.comment != "ö comment" {
                return Err("zip cp437 special case lost comment".to_string());
            }
            Ok(entries[0].data.clone())
        }
        (Algorithm::Zip, "aes256") => {
            let mut encoder = zip::encode::ZipEncoder::new();
            encoder.set_password("secret");
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries =
                zip::decode::decode_with_password(&archive, "secret").map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::Zip, "traditional") => {
            let mut encoder = zip::encode::ZipEncoder::new();
            encoder.set_traditional_password("secret");
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries =
                zip::decode::decode_with_password(&archive, "secret").map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::SevenZ, "copy-method") => {
            let mut encoder = sevenz::encode::SevenZEncoder::new();
            encoder.set_method(sevenz::encode::SevenZMethod::Copy);
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode(&archive).map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::SevenZ, "ppmd") => {
            let mut encoder = sevenz::encode::SevenZEncoder::new();
            encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
                order: 6,
                mem_size: 1 << 20,
            });
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode(&archive).map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::SevenZ, "encrypted") => {
            let mut encoder = sevenz::encode::SevenZEncoder::new();
            encoder.set_password("secret");
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode_with_password(&archive, "secret")
                .map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::SevenZ, "encoded-header") => {
            let mut encoder = sevenz::encode::SevenZEncoder::new();
            encoder.set_encoded_header(true);
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode(&archive).map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        (Algorithm::SevenZ, "encrypted-header") => {
            let mut encoder = sevenz::encode::SevenZEncoder::new();
            encoder.set_password("secret");
            encoder.set_encoded_header(true);
            encoder.add_file("fuzz_test", data);
            let archive = encoder.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode_with_password(&archive, "secret")
                .map_err(|e| e.to_string())?;
            Ok(entries[0].data.clone())
        }
        _ => Err(format!("unknown special case for {algo}: {label}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Algorithm, decode_with, encode_with, run_special_case, special_case_labels};

    #[test]
    fn roundtrips_new_archive_targets() {
        let payload = b"archive fuzz payload";
        for algo in [
            Algorithm::Ar,
            Algorithm::ArBsd,
            Algorithm::Zip,
            Algorithm::ZipStore,
            Algorithm::ZipBzip2,
            Algorithm::ZipZstd,
            Algorithm::SevenZ,
            Algorithm::SevenZCopy,
            Algorithm::SevenZLzma,
            Algorithm::SevenZPpmd,
        ] {
            let encoded = encode_with(algo, payload);
            let decoded = decode_with(algo, &encoded).unwrap();
            assert_eq!(decoded, payload, "{algo}");
        }
    }

    #[test]
    fn special_cases_roundtrip_payload() {
        let payload = b"special case payload";
        for algo in [
            Algorithm::Ar,
            Algorithm::ArBsd,
            Algorithm::TarGnu,
            Algorithm::TarPax,
            Algorithm::Cpio,
            Algorithm::CpioCrc,
            Algorithm::Zip,
            Algorithm::SevenZ,
        ] {
            for &label in special_case_labels(algo) {
                let decoded = run_special_case(algo, label, payload).unwrap();
                assert_eq!(decoded, payload, "{algo}::{label}");
            }
        }
    }
}
