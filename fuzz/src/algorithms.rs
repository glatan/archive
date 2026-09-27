//! Algorithm registry — maps algorithm names to encode/decode functions.
//!
//! Each [`Algorithm`] variant corresponds to a compression format or archive
//! format supported by the `archive` crate. The [`encode_with`] and
//! [`decode_with`] functions dispatch to the appropriate library calls.
//!
//! Archive formats (tar, cpio) are wrapped so they present the same
//! `&[u8] → Vec<u8>` interface as compression: a single file named
//! `"fuzz_test"` is packed/unpacked as the archive payload.

use archive::archive::{
    ar, arc, arj, cpio, deb, lha, mscab, mtree, rpm, sevenz, squashfs, tar, warc, zim, zip,
};
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
    Lz4Block,
    Xpress,
    XpressHuff,
    Lznt1,
    Lzf,
    Fastlz,
    Zx0,
    Lzsa,
    Lzsa2,
    Lzrw1,
    Lzrw1a,
    Lzrw2,
    Lzrw3,
    Lzrw3a,
    Lzxd,
    Cmpsc,
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
    Zip,
    ZipStore,
    ZipBzip2,
    ZipZstd,
    SevenZ,
    SevenZCopy,
    SevenZLzma,
    SevenZPpmd,
    SevenZDeflate,
    SevenZBzip2,
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
        Algorithm::Lz4Block,
        Algorithm::Xpress,
        Algorithm::XpressHuff,
        Algorithm::Lznt1,
        Algorithm::Lzf,
        Algorithm::Fastlz,
        Algorithm::Zx0,
        Algorithm::Lzsa,
        Algorithm::Lzsa2,
        Algorithm::Lzrw1,
        Algorithm::Lzrw1a,
        Algorithm::Lzrw2,
        Algorithm::Lzrw3,
        Algorithm::Lzrw3a,
        Algorithm::Lzxd,
        Algorithm::Cmpsc,
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
        Algorithm::Deb,
        Algorithm::Rpm,
        Algorithm::Squashfs,
        Algorithm::Mscab,
        Algorithm::Zim,
        Algorithm::Mtree,
        Algorithm::Warc,
        Algorithm::Zip,
        Algorithm::ZipStore,
        Algorithm::ZipBzip2,
        Algorithm::ZipZstd,
        Algorithm::SevenZ,
        Algorithm::SevenZCopy,
        Algorithm::SevenZLzma,
        Algorithm::SevenZPpmd,
        Algorithm::SevenZDeflate,
        Algorithm::SevenZBzip2,
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
            Algorithm::Lz4Block => "lz4-block",
            Algorithm::Xpress => "xpress",
            Algorithm::XpressHuff => "xpress-huff",
            Algorithm::Lznt1 => "lznt1",
            Algorithm::Lzf => "lzf",
            Algorithm::Fastlz => "fastlz",
            Algorithm::Zx0 => "zx0",
            Algorithm::Lzsa => "lzsa",
            Algorithm::Lzsa2 => "lzsa2",
            Algorithm::Lzrw1 => "lzrw1",
            Algorithm::Lzrw1a => "lzrw1a",
            Algorithm::Lzrw2 => "lzrw2",
            Algorithm::Lzrw3 => "lzrw3",
            Algorithm::Lzrw3a => "lzrw3a",
            Algorithm::Lzxd => "lzxd",
            Algorithm::Cmpsc => "cmpsc",
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
            Algorithm::Deb => "deb",
            Algorithm::Rpm => "rpm",
            Algorithm::Squashfs => "squashfs",
            Algorithm::Mscab => "mscab",
            Algorithm::Zim => "zim",
            Algorithm::Mtree => "mtree",
            Algorithm::Warc => "warc",
            Algorithm::Lha => "lha",
            Algorithm::Arj => "arj",
            Algorithm::Arc => "arc",
            Algorithm::Zip => "zip",
            Algorithm::ZipStore => "zip-store",
            Algorithm::ZipBzip2 => "zip-bzip2",
            Algorithm::ZipZstd => "zip-zstd",
            Algorithm::SevenZ => "7z",
            Algorithm::SevenZCopy => "7z-copy",
            Algorithm::SevenZLzma => "7z-lzma",
            Algorithm::SevenZPpmd => "7z-ppmd",
            Algorithm::SevenZDeflate => "7z-deflate",
            Algorithm::SevenZBzip2 => "7z-bzip2",
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
            "lz4-block" => Some(Algorithm::Lz4Block),
            "xpress" => Some(Algorithm::Xpress),
            "xpress-huff" => Some(Algorithm::XpressHuff),
            "lznt1" => Some(Algorithm::Lznt1),
            "lzf" => Some(Algorithm::Lzf),
            "fastlz" => Some(Algorithm::Fastlz),
            "zx0" => Some(Algorithm::Zx0),
            "lzsa" => Some(Algorithm::Lzsa),
            "lzsa2" => Some(Algorithm::Lzsa2),
            "lzrw1" => Some(Algorithm::Lzrw1),
            "lzrw1a" => Some(Algorithm::Lzrw1a),
            "lzrw2" => Some(Algorithm::Lzrw2),
            "lzrw3" => Some(Algorithm::Lzrw3),
            "lzrw3a" => Some(Algorithm::Lzrw3a),
            "lzxd" => Some(Algorithm::Lzxd),
            "cmpsc" => Some(Algorithm::Cmpsc),
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
            "deb" => Some(Algorithm::Deb),
            "rpm" => Some(Algorithm::Rpm),
            "squashfs" | "sqfs" => Some(Algorithm::Squashfs),
            "mscab" | "cab" => Some(Algorithm::Mscab),
            "zim" => Some(Algorithm::Zim),
            "mtree" => Some(Algorithm::Mtree),
            "warc" => Some(Algorithm::Warc),
            "lha" | "lzh" => Some(Algorithm::Lha),
            "arj" => Some(Algorithm::Arj),
            "arc" => Some(Algorithm::Arc),
            "zip" => Some(Algorithm::Zip),
            "zip-store" => Some(Algorithm::ZipStore),
            "zip-bzip2" => Some(Algorithm::ZipBzip2),
            "zip-zstd" => Some(Algorithm::ZipZstd),
            "7z" | "sevenz" => Some(Algorithm::SevenZ),
            "7z-copy" => Some(Algorithm::SevenZCopy),
            "7z-lzma" => Some(Algorithm::SevenZLzma),
            "7z-ppmd" => Some(Algorithm::SevenZPpmd),
            "7z-deflate" => Some(Algorithm::SevenZDeflate),
            "7z-bzip2" => Some(Algorithm::SevenZBzip2),
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
        Algorithm::Lz4Block => lz4::encode::encode_block(data),
        Algorithm::Xpress => xca::lz77::encode(data),
        Algorithm::XpressHuff => xca::huffman::encode(data),
        Algorithm::Lznt1 => xca::lznt1::encode(data),
        Algorithm::Lzf => lzf::encode(data),
        Algorithm::Fastlz => fastlz::encode(data),
        Algorithm::Zx0 => zx0::encode(data),
        Algorithm::Lzsa => lzsa::encode(data),
        Algorithm::Lzsa2 => lzsa::encode_lzsa2(data),
        Algorithm::Lzrw1 => lzrw1::encode(data),
        Algorithm::Lzrw1a => lzrw1a::encode(data),
        Algorithm::Lzrw2 => lzrw2::encode(data),
        Algorithm::Lzrw3 => lzrw3::encode(data),
        Algorithm::Lzrw3a => lzrw3a::encode(data),
        Algorithm::Lzxd => lzxd::encode(data),
        Algorithm::Cmpsc => cmpsc::encode(data),
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
        Algorithm::Deb => {
            let mut data_tar = tar::encode::TarEncoder::new();
            data_tar.add_file("fuzz_test", data);
            let mut control_tar = tar::encode::TarEncoder::new();
            control_tar.add_file("./control", b"Package: fuzz\n");
            let mut enc = ar::encode::ArEncoder::new();
            enc.add_file("debian-binary", b"2.0\n");
            enc.add_file("control.tar", &control_tar.finish());
            enc.add_file("data.tar", &data_tar.finish());
            enc.finish().expect("deb encode should succeed")
        }
        Algorithm::Rpm => rpm_fixture(data),
        Algorithm::Squashfs => squashfs_fixture(data),
        Algorithm::Mscab => mscab_fixture(data),
        Algorithm::Zim => zim_fixture(data),
        Algorithm::Mtree => mtree_fixture(data),
        Algorithm::Warc => warc_fixture(data),
        Algorithm::Lha => {
            let mut enc = lha::encode::LhaEncoder::new();
            enc.add_file("fuzz_test", data, 0)
                .expect("lha encode should succeed");
            enc.finish()
        }
        Algorithm::Arj => {
            let mut enc = arj::encode::ArjEncoder::new();
            enc.add_file("fuzz_test", data, 0)
                .expect("arj encode should succeed");
            enc.finish()
        }
        Algorithm::Arc => {
            let mut enc = arc::encode::ArcEncoder::new();
            enc.add_file("fuzz_test", data, 0, 0)
                .expect("arc encode should succeed");
            enc.finish()
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
        Algorithm::SevenZDeflate => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.set_method(sevenz::encode::SevenZMethod::Deflate {
                level: archive::compress::deflate::encode::Level::Default,
            });
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z-deflate encode should succeed")
        }
        Algorithm::SevenZBzip2 => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.set_method(sevenz::encode::SevenZMethod::Bzip2 { level: 9 });
            enc.add_file("fuzz_test", data);
            enc.finish().expect("7z-bzip2 encode should succeed")
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
        Algorithm::Lz4Block => lz4::decode::decode_block(data, 64 << 20),
        Algorithm::Xpress => xca::lz77::decode(data),
        Algorithm::XpressHuff => xca::huffman::decode(data),
        Algorithm::Lznt1 => xca::lznt1::decode(data),
        Algorithm::Lzf => lzf::decode(data),
        Algorithm::Fastlz => fastlz::decode(data),
        Algorithm::Zx0 => zx0::decode(data),
        Algorithm::Lzsa | Algorithm::Lzsa2 => lzsa::decode(data),
        Algorithm::Lzrw1 => lzrw1::decode(data),
        Algorithm::Lzrw1a => lzrw1a::decode(data),
        Algorithm::Lzrw2 => lzrw2::decode(data),
        Algorithm::Lzrw3 => lzrw3::decode(data),
        Algorithm::Lzrw3a => lzrw3a::decode(data),
        Algorithm::Lzxd => lzxd::decode_all(data, 1 << 25, &[], 64 << 20),
        Algorithm::Cmpsc => cmpsc::decode(data, 64 << 20),
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
        Algorithm::Deb => {
            let package = deb::decode::decode(data)?;
            let entries = package.data_entries()?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Rpm => {
            let package = rpm::decode::decode(data)?;
            let entries = package.payload_entries()?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Squashfs => {
            let image = squashfs::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == squashfs::decode::SquashfsKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Mscab => {
            let entries = mscab::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Zim => {
            let entries = zim::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Mtree => {
            let _ = mtree::decode::decode(data)?;
            Ok(Vec::new())
        }
        Algorithm::Warc => {
            let entries = warc::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Lha => {
            let entries = lha::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Arj => {
            let entries = arj::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Arc => {
            let entries = arc::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Zip | Algorithm::ZipStore | Algorithm::ZipBzip2 | Algorithm::ZipZstd => {
            let entries = zip::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::SevenZ
        | Algorithm::SevenZCopy
        | Algorithm::SevenZLzma
        | Algorithm::SevenZPpmd
        | Algorithm::SevenZDeflate
        | Algorithm::SevenZBzip2 => {
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

/// Build a minimal `.rpm` fixture: lead + signature header + package header
/// (uncompressed cpio payload) wrapping a single `fuzz_test` file.
fn rpm_fixture(data: &[u8]) -> Vec<u8> {
    fn build_header(tags: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut index = Vec::new();
        let mut store = Vec::new();
        for &(tag, ty, bytes) in tags {
            index.extend_from_slice(&tag.to_be_bytes());
            index.extend_from_slice(&ty.to_be_bytes());
            index.extend_from_slice(&(store.len() as u32).to_be_bytes());
            index.extend_from_slice(&1u32.to_be_bytes());
            store.extend_from_slice(bytes);
        }
        let mut out = vec![0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
        out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
        out.extend_from_slice(&(store.len() as u32).to_be_bytes());
        out.extend_from_slice(&index);
        out.extend_from_slice(&store);
        out
    }

    let mut rpm = vec![0u8; 96];
    rpm[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    rpm[4] = 4;
    let mut sig = build_header(&[(62, 7, &[0u8; 16])]);
    while !sig.len().is_multiple_of(8) {
        sig.push(0);
    }
    let header = build_header(&[(63, 7, &[0u8; 16]), (1125, 6, b"none\0")]);
    let mut payload = cpio::encode::CpioEncoder::new();
    payload.add_file("fuzz_test", data);
    rpm.extend_from_slice(&sig);
    rpm.extend_from_slice(&header);
    rpm.extend_from_slice(&payload.finish());
    rpm
}

/// Build a minimal `.warc` stream with one resource record whose
/// block is the fuzzed bytes.
fn warc_fixture(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"WARC/1.1\r\n");
    out.extend_from_slice(b"WARC-Type: resource\r\n");
    out.extend_from_slice(b"WARC-Record-ID: <urn:uuid:fuzz>\r\n");
    out.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
    out.extend_from_slice(b"WARC-Target-URI: fuzz_test\r\n");
    out.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", data.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n\r\n");
    out
}

/// Build a minimal mtree manifest referencing `fuzz_test`.
/// The manifest has no payload; the fuzzed bytes are folded into the
/// `size=` keyword so the decode result stays input-dependent.
fn mtree_fixture(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"#mtree\n");
    out.extend_from_slice(b"/set type=file uid=0 gid=0 mode=644\n");
    out.extend_from_slice(b"./fuzz_test size=");
    let size = data.len().min(u32::MAX as usize) as u32;
    out.extend_from_slice(size.to_string().as_bytes());
    out.extend_from_slice(b" time=0.000000000\n");
    out
}

/// Build a minimal `.zim` archive with one stored cluster holding a
/// single `C/fuzz_test` entry.
fn zim_fixture(data: &[u8]) -> Vec<u8> {
    let mime = b"text/plain\0\0";
    // content dirent: mimetype 0, param 0, ns 'C', rev 0, cluster 0, blob 0
    let mut dirent = Vec::new();
    dirent.extend_from_slice(&0u16.to_le_bytes());
    dirent.push(0);
    dirent.push(b'C');
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(&0u32.to_le_bytes());
    dirent.extend_from_slice(b"fuzz_test");
    dirent.push(0);
    dirent.push(0);

    let dirent_pos = 80 + mime.len();
    let path_ptr_pos = dirent_pos + dirent.len();
    let title_ptr_pos = path_ptr_pos + 8;
    let cluster_ptr_pos = title_ptr_pos + 4;
    let cluster_pos = cluster_ptr_pos + 8;

    // stored cluster: info=1, offsets [8, 8+len], blob data
    let mut cluster = Vec::new();
    cluster.push(1u8);
    cluster.extend_from_slice(&8u32.to_le_bytes());
    cluster.extend_from_slice(&((8 + data.len()) as u32).to_le_bytes());
    cluster.extend_from_slice(data);
    let checksum_pos = (cluster_pos + cluster.len()) as u64;

    let mut out = Vec::new();
    out.extend_from_slice(&0x044D_495Au32.to_le_bytes());
    out.extend_from_slice(&5u16.to_le_bytes()); // major 5
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&1u32.to_le_bytes()); // entryCount
    out.extend_from_slice(&1u32.to_le_bytes()); // clusterCount
    out.extend_from_slice(&(path_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&(title_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&(cluster_ptr_pos as u64).to_le_bytes());
    out.extend_from_slice(&80u64.to_le_bytes()); // mimeListPos
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    out.extend_from_slice(&checksum_pos.to_le_bytes());
    out.extend_from_slice(mime);
    out.extend_from_slice(&dirent);
    out.extend_from_slice(&(dirent_pos as u64).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(cluster_pos as u64).to_le_bytes());
    out.extend_from_slice(&cluster);
    out
}

/// Build a minimal stored (uncompressed) `.cab` archive containing a
/// single `fuzz_test` file.
fn mscab_fixture(data: &[u8]) -> Vec<u8> {
    let mut files_buf = Vec::new();
    files_buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // cbFile
    files_buf.extend_from_slice(&0u32.to_le_bytes()); // uoffFolderStart
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // iFolder
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // date
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // time
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // attribs
    files_buf.extend_from_slice(b"fuzz_test");
    files_buf.push(0);

    let folders_off = 36usize;
    let files_off = folders_off + 8;
    let data_off = files_off + files_buf.len();
    let cb_cabinet = (data_off + 8 + data.len()) as u32;

    let mut out = Vec::with_capacity(cb_cabinet as usize);
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&cb_cabinet.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(files_off as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3u8, 1u8]); // version 1.3
    out.extend_from_slice(&1u16.to_le_bytes()); // cFolders
    out.extend_from_slice(&1u16.to_le_bytes()); // cFiles
    out.extend_from_slice(&0u16.to_le_bytes()); // flags
    out.extend_from_slice(&0u16.to_le_bytes()); // setID
    out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
    out.extend_from_slice(&(data_off as u32).to_le_bytes()); // coffCabStart
    out.extend_from_slice(&1u16.to_le_bytes()); // cCFDATA
    out.extend_from_slice(&0u16.to_le_bytes()); // tcompTYPE_NONE
    out.extend_from_slice(&files_buf);
    out.extend_from_slice(&0u32.to_le_bytes()); // csum
    out.extend_from_slice(&(data.len() as u16).to_le_bytes()); // cbData
    out.extend_from_slice(&(data.len() as u16).to_le_bytes()); // cbUncomp
    out.extend_from_slice(data);
    out
}

/// Build a minimal uncompressed `.squashfs` image containing a single
/// `fuzz_test` file in the root directory.
fn squashfs_fixture(data: &[u8]) -> Vec<u8> {
    let block_size = 4096usize;
    let mut out = vec![0u8; 96];

    // data blocks, stored uncompressed (bit 24 of each size field set)
    let data_start = out.len();
    let mut sizes = Vec::new();
    for chunk in data.chunks(block_size) {
        sizes.push(chunk.len() as u32 | (1 << 24));
        out.extend_from_slice(chunk);
    }

    // inode table: one uncompressed metadata block holding the root dir
    // inode followed by the file inode
    let inode_table_start = out.len();
    let mut inode_stream = Vec::new();
    // basic dir inode (type 1), inode number 1
    inode_stream.extend_from_slice(&1u16.to_le_bytes());
    inode_stream.extend_from_slice(&0o755u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u32.to_le_bytes());
    inode_stream.extend_from_slice(&1u32.to_le_bytes());
    inode_stream.extend_from_slice(&0u32.to_le_bytes()); // dir block_index
    inode_stream.extend_from_slice(&3u32.to_le_bytes()); // link_count
    inode_stream.extend_from_slice(&32u16.to_le_bytes()); // listing size + 3
    inode_stream.extend_from_slice(&0u16.to_le_bytes()); // block_offset
    inode_stream.extend_from_slice(&0u32.to_le_bytes()); // parent
    // basic file inode (type 2), inode number 2, at stream offset 32
    inode_stream.extend_from_slice(&2u16.to_le_bytes());
    inode_stream.extend_from_slice(&0o644u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u16.to_le_bytes());
    inode_stream.extend_from_slice(&0u32.to_le_bytes());
    inode_stream.extend_from_slice(&2u32.to_le_bytes());
    inode_stream.extend_from_slice(&(data_start as u32).to_le_bytes());
    inode_stream.extend_from_slice(&u32::MAX.to_le_bytes()); // no fragment
    inode_stream.extend_from_slice(&0u32.to_le_bytes());
    inode_stream.extend_from_slice(&(data.len() as u32).to_le_bytes());
    for s in &sizes {
        inode_stream.extend_from_slice(&s.to_le_bytes());
    }
    out.extend_from_slice(&((inode_stream.len() as u16 | 0x8000).to_le_bytes()));
    out.extend_from_slice(&inode_stream);

    // directory table: one uncompressed metadata block, one header + entry
    let dir_table_start = out.len();
    let mut dir_stream = Vec::new();
    dir_stream.extend_from_slice(&0u32.to_le_bytes()); // count-1: 1 entry
    dir_stream.extend_from_slice(&0u32.to_le_bytes()); // inode meta block rel
    dir_stream.extend_from_slice(&2u32.to_le_bytes()); // base inode number
    dir_stream.extend_from_slice(&32u16.to_le_bytes()); // inode block offset
    dir_stream.extend_from_slice(&0i16.to_le_bytes()); // inode diff
    dir_stream.extend_from_slice(&2u16.to_le_bytes()); // type: basic file
    dir_stream.extend_from_slice(&8u16.to_le_bytes()); // name_size-1
    dir_stream.extend_from_slice(b"fuzz_test");
    out.extend_from_slice(&((dir_stream.len() as u16 | 0x8000).to_le_bytes()));
    out.extend_from_slice(&dir_stream);

    // ID table: uncompressed location list + one-entry metadata block
    let id_table_start = out.len();
    let id_meta_pos = id_table_start + 8;
    out.extend_from_slice(&(id_meta_pos as u64).to_le_bytes());
    out.extend_from_slice(&((4u16 | 0x8000).to_le_bytes()));
    out.extend_from_slice(&0u32.to_le_bytes());

    let bytes_used = out.len() as u64;
    out[0..4].copy_from_slice(&0x7371_7368u32.to_le_bytes());
    out[4..8].copy_from_slice(&2u32.to_le_bytes()); // inode_count
    out[12..16].copy_from_slice(&(block_size as u32).to_le_bytes());
    out[20..22].copy_from_slice(&1u16.to_le_bytes()); // compressor: gzip
    out[22..24].copy_from_slice(&12u16.to_le_bytes()); // block_log
    out[26..28].copy_from_slice(&1u16.to_le_bytes()); // id_count
    out[28..30].copy_from_slice(&4u16.to_le_bytes()); // version 4.0
    out[32..40].copy_from_slice(&0u64.to_le_bytes()); // root inode ref
    out[40..48].copy_from_slice(&bytes_used.to_le_bytes());
    out[48..56].copy_from_slice(&(id_table_start as u64).to_le_bytes());
    out[56..64].copy_from_slice(&u64::MAX.to_le_bytes()); // xattr absent
    out[64..72].copy_from_slice(&(inode_table_start as u64).to_le_bytes());
    out[72..80].copy_from_slice(&(dir_table_start as u64).to_le_bytes());
    out[80..88].copy_from_slice(&u64::MAX.to_le_bytes()); // fragment absent
    out[88..96].copy_from_slice(&u64::MAX.to_le_bytes()); // export absent
    out
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
