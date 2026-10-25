//! Algorithm registry — maps algorithm names to encode/decode functions.
//!
//! Each [`Algorithm`] variant corresponds to a compression format or archive
//! format supported by the `archive` crate. The [`encode_with`],
//! [`decode_with`], and [`decode_bounded_with`] functions dispatch to the
//! appropriate library calls.
//!
//! Archive formats (tar, cpio) are wrapped so they present the same
//! `&[u8] → Vec<u8>` interface as compression: a single file named
//! `"fuzz_test"` is packed/unpacked as the archive payload.

use archive::archive::{
    ar, arc, arj, cpio, cramfs, crx3, deb, erofs, git_pack, iso9660, lha, mscab, mscfb, mtree, pea,
    romfs, rpm, sevenz, squashfs, tar, warc, xar, zim, zip, zpaq as zpaq_archive,
};
use archive::compress::*;
use archive::encoding::{ascii85, binhex, uuencode, yenc};
use archive::error::Error;
use std::fmt;
use std::sync::OnceLock;

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
    ZstdSeekable,
    ZstdDict,
    Bzip2,
    Bzip2Fast,
    Bzip2Best,
    Lzip,
    LzipFast,
    LzipBest,
    LzipDict,
    LzmaAlone,
    Xz,
    XzFast,
    XzBest,
    XzDelta,
    XzX86,
    XzPpc,
    XzIa64,
    XzSparc,
    XzArm,
    XzArmThumb,
    XzArm64,
    XzRiscV,
    Lzw,
    LzwBits9,
    Lz4,
    Lz4Fast,
    Lz4Best,
    Lz4SmallBlock,
    Lz4Block,
    Lz4Dict,
    Lz4Legacy,
    Lz4BlockDependent,
    Xpress,
    XpressHuff,
    Lznt1,
    Lzf,
    Fastlz,
    PackBits,
    Zx0,
    Zx1,
    Zx2,
    Zx5,
    Vcdiff,
    VcdiffSrc,
    Mppc,
    MppcRdp4,
    MppcRdp5,
    Lzs,
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
    BrotliMeta,
    Snappy,
    Rzip,
    Zlib,
    Zpaq,
    ZpaqLevel2,
    ZpaqLevel3,
    ZpaqArchive,
    Ar,
    ArBsd,
    Deb,
    Rpm,
    Squashfs,
    Mscab,
    Zim,
    Mtree,
    Warc,
    GitPack,
    GitPackDelta,
    GitPackSha256,
    Xar,
    Lha,
    LhaLh4,
    LhaLh5,
    LhaLh6,
    LhaLh7,
    LhaLzs,
    LhaLz5,
    LhaPm1,
    LhaPm2,
    Arj,
    Arj1,
    Arj2,
    Arj3,
    Arj4,
    ArjGarbled,
    Arc,
    Zip,
    ZipStore,
    ZipBzip2,
    ZipZstd,
    ZipDeflate64,
    ZipLzma,
    ZipXz,
    ZipPpmd,
    ZipShrunk,
    ZipImplode,
    ZipReduce,
    SevenZ,
    SevenZCopy,
    SevenZLzma,
    SevenZPpmd,
    SevenZDeflate,
    SevenZBzip2,
    SevenZDeflate64,
    SevenZBrotli,
    SevenZX86,
    SevenZBcj2,
    SevenZDelta,
    TarGnu,
    TarUstar,
    TarPax,
    Cpio,
    CpioCrc,
    CpioOdc,
    CpioBin,
    Cramfs,
    Romfs,
    Erofs,
    Iso9660,
    IsoRr,
    Mscfb,
    MscfbV4,
    Pea,
    PeaStore,
    PeaSha256,
    Crx3,
    Ascii85,
    Yenc,
    Uuencode,
    BinHex,
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
        Algorithm::ZstdSeekable,
        Algorithm::ZstdDict,
        Algorithm::Bzip2,
        Algorithm::Bzip2Fast,
        Algorithm::Bzip2Best,
        Algorithm::Lzip,
        Algorithm::LzipFast,
        Algorithm::LzipBest,
        Algorithm::LzipDict,
        Algorithm::LzmaAlone,
        Algorithm::Xz,
        Algorithm::XzFast,
        Algorithm::XzBest,
        Algorithm::XzDelta,
        Algorithm::XzX86,
        Algorithm::XzPpc,
        Algorithm::XzIa64,
        Algorithm::XzSparc,
        Algorithm::XzArm,
        Algorithm::XzArmThumb,
        Algorithm::XzArm64,
        Algorithm::XzRiscV,
        Algorithm::Lzw,
        Algorithm::LzwBits9,
        Algorithm::Lz4,
        Algorithm::Lz4Fast,
        Algorithm::Lz4Best,
        Algorithm::Lz4SmallBlock,
        Algorithm::Lz4Block,
        Algorithm::Lz4Dict,
        Algorithm::Lz4Legacy,
        Algorithm::Lz4BlockDependent,
        Algorithm::Xpress,
        Algorithm::XpressHuff,
        Algorithm::Lznt1,
        Algorithm::Lzf,
        Algorithm::Fastlz,
        Algorithm::PackBits,
        Algorithm::Zx0,
        Algorithm::Zx1,
        Algorithm::Zx2,
        Algorithm::Zx5,
        Algorithm::Vcdiff,
        Algorithm::VcdiffSrc,
        Algorithm::Mppc,
        Algorithm::MppcRdp4,
        Algorithm::MppcRdp5,
        Algorithm::Lzs,
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
        Algorithm::BrotliMeta,
        Algorithm::Snappy,
        Algorithm::Rzip,
        Algorithm::Zlib,
        Algorithm::Zpaq,
        Algorithm::ZpaqLevel2,
        Algorithm::ZpaqLevel3,
        Algorithm::ZpaqArchive,
        Algorithm::Ar,
        Algorithm::ArBsd,
        Algorithm::Deb,
        Algorithm::Rpm,
        Algorithm::Squashfs,
        Algorithm::Mscab,
        Algorithm::Zim,
        Algorithm::Mtree,
        Algorithm::Warc,
        Algorithm::GitPack,
        Algorithm::GitPackDelta,
        Algorithm::GitPackSha256,
        Algorithm::Xar,
        Algorithm::Lha,
        Algorithm::LhaLh4,
        Algorithm::LhaLh5,
        Algorithm::LhaLh6,
        Algorithm::LhaLh7,
        Algorithm::LhaLzs,
        Algorithm::LhaLz5,
        Algorithm::LhaPm1,
        Algorithm::LhaPm2,
        Algorithm::Arj,
        Algorithm::Arj1,
        Algorithm::Arj2,
        Algorithm::Arj3,
        Algorithm::Arj4,
        Algorithm::ArjGarbled,
        Algorithm::Arc,
        Algorithm::Zip,
        Algorithm::ZipStore,
        Algorithm::ZipBzip2,
        Algorithm::ZipZstd,
        Algorithm::ZipDeflate64,
        Algorithm::ZipLzma,
        Algorithm::ZipXz,
        Algorithm::ZipPpmd,
        Algorithm::ZipShrunk,
        Algorithm::ZipImplode,
        Algorithm::ZipReduce,
        Algorithm::SevenZ,
        Algorithm::SevenZCopy,
        Algorithm::SevenZLzma,
        Algorithm::SevenZPpmd,
        Algorithm::SevenZDeflate,
        Algorithm::SevenZBzip2,
        Algorithm::SevenZDeflate64,
        Algorithm::SevenZBrotli,
        Algorithm::SevenZX86,
        Algorithm::SevenZBcj2,
        Algorithm::SevenZDelta,
        Algorithm::TarGnu,
        Algorithm::TarUstar,
        Algorithm::TarPax,
        Algorithm::Cpio,
        Algorithm::CpioCrc,
        Algorithm::CpioOdc,
        Algorithm::CpioBin,
        Algorithm::Cramfs,
        Algorithm::Romfs,
        Algorithm::Erofs,
        Algorithm::Iso9660,
        Algorithm::IsoRr,
        Algorithm::Mscfb,
        Algorithm::MscfbV4,
        Algorithm::Pea,
        Algorithm::PeaStore,
        Algorithm::PeaSha256,
        Algorithm::Crx3,
        Algorithm::Ascii85,
        Algorithm::Yenc,
        Algorithm::Uuencode,
        Algorithm::BinHex,
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
            Algorithm::ZstdSeekable => "zstd-seekable",
            Algorithm::ZstdDict => "zstd-dict",
            Algorithm::Bzip2 => "bzip2",
            Algorithm::Bzip2Fast => "bzip2-fast",
            Algorithm::Bzip2Best => "bzip2-best",
            Algorithm::Lzip => "lzip",
            Algorithm::LzipFast => "lzip-fast",
            Algorithm::LzipBest => "lzip-best",
            Algorithm::LzipDict => "lzip-dict",
            Algorithm::LzmaAlone => "lzma",
            Algorithm::Xz => "xz",
            Algorithm::XzFast => "xz-fast",
            Algorithm::XzBest => "xz-best",
            Algorithm::XzDelta => "xz-delta",
            Algorithm::XzX86 => "xz-x86",
            Algorithm::XzPpc => "xz-powerpc",
            Algorithm::XzIa64 => "xz-ia64",
            Algorithm::XzSparc => "xz-sparc",
            Algorithm::XzArm => "xz-arm",
            Algorithm::XzArmThumb => "xz-armthumb",
            Algorithm::XzArm64 => "xz-arm64",
            Algorithm::XzRiscV => "xz-riscv",
            Algorithm::Lzw => "lzw",
            Algorithm::LzwBits9 => "lzw-bits9",
            Algorithm::Lz4 => "lz4",
            Algorithm::Lz4Fast => "lz4-fast",
            Algorithm::Lz4Best => "lz4-best",
            Algorithm::Lz4SmallBlock => "lz4-small-block",
            Algorithm::Lz4Block => "lz4-block",
            Algorithm::Lz4Dict => "lz4-dict",
            Algorithm::Lz4Legacy => "lz4-legacy",
            Algorithm::Lz4BlockDependent => "lz4-block-dependent",
            Algorithm::Xpress => "xpress",
            Algorithm::XpressHuff => "xpress-huff",
            Algorithm::Lznt1 => "lznt1",
            Algorithm::Lzf => "lzf",
            Algorithm::Fastlz => "fastlz",
            Algorithm::PackBits => "packbits",
            Algorithm::Zx0 => "zx0",
            Algorithm::Zx1 => "zx1",
            Algorithm::Zx2 => "zx2",
            Algorithm::Zx5 => "zx5",
            Algorithm::Vcdiff => "vcdiff",
            Algorithm::VcdiffSrc => "vcdiff-source",
            Algorithm::Mppc => "mppc",
            Algorithm::MppcRdp4 => "mppc-rdp4",
            Algorithm::MppcRdp5 => "mppc-rdp5",
            Algorithm::Lzs => "lzs",
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
            Algorithm::BrotliMeta => "brotli-metadata",
            Algorithm::Snappy => "snappy",
            Algorithm::Rzip => "rzip",
            Algorithm::Zlib => "zlib",
            Algorithm::Zpaq => "zpaq",
            Algorithm::ZpaqLevel2 => "zpaq-level2",
            Algorithm::ZpaqLevel3 => "zpaq-level3",
            Algorithm::ZpaqArchive => "zpaq-archive",
            Algorithm::Ar => "ar",
            Algorithm::ArBsd => "ar-bsd",
            Algorithm::Deb => "deb",
            Algorithm::Rpm => "rpm",
            Algorithm::Squashfs => "squashfs",
            Algorithm::Mscab => "mscab",
            Algorithm::Zim => "zim",
            Algorithm::Mtree => "mtree",
            Algorithm::Warc => "warc",
            Algorithm::GitPack => "git-pack",
            Algorithm::GitPackDelta => "git-pack-delta",
            Algorithm::GitPackSha256 => "git-pack-sha256",
            Algorithm::Xar => "xar",
            Algorithm::Lha => "lha",
            Algorithm::LhaLh4 => "lha-lh4",
            Algorithm::LhaLh5 => "lha-lh5",
            Algorithm::LhaLh6 => "lha-lh6",
            Algorithm::LhaLh7 => "lha-lh7",
            Algorithm::LhaLzs => "lha-lzs",
            Algorithm::LhaLz5 => "lha-lz5",
            Algorithm::LhaPm1 => "lha-pm1",
            Algorithm::LhaPm2 => "lha-pm2",
            Algorithm::Arj => "arj",
            Algorithm::Arj1 => "arj-1",
            Algorithm::Arj2 => "arj-2",
            Algorithm::Arj3 => "arj-3",
            Algorithm::Arj4 => "arj-4",
            Algorithm::ArjGarbled => "arj-garbled",
            Algorithm::Arc => "arc",
            Algorithm::Zip => "zip",
            Algorithm::ZipStore => "zip-store",
            Algorithm::ZipBzip2 => "zip-bzip2",
            Algorithm::ZipZstd => "zip-zstd",
            Algorithm::ZipDeflate64 => "zip-deflate64",
            Algorithm::ZipLzma => "zip-lzma",
            Algorithm::ZipXz => "zip-xz",
            Algorithm::ZipPpmd => "zip-ppmd",
            Algorithm::ZipShrunk => "zip-shrunk",
            Algorithm::ZipImplode => "zip-implode",
            Algorithm::ZipReduce => "zip-reduce",
            Algorithm::SevenZ => "7z",
            Algorithm::SevenZCopy => "7z-copy",
            Algorithm::SevenZLzma => "7z-lzma",
            Algorithm::SevenZPpmd => "7z-ppmd",
            Algorithm::SevenZDeflate => "7z-deflate",
            Algorithm::SevenZBzip2 => "7z-bzip2",
            Algorithm::SevenZDeflate64 => "7z-deflate64",
            Algorithm::SevenZBrotli => "7z-brotli",
            Algorithm::SevenZX86 => "7z-x86",
            Algorithm::SevenZBcj2 => "7z-bcj2",
            Algorithm::SevenZDelta => "7z-delta",
            Algorithm::TarGnu => "tar-gnu",
            Algorithm::TarUstar => "tar-ustar",
            Algorithm::TarPax => "tar-pax",
            Algorithm::Cpio => "cpio",
            Algorithm::CpioCrc => "cpio-crc",
            Algorithm::CpioOdc => "cpio-odc",
            Algorithm::CpioBin => "cpio-bin",
            Algorithm::Cramfs => "cramfs",
            Algorithm::Romfs => "romfs",
            Algorithm::Erofs => "erofs",
            Algorithm::Iso9660 => "iso9660",
            Algorithm::IsoRr => "iso9660-rr",
            Algorithm::Mscfb => "mscfb",
            Algorithm::MscfbV4 => "mscfb-v4",
            Algorithm::Pea => "pea",
            Algorithm::PeaStore => "pea-store",
            Algorithm::PeaSha256 => "pea-sha256",
            Algorithm::Crx3 => "crx3",
            Algorithm::Ascii85 => "ascii85",
            Algorithm::Yenc => "yenc",
            Algorithm::Uuencode => "uuencode",
            Algorithm::BinHex => "binhex",
        }
    }

    /// Parse a CLI name back into an [`Algorithm`]. Returns `None` for unknown names.
    pub fn from_name(name: &str) -> Option<Algorithm> {
        Algorithm::ALL
            .iter()
            .find(|algo| algo.name() == name)
            .copied()
            .or(match name {
                "lzma" | "lzma-alone" => Some(Algorithm::LzmaAlone),
                "lrzip" => Some(Algorithm::LrzipLzma),
                "ar-gnu" => Some(Algorithm::Ar),
                "sqfs" => Some(Algorithm::Squashfs),
                "cab" => Some(Algorithm::Mscab),
                "pack" => Some(Algorithm::GitPack),
                "lzh" => Some(Algorithm::Lha),
                "sevenz" => Some(Algorithm::SevenZ),
                "tar" => Some(Algorithm::TarGnu),
                _ => None,
            })
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
        // Small frames so multi-frame streams are exercised on modest inputs.
        Algorithm::ZstdSeekable => zstd::seekable::encode(data, 64 * 1024),
        Algorithm::ZstdDict => zstd::encode::encode_with_dict(data, zstd_dict()),
        Algorithm::Bzip2 => bzip2::encode::encode(data),
        Algorithm::Bzip2Fast => bzip2::encode::encode_with_level(data, 1),
        Algorithm::Bzip2Best => bzip2::encode::encode_with_level(data, 9),
        Algorithm::Lzip | Algorithm::LzipFast | Algorithm::LzipBest => lzip::encode::encode(data),
        // Non-default dictionary size (64 KiB) exercises the member header's
        // dictionary-size field on both sides.
        Algorithm::LzipDict => lzip::encode::encode_with_dict_size(data, 0x10, 65536)
            .expect("lzip dict encode should succeed"),
        Algorithm::LzmaAlone => lzma_alone::encode::encode(data),
        Algorithm::Xz | Algorithm::XzFast | Algorithm::XzBest => xz::encode::encode(data),
        Algorithm::XzDelta => xz_filter(data, xz::filters::Filter::Delta { distance: 4 }),
        Algorithm::XzX86 => xz_filter(data, xz::filters::Filter::X86 { start_offset: 0 }),
        Algorithm::XzPpc => xz_filter(data, xz::filters::Filter::PowerPc { start_offset: 0 }),
        Algorithm::XzIa64 => xz_filter(data, xz::filters::Filter::Ia64 { start_offset: 0 }),
        Algorithm::XzSparc => xz_filter(data, xz::filters::Filter::Sparc { start_offset: 0 }),
        Algorithm::XzArm => xz_filter(data, xz::filters::Filter::Arm { start_offset: 0 }),
        Algorithm::XzArmThumb => xz_filter(data, xz::filters::Filter::ArmThumb { start_offset: 0 }),
        Algorithm::XzArm64 => xz_filter(data, xz::filters::Filter::Arm64 { start_offset: 0 }),
        Algorithm::XzRiscV => xz_filter(data, xz::filters::Filter::RiscV { start_offset: 0 }),
        Algorithm::Lzw => lzw::encode::encode(data),
        Algorithm::LzwBits9 => lzw::encode::encode_with_options(data, 9),
        Algorithm::Lz4 | Algorithm::Lz4Fast | Algorithm::Lz4Best => lz4::encode::encode(data),
        Algorithm::Lz4SmallBlock => {
            lz4::encode::encode_with_options(data, lz4::encode::BlockMaxSize::KB64, true)
        }
        Algorithm::Lz4Block => lz4::encode::encode_block(data),
        Algorithm::Lz4Dict => lz4::encode::encode_with_dict(data, lz4_dict()),
        Algorithm::Lz4Legacy => lz4::encode::encode_legacy(data),
        Algorithm::Lz4BlockDependent => lz4::encode::encode_block_dependent(data),
        Algorithm::Xpress => xca::lz77::encode(data),
        Algorithm::XpressHuff => xca::huffman::encode(data),
        Algorithm::Lznt1 => xca::lznt1::encode(data),
        Algorithm::Lzf => lzf::encode(data),
        Algorithm::Fastlz => fastlz::encode(data),
        Algorithm::PackBits => packbits::encode(data),
        Algorithm::Zx0 => zx0::encode(data),
        Algorithm::Zx1 => zx1::encode(data),
        Algorithm::Zx2 => zx2::encode(data),
        Algorithm::Zx5 => zx5::encode(data),
        Algorithm::Vcdiff => vcdiff::encode(data),
        Algorithm::VcdiffSrc => vcdiff::encode_with_source(delta_source(), data),
        Algorithm::Mppc => mppc::encode(data).expect("mppc encode should succeed"),
        // RDP packets travel as (flags, payload); the flags byte selects the
        // dictionary variant on decode. Framed as [flags][payload] so the
        // self/corrupt patterns can replay it.
        Algorithm::MppcRdp4 => mppc_rdp_framed(mppc::CompressionType::Rdp4, data),
        Algorithm::MppcRdp5 => mppc_rdp_framed(mppc::CompressionType::Rdp5, data),
        Algorithm::Lzs => lzs::encode(data).expect("lzs encode should succeed"),
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
        Algorithm::BrotliMeta => brotli::encode::encode_with_metadata(data, b"fuzz-metadata"),
        Algorithm::Snappy => snappy::encode::encode(data),
        Algorithm::Rzip => rzip::encode::encode(data),
        Algorithm::Zlib => zlib::encode::encode(data),
        Algorithm::Zpaq => zpaq::encode::encode(data, 1),
        Algorithm::ZpaqLevel2 => zpaq::encode::encode(data, 2),
        Algorithm::ZpaqLevel3 => zpaq::encode::encode(data, 3),
        Algorithm::ZpaqArchive => {
            let mut enc = zpaq_archive::encode::ZpaqEncoder::new(1);
            enc.add_file("fuzz_test", data);
            enc.finish().expect("zpaq archive encode should succeed")
        }
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
        Algorithm::GitPack => {
            let mut enc = git_pack::encode::GitPackEncoder::new();
            enc.add_object(git_pack::ObjectType::Blob, data);
            enc.finish()
        }
        Algorithm::GitPackDelta => {
            let mut enc = git_pack::encode::GitPackEncoder::new();
            let base = enc.add_object(git_pack::ObjectType::Blob, b"fuzz-base-blob");
            enc.add_delta_object(data, base)
                .expect("git-pack delta encode should succeed");
            enc.finish()
        }
        Algorithm::GitPackSha256 => {
            let mut enc = git_pack::encode::GitPackEncoder::new_sha256();
            enc.add_object(git_pack::ObjectType::Blob, data);
            enc.finish()
        }
        Algorithm::Xar => {
            let mut enc = xar::encode::XarEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::Warc => warc_fixture(data),
        Algorithm::Lha => {
            let mut enc = lha::encode::LhaEncoder::new();
            enc.add_file("fuzz_test", data, 0)
                .expect("lha encode should succeed");
            enc.finish()
        }
        Algorithm::LhaLh4 => lha_with_method(b"-lh4-", data),
        Algorithm::LhaLh5 => lha_with_method(b"-lh5-", data),
        Algorithm::LhaLh6 => lha_with_method(b"-lh6-", data),
        Algorithm::LhaLh7 => lha_with_method(b"-lh7-", data),
        Algorithm::LhaLzs => lha_with_method(b"-lzs-", data),
        Algorithm::LhaLz5 => lha_with_method(b"-lz5-", data),
        Algorithm::LhaPm1 => lha_with_method(b"-pm1-", data),
        Algorithm::LhaPm2 => lha_with_method(b"-pm2-", data),
        Algorithm::Arj => {
            let mut enc = arj::encode::ArjEncoder::new();
            enc.add_file("fuzz_test", data, 0)
                .expect("arj encode should succeed");
            enc.finish()
        }
        Algorithm::Arj1 => arj_with_method(1, data),
        Algorithm::Arj2 => arj_with_method(2, data),
        Algorithm::Arj3 => arj_with_method(3, data),
        Algorithm::Arj4 => arj_with_method(4, data),
        Algorithm::ArjGarbled => {
            let mut enc = arj::encode::ArjEncoder::with_method(1)
                .and_then(|e| e.with_password(b"secret", 0x5A))
                .expect("arj garbled encoder should be accepted");
            enc.add_file("fuzz_test", data, 0)
                .expect("arj garbled encode should succeed");
            enc.finish()
        }
        Algorithm::Arc => {
            let mut enc = arc::encode::ArcEncoder::new();
            // Rotate through the supported member methods so the
            // packed/squeezed/crunched/squashed codecs also roundtrip.
            const METHODS: [u8; 6] = [1, 2, 3, 4, 8, 9];
            let method = METHODS[data.len() % METHODS.len()];
            enc.add_file_with_method("fuzz_test", data, 0, 0, method)
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
        Algorithm::ZipDeflate64 => {
            zip_with_compression(data, zip::encode::ZipCompression::Deflate64)
        }
        Algorithm::ZipLzma => zip_with_compression(data, zip::encode::ZipCompression::Lzma),
        Algorithm::ZipXz => zip_with_compression(data, zip::encode::ZipCompression::Xz),
        Algorithm::ZipPpmd => zip_with_compression(data, zip::encode::ZipCompression::Ppmd),
        Algorithm::ZipShrunk => zip_with_compression(data, zip::encode::ZipCompression::Shrunk),
        Algorithm::ZipImplode => zip_with_compression(data, zip::encode::ZipCompression::Implode),
        Algorithm::ZipReduce => zip_with_compression(data, zip::encode::ZipCompression::Reduce(3)),
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
        Algorithm::SevenZDeflate64 => {
            sevenz_with(data, sevenz::encode::SevenZMethod::Deflate64, &[])
        }
        Algorithm::SevenZBrotli => sevenz_with(data, sevenz::encode::SevenZMethod::Brotli, &[]),
        Algorithm::SevenZX86 => sevenz_with(
            data,
            sevenz::encode::SevenZMethod::Lzma2 { dict_size: 1 << 23 },
            &[sevenz::encode::SevenZFilter::X86Bcj],
        ),
        Algorithm::SevenZBcj2 => sevenz_with(
            data,
            sevenz::encode::SevenZMethod::Lzma2 { dict_size: 1 << 23 },
            &[sevenz::encode::SevenZFilter::X86Bcj2],
        ),
        Algorithm::SevenZDelta => sevenz_with(
            data,
            sevenz::encode::SevenZMethod::Lzma2 { dict_size: 1 << 23 },
            &[sevenz::encode::SevenZFilter::Delta { distance: 4 }],
        ),
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
        Algorithm::CpioOdc => {
            let mut enc = cpio::encode::CpioEncoder::new_odc();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::CpioBin => {
            let mut enc = cpio::encode::CpioEncoder::new_bin();
            enc.add_file("fuzz_test", data);
            enc.finish()
        }
        Algorithm::Cramfs => {
            let mut enc = cramfs::encode::CramfsEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("cramfs encode should succeed")
        }
        Algorithm::Romfs => {
            let mut enc = romfs::encode::RomfsEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("romfs encode should succeed")
        }
        Algorithm::Erofs => {
            let mut enc = erofs::encode::ErofsEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("erofs encode should succeed")
        }
        Algorithm::Iso9660 => {
            let mut enc = iso9660::encode::IsoEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("iso9660 encode should succeed")
        }
        Algorithm::IsoRr => {
            let mut enc = iso9660::encode::IsoEncoder::new().with_rock_ridge();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("iso9660-rr encode should succeed")
        }
        Algorithm::Mscfb => {
            let mut enc = mscfb::encode::CfbEncoder::new();
            enc.add_stream("fuzz_test", data);
            enc.finish().expect("mscfb encode should succeed")
        }
        Algorithm::MscfbV4 => {
            let mut enc = mscfb::encode::CfbEncoder::version4();
            enc.add_stream("fuzz_test", data);
            enc.finish().expect("mscfb-v4 encode should succeed")
        }
        Algorithm::Pea => {
            let mut enc = pea::encode::PeaEncoder::new();
            enc.add_file("fuzz_test", data);
            enc.finish().expect("pea encode should succeed")
        }
        Algorithm::PeaStore => {
            let mut enc =
                pea::encode::PeaEncoder::new().compression(pea::encode::PeaCompression::Store);
            enc.add_file("fuzz_test", data);
            enc.finish().expect("pea-store encode should succeed")
        }
        Algorithm::PeaSha256 => {
            let mut enc = pea::encode::PeaEncoder::new()
                .stream_control(pea::decode::PeaAlgo::Sha256)
                .object_control(pea::decode::PeaAlgo::Sha256)
                .volume_control(pea::decode::PeaAlgo::Sha256);
            enc.add_file("fuzz_test", data);
            enc.finish().expect("pea-sha256 encode should succeed")
        }
        Algorithm::Crx3 => crx3_fixture(data),
        Algorithm::Ascii85 => ascii85::encode(data),
        Algorithm::Yenc => yenc::encode("fuzz", data),
        Algorithm::Uuencode => uuencode::encode("fuzz", 0o644, data),
        Algorithm::BinHex => binhex::encode(&binhex::BinHexEntry {
            name: "fuzz".to_string(),
            file_type: *b"TEXT",
            creator: *b"fuzz",
            flags: 0,
            data: data.to_vec(),
            resource: Vec::new(),
        }),
    }
}

fn zip_with_compression(data: &[u8], compression: zip::encode::ZipCompression) -> Vec<u8> {
    let mut enc = zip::encode::ZipEncoder::new();
    enc.add_file_with_options(
        "fuzz_test",
        data,
        &zip::encode::ZipEntryOptions {
            compression,
            ..Default::default()
        },
    );
    enc.finish().expect("zip encode should succeed")
}

fn sevenz_with(
    data: &[u8],
    method: sevenz::encode::SevenZMethod,
    filters: &[sevenz::encode::SevenZFilter],
) -> Vec<u8> {
    let mut enc = sevenz::encode::SevenZEncoder::new();
    enc.set_method(method);
    if !filters.is_empty() {
        enc.set_filters(filters.to_vec());
    }
    enc.add_file("fuzz_test", data);
    enc.finish().expect("7z encode should succeed")
}

fn lha_with_method(method: &[u8; 5], data: &[u8]) -> Vec<u8> {
    let mut enc = lha::encode::LhaEncoder::new()
        .with_method(method)
        .expect("lha write method should be accepted");
    enc.add_file("fuzz_test", data, 0)
        .expect("lha encode should succeed");
    enc.finish()
}

fn arj_with_method(method: u8, data: &[u8]) -> Vec<u8> {
    let mut enc =
        arj::encode::ArjEncoder::with_method(method).expect("arj method should be accepted");
    enc.add_file("fuzz_test", data, 0)
        .expect("arj encode should succeed");
    enc.finish()
}

fn xz_filter(data: &[u8], filter: xz::filters::Filter) -> Vec<u8> {
    xz::encode::encode_with_filters(data, &[filter]).expect("xz filter encode should succeed")
}

fn mppc_rdp_framed(ty: mppc::CompressionType, data: &[u8]) -> Vec<u8> {
    let (flags, packet) = mppc::encode_rdp(ty, data).expect("mppc rdp encode should succeed");
    let mut out = Vec::with_capacity(packet.len() + 1);
    out.push(flags);
    out.extend_from_slice(&packet);
    out
}

/// Build a synthetic CRX3 container: `Cr24` magic + version 3 + an empty
/// `SignedData` header, followed by a ZIP archive holding the payload.
fn crx3_fixture(data: &[u8]) -> Vec<u8> {
    let mut enc = zip::encode::ZipEncoder::new();
    enc.add_file("fuzz_test", data);
    let inner = enc.finish().expect("crx3 inner zip encode should succeed");
    let mut out = Vec::with_capacity(12 + inner.len());
    out.extend_from_slice(b"Cr24");
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&inner);
    out
}

/// Fixed reference content shared by the VCDIFF source-window round-trip.
fn delta_source() -> &'static [u8] {
    static SOURCE: OnceLock<Vec<u8>> = OnceLock::new();
    SOURCE.get_or_init(|| (0..8192u32).map(|i| ((i * 31 + 7) % 251) as u8).collect())
}

/// Fixed LZ4 prefix dictionary shared by the dict round-trip.
fn lz4_dict() -> &'static lz4::decode::Lz4Dict {
    static DICT: OnceLock<lz4::decode::Lz4Dict> = OnceLock::new();
    DICT.get_or_init(|| {
        let content: Vec<u8> = (0..4096u32).map(|i| ((i * 17 + 3) % 251) as u8).collect();
        lz4::decode::Lz4Dict::new(&content)
    })
}

/// Fixed trained zstd dictionary shared by the dict round-trip.
fn zstd_dict() -> &'static zstd::decode::ZstdDict {
    static DICT: OnceLock<zstd::decode::ZstdDict> = OnceLock::new();
    DICT.get_or_init(|| {
        let samples: Vec<Vec<u8>> = (0..16u32)
            .map(|s| {
                (0..2048u32)
                    .map(|i| ((i * 13 + s * 97) % 251) as u8)
                    .collect()
            })
            .collect();
        let refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
        zstd::train::train_dictionary(&refs, &zstd::train::TrainOptions::default())
            .expect("zstd dictionary training should succeed")
    })
}

/// Decode `data` using the specified algorithm, returning the original bytes.
pub fn decode_with(algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, Error> {
    match algo {
        Algorithm::Deflate => deflate::decode::decode(data),
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => gzip::decode::decode(data),
        Algorithm::Zstd | Algorithm::ZstdFast | Algorithm::ZstdBest | Algorithm::ZstdNoChecksum => {
            zstd::decode::decode(data)
        }
        Algorithm::ZstdSeekable => zstd::seekable::decode(data),
        Algorithm::ZstdDict => zstd::decode::decode_with_dict(data, zstd_dict()),
        Algorithm::Bzip2 | Algorithm::Bzip2Fast | Algorithm::Bzip2Best => {
            bzip2::decode::decode(data)
        }
        Algorithm::Lzip | Algorithm::LzipFast | Algorithm::LzipBest | Algorithm::LzipDict => {
            lzip::decode::decode(data)
        }
        Algorithm::LzmaAlone => lzma_alone::decode::decode(data),
        Algorithm::Xz
        | Algorithm::XzFast
        | Algorithm::XzBest
        | Algorithm::XzDelta
        | Algorithm::XzX86
        | Algorithm::XzPpc
        | Algorithm::XzIa64
        | Algorithm::XzSparc
        | Algorithm::XzArm
        | Algorithm::XzArmThumb
        | Algorithm::XzArm64
        | Algorithm::XzRiscV => xz::decode::decode(data),
        Algorithm::Lzw | Algorithm::LzwBits9 => lzw::decode::decode(data),
        Algorithm::Lz4
        | Algorithm::Lz4Fast
        | Algorithm::Lz4Best
        | Algorithm::Lz4SmallBlock
        | Algorithm::Lz4Legacy
        | Algorithm::Lz4BlockDependent => lz4::decode::decode(data),
        Algorithm::Lz4Block => lz4::decode::decode_block(data, 64 << 20),
        Algorithm::Lz4Dict => lz4::decode::decode_with_dict(data, lz4_dict()),
        Algorithm::Xpress => xca::lz77::decode(data),
        Algorithm::XpressHuff => xca::huffman::decode(data),
        Algorithm::Lznt1 => xca::lznt1::decode(data),
        Algorithm::Lzf => lzf::decode(data),
        Algorithm::Fastlz => fastlz::decode(data),
        Algorithm::PackBits => packbits::decode(data),
        Algorithm::Zx0 => zx0::decode(data),
        Algorithm::Zx1 => zx1::decode(data),
        Algorithm::Zx2 => zx2::decode(data),
        Algorithm::Zx5 => zx5::decode(data),
        Algorithm::Vcdiff => vcdiff::decode(data),
        Algorithm::VcdiffSrc => vcdiff::decode_with_source(delta_source(), data),
        Algorithm::Mppc => mppc::decode(data),
        Algorithm::MppcRdp4 | Algorithm::MppcRdp5 => {
            let (&flags, body) = data
                .split_first()
                .ok_or(Error::InvalidData("mppc rdp: missing flags byte"))?;
            mppc::decode_rdp(flags, body)
        }
        Algorithm::Lzs => lzs::decode(data),
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
        Algorithm::Brotli
        | Algorithm::BrotliFast
        | Algorithm::BrotliBest
        | Algorithm::BrotliMeta => brotli::decode::decode(data),
        Algorithm::Snappy => snappy::decode::decode(data),
        Algorithm::Rzip => rzip::decode::decode(data),
        Algorithm::Zlib => zlib::decode::decode(data),
        Algorithm::ZpaqArchive => {
            let entries = zpaq_archive::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Zpaq | Algorithm::ZpaqLevel2 | Algorithm::ZpaqLevel3 => {
            // The upstream `zpaq` CLI produces JIDAC journaling
            // archives whose metadata segments would pollute a raw
            // payload decode; decode those at the journal layer and
            // concatenate file contents (the oracle archives contain
            // exactly one file).
            match archive::archive::zpaq::jidac::decode_jidac(data) {
                Ok(journal) => Ok(journal.files.into_iter().flat_map(|f| f.data).collect()),
                Err(_) => zpaq::decode::decode(data),
            }
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
        Algorithm::GitPack | Algorithm::GitPackSha256 => {
            let entries = git_pack::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| {
                archive::traits::ArchiveEntry::data(&e).to_vec()
            }))
        }
        Algorithm::GitPackDelta => {
            let entries = git_pack::decode::decode(data)?;
            Ok(entries.into_iter().last().map_or(Vec::new(), |e| {
                archive::traits::ArchiveEntry::data(&e).to_vec()
            }))
        }
        Algorithm::Xar => {
            let entries = xar::decode::decode(data)?;
            Ok(entries
                .into_iter()
                .find(|e| !e.is_dir)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Warc => {
            let entries = warc::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Lha
        | Algorithm::LhaLh4
        | Algorithm::LhaLh5
        | Algorithm::LhaLh6
        | Algorithm::LhaLh7
        | Algorithm::LhaLzs
        | Algorithm::LhaLz5
        | Algorithm::LhaPm1
        | Algorithm::LhaPm2 => {
            let entries = lha::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Arj | Algorithm::Arj1 | Algorithm::Arj2 | Algorithm::Arj3 | Algorithm::Arj4 => {
            let entries = arj::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::ArjGarbled => {
            let entries = arj::decode::decode_with_password(data, "secret")?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Arc => {
            let entries = arc::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Zip
        | Algorithm::ZipStore
        | Algorithm::ZipBzip2
        | Algorithm::ZipZstd
        | Algorithm::ZipDeflate64
        | Algorithm::ZipLzma
        | Algorithm::ZipXz
        | Algorithm::ZipPpmd
        | Algorithm::ZipShrunk
        | Algorithm::ZipImplode
        | Algorithm::ZipReduce => {
            let entries = zip::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::SevenZ
        | Algorithm::SevenZCopy
        | Algorithm::SevenZLzma
        | Algorithm::SevenZPpmd
        | Algorithm::SevenZDeflate
        | Algorithm::SevenZBzip2
        | Algorithm::SevenZDeflate64
        | Algorithm::SevenZBrotli
        | Algorithm::SevenZX86
        | Algorithm::SevenZBcj2
        | Algorithm::SevenZDelta => {
            let entries = sevenz::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::TarGnu | Algorithm::TarUstar | Algorithm::TarPax => {
            let entries = tar::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Cpio | Algorithm::CpioCrc | Algorithm::CpioOdc | Algorithm::CpioBin => {
            let entries = cpio::decode::decode(data)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Cramfs => {
            let image = cramfs::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == cramfs::decode::CramfsKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Romfs => {
            let image = romfs::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == romfs::decode::RomfsKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Erofs => {
            let image = erofs::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == erofs::decode::ErofsKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Iso9660 | Algorithm::IsoRr => {
            let image = iso9660::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == iso9660::decode::IsoKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Mscfb | Algorithm::MscfbV4 => {
            let entries = mscfb::decode::decode(data)?;
            Ok(entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Pea | Algorithm::PeaStore | Algorithm::PeaSha256 => {
            let image = pea::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| !e.is_dir)
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Crx3 => {
            let image = crx3::decode::decode(data)?;
            Ok(image
                .entries
                .into_iter()
                .next()
                .map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Ascii85 => ascii85::decode(data),
        Algorithm::Yenc => Ok(yenc::decode(data)?.data),
        Algorithm::Uuencode => Ok(uuencode::decode(data)?.data),
        Algorithm::BinHex => Ok(binhex::decode(data)?.data),
    }
}

/// Bounded variant of [`decode_with`] for the corrupt-pattern probe.
///
/// Codecs whose stream carries no output length expose a `decode_bounded`
/// API; routing the probe through it caps a mutated stream's output at the
/// harness limit ([`Error::OutputLimitExceeded`] on excess) instead of
/// materializing it and tripping the resource oracle afterwards. Formats
/// without a bounded decode fall back to [`decode_with`].
pub fn decode_bounded_with(
    algo: Algorithm,
    data: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    match algo {
        // A corrupt zstd stream can chain RLE blocks and emit unbounded
        // output. The unbounded `decode` path made the probe allocate until
        // the fuzz process hit its 2 GiB address-space limit (run-1792712029).
        Algorithm::Zstd | Algorithm::ZstdFast | Algorithm::ZstdBest | Algorithm::ZstdNoChecksum => {
            zstd::decode::decode_bounded(data, max_output)
        }
        Algorithm::ZstdDict => {
            zstd::decode::decode_with_dict_bounded(data, zstd_dict(), max_output)
        }
        Algorithm::Xpress => xca::lz77::decode_bounded(data, max_output),
        Algorithm::XpressHuff => xca::huffman::decode_bounded(data, max_output),
        Algorithm::Lznt1 => xca::lznt1::decode_bounded(data, max_output),
        Algorithm::Lzf => lzf::decode_bounded(data, max_output),
        Algorithm::Fastlz => fastlz::decode_bounded(data, max_output),
        Algorithm::Zx0 => zx0::decode_bounded(data, max_output),
        Algorithm::Zx1 => zx1::decode_bounded(data, max_output),
        Algorithm::Zx2 => zx2::decode_bounded(data, max_output),
        Algorithm::Zx5 => zx5::decode_bounded(data, max_output),
        Algorithm::Vcdiff => vcdiff::decode_bounded(&[], data, max_output),
        Algorithm::VcdiffSrc => vcdiff::decode_bounded(delta_source(), data, max_output),
        Algorithm::Mppc => mppc::decode_bounded(data, max_output),
        Algorithm::MppcRdp4 | Algorithm::MppcRdp5 => {
            let (&flags, body) = data
                .split_first()
                .ok_or(Error::InvalidData("mppc rdp: missing flags byte"))?;
            mppc::decode_rdp_bounded(flags, body, max_output)
        }
        Algorithm::Lzs => lzs::decode_bounded(data, max_output),
        Algorithm::Lzsa | Algorithm::Lzsa2 => lzsa::decode_bounded(data, max_output),
        Algorithm::Lzrw1 => lzrw1::decode_bounded(data, max_output),
        Algorithm::Lzrw1a => lzrw1a::decode_bounded(data, max_output),
        Algorithm::Lzrw2 => lzrw2::decode_bounded(data, max_output),
        Algorithm::Lzrw3 => lzrw3::decode_bounded(data, max_output),
        Algorithm::Lzrw3a => lzrw3a::decode_bounded(data, max_output),
        // A corrupt zpaq stream can emit unbounded output from finite
        // input (the arithmetic decoder need not consume input to produce
        // bits), so probes must go through the bounded codec entry point.
        Algorithm::Zpaq | Algorithm::ZpaqLevel2 | Algorithm::ZpaqLevel3 => {
            zpaq::decode::decode_bounded(data, max_output)
        }
        Algorithm::ZpaqArchive => {
            let entries = zpaq_archive::decode::decode_bounded(data, max_output)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        // LHA/ARJ member headers declare the uncompressed size up
        // front; a corrupt `orig` field (e.g. 0xFFFFFF1C) would
        // otherwise materialize ~4 GiB before the oracle sees it.
        Algorithm::Lha
        | Algorithm::LhaLh4
        | Algorithm::LhaLh5
        | Algorithm::LhaLh6
        | Algorithm::LhaLh7
        | Algorithm::LhaLzs
        | Algorithm::LhaLz5
        | Algorithm::LhaPm1
        | Algorithm::LhaPm2 => {
            let entries = lha::decode::decode_bounded(data, max_output)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::Arj | Algorithm::Arj1 | Algorithm::Arj2 | Algorithm::Arj3 | Algorithm::Arj4 => {
            let entries = arj::decode::decode_bounded(data, max_output)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        Algorithm::ArjGarbled => {
            let entries = arj::decode::decode_bounded_with_password(data, "secret", max_output)?;
            Ok(entries.into_iter().next().map_or(Vec::new(), |e| e.data))
        }
        // erofs `i_size` is a u64 that directly sizes the payload
        // allocation; a corrupt inode must trip the harness limit
        // rather than request an exabyte-scale buffer.
        Algorithm::Erofs => {
            let image = erofs::decode::decode_bounded(data, max_output)?;
            Ok(image
                .entries
                .into_iter()
                .find(|e| e.kind == erofs::decode::ErofsKind::File)
                .map_or(Vec::new(), |e| e.data))
        }
        // Block `u_len` is the library cap, except `usize::MAX`, which the
        // library rejects. A mutated `chunk_bytes` of 4..=8 can still declare
        // a huge finite `u_len`, so the corrupt probe also applies `max_output`.
        Algorithm::LrzipZpaq => lrzip::decode::decode_bounded(data, max_output),
        _ => decode_with(algo, data),
    }
}

/// Append a decode into a non-empty buffer when this algorithm's codec
/// implements `decode_into`. `None` means the algorithm is not one of those
/// codecs.
pub fn decode_into_with(
    algo: Algorithm,
    data: &[u8],
    output: &mut Vec<u8>,
    max_output: Option<usize>,
) -> Option<Result<(), Error>> {
    let result = match algo {
        Algorithm::Deflate => deflate::decode::decode_into(data, output, max_output),
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => {
            gzip::decode::decode_into(data, output, max_output)
        }
        Algorithm::Zlib => zlib::decode::decode_into(data, output, max_output),
        Algorithm::Zstd | Algorithm::ZstdFast | Algorithm::ZstdBest | Algorithm::ZstdNoChecksum => {
            zstd::decode::decode_into(data, output, max_output)
        }
        Algorithm::Lz4
        | Algorithm::Lz4Fast
        | Algorithm::Lz4Best
        | Algorithm::Lz4SmallBlock
        | Algorithm::Lz4Legacy
        | Algorithm::Lz4BlockDependent => lz4::decode::decode_into(data, output, max_output),
        Algorithm::LzmaAlone => lzma_alone::decode::decode_into(data, output, max_output),
        Algorithm::Bzip2 | Algorithm::Bzip2Fast | Algorithm::Bzip2Best => {
            bzip2::decode::decode_into(data, output, max_output)
        }
        Algorithm::Lzip | Algorithm::LzipFast | Algorithm::LzipBest | Algorithm::LzipDict => {
            lzip::decode::decode_into(data, output, max_output)
        }
        Algorithm::Lzo | Algorithm::LzoFast | Algorithm::LzoBest => {
            lzo::decode::decode_into(data, output, max_output)
        }
        Algorithm::Brotli
        | Algorithm::BrotliFast
        | Algorithm::BrotliBest
        | Algorithm::BrotliMeta => brotli::decode::decode_into(data, output, max_output),
        Algorithm::Lzw | Algorithm::LzwBits9 => lzw::decode::decode_into(data, output, max_output),
        Algorithm::LrzipLzma
        | Algorithm::LrzipBzip2
        | Algorithm::LrzipGzip
        | Algorithm::LrzipLzo
        | Algorithm::LrzipNone
        | Algorithm::LrzipZpaq => lrzip::decode::decode_into(data, output, max_output),
        Algorithm::Snappy => snappy::decode::decode_into(data, output, max_output),
        Algorithm::Rzip => rzip::decode::decode_into(data, output, max_output),
        Algorithm::Xz
        | Algorithm::XzFast
        | Algorithm::XzBest
        | Algorithm::XzDelta
        | Algorithm::XzX86
        | Algorithm::XzPpc
        | Algorithm::XzIa64
        | Algorithm::XzSparc
        | Algorithm::XzArm
        | Algorithm::XzArmThumb
        | Algorithm::XzArm64
        | Algorithm::XzRiscV => xz::decode::decode_into(data, output, max_output),
        Algorithm::Zpaq | Algorithm::ZpaqLevel2 | Algorithm::ZpaqLevel3 => {
            zpaq::decode::decode_into(data, output, max_output)
        }
        // Formats without a dedicated `decode_into` still append the ordinary
        // decode onto the caller buffer, and leave that buffer unchanged on error.
        _ => append_ordinary_decode(algo, data, output, max_output),
    };
    Some(result)
}

fn append_ordinary_decode(
    algo: Algorithm,
    data: &[u8],
    output: &mut Vec<u8>,
    max_output: Option<usize>,
) -> Result<(), Error> {
    let start = output.len();
    let produced = match max_output {
        Some(limit) => decode_bounded_with(algo, data, limit),
        None => decode_with(algo, data),
    };
    match produced {
        Ok(bytes) => {
            output.extend_from_slice(&bytes);
            Ok(())
        }
        Err(err) => {
            output.truncate(start);
            Err(err)
        }
    }
}

const DECODE_INTO_PREFIX: &[u8] = b"fuzz-prefix";

/// Check `decode_into` on a non-empty buffer.
///
/// Success keeps the prefix and appends the same bytes as the ordinary
/// decode (`decode_bounded_with` when `max_output` is set). `Err` and
/// [`Error::OutputLimitExceeded`] restore the buffer length from entry.
/// Every algorithm takes this path. Formats without a dedicated
/// `decode_into` append the ordinary decode.
pub fn check_prefixed_decode_into(
    algo: Algorithm,
    data: &[u8],
    max_output: Option<usize>,
) -> Result<(), String> {
    let mut output = DECODE_INTO_PREFIX.to_vec();
    let start = output.len();
    let Some(result) = decode_into_with(algo, data, &mut output, max_output) else {
        return Ok(());
    };
    match result {
        Ok(()) => {
            if !output.starts_with(DECODE_INTO_PREFIX) {
                return Err("decode_into dropped the caller prefix".to_string());
            }
            let got = &output[start..];
            if let Some(limit) = max_output
                && got.len() > limit
            {
                return Err(format!(
                    "decode_into appended {} bytes > {limit}",
                    got.len()
                ));
            }
            let expected = match max_output {
                Some(limit) => decode_bounded_with(algo, data, limit),
                None => decode_with(algo, data),
            };
            match expected {
                Ok(bytes) if bytes.as_slice() == got => Ok(()),
                Ok(_) => Err("decode_into suffix disagrees with decode".to_string()),
                Err(err) => Err(format!("decode_into succeeded but decode failed: {err}")),
            }
        }
        Err(Error::OutputLimitExceeded { .. }) => {
            if output.len() != start {
                return Err("decode_into did not restore the prefix length".to_string());
            }
            Ok(())
        }
        Err(_) => {
            if output.len() != start {
                return Err("decode_into did not restore the prefix length".to_string());
            }
            Ok(())
        }
    }
}

/// Two gzip members. The second is a length-3 distance-1 match whose
/// trailer matches the bytes a window crossing into the first member
/// would emit. A correct decoder rejects it with `distance too far back`.
pub fn gzip_cross_member_stream() -> Vec<u8> {
    let mut combined = gzip::encode::encode(b"Hello", deflate::encode::Level::NoCompression);
    let mut bits = Vec::new();
    let mut acc = 0u32;
    let mut n = 0u8;
    let mut write = |value: u32, width: u8| {
        acc |= value << n;
        n += width;
        while n >= 8 {
            bits.push(acc as u8);
            acc >>= 8;
            n -= 8;
        }
    };
    let rev = |mut value: u32, mut width: u8| {
        let mut out = 0u32;
        while width > 0 {
            out = (out << 1) | (value & 1);
            value >>= 1;
            width -= 1;
        }
        out
    };
    write(1, 1);
    write(0b01, 2);
    write(rev(1, 7), 7);
    write(rev(0, 5), 5);
    write(rev(0, 7), 7);
    if n > 0 {
        bits.push(acc as u8);
    }
    let mut member2 = vec![0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0xFF];
    member2.extend_from_slice(&bits);
    member2.extend_from_slice(&0x83a2_5eae_u32.to_le_bytes());
    member2.extend_from_slice(&3u32.to_le_bytes());
    combined.extend_from_slice(&member2);
    combined
}

pub fn extra_corrupt_bases(algo: Algorithm) -> Vec<Vec<u8>> {
    match algo {
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => {
            vec![gzip_cross_member_stream()]
        }
        _ => Vec::new(),
    }
}

pub const fn special_case_labels(algo: Algorithm) -> &'static [&'static str] {
    match algo {
        Algorithm::Ar => &["gnu-long-name", "multi-entry"],
        Algorithm::ArBsd => &["bsd-long-name", "multi-entry"],
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => {
            &["determinism", "multi-member-distance"]
        }
        Algorithm::TarGnu => &["gnu-long-name", "multi-entry", "visit-stop"],
        Algorithm::TarUstar => &["multi-entry", "visit-stop"],
        Algorithm::TarPax => &["pax-metadata", "multi-entry", "visit-stop"],
        Algorithm::Cpio => &["newc-metadata", "multi-entry"],
        Algorithm::CpioCrc => &["newcrc-metadata", "multi-entry"],
        Algorithm::CpioOdc | Algorithm::CpioBin => &["multi-entry"],
        Algorithm::Zip => &[
            "stored-comment",
            "cp437-comment",
            "aes256",
            "traditional",
            "multi-entry",
            "visit-stop",
        ],
        Algorithm::SevenZ => &[
            "copy-method",
            "ppmd",
            "encrypted",
            "encoded-header",
            "encrypted-header",
            "multi-entry",
            "visit-stop",
        ],
        Algorithm::Lha | Algorithm::Arj | Algorithm::Arc | Algorithm::Xar => &["multi-entry"],
        Algorithm::Mscfb | Algorithm::MscfbV4 => &["multi-entry"],
        Algorithm::Pea | Algorithm::PeaStore | Algorithm::PeaSha256 => &["multi-entry"],
        Algorithm::Cramfs | Algorithm::Romfs | Algorithm::Erofs => &["multi-entry"],
        Algorithm::Iso9660 | Algorithm::IsoRr => &["multi-entry"],
        Algorithm::ZpaqArchive | Algorithm::GitPack => &["multi-entry"],
        _ if is_codec(algo) => &["determinism"],
        _ => &[],
    }
}

/// Pure codec (compress::*) variants — those whose encoders take no archive
/// metadata (timestamps, names) and are therefore expected to be
/// byte-for-byte deterministic for identical input.
const fn is_codec(algo: Algorithm) -> bool {
    matches!(
        algo,
        Algorithm::Deflate
            | Algorithm::Zstd
            | Algorithm::ZstdFast
            | Algorithm::ZstdBest
            | Algorithm::ZstdNoChecksum
            | Algorithm::ZstdSeekable
            | Algorithm::ZstdDict
            | Algorithm::Bzip2
            | Algorithm::Bzip2Fast
            | Algorithm::Bzip2Best
            | Algorithm::Lzip
            | Algorithm::LzipFast
            | Algorithm::LzipBest
            | Algorithm::LzipDict
            | Algorithm::LzmaAlone
            | Algorithm::Xz
            | Algorithm::XzFast
            | Algorithm::XzBest
            | Algorithm::XzDelta
            | Algorithm::XzX86
            | Algorithm::XzPpc
            | Algorithm::XzIa64
            | Algorithm::XzSparc
            | Algorithm::XzArm
            | Algorithm::XzArmThumb
            | Algorithm::XzArm64
            | Algorithm::XzRiscV
            | Algorithm::Lzw
            | Algorithm::LzwBits9
            | Algorithm::Lz4
            | Algorithm::Lz4Fast
            | Algorithm::Lz4Best
            | Algorithm::Lz4SmallBlock
            | Algorithm::Lz4Block
            | Algorithm::Lz4Dict
            | Algorithm::Lz4Legacy
            | Algorithm::Lz4BlockDependent
            | Algorithm::Xpress
            | Algorithm::XpressHuff
            | Algorithm::Lznt1
            | Algorithm::Lzf
            | Algorithm::Fastlz
            | Algorithm::PackBits
            | Algorithm::Zx0
            | Algorithm::Zx1
            | Algorithm::Zx2
            | Algorithm::Zx5
            | Algorithm::Vcdiff
            | Algorithm::VcdiffSrc
            | Algorithm::Mppc
            | Algorithm::MppcRdp4
            | Algorithm::MppcRdp5
            | Algorithm::Lzs
            | Algorithm::Lzsa
            | Algorithm::Lzsa2
            | Algorithm::Lzrw1
            | Algorithm::Lzrw1a
            | Algorithm::Lzrw2
            | Algorithm::Lzrw3
            | Algorithm::Lzrw3a
            | Algorithm::Lzxd
            | Algorithm::Cmpsc
            | Algorithm::Lzo
            | Algorithm::LzoFast
            | Algorithm::LzoBest
            | Algorithm::LrzipLzma
            | Algorithm::LrzipBzip2
            | Algorithm::LrzipGzip
            | Algorithm::LrzipLzo
            | Algorithm::LrzipNone
            | Algorithm::LrzipZpaq
            | Algorithm::Brotli
            | Algorithm::BrotliFast
            | Algorithm::BrotliBest
            | Algorithm::BrotliMeta
            | Algorithm::Snappy
            | Algorithm::Rzip
            | Algorithm::Zlib
            | Algorithm::Zpaq
            | Algorithm::ZpaqLevel2
            | Algorithm::ZpaqLevel3
            | Algorithm::Ascii85
            | Algorithm::Yenc
            | Algorithm::Uuencode
            | Algorithm::BinHex
    )
}

/// Variants that share the base codec's encode/decode path and differ only
/// in the external tool's compression level (e.g. `zstd -1` vs `zstd -19`).
/// `--pattern all` still runs them. `self` and `corrupt` repeat the base
/// variant; `original-*` is the level-specific check when the tool exists.
#[cfg_attr(not(test), allow(dead_code))]
pub const fn is_level_alias(algo: Algorithm) -> bool {
    matches!(
        algo,
        Algorithm::ZstdFast
            | Algorithm::ZstdBest
            | Algorithm::Lz4Fast
            | Algorithm::Lz4Best
            | Algorithm::LzoFast
            | Algorithm::LzoBest
            | Algorithm::LzipFast
            | Algorithm::LzipBest
            | Algorithm::XzFast
            | Algorithm::XzBest
            | Algorithm::BrotliFast
            | Algorithm::BrotliBest
    )
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
        (Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore, "multi-member-distance") => {
            let combined = gzip_cross_member_stream();
            match gzip::decode::decode(&combined) {
                Err(Error::InvalidData("distance too far back")) => Ok(data.to_vec()),
                Err(err) => Err(format!("gzip multi-member distance: {err}")),
                Ok(_) => Err("gzip multi-member distance was accepted".to_string()),
            }
        }
        (Algorithm::TarGnu | Algorithm::TarUstar | Algorithm::TarPax, "visit-stop") => {
            let mut enc = if algo == Algorithm::TarPax {
                tar::encode::TarEncoder::new_pax()
            } else {
                tar::encode::TarEncoder::new()
            };
            enc.add_file("a.txt", b"aaa");
            enc.add_file("b.txt", b"bbb");
            let archive = enc.finish();
            let mut seen = Vec::new();
            let err = tar::decode::for_each_entry(&archive, |entry| {
                seen.push(entry.header.name);
                Err(Error::InvalidData("stop"))
            });
            if err.is_err() && seen == ["a.txt"] {
                Ok(data.to_vec())
            } else {
                Err(format!("tar visit-stop saw {seen:?}: {err:?}"))
            }
        }
        (Algorithm::Zip, "visit-stop") => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file("a.txt", b"aaa");
            enc.add_file("b.txt", b"bbb");
            let archive = enc.finish().map_err(|err| err.to_string())?;
            let mut seen = Vec::new();
            let err = zip::decode::for_each_entry(&archive, |entry| {
                seen.push(entry.name);
                Err(Error::InvalidData("stop"))
            });
            if err.is_err() && seen == ["a.txt"] {
                Ok(data.to_vec())
            } else {
                Err(format!("zip visit-stop saw {seen:?}: {err:?}"))
            }
        }
        (Algorithm::SevenZ, "visit-stop") => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.add_file("a.txt", b"aaa");
            enc.add_file("b.txt", b"bbb");
            let archive = enc.finish().map_err(|err| err.to_string())?;
            let mut seen = Vec::new();
            let err = sevenz::decode::for_each_entry(&archive, |entry| {
                seen.push(entry.name);
                Err(Error::InvalidData("stop"))
            });
            if err.is_err() && !seen.iter().any(|name| name == "b.txt") && seen.len() <= 1 {
                Ok(data.to_vec())
            } else {
                Err(format!("7z visit-stop saw {seen:?}: {err:?}"))
            }
        }
        _ if label == "multi-entry" => run_multi_entry_case(algo, data),
        (_, "determinism") => {
            // Codec encoders must be byte-for-byte deterministic: encode the
            // same input twice and require identical output. Non-determinism
            // here (embedded timestamps, HashMap ordering, rng seeds) breaks
            // reproducible artifacts and can hide decode-side divergence.
            let first = encode_with(algo, data);
            let second = encode_with(algo, data);
            if first != second {
                return Err(format!(
                    "non-deterministic encoder for {algo}: {} vs {} bytes",
                    first.len(),
                    second.len()
                ));
            }
            Ok(data.to_vec())
        }
        _ => Err(format!("unknown special case for {algo}: {label}")),
    }
}

/// Extra entry names for multi-entry special cases. Varies with the input
/// so name-table and sorting paths see different strings.
fn extra_entry_names(data: &[u8]) -> [String; 2] {
    let a = usize::from(data.first().copied().unwrap_or(0));
    let b = usize::from(data.get(1).copied().unwrap_or(0));
    [
        format!("entry_{:02x}", a % 97),
        format!("sub_{:02x}.bin", b % 53),
    ]
}

/// Pack two extra files plus the payload as `fuzz_test`, then verify the
/// archive holds all three entries and return the payload bytes.
fn run_multi_entry_case(algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, String> {
    let [n1, n2] = extra_entry_names(data);
    match algo {
        Algorithm::Ar | Algorithm::ArBsd => {
            let mut enc = if algo == Algorithm::ArBsd {
                ar::encode::ArEncoder::new_bsd()
            } else {
                ar::encode::ArEncoder::new()
            };
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let entries = ar::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries.len() != 3 {
                return Err(format!("ar multi-entry lost entries: {}", entries.len()));
            }
            Ok(entries[2].data.clone())
        }
        Algorithm::TarGnu | Algorithm::TarUstar | Algorithm::TarPax => {
            let mut enc = if algo == Algorithm::TarPax {
                tar::encode::TarEncoder::new_pax()
            } else {
                tar::encode::TarEncoder::new()
            };
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let entries = tar::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            if entries.len() != 3 {
                return Err(format!("tar multi-entry lost entries: {}", entries.len()));
            }
            Ok(entries[2].data.clone())
        }
        Algorithm::Cpio | Algorithm::CpioCrc | Algorithm::CpioOdc | Algorithm::CpioBin => {
            let mut enc = match algo {
                Algorithm::CpioCrc => cpio::encode::CpioEncoder::new_crc(),
                Algorithm::CpioOdc => cpio::encode::CpioEncoder::new_odc(),
                Algorithm::CpioBin => cpio::encode::CpioEncoder::new_bin(),
                _ => cpio::encode::CpioEncoder::new(),
            };
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let entries = cpio::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            if entries.len() != 3 {
                return Err(format!("cpio multi-entry lost entries: {}", entries.len()));
            }
            Ok(entries[2].data.clone())
        }
        Algorithm::Zip => {
            let mut enc = zip::encode::ZipEncoder::new();
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let entries = zip::decode::decode(&archive).map_err(|e| e.to_string())?;
            if entries.len() != 3 {
                return Err(format!("zip multi-entry lost entries: {}", entries.len()));
            }
            Ok(entries[2].data.clone())
        }
        Algorithm::SevenZ => {
            let mut enc = sevenz::encode::SevenZEncoder::new();
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let entries = sevenz::decode::decode(&archive).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "7z multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Lha => {
            let mut enc = lha::encode::LhaEncoder::new();
            enc.add_file(&n1, b"first", 0).map_err(|e| e.to_string())?;
            enc.add_file(&n2, b"second", 0).map_err(|e| e.to_string())?;
            enc.add_file("fuzz_test", data, 0)
                .map_err(|e| e.to_string())?;
            let entries = lha::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "lha multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Arj => {
            let mut enc = arj::encode::ArjEncoder::new();
            enc.add_file(&n1, b"first", 0).map_err(|e| e.to_string())?;
            enc.add_file(&n2, b"second", 0).map_err(|e| e.to_string())?;
            enc.add_file("fuzz_test", data, 0)
                .map_err(|e| e.to_string())?;
            let entries = arj::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "arj multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Arc => {
            let mut enc = arc::encode::ArcEncoder::new();
            for (i, (name, payload)) in [
                (n1.as_str(), b"first".as_slice()),
                (n2.as_str(), b"second"),
                ("fuzz_test", data),
            ]
            .into_iter()
            .enumerate()
            {
                enc.add_file_with_method(name, payload, 0, 0, [1u8, 2, 8][i])
                    .map_err(|e| e.to_string())?;
            }
            let entries = arc::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "arc multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Xar => {
            let mut enc = xar::encode::XarEncoder::new();
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let entries = xar::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| !e.is_dir && e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "xar multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Mscfb | Algorithm::MscfbV4 => {
            let mut enc = if algo == Algorithm::MscfbV4 {
                mscfb::encode::CfbEncoder::version4()
            } else {
                mscfb::encode::CfbEncoder::new()
            };
            enc.add_storage("dir1");
            enc.add_stream(&n1, b"first");
            enc.add_stream(&n2, b"second");
            enc.add_stream("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let entries = mscfb::decode::decode(&archive).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "mscfb multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Pea | Algorithm::PeaStore | Algorithm::PeaSha256 => {
            let mut enc = pea::encode::PeaEncoder::new();
            match algo {
                Algorithm::PeaStore => {
                    enc = enc.compression(pea::encode::PeaCompression::Store);
                }
                Algorithm::PeaSha256 => {
                    enc = enc
                        .stream_control(pea::decode::PeaAlgo::Sha256)
                        .object_control(pea::decode::PeaAlgo::Sha256)
                        .volume_control(pea::decode::PeaAlgo::Sha256);
                }
                _ => {}
            }
            enc.add_dir("dir1");
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let image = pea::decode::decode(&archive).map_err(|e| e.to_string())?;
            image
                .entries
                .into_iter()
                .find(|e| !e.is_dir && e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "pea multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Cramfs => {
            let mut enc = cramfs::encode::CramfsEncoder::new();
            enc.add_dir("dir1");
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let image = cramfs::decode::decode(&archive).map_err(|e| e.to_string())?;
            image
                .entries
                .into_iter()
                .find(|e| e.kind == cramfs::decode::CramfsKind::File && e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "cramfs multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Romfs => {
            let mut enc = romfs::encode::RomfsEncoder::new();
            enc.add_directory("dir1");
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let image = romfs::decode::decode(&archive).map_err(|e| e.to_string())?;
            image
                .entries
                .into_iter()
                .find(|e| e.kind == romfs::decode::RomfsKind::File && e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "romfs multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Erofs => {
            let mut enc = erofs::encode::ErofsEncoder::new();
            enc.add_dir("dir1");
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let image = erofs::decode::decode(&archive).map_err(|e| e.to_string())?;
            image
                .entries
                .into_iter()
                .find(|e| e.kind == erofs::decode::ErofsKind::File && e.name == "fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "erofs multi-entry lost fuzz_test".to_string())
        }
        Algorithm::Iso9660 | Algorithm::IsoRr => {
            let mut enc = if algo == Algorithm::IsoRr {
                iso9660::encode::IsoEncoder::new().with_rock_ridge()
            } else {
                iso9660::encode::IsoEncoder::new()
            };
            enc.add_directory("dir1");
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let image = iso9660::decode::decode(&archive).map_err(|e| e.to_string())?;
            // ISO9660 level-1 names rewrite `fuzz_test` (d-characters, 8.3
            // limit), so identify the payload entry by content instead.
            image
                .entries
                .into_iter()
                .find(|e| e.kind == iso9660::decode::IsoKind::File && e.data == data)
                .map(|e| e.data)
                .ok_or_else(|| "iso9660 multi-entry lost file entry".to_string())
        }
        Algorithm::ZpaqArchive => {
            let mut enc = zpaq_archive::encode::ZpaqEncoder::new(1);
            enc.add_file(&n1, b"first");
            enc.add_file(&n2, b"second");
            enc.add_file("fuzz_test", data);
            let archive = enc.finish().map_err(|e| e.to_string())?;
            let entries = zpaq_archive::decode::decode(&archive).map_err(|e| e.to_string())?;
            entries
                .into_iter()
                .find(|e| e.filename == b"fuzz_test")
                .map(|e| e.data)
                .ok_or_else(|| "zpaq multi-entry lost fuzz_test".to_string())
        }
        Algorithm::GitPack => {
            let mut enc = git_pack::encode::GitPackEncoder::new();
            enc.add_object(git_pack::ObjectType::Blob, b"first");
            enc.add_object(git_pack::ObjectType::Blob, b"second");
            enc.add_object(git_pack::ObjectType::Blob, data);
            let entries = git_pack::decode::decode(&enc.finish()).map_err(|e| e.to_string())?;
            if entries.len() != 3 {
                return Err(format!(
                    "git-pack multi-entry lost objects: {}",
                    entries.len()
                ));
            }
            Ok(archive::traits::ArchiveEntry::data(&entries[2]).to_vec())
        }
        _ => Err(format!("no multi-entry special case for {algo}")),
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
///
/// MS-CAB stores `cbData`/`cbUncomp` as u16, so file data is split
/// into CFDATA blocks of at most 32KiB (the conventional stored-block
/// size) rather than a single block that would overflow the fields.
fn mscab_fixture(data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 32 * 1024;

    let mut files_buf = Vec::new();
    files_buf.extend_from_slice(&(data.len() as u32).to_le_bytes()); // cbFile
    files_buf.extend_from_slice(&0u32.to_le_bytes()); // uoffFolderStart
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // iFolder
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // date
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // time
    files_buf.extend_from_slice(&0u16.to_le_bytes()); // attribs
    files_buf.extend_from_slice(b"fuzz_test");
    files_buf.push(0);

    let n_blocks = data.len().div_ceil(BLOCK);
    let folders_off = 36usize;
    let files_off = folders_off + 8;
    let data_off = files_off + files_buf.len();
    let cb_cabinet = (data_off + n_blocks * 8 + data.len()) as u32;

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
    out.extend_from_slice(&(n_blocks as u16).to_le_bytes()); // cCFDATA
    out.extend_from_slice(&0u16.to_le_bytes()); // tcompTYPE_NONE
    out.extend_from_slice(&files_buf);
    for chunk in data.chunks(BLOCK) {
        out.extend_from_slice(&0u32.to_le_bytes()); // csum
        out.extend_from_slice(&(chunk.len() as u16).to_le_bytes()); // cbData
        out.extend_from_slice(&(chunk.len() as u16).to_le_bytes()); // cbUncomp
        out.extend_from_slice(chunk);
    }
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
    use super::{
        Algorithm, decode_bounded_with, decode_with, encode_with, run_special_case,
        special_case_labels,
    };

    #[test]
    fn mscab_fixture_splits_cfdata_blocks() {
        for len in [0usize, 32768, 32769, 70_000] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let encoded = encode_with(Algorithm::Mscab, &data);
            let decoded = decode_with(Algorithm::Mscab, &encoded).unwrap();
            assert_eq!(decoded, data, "len={len}");
        }
    }

    #[test]
    fn all_algorithms_roundtrip() {
        let payload = b"archive fuzz payload";
        for &algo in Algorithm::ALL {
            let encoded = encode_with(algo, payload);
            let decoded =
                decode_with(algo, &encoded).unwrap_or_else(|e| panic!("{algo} decode failed: {e}"));
            if algo == Algorithm::Mtree {
                continue;
            }
            assert_eq!(decoded, payload, "{algo}");
        }
    }

    #[test]
    fn special_cases_roundtrip_payload() {
        let payload = b"special case payload";
        for &algo in Algorithm::ALL {
            for &label in special_case_labels(algo) {
                let decoded = run_special_case(algo, label, payload)
                    .unwrap_or_else(|e| panic!("{algo}::{label} failed: {e}"));
                assert_eq!(decoded, payload, "{algo}::{label}");
            }
        }
    }

    /// Regression (fuzz run-1791677246): a corrupt `-pm1-` member header
    /// declaring a ~4 GiB original size must fail early through the
    /// bounded probe instead of materializing the output.
    #[test]
    fn zstd_bounded_probe_rejects_oversized_rle_output() {
        let mut frame = vec![
            0x28, 0xb5, 0x2f, 0xfd, // magic
            0x20, // single segment, 1-byte FCS, no checksum/dict
            0x00, // FCS = 0
        ];
        // Last block, RLE, 2048 bytes of the same byte.
        let block_header = (2048u32 << 3) | (1 << 1) | 1;
        frame.extend_from_slice(&block_header.to_le_bytes()[..3]);
        frame.push(0x0A);
        assert!(decode_bounded_with(Algorithm::Zstd, &frame, 1024).is_err());
    }

    #[test]
    fn lha_bounded_probe_rejects_oversized_orig() {
        let mut a = Vec::new();
        a.push(23u8); // level-0 hsize = 22 + name_len
        a.push(0u8); // checksum placeholder
        a.extend_from_slice(b"-pm1-");
        a.extend_from_slice(&4u32.to_le_bytes()); // packed
        a.extend_from_slice(&0xFFFF_FF1Cu32.to_le_bytes()); // orig
        a.extend_from_slice(&0u32.to_le_bytes()); // mtime
        a.push(0); // MS-DOS attribute
        a.push(0); // level 0
        a.push(1); // name_len
        a.push(b'a');
        a.extend_from_slice(&0u16.to_le_bytes()); // crc16
        a[1] = a[2..2 + 23].iter().fold(0u8, |s, &b| s.wrapping_add(b));
        a.extend_from_slice(&[0u8; 4]); // packed payload
        a.push(0); // archive terminator
        for algo in [Algorithm::Lha, Algorithm::LhaPm1, Algorithm::LhaPm2] {
            assert!(
                decode_bounded_with(algo, &a, 64 << 20).is_err(),
                "{algo} must reject the oversized declared orig"
            );
        }
    }
}
