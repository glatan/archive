//! Pure Rust archive and compression library.
//!
//! `archive` exposes in-memory encode/decode APIs for compression formats under
//! [`crate::compress`] and archive/container formats under [`crate::archive`].
//! Core logic works in `no_std` + `alloc` environments.
//!
//! # Module layout
//!
//! - [`compress`] provides DEFLATE, gzip, zlib, zstd, bzip2, lzip, `.lzma`,
//!   xz, LZW, LZ4, LZO, Snappy, Brotli, ZPAQ, rzip, and lrzip support.
//! - [`archive`] provides tar, cpio, ar, zpaq, zip, and 7z support.
//! - [`traits`] defines common [`Decode`](traits::Decode) / [`Encode`](traits::Encode)
//!   traits for compression codecs, and [`ArchiveEntry`](traits::ArchiveEntry) /
//!   [`ArchiveDecode`](traits::ArchiveDecode) / [`ArchiveEncode`](traits::ArchiveEncode)
//!   traits for archive formats.  Each format provides a zero-sized codec struct
//!   (e.g. `Bzip2Codec`, `TarCodec`) implementing these traits.
//! - [`traits_io`] (requires `std`) adds [`DecodeReader`](traits_io::DecodeReader)
//!   and [`EncodeWriter`](traits_io::EncodeWriter) for `std::io` adapters.
//!
//! # Documentation map
//!
//! - `README.md`: quick start, supported-format overview, and package entry points
//! - `docs/spec/`: canonical conformance, interoperability scope,
//!   spec-to-test mapping, intentional unsupported features, and future candidates
//! - `archive-cli`: terminal entry point for inspect/list/extract/pack/compress flows
//! - `archive-fuzz`: auxiliary validation lane for roundtrip, interop, and regression export
//!
//! Quick status guide:
//! - Known bugs: none are currently listed as open
//! - Intentionally unsupported features: see `docs/spec/README.md` section
//!   "実装対象外フォーマット" and each format's `intentional exclusion`
//! - Future candidates: see `docs/spec/README.md` section "次の library 実装候補"
//!
//! # Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `std` (default) | Enables `std::error::Error` and `std::io` adapters |
//! | `deflate` | Raw DEFLATE stream support |
//! | `gzip` (default) | gzip format (auto-enables `deflate`) |
//! | `zstd` (default) | zstd format |
//! | `bzip2` (default) | bzip2 format |
//! | `lzip` (default) | lzip format (LZMA) |
//! | `lzma-alone` (default) | LZMA-Alone `.lzma` format |
//! | `lzw` (default) | LZW / Unix compress (`.Z`) format |
//! | `lz4` (default) | LZ4 frame format and raw block codec |
//! | `lzo` (default) | LZO / lzop format |
//! | `rzip` (default) | rzip long-range redundancy reduction (auto-enables `bzip2`) |
//! | `zlib` (default) | zlib format (auto-enables `deflate`) |
//! | `brotli` | Brotli format |
//! | `zpaq` (default) | ZPAQ context-mixing compression |
//! | `lrzip` (default) | lrzip format (auto-enables `lzip`, `bzip2`, `lzo`, `zlib`, `zpaq`, `rzip`) |
//! | `xz` (default) | xz format (auto-enables `lzip`) |
//! | `snappy` (default) | Snappy raw/framed format |
//! | `xca` (default) | MS-XCA Xpress / Xpress Huffman / LZNT1 codecs |
//! | `lzf` (default) | LZF (liblzf) raw codec |
//! | `fastlz` (default) | FastLZ raw codec (level 1/2) |
//! | `zx0` (default) | ZX0 raw codec |
//! | `zx1` (default) | ZX1 raw codec |
//! | `zx2` (default) | ZX2 raw codec |
//! | `zx5` (default) | ZX5 raw codec |
//! | `vcdiff` (default) | VCDIFF (RFC 3284) delta codec |
//! | `mppc` (default) | MPPC packet codec (RFC 2118, RDP 4.0/5.0 bulk) |
//! | `lzs` (default) | Stac LZS (RFC 2395) datagram codec |
//! | `lzrw1` (default) | LZRW1 raw codec |
//! | `lzrw1a` (default) | LZRW1-A raw codec |
//! | `lzrw2` (default) | LZRW2 raw codec |
//! | `lzrw3` (default) | LZRW3 raw codec |
//! | `lzrw3a` (default) | LZRW3-A raw codec |
//! | `lzsa` (default) | LZSA stream / LZSA1 / LZSA2 raw codecs |
//! | `lzxd` (default) | LZX DELTA (MS-PATCH) codec (decode; uncompressed-block encode) |
//! | `cmpsc` (default) | IBM CMPSC (z/Arch compression call) codec |
//! | `packbits` (default) | PackBits RLE codec (Apple TN1023 / TIFF §9) |
//! | `uuencode` (default) | uuencode historical and Base64 algorithms (POSIX.1-2017) |
//! | `ascii85` (default) | Ascii85 (Adobe ASCII85Decode + RFC 1924) |
//! | `yenc` (default) | yEnc binary-to-text encoding (draft 1.3) |
//! | `macbinary` (default) | MacBinary II container format |
//! | `binhex` (default) | BinHex 4.0 (.hqx) encoding |
//! | `tar` (default) | tar archive format |
//! | `cpio` (default) | cpio archive format |
//! | `ar` (default) | GNU/BSD `ar` archive format |
//! | `deb` (default) | Debian binary package (`.deb`) read/write support |
//! | `rpm` (default) | RPM package (`.rpm`) read/write support |
//! | `squashfs` (default) | SquashFS image read/write support |
//! | `mscab` (default) | Microsoft Cabinet (`.cab`) read/write support (stored/MSZIP write; Quantum/LZX read) |
//! | `mscfb` (default) | Microsoft Compound File Binary (OLE2) read/write support |
//! | `cramfs` (default) | Linux cramfs filesystem image read/write |
//! | `romfs` (default) | Linux romfs filesystem image read/write |
//! | `erofs` (default) | Linux erofs filesystem image read (incl. z_erofs LZ4/MicroLZMA/DEFLATE/Zstd, metabox) / uncompressed flat-layout write |
//! | `iso9660` (default) | ISO 9660 CD-ROM image read/write (write: Rock Ridge; read: Rock Ridge / Joliet / XA) |
//! | `crx3` (default) | Chrome extension package (CRX3/CRX2) read support |
//! | `pea` (default) | PEA (Pack, Encrypt, Authenticate) archive read/write support (stored/PCOMPRESS2 deflate write; AES encrypted-stream decode; multi-volume join) |
//! | `zim` (default) | ZIM archive (`.zim`) read/write support (v5/v6 write) |
//! | `mtree` (default) | mtree(5) manifest read/write support |
//! | `warc` (default) | WARC (`.warc`) record read/write support |
//! | `git-pack` (default) | Git pack (`pack-*.pack`/`pack-*.idx`) read/write support |
//! | `xar` (default) | XAR (`.xar`) archive read/write support |
//! | `lha` (default) | LHA/LZH archive support (header levels 0-3 read/write; lh0-lh7/LArc/PMarc decode, lh0/lz4/pm0/lh4-lh7/lzs/lz5 write + pm1/pm2 literal) |
//! | `arj` (default) | ARJ archive support (stored + methods 1-4 + no-data 8/9 decode incl. garbled/multi-volume, methods 0-4 write incl. multi-volume) |
//! | `arc` (default) | SEA ARC archive support (method 1-9/0xa/0xb read/write; ARC 6.0+ info/control items skipped on read) |
//! | `zip` | ZIP archive format |
//! | `sevenz` | 7z archive format |
//!
//! For `no_std` environments, use `default-features = false` and enable only
//! the features you need.
//!
//! Selected scope notes:
//! - `rzip` decodes upstream `.rz` archives and exposes a crate-local encoder for
//!   the documented container/token subset; current encode output is validated
//!   for crate roundtrip plus direct text, binary, and level-1 multi-chunk
//!   `system rzip -d` interoperability.
//! - `lrzip` reuses the shared long-range match finder but encodes lrzip's
//!   variable-width token stream inside a bounded `.lrz` container contract;
//!   current coverage includes system-authored simple and match-rich LZMA decode
//!   plus crate encode consumed by system `lrzip -d` across the supported
//!   backend matrix.
//! - `lzip`, `lzma-alone`, `xz`, `lrzip`, and `sevenz` reuse the shared internal `compress::lzma` codec. `xz` and `sevenz` additionally use `compress::lzma2` for chunked LZMA2 paths. `xz` / `lrzip` / `lzma-alone` decoders accept arbitrary valid `lc/lp/pb` within the shared literal-context limit (`lc+lp<=4`); current encoders still emit the default `3/0/2` property tuple.
//! - `brotli` decoder supports the full RFC 7932 stream format. The encoder emits compressed metablocks (literal-only, LSB6 context-modeled, two-block-type, or single-block LZ77 variants; the first strategy in this order that beats the uncompressed size is used) with insert-and-copy commands, static dictionary identity references, metadata metablocks, and multi-metablock splitting, falling back to uncompressed metablocks; output is validated against the crate decoder and system `brotli -d`.
//! - `zip` supports baseline Store/Deflate read/write, ZIP64, Data Descriptor, CP437/UTF-8 metadata, traditional PKZIP encrypted entries, and WinZip AES-128/192/256 entry read/write.
//! - `sevenz` supports plain/encoded headers, multi-folder decode for the current supported folder DAG subset, password-based 7zAES decode for those folders and encoded headers, x86 BCJ2 decode for supported DAG layouts, and bounded writing with one or two linear folders using LZMA2/LZMA/PPMdH/Deflate/BZip2/Copy plus x86 BCJ / Delta filters, including linear 7zAES file-content encryption and encoded-header write. Current direct `system 7z` interop coverage includes baseline one-folder archives, one-folder/two-folder PPMd including encoded-header and encrypted/encrypted+encoded-header PPMd, two-folder encrypted / encoded-header / encrypted+encoded-header variants, and one-folder / two-folder x86 BCJ / Delta writer combinations including encoded-header and encrypted filter variants. The decoder normalizes folder graphs to explicit input-source / output-owner / final-root metadata and executes them through a demand-driven cached evaluator. Upstream interface audit shows that the current method surface uses single-stream interfaces for `Copy`, `LZMA`, `LZMA2`, `PPMdH`, `Delta`, `7zAES`, `Deflate`, `Deflate64`, and `BZip2`, while `BCJ2` remains the only fixed 4-input multi-stream coder. Non-`BCJ2` multi-input or multi-output declarations are therefore rejected as nonstandard arity instead of being treated as pending feature work.
//! - `xz` supports LZMA2 final filters, the standard BCJ / Delta prefilter set, and registry-backed custom filter IDs on encode/decode paths plus the reader adapters. `FilterRegistry::register_passthrough()` provides an identity codec for application-defined custom IDs, while unregistered custom filters are preserved at parse time but still fail explicitly when application is attempted.
//! - ZPAQ is exposed as two layers: `compress::zpaq` for the low-level codec and `archive::zpaq` for multi-entry archives. The low-level codec is wire-compatible with upstream ZPAQ/libzpaq: it decodes upstream-produced streams (modeled levels 1-3, unmodeled n=0 stored streams, and PROG segments carrying PCOMP postprocessor programs) and produces streams that upstream decodes. The encoder supports the built-in upstream level `1..=3` models plus a validated `CustomModel` surface for arbitrary predictor/HCOMP authoring; emitted segments use the PASS postprocessor by default, with opt-in PCOMP/PROG emission through `CustomModel::with_pcomp`. The upstream `.cfg` config language is compiled by `compress::zpaq::config::compile_config` into a bridgeable model. The archive layer covers multi-entry sequential-segment archives, append-as-new-block workflows that reuse an existing parsed header/model, crate-local journaling transactions with committed latest-view / version-history helpers, upstream JIDAC journaling streams via `archive::zpaq::jidac` (decode, single-transaction emit, and incremental append with content-defined fragmenting and SHA-1 deduplication), and a materializing `ZpaqArchiveEditor` that can import plain archives or the latest journal view, apply push/put/delete operations, and rewrite one archive. The decoder acceptance corpus includes committed upstream-produced fixtures covering the built-in level 1-3 predictor component mix (7 of the 9 upstream component types; `CM` and `AVG` are exercised through a dedicated `CustomModel` roundtrip), stored and PROG segments, malformed-input rejection (missing locator, truncation, invalid level/type bytes, incomplete COMP records, checksum corruption), and multi-segment archive metadata plus empty-payload boundaries. The archive encoder rejects embedded NUL bytes in filename/comment metadata because those fields are stored as NUL-terminated strings.
//!
//! # Decompression bomb protection
//!
//! Codecs expose `decode_bounded`, and [`traits::Decode`] takes
//! `max_output`. Several of those checks run only after the codec has
//! produced the full output, so peak memory can exceed `max_output`.
//! `lzma_alone`, `xz`, and `rzip` document that post-hoc check. A header
//! field that is itself the allocation or loop bound is rejected above
//! 1 GiB for PPMd output, ZIP methods 2–6, 14, 16, and 98, 7z PPMd, LZMA,
//! and BCJ2, git-pack delta results, and the shared LZMA decoder when an
//! expected size is supplied. Unknown-size LZMA, 7z methods that size the
//! buffer from the packed input, and non-LZMA lrzip blocks are outside
//! that ceiling. PPMd decode also refuses a model larger than 256 MiB.
//! `decode` without `max_output` stays unlimited except for those fields.
//!
//! ```
//! # #[cfg(feature = "bzip2")] {
//! use archive::traits::{Decode, Encode};
//! use archive::compress::bzip2::Bzip2Codec;
//!
//! let codec = Bzip2Codec;
//! let compressed = codec.encode(b"hello world", &()).unwrap();
//!
//! // Bounded decode — rejects output larger than 5 bytes
//! let err = codec.decode(&compressed, Some(5)).unwrap_err();
//! assert!(matches!(err, archive::error::Error::OutputLimitExceeded { .. }));
//!
//! // Unbounded decode — no limit
//! let data = codec.decode(&compressed, None).unwrap();
//! assert_eq!(data, b"hello world");
//! # }
//! ```
//!
//! # Examples
//!
//! ## DEFLATE compression
//!
//! ```
//! # #[cfg(feature = "deflate")] {
//! use archive::compress::deflate::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data, encode::Level::Default);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## gzip compression
//!
//! ```
//! # #[cfg(all(feature = "gzip", feature = "deflate"))] {
//! use archive::compress::gzip::{decode, encode};
//! use archive::compress::deflate::encode::Level;
//!
//! let data = b"Hello, World!";
//! let gz = encode::encode(data, Level::Default);
//! let decoded = decode::decode(&gz).unwrap();
//! assert_eq!(decoded, data);
//! # }
//! ```
//!
//! ## bzip2 compression
//!
//! ```
//! # #[cfg(feature = "bzip2")] {
//! use archive::compress::bzip2::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## lzip compression
//!
//! ```
//! # #[cfg(feature = "lzip")] {
//! use archive::compress::lzip::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## LZ4 compression
//!
//! ```
//! # #[cfg(feature = "lz4")] {
//! use archive::compress::lz4::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## LZO compression
//!
//! ```
//! # #[cfg(feature = "lzo")] {
//! use archive::compress::lzo::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## zlib compression
//!
//! ```
//! # #[cfg(feature = "zlib")] {
//! use archive::compress::zlib::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## ZPAQ compression
//!
//! ```
//! # #[cfg(feature = "zpaq")] {
//! use archive::compress::zpaq::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data, 1);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## lrzip compression
//!
//! ```
//! # #[cfg(feature = "lrzip")] {
//! use archive::compress::lrzip::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## lrzip with backend selection
//!
//! ```
//! # #[cfg(feature = "lrzip")] {
//! use archive::compress::lrzip::{decode, encode};
//! use archive::compress::lrzip::encode::CompressionType;
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode_with(data, CompressionType::Bzip2);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## xz compression
//!
//! ```
//! # #[cfg(feature = "xz")] {
//! use archive::compress::xz::{decode, encode};
//!
//! let data = b"Hello, World!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## Snappy compression
//!
//! ```
//! # #[cfg(feature = "snappy")] {
//! use archive::compress::snappy::{decode, encode};
//!
//! let data = b"Hello, Snappy!";
//! let compressed = encode::encode(data);
//! let decompressed = decode::decode(&compressed).unwrap();
//! assert_eq!(decompressed, data);
//! # }
//! ```
//!
//! ## tar archive (GNU mode)
//!
//! ```
//! # #[cfg(feature = "tar")] {
//! use archive::archive::tar::{decode, encode};
//!
//! let mut enc = encode::TarEncoder::new();
//! enc.add_file("hello.txt", b"Hello!");
//! let tar_data = enc.finish();
//! let entries = decode::decode(&tar_data).unwrap();
//! assert_eq!(entries[0].header.name, "hello.txt");
//! # }
//! ```
//!
//! ## ar archive
//!
//! ```
//! # #[cfg(feature = "ar")] {
//! use archive::archive::ar::{decode, encode};
//!
//! let mut enc = encode::ArEncoder::new();
//! enc.add_file("hello.txt", b"Hello!");
//! let archive = enc.finish().unwrap();
//! let entries = decode::decode(&archive).unwrap();
//! assert_eq!(entries[0].name, "hello.txt");
//! assert_eq!(entries[0].data, b"Hello!");
//! # }
//! ```
//!
//! ## ZIP archive
//!
//! ```
//! # #[cfg(feature = "zip")] {
//! use archive::archive::zip::{decode, encode};
//!
//! let mut encoder = encode::ZipEncoder::new();
//! encoder.add_file("hello.txt", b"Hello ZIP!");
//! let archive = encoder.finish().unwrap();
//! let entries = decode::decode(&archive).unwrap();
//! assert_eq!(entries[0].name, "hello.txt");
//! assert_eq!(entries[0].data, b"Hello ZIP!");
//! # }
//! ```
//!
//! ```no_run
//! # #[cfg(all(feature = "zip", feature = "std"))] {
//! use std::fs::File;
//! use archive::archive::zip::encode::{ZipEntryOptions, ZipStreamWriter};
//!
//! let file = File::create("streamed.zip").unwrap();
//! let mut writer = ZipStreamWriter::new(file);
//! writer
//!     .write_file_from_reader("hello.txt", "Hello ZIP!".as_bytes(), &ZipEntryOptions::default())
//!     .unwrap();
//! let _file = writer.finish().unwrap();
//! # }
//! ```
//!
//! ## ZPAQ archive
//!
//! ```
//! # #[cfg(feature = "zpaq")] {
//! use archive::archive::zpaq::{decode, encode};
//!
//! let mut encoder = encode::ZpaqEncoder::new(2);
//! encoder.add_file("hello.txt", b"Hello ZPAQ archive!");
//! let archive = encoder.finish().unwrap();
//! let entries = decode::decode(&archive).unwrap();
//! assert_eq!(entries[0].filename_utf8(), Some("hello.txt"));
//! assert_eq!(entries[0].data, b"Hello ZPAQ archive!");
//! # }
//! ```
//!
//! ## ZPAQ journal archive
//!
//! ```
//! # #[cfg(feature = "zpaq")] {
//! use archive::archive::zpaq::{decode, encode};
//!
//! let mut tx1 = encode::ZpaqJournalEncoder::new(1);
//! tx1.put_file("hello.txt", b"one");
//! let mut archive = tx1.finish().unwrap();
//!
//! let mut tx2 = encode::ZpaqJournalEncoder::new(1);
//! tx2.put_file_with_comment("hello.txt", "v2", b"two");
//! archive = tx2.append_transaction(&archive).unwrap();
//!
//! let latest = decode::decode_journal_latest(&archive).unwrap();
//! assert_eq!(latest.len(), 1);
//! assert_eq!(latest[0].comment_utf8(), Some("v2"));
//! assert_eq!(latest[0].data, b"two");
//! # }
//! ```
//!
//! ## tar archive (PAX mode)
//!
//! ```
//! # #[cfg(feature = "tar")] {
//! use archive::archive::tar::{decode, encode};
//!
//! let mut enc = encode::TarEncoder::new_pax();
//! enc.add_file("hello.txt", b"Hello!");
//! let tar_data = enc.finish();
//! let entries = decode::decode(&tar_data).unwrap();
//! assert_eq!(entries[0].header.name, "hello.txt");
//! # }
//! ```
//!
//! ## Combined: tar.gz
//!
//! ```no_run
//! # #[cfg(all(feature = "gzip", feature = "tar", feature = "std"))] {
//! use archive::compress::gzip;
//! use archive::archive::tar;
//!
//! let gz_data = std::fs::read("archive.tar.gz").unwrap();
//! let tar_data = gzip::decode::decode(&gz_data).unwrap();
//! let entries = tar::decode::decode(&tar_data).unwrap();
//! for entry in &entries {
//!     println!("{}: {} bytes", entry.header.name, entry.data.len());
//! }
//! # }
//! ```
//!
//! ## `std::io` adapters
//!
//! With the `std` feature enabled, reader/writer adapters are available:
//!
//! ```no_run
//! # #[cfg(all(feature = "std", feature = "gzip", feature = "zstd", feature = "deflate"))] {
//! use archive::compress::gzip;
//! use archive::compress::zstd;
//! use archive::compress::deflate::encode::Level;
//!
//! // Decode from std::io::Read
//! let reader = std::fs::File::open("data.gz").unwrap();
//! let data = gzip::decode::decode_reader(reader).unwrap();
//!
//! // Encode to std::io::Write
//! let mut output = Vec::new();
//! gzip::encode::encode_writer(&data, Level::Default, &mut output).unwrap();
//! # }
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

/// Unified error types for all formats.
pub mod error;

/// Common traits for compression and archive operations.
pub mod traits;

/// `std::io` adapter traits for compression codecs.
#[cfg(feature = "std")]
pub mod traits_io;

/// Utility modules: CRC32, XXH64, bit reader.
pub(crate) mod util;

/// Compression formats and shared filters: DEFLATE, gzip, zlib, zstd, bzip2, lzip, `.lzma`, LZW, LZ4, LZO, lrzip, xz, Snappy, Brotli, ZPAQ, MS-XCA, LZF, FastLZ, LZRW1-A, plus BCJ/Delta helpers.
#[cfg(any(
    feature = "deflate",
    feature = "gzip",
    feature = "zstd",
    feature = "bzip2",
    feature = "lzip",
    feature = "lzma-alone",
    feature = "lzw",
    feature = "lz4",
    feature = "lzo",
    feature = "lrzip",
    feature = "xz",
    feature = "rzip",
    feature = "zlib",
    feature = "zpaq",
    feature = "snappy",
    feature = "brotli",
    feature = "xca",
    feature = "lzf",
    feature = "fastlz",
    feature = "lzrw1",
    feature = "lzrw1a",
    feature = "lzrw2",
    feature = "lzrw3",
    feature = "lzrw3a",
    feature = "lzsa",
    feature = "zx0",
    feature = "zx1",
    feature = "zx2",
    feature = "zx5",
    feature = "vcdiff",
    feature = "mppc",
    feature = "lzs",
    feature = "lzxd",
    feature = "cmpsc",
    feature = "packbits",
    feature = "lha",
    feature = "arj",
    feature = "erofs"
))]
pub mod compress;

/// Archive formats: tar, cpio, ar, deb, rpm, squashfs, cramfs, romfs, erofs, iso9660, crx3, pea, mscab, mscfb, zim, mtree, warc,
/// git pack, xar,
/// lha, arj, arc, zpaq, zip, and 7z.
#[cfg(any(
    feature = "tar",
    feature = "cpio",
    feature = "ar",
    feature = "deb",
    feature = "rpm",
    feature = "squashfs",
    feature = "cramfs",
    feature = "romfs",
    feature = "erofs",
    feature = "iso9660",
    feature = "crx3",
    feature = "pea",
    feature = "mscab",
    feature = "mscfb",
    feature = "zim",
    feature = "mtree",
    feature = "warc",
    feature = "git-pack",
    feature = "xar",
    feature = "lha",
    feature = "arj",
    feature = "arc",
    feature = "zpaq",
    feature = "zip",
    feature = "sevenz",
))]
pub mod archive;

/// Byte encodings: uuencode, Ascii85, yEnc, MacBinary, BinHex.
#[cfg(any(
    feature = "uuencode",
    feature = "ascii85",
    feature = "yenc",
    feature = "macbinary",
    feature = "binhex"
))]
pub mod encoding;
