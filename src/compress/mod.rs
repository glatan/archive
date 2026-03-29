//! Compression format implementations.
//!
//! Public modules in this tree expose bounded encode/decode APIs for individual
//! formats. Shared codec/filter cores such as BCJ, Delta, LZMA, LZMA2, and PPMd
//! live here as internal building blocks for archive/container formats too.

/// Branch/Call/Jump conversion filters shared by XZ / 7z style formats.
pub mod bcj;

/// Delta filter shared by XZ / 7z style formats.
pub mod delta;

/// DEFLATE compression and decompression ([RFC 1951]).
///
/// [RFC 1951]: https://datatracker.ietf.org/doc/html/rfc1951
#[cfg(feature = "deflate")]
pub mod deflate;

/// gzip compression and decompression ([RFC 1952]).
///
/// [RFC 1952]: https://datatracker.ietf.org/doc/html/rfc1952
#[cfg(feature = "gzip")]
pub mod gzip;

/// Zstandard compression and decompression ([RFC 8878]).
///
/// [RFC 8878]: https://datatracker.ietf.org/doc/html/rfc8878
#[cfg(feature = "zstd")]
pub mod zstd;

/// bzip2 compression and decompression.
#[cfg(feature = "bzip2")]
pub mod bzip2;

/// Shared LZMA1 codec used by lzip/xz/lrzip/7z-style formats.
#[cfg(any(
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip"
))]
pub(crate) mod lzma;

/// Shared LZMA2 codec used by xz and 7z-style formats.
#[cfg(any(feature = "xz", feature = "sevenz"))]
pub(crate) mod lzma2;

/// lzip compression and decompression.
///
/// Uses LZMA with fixed parameters (lc=3, lp=0, pb=2) and a simple
/// framing format with CRC-32 integrity checking.
#[cfg(feature = "lzip")]
pub mod lzip;

/// LZW compression and decompression (Unix compress `.Z` format).
///
/// Variable-width codes (9-16 bits) with optional clear code for
/// dictionary reset.
#[cfg(feature = "lzw")]
pub mod lzw;

/// LZ4 compression and decompression ([LZ4 frame format]).
///
/// Supports the LZ4 frame format with content size, content checksum,
/// and multiple block sizes (64KB-4MB).
///
/// [LZ4 frame format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
#[cfg(feature = "lz4")]
pub mod lz4;

/// LZO compression and decompression (lzop format).
///
/// Implements LZO1X-1 compression wrapped in the lzop file format
/// with Adler-32 checksums.
#[cfg(feature = "lzo")]
pub mod lzo;

/// lrzip (Long Range ZIP) compression and decompression.
///
/// Uses rzip-style long-range redundancy reduction followed by
/// a configurable backend (LZMA, bzip2, LZO, zlib, ZPAQ, or none).
/// The current outer-container contract is crate-local and intentionally
/// narrower than promising full system `lrzip` interchange.
#[cfg(feature = "lrzip")]
pub mod lrzip;

/// rzip long-range redundancy reduction preprocessing.
///
/// Also exposes the public `.rz` container support built on the same token/chunk
/// layer used internally by lrzip.
#[cfg(feature = "rzip")]
pub mod rzip;

/// zlib compression and decompression ([RFC 1950]).
///
/// Wraps raw DEFLATE with a header and Adler-32 checksum.
///
/// [RFC 1950]: https://datatracker.ietf.org/doc/html/rfc1950
#[cfg(feature = "zlib")]
pub mod zlib;

/// ZPAQ compression and decompression.
///
/// Context-mixing compression with arithmetic coding and a
/// ZPAQL virtual machine for context computation.
#[cfg(feature = "zpaq")]
pub mod zpaq;

/// xz compression and decompression ([xz file format]).
///
/// Uses LZMA2 compression with xz stream/block integrity checks plus the
/// supported BCJ / Delta prefilter set and registry-backed custom filters.
///
/// [xz file format]: https://tukaani.org/xz/xz-file-format.txt
#[cfg(feature = "xz")]
pub mod xz;

/// Snappy compression and decompression.
#[cfg(feature = "snappy")]
pub mod snappy;

/// Brotli compression and decompression.
///
/// Decoder support is broader than the current encoder; the public encoder
/// currently emits a bounded baseline uncompressed-metablock stream.
#[cfg(feature = "brotli")]
pub mod brotli;

/// Deflate64 (Enhanced Deflating) decompression.
///
/// Extends DEFLATE with a 64KB window, two additional distance codes,
/// and a longer maximum match length. Used as ZIP method 9.
#[cfg(feature = "zip")]
pub(crate) mod deflate64;

/// Shared PPMd (PPMd var.H / PPMdH) codec, currently used by 7z.
#[cfg(feature = "sevenz")]
pub(crate) mod ppmd;
