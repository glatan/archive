//! Compression format implementations.
//!
//! Public modules in this tree expose bounded encode/decode APIs for individual
//! formats. Shared codec/filter cores such as BCJ, Delta, LZMA, LZMA2, and PPMd
//! live here as internal building blocks for archive/container formats too.

/// Overlap-safe match copies and bounded match lengths shared by LZ codecs.
///
/// Compiled only when a caller feature is on. Each function is further
/// limited to the features that call it, so an unused helper is not
/// silenced by a single caller's feature.
#[cfg(any(
    test,
    feature = "deflate",
    feature = "zstd",
    feature = "lzs",
    feature = "lzo",
    feature = "vcdiff",
    feature = "xca",
    feature = "snappy",
    feature = "fastlz",
    feature = "lz4",
    feature = "brotli",
    feature = "rzip",
    feature = "lzip",
    feature = "lzma-alone",
    feature = "erofs",
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
    feature = "packbits",
    feature = "mppc",
    feature = "lha",
    feature = "arj",
    feature = "mscab",
    feature = "lzxd",
    feature = "lzf",
))]
pub(crate) mod match_ops;

/// First-byte scan shared by BCJ and LZX.
pub(crate) mod scan;

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

/// Shared LZMA1 codec used by lzip/xz/lrzip/7z-style formats, `.lzma`,
/// ZIP method 14, and EROFS microlzma.
#[cfg(any(
    feature = "lzip",
    feature = "xz",
    feature = "sevenz",
    feature = "lrzip",
    feature = "lzma-alone"
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

/// LZMA-Alone `.lzma` compression and decompression.
///
/// A 13-byte header (properties, dictionary size, uncompressed size)
/// followed by a raw LZMA stream.
#[cfg(feature = "lzma-alone")]
pub mod lzma_alone;

/// LZH compression family shared by the LHA and ARJ formats
/// (MSB bit stream + static-Huffman "st1" block decoder and
/// its `st1_enc` encoder counterpart).
#[cfg(any(feature = "lha", feature = "arj"))]
pub(crate) mod lzh;

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

/// Microsoft Xpress Compression Algorithms ([MS-XCA]):
/// plain LZ77 ("Xpress"), LZ77+Huffman ("Xpress Huffman"), and LZNT1.
///
/// [MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/
#[cfg(feature = "xca")]
pub mod xca;

/// FastLZ compression and decompression.
#[cfg(feature = "fastlz")]
pub mod fastlz;

/// Shared framing (copy flag + control-word groups) for the LZRW family.
#[cfg(any(
    feature = "lzrw1",
    feature = "lzrw1a",
    feature = "lzrw2",
    feature = "lzrw3",
    feature = "lzrw3a"
))]
mod lzrw;

/// LZRW1 compression and decompression.
#[cfg(feature = "lzrw1")]
pub mod lzrw1;

/// LZRW1-A compression and decompression.
#[cfg(feature = "lzrw1a")]
pub mod lzrw1a;

/// LZRW2 compression and decompression.
#[cfg(feature = "lzrw2")]
pub mod lzrw2;

/// LZRW3 compression and decompression.
#[cfg(feature = "lzrw3")]
pub mod lzrw3;

/// LZRW3-A compression and decompression.
#[cfg(feature = "lzrw3a")]
pub mod lzrw3a;

/// LZSA stream and raw block compression/decompression.
#[cfg(feature = "lzsa")]
pub mod lzsa;

/// ZX0 compression and decompression.
#[cfg(feature = "zx0")]
pub mod zx0;

/// ZX1 compression and decompression.
#[cfg(feature = "zx1")]
pub mod zx1;

/// ZX2 compression and decompression.
#[cfg(feature = "zx2")]
pub mod zx2;

/// ZX5 compression and decompression.
#[cfg(feature = "zx5")]
pub mod zx5;

/// IBM CMPSC "Compression Call" basic method (LZ78 family), per
/// SA22-7832 Appendix D / SA22-7208.
#[cfg(feature = "cmpsc")]
pub mod cmpsc;
/// Stac LZS compression/decompression (RFC 2395 section 2.2).
#[cfg(feature = "lzs")]
pub mod lzs;
/// MPPC compression/decompression (RFC 2118): packet-oriented LZ77 with an
/// 8192-byte history, packet flags, and a 12-bit coherency count.
#[cfg(feature = "mppc")]
pub mod mppc;
/// VCDIFF delta compression/decompression (RFC 3284).
#[cfg(feature = "vcdiff")]
pub mod vcdiff;

/// LZX DELTA decompression ([MS-PATCH]): delta-compressed streams with
/// caller-supplied reference data, used by Exchange Offline Address Book
/// differential patches.
///
/// [MS-PATCH]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/
#[cfg(feature = "lzxd")]
pub mod lzxd;

/// Shared LZX decompression core for the Cabinet ([MS-CAB]
/// tcompTYPE_LZX) and LZX DELTA ([MS-PATCH]) variants.
///
/// [MS-CAB]: https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10)
/// [MS-PATCH]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/
#[cfg(any(feature = "lzxd", feature = "mscab"))]
pub(crate) mod lzx;
/// PackBits run-length encoding (Apple TN1023 / TIFF 6.0 §9).
#[cfg(feature = "packbits")]
pub mod packbits;

/// LZF compression and decompression (liblzf format).
#[cfg(feature = "lzf")]
pub mod lzf;

/// Snappy compression and decompression.
#[cfg(feature = "snappy")]
pub mod snappy;

/// Brotli compression and decompression.
///
/// The encoder emits LZ77-compressed metablocks using hash-table matching
/// with literal-only, context-modeling, multi-block-type, and single-block
/// strategies, falling back to uncompressed metablocks when smaller.
#[cfg(feature = "brotli")]
pub mod brotli;

/// Deflate64 (Enhanced Deflating) compression and decompression.
///
/// Extends DEFLATE with a 64KB window, two additional distance codes,
/// and a longer maximum match length. The encoder reuses the DEFLATE
/// encoder restricted to the compatible subset. Used as ZIP method 9
/// and 7z method `04 01 09`.
#[cfg(any(feature = "zip", feature = "sevenz"))]
pub(crate) mod deflate64;

/// Shared PPMd (PPMd var.H / PPMdH) codec, used by 7z and ZIP method 98.
#[cfg(feature = "sevenz")]
pub(crate) mod ppmd;

/// Move `produced` into an empty `output`, or append it otherwise.
///
/// Replacing an empty buffer drops any capacity the caller had reserved.
pub(crate) fn move_into(output: &mut alloc::vec::Vec<u8>, produced: alloc::vec::Vec<u8>) {
    if output.is_empty() {
        *output = produced;
    } else {
        output.extend_from_slice(&produced);
    }
}

#[cfg(test)]
mod tests {
    use super::move_into;

    #[test]
    fn move_into_replaces_empty_and_appends_otherwise() {
        let mut output = alloc::vec::Vec::new();
        move_into(&mut output, alloc::vec![1, 2, 3]);
        assert_eq!(output, [1, 2, 3]);

        let mut kept = alloc::vec![9];
        kept.reserve(32);
        let cap = kept.capacity();
        move_into(&mut kept, alloc::vec![8]);
        assert_eq!(kept, [9, 8]);
        assert!(kept.capacity() >= cap);
    }
}
