//! Utility modules shared across formats.

/// CRC32 (IEEE) checksum computation.
pub(crate) mod crc32;

/// CRC-16/ARC checksum for LHA and SEA ARC.
#[cfg(any(feature = "lha", feature = "arc"))]
pub(crate) mod crc16;

/// CRC-16/CCITT checksum for MacBinary II and BinHex 4.0.
#[cfg(any(feature = "macbinary", feature = "binhex"))]
pub(crate) mod crc16ccitt;

/// CRC32C (Castagnoli) checksum for Snappy framing and erofs.
#[cfg(any(feature = "snappy", feature = "erofs"))]
pub(crate) mod crc32c;

/// LSB-first bit reader for DEFLATE and zstd streams.
#[cfg(any(feature = "deflate", feature = "zstd"))]
pub(crate) mod bitreader;

/// Shared range coder for LZMA-style entropy coding.
#[cfg(any(
    feature = "lzip",
    feature = "lrzip",
    feature = "xz",
    feature = "sevenz",
))]
pub(crate) mod range_coder;

/// XXH64/XXH32 hashes for zstd and LZ4 checksums.
#[cfg(any(feature = "zstd", feature = "lz4"))]
pub(crate) mod xxhash;

/// Adler-32 checksum for LZO/lzop and zlib.
#[cfg(any(feature = "lzo", feature = "zlib", feature = "vcdiff"))]
pub(crate) mod adler32;

/// CRC-64/XZ checksum for xz and PEA integrity tags.
#[cfg(any(feature = "xz", feature = "pea"))]
pub(crate) mod crc64;

/// SHA-256 for xz SHA-256 integrity checks, SHA-256 git pack object IDs,
/// PEA integrity tags, XAR "sha256" digests, CRX3 crx_id checks, and
/// RPM digest tags.
#[cfg(any(
    feature = "xz",
    feature = "sevenz",
    feature = "git-pack",
    feature = "pea",
    feature = "xar",
    feature = "crx3",
    feature = "rpm"
))]
pub(crate) mod sha256;

/// SHA-1 for ZIP AES key derivation, git pack object IDs/checksums,
/// WARC digests, PEA integrity tags, ZPAQ segment checksums, and RPM
/// digest tags.
#[cfg(any(
    feature = "zip",
    feature = "git-pack",
    feature = "xar",
    feature = "warc",
    feature = "pea",
    feature = "zpaq",
    feature = "rpm"
))]
pub(crate) mod sha1;

/// MD5 for lrzip file-level integrity verification, XAR checksums,
/// ZIM trailer checksums, PEA integrity tags, and RPM digest tags.
#[cfg(any(
    feature = "lrzip",
    feature = "xar",
    feature = "zim",
    feature = "pea",
    feature = "rpm"
))]
pub(crate) mod md5;

/// SHA-512 for XAR "sha512" digests and RPM payload digests.
#[cfg(any(feature = "xar", feature = "rpm"))]
pub(crate) mod sha512;

/// AES helpers for encrypted 7z, ZIP, and PEA streams.
#[cfg(any(feature = "sevenz", feature = "zip", feature = "pea"))]
pub(crate) mod aes256;

/// Whirlpool hash for PEA AES-256 EAX key derivation and XAR digests.
#[cfg(any(feature = "pea", feature = "xar"))]
pub(crate) mod whirlpool;

/// PBKDF2 (RFC 2898) key derivation for PEA encrypted streams.
#[cfg(feature = "pea")]
pub(crate) mod pbkdf2;

/// AES OMAC/CTR/EAX helpers for PEA authenticated-encryption streams.
#[cfg(feature = "pea")]
pub(crate) mod eax;

/// Output size limit helpers for decompression bomb protection.
pub(crate) mod bounded;

/// Base64 (RFC 4648) codec for the POSIX uuencode Base64 algorithm.
#[cfg(feature = "uuencode")]
pub(crate) mod base64;
