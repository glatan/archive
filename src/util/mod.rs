//! Utility modules shared across formats.

/// CRC32 (IEEE) checksum computation.
pub(crate) mod crc32;

/// CRC-16/ARC checksum for LHA and SEA ARC.
#[cfg(any(feature = "lha", feature = "arc"))]
pub(crate) mod crc16;

/// CRC-16/CCITT checksum for MacBinary II and BinHex 4.0.
#[cfg(any(feature = "macbinary", feature = "binhex"))]
pub(crate) mod crc16ccitt;

/// CRC32C (Castagnoli) checksum for Snappy framing.
#[cfg(feature = "snappy")]
pub(crate) mod crc32c;

/// LSB-first bit reader for DEFLATE and zstd streams.
#[cfg(any(feature = "deflate", feature = "zstd"))]
pub(crate) mod bitreader;

/// Shared range coder for LZMA / PPMd style entropy coding.
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

/// CRC-64/XZ checksum for xz.
#[cfg(feature = "xz")]
pub(crate) mod crc64;

/// SHA-256 for xz SHA-256 integrity checks.
#[cfg(any(feature = "xz", feature = "sevenz"))]
pub(crate) mod sha256;

/// SHA-1 for ZIP AES key derivation and git pack object IDs/checksums.
#[cfg(any(feature = "zip", feature = "git-pack", feature = "xar"))]
pub(crate) mod sha1;

/// MD5 for lrzip file-level integrity verification and XAR checksums.
#[cfg(any(feature = "lrzip", feature = "xar"))]
pub(crate) mod md5;

/// AES-256 helpers for encrypted 7z and ZIP streams.
#[cfg(any(feature = "sevenz", feature = "zip"))]
pub(crate) mod aes256;

/// DES and Triple DES (3DES) for ZIP Strong Encryption.
#[cfg(feature = "zip")]
pub(crate) mod des;

/// RC2 block cipher for ZIP Strong Encryption.
#[cfg(feature = "zip")]
pub(crate) mod rc2;

/// RC4 stream cipher for ZIP Strong Encryption.
#[cfg(feature = "zip")]
pub(crate) mod rc4;

/// Output size limit helpers for decompression bomb protection.
pub(crate) mod bounded;
