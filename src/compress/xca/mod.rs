//! Microsoft Xpress Compression Algorithms ([MS-XCA]).
//!
//! Three LZ77-derived codecs used by Windows protocols (SMB, WOF, NTFS):
//!
//! - [`lz77`]: Plain LZ77 — 32-bit flag groups, fixed 13-bit offset / 3-bit
//!   length match words, nibble-packed extended lengths. Also known as
//!   "Xpress" or `COMPRESSION_FORMAT_XPRESS`.
//! - [`huffman`]: LZ77+Huffman — 64 KiB blocks, 512-symbol canonical Huffman
//!   over literals and match classes. Also known as "Xpress Huffman" or
//!   `COMPRESSION_FORMAT_XPRESS_HUFF`.
//! - [`lznt1`]: LZNT1 — chunked format (4 KiB uncompressed per chunk) with
//!   byte-aligned flag groups and position-dependent match word layout.
//!   Used by NTFS compression and `COMPRESSION_FORMAT_LZNT1`.
//!
//! [MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/

pub mod huffman;
pub mod lz77;
pub mod lznt1;
