//! LZH compression family shared by the `lha` and `arj` archive
//! formats.
//!
//! LZH streams are MSB-first bit streams. The [`st1`] decoder covers
//! the static-Huffman block format used by LHA methods `-lh4-`
//! through `-lh7-` and by ARJ methods 1-3 (15-bit window).
//!
//! De-facto format reference (behaviour observation only): Okumura's
//! public-domain LHa code and lhasa (ISC).

pub(crate) mod bits;
pub(crate) mod huf;
pub(crate) mod st1;
