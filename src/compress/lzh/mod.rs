//! LZH compression family shared by the `lha` and `arj` archive
//! formats.
//!
//! LZH streams are MSB-first bit streams. The [`st1`] decoder covers
//! the static-Huffman block format used by LHA methods `-lh4-`
//! through `-lh7-` and by ARJ methods 1-3 (15-bit window);
//! [`st1_enc`] is its encoder counterpart.
//!
//! De-facto format references: LHa for UNIX (Yoshizaki, free-use
//! license), lhasa (ISC), and XADMaster's
//! `XADLZHStaticHandle`/`XADLZHOldHandles.m` (The Unarchiver,
//! LGPL-2.1-or-later; see `THIRD_PARTY_NOTICES`). `st1` is
//! behaviour-matched/adapted against them; `st1_enc` is a crate-original
//! encoder counterpart.

pub(crate) mod bits;
pub(crate) mod huf;
pub(crate) mod st1;
pub(crate) mod st1_enc;
