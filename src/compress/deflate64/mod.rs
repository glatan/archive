//! Deflate64 (Enhanced Deflating) decompression.
//!
//! Deflate64 extends DEFLATE with a 64KB sliding window, distance codes 30-31,
//! and a longer maximum match length (65538 vs 258).
//! Used as ZIP compression method 9 (APPNOTE.TXT [section 4.4.5, section 5.6]).

pub(crate) mod decode;
pub(crate) mod encode;
mod tables;
