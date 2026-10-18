//! Predefined ZPAQ model headers for levels 1-3.
//!
//! These are the canonical model headers embedded in upstream libzpaq
//! (`Compressor::startBlock`: `min.cfg`, `mid.cfg`, `max.cfg`).  Each
//! blob is a complete serialized ZPAQL header including the 2-byte
//! `hsize` field, the `hh hm ph pm n` preamble, the COMP section with
//! its `0` terminator, and the HCOMP program with its `0` terminator.
//! The 128-byte guard gap is implicit in the parsed representation and
//! is not stored here.

use crate::error::Error;

use super::zpaql::Zpaql;

/// Level 1 header (upstream `min.cfg`). `hsize = 26`.
pub(crate) const MODEL_LEVEL1: &[u8] = &[
    26, 0, 1, 2, 0, 0, 2, 3, 16, 8, 19, 0, 0, 96, 4, 28, 59, 10, 59, 112, 25, 10, 59, 10, 59, 112,
    56, 0,
];

/// Level 2 header (upstream `mid.cfg`). `hsize = 69`.
pub(crate) const MODEL_LEVEL2: &[u8] = &[
    69, 0, 3, 3, 0, 0, 8, 3, 5, 8, 13, 0, 8, 17, 1, 8, 18, 2, 8, 18, 3, 8, 19, 4, 4, 22, 24, 7, 16,
    0, 7, 24, 255, 0, 17, 104, 74, 4, 95, 1, 59, 112, 10, 25, 59, 112, 10, 25, 59, 112, 10, 25, 59,
    112, 10, 25, 59, 112, 10, 25, 59, 10, 59, 112, 25, 69, 207, 8, 112, 56, 0,
];

/// Level 3 header (upstream `max.cfg`). `hsize = 196`.
pub(crate) const MODEL_LEVEL3: &[u8] = &[
    196, 0, 5, 9, 0, 0, 22, 1, 160, 3, 5, 8, 13, 1, 8, 16, 2, 8, 18, 3, 8, 19, 4, 8, 19, 5, 8, 20,
    6, 4, 22, 24, 3, 17, 8, 19, 9, 3, 13, 3, 13, 3, 13, 3, 14, 7, 16, 0, 15, 24, 255, 7, 8, 0, 16,
    10, 255, 6, 0, 15, 16, 24, 0, 9, 8, 17, 32, 255, 6, 8, 17, 18, 16, 255, 9, 16, 19, 32, 255, 6,
    0, 19, 20, 16, 0, 0, 17, 104, 74, 4, 95, 2, 59, 112, 10, 25, 59, 112, 10, 25, 59, 112, 10, 25,
    59, 112, 10, 25, 59, 112, 10, 25, 59, 10, 59, 112, 10, 25, 59, 112, 10, 25, 69, 183, 32, 239,
    64, 47, 14, 231, 91, 47, 10, 25, 60, 26, 48, 134, 151, 20, 112, 63, 9, 70, 223, 0, 39, 3, 25,
    112, 26, 52, 25, 25, 74, 10, 4, 59, 112, 25, 10, 4, 59, 112, 25, 10, 4, 59, 112, 25, 65, 143,
    212, 72, 4, 59, 112, 8, 143, 216, 8, 68, 175, 60, 60, 25, 69, 207, 9, 112, 25, 25, 25, 25, 25,
    112, 56, 0,
];

/// Build the [`Zpaql`] header for a built-in model `level` (1-3).
///
/// The blob is parsed through [`Zpaql::read`], so structural errors in
/// a table surface as header errors rather than silent misreads.
pub(crate) fn model_zpaql(level: u32) -> Result<Zpaql, Error> {
    let blob = match level {
        1 => MODEL_LEVEL1,
        2 => MODEL_LEVEL2,
        _ => MODEL_LEVEL3,
    };
    let mut z = Zpaql::new();
    let mut pos = 0;
    z.read(blob, &mut pos)?;
    debug_assert_eq!(pos, blob.len());
    Ok(z)
}

/// Built-in level whose header is `z`, if it is one of levels 1-3.
pub(crate) fn builtin_level(z: &Zpaql) -> Option<u32> {
    if z.is_model(MODEL_LEVEL1) {
        Some(1)
    } else if z.is_model(MODEL_LEVEL2) {
        Some(2)
    } else if z.is_model(MODEL_LEVEL3) {
        Some(3)
    } else {
        None
    }
}
