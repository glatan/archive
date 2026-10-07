//! LZH "st1" static-Huffman block decoder shared by LHA
//! (`-lh4-`-`-lh7-`) and ARJ (methods 1-3,
//! 15-bit window).
//!
//! The payload is a sequence of blocks. Each block starts with a
//! 16-bit command count, then three serialized code-length tables: a
//! small temp table encoding the main literal/match table, the match
//! table itself, and an offset-length table. A code below 256 is a
//! literal; otherwise it is a match of `code - 256 + 3` bytes at a
//! distance coded as `(1 << (bits - 1)) + low` into a
//! space-filled history ring.
//!
//! Parameters: `hist_bits` is log2 of the history ring (14 for
//! lh4/lh5, 15 for ARJ, 16 for lh6, 17 for lh7) and `offset_bits` is
//! the width of the offset-table symbol count (4 below 15-bit
//! windows, 5 at 15 and above). The serialized table section is
//! self-describing (each table is preceded by its symbol count), so
//! a larger-than-original history ring is a decoding superset: the
//! 14/16/17-bit values are the de facto decoder parameters used by
//! lhasa and cover every stream written by the original LHA/LHa
//! encoders (12/13/15/16-bit dictionaries).
//!
//! Format reference: Haruhiko Okumura's `ar002` distribution
//! (`huf.c`/`decode.c`), which the author released to the public
//! domain — the algorithm inventor's own reference implementation of
//! this block format. `-lh4-`/`-lh5-` use its parameters directly
//! (`DICBIT` 13 documented as "12(-lh4-) or 13(-lh5-)" in `ar.h`);
//! `-lh6-`/`-lh7-` are the same format at the LHa-extended
//! dictionary sizes. Behaviour cross-checked against lhasa
//! `lh_new_decoder.c` (ISC). No code is derived from LHa for UNIX
//! (non-OSI license) or `lzhuf.c` (no license grant).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::MsbReader;
use super::huf::{self, Table};

/// Literal + match alphabet size for all st1 methods.
const NUM_CODES: usize = 510;
/// First match length (codes start at 256).
const COPY_THRESHOLD: usize = 3;
/// Temp-table alphabet size and its count width.
const MAX_TEMP_CODES: usize = (1 << 5) - 1;
const TEMP_CODE_BITS: u32 = 5;
/// Code-table count width.
const CODE_BITS: u32 = 9;
/// Position in the temp table where the 2-bit zero-run insert lives.
const TEMP_SPECIAL: usize = 3;

/// Decode an st1 payload to `expected` bytes.
pub(crate) fn decode(
    hist_bits: u32,
    offset_bits: u32,
    input: &[u8],
    expected: usize,
) -> Result<Vec<u8>, Error> {
    let n = 1usize << hist_bits;
    let max_off = (1usize << offset_bits) - 1;

    let mut out = Vec::with_capacity(expected.min(1 << 24));
    if expected == 0 {
        return Ok(out);
    }
    let mut ring = vec![b' '; n];
    let mut w = 0usize;
    let mut r = MsbReader::new(input);
    let mut remaining = 0usize;
    let mut c_tab = Table::constant(0);
    let mut p_tab = Table::constant(0);

    while out.len() < expected {
        if remaining == 0 {
            remaining = usize::try_from(r.get(16)).unwrap_or(0);
            if r.overran() {
                return Err(Error::InvalidData("lzh: truncated block count"));
            }
            // A block with a zero command count is meaningless in the
            // format; accepting it would underflow `remaining` below.
            if remaining == 0 {
                return Err(Error::InvalidData("lzh: zero block count"));
            }
            let t_tab = huf::read_pt_len(&mut r, MAX_TEMP_CODES, TEMP_CODE_BITS, TEMP_SPECIAL)?;
            c_tab = huf::read_c_len(&mut r, &t_tab, NUM_CODES, CODE_BITS)?;
            p_tab = huf::read_pt_len(&mut r, max_off, offset_bits, usize::MAX)?;
            if r.overran() {
                return Err(Error::InvalidData("lzh: truncated block"));
            }
        }
        remaining -= 1;
        let c = usize::from(c_tab.decode(&mut r)?);
        if c < 256 {
            out.push(c as u8);
            ring[w] = c as u8;
            w = (w + 1) & (n - 1);
        } else {
            // Offset code = bit-length of the distance field.
            let bits = usize::from(p_tab.decode(&mut r)?);
            let offset = match bits {
                0 => 0usize,
                1 => 1,
                _ => (1usize << (bits - 1)) + usize::try_from(r.get(bits as u32 - 1)).unwrap_or(0),
            };
            if r.overran() {
                return Err(Error::InvalidData("lzh: truncated stream"));
            }
            let len = c - 256 + COPY_THRESHOLD;
            let mut src = (w + n - offset - 1) & (n - 1);
            for _ in 0..len {
                if out.len() >= expected {
                    break;
                }
                let v = ring[src];
                out.push(v);
                ring[w] = v;
                w = (w + 1) & (n - 1);
                src = (src + 1) & (n - 1);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (fuzz run-1791310276): a block whose 16-bit command
    /// count is zero must be rejected instead of underflowing
    /// `remaining` (which panicked in debug builds and silently
    /// returned padded garbage in release).
    #[test]
    fn test_st1_zero_block_count_rejected() {
        let err = decode(14, 4, &[0u8; 8], 1).unwrap_err();
        assert!(matches!(err, Error::InvalidData(_)));
    }
}
