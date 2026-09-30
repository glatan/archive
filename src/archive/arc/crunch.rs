//! ARC methods 5/6/7 ("crunched") — fixed 12-bit LZW over a hash-coded
//! string table.
//!
//! Wire format: a stream of 12-bit codes, most-significant-bit first.
//! Unlike Unix `compress` the code values are not sequential — each new
//! string `(parent, byte)` is inserted into a 4096-slot table at a
//! position derived from a hash of the parent code and the byte, with
//! linear probing on collision. The decoder must reproduce the exact
//! same placement, so two hash variants exist: the older quadratic
//! hash (methods 5 and 6) and a faster multiplicative one (method 7).
//! Codes 0-255 are literals; the first code of a stream is always a
//! literal. A code that is not yet in the table takes the KwKwK
//! expansion (previous string plus its own first byte).
//!
//! Ported from the newtua_dos transliteration of XADMaster `XADARCCrunchHandle` (LGPL-3.0-or-later). nomarch `readlzw.c` and hyc/arc `arclzw.c` (GPL-2)
//! were consulted for behaviour confirmation only.

use alloc::vec::Vec;

use crate::error::Error;

use super::bits::MsbBits;

/// Number of slots in the hash-coded string table (12-bit codes).
const TABLE_SIZE: usize = 4096;

/// Which hash places new strings into the crunch table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrunchHash {
    /// Older quadratic hash (methods 5 and 6).
    Quadratic,
    /// Faster multiplicative hash (method 7).
    Multiplicative,
}

/// Hash function for a `(parent, byte)` pair (`parent == -1` for
/// single literals).
fn hash(kind: CrunchHash, parent: i32, byte: u8) -> usize {
    let pb = parent.wrapping_add(i32::from(byte));
    match kind {
        CrunchHash::Multiplicative => (pb & 0xffff).wrapping_mul(15073) as usize & 0xfff,
        CrunchHash::Quadratic => {
            let index = (pb | 0x0800) & 0xffff;
            ((index.wrapping_mul(index) >> 6) & 0xfff) as usize
        }
    }
}

/// Decode a crunched stream (methods 5/6/7 share the codec; the
/// caller picks the hash and post-processing). Stops at end of input
/// or when `limit` output bytes were produced.
pub(crate) fn decode(input: &[u8], kind: CrunchHash, limit: usize) -> Result<Vec<u8>, Error> {
    let mut used = [false; TABLE_SIZE];
    let mut byte = [0u8; TABLE_SIZE];
    let mut next = [0usize; TABLE_SIZE];
    let mut parent = [-1i32; TABLE_SIZE];
    let mut numfree = TABLE_SIZE - 256;

    // Insert `(parent, byte)` at its hash slot, probing on collision.
    let update = |parent_code: i32,
                  b: u8,
                  used: &mut [bool; TABLE_SIZE],
                  byte: &mut [u8; TABLE_SIZE],
                  next: &mut [usize; TABLE_SIZE],
                  parent: &mut [i32; TABLE_SIZE]| {
        let mut index = hash(kind, parent_code, b);
        if used[index] {
            while next[index] != 0 {
                index = next[index];
            }
            let mut nxt = (index + 101) & 0xfff;
            while used[nxt] {
                nxt = (nxt + 1) & 0xfff;
            }
            next[index] = nxt;
            index = nxt;
        }
        used[index] = true;
        next[index] = 0;
        parent[index] = parent_code;
        byte[index] = b;
    };

    for i in 0..256 {
        update(-1, i as u8, &mut used, &mut byte, &mut next, &mut parent);
    }

    let mut bits = MsbBits::new(input);
    let mut out = Vec::new();
    let mut seq: Vec<u8> = Vec::new();

    // The first code is a literal; emit its byte directly.
    let first = match bits.read(12) {
        Some(c) => c as usize,
        None => return Ok(out),
    };
    out.push(byte[first]);
    let mut lastcode = first;

    while let Some(c) = bits.read(12) {
        let c = c as usize;
        seq.clear();
        let mut idx = c;
        let kwk = !used[idx];
        if kwk {
            // Code not yet assigned: previous string plus its first
            // byte.
            idx = lastcode;
        }
        while parent[idx] != -1 {
            seq.push(byte[idx]);
            idx = parent[idx] as usize;
            if seq.len() > TABLE_SIZE {
                return Err(Error::InvalidData("arc: crunch parent cycle"));
            }
        }
        seq.push(byte[idx]);
        let firstbyte = byte[idx];

        for &b in seq.iter().rev() {
            if out.len() >= limit {
                return Err(Error::InvalidData("arc: crunch expansion exceeds bound"));
            }
            out.push(b);
        }
        if kwk {
            if out.len() >= limit {
                return Err(Error::InvalidData("arc: crunch expansion exceeds bound"));
            }
            out.push(firstbyte);
        }

        if numfree != 0 {
            update(
                lastcode as i32,
                firstbyte,
                &mut used,
                &mut byte,
                &mut next,
                &mut parent,
            );
            numfree -= 1;
        }
        lastcode = c;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn quadratic_vectors() {
        assert_eq!(
            decode(&hex("0a5d1f0a50"), CrunchHash::Quadratic, 16).unwrap(),
            b"AAAA"
        );
        assert_eq!(
            decode(&hex("0a5082d6698b0820"), CrunchHash::Quadratic, 16).unwrap(),
            b"ABABABAB"
        );
        assert_eq!(
            decode(
                &hex("938890bf93d58907cf07523e23e0"),
                CrunchHash::Quadratic,
                16
            )
            .unwrap(),
            b"banana banana"
        );
    }

    #[test]
    fn multiplicative_vector() {
        assert_eq!(
            decode(&hex("8403618400"), CrunchHash::Multiplicative, 16).unwrap(),
            b"AAAA"
        );
    }

    #[test]
    fn empty_input() {
        assert!(decode(&[], CrunchHash::Quadratic, 16).unwrap().is_empty());
        assert!(
            decode(&[], CrunchHash::Multiplicative, 16)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn bound_enforced() {
        // "AAAA" decoded with a tighter limit must error.
        assert!(decode(&hex("0a5d1f0a50"), CrunchHash::Quadratic, 3).is_err());
    }
}
