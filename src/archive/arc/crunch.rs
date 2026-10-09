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
//! Ported from the newtua_dos transliteration of XADMaster `XADARCCrunchHandle` (LGPL-3.0-or-later). nomarch and hyc-arc
//! are used only as test-time oracles, not as implementation references.
//!
//! Licensing: incorporated under LGPL-3.0 by removing its additional
//! permissions per GPL-3.0 section 7, and combined with this AGPL-3.0
//! work via AGPL-3.0 section 13.

use alloc::vec::Vec;

use crate::error::Error;

use super::bits::{MsbBits, MsbWriter};

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

/// The 4096-entry string table. Each slot holds the `(parent, byte)`
/// expansion of one string; `next` links entries that hashed to an
/// already-used slot. Encoder and decoder run identical placement so
/// that a slot index doubles as the wire code.
struct Table {
    used: [bool; TABLE_SIZE],
    byte: [u8; TABLE_SIZE],
    next: [usize; TABLE_SIZE],
    parent: [i32; TABLE_SIZE],
    kind: CrunchHash,
}

impl Table {
    fn new(kind: CrunchHash) -> Self {
        Table {
            used: [false; TABLE_SIZE],
            byte: [0; TABLE_SIZE],
            next: [0; TABLE_SIZE],
            parent: [-1; TABLE_SIZE],
            kind,
        }
    }

    /// Insert `(parent_code, b)` at its hash slot, probing on
    /// collision; returns the slot used.
    fn update(&mut self, parent_code: i32, b: u8) -> usize {
        let mut index = hash(self.kind, parent_code, b);
        if self.used[index] {
            while self.next[index] != 0 {
                index = self.next[index];
            }
            let mut nxt = (index + 101) & 0xfff;
            while self.used[nxt] {
                nxt = (nxt + 1) & 0xfff;
            }
            self.next[index] = nxt;
            index = nxt;
        }
        self.used[index] = true;
        self.next[index] = 0;
        self.parent[index] = parent_code;
        self.byte[index] = b;
        index
    }

    /// Slot of the `(parent_code, b)` string, following the collision
    /// chain from its hash slot.
    fn find(&self, parent_code: i32, b: u8) -> Option<usize> {
        let mut index = hash(self.kind, parent_code, b);
        while self.used[index] {
            if self.parent[index] == parent_code && self.byte[index] == b {
                return Some(index);
            }
            if self.next[index] == 0 {
                return None;
            }
            index = self.next[index];
        }
        None
    }
}

/// Decode a crunched stream (methods 5/6/7 share the codec; the
/// caller picks the hash and post-processing). Stops at end of input
/// or when `limit` output bytes were produced.
pub(crate) fn decode(input: &[u8], kind: CrunchHash, limit: usize) -> Result<Vec<u8>, Error> {
    let mut tab = Table::new(kind);
    let mut numfree = TABLE_SIZE - 256;

    for i in 0..256 {
        tab.update(-1, i as u8);
    }

    let mut bits = MsbBits::new(input);
    let mut out = Vec::new();
    let mut seq: Vec<u8> = Vec::new();

    // The first code is a literal; emit its byte directly.
    let first = match bits.read(12) {
        Some(c) => c as usize,
        None => return Ok(out),
    };
    out.push(tab.byte[first]);
    let mut lastcode = first;

    while let Some(c) = bits.read(12) {
        let c = c as usize;
        seq.clear();
        let mut idx = c;
        let kwk = !tab.used[idx];
        if kwk {
            // Code not yet assigned: previous string plus its first
            // byte.
            idx = lastcode;
        }
        while tab.parent[idx] != -1 {
            seq.push(tab.byte[idx]);
            idx = tab.parent[idx] as usize;
            if seq.len() > TABLE_SIZE {
                return Err(Error::InvalidData("arc: crunch parent cycle"));
            }
        }
        seq.push(tab.byte[idx]);
        let firstbyte = tab.byte[idx];

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
            tab.update(lastcode as i32, firstbyte);
            numfree -= 1;
        }
        lastcode = c;
    }
    Ok(out)
}

/// Encode `input` as a crunched stream: 12-bit codes, MSB-first,
/// where each code is the slot [`Table::update`] assigned to the
/// string. Insertions stop when the table budget runs out, matching
/// the decoder.
pub(crate) fn encode(input: &[u8], kind: CrunchHash) -> Vec<u8> {
    let mut tab = Table::new(kind);
    let mut lit = [0usize; 256];
    for (i, slot) in lit.iter_mut().enumerate() {
        *slot = tab.update(-1, i as u8);
    }

    let mut bits = MsbWriter::new();
    let mut numfree = TABLE_SIZE - 256;
    let Some((&first, rest)) = input.split_first() else {
        return bits.finish();
    };

    // `w` is the slot (== wire code) of the current string.
    let mut w = lit[usize::from(first)];
    for &b in rest {
        match tab.find(w as i32, b) {
            Some(slot) => w = slot,
            None => {
                bits.put(w as u32, 12);
                if numfree != 0 {
                    tab.update(w as i32, b);
                    numfree -= 1;
                }
                w = lit[usize::from(b)];
            }
        }
    }
    bits.put(w as u32, 12);
    bits.finish()
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
        assert!(encode(&[], CrunchHash::Quadratic).is_empty());
        assert!(encode(&[], CrunchHash::Multiplicative).is_empty());
    }

    #[test]
    fn bound_enforced() {
        // "AAAA" decoded with a tighter limit must error.
        assert!(decode(&hex("0a5d1f0a50"), CrunchHash::Quadratic, 3).is_err());
    }

    #[test]
    fn encode_reference_streams() {
        // Encoder output is the canonical code stream: slot-coded
        // LZW is fully determined by input plus table placement, so
        // it must match the decoder vectors byte-for-byte.
        assert_eq!(encode(b"AAAA", CrunchHash::Quadratic), hex("0a5d1f0a50"));
        assert_eq!(
            encode(b"banana banana", CrunchHash::Quadratic),
            hex("938890bf93d58907cf07523e23e0")
        );
        assert_eq!(
            encode(b"AAAA", CrunchHash::Multiplicative),
            hex("8403618400")
        );
    }

    #[test]
    fn encode_decode_roundtrip() {
        fn roundtrip(data: &[u8], kind: CrunchHash) {
            let packed = encode(data, kind);
            assert_eq!(decode(&packed, kind, data.len()).unwrap(), data);
        }
        for kind in [CrunchHash::Quadratic, CrunchHash::Multiplicative] {
            roundtrip(&[], kind);
            roundtrip(b"a", kind);
            roundtrip(b"AAAA", kind);
            roundtrip(b"hello, world!", kind);
            roundtrip(b"banana banana", kind);
            // All byte values, then long runs.
            let mut v: Vec<u8> = (0..=255).collect();
            v.extend_from_within(..);
            v.extend_from_slice(&[7u8; 4000]);
            roundtrip(&v, kind);
            // Long input: exceeds the 3840-entry string budget, so
            // the table-full path is exercised.
            let big: Vec<u8> = (0..20000).map(|i| ((i * 31) ^ (i >> 3)) as u8).collect();
            roundtrip(&big, kind);
            roundtrip(&b"the quick brown fox. ".repeat(500), kind);
        }
    }
}
