//! ARC method 0x0a ("crushed") — adaptive LZW with usage-based code
//! replacement and a switchable literal-bit coding mode.
//!
//! Codes are read least-significant-bit first. The string table is an
//! 8192-slot LZW tree: codes 0-255 are literals, 0x100 is the
//! end-of-data marker, and strings grow from 257. Two things make the
//! format unusual:
//!
//! - **Literal-bit mode.** A 500-symbol sliding window tracks how many
//!   recent symbols were multi-byte strings. While literals dominate
//!   (fewer than 375 of the last 500), each symbol is prefixed by one
//!   bit selecting a literal (8 bits) or a string (`symbolsize` bits).
//!   Once strings dominate the prefix is dropped and both kinds share
//!   one width — and literal codes arrive bit-inverted.
//! - **Replacement.** Once the table fills, new strings evict the
//!   least-recently-used entry instead of growing the table.
//!
//! Ported from the newtua_dos transliteration of XADMaster `XADARCCrushHandle` (LGPL-3.0-or-later). nomarch `readlzw.c` (GPL-2) was consulted for
//! behaviour confirmation only.
//!
//! Licensing: incorporated under LGPL-3.0 section 2 (GPL-3.0) and
//! combined with this AGPL-3.0 work via AGPL-3.0 section 13.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::{LsbBits, LsbWriter};

/// Maximum number of symbols in the crush string table.
const MAX_SYMBOLS: usize = 8192;
/// End-of-data symbol.
const EOF_CODE: usize = 0x100;
/// Sliding-window size counting recent string-vs-literal usage.
const RING: usize = 500;
/// String-dominance threshold inside the sliding window.
const RING_THRESHOLD: i32 = 375;

/// First byte of a symbol's string (walks to the tree root).
fn first_byte(mut sym: usize, parent: &[i32; MAX_SYMBOLS], chr: &[u8; MAX_SYMBOLS]) -> u8 {
    let mut depth = 0;
    while parent[sym] >= 0 {
        sym = parent[sym] as usize;
        depth += 1;
        if depth > MAX_SYMBOLS {
            return 0;
        }
    }
    chr[sym]
}

/// Decode a crushed stream. Stops at the end-of-data marker, at end of
/// input, or when `limit` output bytes were produced.
pub(crate) fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>, Error> {
    let mut chr = [0u8; MAX_SYMBOLS];
    for (i, c) in chr.iter_mut().enumerate().take(256) {
        *c = i as u8;
    }
    let mut parent = [-1i32; MAX_SYMBOLS];
    let mut usage = [0u8; MAX_SYMBOLS];
    let mut numsymbols = 257usize;
    let mut prevsymbol = -1i32;

    let mut symbolsize = 1u8;
    let mut nextsizebump: i32 = 2;
    let mut useliteralbit = true;

    let mut numrecentstrings = 0i32;
    let mut ringindex = 0usize;
    let mut stringring = [false; RING];
    let mut usageindex = 0x101usize;

    let mut bits = LsbBits::new(input);
    let mut out = Vec::new();
    let mut stack: Vec<u8> = Vec::new();

    loop {
        // Read the next symbol in the current coding mode.
        let symbol = if useliteralbit {
            // A leading bit selects literal (8 bits) or string
            // (symbolsize bits, offset 256).
            match bits.read(1) {
                None => break,
                Some(0) => match bits.read(8) {
                    None => break,
                    Some(v) => v as usize,
                },
                Some(_) => match bits.read(symbolsize) {
                    None => break,
                    Some(v) => v as usize + 256,
                },
            }
        } else {
            match bits.read(symbolsize) {
                None => break,
                Some(v) => {
                    let s = v as usize;
                    // Literals arrive bit-inverted in this mode.
                    if s < 0x100 { s ^ 0xff } else { s }
                }
            }
        };
        if symbol == EOF_CODE {
            break;
        }

        // Bump the usage of the symbol and all its parents so a
        // freshly-seen string is not the next eviction candidate.
        let mut m = symbol as i32;
        let mut depth = 0;
        while m >= 0 {
            usage[m as usize] = 4;
            m = parent[m as usize];
            depth += 1;
            if depth > MAX_SYMBOLS {
                return Err(Error::InvalidData("arc: crush parent cycle"));
            }
        }

        // Slide the 500-symbol window and recount recent strings.
        if stringring[ringindex] {
            numrecentstrings -= 1;
        }
        let is_string = symbol >= 0x100;
        stringring[ringindex] = is_string;
        if is_string {
            numrecentstrings += 1;
        }
        ringindex = (ringindex + 1) % RING;

        // Switch coding mode when literals vs strings crosses the
        // threshold.
        let manyliterals = numrecentstrings < RING_THRESHOLD;
        if manyliterals != useliteralbit {
            useliteralbit = manyliterals;
            nextsizebump = 1i32 << symbolsize;
            if !useliteralbit {
                nextsizebump -= 0x100;
            }
        }

        // Extend the tree with `string(prevsymbol) + first_byte(symbol)`
        // (classic LZW lag), evicting once the table is full.
        if numsymbols != MAX_SYMBOLS {
            if prevsymbol >= 0 {
                let postfix = if symbol < numsymbols {
                    first_byte(symbol, &parent, &chr)
                } else if symbol == numsymbols {
                    first_byte(prevsymbol as usize, &parent, &chr)
                } else {
                    return Err(Error::InvalidData("arc: corrupt crush code"));
                };
                parent[numsymbols] = prevsymbol;
                chr[numsymbols] = postfix;
                numsymbols += 1;
            }
            usage[numsymbols - 1] = 2;
            prevsymbol = symbol as i32;
        } else {
            if symbol >= numsymbols {
                return Err(Error::InvalidData("arc: corrupt crush code"));
            }
            // Evict the least-used slot: sweep from `usageindex`,
            // decaying entries, and pick the minimum seen.
            let (mut minindex, mut minusage) = (0usize, i32::MAX);
            let mut index = usageindex;
            loop {
                index += 1;
                if index == MAX_SYMBOLS {
                    index = 0x101;
                }
                let u = i32::from(usage[index]);
                if u < minusage {
                    minindex = index;
                    minusage = u;
                }
                usage[index] = usage[index].wrapping_sub(1);
                if usage[index] == 0 || index == usageindex {
                    break;
                }
            }
            usageindex = index;
            parent[minindex] = prevsymbol;
            chr[minindex] = first_byte(symbol, &parent, &chr);
            prevsymbol = symbol as i32;
            usage[minindex] = 2;
        }

        // Emit the bytes of the current symbol (root-to-leaf order).
        stack.clear();
        let mut sym = prevsymbol;
        depth = 0;
        while sym >= 0 {
            stack.push(chr[sym as usize]);
            sym = parent[sym as usize];
            depth += 1;
            if depth > MAX_SYMBOLS {
                return Err(Error::InvalidData("arc: crush parent cycle"));
            }
        }
        for &b in stack.iter().rev() {
            if out.len() >= limit {
                return Err(Error::InvalidData("arc: crush expansion exceeds bound"));
            }
            out.push(b);
        }

        // Widen string codes once enough strings exist; the trigger
        // depends on the coding mode.
        if numsymbols as i32 - 257 >= nextsizebump {
            symbolsize += 1;
            nextsizebump = 1i32 << symbolsize;
            if !useliteralbit {
                nextsizebump -= 0x100;
            }
        }
    }
    Ok(out)
}

/// Encoder-side mirror of the decoder's string table. A greedy LZW
/// parse emits codes that only ever reference strings the decoder has
/// already committed, so the decoder's `symbol == numsymbols` (KwKwK)
/// path is never triggered. `map`/`slot_key` track which
/// `(parent, byte)` pair occupies each slot so lookups never see a
/// stale string once a slot is evicted.
struct Encoder {
    bits: LsbWriter,
    map: BTreeMap<u32, u16>,
    slot_key: [u32; MAX_SYMBOLS],
    chr: [u8; MAX_SYMBOLS],
    parent: [i32; MAX_SYMBOLS],
    usage: [u8; MAX_SYMBOLS],
    numsymbols: usize,
    prevsymbol: i32,
    symbolsize: u8,
    nextsizebump: i32,
    useliteralbit: bool,
    numrecentstrings: i32,
    ringindex: usize,
    stringring: [bool; RING],
    usageindex: usize,
}

/// `slot_key` value for slots not carrying a string yet.
const NO_KEY: u32 = u32::MAX;

impl Encoder {
    fn new() -> Self {
        let mut chr = [0u8; MAX_SYMBOLS];
        for (i, c) in chr.iter_mut().enumerate().take(256) {
            *c = i as u8;
        }
        Encoder {
            bits: LsbWriter::new(),
            map: BTreeMap::new(),
            slot_key: [NO_KEY; MAX_SYMBOLS],
            chr,
            parent: [-1i32; MAX_SYMBOLS],
            usage: [0u8; MAX_SYMBOLS],
            numsymbols: 257,
            prevsymbol: -1,
            symbolsize: 1,
            nextsizebump: 2,
            useliteralbit: true,
            numrecentstrings: 0,
            ringindex: 0,
            stringring: [false; RING],
            usageindex: 0x101,
        }
    }

    /// Slot of the `w + b` string, if the decoder has it committed.
    fn find(&self, w: usize, b: u8) -> Option<usize> {
        self.map
            .get(&((w as u32) << 8 | u32::from(b)))
            .map(|&s| s as usize)
    }

    /// Commit `(parent_code, byte) -> slot` to the lookup map.
    fn link(&mut self, slot: usize, parent_code: i32, byte: u8) {
        let key = (parent_code as u32) << 8 | u32::from(byte);
        self.slot_key[slot] = key;
        self.map.insert(key, slot as u16);
    }

    /// Emit `sym` on the wire in the current coding mode, then mirror
    /// the exact decoder state transition for that symbol.
    fn emit(&mut self, sym: usize) -> Result<(), Error> {
        if self.useliteralbit {
            if sym < 0x100 {
                self.bits.put(0, 1);
                self.bits.put(sym as u32, 8);
            } else {
                self.bits.put(1, 1);
                self.bits
                    .put((sym - 0x100) as u32, u32::from(self.symbolsize));
            }
        } else {
            // Non-literal mode always has symbolsize >= 9: reaching it
            // takes >= 375 recent strings, which implies that many
            // inserts and a bump past 8 bits.
            debug_assert!(self.symbolsize >= 9);
            let v = if sym < 0x100 { sym ^ 0xff } else { sym };
            self.bits.put(v as u32, u32::from(self.symbolsize));
        }
        if sym == EOF_CODE {
            return Ok(());
        }

        // Bump the usage of the symbol's ancestry, same as decode.
        let mut m = sym as i32;
        let mut depth = 0;
        while m >= 0 {
            self.usage[m as usize] = 4;
            m = self.parent[m as usize];
            depth += 1;
            if depth > MAX_SYMBOLS {
                return Err(Error::InvalidData("arc: crush parent cycle"));
            }
        }

        // Slide the sliding window and recount recent strings.
        if self.stringring[self.ringindex] {
            self.numrecentstrings -= 1;
        }
        let is_string = sym >= 0x100;
        self.stringring[self.ringindex] = is_string;
        if is_string {
            self.numrecentstrings += 1;
        }
        self.ringindex = (self.ringindex + 1) % RING;

        let manyliterals = self.numrecentstrings < RING_THRESHOLD;
        if manyliterals != self.useliteralbit {
            self.useliteralbit = manyliterals;
            self.nextsizebump = 1i32 << self.symbolsize;
            if !self.useliteralbit {
                self.nextsizebump -= 0x100;
            }
        }

        // Commit `string(prevsymbol) + first_byte(sym)`, mirroring the
        // decoder's grow-or-evict insert.
        if self.numsymbols != MAX_SYMBOLS {
            if self.prevsymbol >= 0 {
                debug_assert!(sym < self.numsymbols);
                let postfix = first_byte(sym, &self.parent, &self.chr);
                self.parent[self.numsymbols] = self.prevsymbol;
                self.chr[self.numsymbols] = postfix;
                self.link(self.numsymbols, self.prevsymbol, postfix);
                self.numsymbols += 1;
            }
            self.usage[self.numsymbols - 1] = 2;
            self.prevsymbol = sym as i32;
        } else {
            // Evict the least-used slot; verbatim sweep from decode.
            let (mut minindex, mut minusage) = (0usize, i32::MAX);
            let mut index = self.usageindex;
            loop {
                index += 1;
                if index == MAX_SYMBOLS {
                    index = 0x101;
                }
                let u = i32::from(self.usage[index]);
                if u < minusage {
                    minindex = index;
                    minusage = u;
                }
                self.usage[index] = self.usage[index].wrapping_sub(1);
                if self.usage[index] == 0 || index == self.usageindex {
                    break;
                }
            }
            self.usageindex = index;
            // sym's chain was just bumped to 4, so the evicted slot
            // can only alias it if every scanned slot is saturated —
            // unreachable in practice, refuse rather than corrupt.
            if minusage >= 4 {
                return Err(Error::InvalidData("arc: crush evict saturated"));
            }
            let old = self.slot_key[minindex];
            if old != NO_KEY && self.map.get(&old) == Some(&(minindex as u16)) {
                self.map.remove(&old);
            }
            self.parent[minindex] = self.prevsymbol;
            self.chr[minindex] = first_byte(sym, &self.parent, &self.chr);
            self.link(minindex, self.prevsymbol, self.chr[minindex]);
            self.prevsymbol = sym as i32;
            self.usage[minindex] = 2;
        }

        // Widen string codes on the same trigger as the decoder.
        if self.numsymbols as i32 - 257 >= self.nextsizebump {
            self.symbolsize += 1;
            self.nextsizebump = 1i32 << self.symbolsize;
            if !self.useliteralbit {
                self.nextsizebump -= 0x100;
            }
        }
        Ok(())
    }
}

/// Encode `input` (the RLE90-packed member bytes) as a crushed stream.
///
/// The decoder lags the encoder by one string insert, so a newly added
/// `w + b` string is only visible to `find` from the following emitted
/// symbol on — exactly matching what the decoder can resolve.
pub(crate) fn encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut enc = Encoder::new();
    if let Some((&first, rest)) = input.split_first() {
        let mut w = usize::from(first);
        for &b in rest {
            match enc.find(w, b) {
                Some(slot) => w = slot,
                None => {
                    enc.emit(w)?;
                    w = usize::from(b);
                }
            }
        }
        enc.emit(w)?;
    }
    enc.emit(EOF_CODE)?;
    Ok(enc.bits.finish())
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
    fn vectors() {
        assert_eq!(decode(&hex("82041d"), 64).unwrap(), b"AAAA");
        assert_eq!(decode(&hex("8208bd05"), 64).unwrap(), b"ABABABAB");
        assert_eq!(
            decode(&hex("c48471ab3020731700"), 64).unwrap(),
            b"banana banana"
        );
        assert_eq!(
            decode(&hex("e8a02903224e9d3463d6801023e7cd1d3720ccbcc10b00"), 64).unwrap(),
            b"the quick brown fox"
        );
    }

    #[test]
    fn empty_and_eof() {
        assert!(decode(&[], 64).unwrap().is_empty());
        // Literal-bit set then a 1-bit string code 0 -> EOF (0x100).
        assert!(decode(&hex("01"), 64).unwrap().is_empty());
    }

    #[test]
    fn truncated_stops() {
        let out = decode(&hex("c48471"), 64).unwrap();
        assert!(b"banana banana".starts_with(&out[..]));
    }

    #[test]
    fn encode_reference_streams() {
        // The greedy parse mirrors the original encoder on these
        // vectors, so wire output is byte-identical.
        assert_eq!(encode(b"AAAA").unwrap(), hex("82041d"));
        assert_eq!(encode(b"ABABABAB").unwrap(), hex("8208bd05"));
        assert_eq!(encode(b"banana banana").unwrap(), hex("c48471ab3020731700"));
        assert_eq!(
            encode(b"the quick brown fox").unwrap(),
            hex("e8a02903224e9d3463d6801023e7cd1d3720ccbcc10b00")
        );
        assert_eq!(encode(b"").unwrap(), hex("01"));
    }

    #[test]
    fn encode_decode_roundtrip() {
        fn roundtrip(data: &[u8]) {
            let packed = encode(data).unwrap();
            assert_eq!(decode(&packed, data.len()).unwrap(), data);
        }
        roundtrip(&[]);
        roundtrip(b"a");
        roundtrip(b"AAAA");
        roundtrip(b"hello, world!");
        roundtrip(b"banana banana");
        // Every byte value, twice.
        let mut v: Vec<u8> = (0..=255).collect();
        v.extend_from_within(..);
        roundtrip(&v);
        // Repetitive input: string density crosses the 375/500
        // threshold, switching to non-literal coding and back.
        roundtrip(&b"abcdefghij".repeat(6000));
        // Pseudo-random input: inserts outgrow the table, exercising
        // the eviction sweep on every later symbol.
        let noise: Vec<u8> = (0..60000usize)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        roundtrip(&noise);
        // Both paths in one stream.
        let mut mixed = b"the quick brown fox. ".repeat(3000);
        mixed.extend_from_slice(&noise);
        mixed.extend_from_within(..10000);
        roundtrip(&mixed);
    }

    #[test]
    fn encode_reaches_evict_and_nonliteral_mode() {
        // Drive the encoder by hand to observe the internal mode flip
        // and the table filling (eviction sweep entry).
        let mut data = b"abcdefghij".repeat(6000);
        data.extend((0..60000usize).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        let mut enc = Encoder::new();
        let mut saw_nonliteral = false;
        let mut filled = false;
        let mut w = usize::from(data[0]);
        for &b in &data[1..] {
            match enc.find(w, b) {
                Some(s) => w = s,
                None => {
                    enc.emit(w).unwrap();
                    w = usize::from(b);
                    saw_nonliteral |= !enc.useliteralbit;
                    filled |= enc.numsymbols == MAX_SYMBOLS;
                }
            }
        }
        enc.emit(w).unwrap();
        enc.emit(EOF_CODE).unwrap();
        assert!(saw_nonliteral, "never left literal-bit mode");
        assert!(filled, "table never filled");
        assert_eq!(decode(&enc.bits.finish(), data.len()).unwrap(), data);
    }
}
