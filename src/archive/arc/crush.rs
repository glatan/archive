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

use alloc::vec::Vec;

use crate::error::Error;

use super::bits::LsbBits;

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
}
