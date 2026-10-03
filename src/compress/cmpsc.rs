//! IBM CMPSC "Compression Call" basic method (LZ78 family), per the
//! dictionary formats in z/Architecture Principles of Operation
//! (SA22-7832) Appendix D and IBM ESA/390 Data Compression (SA22-7208).
//!
//! A compressed stream is a sequence of fixed-width index symbols
//! (9-13 bits depending on dictionary size: 512/1K/2K/4K/8K entries),
//! packed MSB-first. Expansion resolves each index through an
//! expansion dictionary; compression walks a compression dictionary
//! (character entries + format-0 sibling descriptors).
//!
//! Scope (basic method only):
//! - format-0 sibling descriptors; format-1 sibling descriptors,
//!   symbol translation, order preservation, and entropy encoding
//!   (CMPSC-enhancement facility) are not supported.
//! - [`expand`] and [`compress`] take dictionaries out-of-band.
//! - [`decode`]/[`encode`] use the PKWARE APPNOTE method-16 container:
//!   `[version=1][flags|symsize][u32be dict len][expansion dict][data]`.
//!   Flag 0x40 (deflate-compressed dictionary) is rejected.
//! - [`encode`] emits an alphabet-only dictionary: every byte becomes
//!   its own index symbol. It produces valid streams but does not
//!   compress; like the LZXD uncompressed-block encoder it exists for
//!   round-trip and interoperability testing.

use alloc::vec::Vec;

use crate::error::Error;

/// Bytes per dictionary entry (one doubleword).
const ENTRY: usize = 8;
/// Alphabet (unpreceded single-character) entries in every dictionary.
const ALPHABET: usize = 256;

fn check_sym_size(sym_size: u8) -> Result<usize, Error> {
    if !(9..=13).contains(&sym_size) {
        return Err(Error::InvalidData("cmpsc: symbol size out of range"));
    }
    Ok(1usize << sym_size)
}

// ---------------------------------------------------------------------------
// Expansion-dictionary entry
// ---------------------------------------------------------------------------

struct ExpEntry {
    /// Partial-symbol length; 0 marks an unpreceded (complete) entry.
    psl: u8,
    /// Predecessor index (preceded entries only).
    pptr: u16,
    /// Extension characters stored in this entry.
    ecs: [u8; 7],
}

fn exp_entry(dict: &[u8], index: usize) -> ExpEntry {
    let e = &dict[index * ENTRY..index * ENTRY + ENTRY];
    let psl = e[0] >> 5;
    let mut ecs = [0u8; 7];
    if psl == 0 {
        // Unpreceded: CSL in bits 3-5, ECs in bytes 1-7.
        let csl = ((e[0] >> 2) & 7) as usize;
        ecs[..csl.min(7)].copy_from_slice(&e[1..1 + csl.min(7)]);
        ExpEntry { psl, pptr: 0, ecs }
    } else {
        // Preceded: PPTR in bits 3-15, up to 5 ECs in bytes 2-6.
        let pptr = (((e[0] & 0x1f) as u16) << 8) | e[1] as u16;
        ecs[..5].copy_from_slice(&e[2..7]);
        ExpEntry { psl, pptr, ecs }
    }
}

/// Expand one index symbol into `out` following predecessor chains.
fn expand_index(
    dict: &[u8],
    entries: usize,
    index: usize,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), Error> {
    // Collect the predecessor chain: index -> pptr -> ... -> unpreceded.
    let mut chain = Vec::with_capacity(16);
    let mut cur = index;
    loop {
        if cur >= entries {
            return Err(Error::InvalidData("cmpsc: index out of range"));
        }
        let e = exp_entry(dict, cur);
        if e.psl == 0 {
            chain.push((cur, 0usize));
            break;
        }
        chain.push((cur, e.psl as usize));
        cur = e.pptr as usize;
        if chain.len() > entries {
            return Err(Error::InvalidData("cmpsc: predecessor cycle"));
        }
    }
    for &(ci, n) in chain.iter().rev() {
        let e = exp_entry(dict, ci);
        let take = if e.psl == 0 {
            ((dict[ci * ENTRY] >> 2) & 7) as usize
        } else {
            n.min(5)
        };
        if out.len() + take > max_output {
            return Err(Error::InvalidData("cmpsc: output limit exceeded"));
        }
        out.extend_from_slice(&e.ecs[..take]);
    }
    Ok(())
}

/// Expand a CMPSC index-symbol stream using `dict` (expansion
/// dictionary, 8-byte entries) and symbol width `sym_size` (9-13).
///
/// Trailing bits that do not form a complete symbol are ignored, per
/// the operand model (a partial symbol cannot be produced by a valid
/// stream).
pub fn expand(
    dict: &[u8],
    sym_size: u8,
    input: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    let entries = check_sym_size(sym_size)?;
    if !dict.len().is_multiple_of(ENTRY)
        || dict.len() / ENTRY > entries
        || dict.len() / ENTRY < ALPHABET
    {
        return Err(Error::InvalidData("cmpsc: bad dictionary length"));
    }
    let dict_entries = dict.len() / ENTRY;
    let total_bits = input.len() * 8;
    let mut out = Vec::new();
    let mut bitpos = 0usize;
    while bitpos + sym_size as usize <= total_bits {
        let mut sym = 0u32;
        for i in 0..sym_size as usize {
            let b = input[(bitpos + i) / 8];
            sym = (sym << 1) | ((b >> (7 - (bitpos + i) % 8)) & 1) as u32;
        }
        bitpos += sym_size as usize;
        expand_index(dict, dict_entries, sym as usize, &mut out, max_output)?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Compression-dictionary entry (format-0 sibling descriptors)
// ---------------------------------------------------------------------------

struct CmpEntry {
    /// Child count after adjusting for the "more children" case.
    cct: usize,
    /// Examine bits for in-entry children (entry byte 0 bits 3-7, i.e.
    /// mask 0x10 >> k for child k). Clear means the child is selected
    /// without fetching its own entry; the match ends at the child.
    ecb: u8,
    /// Additional-extension-character count (0-4/5).
    act: usize,
    /// Child characters stored in this entry.
    ccs: [u8; 5],
    /// Index of the first child.
    cptr: u16,
    /// Another sibling descriptor follows the in-entry children.
    more_children: bool,
    /// Whether this entry has children at all.
    has_children: bool,
}

fn cmp_entry(cdict: &[u8], entries: usize, index: usize) -> Result<CmpEntry, Error> {
    if index >= entries {
        return Err(Error::InvalidData("cmpsc: child pointer out of range"));
    }
    let e = &cdict[index * ENTRY..index * ENTRY + ENTRY];
    let cct = (e[0] >> 5) as usize;
    if cct == 0 {
        // No children: ACT in bits 8-10, ECs follow at byte 3.
        let act = ((e[1] >> 5) & 7) as usize;
        if act > 5 {
            return Err(Error::InvalidData("cmpsc: bad ACT"));
        }
        return Ok(CmpEntry {
            cct: 0,
            ecb: 0,
            act,
            ccs: [0; 5],
            cptr: 0,
            more_children: false,
            has_children: false,
        });
    }
    if cct == 1 {
        // One child: examine bit 3, ACT bits 8-10, CPTR bits 11-23,
        // ECs at byte 3 then one child character.
        let act = ((e[1] >> 5) & 7) as usize;
        if act > 4 {
            return Err(Error::InvalidData("cmpsc: bad ACT"));
        }
        let cptr = (((e[1] & 0x1f) as u16) << 8) | e[2] as u16;
        let mut ccs = [0u8; 5];
        ccs[0] = e[3 + act];
        return Ok(CmpEntry {
            cct: 1,
            ecb: e[0] & 0x1f,
            act,
            ccs,
            cptr,
            more_children: false,
            has_children: true,
        });
    }
    // Many children: ACT is bit 10 (0 or 1), CPTR bits 11-23, an
    // optional EC byte, then child characters.
    let act = ((e[1] >> 5) & 1) as usize;
    let maxcc = 5 - act;
    let cptr = (((e[1] & 0x1f) as u16) << 8) | e[2] as u16;
    let (cct, more_children) = if cct == maxcc + 1 {
        (maxcc, true)
    } else if cct <= maxcc {
        (cct, false)
    } else {
        return Err(Error::InvalidData("cmpsc: bad CCT"));
    };
    let mut ccs = [0u8; 5];
    ccs[..cct].copy_from_slice(&e[3 + act..3 + act + cct]);
    Ok(CmpEntry {
        cct,
        ecb: e[0] & 0x1f,
        act,
        ccs,
        cptr,
        more_children,
        has_children: true,
    })
}

/// Format-0 sibling descriptor (8 bytes inside the compression dict).
struct Sibling {
    /// Number of sibling characters (1-7); an SCT of 0 is treated as 7.
    sct: usize,
    /// Sibling characters.
    scs: [u8; 7],
    /// Another sibling descriptor follows these children (SCT == 0).
    more: bool,
}

fn sibling0(cdict: &[u8], entries: usize, index: usize) -> Result<Sibling, Error> {
    if index >= entries {
        return Err(Error::InvalidData("cmpsc: sibling descriptor out of range"));
    }
    let e = &cdict[index * ENTRY..index * ENTRY + ENTRY];
    let raw = (e[0] >> 5) as usize;
    // POP: an SCT of 0 is treated as 7 and indicates that another
    // sibling descriptor follows the children; SCT=7 carries exactly
    // 7 siblings with no continuation.
    let (sct, more) = if raw == 0 { (7, true) } else { (raw, false) };
    let mut scs = [0u8; 7];
    scs[..sct].copy_from_slice(&e[1..1 + sct]);
    Ok(Sibling { sct, scs, more })
}

/// MSB-first bit writer for index symbols.
struct BitOut {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitOut {
    fn new() -> Self {
        BitOut {
            out: Vec::new(),
            acc: 0,
            n: 0,
        }
    }
    fn push(&mut self, value: u32, bits: u32) {
        for i in (0..bits).rev() {
            self.acc = (self.acc << 1) | ((value >> i) & 1);
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push((self.acc << (8 - self.n)) as u8);
        }
        self.out
    }
}

/// Compress `input` into CMPSC index symbols using `cdict`
/// (compression dictionary with format-0 sibling descriptors) and
/// symbol width `sym_size` (9-13 bits, i.e. 512-8K entries).
///
/// Matching uses the unordered comparison algorithm: children are
/// scanned in dictionary order and a later child may still match when
/// an earlier child's additional extension characters fail — both
/// continuations are model-permitted by the architecture.
pub fn compress(cdict: &[u8], sym_size: u8, input: &[u8]) -> Result<Vec<u8>, Error> {
    let entries = check_sym_size(sym_size)?;
    if !cdict.len().is_multiple_of(ENTRY)
        || cdict.len() / ENTRY > entries
        || cdict.len() / ENTRY < ALPHABET
    {
        return Err(Error::InvalidData("cmpsc: bad dictionary length"));
    }
    let dict_entries = cdict.len() / ENTRY;
    let mut w = BitOut::new();
    let mut i = 0usize;
    while i < input.len() {
        let mut parent = input[i] as usize;
        i += 1;
        'descend: loop {
            let e = cmp_entry(cdict, dict_entries, parent)?;
            if !e.has_children || i >= input.len() {
                break;
            }
            // In-entry children: child index = cptr + ordinal.
            for k in 0..e.cct {
                if e.ccs[k] != input[i] {
                    continue;
                }
                let child = e.cptr as usize + k;
                if e.ecb & (0x10 >> k) == 0 {
                    // Examine bit clear: the child is selected without
                    // fetching its own entry and the match ends here.
                    if child >= dict_entries {
                        return Err(Error::InvalidData("cmpsc: child pointer out of range"));
                    }
                    parent = child;
                    i += 1;
                    break 'descend;
                }
                if let Some(next) = try_descend(cdict, dict_entries, child, input, i)? {
                    parent = next.0;
                    i = next.1;
                    continue 'descend;
                }
            }
            if !e.more_children {
                break;
            }
            // Format-0 sibling descriptors: SD occupies one index and is
            // followed by the children it designates.
            let mut sd_index = e.cptr as usize + e.cct;
            loop {
                let sd = sibling0(cdict, dict_entries, sd_index)?;
                for k in 0..sd.sct {
                    if sd.scs[k] != input[i] {
                        continue;
                    }
                    if let Some(next) =
                        try_descend(cdict, dict_entries, sd_index + 1 + k, input, i)?
                    {
                        parent = next.0;
                        i = next.1;
                        continue 'descend;
                    }
                }
                if !sd.more {
                    break;
                }
                sd_index += 1 + sd.sct;
            }
            break;
        }
        w.push(parent as u32, sym_size as u32);
    }
    Ok(w.finish())
}

/// If the child at `index` matches the input continuation (additional
/// extension characters), return the new (parent, position) pair.
fn try_descend(
    cdict: &[u8],
    entries: usize,
    index: usize,
    input: &[u8],
    pos: usize,
) -> Result<Option<(usize, usize)>, Error> {
    let ce = cmp_entry(cdict, entries, index)?;
    if ce.act > 0 {
        if pos + 1 + ce.act > input.len() {
            return Ok(None);
        }
        // ECs sit at byte 3 in every character-entry layout.
        for k in 0..ce.act {
            if cdict[index * ENTRY + 3 + k] != input[pos + 1 + k] {
                return Ok(None);
            }
        }
    }
    Ok(Some((index, pos + 1 + ce.act)))
}

// ---------------------------------------------------------------------------
// PKWARE APPNOTE method-16 container
// ---------------------------------------------------------------------------

/// Build the trivial alphabet-only expansion dictionary used by
/// [`encode`]: every byte expands to itself.
fn alphabet_expansion_dictionary(entries: usize) -> Vec<u8> {
    let mut d = vec![0u8; entries * ENTRY];
    for i in 0..ALPHABET {
        d[i * ENTRY] = 1 << 2; // PSL=0, CSL=1
        d[i * ENTRY + 1] = i as u8;
    }
    d
}

/// Build the matching alphabet-only compression dictionary: every
/// alphabet entry is a leaf, so `compress` emits one symbol per byte.
fn alphabet_compression_dictionary(entries: usize) -> Vec<u8> {
    vec![0u8; entries * ENTRY]
}

/// Decode a PKWARE APPNOTE method-16 payload:
/// `[version=1][flags|symsize][u32be dict len][dict][cmpsc data]`.
///
/// Flag 0x80 must be set (expansion dictionary present). Flag 0x40
/// (deflate-compressed dictionary) is rejected as an intentional scope
/// limitation; flags 0x20/0x10 are reserved and rejected.
pub fn decode(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    if input.len() < 6 {
        return Err(Error::InvalidData("cmpsc: truncated method-16 header"));
    }
    if input[0] != 1 {
        return Err(Error::InvalidData("cmpsc: bad dictionary header version"));
    }
    let flags = input[1] & 0xf0;
    let sym_size = input[1] & 0x0f;
    if flags & 0x80 == 0 {
        return Err(Error::InvalidData("cmpsc: no expansion dictionary"));
    }
    if flags & 0x70 != 0 {
        return Err(Error::InvalidData("cmpsc: unsupported dictionary flags"));
    }
    check_sym_size(sym_size)?;
    let dict_len = u32::from_be_bytes([input[2], input[3], input[4], input[5]]) as usize;
    if 6 + dict_len > input.len() {
        return Err(Error::InvalidData("cmpsc: truncated expansion dictionary"));
    }
    let dict = &input[6..6 + dict_len];
    expand(dict, sym_size, &input[6 + dict_len..], max_output)
}

/// Encode `input` as a PKWARE APPNOTE method-16 payload using a 9-bit
/// alphabet-only dictionary. The output is a valid CMPSC stream but
/// does not compress the data; it exists for round-trip and
/// interoperability testing, mirroring the LZXD uncompressed encoder.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let sym_size = 9u8;
    let entries = 1usize << sym_size;
    let edict = alphabet_expansion_dictionary(entries);
    let cdict = alphabet_compression_dictionary(entries);
    let data = compress(&cdict, sym_size, input).unwrap_or_default();
    let mut out = Vec::with_capacity(6 + edict.len() + data.len());
    out.push(1);
    out.push(0x80 | sym_size);
    out.extend_from_slice(&(edict.len() as u32).to_be_bytes());
    out.extend_from_slice(&edict);
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 512-entry pair: 'A' -> "AB"/"AX", "AB" -> "ABC"; 'S' -> "SA".."SE"
    /// in-entry plus "SF".."SH" via a format-0 sibling descriptor.
    fn test_dictionaries() -> (Vec<u8>, Vec<u8>) {
        let entries = 512usize;
        let mut cd = alphabet_compression_dictionary(entries);
        let mut ed = alphabet_expansion_dictionary(entries);

        // 'A' (65): CCT=2, CPTR=256, CCs 'B','X'.
        cd[65 * ENTRY] = (2 << 5) | 0x18; // X=1 for both children
        cd[65 * ENTRY + 1] = (256 >> 8) as u8;
        cd[65 * ENTRY + 2] = 0;
        cd[65 * ENTRY + 3] = b'B';
        cd[65 * ENTRY + 4] = b'X';
        // 256 "AB": CCT=1, CPTR=258, CC 'C'.
        cd[256 * ENTRY] = (1 << 5) | 0x10; // X=1 (examine child)
        cd[256 * ENTRY + 1] = (258 >> 8) as u8;
        cd[256 * ENTRY + 2] = (258 & 0xff) as u8;
        cd[256 * ENTRY + 3] = b'C';
        // 257 "AX", 258 "ABC": leaves (all zero).
        // 'S' (83): CCT=6 (5 in-entry children + SD), CPTR=259, CCs A-E.
        cd[83 * ENTRY] = (6 << 5) | 0x1f; // X=1 for all in-entry children
        cd[83 * ENTRY + 1] = (259 >> 8) as u8;
        cd[83 * ENTRY + 2] = (259 & 0xff) as u8;
        cd[83 * ENTRY + 3..83 * ENTRY + 8].copy_from_slice(b"ABCDE");
        // 264: format-0 SD, SCT=3, SCs 'F','G','H'.
        cd[264 * ENTRY] = 3 << 5;
        cd[264 * ENTRY + 1] = b'F';
        cd[264 * ENTRY + 2] = b'G';
        cd[264 * ENTRY + 3] = b'H';
        // children 259-263 ("SA".."SE"), 265-267 ("SF".."SH"): leaves.

        // Expansion: 256 "AB" PSL=1 PPTR=65 EC='B' OFST=1.
        ed[256 * ENTRY] = (1 << 5) | (65 >> 8) as u8;
        ed[256 * ENTRY + 1] = 65;
        ed[256 * ENTRY + 2] = b'B';
        ed[256 * ENTRY + 7] = 1;
        // 257 "AX".
        ed[257 * ENTRY] = (1 << 5) | (65 >> 8) as u8;
        ed[257 * ENTRY + 1] = 65;
        ed[257 * ENTRY + 2] = b'X';
        ed[257 * ENTRY + 7] = 1;
        // 258 "ABC" PSL=1 PPTR=256 EC='C' OFST=2.
        ed[258 * ENTRY] = (1 << 5) | (256 >> 8) as u8;
        ed[258 * ENTRY + 1] = (256 & 0xff) as u8;
        ed[258 * ENTRY + 2] = b'C';
        ed[258 * ENTRY + 7] = 2;
        // 259-263 "SA".."SE": PSL=1 PPTR=83 OFST=1.
        for (k, idx) in (259..=263usize).enumerate() {
            ed[idx * ENTRY] = (1 << 5) | (83 >> 8) as u8;
            ed[idx * ENTRY + 1] = 83;
            ed[idx * ENTRY + 2] = b'A' + k as u8;
            ed[idx * ENTRY + 7] = 1;
        }
        // 265-267 "SF".."SH".
        for (k, idx) in (265..=267usize).enumerate() {
            ed[idx * ENTRY] = (1 << 5) | (83 >> 8) as u8;
            ed[idx * ENTRY + 1] = 83;
            ed[idx * ENTRY + 2] = b'F' + k as u8;
            ed[idx * ENTRY + 7] = 1;
        }
        (cd, ed)
    }

    fn pack9(symbols: &[u16]) -> Vec<u8> {
        let mut w = BitOut::new();
        for &s in symbols {
            w.push(s as u32, 9);
        }
        w.finish()
    }

    #[test]
    fn expand_alphabet_symbols() {
        let (_, ed) = test_dictionaries();
        let data = pack9(&[65, 66, 67]);
        assert_eq!(expand(&ed, 9, &data, 1 << 20).unwrap(), b"ABC");
    }

    #[test]
    fn expand_preceded_chain() {
        let (_, ed) = test_dictionaries();
        let data = pack9(&[258, 259, 262, 265]);
        assert_eq!(expand(&ed, 9, &data, 1 << 20).unwrap(), b"ABCSASDSF");
    }

    #[test]
    fn compress_then_expand() {
        let (cd, ed) = test_dictionaries();
        let input = b"ABCSASDAX";
        let c = compress(&cd, 9, input).unwrap();
        assert_eq!(expand(&ed, 9, &c, 1 << 20).unwrap(), input);
    }

    #[test]
    fn compress_matches_expected_symbols() {
        let (cd, _) = test_dictionaries();
        let c = compress(&cd, 9, b"ABCSASD").unwrap();
        assert_eq!(c, pack9(&[258, 259, 262]));
    }

    #[test]
    fn compress_respects_examine_bit() {
        let (mut cd, _ed) = test_dictionaries();
        // 'A' entry: examine only child 'B'; child 'X' keeps X=0 so it is
        // selected without fetching its own entry.
        cd[65 * ENTRY] = (2 << 5) | 0x10;
        // "AX" (257) would have a deeper child "AXY" at 268, but X=0 on
        // the 'A' side means that entry is never examined.
        cd[257 * ENTRY] = (1 << 5) | 0x10;
        cd[257 * ENTRY + 1] = (268 >> 8) as u8;
        cd[257 * ENTRY + 2] = (268 & 0xff) as u8;
        cd[257 * ENTRY + 3] = b'Y';
        // "AXY": child 'X' is emitted as symbol 257 and the match ends;
        // 'Y' starts a fresh match. 268 is never reached.
        assert_eq!(
            compress(&cd, 9, b"AXY").unwrap(),
            pack9(&[257, b'Y' as u16])
        );
        // The examined child 'B' still descends to 258 "ABC".
        assert_eq!(compress(&cd, 9, b"ABC").unwrap(), pack9(&[258]));
    }

    #[test]
    fn method16_roundtrip() {
        for input in [b"".as_slice(), b"hello".as_slice(), &[7u8; 1000]] {
            let s = encode(input);
            assert_eq!(decode(&s, 1 << 20).unwrap(), input);
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert!(expand(&[0u8; 8], 9, &[0xff], 1 << 20).is_err());
        assert!(expand(&[0u8; 512 * 8], 8, &[0xff], 1 << 20).is_err());
        assert!(decode(&[1, 0x80 | 9, 0, 0, 0], 1 << 20).is_err());
        let (cd, ed) = test_dictionaries();
        // index beyond dictionary entries.
        let bad = pack9(&[511]);
        assert!(expand(&ed[..256 * 8], 9, &bad, 1 << 20).is_err());
        assert!(compress(&cd[..8], 9, b"AB").is_err());
    }
}
