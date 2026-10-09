//! ARC method 0x0b ("distilled") — LZSS with a header-supplied Huffman
//! code.
//!
//! Unlike the other ARC methods this one is not LZW. The compressed
//! stream opens with a serialised main Huffman tree — a `u16` node
//! count, a code-width byte, then that many fixed-width node links —
//! after which symbols are decoded least-significant-bit first:
//!
//! - `< 256` is a literal byte;
//! - `256` ends the stream;
//! - `> 256` is a match of length `symbol - 0x101 + 3`, whose offset is
//!   a 6-bit value from a fixed prefix table shifted by a number of
//!   extra bits that grows with the output position, plus those extra
//!   bits, plus one.
//!
//! The window is 8 KiB.
//!
//! Ported from the newtua_dos transliteration of XADMaster `XADARCDistillHandle` (LGPL-3.0-or-later).
//!
//! Licensing: incorporated under LGPL-3.0 by removing its additional
//! permissions per GPL-3.0 section 7, and combined with this AGPL-3.0
//! work via AGPL-3.0 section 13.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::{LsbBits, LsbWriter};

/// LZSS window size.
const WINDOW: usize = 8192;
/// Upper bound on the serialised node count.
const MAX_NODES: usize = 0x274;

/// Bit length of each entry in the fixed offset prefix table.
const OFFSET_LENGTHS: [u8; 0x40] = [
    3, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, //
    6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, //
];

/// Codes (emitted low-bit-first) of the fixed offset prefix table.
const OFFSET_CODES: [u32; 0x40] = [
    0x00, 0x02, 0x04, 0x0c, 0x01, 0x06, 0x0a, 0x0e, //
    0x11, 0x16, 0x1a, 0x1e, 0x05, 0x09, 0x0d, 0x15, //
    0x19, 0x1d, 0x25, 0x29, 0x2d, 0x35, 0x39, 0x3d, //
    0x03, 0x07, 0x0b, 0x13, 0x17, 0x1b, 0x23, 0x27, //
    0x2b, 0x33, 0x37, 0x3b, 0x43, 0x47, 0x4b, 0x53, //
    0x57, 0x5b, 0x63, 0x67, 0x6b, 0x73, 0x77, 0x7b, //
    0x0f, 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f, 0x7f, //
    0x8f, 0x9f, 0xaf, 0xbf, 0xcf, 0xdf, 0xef, 0xff, //
];

/// LSB-first bit cursor over a byte slice.
/// Number of extra offset bits at output position `pos`; the usable
/// window grows as output accumulates.
fn extra_offset_bits(pos: u64) -> u8 {
    const BIAS: u64 = 0x3c;
    const EDGES: [u64; 7] = [0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000];
    for (i, edge) in EDGES.iter().enumerate() {
        if pos < edge - BIAS {
            return i as u8;
        }
    }
    7
}

/// Decode a distilled member payload. The stream is authoritative on
/// its own length (the 0x100 symbol terminates it).
pub(crate) fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let header = input
        .get(..3)
        .ok_or(Error::InvalidData("arc: truncated distill header"))?;
    let numnodes = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let codelength = header[2];

    if !(2..=MAX_NODES).contains(&numnodes) || numnodes % 2 != 0 {
        return Err(Error::InvalidData("arc: bad distill node count"));
    }
    if codelength == 0 || codelength > 24 {
        return Err(Error::InvalidData("arc: bad distill code width"));
    }

    let mut bits = LsbBits::new(&input[3..]);
    let mut nodes = Vec::with_capacity(numnodes);
    for _ in 0..numnodes {
        nodes.push(
            bits.read(codelength)
                .ok_or(Error::InvalidData("arc: truncated distill node table"))?,
        );
    }

    // Walk the serialised tree: starting at the root pair (the last
    // two entries), a `0` bit takes `nodes[idx]` and a `1` bit
    // `nodes[idx+1]`; a value >= numnodes is the leaf `value-numnodes`.
    let next_symbol = |bits: &mut LsbBits| -> Result<Option<u32>, Error> {
        let mut idx = numnodes - 2;
        for _ in 0..=numnodes {
            let bit = match bits.read(1) {
                Some(b) => b as usize,
                None => return Ok(None),
            };
            let child = nodes[idx + bit];
            if child as usize >= numnodes {
                return Ok(Some(child - numnodes as u32));
            }
            idx = child as usize;
            if idx + 1 >= numnodes {
                return Err(Error::InvalidData("arc: bad distill node link"));
            }
        }
        Err(Error::InvalidData("arc: malformed distill tree"))
    };

    // Read one offset-table symbol (prefix code, LSB-first, max 8 bits).
    let next_offset = |bits: &mut LsbBits| -> Result<Option<u32>, Error> {
        let mut v = 0u32;
        for len in 1..=8u8 {
            match bits.read(1) {
                Some(b) => v |= b << (len - 1),
                None => return Ok(None),
            }
            for (i, (&c, &l)) in OFFSET_CODES.iter().zip(&OFFSET_LENGTHS).enumerate() {
                if l == len && c == v {
                    return Ok(Some(i as u32));
                }
            }
        }
        Err(Error::InvalidData("arc: bad distill offset code"))
    };

    let mut window = [0u8; WINDOW];
    let mut pos = 0usize; // total emitted bytes
    let mut out = Vec::new();

    loop {
        let symbol =
            next_symbol(&mut bits)?.ok_or(Error::InvalidData("arc: truncated distill stream"))?;
        if symbol == 256 {
            return Ok(out);
        }
        if symbol < 256 {
            window[pos % WINDOW] = symbol as u8;
            pos += 1;
            out.push(symbol as u8);
            continue;
        }

        let length = (symbol - 0x101 + 3) as usize;
        if length > WINDOW {
            return Err(Error::InvalidData("arc: distill match length out of range"));
        }
        let offsym =
            next_offset(&mut bits)?.ok_or(Error::InvalidData("arc: truncated distill offset"))?;
        let extralen = extra_offset_bits(pos as u64);
        let extrabits = bits
            .read(extralen)
            .ok_or(Error::InvalidData("arc: truncated distill offset bits"))?;
        let distance = ((offsym as u64) << extralen) + u64::from(extrabits) + 1;
        if distance > WINDOW as u64 {
            return Err(Error::InvalidData("arc: distill distance out of range"));
        }
        for _ in 0..length {
            let b = window[(pos as u64).wrapping_sub(distance) as usize % WINDOW];
            window[pos % WINDOW] = b;
            pos += 1;
            out.push(b);
        }
    }
}

/// Minimum LZSS match length (symbols encode length - 3).
const MIN_MATCH: usize = 3;
/// Bound on the number of distinct match-length symbols: the
/// serialised tree holds at most MAX_NODES / 2 + 1 leaves and 257
/// are taken by the literal alphabet plus the end-of-stream symbol.
const MAX_LENGTH_SYMS: usize = MAX_NODES / 2 + 1 - 257;
/// Hash-chain table size for the match finder.
const HASH_SIZE: usize = 1 << 15;
/// Chain candidates examined per position.
const CHAIN_DEPTH: usize = 64;

/// A parse token: a literal byte or a back reference.
#[derive(Clone, Copy)]
enum Tok {
    Lit(u8),
    Match { len: usize, dist: usize },
}

fn hash3(input: &[u8], i: usize) -> usize {
    let v = u32::from(input[i]) | (u32::from(input[i + 1]) << 8) | (u32::from(input[i + 2]) << 16);
    (v.wrapping_mul(2_654_435_761) >> 17) as usize
}

/// Greedy hash-chain LZSS parse of the input over the 8 KiB window;
/// overlapping matches (dist below len) are allowed.
fn parse(input: &[u8]) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut head = vec![usize::MAX; HASH_SIZE];
    let mut prev = vec![usize::MAX; input.len().max(1)];
    let mut i = 0usize;
    while i < input.len() {
        let remaining = input.len() - i;
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if remaining >= MIN_MATCH {
            let mut cand = head[hash3(input, i)];
            let limit = remaining.min(WINDOW);
            for _ in 0..CHAIN_DEPTH {
                if cand == usize::MAX {
                    break;
                }
                let dist = i - cand;
                if dist > WINDOW {
                    break;
                }
                let mut l = 0usize;
                while l < limit && input[cand + l] == input[i + l] {
                    l += 1;
                }
                if l > best_len {
                    best_len = l;
                    best_dist = dist;
                    if l >= limit {
                        break;
                    }
                }
                cand = prev[cand];
            }
        }
        let advance = if best_len >= MIN_MATCH {
            toks.push(Tok::Match {
                len: best_len,
                dist: best_dist,
            });
            best_len
        } else {
            toks.push(Tok::Lit(input[i]));
            1
        };
        for (j, slot) in prev.iter_mut().enumerate().skip(i).take(advance) {
            if j + MIN_MATCH <= input.len() {
                let h = hash3(input, j);
                *slot = head[h];
                head[h] = j;
            }
        }
        i += advance;
    }
    toks
}

/// Rewrite matches whose length is outside the allowed set (ascending) as a
/// sum of allowed lengths; irreducible remainders degrade to literals.
/// The second and later pieces keep the original distance: distance
/// d still resolves correctly after a more output bytes.
fn expand(input: &[u8], toks: &[Tok], allowed: &[usize]) -> Vec<Tok> {
    let mut out = Vec::with_capacity(toks.len());
    let mut pos = 0usize;
    for t in toks {
        match *t {
            Tok::Lit(b) => {
                out.push(Tok::Lit(b));
                pos += 1;
            }
            Tok::Match { len, dist } => {
                let mut rem = len;
                while rem > 0 {
                    let piece = allowed
                        .iter()
                        .rev()
                        .copied()
                        .find(|&a| a <= rem && (rem == a || rem - a >= MIN_MATCH));
                    match piece {
                        Some(a) => {
                            out.push(Tok::Match { len: a, dist });
                            rem -= a;
                            pos += a;
                        }
                        None => {
                            out.push(Tok::Lit(input[pos]));
                            rem -= 1;
                            pos += 1;
                        }
                    }
                }
            }
        }
    }
    out
}

/// A Huffman-tree child reference during construction: a leaf symbol
/// or the index of an internal pair in .
#[derive(Clone, Copy)]
enum Child {
    Leaf(u32),
    Pair(u32),
}

/// Assign every leaf its root-to-leaf bit path (emitted first bit
/// first by the LSB-first writer).
fn assign_codes(
    pairs: &[[Child; 2]],
    idx: usize,
    path: &mut Vec<bool>,
    codes: &mut BTreeMap<u32, Vec<bool>>,
) {
    for (bit, child) in pairs[idx].iter().enumerate() {
        path.push(bit == 1);
        match *child {
            Child::Leaf(s) => {
                codes.insert(s, path.clone());
            }
            Child::Pair(i) => assign_codes(pairs, i as usize, path, codes),
        }
        path.pop();
    }
}

/// Encode `input` as a distilled member payload.
pub(crate) fn encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let toks = parse(input);

    // Cap the number of distinct match lengths to what the serialised
    // tree can hold; over-long or rare lengths are split into pieces.
    let mut lenfreq = [0u32; WINDOW + 1];
    for t in &toks {
        if let Tok::Match { len, .. } = *t {
            lenfreq[len] += 1;
        }
    }
    let mut lengths: Vec<usize> = (MIN_MATCH..=WINDOW).filter(|&l| lenfreq[l] > 0).collect();
    let toks = if lengths.len() > MAX_LENGTH_SYMS {
        lengths.sort_by_key(|&l| core::cmp::Reverse(lenfreq[l]));
        lengths.truncate(MAX_LENGTH_SYMS);
        lengths.sort_unstable();
        expand(input, &toks, &lengths)
    } else {
        toks
    };

    // Symbol frequencies: literals 0-255, end-of-stream 256 and match
    // length symbols `len + 0xfe` (= 0x101 + len - 3).
    let mut freq = BTreeMap::<u32, u64>::new();
    for t in &toks {
        let sym = match *t {
            Tok::Lit(b) => u32::from(b),
            Tok::Match { len, .. } => len as u32 + 0xfe,
        };
        *freq.entry(sym).or_insert(0) += 1;
    }
    *freq.entry(256).or_insert(0) += 1;
    let mut syms: Vec<u32> = freq.keys().copied().collect();
    if syms.len() == 1 {
        // A lone leaf (empty input) cannot form a pair; add a dummy
        // leaf that is never emitted.
        syms.insert(0, 0);
    }

    // Huffman merge. Every internal node is one serialised pair; the
    // merge order already places the root pair last, matching the
    // decoder which starts walking at nodes[numnodes - 2].
    let mut pairs: Vec<[Child; 2]> = Vec::new();
    let mut heap: Vec<(u64, usize, Child)> = syms
        .iter()
        .enumerate()
        .map(|(i, &s)| (freq.get(&s).copied().unwrap_or(0), i, Child::Leaf(s)))
        .collect();
    while heap.len() > 1 {
        heap.sort_by_key(|&(f, seq, _)| (f, seq));
        let (fa, _, a) = heap.remove(0);
        let (fb, _, b) = heap.remove(0);
        let idx = pairs.len() as u32;
        pairs.push([a, b]);
        heap.push((fa + fb, syms.len() + idx as usize, Child::Pair(idx)));
    }

    let numnodes = pairs.len() * 2;
    if numnodes > MAX_NODES {
        return Err(Error::InvalidData("arc: distill tree too large"));
    }
    let mut nodes = Vec::with_capacity(numnodes);
    for &[l, r] in &pairs {
        let s = |c: Child| match c {
            Child::Leaf(s) => numnodes as u32 + s,
            Child::Pair(i) => i * 2,
        };
        nodes.push(s(l));
        nodes.push(s(r));
    }
    let maxval = nodes.iter().copied().max().unwrap_or(1);
    let codelength = (32 - maxval.leading_zeros()).max(1) as u8;

    let mut codes = BTreeMap::<u32, Vec<bool>>::new();
    let mut path = Vec::new();
    assign_codes(&pairs, pairs.len() - 1, &mut path, &mut codes);
    let emit_sym = |w: &mut LsbWriter, sym: u32| {
        for &b in &codes[&sym] {
            w.put(u32::from(b), 1);
        }
    };

    let mut w = LsbWriter::new();
    for &v in &nodes {
        w.put(v, u32::from(codelength));
    }
    let mut pos = 0u64;
    for t in &toks {
        match *t {
            Tok::Lit(b) => {
                emit_sym(&mut w, u32::from(b));
                pos += 1;
            }
            Tok::Match { len, dist } => {
                emit_sym(&mut w, len as u32 + 0xfe);
                // distance - 1 = (offsym << extralen) | extrabits; the
                // extralen ladder runs on the output position.
                let extralen = extra_offset_bits(pos);
                let v = (dist - 1) as u32;
                let offsym = (v >> extralen) as usize;
                let (&code, &clen) = OFFSET_CODES
                    .get(offsym)
                    .zip(OFFSET_LENGTHS.get(offsym))
                    .ok_or(Error::InvalidData("arc: distill offset out of range"))?;
                w.put(code, u32::from(clen));
                w.put(v & ((1u32 << extralen) - 1), u32::from(extralen));
                pos += len as u64;
            }
        }
    }
    emit_sym(&mut w, 256);

    let mut out = (numnodes as u16).to_le_bytes().to_vec();
    out.push(codelength);
    out.extend_from_slice(&w.finish());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    /// LSB-first bit writer used to assemble streams in tests.
    struct BitWriter {
        bytes: Vec<u8>,
        cur: u8,
        nbits: u8,
    }

    impl BitWriter {
        fn new() -> Self {
            BitWriter {
                bytes: Vec::new(),
                cur: 0,
                nbits: 0,
            }
        }
        fn bit(&mut self, b: bool) {
            if b {
                self.cur |= 1 << self.nbits;
            }
            self.nbits += 1;
            if self.nbits == 8 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.nbits = 0;
            }
        }
        fn bits(&mut self, val: u32, n: u8) {
            for i in 0..n {
                self.bit((val >> i) & 1 != 0);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push(self.cur);
            }
            self.bytes
        }
    }

    /// Assemble a distilled stream from a node array and a symbol code
    /// table: `codes[i]` is the bit path (decode order) for leaf `i`.
    fn build(nodes: &[u32], symbols: &[(u32, u32, Vec<bool>)]) -> Vec<u8> {
        let codelength = (32 - nodes.iter().max().copied().unwrap_or(1).leading_zeros()).max(1);
        let mut out = (nodes.len() as u16).to_le_bytes().to_vec();
        out.push(codelength as u8);
        let mut bw = BitWriter::new();
        for &v in nodes {
            bw.bits(v, codelength as u8);
        }
        let mut pos = 0u64;
        for &(sym, arg, ref path) in symbols {
            for &b in path {
                bw.bit(b);
            }
            if sym > 256 {
                // arg carries (distance, length) packed for convenience.
                let (distance, _length) = ((arg >> 16) as usize, (arg & 0xffff) as usize);
                let extralen = extra_offset_bits(pos);
                let v = (distance as u32) - 1;
                let offsym = (v >> extralen) as usize;
                bw.bits(OFFSET_CODES[offsym], OFFSET_LENGTHS[offsym]);
                bw.bits(v & ((1u32 << extralen) - 1), extralen);
                pos += ((sym - 0x101 + 3) as u64).min(pos + WINDOW as u64);
            } else {
                pos += 1;
            }
        }
        out.extend_from_slice(&bw.finish());
        out
    }

    #[test]
    fn literal_stream() {
        // Tree: 0 -> 'A' (leaf 2+65=67), 1 -> EOF (leaf 2+256=258).
        let nodes = [67u32, 258];
        // Root pair is nodes[0..2]; 'A' takes bit 0, EOF bit 1.
        let stream = build(&nodes, &[(65, 0, vec![false]), (256, 0, vec![true])]);
        assert_eq!(decode(&stream).unwrap(), b"A");
    }

    #[test]
    fn multi_literal_stream() {
        // Right-leaning chain over {B, A, N, EOF} for "BANANA".
        // nodes: [n+leaf('N'), n+leaf(EOF), n+leaf('A'), 0, n+leaf('B'), 2]
        // internal pairs: [leaf('N'), leaf(EOF)] -> idx 0; [leaf('A'), idx0]
        //   -> idx 2; [leaf('B'), idx2] -> idx 4 (root).
        let n = 6u32;
        let nodes = [n + 78, n + 256, n + 65, 0, n + 66, 2];
        // Codes: B=0, A=10, N=110, EOF=111.
        let s = build(
            &nodes,
            &[
                (66, 0, vec![false]),
                (65, 0, vec![true, false]),
                (78, 0, vec![true, true, false]),
                (65, 0, vec![true, false]),
                (78, 0, vec![true, true, false]),
                (65, 0, vec![true, false]),
                (256, 0, vec![true, true, true]),
            ],
        );
        assert_eq!(decode(&s).unwrap(), b"BANANA");
    }

    #[test]
    fn match_stream() {
        // "AB" then a length-4 match at distance 2 -> "ABABAB".
        // Symbols: A=0, B=10, match-len-4 (0x101+1)=110, EOF=111.
        let n = 6u32;
        let nodes = [n + 0x102, n + 256, n + 66, 0, n + 65, 2];
        let mlen4 = 0x101u32 + 1;
        let s = build(
            &nodes,
            &[
                (65, 0, vec![false]),
                (66, 0, vec![true, false]),
                // match: distance 2 -> sym mlen4, offset value v=1:
                // extra bits at pos=2 is 0 (2 < 0x40-0x3c), offsym=1.
                (mlen4, (2 << 16) | 4, vec![true, true, false]),
                (256, 0, vec![true, true, true]),
            ],
        );
        assert_eq!(decode(&s).unwrap(), b"ABABAB");
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x02, 0x00]).is_err());
        // numnodes < 2.
        assert!(decode(&[0x01, 0x00, 0x09]).is_err());
        // Truncated node table.
        assert!(decode(&[0x02, 0x00, 0x09, 0x00]).is_err());
    }
}

#[cfg(test)]
mod encode_tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let enc = encode(data).unwrap();
        decode(&enc).unwrap()
    }

    #[test]
    fn encode_roundtrip_basic() {
        assert_eq!(roundtrip(b""), b"");
        assert_eq!(roundtrip(b"x"), b"x");
        assert_eq!(roundtrip(b"AAAA"), b"AAAA");
        assert_eq!(roundtrip(b"banana banana"), b"banana banana");
        assert_eq!(roundtrip(b"the quick brown fox"), b"the quick brown fox");
    }

    #[test]
    fn encode_roundtrip_matches() {
        // Long run: overlapping matches at distance 1 exercising the
        // largest length symbols.
        let run = vec![b'a'; 20000];
        assert_eq!(roundtrip(&run), run);
        // Repeated block crossing the 8 KiB window.
        let rep = b"abcdefghij".repeat(3000);
        assert_eq!(roundtrip(&rep), rep);
    }

    #[test]
    fn encode_roundtrip_mixed() {
        let mut data = b"the quick brown fox. ".repeat(500).to_vec();
        data.extend((0..40000usize).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
        let head = data[..8000].to_vec();
        data.extend_from_slice(&head);
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn encode_caps_match_length_symbols() {
        // More than MAX_LENGTH_SYMS distinct match lengths: repeated
        // unique blocks of every size 3..=140. Rare lengths are split
        // into allowed pieces; the node count must stay in bounds.
        let mut data = Vec::new();
        let mut x = 0x1234_5678u32;
        for n in MIN_MATCH..=140usize {
            let blk: Vec<u8> = (0..n)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 16) as u8
                })
                .collect();
            data.extend_from_slice(&blk);
            data.extend_from_slice(&blk);
        }
        let enc = encode(&data).unwrap();
        let numnodes = usize::from(u16::from_le_bytes([enc[0], enc[1]]));
        assert!(numnodes <= MAX_NODES);
        assert_eq!(decode(&enc).unwrap(), data);
    }

    #[test]
    fn encode_header_layout() {
        // Empty input: a single pair joining a dummy leaf and EOF.
        let enc = encode(b"").unwrap();
        assert_eq!(&enc[..2], &2u16.to_le_bytes());
        let codelength = enc[2];
        assert!((1..=24).contains(&codelength));
        // numnodes * codelength bits of node table plus the EOF path.
        let bits = 2 * usize::from(codelength) + 1;
        assert_eq!(enc.len(), 3 + bits.div_ceil(8));
    }
}
