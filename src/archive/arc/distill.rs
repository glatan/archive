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

use alloc::vec::Vec;

use crate::error::Error;

use super::bits::LsbBits;

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
