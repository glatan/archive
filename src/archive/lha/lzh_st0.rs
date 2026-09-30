//! LHA `-lh3-` decoder ("st0" static-Huffman LZH, 8 KiB history ring).
//!
//! The payload is a sequence of blocks. Each block starts with a
//! 16-bit command count, then a serialized literal/match code-length
//! table, then a flag bit selecting either a serialized position
//! table or a built-in fixed position table. A code below 256 is a
//! literal; otherwise it is a match of `code - 253` bytes at distance
//! `pos + 1`, where `pos` is a position symbol shifted left by 6 plus
//! 6 low bits. Code 285 reads 8 extra bits, extending the match
//! length to `32 + extra`.
//!
//! The literal/match alphabet is 286 symbols; the position alphabet
//! is 128 symbols (one per 64 bytes of the 8 KiB ring). Both
//! serialized tables carry a degenerate "all one symbol" escape that
//! the reference writes by reading the first three lengths (all
//! forced to 1) and then a constant symbol.
//!
//! Behaviour-matched/adapted from LHa for
//! UNIX `shuf.c` (`decode_c_st0`/`decode_p_st0`/`read_tree_c`/
//! `read_tree_p`) and the XADMaster port in `XADLZHOldHandles.m`.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use crate::compress::lzh::bits::MsbReader;
use crate::compress::lzh::huf::Table;

/// log2 of the history ring size.
const DICBIT: usize = 13;
/// Literal + match alphabet size.
const N1: usize = 286;
/// Position alphabet size (8 KiB ring in 64-byte units).
const NP: usize = 128;
/// Code that reads 8 extra bits before the length is known.
const N1_SPECIAL: usize = N1 - 1;
/// Bit width of the serialized length fields.
const LENFIELD: u32 = 4;
/// Bit width of the serialized constant literal/match symbol.
const CBIT: u32 = 9;
/// Bit width of the serialized constant position symbol
/// (XADMaster reads `MAX_DICBIT - 6` = 10 bits).
const P_CBIT: u32 = 10;
/// Block command count width.
const BUFBITS: u32 = 16;

/// The built-in position code-length table (`ready_made(1)`, the
/// "8K buf" row of `fixed` in the reference sources).
fn fixed_pt_lens() -> [u8; NP] {
    const BOUNDS: [usize; 7] = [1, 1, 3, 6, 0x0d, 0x1f, 0x4e];
    let mut lens = [0u8; NP];
    let mut j = 2u8;
    let mut b = 0usize;
    for (i, len) in lens.iter_mut().enumerate() {
        while b < BOUNDS.len() && BOUNDS[b] == i {
            j += 1;
            b += 1;
        }
        *len = j;
    }
    lens
}

/// Read the serialized literal/match table: for each of `N1`
/// symbols a 1-bit flag tells whether a `LENFIELD`-wide length
/// (+1) follows; symbol 0 otherwise. After the third symbol, three
/// consecutive lengths of 1 mean the table is degenerate and a
/// `CBIT`-wide constant symbol follows.
fn read_tree_c(r: &mut MsbReader<'_>) -> Result<Table, Error> {
    let mut lens = [0u8; N1];
    let mut i = 0usize;
    while i < N1 {
        lens[i] = if r.get(1) != 0 {
            u8::try_from(r.get(LENFIELD)).unwrap_or(0) + 1
        } else {
            0
        };
        i += 1;
        if i == 3 && lens[0] == 1 && lens[1] == 1 && lens[2] == 1 {
            let c = u16::try_from(r.get(CBIT)).unwrap_or(0);
            return Ok(Table::constant(c));
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated st0 table"));
        }
    }
    Table::build(N1, &lens)
}

/// Read the serialized position table: `NP` symbols with
/// `LENFIELD`-wide lengths, with the same degenerate escape as the
/// literal/match table but a `P_CBIT`-wide constant.
fn read_tree_p(r: &mut MsbReader<'_>) -> Result<Table, Error> {
    let mut lens = [0u8; NP];
    let mut i = 0usize;
    while i < NP {
        lens[i] = u8::try_from(r.get(LENFIELD)).unwrap_or(0);
        i += 1;
        if i == 3 && lens[0] == 1 && lens[1] == 1 && lens[2] == 1 {
            let c = u16::try_from(r.get(P_CBIT)).unwrap_or(0);
            return Ok(Table::constant(c));
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated st0 table"));
        }
    }
    Table::build(NP, &lens)
}

/// `true` when `method` is `-lh3-`.
pub(crate) fn supported(method: &[u8; 5]) -> bool {
    method == b"-lh3-"
}

/// Decode an `-lh3-` payload to `expected` bytes.
pub(crate) fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let n = 1usize << DICBIT;
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
            remaining = usize::try_from(r.get(BUFBITS)).unwrap_or(0);
            c_tab = read_tree_c(&mut r)?;
            if r.get(1) != 0 {
                p_tab = read_tree_p(&mut r)?;
            } else {
                p_tab = Table::build(NP, &fixed_pt_lens())?;
            }
            if r.overran() {
                return Err(Error::InvalidData("lha: truncated block"));
            }
        }
        remaining -= 1;
        let mut c = usize::from(c_tab.decode(&mut r)?);
        if c == N1_SPECIAL {
            c += usize::try_from(r.get(8)).unwrap_or(0);
        }
        if c < 256 {
            out.push(c as u8);
            ring[w] = c as u8;
            w = (w + 1) & (n - 1);
        } else {
            // Position = symbol * 64 + 6 low bits; distance = pos + 1.
            let j = usize::from(p_tab.decode(&mut r)?);
            let pos = (j << 6) + usize::try_from(r.get(6)).unwrap_or(0);
            if r.overran() {
                return Err(Error::InvalidData("lha: truncated stream"));
            }
            let len = c + 3 - 256;
            let mut src = (w + n - pos - 1) & (n - 1);
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
    use crate::compress::lzh::bits::MsbWriter;

    /// Canonical codes for a length table (first code per length in
    /// increasing-length order, matching `Table::build`).
    fn canonical_codes(lens: &[u8]) -> Vec<u32> {
        let mut count = [0u32; 17];
        for &l in lens {
            count[usize::from(l)] += 1;
        }
        let mut next = [0u32; 17];
        let mut code = 0u32;
        for l in 1..=16 {
            code = (code + count[l - 1]) << 1;
            next[l] = code;
        }
        lens.iter()
            .map(|&l| {
                if l == 0 {
                    0
                } else {
                    let c = next[usize::from(l)];
                    next[usize::from(l)] += 1;
                    c
                }
            })
            .collect()
    }

    /// Minimal complete-code lengths for `n` used symbols: `2^d - n`
    /// leaves at depth `d - 1` and the rest at depth `d`.
    fn complete_lens(n: usize) -> Vec<u8> {
        let mut d = 0usize;
        while (1usize << d) < n {
            d += 1;
        }
        let x = (1usize << d) - n;
        (0..n)
            .map(|i| if i < x { (d - 1) as u8 } else { d as u8 })
            .collect()
    }

    /// Emit a serialized literal/match table for `syms` (sorted used
    /// symbols) with complete-code lengths; returns the full `N1`
    /// entry length map.
    fn emit_tree_c(w: &mut MsbWriter, syms: &[usize]) -> Vec<u8> {
        let lens = complete_lens(syms.len());
        let mut lenmap = [0u8; N1];
        for (i, &s) in syms.iter().enumerate() {
            lenmap[s] = lens[i];
        }
        let mut out_lens = vec![0u8; N1];
        for (i, l) in lenmap.iter().enumerate() {
            if *l == 0 {
                w.put(0, 1);
            } else {
                w.put(1, 1);
                w.put(u32::from(*l - 1), LENFIELD);
            }
            out_lens[i] = *l;
        }
        out_lens
    }

    /// Build an st0 payload: one block of literals/matches emitted
    /// through a serialized c table and the fixed position table.
    /// `cmds` are `Ok(byte)` literals or `Err((len, dist))` matches.
    fn encode(cmds: &[Result<u8, (usize, usize)>]) -> Vec<u8> {
        let mut syms: Vec<usize> = cmds
            .iter()
            .map(|c| match c {
                Ok(b) => usize::from(*b),
                Err((len, _)) => {
                    if *len >= 32 {
                        N1_SPECIAL
                    } else {
                        len + 253
                    }
                }
            })
            .collect();
        syms.sort_unstable();
        syms.dedup();

        let mut w = MsbWriter::new();
        w.put(cmds.len() as u32, BUFBITS);
        let lens = emit_tree_c(&mut w, &syms);
        let codes = canonical_codes(&lens);
        w.put(0, 1); // fixed position table
        let pt_lens = fixed_pt_lens();
        let pt_codes = canonical_codes(&pt_lens);
        for c in cmds {
            match *c {
                Ok(b) => {
                    let s = usize::from(b);
                    w.put(codes[s], u32::from(lens[s]));
                }
                Err((len, dist)) => {
                    let (s, extra) = if len >= 32 {
                        (N1_SPECIAL, Some((len - 32) as u32))
                    } else {
                        (len + 253, None)
                    };
                    w.put(codes[s], u32::from(lens[s]));
                    if let Some(e) = extra {
                        w.put(e, 8);
                    }
                    let j = (dist - 1) >> 6;
                    w.put(pt_codes[j], u32::from(pt_lens[j]));
                    w.put(((dist - 1) & 0x3f) as u32, 6);
                }
            }
        }
        w.finish()
    }

    #[test]
    fn literals_only() {
        let payload = encode(&[Ok(b'A'), Ok(b'B'), Ok(b'A'), Ok(0xff)]);
        let out = decode(&payload, 4).unwrap();
        assert_eq!(out, b"ABA\xff");
    }

    #[test]
    fn matches_fixed_pt() {
        let mut cmds: Vec<Result<u8, (usize, usize)>> = b"hello".iter().map(|b| Ok(*b)).collect();
        // len-4 match at distance 5 copies "hell".
        cmds.push(Err((4, 5)));
        let payload = encode(&cmds);
        let out = decode(&payload, 9).unwrap();
        assert_eq!(out, b"hellohell");
    }

    #[test]
    fn long_match_extra_bits() {
        let mut cmds: Vec<Result<u8, (usize, usize)>> = b"xy".iter().map(|b| Ok(*b)).collect();
        // len-40 (> 31) at dist 2: uses code 285 + extra bits.
        cmds.push(Err((40, 2)));
        let payload = encode(&cmds);
        let out = decode(&payload, 42).unwrap();
        assert_eq!(out.len(), 42);
        assert_eq!(&out[..2], b"xy");
        assert_eq!(&out[2..4], b"xy");
    }

    #[test]
    fn constant_c_table() {
        // Degenerate table: three lengths of 1, then constant 'K'.
        let mut w = MsbWriter::new();
        w.put(5, BUFBITS); // five commands
        for _ in 0..3 {
            w.put(1, 1);
            w.put(0, LENFIELD); // length 1
        }
        w.put(u32::from(b'K'), CBIT);
        w.put(0, 1); // fixed pt (unused: constant = literal)
        let payload = w.finish();
        let out = decode(&payload, 5).unwrap();
        assert_eq!(out, b"KKKKK");
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[0, 4], 10).is_err());
    }

    /// The fixture payload: literals plus matches at several
    /// distances including a symbol-285 length extension.
    type Cmd = Result<u8, (usize, usize)>;

    fn fixture_cmds() -> (Vec<Cmd>, Vec<u8>) {
        let mut expected: Vec<u8> = Vec::new();
        let mut cmds: Vec<Cmd> = Vec::new();
        for i in 0u32..200 {
            let b = ((i * 53 + 7) & 0xff) as u8;
            cmds.push(Ok(b));
            expected.push(b);
        }
        for (len, dist) in [(5usize, 4usize), (20, 150), (40, 77), (3, 1)] {
            let pos = expected.len() - dist;
            cmds.push(Err((len, dist)));
            for k in 0..len {
                let b = expected[pos + k];
                expected.push(b);
            }
        }
        (cmds, expected)
    }

    #[test]
    fn fixture_payload_roundtrip() {
        let (cmds, expected) = fixture_cmds();
        let payload = encode(&cmds);
        let out = decode(&payload, expected.len()).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn archive_roundtrip() {
        let (cmds, expected) = fixture_cmds();
        let payload = encode(&cmds);
        let a = crate::archive::lha::decode::level0_archive(
            b"-lh3-",
            "st0.bin",
            &payload,
            expected.len(),
            &expected,
        );
        let e = crate::archive::lha::decode::decode(&a).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "st0.bin");
        assert_eq!(e[0].data, expected);
    }
}
