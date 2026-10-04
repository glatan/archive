//! Static canonical-Huffman machinery shared by the block-structured
//! LZH methods (`-lh4-` through `-lh7-`).
//!
//! Each block carries three serialized code-length tables: a small
//! "temp" table that encodes the main literal/length table, and a
//! separate offset-length table. Symbols decode through a plain
//! binary trie (`left`/`right` links; node ids start at `nchar` and
//! links below `nchar` are leaf symbols).
//!
//! Format reference: Haruhiko Okumura's `ar002` `huf.c`
//! (`make_table`/`read_pt_len`/`read_c_len` equivalents), released
//! by the author to the public domain. Behaviour cross-checked
//! against lhasa `lh_new_decoder.c` (ISC). Not derived from LHa for
//! UNIX source (non-OSI license).

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::bits::MsbReader;

/// Maximum code length in the LZH schemes.
const MAX_LEN: usize = 16;

/// A decoded static Huffman table as a binary trie.
pub(crate) struct Table {
    /// Left/right links per internal node; node ids start at `nchar`,
    /// link values `< nchar` are leaf symbols.
    left: Vec<u16>,
    right: Vec<u16>,
    /// Root node id; `None` only for the constant table.
    root: u16,
    nchar: usize,
    /// Constant table (`n == 0` case): always yields this symbol and
    /// consumes no bits.
    single: Option<u16>,
}

impl Table {
    /// Build a trie from per-symbol code lengths (0 = absent).
    ///
    /// Errors when the lengths do not form a complete prefix code
    /// (the Kraft sum must exhaust the 16-bit code space), matching
    /// the reference decoder's `total & 0xFFFF` check.
    pub(crate) fn build(nchar: usize, lens: &[u8]) -> Result<Table, Error> {
        let mut count = [0usize; MAX_LEN + 1];
        for &l in lens.iter().take(nchar) {
            if usize::from(l) > MAX_LEN {
                return Err(Error::InvalidData("lha: bad huffman length"));
            }
            count[usize::from(l)] += 1;
        }
        // Kraft sum in 16-bit left-aligned units; a complete code
        // totals exactly 0x10000.
        let mut total = 0usize;
        for (i, &c) in count.iter().enumerate().skip(1) {
            total += c << (16 - i);
        }
        if total & 0xffff != 0 || total > 0x1_0000 {
            return Err(Error::InvalidData("lha: bad huffman table"));
        }
        // Canonical first code per length.
        let mut next = [0u32; MAX_LEN + 1];
        let mut code = 0u32;
        for l in 1..=MAX_LEN {
            code = (code + count[l - 1] as u32) << 1;
            next[l] = code;
        }

        let mut t = Table {
            left: vec![0u16; nchar * 2],
            right: vec![0u16; nchar * 2],
            root: nchar as u16,
            nchar,
            single: None,
        };
        let mut avail = nchar + 1;
        for (sym, &kl) in lens.iter().enumerate().take(nchar) {
            let k = usize::from(kl);
            if k == 0 {
                continue;
            }
            let code = next[k];
            next[k] += 1;
            let mut node = usize::from(t.root);
            for shift in (0..k).rev() {
                let bit = (code >> shift) & 1;
                let link = if bit != 0 {
                    &mut t.right[node]
                } else {
                    &mut t.left[node]
                };
                if shift == 0 {
                    *link = sym as u16;
                } else {
                    if *link == 0 {
                        *link = avail as u16;
                        avail += 1;
                    }
                    node = usize::from(*link);
                }
            }
        }
        Ok(t)
    }

    /// Table where every code resolves to `sym` and consumes no bits
    /// (the `n == 0` degenerate case of the length readers).
    pub(crate) fn constant(sym: u16) -> Table {
        Table {
            left: Vec::new(),
            right: Vec::new(),
            root: 0,
            nchar: 0,
            single: Some(sym),
        }
    }

    /// Decode one symbol, consuming its code length.
    pub(crate) fn decode(&self, r: &mut MsbReader<'_>) -> Result<u16, Error> {
        if let Some(s) = self.single {
            return Ok(s);
        }
        let mut node = usize::from(self.root);
        loop {
            let v = if r.get(1) != 0 {
                usize::from(*self.right.get(node).unwrap_or(&0))
            } else {
                usize::from(*self.left.get(node).unwrap_or(&0))
            };
            if v < self.nchar {
                return Ok(v as u16);
            }
            if v >= self.left.len() {
                return Err(Error::InvalidData("lha: bad huffman link"));
            }
            node = v;
        }
    }
}

/// Read a `pt_len` style table: `nbit`-wide symbol count, then
/// per-symbol 3-bit lengths with the all-ones extension; after
/// `i_special` symbols a 2-bit count inserts that many zero lengths.
/// `nn` is the alphabet size. `i_special == usize::MAX` disables the
/// zero-run insert (offset tables have none).
pub(crate) fn read_pt_len(
    r: &mut MsbReader<'_>,
    nn: usize,
    nbit: u32,
    i_special: usize,
) -> Result<Table, Error> {
    let n = usize::try_from(r.get(nbit)).unwrap_or(0);
    if n == 0 {
        let c = u16::try_from(r.get(nbit)).unwrap_or(0);
        return Ok(Table::constant(c));
    }
    if r.overran() {
        return Err(Error::InvalidData("lha: truncated huffman table"));
    }
    let n = n.min(nn);
    let mut lens = vec![0u8; nn];
    let mut i = 0usize;
    while i < n {
        // 3-bit length; a value of 7 means keep reading 1 bits, each
        // adding one, until a 0 bit.
        let mut len3 = r.get(3);
        if len3 == 7 {
            while r.get(1) != 0 {
                len3 += 1;
                if len3 > MAX_LEN as u32 {
                    return Err(Error::InvalidData("lha: bad length code"));
                }
            }
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated huffman table"));
        }
        lens[i] = len3 as u8;
        i += 1;
        if i == i_special {
            i = (i + usize::try_from(r.get(2)).unwrap_or(0)).min(nn);
        }
    }
    Table::build(nn, &lens)
}

/// Read a `c_len` style table: `cbit`-wide symbol count decoded
/// through the previous `pt_len` table, with 0/1/2-coded zero runs
/// (1, 4-bit+3, 9-bit+20).
pub(crate) fn read_c_len(
    r: &mut MsbReader<'_>,
    pt: &Table,
    nc: usize,
    cbit: u32,
) -> Result<Table, Error> {
    let n = usize::try_from(r.get(cbit)).unwrap_or(0);
    if n == 0 {
        let c = u16::try_from(r.get(cbit)).unwrap_or(0);
        return Ok(Table::constant(c));
    }
    let n = n.min(nc);
    let mut lens = vec![0u8; nc];
    let mut i = 0usize;
    while i < n {
        let c = usize::from(pt.decode(r)?);
        if c <= 2 {
            let zeros = match c {
                0 => 1,
                1 => usize::try_from(r.get(4)).unwrap_or(0) + 3,
                _ => usize::try_from(r.get(9)).unwrap_or(0) + 20,
            };
            i = (i + zeros).min(nc);
        } else {
            lens[i] = (c - 2) as u8;
            i += 1;
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated huffman table"));
        }
    }
    Table::build(nc, &lens)
}
