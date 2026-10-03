//! LHA `-lh2-` decoder ("dyn" dynamic-Huffman LZH, 8 KiB history
//! ring).
//!
//! Both the literal/match alphabet (286 base symbols; symbol 285
//! carries an 8-bit extension reaching match length 287) and the
//! position alphabet (up to 128 symbols in 64-byte units) use
//! adaptive Huffman trees that update after every decoded symbol.
//! The position tree additionally grows a new leaf every time the
//! emitted byte count crosses a multiple of 64, so position symbol
//! `s` only exists once `s * 64` bytes are in the history.
//!
//! Tree representation (Yoshizaki/Okumura "dynamic Huffman"): nodes
//! live in frequency-sorted arrays; `child[v]` holds a leaf's
//! `!symbol` marker or the head of the node's child pair (siblings
//! occupy adjacent indices `head`/`head - 1`). `block`/`edge`/`stock`
//! track equal-frequency runs so `swap_inc` can promote a node to
//! the front of its frequency class in O(1).
//!
//! Transliterated from LHa for
//! UNIX `dhuf.c` (`decode_c_dyn`/`decode_p_dyn`, `reconst`,
//! `swap_inc`, `make_new_node`) and the XADMaster port in
//! `XADLZHOldHandles.m` (`LhA_Decrunch` for `-lh2-`).
//!
//! Upstream copyright/attribution notice retained per the LHa for UNIX
//! free-use terms (verbatim from `dhuf.c`):
//!
//! ```text
//! LHa for UNIX
//!             dhuf.c -- Dynamic Hufffman routine
//!
//!     Modified                H.Yoshizaki
//!
//! Ver. 1.14   Source All chagned              1995.01.14  N.Watazaki
//! ```

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use crate::compress::lzh::bits::MsbReader;

/// `N_CHAR` in the reference: position leaves are tagged
/// `!(p + N_CHAR)` so both trees can share the `child`/`s_node`
/// arrays split at `ROOT_P`.
const N_CHAR: usize = 314;
/// Literal/match alphabet size (`n_max`).
const N_MAX: usize = 286;
/// Literal/match tree array size.
const TREESIZE_C: usize = N_CHAR * 2;
/// Position tree array size (128 leaf symbols max).
const TREESIZE_P: usize = 128 * 2;
const TREESIZE: usize = TREESIZE_C + TREESIZE_P;
/// Root node index of the literal/match tree.
const ROOT_C: usize = 0;
/// Root node index of the position tree.
const ROOT_P: usize = TREESIZE_C;
/// log2 of the history ring size.
const DICBIT: usize = 13;
/// Symbol carrying the 8-bit length extension (`n1`).
const N1: usize = N_MAX - 1;
/// Frequency threshold that triggers a tree rebuild.
const RECONST_FREQ: u32 = 0x8000;
/// Position trees grow one leaf per this many emitted bytes.
const P_NODE_SPAN: u64 = 64;

/// Adaptive-tree state shared by the literal/match and position
/// trees (both live in the same arrays, split at `ROOT_P`).
struct Dyn {
    freq: Vec<u32>,
    /// `child[v]` = `!symbol` for leaves, children-pair head
    /// otherwise; siblings are `head` and `head - 1`.
    child: Vec<i32>,
    parent: Vec<u16>,
    block: Vec<u16>,
    edge: Vec<u16>,
    stock: Vec<u16>,
    /// Symbol -> leaf node index (position symbols offset by N_CHAR).
    s_node: Vec<u16>,
    /// Stack pointer into `stock` (free frequency-class ids).
    avail: usize,
    /// Rightmost node of the position tree (grows by 2 per leaf).
    most_p: usize,
    /// Total position-tree frequency (rebuild trigger).
    total_p: u32,
    /// Next output-byte count at which a position leaf is added.
    nextcount: u64,
}

impl Dyn {
    fn new() -> Self {
        let mut d = Dyn {
            freq: vec![0u32; TREESIZE],
            child: vec![0i32; TREESIZE],
            parent: vec![0u16; TREESIZE],
            block: vec![0u16; TREESIZE],
            edge: vec![0u16; TREESIZE],
            stock: vec![0u16; TREESIZE],
            s_node: vec![0u16; TREESIZE / 2],
            avail: 0,
            most_p: 0,
            total_p: 0,
            nextcount: P_NODE_SPAN,
        };
        // start_c_dyn: leaves for every symbol at the tail of the
        // frequency array, internal nodes built right-to-left.
        for i in 0..TREESIZE_C {
            d.stock[i] = i as u16;
            d.block[i] = 0;
        }
        let mut i = 0usize;
        let mut j = N_MAX * 2 - 2;
        while i < N_MAX {
            d.freq[j] = 1;
            d.child[j] = !(i as i32);
            d.s_node[i] = j as u16;
            d.block[j] = 1;
            i += 1;
            j -= 1;
        }
        d.avail = 2;
        d.edge[1] = (N_MAX - 1) as u16;
        i = N_MAX * 2 - 2;
        loop {
            let f = d.freq[i] + d.freq[i - 1];
            d.freq[j] = f;
            d.child[j] = i as i32;
            d.parent[i] = j as u16;
            d.parent[i - 1] = j as u16;
            if f == d.freq[j + 1] {
                d.block[j] = d.block[j + 1];
                d.edge[usize::from(d.block[j])] = j as u16;
            } else {
                let b = usize::from(d.stock[d.avail]);
                d.avail += 1;
                d.block[j] = b as u16;
                d.edge[b] = j as u16;
            }
            if j == 0 {
                break;
            }
            i -= 2;
            j -= 1;
        }
        // start_p_dyn: single leaf for position symbol 0.
        d.freq[ROOT_P] = 1;
        d.child[ROOT_P] = !(N_CHAR as i32);
        d.s_node[N_CHAR] = ROOT_P as u16;
        let b = usize::from(d.stock[d.avail]);
        d.avail += 1;
        d.block[ROOT_P] = b as u16;
        d.edge[b] = ROOT_P as u16;
        d.most_p = ROOT_P;
        d.total_p = 0;
        d
    }

    /// Halve leaf frequencies and rebuild the node order for
    /// `[start, end)` (`reconst` in the reference).
    fn reconst(&mut self, start: usize, end: usize) {
        let mut b = 0usize;
        let mut j = start;
        for i in start..end {
            let k = self.child[i];
            if k < 0 {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.child[j] = k;
                j += 1;
            }
            b = usize::from(self.block[i]);
            if usize::from(self.edge[b]) == i {
                self.avail -= 1;
                self.stock[self.avail] = b as u16;
            }
        }
        let mut j = j as i64 - 1;
        let mut i = end as i64 - 1;
        let mut l = end as i64 - 2;
        while i >= start as i64 {
            while i >= l {
                self.freq[i as usize] = self.freq[j as usize];
                self.child[i as usize] = self.child[j as usize];
                i -= 1;
                j -= 1;
            }
            let f = self.freq[l as usize] + self.freq[(l + 1) as usize];
            let mut k = start;
            while f < self.freq[k] {
                k += 1;
            }
            while j >= k as i64 {
                self.freq[i as usize] = self.freq[j as usize];
                self.child[i as usize] = self.child[j as usize];
                i -= 1;
                j -= 1;
            }
            self.freq[i as usize] = f;
            self.child[i as usize] = (l + 1) as i32;
            i -= 1;
            l -= 2;
        }
        let mut f = 0u32;
        for i in start..end {
            let jc = self.child[i];
            if jc < 0 {
                self.s_node[(!jc) as usize] = i as u16;
            } else {
                let jc = jc as usize;
                self.parent[jc] = i as u16;
                self.parent[jc - 1] = i as u16;
            }
            let g = self.freq[i];
            if g == f {
                self.block[i] = b as u16;
            } else {
                b = usize::from(self.stock[self.avail]);
                self.avail += 1;
                self.block[i] = b as u16;
                self.edge[b] = i as u16;
                f = g;
            }
        }
    }

    /// Increment node `p`'s frequency, swapping with the frequency
    /// class leader when needed; returns `p`'s parent
    /// (`swap_inc` in the reference).
    fn swap_inc(&mut self, mut p: usize) -> usize {
        let b = usize::from(self.block[p]);
        let q = usize::from(self.edge[b]);
        if q != p {
            // Swap `p` with the class leader `q`.
            let rp = self.child[p];
            let s = self.child[q];
            self.child[p] = s;
            self.child[q] = rp;
            if rp >= 0 {
                let rp = rp as usize;
                self.parent[rp] = q as u16;
                self.parent[rp - 1] = q as u16;
            } else {
                self.s_node[(!rp) as usize] = q as u16;
            }
            if s >= 0 {
                let s = s as usize;
                self.parent[s] = p as u16;
                self.parent[s - 1] = p as u16;
            } else {
                self.s_node[(!s) as usize] = p as u16;
            }
            p = q;
            self.edge[b] += 1;
            self.freq[p] += 1;
            if self.freq[p] == self.freq[p - 1] {
                self.block[p] = self.block[p - 1];
            } else {
                let nb = usize::from(self.stock[self.avail]);
                self.avail += 1;
                self.block[p] = nb as u16;
                self.edge[nb] = p as u16;
            }
        } else if b == usize::from(self.block[p + 1]) {
            self.edge[b] += 1;
            self.freq[p] += 1;
            if self.freq[p] == self.freq[p - 1] {
                self.block[p] = self.block[p - 1];
            } else {
                let nb = usize::from(self.stock[self.avail]);
                self.avail += 1;
                self.block[p] = nb as u16;
                self.edge[nb] = p as u16;
            }
        } else {
            self.freq[p] += 1;
            if self.freq[p] == self.freq[p - 1] {
                self.avail -= 1;
                self.stock[self.avail] = b as u16;
                self.block[p] = self.block[p - 1];
            }
        }
        usize::from(self.parent[p])
    }

    fn update_c(&mut self, sym: usize) {
        if self.freq[ROOT_C] == RECONST_FREQ {
            self.reconst(0, N_MAX * 2 - 1);
        }
        self.freq[ROOT_C] += 1;
        let mut q = usize::from(self.s_node[sym]);
        loop {
            q = self.swap_inc(q);
            if q == ROOT_C {
                break;
            }
        }
    }

    fn update_p(&mut self, sym: usize) {
        if self.total_p == RECONST_FREQ {
            self.reconst(ROOT_P, self.most_p + 1);
            self.total_p = self.freq[ROOT_P];
            self.freq[ROOT_P] = 0xffff;
        }
        let mut q = usize::from(self.s_node[sym + N_CHAR]);
        while q != ROOT_P {
            q = self.swap_inc(q);
        }
        self.total_p += 1;
    }

    /// Split the rightmost position leaf into two children, making
    /// room for position symbol `p` (`make_new_node`).
    fn make_new_node(&mut self, p: usize) {
        let r = self.most_p + 1;
        let q = r + 1;
        let old = self.child[self.most_p];
        self.child[r] = old;
        self.s_node[(!old) as usize] = r as u16;
        self.child[q] = !((p + N_CHAR) as i32);
        self.child[self.most_p] = q as i32;
        self.freq[r] = self.freq[self.most_p];
        self.freq[q] = 0;
        self.block[r] = self.block[self.most_p];
        if self.most_p == ROOT_P {
            self.freq[ROOT_P] = 0xffff;
            self.edge[usize::from(self.block[ROOT_P])] += 1;
        }
        self.parent[r] = self.most_p as u16;
        self.parent[q] = self.most_p as u16;
        let nb = usize::from(self.stock[self.avail]);
        self.avail += 1;
        self.block[q] = nb as u16;
        self.edge[nb] = q as u16;
        self.s_node[p + N_CHAR] = q as u16;
        self.most_p = q;
        self.update_p(p);
    }

    /// Descend a tree from `root` until a leaf's `!symbol` marker.
    fn descend(&self, r: &mut MsbReader<'_>, root: usize) -> Result<i32, Error> {
        let mut c = self.child[root];
        while c > 0 {
            let bit = usize::try_from(r.get(1)).unwrap_or(0);
            c = self.child[c as usize - bit];
        }
        if c == 0 {
            return Err(Error::InvalidData("lha: corrupt dyn tree"));
        }
        Ok(c)
    }

    fn decode_c(&mut self, r: &mut MsbReader<'_>) -> Result<usize, Error> {
        let c = self.descend(r, ROOT_C)?;
        let sym = (!c) as usize;
        self.update_c(sym);
        if sym == N1 {
            Ok(sym + usize::try_from(r.get(8)).unwrap_or(0))
        } else {
            Ok(sym)
        }
    }

    fn decode_p(&mut self, r: &mut MsbReader<'_>, count: u64) -> Result<usize, Error> {
        while count > self.nextcount {
            self.make_new_node((self.nextcount / P_NODE_SPAN) as usize);
            self.nextcount += P_NODE_SPAN;
            if self.nextcount >= (1u64 << DICBIT) {
                self.nextcount = u64::MAX;
            }
        }
        let c = self.descend(r, ROOT_P)?;
        let sym = (!c) as usize - N_CHAR;
        self.update_p(sym);
        Ok((sym << 6) + usize::try_from(r.get(6)).unwrap_or(0))
    }
}

/// `true` when `method` is `-lh2-`.
pub(crate) fn supported(method: &[u8; 5]) -> bool {
    method == b"-lh2-"
}

/// Decode an `-lh2-` payload to `expected` bytes.
pub(crate) fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let n = 1usize << DICBIT;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    if expected == 0 {
        return Ok(out);
    }
    let mut ring = vec![b' '; n];
    let mut w = 0usize;
    let mut count = 0u64;
    let mut r = MsbReader::new(input);
    let mut d = Dyn::new();

    while out.len() < expected {
        let c = d.decode_c(&mut r)?;
        if c < 256 {
            out.push(c as u8);
            ring[w] = c as u8;
            w = (w + 1) & (n - 1);
            count += 1;
        } else {
            let pos = d.decode_p(&mut r, count)?;
            if r.overran() {
                return Err(Error::InvalidData("lha: truncated stream"));
            }
            let len = c + 3 - 256;
            count += len as u64;
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
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated stream"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzh::bits::MsbWriter;

    /// Emit the Huffman code for the leaf `s_node[sym_off]` in tree
    /// `root` into `w`, walking the leaf-to-root path like
    /// `encode_c_dyn` in the reference.
    fn emit_code(d: &Dyn, w: &mut MsbWriter, root: usize, sym_off: usize) {
        let mut bits = Vec::new();
        let mut p = usize::from(d.s_node[sym_off]);
        while p != root {
            // Even node id = head sibling (bit 0), odd = tail (bit 1).
            bits.push((p & 1) as u32);
            p = usize::from(d.parent[p]);
        }
        for &b in bits.iter().rev() {
            w.put(b, 1);
        }
    }

    /// Mirror encoder for tests: emits a `-lh2-` payload for `cmds`
    /// (`Ok(byte)` literal, `Err((len, dist))` match with `dist`
    /// 1..=8192 — the position symbol is restricted to what the
    /// emitted byte count has already unlocked, matching the
    /// decoder-side node growth).
    fn encode(cmds: &[Result<u8, (usize, usize)>]) -> Vec<u8> {
        let mut d = Dyn::new();
        let mut w = MsbWriter::new();
        let mut count = 0u64;
        for &c in cmds {
            match c {
                Ok(b) => {
                    let sym = usize::from(b);
                    emit_code(&d, &mut w, ROOT_C, sym);
                    d.update_c(sym);
                    count += 1;
                }
                Err((len, dist)) => {
                    assert!((3..=287).contains(&len));
                    assert!((1..=(1 << DICBIT)).contains(&dist));
                    let sym = if len >= 32 { N1 } else { len + 253 };
                    emit_code(&d, &mut w, ROOT_C, sym);
                    d.update_c(sym);
                    if len >= 32 {
                        w.put((len - 32) as u32, 8);
                    }
                    // Mirror decode_p's node-growth schedule.
                    while count > d.nextcount {
                        d.make_new_node((d.nextcount / P_NODE_SPAN) as usize);
                        d.nextcount += P_NODE_SPAN;
                        if d.nextcount >= (1u64 << DICBIT) {
                            d.nextcount = u64::MAX;
                        }
                    }
                    let pos = dist - 1;
                    let psym = pos >> 6;
                    assert!(
                        psym == 0 || count > (psym as u64) * P_NODE_SPAN,
                        "position symbol unavailable: sym {} count {}",
                        psym,
                        count
                    );
                    emit_code(&d, &mut w, ROOT_P, psym + N_CHAR);
                    d.update_p(psym);
                    w.put((pos & 0x3f) as u32, 6);
                    count += len as u64;
                }
            }
        }
        w.put(0, 7); // encode_end_dyn padding
        w.finish()
    }

    #[test]
    fn literals_only() {
        let payload = encode(&[Ok(b'h'), Ok(b'i'), Ok(b'!'), Ok(b'h')]);
        let out = decode(&payload, 4).unwrap();
        assert_eq!(out, b"hi!h");
    }

    #[test]
    fn literal_extension_symbol() {
        // len-33 (> 31) match uses symbol 285 + 8 extension bits.
        let cmds = [Ok(b'a'), Ok(b'b'), Err((33, 2))];
        let payload = encode(&cmds);
        let out = decode(&payload, 35).unwrap();
        assert_eq!(out.len(), 35);
        assert_eq!(&out[..2], b"ab");
    }

    #[test]
    fn match_near_position_zero() {
        let mut cmds: Vec<Result<u8, (usize, usize)>> = b"abcd".iter().map(|b| Ok(*b)).collect();
        cmds.push(Err((3, 3))); // dist 3 -> pos 2 -> sym 0
        let payload = encode(&cmds);
        let out = decode(&payload, 7).unwrap();
        assert_eq!(out, b"abcdbcd");
    }

    #[test]
    fn position_tree_growth() {
        // > 64 literal bytes so position symbol 1 exists, then a
        // far match referencing symbol-1 territory.
        let mut cmds: Vec<Result<u8, (usize, usize)>> =
            (0u8..100).map(|i| Ok(b'a' + i % 26)).collect();
        cmds.push(Err((10, 80))); // pos 79 -> sym 1
        let payload = encode(&cmds);
        let out = decode(&payload, 110).unwrap();
        assert_eq!(out.len(), 110);
        let expected: Vec<u8> = (0u8..100).map(|i| b'a' + i % 26).collect();
        assert_eq!(&out[..100], &expected[..]);
        assert_eq!(&out[100..], &expected[20..30]);
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode(&[], 1).is_err());
        assert!(decode(&[0], 2).is_err());
    }

    /// The fixture payload: literals exercising most of the byte
    /// range, then matches at several distances including a
    /// symbol-285 length extension and far positions that require
    /// decoder-side position-tree growth.
    type Cmd = Result<u8, (usize, usize)>;

    fn fixture_cmds() -> (Vec<Cmd>, Vec<u8>) {
        let mut expected: Vec<u8> = Vec::new();
        let mut cmds: Vec<Cmd> = Vec::new();
        for i in 0u32..300 {
            let b = ((i * 37 + 11) & 0xff) as u8;
            cmds.push(Ok(b));
            expected.push(b);
        }
        for (len, dist) in [(5usize, 4usize), (20, 300), (40, 77), (10, 300), (3, 1)] {
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
            b"-lh2-",
            "dyn.bin",
            &payload,
            expected.len(),
            &expected,
        );
        let e = crate::archive::lha::decode::decode(&a).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "dyn.bin");
        assert_eq!(e[0].data, expected);
    }
}
