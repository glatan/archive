//! LHA `-lh1-` decoder: LZSS over a 4 KiB ring with an adaptive
//! Huffman tree — the classic LZHUF scheme of Yoshizaki & Okumura.
//!
//! The literal/length alphabet is 314 symbols (256 byte literals plus
//! 58 copy codes giving match lengths 3..=60). Decoder and encoder
//! update the tree identically after every symbol; when the root
//! frequency saturates the tree is rebuilt with halved counts.
//! Positions use a *fixed* code: a variable-length high part selects
//! one of 64 offset buckets and the low 6 bits complete a 12-bit ring
//! position.
//!
//! Tree layout follows the original lzhuf scheme (also used by the
//! deark port `foreign/lzhuf.h`): `son[v]` is a node's first child,
//! its sibling is at `+1`; leaf positions hold `T + symbol` markers.
//! `freq[]` is kept sorted ascending; `update` swaps a node with the
//! last position of the smaller-frequency block when order breaks.
//!
//! Ported from the original `lzhuf.c` (written by Haruyasu Yoshizaki
//! 1988, comments translated by Okumura; distributed without an
//! explicit license grant) and the deark `foreign/lzhuf.h` port.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use crate::compress::lzh::bits::MsbReader;

/// Ring size.
const N: usize = 4096;
/// Maximum match length.
const F: usize = 60;
/// Matches of `<= THRESHOLD` bytes are emitted as literals.
const THRESHOLD: usize = 2;
/// Literal + match alphabet size.
const N_CHAR: usize = 256 - THRESHOLD + F; // 314
/// Total node count.
const T: usize = N_CHAR * 2 - 1;
/// Root node index.
const R: usize = T - 1;
/// Frequency at which the tree is rebuilt.
const MAX_FREQ: u16 = 0x8000;

/// Number of offset buckets assigned each code length 3..=8 (sums to
/// 64, one bucket per 6-bit high part of the position).
const P_DIST: [usize; 6] = [1, 3, 8, 12, 24, 16];

struct Tree {
    /// `son[v]`: first child of internal node `v` (children `v'`,
    /// `v'+1`), or `T + symbol` when `v` is a leaf position.
    son: Vec<u16>,
    /// Parent links indexed by node id *and* by leaf marker
    /// (`T + symbol`); `prnt[T]` is the unused root slot.
    prnt: Vec<u16>,
    /// Frequencies, ascending; `freq[T]` is the `0xffff` sentinel used
    /// by the update scan.
    freq: Vec<u16>,
}

impl Tree {
    fn new() -> Self {
        let mut t = Tree {
            son: vec![0u16; T],
            prnt: vec![0u16; T + N_CHAR],
            freq: vec![0u16; T + 1],
        };
        for i in 0..N_CHAR {
            t.freq[i] = 1;
            t.son[i] = (i + T) as u16;
            t.prnt[i + T] = i as u16;
        }
        let mut i = 0usize;
        for j in N_CHAR..T {
            t.freq[j] = t.freq[i] + t.freq[i + 1];
            t.son[j] = i as u16;
            t.prnt[i] = j as u16;
            t.prnt[i + 1] = j as u16;
            i += 2;
        }
        t.freq[T] = 0xffff;
        t
    }

    /// Halve leaf counts and rebuild (the reference `reconst`):
    /// leaves keep their order in the low half, then internal nodes
    /// are re-paired and each insertion re-sorts the table.
    fn reconst(&mut self) {
        // Collect leaves into positions 0..N_CHAR, halving freq.
        let mut j = 0usize;
        for i in 0..T {
            if usize::from(self.son[i]) >= T {
                self.freq[j] = self.freq[i].div_ceil(2);
                self.son[j] = self.son[i];
                j += 1;
            }
        }
        // Reconnect sons pairwise, keeping freq ascending: each new
        // parent is inserted at its sorted slot via a table shift.
        let mut i = 0usize;
        for j in N_CHAR..T {
            let f = self.freq[i] + self.freq[i + 1];
            let mut k = j;
            while k > 0 && f < self.freq[k - 1] {
                k -= 1;
            }
            // Shift [k..j) right by one and drop the new node at k.
            self.freq.copy_within(k..j, k + 1);
            self.freq[k] = f;
            self.son.copy_within(k..j, k + 1);
            self.son[k] = i as u16;
            i += 2;
        }
        // Reconnect parents.
        for i in 0..T {
            let k = usize::from(self.son[i]);
            self.prnt[k] = i as u16;
            if usize::from(self.son[i]) < T {
                self.prnt[k + 1] = i as u16;
            }
        }
        self.freq[T] = 0xffff;
    }

    /// Increment the leaf for `sym` and restore sorted order.
    fn update(&mut self, sym: usize) {
        if self.freq[R] == MAX_FREQ {
            self.reconst();
        }
        let mut c = usize::from(self.prnt[sym + T]);
        loop {
            self.freq[c] += 1;
            let k = self.freq[c];
            // If order is disturbed, move the node past the block of
            // strictly smaller frequencies (swap with the last slot).
            if usize::from(k) > usize::from(self.freq[c + 1]) {
                let mut l = c + 1;
                loop {
                    l += 1;
                    if k <= self.freq[l] {
                        break;
                    }
                }
                l -= 1;
                self.freq.swap(c, l);
                // Swap the child pointers and fix parents.
                let i = usize::from(self.son[c]);
                let j = usize::from(self.son[l]);
                self.son.swap(c, l);
                self.prnt[i] = l as u16;
                if i < T {
                    self.prnt[i + 1] = l as u16;
                }
                self.prnt[j] = c as u16;
                if j < T {
                    self.prnt[j + 1] = c as u16;
                }
                c = l;
            }
            c = usize::from(self.prnt[c]);
            if c == 0 {
                break;
            }
        }
    }
}

/// Position high-bit tables generated from `P_DIST`: `bucket[i]`
/// maps a peeked top byte to its bucket (the position's high 6 bits)
/// and `bits[i]` to that bucket's code length.
fn pos_tables() -> ([u8; 256], [u8; 256]) {
    let mut bucket = [0u8; 256];
    let mut bits = [0u8; 256];
    let mut b = 0usize;
    let mut top = 0usize;
    for (k, &count) in P_DIST.iter().enumerate() {
        let len = (k + 3) as u8;
        for _ in 0..count {
            for _ in 0..(1usize << (8 - len)) {
                if top < 256 {
                    bucket[top] = b as u8;
                    bits[top] = len;
                    top += 1;
                }
            }
            b += 1;
        }
    }
    (bucket, bits)
}

/// Decode an `-lh1-` payload to `expected` bytes.
pub(crate) fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    if expected == 0 {
        return Ok(out);
    }
    let (bucket, bits) = pos_tables();
    let mut tree = Tree::new();
    let mut ring = vec![b' '; N];
    let mut w = 0usize;
    let mut r = MsbReader::new(input);

    while out.len() < expected {
        // Descend: `c` is a node's first-child pointer — an internal
        // position (< T) or a leaf marker (>= T). Bit 0 selects the
        // child at `c`, bit 1 the sibling at `c + 1`.
        let mut c = usize::from(tree.son[R]);
        let mut guard = 0usize;
        while c < T {
            let next = c + usize::try_from(r.get(1)).unwrap_or(0);
            c = usize::from(
                *tree
                    .son
                    .get(next)
                    .ok_or(Error::InvalidData("lha: lh1 tree corruption"))?,
            );
            guard += 1;
            if guard > T {
                return Err(Error::InvalidData("lha: lh1 huffman loop"));
            }
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated lh1 stream"));
        }
        let sym = c - T;
        tree.update(sym);
        if sym < 256 {
            out.push(sym as u8);
            ring[w] = sym as u8;
            w = (w + 1) & (N - 1);
        } else {
            // Position: variable-length bucket code + 6 low bits;
            // the ring distance is `pos + 1`.
            let top = usize::try_from(r.peek(8)).unwrap_or(0);
            let b = usize::from(bucket[top]);
            r.get(u32::from(bits[top]));
            let pos = ((b << 6) | usize::try_from(r.get(6)).unwrap_or(0)) + 1;
            if r.overran() {
                return Err(Error::InvalidData("lha: truncated lh1 stream"));
            }
            let len = sym - 256 + THRESHOLD + 1;
            let mut src = (w + N - pos) & (N - 1);
            for _ in 0..len {
                if out.len() >= expected {
                    break;
                }
                let v = ring[src];
                out.push(v);
                ring[w] = v;
                w = (w + 1) & (N - 1);
                src = (src + 1) & (N - 1);
            }
        }
    }
    Ok(out)
}
