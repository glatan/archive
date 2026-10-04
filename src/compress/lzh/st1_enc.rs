//! LZH "st1" static-Huffman block encoder for LHA `-lh4-` through
//! `-lh7-` and ARJ methods 1-3 (15-bit window) — the encode mirror
//! of `st1::decode`.
//!
//! The stream is a sequence of blocks, each starting with a 16-bit
//! command count followed by three serialized code-length tables: a
//! small "temp" table encoding the literal/match table, the
//! literal/match table itself, and an offset-length table. A code
//! below 256 is a literal; otherwise it is a match of
//! `code - 256 + 3` bytes at a distance `off + 1` where `off` is
//! coded as a bit-length symbol plus `len - 1` raw low bits.
//!
//! The LZ parse is a greedy hash-chain search and code lengths are
//! plain frequency-based Huffman codes (not optimal parsing):
//! correctness over ratio. Serialized tables always describe a
//! complete prefix code — the decoder requires the Kraft sum to
//! exhaust the 16-bit code space — with a single-symbol escape for
//! degenerate tables.

use alloc::collections::BinaryHeap;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Reverse;

use crate::compress::lzh::bits::MsbWriter;

/// Literal + match alphabet size (see the st1 decoder).
const NUM_CODES: usize = 510;
/// First match length (codes start at 256).
const COPY_THRESHOLD: usize = 3;
/// Longest encodable match (`code - 256 + 3` maxes at 256).
const MAX_MATCH: usize = NUM_CODES - 256 + COPY_THRESHOLD - 1;
/// Temp-table alphabet size and its count-field width.
const MAX_TEMP_CODES: usize = (1 << 5) - 1;
const TEMP_CODE_BITS: u32 = 5;
/// Literal/match table count width.
const CODE_BITS: u32 = 9;
/// Temp-table index where the 2-bit zero-run insert lives.
const TEMP_SPECIAL: usize = 3;
/// Maximum Huffman code length (the decoder caps at 16).
const MAX_LEN: usize = 16;
/// Maximum commands per block (16-bit blocksize field).
const BLOCK_MAX: usize = 0xffff;
/// Hash-table size for the match search.
const HASH_SIZE: usize = 1 << 15;
/// Maximum chain links followed per position.
const MAX_CHAIN: usize = 32;
/// Chain-list terminator.
const NIL: u32 = u32::MAX;

/// One LZ command: a literal byte or a (length, distance) match.
enum Cmd {
    Lit(u8),
    Match { len: u16, dist: u32 },
}

/// Hash of the 3-byte prefix at `b` (caller guarantees len >= 3).
fn hash(b: &[u8]) -> usize {
    (b[0] as usize * 251 + b[1] as usize * 11 + b[2] as usize) & (HASH_SIZE - 1)
}

fn insert(input: &[u8], pos: usize, head: &mut [u32], prev: &mut [u32]) {
    if pos + COPY_THRESHOLD > input.len() {
        return;
    }
    let h = hash(&input[pos..]);
    prev[pos] = head[h];
    head[h] = pos as u32;
}

/// Greedy LZ parse: longest match within `window` bytes back, length
/// 3..=256, else a literal. Distances never reach before position 0,
/// so the decoder's space-filled ring never leaks into the output.
fn parse(input: &[u8], window: usize) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    let mut head = vec![NIL; HASH_SIZE];
    let mut prev = vec![NIL; input.len()];
    let mut pos = 0usize;
    while pos < input.len() {
        let max_len = (input.len() - pos).min(MAX_MATCH);
        let mut best_len = 0usize;
        let mut best_dist = 0usize;
        if max_len >= COPY_THRESHOLD {
            let mut cand = head[hash(&input[pos..])];
            let mut chain = MAX_CHAIN;
            while cand != NIL && chain > 0 && best_len < max_len {
                let c = cand as usize;
                // c < pos, so the distance stays inside emitted data.
                if pos - c > window {
                    break; // chains only get older
                }
                if input[c + best_len] == input[pos + best_len] {
                    let mut l = 0usize;
                    while l < max_len && input[c + l] == input[pos + l] {
                        l += 1;
                    }
                    if l > best_len {
                        best_len = l;
                        best_dist = pos - c;
                    }
                }
                cand = prev[c];
                chain -= 1;
            }
        }
        if best_len >= COPY_THRESHOLD {
            cmds.push(Cmd::Match {
                len: best_len as u16,
                dist: best_dist as u32,
            });
            let end = pos + best_len;
            while pos < end {
                insert(input, pos, &mut head, &mut prev);
                pos += 1;
            }
        } else {
            cmds.push(Cmd::Lit(input[pos]));
            insert(input, pos, &mut head, &mut prev);
            pos += 1;
        }
    }
    cmds
}

/// Offset-table symbol for a position offset: its bit-length
/// (offset 0 -> symbol 0, 1 -> 1, 2..=3 -> 2, 4..=7 -> 3, ...).
fn pos_sym(off: usize) -> usize {
    (usize::BITS - off.leading_zeros()) as usize
}

/// Plain Huffman code depths for `freq`; symbols with zero
/// frequency get length 0. Depths saturate at 255.
fn huffman_lengths(freq: &[u64], lens: &mut [u8]) {
    lens.fill(0);
    let n = freq.len();
    // Caller guarantees >= 2 nonzero frequencies.
    let mut parent: Vec<u32> = vec![u32::MAX; n];
    let mut heap: BinaryHeap<Reverse<(u64, u32)>> = BinaryHeap::new();
    for (i, &f) in freq.iter().enumerate() {
        if f > 0 {
            heap.push(Reverse((f, i as u32)));
        }
    }
    while heap.len() > 1 {
        let Reverse((fa, a)) = heap.pop().unwrap();
        let Reverse((fb, b)) = heap.pop().unwrap();
        let id = parent.len() as u32;
        parent[a as usize] = id;
        parent[b as usize] = id;
        parent.push(u32::MAX);
        heap.push(Reverse((fa + fb, id)));
    }
    for (i, &f) in freq.iter().enumerate() {
        if f == 0 {
            continue;
        }
        let mut d = 0u32;
        let mut v = i;
        while parent[v] != u32::MAX {
            v = parent[v] as usize;
            d += 1;
        }
        lens[i] = d.min(u8::MAX as u32) as u8;
    }
}

/// Code lengths for `freq`, limited to `MAX_LEN` and forming a
/// complete prefix code (the decoder requires Kraft sum == 1).
/// `freq` must hold at least two nonzero entries.
fn code_lengths(freq: &[u64]) -> Vec<u8> {
    let n = freq.len();
    let mut lens = vec![0u8; n];
    let mut f = freq.to_vec();
    loop {
        huffman_lengths(&f, &mut lens);
        if lens.iter().all(|&l| l <= MAX_LEN as u8) {
            return lens;
        }
        // Skewed frequencies can overflow the length limit; halving
        // flattens the distribution until the tree fits (frequencies
        // converge to all-ones, whose tree is balanced).
        for x in f.iter_mut() {
            if *x > 1 {
                *x = (*x + 1) >> 1;
            }
        }
    }
}

/// Canonical codes matching the decoder's `Table::build` numbering:
/// first code per length is `(prev + count[l - 1]) << 1`, codes are
/// handed out in symbol order. Only the low `len` bits are emitted,
/// so the zero-length contribution folded into `count[0]` is
/// irrelevant.
fn canon(lens: &[u8]) -> Vec<u32> {
    let mut count = [0u32; MAX_LEN + 1];
    for &l in lens {
        count[usize::from(l)] += 1;
    }
    let mut next = [0u32; MAX_LEN + 1];
    let mut code = 0u32;
    for (l, slot) in next.iter_mut().enumerate().skip(1) {
        code = (code + count[l - 1]) << 1;
        *slot = code;
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

/// A serialized-table candidate: full length table plus canonical
/// codes, or the constant escape ( + one symbol) used when
/// at most one symbol occurs — every decode then yields it with no
/// bits consumed.
struct Codes {
    lens: Vec<u8>,
    codes: Vec<u32>,
    constant: Option<u16>,
}

impl Codes {
    fn from_freq(freq: &[u64]) -> Codes {
        let used = freq.iter().filter(|&&f| f > 0).count();
        if used <= 1 {
            let sym = freq.iter().position(|&f| f > 0).unwrap_or(0) as u16;
            Codes {
                lens: vec![0; freq.len()],
                codes: Vec::new(),
                constant: Some(sym),
            }
        } else {
            let lens = code_lengths(freq);
            let codes = canon(&lens);
            Codes {
                lens,
                codes,
                constant: None,
            }
        }
    }

    /// Emit `sym`'s code; constant tables consume no bits.
    fn emit(&self, w: &mut MsbWriter, sym: usize) {
        if self.constant.is_none() {
            w.put(self.codes[sym], u32::from(self.lens[sym]));
        }
    }
}

/// Serialize a `pt_len` style table (mirror of `huf::read_pt_len`):
/// `nbit`-wide symbol count, per-symbol 3-bit lengths with the
/// all-ones extension, and a 2-bit zero-run insert whenever the
/// write index lands on `i_special` (`usize::MAX` disables it).
fn write_pt_len(w: &mut MsbWriter, table: &Codes, nbit: u32, i_special: usize) {
    if let Some(sym) = table.constant {
        w.put(0, nbit);
        w.put(u32::from(sym), nbit);
        return;
    }
    let lens = &table.lens;
    let n = lens.iter().rposition(|&l| l != 0).unwrap() + 1;
    w.put(n as u32, nbit);
    let mut i = 0usize;
    while i < n {
        let l = u32::from(lens[i]);
        if l < 7 {
            w.put(l, 3);
        } else {
            // Lengths >= 7 are 7 followed by `l - 7` one bits + zero.
            w.put(7, 3);
            for _ in 7..l {
                w.put(1, 1);
            }
            w.put(0, 1);
        }
        i += 1;
        if i == i_special {
            let mut z = 0usize;
            while z < 3 && i + z < n && lens[i + z] == 0 {
                z += 1;
            }
            w.put(z as u32, 2);
            i += z;
        }
    }
}

/// One serialized literal/match-table entry.
enum CEnt {
    /// One zero length (temp symbol 0).
    Z1,
    /// 4-bit zero run +3 (temp symbol 1).
    Z4(u16),
    /// 9-bit zero run +20 (temp symbol 2).
    Z9(u16),
    /// Code length `l` (temp symbol `l + 2`).
    Len(u8),
}

impl CEnt {
    /// Temp-table symbol this entry is coded with.
    fn sym(&self) -> usize {
        match *self {
            CEnt::Z1 => 0,
            CEnt::Z4(_) => 1,
            CEnt::Z9(_) => 2,
            CEnt::Len(l) => usize::from(l) + 2,
        }
    }
}

/// Symbol entries emitted by `write_c_len` for `c_lens` (needed to
/// build the temp table before serializing anything).
fn c_len_stream(c_lens: &[u8]) -> Vec<CEnt> {
    let n = c_lens.iter().rposition(|&l| l != 0).unwrap() + 1;
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n {
        if c_lens[i] == 0 {
            let mut z = 0usize;
            while i + z < n && c_lens[i + z] == 0 {
                z += 1;
            }
            i += z;
            while z >= 20 {
                let r = z.min(20 + 0x1ff);
                out.push(CEnt::Z9((r - 20) as u16));
                z -= r;
            }
            while z >= 3 {
                let r = z.min(3 + 0xf);
                out.push(CEnt::Z4((r - 3) as u16));
                z -= r;
            }
            while z > 0 {
                out.push(CEnt::Z1);
                z -= 1;
            }
        } else {
            out.push(CEnt::Len(c_lens[i]));
            i += 1;
        }
    }
    out
}

/// Serialize the literal/match table (mirror of ):
/// 9-bit count, then entries coded through the temp table.
fn write_c_len(w: &mut MsbWriter, c: &Codes, t: &Codes, entries: &[CEnt]) {
    if let Some(sym) = c.constant {
        w.put(0, CODE_BITS);
        w.put(u32::from(sym), CODE_BITS);
        return;
    }
    let n = c.lens.iter().rposition(|&l| l != 0).unwrap() + 1;
    w.put(n as u32, CODE_BITS);
    for e in entries {
        match *e {
            CEnt::Z1 => t.emit(w, 0),
            CEnt::Z4(v) => {
                t.emit(w, 1);
                w.put(u32::from(v), 4);
            }
            CEnt::Z9(v) => {
                t.emit(w, 2);
                w.put(u32::from(v), 9);
            }
            CEnt::Len(l) => t.emit(w, usize::from(l) + 2),
        }
    }
}

/// Serialize one block: command count, temp table, literal/match
/// table, offset table, then the commands.
fn write_block(w: &mut MsbWriter, cmds: &[Cmd], offset_bits: u32) {
    let max_off = (1usize << offset_bits) - 1;
    let mut c_freq = vec![0u64; NUM_CODES];
    let mut p_freq = vec![0u64; max_off];
    for cmd in cmds {
        match *cmd {
            Cmd::Lit(b) => c_freq[usize::from(b)] += 1,
            Cmd::Match { len, dist } => {
                c_freq[256 + usize::from(len) - COPY_THRESHOLD] += 1;
                p_freq[pos_sym(dist as usize - 1)] += 1;
            }
        }
    }
    let c = Codes::from_freq(&c_freq);
    let p = Codes::from_freq(&p_freq);
    let entries = if c.constant.is_none() {
        c_len_stream(&c.lens)
    } else {
        Vec::new()
    };
    let mut t_freq = vec![0u64; MAX_TEMP_CODES];
    for e in &entries {
        t_freq[e.sym()] += 1;
    }
    let t = Codes::from_freq(&t_freq);

    w.put(cmds.len() as u32, 16);
    write_pt_len(w, &t, TEMP_CODE_BITS, TEMP_SPECIAL);
    write_c_len(w, &c, &t, &entries);
    write_pt_len(w, &p, offset_bits, usize::MAX);
    for cmd in cmds {
        match *cmd {
            Cmd::Lit(b) => c.emit(w, usize::from(b)),
            Cmd::Match { len, dist } => {
                c.emit(w, 256 + usize::from(len) - COPY_THRESHOLD);
                let off = dist as usize - 1;
                let b = pos_sym(off);
                p.emit(w, b);
                if b >= 2 {
                    w.put((off - (1usize << (b - 1))) as u32, b as u32 - 1);
                }
            }
        }
    }
}

/// Encode `input` as an st1 stream; `hist_bits`/`offset_bits` carry
/// the same meaning as in `st1::decode` (14/4 for `-lh4-`/`-lh5-`,
/// 16/5 for `-lh6-`, 17/5 for `-lh7-`, 15/5 for ARJ methods 1-3).
/// These are the de facto (lhasa-family) window sizes, so the
/// encoder may emit distances beyond the original LHa dictionary
/// (8/32/64 KiB for `-lh5-`/`-lh6-`/`-lh7-`): valid wire within the
/// ar002 alphabet and correct under modern decoders, but strict old
/// de jure-window decoders may not reproduce the stream — an
/// intentional scope choice (see `docs/spec/lha/README.md`).
pub(crate) fn encode(hist_bits: u32, offset_bits: u32, input: &[u8]) -> Vec<u8> {
    let window = 1usize << hist_bits;
    let cmds = parse(input, window);
    let mut w = MsbWriter::new();
    for chunk in cmds.chunks(BLOCK_MAX) {
        write_block(&mut w, chunk, offset_bits);
    }
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzh::st1;

    fn roundtrip(hist_bits: u32, offset_bits: u32, data: &[u8]) {
        let packed = encode(hist_bits, offset_bits, data);
        let out = st1::decode(hist_bits, offset_bits, &packed, data.len()).unwrap();
        assert_eq!(out, data);
    }

    /// Deterministic non-repeating bytes (xorshift32).
    fn noisy(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut s = 0x1234_5678u32;
        while v.len() < n {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            v.push((s >> 24) as u8);
        }
        v
    }

    #[test]
    fn test_st1_roundtrip_lh5() {
        let data = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
        let packed = encode(14, 4, &data);
        assert!(packed.len() < data.len());
        roundtrip(14, 4, &data);
    }

    #[test]
    fn test_st1_roundtrip_lh6_lh7() {
        // Long-range repeats exercise the wide windows.
        let mut data = b"header-".to_vec();
        data.extend_from_slice(&b"0123456789abcdef".repeat(5000));
        data.extend_from_slice(b"header-");
        data.extend_from_slice(&b"0123456789abcdef".repeat(5000));
        roundtrip(16, 5, &data);
        roundtrip(17, 5, &data);
        roundtrip(14, 4, &data);
    }

    #[test]
    fn test_st1_roundtrip_arj_params() {
        // ARJ methods 1-3 share one wire format: 15-bit window with
        // a 5-bit-wide offset-table count.
        let data = b"arj st1 payload payload payload ".repeat(300);
        let packed = encode(15, 5, &data);
        assert!(packed.len() < data.len());
        roundtrip(15, 5, &data);
        let noise = noisy(50_000);
        roundtrip(15, 5, &noise);
    }

    #[test]
    fn test_st1_roundtrip_incompressible() {
        let data = noisy(40_000);
        roundtrip(14, 4, &data);
        roundtrip(17, 5, &data);
    }

    #[test]
    fn test_st1_multi_block() {
        // More than 65535 commands forces a second block.
        let data = noisy(80_000);
        let packed = encode(14, 4, &data);
        let out = st1::decode(14, 4, &packed, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn test_st1_empty_and_tiny() {
        for data in [&b""[..], &b"x"[..], &b"ab"[..], &b"aaa"[..]] {
            roundtrip(14, 4, data);
        }
    }

    #[test]
    fn test_st1_single_symbol_tables() {
        // One literal byte value + one match shape: exercises the
        // constant-table escape paths.
        let data = vec![b'z'; 10_000];
        let packed = encode(14, 4, &data);
        assert!(packed.len() < data.len() / 10);
        roundtrip(14, 4, &data);
    }

    #[test]
    fn test_code_lengths_limited() {
        // Fibonacci frequencies maximize Huffman depth; the builder
        // must still cap at MAX_LEN and stay a complete code.
        let mut freq = vec![0u64; 40];
        let (mut a, mut b) = (1u64, 1u64);
        for f in freq.iter_mut() {
            *f = a;
            let c = a + b;
            a = b;
            b = c;
        }
        let lens = code_lengths(&freq);
        assert!(lens.iter().all(|&l| (1..=MAX_LEN as u8).contains(&l)));
        let kraft: u64 = lens.iter().map(|&l| 1u64 << (MAX_LEN - l as usize)).sum();
        assert_eq!(kraft, 1 << MAX_LEN);
    }
}
