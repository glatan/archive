//! PMarc `-pm1-` and `-pm2-` decoders (PMarc variants used on MSX;
//! `-pm0-` is stored and handled by the caller like `-lh0-`).
//!
//! Both methods mix a move-to-front byte model (a circular linked
//! list walked by a variable-length distance code) with LZ77-style
//! history copies. `-pm1-` interleaves literal blocks and copy
//! commands behind static trees that "grow" as output progresses;
//! `-pm2-` uses serialized Huffman trees rebuilt at fixed output
//! checkpoints.
//!
//! Ported from lhasa
//! `pm1_decoder.c`, `pm2_decoder.c`, `pma_common.c` — the latter
//! originally reverse-engineered from PMarc/UNPMA10. lhasa is
//! ISC-licensed (Copyright (c) 2011-2012, Simon Howard); the
//! license text is reproduced verbatim in THIRD_PARTY_NOTICES.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use crate::compress::lzh::bits::MsbReader;

/// `(offset, extra bits)` entry of a variable-length code table.
pub(crate) struct Vl {
    pub(crate) offset: u32,
    pub(crate) bits: u32,
}

/// Read `table[i].bits` extra bits and add them to `table[i].offset`.
fn vl_decode(r: &mut MsbReader<'_>, table: &[Vl], i: usize) -> Result<u32, Error> {
    let e = table
        .get(i)
        .ok_or(Error::InvalidData("lha: bad pmarc code"))?;
    Ok(e.offset + r.get(e.bits))
}

/// Circular move-to-front byte list (`HistoryLinkedList` in lhasa).
/// `prev` walks towards the tail, `next` towards the head.
pub(crate) struct History {
    prev: [u8; 256],
    next: [u8; 256],
    head: u8,
}

impl History {
    /// Linear chain cut into groups so ASCII bytes sit nearest the
    /// head: `0x20..0x7f`, `0x00..0x1f`, `0xa0..0xdf`, `0x80..0x9f`,
    /// `0xe0..0xff`.
    pub(crate) fn new() -> Self {
        let mut h = History {
            prev: [0; 256],
            next: [0; 256],
            head: 0x20,
        };
        for i in 0..256usize {
            h.prev[i] = i.wrapping_add(1) as u8;
            h.next[i] = i.wrapping_sub(1) as u8;
        }
        h.prev[0x7f] = 0x00;
        h.next[0x00] = 0x7f;
        h.prev[0x1f] = 0xa0;
        h.next[0xa0] = 0x1f;
        h.prev[0xdf] = 0x80;
        h.next[0x80] = 0xdf;
        h.prev[0x9f] = 0xe0;
        h.next[0xe0] = 0x9f;
        h.prev[0xff] = 0x20;
        h.next[0x20] = 0xff;
        h
    }

    /// Walk `count` links from the head (`prev` direction under 128,
    /// `next` otherwise) and return the byte found.
    fn find(&self, count: u8) -> u8 {
        let mut code = self.head;
        if count < 128 {
            for _ in 0..count {
                code = self.prev[usize::from(code)];
            }
        } else {
            for _ in 0..256usize - usize::from(count) {
                code = self.next[usize::from(code)];
            }
        }
        code
    }

    /// Position of `b` counted in `prev` links from the head — the
    /// distance an encoder feeds to [`History::find`] to emit `b`.
    pub(crate) fn pos(&self, b: u8) -> usize {
        let mut code = self.head;
        let mut n = 0usize;
        while code != b {
            code = self.prev[usize::from(code)];
            n += 1;
        }
        n
    }

    /// Move byte `b` to the head of the chain.
    pub(crate) fn update(&mut self, b: u8) {
        if self.head == b {
            return;
        }
        let b_ = usize::from(b);
        let (p, n) = (self.prev[b_], self.next[b_]);
        self.next[usize::from(p)] = n;
        self.prev[usize::from(n)] = p;
        let head = usize::from(self.head);
        self.prev[b_] = self.head;
        self.next[b_] = self.next[head];
        self.prev[usize::from(self.next[head])] = b;
        self.next[head] = b;
        self.head = b;
    }
}

/// Shared output state: output vector, history ring, and MTF list.
struct Sink {
    out: Vec<u8>,
    ring: Vec<u8>,
    w: usize,
    hist: History,
    mask: usize,
}

impl Sink {
    fn new(ring_size: usize, fill: u8, expected: usize) -> Self {
        Sink {
            out: Vec::with_capacity(expected.min(1 << 24)),
            ring: vec![fill; ring_size],
            w: 0,
            hist: History::new(),
            mask: ring_size - 1,
        }
    }

    fn emit(&mut self, b: u8) {
        self.ring[self.w] = b;
        self.w = (self.w + 1) & self.mask;
        self.out.push(b);
        self.hist.update(b);
    }
}

/// `true` when `method` is handled by this module.
pub(crate) fn supported(method: &[u8; 5]) -> bool {
    matches!(method, b"-pm1-" | b"-pm2-")
}

/// Decode a PMarc payload to `expected` bytes.
pub(crate) fn decode(method: &[u8; 5], input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    match method {
        b"-pm1-" => decode_pm1(input, expected),
        b"-pm2-" => decode_pm2(input, expected),
        _ => Err(Error::Unsupported("lha: unsupported method")),
    }
}

/// Lenient binary trie for PMarc code trees, stored the way the
/// reference `tree_decode.c` does: `nodes[s]` is either `LEAF|sym`
/// for a leaf or the base position of the node's child pair
/// (children at `nodes[v]` and `nodes[v+1]`); `nodes[0]` is the root.
struct Trie {
    nodes: Vec<u8>,
}

const LEAF: u8 = 0x80;

impl Trie {
    /// Constant/single-code tree.
    fn single(sym: u8) -> Trie {
        Trie {
            nodes: vec![LEAF | sym],
        }
    }

    /// Build from per-symbol code lengths (0 = absent). Faithful
    /// port of `build_tree`: slots `next_entry..allocated` form a
    /// FIFO; each level expands every open slot into a node whose
    /// children are the next two fresh slots, then symbols of the
    /// current length consume open slots in order.
    fn build(lens: &[u8], cap: usize) -> Result<Trie, Error> {
        let mut nodes = vec![LEAF; cap];
        let mut next_entry = 0usize;
        let mut allocated = 1usize;
        let mut code_len = 0usize;
        loop {
            // Expand every open slot into a node with two children.
            let end = allocated;
            while next_entry < end {
                if allocated + 2 <= cap {
                    nodes[next_entry] = allocated as u8;
                    allocated += 2;
                }
                next_entry += 1;
            }
            code_len += 1;
            if code_len > 32 {
                return Err(Error::InvalidData("lha: pmarc bad tree:len"));
            }
            let mut remain = false;
            for (sym, &l) in lens.iter().enumerate() {
                if usize::from(l) == code_len {
                    if sym > 0x7f {
                        return Err(Error::InvalidData("lha: pmarc bad tree:sym"));
                    }
                    // : empty queue returns slot 0
                    // without consuming a position (mirrors lhasa).
                    let slot = if next_entry < allocated {
                        let s = next_entry;
                        next_entry += 1;
                        s
                    } else {
                        0
                    };
                    nodes[slot] = LEAF | sym as u8;
                } else if usize::from(l) > code_len {
                    remain = true;
                }
            }
            if !remain {
                return Ok(Trie { nodes });
            }
        }
    }

    /// Decode one symbol; an unfilled slot reads as symbol 0
    /// (matching the reference's leaf-initialized empty slots).
    fn decode(&self, r: &mut MsbReader<'_>) -> Result<u32, Error> {
        let mut code = *self.nodes.first().unwrap_or(&LEAF);
        for _ in 0..64 {
            if code & LEAF != 0 {
                return Ok(u32::from(code & !LEAF));
            }
            let idx = usize::from(code) + usize::try_from(r.get(1)).unwrap_or(0);
            code = *self
                .nodes
                .get(idx)
                .ok_or(Error::InvalidData("lha: pmarc bad tree:idx"))?;
        }
        Err(Error::InvalidData("lha: pmarc tree loop"))
    }
}

/// `-pm2-` history-distance code (recent bytes take fewer bits).
pub(crate) const PM2_HISTORY: &[Vl] = &[
    Vl { offset: 0, bits: 3 },
    Vl { offset: 8, bits: 3 },
    Vl {
        offset: 16,
        bits: 4,
    },
    Vl {
        offset: 32,
        bits: 5,
    },
    Vl {
        offset: 64,
        bits: 5,
    },
    Vl {
        offset: 96,
        bits: 5,
    },
    Vl {
        offset: 128,
        bits: 6,
    },
    Vl {
        offset: 192,
        bits: 6,
    },
];

/// `-pm2-` copy-length code for length codes `>= 15`.
const PM2_COPY: &[Vl] = &[
    Vl {
        offset: 17,
        bits: 3,
    },
    Vl {
        offset: 25,
        bits: 3,
    },
    Vl {
        offset: 33,
        bits: 5,
    },
    Vl {
        offset: 65,
        bits: 6,
    },
    Vl {
        offset: 129,
        bits: 7,
    },
    Vl {
        offset: 256,
        bits: 0,
    },
];

/// Read a `-pm2-` code tree: 5-bit symbol count, 3-bit minimum code
/// length, 3-bit entry width, then per-symbol widths.
/// `need_offset` records whether an offset tree follows.
fn pm2_code_tree(r: &mut MsbReader<'_>, need_offset: &mut bool) -> Result<Trie, Error> {
    let num_codes = usize::try_from(r.get(5)).unwrap_or(0);
    let min_len = r.get(3);
    *need_offset = num_codes >= 10 && !(num_codes == 29 && min_len == 0);
    if num_codes == 0 {
        return Ok(Trie::single(0));
    }
    if min_len == 0 {
        return Ok(Trie::single(num_codes.saturating_sub(1) as u8));
    }
    let width = r.get(3);
    if width > 8 {
        return Err(Error::InvalidData("lha: pm2 bad tree width"));
    }
    let mut lens = vec![0u8; num_codes.min(31)];
    for l in lens.iter_mut() {
        let v = r.get(width);
        *l = if v == 0 { 0 } else { (min_len + v - 1) as u8 };
    }
    Trie::build(&lens, 65)
}

/// Read `num_offsets` 3-bit lengths for the `-pm2-` offset tree.
fn pm2_offset_tree(r: &mut MsbReader<'_>, num_offsets: usize, need: bool) -> Result<Trie, Error> {
    if !need {
        return Ok(Trie::single(0));
    }
    let mut lens = vec![0u8; num_offsets.min(8)];
    for l in lens.iter_mut() {
        *l = r.get(3) as u8;
    }
    if lens.iter().filter(|&&l| l != 0).count() == 1 {
        let single = lens.iter().position(|&l| l != 0).unwrap_or(0) as u8;
        return Ok(Trie::single(single));
    }
    Trie::build(&lens, 17)
}

/// Decode `-pm2-` to `expected` bytes.
struct Pm2<'a> {
    r: MsbReader<'a>,
    code_tree: Trie,
    offset_tree: Trie,
    need_offset: bool,
    /// Rebuild schedule index; bytes until the next rebuild.
    state: usize,
    remaining: usize,
}

impl<'a> Pm2<'a> {
    /// Tree rebuild, mirroring the reference state machine. Called
    /// from the emit path the moment the byte countdown reaches zero
    /// (so a copy spanning the boundary interleaves the new tables
    /// exactly like the reference).
    fn rebuild(&mut self) -> Result<(), Error> {
        match self.state {
            0 => {
                self.code_tree = pm2_code_tree(&mut self.r, &mut self.need_offset)?;
                self.offset_tree = pm2_offset_tree(&mut self.r, 5, self.need_offset)?;
                self.remaining = 1024;
            }
            1 | 2 => {
                self.offset_tree = pm2_offset_tree(&mut self.r, 5 + self.state, self.need_offset)?;
                self.remaining = if self.state == 1 { 1024 } else { 2048 };
            }
            3 => {
                if self.r.get(1) == 1 {
                    self.code_tree = pm2_code_tree(&mut self.r, &mut self.need_offset)?;
                }
                self.offset_tree = pm2_offset_tree(&mut self.r, 8, self.need_offset)?;
                self.remaining = 4096;
            }
            _ => {
                if self.r.get(1) == 1 {
                    self.code_tree = pm2_code_tree(&mut self.r, &mut self.need_offset)?;
                    self.offset_tree = pm2_offset_tree(&mut self.r, 8, self.need_offset)?;
                }
                self.remaining = 4096;
            }
        }
        self.state += 1;
        if self.r.overran() {
            return Err(Error::InvalidData("lha: truncated pm2 stream"));
        }
        Ok(())
    }

    fn emit(&mut self, s: &mut Sink, b: u8) -> Result<(), Error> {
        s.emit(b);
        self.remaining = self.remaining.saturating_sub(1);
        if self.remaining == 0 {
            self.rebuild()?;
        }
        Ok(())
    }
}

/// Decode method pm2 payload to  bytes.
fn decode_pm2(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 8192;
    let mut s = Sink::new(N, b' ', expected);
    let mut d = Pm2 {
        r: MsbReader::new(input),
        code_tree: Trie::single(0),
        offset_tree: Trie::single(0),
        need_offset: true,
        state: 0,
        remaining: 0,
    };

    // First stream bit is discarded, then the initial trees load.
    d.r.get(1);
    d.rebuild()?;

    while s.out.len() < expected {
        let code = usize::try_from(d.code_tree.decode(&mut d.r)?).unwrap_or(0);
        if code < 8 {
            let dist = vl_decode(&mut d.r, PM2_HISTORY, code)?;
            let b = s.hist.find(dist as u8);
            d.emit(&mut s, b)?;
        } else {
            let c = code - 8;
            let count = if c < 15 {
                c + 2
            } else {
                usize::try_from(vl_decode(&mut d.r, PM2_COPY, c - 15)?).unwrap_or(0)
            };
            let offset = if c == 0 {
                usize::try_from(d.r.get(6)).unwrap_or(0)
            } else if c < 20 {
                let v = usize::try_from(d.offset_tree.decode(&mut d.r)?).unwrap_or(0);
                if v == 0 {
                    usize::try_from(d.r.get(6)).unwrap_or(0)
                } else {
                    let bits = v + 5;
                    (1usize << bits) + usize::try_from(d.r.get(bits as u32)).unwrap_or(0)
                }
            } else {
                0
            };
            if d.r.overran() {
                return Err(Error::InvalidData("lha: truncated pm2 stream"));
            }
            let mut src = (s.w + N - 1 - offset) & (N - 1);
            for _ in 0..count {
                if s.out.len() >= expected {
                    break;
                }
                let v = s.ring[src];
                d.emit(&mut s, v)?;
                src = (src + 1) & (N - 1);
            }
        }
    }
    Ok(s.out)
}

/// early-stream variants with smaller ranges.
const PM1_COPY_RANGES: &[Vl] = &[
    Vl { offset: 0, bits: 6 },
    Vl {
        offset: 64,
        bits: 8,
    },
    Vl { offset: 0, bits: 6 },
    Vl {
        offset: 64,
        bits: 9,
    },
    Vl {
        offset: 576,
        bits: 11,
    },
    Vl {
        offset: 2624,
        bits: 13,
    },
    Vl {
        offset: 64,
        bits: 8,
    },
    Vl {
        offset: 576,
        bits: 8,
    },
    Vl {
        offset: 576,
        bits: 9,
    },
    Vl {
        offset: 576,
        bits: 10,
    },
    Vl {
        offset: 2624,
        bits: 8,
    },
    Vl {
        offset: 2624,
        bits: 9,
    },
    Vl {
        offset: 2624,
        bits: 10,
    },
    Vl {
        offset: 2624,
        bits: 11,
    },
    Vl {
        offset: 2624,
        bits: 12,
    },
];

/// `-pm1-` byte-distance ranges for history-list walks.
pub(crate) const PM1_BYTE_RANGES: &[Vl] = &[
    Vl { offset: 0, bits: 4 },
    Vl {
        offset: 16,
        bits: 4,
    },
    Vl {
        offset: 32,
        bits: 5,
    },
    Vl {
        offset: 64,
        bits: 6,
    },
    Vl {
        offset: 128,
        bits: 6,
    },
    Vl {
        offset: 192,
        bits: 6,
    },
];

/// `-pm1-` byte-index trees: each row is a flat nybble-encoded binary
/// tree; a nybble `>= 0xa` is a leaf (`nybble - 10`), otherwise an
/// offset to the child entry within the row.
const PM1_BYTE_TREES: &[&[u8]] = &[
    &[0x12, 0x2d, 0xef, 0x1c, 0xab],
    &[0x12, 0x23, 0xde, 0xab, 0xcf],
    &[0x12, 0x2c, 0xd2, 0xab, 0xef],
    &[0x12, 0xa2, 0xd2, 0xbc, 0xef],
    &[0x12, 0xa2, 0xc2, 0xbd, 0xef],
    &[0x12, 0xa2, 0xcd, 0xb1, 0xef],
    &[0x12, 0xab, 0x12, 0xcd, 0xef],
    &[0x12, 0xab, 0x1d, 0xc1, 0xef],
    &[0x12, 0xab, 0xc1, 0xd1, 0xef],
    &[0xa1, 0x12, 0x2c, 0xde, 0xbf],
    &[0xa1, 0x1d, 0x1c, 0xb1, 0xef],
    &[0xa1, 0x12, 0x2d, 0xef, 0xbc],
    &[0xa1, 0x12, 0xb2, 0xde, 0xcf],
    &[0xa1, 0x12, 0xbc, 0xd1, 0xef],
    &[0xa1, 0x1c, 0xb1, 0xd1, 0xef],
    &[0xa1, 0xb1, 0x12, 0xcd, 0xef],
    &[0xa1, 0xb1, 0xc1, 0xd1, 0xef],
    &[0x12, 0x1c, 0xde, 0xab],
    &[0x12, 0xa2, 0xcd, 0xbe],
    &[0x12, 0xab, 0xc1, 0xde],
    &[0xa1, 0x1d, 0x1c, 0xbe],
    &[0xa1, 0x12, 0xbc, 0xde],
    &[0xa1, 0x1c, 0xb1, 0xde],
    &[0xa1, 0xb1, 0xc1, 0xde],
    &[0x1d, 0x1c, 0xab],
    &[0x1c, 0xa1, 0xbd],
    &[0x12, 0xab, 0xcd],
    &[0xa1, 0x1c, 0xbd],
    &[0xa1, 0xb1, 0xcd],
    &[0xa1, 0xbc],
    &[0xab],
    &[0x00],
];

/// `-pm1-` byte-index lookup through `tree` (flat nybble tree).
fn pm1_byte_index(r: &mut MsbReader<'_>, tree: &[u8]) -> Result<usize, Error> {
    let mut p = 0usize;
    if *tree.first().unwrap_or(&0) == 0 {
        return Ok(0);
    }
    loop {
        let bit = usize::try_from(r.get(1)).unwrap_or(0);
        let byte = *tree
            .get(p)
            .ok_or(Error::InvalidData("lha: pm1 tree overflow"))?;
        let child = usize::from(if bit == 0 { byte >> 4 } else { byte & 0x0f });
        if child >= 10 {
            return Ok(child - 10);
        }
        p += child;
        if p >= tree.len() {
            return Err(Error::InvalidData("lha: pm1 tree overflow"));
        }
    }
}

/// `-pm1-` static-huffman literal-block length: 1..=216.
fn pm1_block_len(r: &mut MsbReader<'_>) -> usize {
    let mut x = usize::try_from(r.get(2)).unwrap_or(0);
    if x < 3 {
        return x + 1;
    }
    x = usize::try_from(r.get(3)).unwrap_or(0);
    if x < 7 {
        return x + 4;
    }
    x = usize::try_from(r.get(4)).unwrap_or(0);
    if x < 14 {
        return x + 11;
    }
    if x == 14 {
        return usize::try_from(r.get(6)).unwrap_or(0) + 25;
    }
    usize::try_from(r.get(7)).unwrap_or(0) + 89
}

/// `-pm1-` static-huffman copy length: 3..=244.
fn pm1_copy_len(r: &mut MsbReader<'_>) -> usize {
    let mut x = usize::try_from(r.get(2)).unwrap_or(0);
    if x < 3 {
        return x + 3;
    }
    x = usize::try_from(r.get(3)).unwrap_or(0);
    if x < 5 {
        return x + 6;
    }
    if x == 5 {
        return usize::try_from(r.get(2)).unwrap_or(0) + 11;
    }
    if x == 6 {
        return usize::try_from(r.get(3)).unwrap_or(0) + 15;
    }
    x = usize::try_from(r.get(6)).unwrap_or(0);
    if x < 62 {
        return x + 23;
    }
    if x == 62 {
        return usize::try_from(r.get(5)).unwrap_or(0) + 85;
    }
    usize::try_from(r.get(7)).unwrap_or(0) + 117
}

/// Read a bit only once `pos` reaches `threshold`; `def` otherwise.
fn pm1_bit_after(r: &mut MsbReader<'_>, pos: usize, threshold: usize, def: u32) -> u32 {
    if pos >= threshold { r.get(1) } else { def }
}

/// `-pm1-` copy command: range index, count, distance, then copy.
fn pm1_copy_cmd(s: &mut Sink, r: &mut MsbReader<'_>, expected: usize) -> Result<(), Error> {
    let pos = s.out.len();
    let mut range = if r.get(1) == 0 {
        if pm1_bit_after(r, pos, 576, 0) != 0 {
            4usize
        } else {
            usize::try_from(pm1_bit_after(r, pos, 64, 0)).unwrap_or(0)
        }
    } else if pm1_bit_after(r, pos, 64, 1) == 0 {
        3usize
    } else if pm1_bit_after(r, pos, 2624, 1) != 0 {
        2usize
    } else {
        5usize
    };
    let count = if range < 2 { 2 } else { pm1_copy_len(r) };
    // Redirect to the limited early-stream table entries.
    if range == 3 && pos < 320 {
        range = 6;
    } else if range == 4 {
        if pos < 832 {
            range = 7;
        } else if pos < 1088 {
            range = 8;
        } else if pos < 1600 {
            range = 9;
        }
    } else if range == 5 {
        if pos < 2880 {
            range = 10;
        } else if pos < 3136 {
            range = 11;
        } else if pos < 3648 {
            range = 12;
        } else if pos < 4672 {
            range = 13;
        } else if pos < 6720 {
            range = 14;
        }
    }
    let e = &PM1_COPY_RANGES[range];
    let dist = usize::try_from(e.offset + r.get(e.bits)).unwrap_or(0);
    if dist >= pos {
        return Err(Error::InvalidData("lha: pm1 bad distance"));
    }
    let mut src = (s.w + s.ring.len() - dist - 1) & s.mask;
    for _ in 0..count {
        if s.out.len() >= expected {
            break;
        }
        let v = s.ring[src];
        s.emit(v);
        src = (src + 1) & s.mask;
    }
    Ok(())
}

/// Decode `-pm1-` to `expected` bytes.
fn decode_pm1(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 16384;
    const MAX_BLOCK: usize = 216;

    // PM1 reads zero bytes past end-of-stream (reference behaviour
    // for archives whose stored size undershoots the bit stream).
    let mut padded = input.to_vec();
    padded.resize(input.len() + 512, 0);
    let mut r = MsbReader::new(&padded);
    let mut s = Sink::new(N, 0, expected);

    let tree_idx = usize::try_from(r.get(5)).unwrap_or(0);
    let byte_tree = PM1_BYTE_TREES
        .get(tree_idx)
        .copied()
        .ok_or(Error::InvalidData("lha: bad pm1 header"))?;

    while s.out.len() < expected {
        // Command type bit: 0 = copy, 1 = literal block (+ copy).
        if r.get(1) == 0 {
            pm1_copy_cmd(&mut s, &mut r, expected)?;
            continue;
        }
        let n = pm1_block_len(&mut r);
        for _ in 0..n {
            if s.out.len() >= expected {
                break;
            }
            let idx = pm1_byte_index(&mut r, byte_tree)?;
            let dist = vl_decode(&mut r, PM1_BYTE_RANGES, idx)?;
            let b = s.hist.find(dist as u8);
            s.emit(b);
        }
        if n == MAX_BLOCK {
            continue;
        }
        pm1_copy_cmd(&mut s, &mut r, expected)?;
    }
    Ok(s.out)
}
