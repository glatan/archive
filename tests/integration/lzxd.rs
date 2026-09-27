use super::*;

// ============================================================
// LZX DELTA (MS-PATCH) tests
// ============================================================
//
// The *_LZD byte arrays below are verbatim/aligned/uncompressed-block
// LZXD streams produced by the test-side encoder in this file. Every
// stream was additionally decoded with libmspack's reference LZXD
// decoder (LGPL 2.1, `lzxd_decompress` with is_delta=1) during vector
// creation and produced identical output.

const W17: usize = 1 << 17;

// -------------------------------------------------------------------
// Test-side LZXD encoder: verbatim/aligned/uncompressed blocks.
// -------------------------------------------------------------------
mod enc {
    #![allow(dead_code)]

    pub const NUM_LIT: usize = 256;

    pub struct Bits {
        pub out: Vec<u8>,
        acc: u32,
        n: u32,
    }
    impl Bits {
        pub fn new() -> Self {
            Bits {
                out: vec![],
                acc: 0,
                n: 0,
            }
        }
        pub fn bits(&mut self, v: u32, n: u32) {
            for i in (0..n).rev() {
                self.acc = (self.acc << 1) | ((v >> i) & 1);
                self.n += 1;
                if self.n == 16 {
                    self.out.push((self.acc & 0xff) as u8);
                    self.out.push(((self.acc >> 8) & 0xff) as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }
        pub fn align16(&mut self) {
            while self.n != 0 {
                self.bits(0, 1);
            }
        }
        pub fn raw(&mut self, bs: &[u8]) {
            debug_assert_eq!(self.n % 8, 0);
            if self.n == 8 {
                self.out.push((self.acc & 0xff) as u8);
                self.acc = 0;
                self.n = 0;
            }
            debug_assert_eq!(self.n, 0);
            self.out.extend_from_slice(bs);
        }
    }

    pub fn canon(lens: &[u8]) -> Vec<u32> {
        let mut codes = vec![0u32; lens.len()];
        let mut code = 0u32;
        for l in 1u8..=16 {
            for (s, &sl) in lens.iter().enumerate() {
                if sl == l {
                    codes[s] = code;
                    code += 1;
                }
            }
            code <<= 1;
        }
        codes
    }

    pub fn slot_bf(slot: usize) -> (u32, u32) {
        if slot < 4 {
            (slot as u32, 0)
        } else if slot < 36 {
            let f = (slot >> 1) - 1;
            (((2 + (slot & 1)) << f) as u32, f as u32)
        } else {
            (((slot - 34) << 17) as u32, 17)
        }
    }
    pub fn slot_for(formatted: u32) -> usize {
        let mut s = 0usize;
        while slot_bf(s + 1).0 <= formatted {
            s += 1;
        }
        s
    }
    pub fn nslots(window: usize) -> usize {
        if window <= 1 << 19 {
            window.trailing_zeros() as usize * 2
        } else {
            (window >> 17) + 34
        }
    }

    #[derive(Clone, Copy)]
    pub enum Elem {
        Lit(u8),
        Match { len: usize, offset: u32 },
        RMatch { len: usize, r: usize },
    }
    impl Elem {
        pub fn produced(&self) -> usize {
            match *self {
                Elem::Lit(_) => 1,
                Elem::Match { len, .. } | Elem::RMatch { len, .. } => len,
            }
        }
    }

    #[derive(Clone)]
    pub struct Trees {
        pub main: Vec<u8>,
        pub len: Vec<u8>,
        pub aligned: [u8; 8],
    }

    /// Complete-tree code lengths (Kraft sum = 1) for a used-symbol set.
    pub fn complete_lens(total: usize, used: &[usize]) -> Vec<u8> {
        let mut lens = vec![0u8; total];
        let mut used: Vec<usize> = used.to_vec();
        used.sort();
        used.dedup();
        if used.is_empty() {
            return lens;
        }
        if used.len() == 1 {
            lens[used[0]] = 1;
            let other = (0..total).find(|&i| i != used[0]).unwrap();
            lens[other] = 1;
            return lens;
        }
        let n = used.len();
        let l = (usize::BITS - (n - 1).leading_zeros()) as usize;
        let b = (1usize << l) - n;
        let a = n - b;
        for (i, &sym) in used.iter().enumerate() {
            lens[sym] = if i < a { l as u8 } else { (l - 1) as u8 };
        }
        lens
    }

    pub fn trees_for(
        lits: &[usize],
        matches: &[usize],
        lens: &[usize],
        aligned_used: &[usize],
        nsl: usize,
    ) -> Trees {
        let mut mainset: Vec<usize> = lits.to_vec();
        mainset.extend(matches.iter().map(|i| NUM_LIT + i));
        let main = complete_lens(NUM_LIT + 8 * nsl, &mainset);
        let ln = complete_lens(249, lens);
        let alv = complete_lens(8, aligned_used);
        let mut al = [0u8; 8];
        al.copy_from_slice(&alv);
        Trees {
            main,
            len: ln,
            aligned: al,
        }
    }

    pub struct Enc {
        pub out: Vec<u8>,
        seg: Bits,
        first_chunk: bool,
        e8: Option<u32>,
        pub nslots: usize,
        prev: Option<Trees>,
        block_aligned: bool,
    }

    impl Enc {
        pub fn new(window: usize, e8: Option<u32>) -> Self {
            Enc {
                out: vec![],
                seg: Bits::new(),
                first_chunk: true,
                e8,
                nslots: nslots(window),
                prev: None,
                block_aligned: false,
            }
        }

        fn emit_tree(&mut self, new: &[u8], prev: &[u8]) {
            // Complete pretree: 12 x len 4 + 8 x len 5 (Kraft = 1).
            static PT: [u8; 20] = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5];
            let pc = canon(&PT);
            for &l in PT.iter() {
                self.seg.bits(l as u32, 4);
            }
            for (&p, &n) in prev.iter().zip(new.iter()) {
                let code = (p as i32 - n as i32).rem_euclid(17) as u32;
                self.seg.bits(pc[code as usize], PT[code as usize] as u32);
            }
        }

        fn header(&mut self) {
            if self.first_chunk {
                match self.e8 {
                    Some(sz) => {
                        self.seg.bits(1, 1);
                        self.seg.bits(sz >> 16, 16);
                        self.seg.bits(sz & 0xffff, 16);
                    }
                    None => self.seg.bits(0, 1),
                }
                self.first_chunk = false;
            }
        }

        pub fn uncompressed(&mut self, data: &[u8], r: [u32; 3]) {
            self.header();
            self.seg.bits(3, 3);
            self.seg.bits(data.len() as u32, 24);
            self.seg.align16();
            let mut rb = Vec::new();
            for v in r {
                rb.extend_from_slice(&v.to_le_bytes());
            }
            rb.extend_from_slice(data);
            self.seg.raw(&rb);
            if data.len() % 2 == 1 {
                self.seg.raw(&[0]);
            }
        }

        pub fn compressed(&mut self, aligned: bool, size: u32, trees: &Trees, elems: &[Elem]) {
            self.header();
            self.block_aligned = aligned;
            self.seg.bits(if aligned { 2 } else { 1 }, 3);
            self.seg.bits(size, 24);
            if aligned {
                for i in 0..8 {
                    self.seg.bits(trees.aligned[i] as u32, 3);
                }
            }
            let zeros_main = vec![0u8; trees.main.len()];
            let zeros_len = vec![0u8; 249];
            let (pm1, pm2, pl) = match &self.prev {
                Some(p) => (
                    p.main[..NUM_LIT].to_vec(),
                    p.main[NUM_LIT..].to_vec(),
                    p.len.clone(),
                ),
                None => (
                    zeros_main[..NUM_LIT].to_vec(),
                    zeros_main[NUM_LIT..].to_vec(),
                    zeros_len,
                ),
            };
            self.emit_tree(&trees.main[..NUM_LIT], &pm1);
            self.emit_tree(&trees.main[NUM_LIT..], &pm2);
            self.emit_tree(&trees.len, &pl);
            self.prev = Some(trees.clone());
            self.emit_elems(trees, elems);
        }

        /// Continue a block's element sequence into the next chunk
        /// (blocks may span chunk boundaries; no new header).
        pub fn second_segment(&mut self, trees: &Trees, elems: &[Elem]) {
            self.emit_elems(trees, elems);
        }

        fn emit_elems(&mut self, trees: &Trees, elems: &[Elem]) {
            let mc = canon(&trees.main);
            let lc = canon(&trees.len);
            let ac = canon(&trees.aligned);
            for e in elems {
                match *e {
                    Elem::Lit(b) => {
                        self.seg.bits(mc[b as usize], trees.main[b as usize] as u32);
                    }
                    Elem::Match { len, offset } => {
                        let formatted = offset + 2;
                        let slot = slot_for(formatted);
                        self.emit_match(len, slot, formatted, trees, &mc, &lc, &ac);
                    }
                    Elem::RMatch { len, r } => {
                        self.emit_match(len, r, r as u32, trees, &mc, &lc, &ac);
                    }
                }
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn emit_match(
            &mut self,
            len: usize,
            slot: usize,
            formatted: u32,
            t: &Trees,
            mc: &[u32],
            lc: &[u32],
            ac: &[u32],
        ) {
            let (header, len_elem, extra) = if len <= 8 {
                (len - 2, None, None)
            } else if len <= 256 {
                (7, Some(len - 9), None)
            } else {
                (7, Some(248), Some(len))
            };
            let elem = NUM_LIT + slot * 8 + header;
            self.seg.bits(mc[elem], t.main[elem] as u32);
            if let Some(le) = len_elem {
                self.seg.bits(lc[le], t.len[le] as u32);
            }
            let (base, fbits) = slot_bf(slot);
            let footer = formatted - base;
            if self.block_aligned && fbits > 3 {
                self.seg.bits(footer >> 3, fbits - 3);
                self.seg.bits(
                    ac[(footer & 7) as usize],
                    t.aligned[(footer & 7) as usize] as u32,
                );
            } else if fbits > 0 {
                self.seg.bits(footer, fbits);
            }
            if let Some(l) = extra {
                if l <= 512 {
                    self.seg.bits(0, 1);
                    self.seg.bits((l - 257) as u32, 8);
                } else if l <= 1536 {
                    self.seg.bits(0b10, 2);
                    self.seg.bits((l - 513) as u32, 10);
                } else if l <= 5632 {
                    self.seg.bits(0b110, 3);
                    self.seg.bits((l - 1537) as u32, 12);
                } else {
                    self.seg.bits(0b111, 3);
                    self.seg.bits((l - 257) as u32, 15);
                }
            }
        }

        pub fn end_chunk(&mut self) {
            self.seg.align16();
            self.out
                .extend_from_slice(&(self.seg.out.len() as u16).to_le_bytes());
            self.out.append(&mut self.seg.out);
            self.seg = Bits::new();
        }
    }

    /// Simulate element output (for building expected data).
    pub fn simulate(elems: &[Elem], reference: &[u8]) -> Vec<u8> {
        let mut win = reference.to_vec();
        let start = win.len();
        let mut r = [1u32, 1, 1];
        for el in elems {
            match *el {
                Elem::Lit(b) => win.push(b),
                Elem::Match { len, offset } => {
                    let st = win.len() - offset as usize;
                    for i in 0..len {
                        let b = win[st + i];
                        win.push(b);
                    }
                    r = [offset, r[0], r[1]];
                }
                Elem::RMatch { len, r: rr } => {
                    let off = r[rr] as usize;
                    let st = win.len() - off;
                    for i in 0..len {
                        let b = win[st + i];
                        win.push(b);
                    }
                    match rr {
                        1 => r.swap(0, 1),
                        2 => r.swap(0, 2),
                        _ => {}
                    }
                }
            }
        }
        win.split_off(start)
    }

    pub fn match_elem_index(len: usize, offset: u32) -> usize {
        let slot = slot_for(offset + 2);
        let hdr = if len <= 8 { len - 2 } else { 7 };
        slot * 8 + hdr
    }
}

use enc::{Elem, Enc};

// -------------------------------------------------------------------
// libmspack-validated vectors (see header comment).
// -------------------------------------------------------------------

const V4_REF: &[u8] = b"ABCDEFGHIJ";

// v1: verbatim literals "Hello, LZXD!"
const V1_LITERALS_LZD: &[u8] = &[
    0xae, 0x01, 0x00, 0x10, 0xc4, 0x00, 0x44, 0x44, 0x44, 0x44, 0x45, 0x44, 0x55, 0x55, 0x50, 0x55,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
    0x00, 0xe4, 0x00, 0x00, 0x03, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x90, 0x00, 0xc8, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x34, 0x00, 0x00,
    0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x80, 0x06, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x00, 0x88, 0x88, 0x88, 0x88, 0xaa, 0x88, 0xaa, 0xaa, 0x00, 0xaa, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x88, 0x00, 0x88, 0x88, 0x88, 0x88, 0xaa, 0x88, 0xaa, 0xaa, 0x00, 0xaa, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x99, 0x9b, 0x46, 0x5e, 0x00, 0xd8,
];

// v4: delta match into reference data ("ABCDEFGHIJ" -> "abcDEFabce")
const V4_REFERENCE_LZD: &[u8] = &[
    0xaa, 0x01, 0x00, 0x10, 0xa4, 0x00, 0x44, 0x44, 0x44, 0x44, 0x45, 0x44, 0x55, 0x55, 0x50, 0x55,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb4, 0xd6, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x55, 0x55, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x80, 0x0d, 0x00, 0x00, 0xc0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x55, 0x15, 0x55, 0x55, 0x00, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5c, 0x02, 0xc0, 0x81,
];

// v6: verbatim block + uncompressed block (odd size, R0..R2 = 10/20/30)
const V6_MIXED_LZD: &[u8] = &[
    0xca, 0x01, 0x00, 0x10, 0xa4, 0x00, 0x44, 0x44, 0x44, 0x44, 0x45, 0x44, 0x55, 0x55, 0x50, 0x55,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x41, 0x6b, 0x0d, 0xa0, 0x80, 0x06, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x55, 0x15, 0x55, 0x55, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x88, 0x08, 0x88, 0x88, 0x88, 0x88, 0xaa, 0x8a, 0xaa, 0xaa, 0x00, 0xa0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf2, 0x00, 0x83, 0x97, 0x00, 0x00, 0x00, 0x0f,
    0x0a, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x00,
];

#[test]
fn lzxd_verbatim_literals_vector() {
    let out = lzxd::decode(V1_LITERALS_LZD, W17, &[], 12).unwrap();
    assert_eq!(out, b"Hello, LZXD!");
    assert_eq!(
        lzxd::decode_all(V1_LITERALS_LZD, W17, &[], 1 << 20).unwrap(),
        out
    );
}

#[test]
fn lzxd_reference_data_vector() {
    let out = lzxd::decode(V4_REFERENCE_LZD, W17, V4_REF, 10).unwrap();
    assert_eq!(out, b"abcDEFabce");
}

#[test]
fn lzxd_mixed_blocks_vector() {
    let out = lzxd::decode(V6_MIXED_LZD, W17, &[], 25).unwrap();
    assert_eq!(out, b"QWERTYQWER0123456789abcde");
}

#[test]
fn lzxd_generated_matches_and_repeats() {
    let nsl = enc::nslots(W17);
    let elems = vec![
        Elem::Lit(b'a'),
        Elem::Lit(b'b'),
        Elem::Lit(b'c'),
        Elem::Lit(b'd'),
        Elem::Lit(b'e'),
        Elem::Lit(b'f'),
        Elem::Lit(b'g'),
        Elem::Lit(b'h'),
        Elem::Match { len: 6, offset: 8 },
        Elem::Lit(b'Z'),
        Elem::RMatch { len: 4, r: 0 },
        Elem::Lit(b'!'),
        Elem::Match { len: 3, offset: 2 },
        Elem::RMatch { len: 5, r: 1 },
        Elem::RMatch { len: 5, r: 2 },
    ];
    let exp = enc::simulate(&elems, &[]);
    let lits: Vec<usize> = {
        let mut v: Vec<usize> = exp.iter().map(|&b| b as usize).collect();
        v.sort();
        v.dedup();
        v
    };
    let mut mset: Vec<usize> = vec![];
    for el in &elems {
        let (len, slot) = match *el {
            Elem::Match { len, offset } => (len, enc::slot_for(offset + 2)),
            Elem::RMatch { len, r } => (len, r),
            _ => continue,
        };
        mset.push(slot * 8 + (len - 2));
    }
    mset.sort();
    mset.dedup();
    let trees = enc::trees_for(&lits, &mset, &[], &[], nsl);
    let mut e = Enc::new(W17, None);
    e.compressed(false, exp.len() as u32, &trees, &elems);
    e.end_chunk();
    assert_eq!(lzxd::decode(&e.out, W17, &[], exp.len()).unwrap(), exp);
}

#[test]
fn lzxd_generated_extra_lengths() {
    let nsl = enc::nslots(W17);
    let elems = vec![
        Elem::Lit(b'a'),
        Elem::Lit(b'b'),
        Elem::Lit(b'c'),
        Elem::Lit(b'd'),
        Elem::Lit(b'e'),
        Elem::Lit(b'f'),
        Elem::Lit(b'g'),
        Elem::Lit(b'h'),
        Elem::Lit(b'i'),
        Elem::Lit(b'j'),
        Elem::Match {
            len: 300,
            offset: 10,
        }, // prefix '0'
        Elem::Match {
            len: 600,
            offset: 310,
        }, // prefix '10'
        Elem::Match {
            len: 2000,
            offset: 50,
        }, // prefix '110'
        Elem::Match {
            len: 6000,
            offset: 100,
        }, // prefix '111'
    ];
    let exp = enc::simulate(&elems, &[]);
    let lits: Vec<usize> = (b'a'..=b'j').map(|b| b as usize).collect();
    let mut mset: Vec<usize> = vec![];
    let mut lset: Vec<usize> = vec![248];
    for el in &elems {
        if let Elem::Match { len, offset } = *el {
            mset.push(enc::match_elem_index(len, offset));
            if len > 8 && len <= 256 {
                lset.push(len - 9);
            }
        }
    }
    mset.sort();
    mset.dedup();
    let trees = enc::trees_for(&lits, &mset, &lset, &[], nsl);
    let mut e = Enc::new(W17, None);
    e.compressed(false, exp.len() as u32, &trees, &elems);
    e.end_chunk();
    assert_eq!(lzxd::decode(&e.out, W17, &[], exp.len()).unwrap(), exp);
}

#[test]
fn lzxd_generated_aligned_block() {
    let nsl = enc::nslots(W17);
    let mut elems: Vec<Elem> = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
        .iter()
        .map(|&b| Elem::Lit(b))
        .collect();
    elems.push(Elem::Match { len: 8, offset: 30 });
    elems.push(Elem::Match { len: 8, offset: 40 });
    elems.push(Elem::Match { len: 5, offset: 39 });
    elems.push(Elem::Match { len: 6, offset: 16 });
    let exp = enc::simulate(&elems, &[]);
    let lits: Vec<usize> = {
        let mut v: Vec<usize> = exp.iter().map(|&b| b as usize).collect();
        v.sort();
        v.dedup();
        v
    };
    let mut mset: Vec<usize> = vec![];
    for el in &elems {
        if let Elem::Match { len, offset } = *el {
            mset.push(enc::match_elem_index(len, offset));
        }
    }
    mset.sort();
    mset.dedup();
    let trees = enc::trees_for(&lits, &mset, &[], &[0, 1, 2, 3, 4, 5, 6, 7], nsl);
    let mut e = Enc::new(W17, None);
    e.compressed(true, exp.len() as u32, &trees, &elems);
    e.end_chunk();
    assert_eq!(lzxd::decode(&e.out, W17, &[], exp.len()).unwrap(), exp);
}

#[test]
fn lzxd_generated_multichunk_span() {
    // One verbatim block spanning a 32 KiB chunk boundary.
    let nsl = enc::nslots(W17);
    let seed = b"0123456789abcdef";
    let mut elems: Vec<Elem> = seed.iter().map(|&b| Elem::Lit(b)).collect();
    let mut produced = 16usize;
    while produced < 32768 {
        let l = (32768 - produced).min(250);
        elems.push(Elem::Match { len: l, offset: 16 });
        produced += l;
    }
    elems.push(Elem::Lit(b'Z'));
    elems.push(Elem::Match {
        len: 100,
        offset: 16,
    });
    let exp = enc::simulate(&elems, &[]);
    assert_eq!(exp.len(), 32869);
    let lits: Vec<usize> = {
        let mut v: Vec<usize> = seed.iter().map(|&b| b as usize).collect();
        v.push(b'Z' as usize);
        v.sort();
        v.dedup();
        v
    };
    let mut mset: Vec<usize> = vec![];
    let mut lset: Vec<usize> = vec![];
    for el in &elems {
        if let Elem::Match { len, offset } = *el {
            mset.push(enc::match_elem_index(len, offset));
            if len > 8 && len <= 256 {
                lset.push(len - 9);
            }
        }
    }
    mset.sort();
    mset.dedup();
    lset.sort();
    lset.dedup();
    let trees = enc::trees_for(&lits, &mset, &lset, &[], nsl);
    let mut e = Enc::new(W17, None);
    let mut i = 0usize;
    let mut acc = 0usize;
    while acc < 32768 {
        acc += elems[i].produced();
        i += 1;
    }
    e.compressed(false, exp.len() as u32, &trees, &elems[..i]);
    e.end_chunk();
    e.second_segment(&trees, &elems[i..]);
    e.end_chunk();
    assert_eq!(lzxd::decode(&e.out, W17, &[], exp.len()).unwrap(), exp);
}

#[test]
fn lzxd_generated_e8() {
    let nsl = enc::nslots(W17);
    let filesize = 100_000i64;
    let mut raw: Vec<u8> = (0..200u32).map(|i| (i * 37 + 11) as u8).collect();
    let cur = 20i64;
    let target = 5000i64;
    raw[20] = 0xe8;
    raw[21..25].copy_from_slice(&((target - cur) as i32).to_le_bytes());
    // Encode-side E8 translation per [MS-PATCH] 2.2.2.
    let mut enc_data = raw.clone();
    let n = enc_data.len();
    for i in 0..n.saturating_sub(10) {
        if enc_data[i] == 0xe8 {
            let cur = i as i64;
            let d = i32::from_le_bytes([
                enc_data[i + 1],
                enc_data[i + 2],
                enc_data[i + 3],
                enc_data[i + 4],
            ]) as i64;
            let target = cur + d;
            if target >= 0 && target < filesize + cur {
                let t = if target >= filesize {
                    d - filesize
                } else {
                    target
                };
                let v = t as u32;
                enc_data[i + 1] = (v & 0xff) as u8;
                enc_data[i + 2] = ((v >> 8) & 0xff) as u8;
                enc_data[i + 3] = ((v >> 16) & 0xff) as u8;
                enc_data[i + 4] = ((v >> 24) & 0xff) as u8;
            }
        }
    }
    let lits: Vec<usize> = {
        let mut v: Vec<usize> = enc_data.iter().map(|&b| b as usize).collect();
        v.sort();
        v.dedup();
        v
    };
    let trees = enc::trees_for(&lits, &[], &[], &[], nsl);
    let elems: Vec<Elem> = enc_data.iter().map(|&b| Elem::Lit(b)).collect();
    let mut e = Enc::new(W17, Some(filesize as u32));
    e.compressed(false, enc_data.len() as u32, &trees, &elems);
    e.end_chunk();
    assert_eq!(lzxd::decode(&e.out, W17, &[], raw.len()).unwrap(), raw);
}

#[test]
fn lzxd_decode_all_matches_decode() {
    let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 3) as u8).collect();
    let c = lzxd::encode(&data);
    assert_eq!(lzxd::decode_all(&c, W17, &[], 1 << 20).unwrap(), data);
}

#[test]
fn lzxd_rejects_invalid() {
    // Invalid block type (type 5).
    let mut bad: Vec<u8> = vec![];
    bad.extend_from_slice(&6u16.to_le_bytes());
    // e8=0, type=5 (101), size 4, pad to word
    bad.extend_from_slice(&(5u16 << 12).to_le_bytes());
    bad.extend_from_slice(&((4u16 & 0xfff) << 4).to_le_bytes());
    assert!(lzxd::decode(&bad, W17, &[], 4).is_err());

    // Match offset before start of window.
    let nsl = enc::nslots(W17);
    let elems = vec![
        Elem::Lit(b'x'),
        Elem::Match { len: 4, offset: 5 }, // only 1 byte produced
    ];
    let mut mset = vec![enc::match_elem_index(4, 5)];
    mset.dedup();
    let trees = enc::trees_for(&[b'x' as usize], &mset, &[], &[], nsl);
    let mut e = Enc::new(W17, None);
    e.compressed(false, 5, &trees, &elems);
    e.end_chunk();
    assert!(lzxd::decode(&e.out, W17, &[], 5).is_err());
}

#[test]
fn lzxd_encode_decode_roundtrip() {
    for data in [
        b"a".as_slice(),
        b"odd sized  ".as_slice(),
        &vec![7u8; 32768],
        &vec![9u8; 65536 + 17],
    ] {
        let c = lzxd::encode(data);
        assert_eq!(lzxd::decode(&c, W17, &[], data.len()).unwrap(), data);
    }
}

#[test]
fn lzxd_rejects_match_crossing_chunk_boundary() {
    // A match element must not extend output past the 32 KiB output-chunk
    // boundary; [MS-PATCH] requires elements to be contained in a chunk.
    let nsl = enc::nslots(W17);
    let mut elems: Vec<Elem> = (0..32760u32).map(|i| Elem::Lit(i as u8)).collect();
    elems.push(Elem::Match { len: 16, offset: 8 });
    let exp_len: u32 = elems.iter().map(|e| e.produced()).sum::<usize>() as u32;
    // Every literal byte value occurs, and len 16 uses length symbol 16-9.
    let lits: Vec<usize> = (0..=255).collect();
    let mset = vec![enc::match_elem_index(16, 8)];
    let trees = enc::trees_for(&lits, &mset, &[7], &[], nsl);
    let mut e = Enc::new(W17, None);
    e.compressed(false, exp_len, &trees, &elems);
    e.end_chunk();
    match lzxd::decode(&e.out, W17, &[], exp_len as usize) {
        Err(archive::error::Error::InvalidData(msg)) => {
            assert_eq!(msg, "lzxd: match spans chunk boundary")
        }
        other => panic!("expected chunk-boundary error, got {other:?}"),
    }
}
