//! Quantum (tcompTYPE_QUANTUM) decompression for cabinet folders.
//!
//! Quantum is an adaptive arithmetic coder over an LZ match scheme
//! designed by David Stafford. The bit stream is
//! MSB-first, injected two bytes at a time. Output advances in 32 KiB
//! frames; after each frame the bit position is realigned to a byte
//! boundary and a trailer of `0x00`*`0xFF` is consumed.
//!
//! The selector model (`model7`) chooses per packet:
//! - `0..=3` -> literal byte from `model0..=model3` (64-symbol bands),
//! - `4` -> 3-byte match, position slot from `model4`,
//! - `5` -> 4-byte match, position slot from `model5`,
//! - `6` -> length from `model6len`, position slot from `model6`.
//!
//! Position slots index `POSITION_BASE`/`EXTRA_BITS`; variable lengths
//! index `LENGTH_BASE`/`LENGTH_EXTRA`.
//!
//! Ported/adapted from libmspack
//! `qtmd.c` (decoder-only upstream), Matthew Russotto's Quantum notes,
//! and the compcol port.
//!
//! Licensing: libmspack `qtmd.c` is LGPL-2.1 (Stuart Caie); this port is
//! incorporated under LGPL-2.1 section 3 (GPL-2.0-or-later) and combined
//! with this AGPL-3.0 work via AGPL-3.0 section 13. The compcol
//! intermediate reference is MIT-licensed.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

/// One Quantum frame produces 32 KiB of output before a realign+trailer.
const FRAME_SIZE: i64 = 32_768;

/// Valid `window_bits` range (1 KiB .. 2 MiB), carried in the high byte
/// of the folder's `type_compress` field.
const WINDOW_BITS_MIN: u32 = 10;
const WINDOW_BITS_MAX: u32 = 21;

/// MSB-first bit reader over the compressed payload, injected two bytes
/// at a time. At end of input one round of 16 zero bits is supplied —
/// the renormalisation loop can legitimately request bits the encoder
/// never emitted — after that the stream is truncated.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    bit_buffer: u32,
    bits_left: u32,
    eof_padded: bool,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            bit_buffer: 0,
            bits_left: 0,
            eof_padded: false,
        }
    }

    fn fill(&mut self) -> Result<(), Error> {
        if self.pos + 2 <= self.buf.len() {
            let v = (u32::from(self.buf[self.pos]) << 8) | u32::from(self.buf[self.pos + 1]);
            self.pos += 2;
            self.bit_buffer |= v << (32 - 16 - self.bits_left);
            self.bits_left += 16;
            Ok(())
        } else if !self.eof_padded {
            self.eof_padded = true;
            self.bits_left += 16;
            Ok(())
        } else {
            Err(Error::InvalidData("mscab: truncated quantum stream"))
        }
    }

    fn ensure(&mut self, n: u32) -> Result<(), Error> {
        while self.bits_left < n {
            self.fill()?;
        }
        Ok(())
    }

    fn get(&mut self, n: u32) -> u32 {
        debug_assert!(n <= self.bits_left);
        if n == 0 {
            return 0;
        }
        let v = self.bit_buffer >> (32 - n);
        self.bit_buffer = if n == 32 { 0 } else { self.bit_buffer << n };
        self.bits_left -= n;
        v
    }

    /// Read `n` bits (`0..=32`), chunking through 16-bit reads.
    fn read(&mut self, n: u32) -> Result<u32, Error> {
        let mut need = n;
        let mut v = 0u32;
        while need > 0 {
            if self.bits_left <= 16 {
                self.fill()?;
            }
            let run = self.bits_left.min(need);
            v = (v << run) | self.get(run);
            need -= run;
        }
        Ok(v)
    }

    /// Discard bits so the position lands on a byte boundary.
    fn align_byte(&mut self) {
        let drop = self.bits_left & 7;
        self.get(drop);
    }
}

/// One `(symbol, cumulative frequency)` pair of a probability model.
/// The last slot is a sentinel with `cumfreq == 0`.
#[derive(Clone, Copy, Default)]
struct ModelSym {
    sym: u16,
    cumfreq: u16,
}

/// Adaptive probability model over a small alphabet (`entries <= 64`).
struct Model {
    shiftsleft: i32,
    entries: usize,
    syms: [ModelSym; 65],
}

impl Model {
    /// Symbols `start..start+len` with initial cumfreqs `len..=0`.
    fn new(start: u16, len: usize) -> Self {
        debug_assert!(len <= 64);
        let mut syms = [ModelSym::default(); 65];
        for (i, s) in syms.iter_mut().take(len + 1).enumerate() {
            s.sym = start + i as u16;
            s.cumfreq = (len - i) as u16;
        }
        Self {
            shiftsleft: 4,
            entries: len,
            syms,
        }
    }

    /// Rescale the model once the total cumfreq budget overflows.
    fn update(&mut self) {
        self.shiftsleft -= 1;
        if self.shiftsleft != 0 {
            // Minor pass: halve cumfreqs, keeping the table monotone.
            for i in (0..self.entries).rev() {
                self.syms[i].cumfreq >>= 1;
                if self.syms[i].cumfreq <= self.syms[i + 1].cumfreq {
                    self.syms[i].cumfreq = self.syms[i + 1].cumfreq + 1;
                }
            }
        } else {
            // Major pass (every 50 minor steps): rebuild + resort.
            self.shiftsleft = 50;
            for i in 0..self.entries {
                self.syms[i].cumfreq -= self.syms[i + 1].cumfreq;
                self.syms[i].cumfreq += 1;
                self.syms[i].cumfreq >>= 1;
            }
            // Selection sort by frequency, descending — the exact
            // tie order matters for decoder agreement.
            for i in 0..self.entries.saturating_sub(1) {
                for j in (i + 1)..self.entries {
                    if self.syms[i].cumfreq < self.syms[j].cumfreq {
                        self.syms.swap(i, j);
                    }
                }
            }
            for i in (0..self.entries).rev() {
                self.syms[i].cumfreq += self.syms[i + 1].cumfreq;
            }
        }
    }
}

/// Arithmetic decoder with 16-bit H/L/C registers.
struct Arith {
    h: u32,
    l: u32,
    c: u32,
}

impl Arith {
    fn init_frame(&mut self, r: &mut Reader) -> Result<(), Error> {
        self.h = 0xFFFF;
        self.l = 0;
        self.c = r.read(16)?;
        Ok(())
    }

    fn symbol(&mut self, m: &mut Model, r: &mut Reader) -> Result<u16, Error> {
        let range = (self.h.wrapping_sub(self.l) & 0xFFFF) + 1;
        let total = m.syms[0].cumfreq as u32;
        if total == 0 {
            return Err(Error::InvalidData("mscab: quantum model exhausted"));
        }
        let symf = ((self
            .c
            .wrapping_sub(self.l)
            .wrapping_add(1)
            .wrapping_mul(total))
        .wrapping_sub(1)
            / range)
            & 0xFFFF;

        let mut i = 1usize;
        while i < m.entries && u32::from(m.syms[i].cumfreq) > symf {
            i += 1;
        }
        let sym = m.syms[i - 1].sym;

        let hi = m.syms[i - 1].cumfreq as u32;
        let lo = m.syms[i].cumfreq as u32;
        self.h = (self.l + hi * range / total).wrapping_sub(1) & 0xFFFF;
        self.l = (self.l + lo * range / total) & 0xFFFF;

        // Bump the chosen symbol's cumfreq and every entry before it.
        for s in m.syms.iter_mut().take(i) {
            s.cumfreq = s.cumfreq.wrapping_add(8);
        }
        if m.syms[0].cumfreq > 3800 {
            m.update();
        }

        // Renormalise: shift matched/underflow bit pairs out, pull in
        // stream bits.
        loop {
            if (self.l & 0x8000) != (self.h & 0x8000) {
                if (self.l & 0x4000) != 0 && (self.h & 0x4000) == 0 {
                    self.c ^= 0x4000;
                    self.l &= 0x3FFF;
                    self.h |= 0x4000;
                } else {
                    break;
                }
            }
            self.l = (self.l << 1) & 0xFFFF;
            self.h = ((self.h << 1) | 1) & 0xFFFF;
            r.ensure(1)?;
            let bit = r.get(1);
            self.c = ((self.c << 1) | bit) & 0xFFFF;
        }
        Ok(sym)
    }
}

/// Base offset per Quantum position slot (42 entries).
const POSITION_BASE: [u32; 42] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 786432, 1048576, 1572864,
];

/// Extra stream bits refining each position slot.
const EXTRA_BITS: [u8; 42] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19,
];

/// Base length per variable-length match code (27 entries).
const LENGTH_BASE: [u16; 27] = [
    0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26, 30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190,
    222, 254,
];

/// Extra stream bits refining each length code.
const LENGTH_EXTRA: [u8; 27] = [
    0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Decode a Quantum folder stream to `expected` bytes. `window_bits`
/// comes from the folder's `type_compress` high byte.
pub(crate) fn decode(input: &[u8], window_bits: u32, expected: usize) -> Result<Vec<u8>, Error> {
    if !(WINDOW_BITS_MIN..=WINDOW_BITS_MAX).contains(&window_bits) {
        return Err(Error::InvalidData(
            "mscab: quantum window bits out of range",
        ));
    }
    let window_size = 1usize << window_bits;
    let window_mask = window_size - 1;
    // Position-model sizes scale with the window.
    let i = (window_bits * 2) as usize;
    let mut models = [
        Model::new(0, 64),        // 0: literal band 0x00-0x3f
        Model::new(64, 64),       // 1: literal band 0x40-0x7f
        Model::new(128, 64),      // 2: literal band 0x80-0xbf
        Model::new(192, 64),      // 3: literal band 0xc0-0xff
        Model::new(0, i.min(24)), // 4: len-3 position slots
        Model::new(0, i.min(36)), // 5: len-4 position slots
        Model::new(0, i),         // 6: variable-length position slots
        Model::new(0, 27),        // 6len: variable match lengths
        Model::new(0, 7),         // 7: packet selector
    ];

    let mut r = Reader::new(input);
    let mut arith = Arith { h: 0, l: 0, c: 0 };
    let mut window = vec![0u8; window_size];
    let mut wpos = 0usize;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    let mut frame_todo = FRAME_SIZE;
    let mut header_read = false;
    let mut seek_ff = false;

    while out.len() < expected {
        if seek_ff {
            // Frame trailer: 0x00* then a 0xFF sentinel byte.
            loop {
                let b = r.read(8)?;
                if b == 0xFF {
                    break;
                }
                if b != 0 {
                    return Err(Error::InvalidData("mscab: bad quantum frame trailer"));
                }
            }
            seek_ff = false;
            header_read = false;
            frame_todo = FRAME_SIZE;
        }
        if !header_read {
            arith.init_frame(&mut r)?;
            header_read = true;
        }
        if frame_todo <= 0 {
            r.align_byte();
            seek_ff = true;
            continue;
        }

        let sel = arith.symbol(&mut models[8], &mut r)?;
        match sel {
            0..=3 => {
                let b = arith.symbol(&mut models[sel as usize], &mut r)? as u8;
                window[wpos & window_mask] = b;
                wpos += 1;
                out.push(b);
                frame_todo -= 1;
            }
            4..=6 => {
                let (len, off) = if sel == 6 {
                    let sl = arith.symbol(&mut models[7], &mut r)? as usize; // model6len
                    if sl >= LENGTH_EXTRA.len() {
                        return Err(Error::InvalidData("mscab: quantum length out of range"));
                    }
                    let le = u32::from(LENGTH_EXTRA[sl]);
                    let extra = if le == 0 { 0 } else { r.read(le)? as usize };
                    let len = LENGTH_BASE[sl] as usize + extra + 5;
                    let so = arith.symbol(&mut models[6], &mut r)? as usize;
                    if so >= EXTRA_BITS.len() {
                        return Err(Error::InvalidData("mscab: quantum offset out of range"));
                    }
                    let eb = u32::from(EXTRA_BITS[so]);
                    let extra = if eb == 0 { 0 } else { r.read(eb)? as usize };
                    (len, POSITION_BASE[so] as usize + extra + 1)
                } else {
                    let m = sel as usize; // 4 -> model4, 5 -> model5
                    let so = arith.symbol(&mut models[m], &mut r)? as usize;
                    if so >= EXTRA_BITS.len() {
                        return Err(Error::InvalidData("mscab: quantum offset out of range"));
                    }
                    let eb = u32::from(EXTRA_BITS[so]);
                    let extra = if eb == 0 { 0 } else { r.read(eb)? as usize };
                    (
                        sel as usize - 1, // 4 -> 3 bytes, 5 -> 4 bytes
                        POSITION_BASE[so] as usize + extra + 1,
                    )
                };
                if off == 0 || off > window_size {
                    return Err(Error::InvalidData("mscab: quantum distance out of range"));
                }
                // A match may overshoot the declared output size;
                // the window still records those bytes.
                let emit = (expected - out.len()).min(len);
                crate::compress::match_ops::copy_ring(
                    &mut window,
                    wpos.wrapping_sub(off),
                    wpos,
                    len,
                    &mut out,
                    emit,
                );
                wpos += len;
                frame_todo -= len as i64;
            }
            _ => return Err(Error::InvalidData("mscab: bad quantum selector")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real Quantum stream (libmspack `qtm.txt` fixture, window_bits 18)
    /// including the per-block synthesised `0xFF` sentinel. Decodes to the
    /// "If you can read this..." message.
    const QTM_TXT: &[u8] = &[
        0xD6, 0x06, 0x69, 0x0B, 0xCB, 0x47, 0xF0, 0x2C, 0x2A, 0x3A, 0x8F, 0x2C, 0xAB, 0xBB, 0x3C,
        0xB9, 0x33, 0x01, 0x8B, 0xD8, 0x58, 0x4B, 0x7B, 0x01, 0xBA, 0x6F, 0x6D, 0x51, 0x6E, 0x3A,
        0xC3, 0x67, 0x42, 0x4B, 0xEB, 0x02, 0x36, 0x43, 0xD6, 0x66, 0x56, 0xCA, 0x9E, 0x72, 0xCC,
        0x30, 0x00, 0x00, 0xFF,
    ];
    const QTM_TXT_EXPECTED: &[u8] = b"If you can read this, the Quantum decompressor is working!\n";

    /// Real Quantum stream (libmspack `cve-2010-2801-qtm-flush.cab`
    /// payload, window_bits 18) with per-block `0xFF` sentinels already
    /// interleaved. Decodes to 524159 zero bytes across 16 frames.
    const CVE_2010_2801: &[u8] = &[
        0xFF, 0x6D, 0xDA, 0x34, 0x62, 0x1A, 0x9B, 0xA9, 0x92, 0x04, 0xD2, 0x80, 0x00, 0x20, 0xFF,
        0x69, 0x33, 0x90, 0x00, 0x06, 0x00, 0xFF, 0x62, 0x63, 0x00, 0x00, 0x60, 0xFF, 0x5D, 0x88,
        0x00, 0x00, 0xC0, 0xFF, 0x69, 0x54, 0x00, 0x01, 0x80, 0xFF, 0x63, 0x96, 0x00, 0x00, 0xC0,
        0xFF, 0x6A, 0x28, 0x00, 0x01, 0x80, 0xFF, 0x64, 0xF0, 0x00, 0x01, 0x80, 0xFF, 0x6B, 0x14,
        0x00, 0x01, 0x80, 0xFF, 0x94, 0x46, 0x00, 0x00, 0xC0, 0xFF, 0xF9, 0x30, 0x00, 0x03, 0x00,
        0xFF, 0xF9, 0x8B, 0x80, 0x00, 0x30, 0xFF, 0xF3, 0x48, 0x00, 0x01, 0x80, 0xFF, 0xF8, 0xE1,
        0x00, 0x00, 0x30, 0xFF, 0xF2, 0xFA, 0x00, 0x00, 0x60, 0xFF, 0xFA, 0xCE, 0x00, 0x00, 0xC0,
        0xFF,
    ];

    #[test]
    fn decodes_real_text_stream() {
        let out = decode(QTM_TXT, 18, QTM_TXT_EXPECTED.len()).unwrap();
        assert_eq!(out, QTM_TXT_EXPECTED);
    }

    #[test]
    fn decodes_single_frame() {
        // First block (14 bytes) + sentinel = one 32 KiB frame of zeros.
        let out = decode(&CVE_2010_2801[..15], 18, 32_768).unwrap();
        assert_eq!(out.len(), 32_768);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn decodes_multi_frame() {
        let out = decode(CVE_2010_2801, 18, 524_159).unwrap();
        assert_eq!(out.len(), 524_159);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_bad_trailer() {
        let mut input = CVE_2010_2801.to_vec();
        input[14] = 0x42; // neither 0x00 padding nor 0xFF sentinel
        assert!(matches!(
            decode(&input, 18, 524_159),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn rejects_bad_window_bits() {
        assert!(decode(&[0; 16], 9, 1).is_err());
        assert!(decode(&[0; 16], 22, 1).is_err());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(decode(&[], 15, 1), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_truncated() {
        // Valid start (16-bit C init) but no packets for 4 output bytes.
        assert!(matches!(
            decode(&[0x00, 0x00], 15, 4),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn empty_expected_is_ok() {
        assert_eq!(decode(&[], 15, 0).unwrap(), Vec::<u8>::new());
    }
}
