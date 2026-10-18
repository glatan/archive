//! VCDIFF delta compression (RFC 3284).
//!
//! A VCDIFF stream encodes a target file as a sequence of windows, each of
//! which is described by ADD (literal), RUN (repeated byte), and COPY (match
//! into the source window or the already-produced target window)
//! instructions. COPY addresses may be coded absolutely (VCD_SELF),
//! relative to the current position (VCD_HERE), or against the near/same
//! address caches defined by the format.
//!
//! A window indicator of `VCD_TARGET` (RFC 3284 Section 4.2) selects the
//! window's source segment from the already-decoded target file rather than
//! from the caller-supplied source; address-space and COPY semantics are
//! identical to `VCD_SOURCE`.
//!
//! Intentional scope (matching the reference xdelta3 implementation, which
//! also leaves these unimplemented):
//!
//! - `VCD_CODETABLE` application-defined code tables are rejected; only the
//!   default code table (`s_near = 4`, `s_same = 3`) is supported.
//! - `VCD_DECOMPRESS` secondary compression of the data/instruction/address
//!   sections is rejected.
//! - `VCD_APPHEADER` (`0x04`, an xdelta3 extension carrying application
//!   metadata) is accepted and skipped for interoperability.
//!
//! Encoding always produces uncompressed-section, default-table streams
//! with single (non-paired) instructions only. [`encode`] and
//! [`encode_with_source`] emit one window per call (`VCD_SOURCE` when a
//! source is supplied); [`encode_with_windows`] splits the target into
//! multiple windows, using `VCD_TARGET` segments for all but the first.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

const MAGIC: [u8; 3] = [0xD6, 0xC3, 0xC4];

const VCD_DECOMPRESS: u8 = 0x01;
const VCD_CODETABLE: u8 = 0x02;
const VCD_APPHEADER: u8 = 0x04;

const VCD_SOURCE: u8 = 0x01;
const VCD_TARGET: u8 = 0x02;
/// xdelta3 extension: the window carries a big-endian Adler-32 checksum of
/// the decoded target window after the three section lengths.
const VCD_ADLER32: u8 = 0x04;

const I_NOOP: u8 = 0;
const I_ADD: u8 = 1;
const I_RUN: u8 = 2;
const I_COPY: u8 = 3;

const S_NEAR: usize = 4;
const S_SAME: usize = 3;
const N_MODES: usize = 2 + S_NEAR + S_SAME;

const MIN_MATCH: usize = 4;

/// One entry of the instruction code table: up to two instructions, each a
/// (type, size, mode) triple. A zero size means the size is coded separately
/// in the instructions stream.
#[derive(Clone, Copy)]
struct Entry {
    inst: [u8; 2],
    size: [u8; 2],
    mode: [u8; 2],
}

const NOOP_ENTRY: Entry = Entry {
    inst: [I_NOOP, I_NOOP],
    size: [0, 0],
    mode: [0, 0],
};

/// Build the default code table (RFC 3284 Section 5.6 depiction).
fn default_table() -> [Entry; 256] {
    let mut t = [NOOP_ENTRY; 256];

    // Line 1: RUN, size coded separately.
    t[0].inst[0] = I_RUN;

    // Line 2: ADD 0,[1,17] -> indices 1..=18.
    for (i, e) in t.iter_mut().enumerate().take(19).skip(1) {
        e.inst[0] = I_ADD;
        e.size[0] = if i == 1 { 0 } else { (i - 1) as u8 };
    }

    // Lines 3..=11: COPY 0,[4,18] with mode 0..=8.
    // 16 entries per mode: index 19+16*m is size 0, then sizes 4..=18.
    for m in 0..N_MODES {
        for s in 0..16usize {
            let e = &mut t[19 + 16 * m + s];
            e.inst[0] = I_COPY;
            e.size[0] = if s == 0 { 0 } else { (s + 3) as u8 };
            e.mode[0] = m as u8;
        }
    }

    // Lines 12..=17: ADD [1,4] + COPY [4,6], mode 0..=5.
    // 12 entries per mode starting at 163+12*m; outer loop is the ADD size.
    for m in 0..6usize {
        for a in 1..=4usize {
            for c in 0..3usize {
                let e = &mut t[163 + 12 * m + (a - 1) * 3 + c];
                e.inst = [I_ADD, I_COPY];
                e.size = [a as u8, (4 + c) as u8];
                e.mode[1] = m as u8;
            }
        }
    }

    // Lines 18..=20: ADD [1,4] + COPY 4, mode 6..=8.
    for m in 6..=8usize {
        for a in 1..=4usize {
            let e = &mut t[235 + (m - 6) * 4 + (a - 1)];
            e.inst = [I_ADD, I_COPY];
            e.size = [a as u8, 4];
            e.mode[1] = m as u8;
        }
    }

    // Line 21: COPY 4 with mode 0..=8, then ADD 1.
    for m in 0..N_MODES {
        let e = &mut t[247 + m];
        e.inst = [I_COPY, I_ADD];
        e.size = [4, 1];
        e.mode[0] = m as u8;
    }

    t
}

fn read_varint(input: &[u8], pos: &mut usize) -> Result<usize, Error> {
    let mut v: usize = 0;
    loop {
        let b = *input
            .get(*pos)
            .ok_or(Error::InvalidData("vcdiff: truncated varint"))?;
        *pos += 1;
        v = v
            .checked_shl(7)
            .and_then(|v| v.checked_add((b & 0x7F) as usize))
            .ok_or(Error::InvalidData("vcdiff: varint overflow"))?;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
}

fn write_varint(out: &mut Vec<u8>, mut v: usize) {
    let mut buf = [0u8; 10];
    let mut n = 0;
    loop {
        buf[n] = (v & 0x7F) as u8;
        v >>= 7;
        n += 1;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(buf[i] | if i == 0 { 0 } else { 0x80 });
    }
}

/// Address caches, initialized per target window (RFC 3284 Section 5.2).
struct Cache {
    near: [usize; S_NEAR],
    next_slot: usize,
    same: [usize; S_SAME * 256],
}

impl Cache {
    fn new() -> Self {
        Self {
            near: [0; S_NEAR],
            next_slot: 0,
            same: [0; S_SAME * 256],
        }
    }

    fn update(&mut self, addr: usize) {
        self.near[self.next_slot] = addr;
        self.next_slot = (self.next_slot + 1) % S_NEAR;
        self.same[addr % (S_SAME * 256)] = addr;
    }
}

struct WindowDecode<'a> {
    source: &'a [u8],
    data: &'a [u8],
    inst: &'a [u8],
    addr: &'a [u8],
    out: Vec<u8>,
    dpos: usize,
    ipos: usize,
    apos: usize,
    cache: Cache,
    /// Declared target length of this window; no instruction may push
    /// `out` past it.
    target_len: usize,
}

impl<'a> WindowDecode<'a> {
    fn exec(&mut self, inst_type: u8, size_code: u8, mode: u8) -> Result<(), Error> {
        if inst_type == I_NOOP {
            return Ok(());
        }
        let size = if size_code == 0 {
            read_varint(self.inst, &mut self.ipos)?
        } else {
            size_code as usize
        };
        // The window's target length is exact, so an instruction that
        // would grow the output past it is malformed. Reject before
        // writing anything: a huge coded size must not reach the
        // RUN resize or the COPY self-copy loop, which would otherwise
        // allocate/copy gigabytes even when `max_output` is usize::MAX.
        if size > self.target_len.saturating_sub(self.out.len()) {
            return Err(Error::InvalidData("vcdiff: instruction exceeds target"));
        }
        match inst_type {
            I_ADD => {
                let end = self
                    .dpos
                    .checked_add(size)
                    .ok_or(Error::InvalidData("vcdiff: ADD size overflow"))?;
                if end > self.data.len() {
                    return Err(Error::InvalidData("vcdiff: ADD out of data"));
                }
                self.out.extend_from_slice(&self.data[self.dpos..end]);
                self.dpos = end;
            }
            I_RUN => {
                let b = *self
                    .data
                    .get(self.dpos)
                    .ok_or(Error::InvalidData("vcdiff: RUN out of data"))?;
                self.dpos += 1;
                self.out.resize(self.out.len() + size, b);
            }
            I_COPY => {
                let here = self.source.len() + self.out.len();
                let a = match mode as usize {
                    0 => read_varint(self.addr, &mut self.apos)?,
                    1 => {
                        let d = read_varint(self.addr, &mut self.apos)?;
                        here.checked_sub(d)
                            .ok_or(Error::InvalidData("vcdiff: HERE underflow"))?
                    }
                    m if (2..2 + S_NEAR).contains(&m) => self.cache.near[m - 2]
                        .checked_add(read_varint(self.addr, &mut self.apos)?)
                        .ok_or(Error::InvalidData("vcdiff: near address overflow"))?,
                    m if (2 + S_NEAR..2 + S_NEAR + S_SAME).contains(&m) => {
                        let b = *self
                            .addr
                            .get(self.apos)
                            .ok_or(Error::InvalidData("vcdiff: truncated address"))?;
                        self.apos += 1;
                        self.cache.same[(m - 2 - S_NEAR) * 256 + b as usize]
                    }
                    _ => return Err(Error::InvalidData("vcdiff: bad address mode")),
                };
                self.cache.update(a);
                if a >= here {
                    return Err(Error::InvalidData("vcdiff: COPY out of range"));
                }
                // RFC 3284 section 3: the copied substring must be entirely
                // contained in either the source segment or the target
                // window; reject copies spanning the boundary.
                // (`size > len - a` instead of `a + size > len` so a huge
                // coded size cannot wrap the sum.)
                if a < self.source.len() && size > self.source.len() - a {
                    return Err(Error::InvalidData("vcdiff: COPY spans boundary"));
                }
                if a < self.source.len() {
                    self.out.extend_from_slice(&self.source[a..a + size]);
                } else {
                    let offset = here - a;
                    crate::compress::match_ops::copy_match(&mut self.out, offset, size)
                        .map_err(|_| Error::InvalidData("vcdiff: COPY out of range"))?;
                }
            }
            _ => return Err(Error::InvalidData("vcdiff: bad instruction")),
        }
        Ok(())
    }
}

/// Decode one window's "delta encoding" body (RFC 3284 Section 4.3):
/// target length, indicator, three section lengths, then the data,
/// instructions, and addresses sections.
fn decode_window(
    source: &[u8],
    enc: &[u8],
    table: &[Entry; 256],
    max_output: usize,
    checksum: Option<u32>,
) -> Result<Vec<u8>, Error> {
    let mut pos = 0usize;
    let target_len = read_varint(enc, &mut pos)?;
    if target_len > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    let indicator = *enc
        .get(pos)
        .ok_or(Error::InvalidData("vcdiff: truncated window"))?;
    pos += 1;
    if indicator != 0 {
        return Err(Error::Unsupported("vcdiff: secondary-compressed sections"));
    }
    let data_len = read_varint(enc, &mut pos)?;
    let inst_len = read_varint(enc, &mut pos)?;
    let addr_len = read_varint(enc, &mut pos)?;
    if checksum.is_some() {
        pos = pos
            .checked_add(4)
            .ok_or(Error::InvalidData("vcdiff: bad section lengths"))?;
    }
    let end = pos
        .checked_add(data_len)
        .and_then(|p| p.checked_add(inst_len))
        .and_then(|p| p.checked_add(addr_len))
        .ok_or(Error::InvalidData("vcdiff: bad section lengths"))?;
    if end != enc.len() {
        return Err(Error::InvalidData("vcdiff: bad section lengths"));
    }
    let data = &enc[pos..pos + data_len];
    let inst = &enc[pos + data_len..pos + data_len + inst_len];
    let addr = &enc[pos + data_len + inst_len..];

    let mut w = WindowDecode {
        source,
        data,
        inst,
        addr,
        out: Vec::with_capacity(target_len.min(1 << 20)),
        dpos: 0,
        ipos: 0,
        apos: 0,
        cache: Cache::new(),
        target_len,
    };

    while w.ipos < inst.len() {
        let e = &table[w.inst[w.ipos] as usize];
        w.ipos += 1;
        w.exec(e.inst[0], e.size[0], e.mode[0])?;
        w.exec(e.inst[1], e.size[1], e.mode[1])?;
        if w.out.len() > target_len {
            return Err(Error::InvalidData("vcdiff: window overflow"));
        }
    }
    if w.out.len() != target_len {
        return Err(Error::InvalidData("vcdiff: target length mismatch"));
    }
    if let Some(expected) = checksum {
        let actual = crate::util::adler32::adler32(&w.out);
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }
    Ok(w.out)
}

/// Decode a VCDIFF stream with an empty source.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_with_source(&[], input)
}

/// Decode a VCDIFF stream against `source`.
pub fn decode_with_source(source: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(source, input, usize::MAX)
}

/// Decode a VCDIFF stream against `source`, bounding total output size.
pub fn decode_bounded(source: &[u8], input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let table = default_table();
    if input.len() < 5 || input[..3] != MAGIC {
        return Err(Error::InvalidData("vcdiff: bad magic"));
    }
    // Header4 (input[3]) is currently always zero and is reserved for
    // future version numbers; the value is not validated.
    let hdr = input[4];
    let mut pos = 5usize;
    if hdr & !(VCD_DECOMPRESS | VCD_CODETABLE | VCD_APPHEADER) != 0 {
        return Err(Error::InvalidData("vcdiff: bad header flags"));
    }
    if hdr & VCD_DECOMPRESS != 0 {
        return Err(Error::Unsupported("vcdiff: secondary compressor"));
    }
    if hdr & VCD_CODETABLE != 0 {
        return Err(Error::Unsupported("vcdiff: custom code table"));
    }
    if hdr & VCD_APPHEADER != 0 {
        let len = read_varint(input, &mut pos)?;
        let end = pos
            .checked_add(len)
            .ok_or(Error::InvalidData("vcdiff: truncated appheader"))?;
        if end > input.len() {
            return Err(Error::InvalidData("vcdiff: truncated appheader"));
        }
        pos = end;
    }

    let mut out = Vec::new();
    while pos < input.len() {
        let win = input[pos];
        pos += 1;
        if win & !(VCD_SOURCE | VCD_TARGET | VCD_ADLER32) != 0
            || win & (VCD_SOURCE | VCD_TARGET) == VCD_SOURCE | VCD_TARGET
        {
            return Err(Error::InvalidData("vcdiff: bad window flags"));
        }
        let seg: &[u8] = if win & VCD_SOURCE != 0 {
            let size = read_varint(input, &mut pos)?;
            let sp = read_varint(input, &mut pos)?;
            let end = sp
                .checked_add(size)
                .ok_or(Error::InvalidData("vcdiff: source position overflow"))?;
            source
                .get(sp..end)
                .ok_or(Error::InvalidData("vcdiff: source out of range"))?
        } else if win & VCD_TARGET != 0 {
            // RFC 3284 Section 4.2: the source segment addresses
            // already-decoded target output instead of the caller-supplied
            // source. Address-space and COPY semantics are unchanged.
            let size = read_varint(input, &mut pos)?;
            let tp = read_varint(input, &mut pos)?;
            let end = tp
                .checked_add(size)
                .ok_or(Error::InvalidData("vcdiff: target position overflow"))?;
            out.get(tp..end)
                .ok_or(Error::InvalidData("vcdiff: target source out of range"))?
        } else {
            &[]
        };
        let delta_len = read_varint(input, &mut pos)?;
        let end = pos
            .checked_add(delta_len)
            .ok_or(Error::InvalidData("vcdiff: delta length overflow"))?;
        let enc = input
            .get(pos..end)
            .ok_or(Error::InvalidData("vcdiff: truncated window"))?;
        pos = end;
        // The checksum sits after the three section lengths; find it by
        // skipping the header integers of the delta body.
        let checksum = if win & VCD_ADLER32 != 0 {
            let mut p = 0usize;
            let _ = read_varint(enc, &mut p)?; // target length
            if p >= enc.len() {
                return Err(Error::InvalidData("vcdiff: truncated window"));
            }
            p += 1; // delta indicator
            let _ = read_varint(enc, &mut p)?;
            let _ = read_varint(enc, &mut p)?;
            let _ = read_varint(enc, &mut p)?;
            let end = p
                .checked_add(4)
                .ok_or(Error::InvalidData("vcdiff: truncated checksum"))?;
            let b = enc
                .get(p..end)
                .ok_or(Error::InvalidData("vcdiff: truncated checksum"))?;
            Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        } else {
            None
        };
        let window = decode_window(
            seg,
            enc,
            &table,
            max_output.saturating_sub(out.len()),
            checksum,
        )?;
        out.extend_from_slice(&window);
    }
    Ok(out)
}

struct Encoder<'a> {
    source: &'a [u8],
    data: Vec<u8>,
    inst: Vec<u8>,
    addr: Vec<u8>,
    cache: Cache,
    produced: usize,
}

impl<'a> Encoder<'a> {
    fn push_add(&mut self, lit: &[u8]) {
        if lit.is_empty() {
            return;
        }
        self.data.extend_from_slice(lit);
        self.produced += lit.len();
        if lit.len() <= 17 {
            self.inst.push((1 + lit.len()) as u8);
        } else {
            self.inst.push(1);
            write_varint(&mut self.inst, lit.len());
        }
    }

    fn push_run(&mut self, byte: u8, size: usize) {
        self.data.push(byte);
        self.produced += size;
        self.inst.push(0);
        write_varint(&mut self.inst, size);
    }

    fn push_copy(&mut self, addr: usize, size: usize) {
        let here = self.source.len() + self.produced;
        let (mode, coded) = self.encode_addr(addr, here);
        if (MIN_MATCH..=18).contains(&size) {
            self.inst.push((19 + 16 * mode + size - 3) as u8);
        } else {
            self.inst.push((19 + 16 * mode) as u8);
            write_varint(&mut self.inst, size);
        }
        if mode >= 2 + S_NEAR {
            self.addr.push(coded as u8);
        } else {
            write_varint(&mut self.addr, coded);
        }
        self.produced += size;
    }

    /// Pick the smallest coded address per RFC 3284 Section 5.4
    /// `addr_encode`, then update the caches.
    fn encode_addr(&mut self, addr: usize, here: usize) -> (usize, usize) {
        let mut bestd = addr;
        let mut bestm = 0usize;
        if here - addr < bestd {
            bestd = here - addr;
            bestm = 1;
        }
        for (i, &n) in self.cache.near.iter().enumerate() {
            if addr >= n && addr - n < bestd {
                bestd = addr - n;
                bestm = i + 2;
            }
        }
        let d = addr % (S_SAME * 256);
        if self.cache.same[d] == addr {
            bestd = d % 256;
            bestm = S_NEAR + 2 + d / 256;
        }
        self.cache.update(addr);
        (bestm, bestd)
    }
}

/// Encode one window's delta-encoding body (RFC 3284 Section 4.3): match
/// `window_target` against the `seg ++ produced-target` virtual address
/// space and return `target length | Delta_Indicator | section lengths |
/// data | instructions | addresses`.
fn encode_window_body(seg: &[u8], window_target: &[u8]) -> Vec<u8> {
    let src_len = seg.len();
    let mut head = vec![-1i32; 1 << 16];
    let hash = |b: &[u8]| -> usize {
        let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (v.wrapping_mul(0x9E37_79B1) >> 16) as usize
    };
    // Index the whole source segment up front (source addresses always
    // precede the target window).
    for p in 0..src_len.saturating_sub(MIN_MATCH - 1) {
        head[hash(&seg[p..])] = p as i32;
    }

    let mut e = Encoder {
        source: seg,
        data: Vec::new(),
        inst: Vec::new(),
        addr: Vec::new(),
        cache: Cache::new(),
        produced: 0,
    };

    let mut lit_start = 0usize;
    let mut t = 0usize;
    while t < window_target.len() {
        // Detect a run of a repeated byte first.
        let mut run = 1usize;
        while t + run < window_target.len() && window_target[t + run] == window_target[t] {
            run += 1;
        }
        if run >= MIN_MATCH {
            e.push_add(&window_target[lit_start..t]);
            e.push_run(window_target[t], run);
            t += run;
            lit_start = t;
            continue;
        }

        // Find a match of at least MIN_MATCH bytes. Match addresses index
        // into the source ++ produced-target virtual space, so only
        // positions strictly before src_len + t are legal.
        let abs = src_len + t;
        let mut best: Option<(usize, usize)> = None;
        if t + MIN_MATCH <= window_target.len() {
            let cand = head[hash(&window_target[t..])];
            head[hash(&window_target[t..])] = abs as i32;
            if cand >= 0 {
                let c = cand as usize;
                debug_assert!(c < abs);
                let mut len = crate::compress::match_ops::match_len_window(
                    seg,
                    window_target,
                    c,
                    src_len + t,
                    window_target.len() - t,
                );
                // RFC 3284 Section 3: a COPY must be entirely contained in
                // either the source segment or the target window, so a
                // match starting in the source may not cross the S/T
                // boundary.
                if c < src_len {
                    len = len.min(src_len - c);
                }
                if len >= MIN_MATCH {
                    best = Some((c, len));
                }
            }
        }

        if let Some((c, len)) = best {
            e.push_add(&window_target[lit_start..t]);
            e.push_copy(c, len);
            // Index produced positions inside the match for later matches.
            for p in t..t + len {
                if p + MIN_MATCH <= window_target.len() {
                    head[hash(&window_target[p..])] = (src_len + p) as i32;
                }
            }
            t += len;
            lit_start = t;
        } else {
            t += 1;
        }
    }
    e.push_add(&window_target[lit_start..]);

    // Assemble the window's delta encoding.
    let mut enc = Vec::new();
    write_varint(&mut enc, window_target.len());
    enc.push(0); // Delta_Indicator: uncompressed sections
    write_varint(&mut enc, e.data.len());
    write_varint(&mut enc, e.inst.len());
    write_varint(&mut enc, e.addr.len());
    enc.extend_from_slice(&e.data);
    enc.extend_from_slice(&e.inst);
    enc.extend_from_slice(&e.addr);
    enc
}

/// Append one window to `out`: Win_Indicator, the optional source segment
/// (size, position), and the delta-encoding body.
fn push_window(out: &mut Vec<u8>, win_ind: u8, seg: Option<(usize, usize)>, enc: &[u8]) {
    out.push(win_ind);
    if let Some((size, pos)) = seg {
        write_varint(out, size);
        write_varint(out, pos);
    }
    write_varint(out, enc.len());
    out.extend_from_slice(enc);
}

/// Encode `target` as a VCDIFF delta against `source`, emitting at most
/// `window_len` target bytes per window.
///
/// The first window uses `VCD_SOURCE` against `source` (or no source
/// segment when `source` is empty). Each subsequent window uses
/// `VCD_TARGET` (RFC 3284 Section 4.2) with its source segment set to the
/// previously emitted window's target bytes, so matches may copy from the
/// immediately preceding target region as well as from within the window
/// itself. A `window_len` of 0 (or one covering the whole target)
/// produces a single-window stream identical to [`encode_with_source`].
pub fn encode_with_windows(source: &[u8], target: &[u8], window_len: usize) -> Vec<u8> {
    let wl = if window_len == 0 {
        usize::MAX
    } else {
        window_len
    };
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.push(0); // Header4: version 0
    out.push(0); // Hdr_Indicator: no optional fields

    let mut pos = 0usize;
    let mut prev_start = 0usize;
    loop {
        let end = pos.saturating_add(wl).min(target.len());
        if pos == 0 {
            let enc = encode_window_body(source, &target[..end]);
            if source.is_empty() {
                push_window(&mut out, 0, None, &enc);
            } else {
                push_window(&mut out, VCD_SOURCE, Some((source.len(), 0)), &enc);
            }
        } else {
            // The source segment is the previously emitted window's
            // target bytes: it always lies within already-produced
            // output, as the decoder requires for VCD_TARGET.
            let seg = &target[prev_start..pos];
            let enc = encode_window_body(seg, &target[pos..end]);
            push_window(&mut out, VCD_TARGET, Some((seg.len(), prev_start)), &enc);
        }
        prev_start = pos;
        pos = end;
        if pos >= target.len() {
            break;
        }
    }
    out
}

/// Encode `target` as a VCDIFF delta against `source`.
///
/// Produces a single-window stream using the default code table with no
/// secondary compression.
pub fn encode_with_source(source: &[u8], target: &[u8]) -> Vec<u8> {
    encode_with_windows(source, target, usize::MAX)
}

/// Encode `target` as a standalone VCDIFF stream (empty source).
pub fn encode(target: &[u8]) -> Vec<u8> {
    encode_with_source(&[], target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(src: &[u8], tgt: &[u8]) {
        let d = encode_with_source(src, tgt);
        assert_eq!(decode_with_source(src, &d).unwrap(), tgt);
    }

    #[test]
    fn roundtrip_no_source() {
        rt(b"", b"hello world, hello vcdiff!");
        rt(b"", &[0u8; 64]);
        rt(b"", &[]);
    }

    #[test]
    fn roundtrip_with_source() {
        rt(
            b"The quick brown fox jumps over the lazy dog",
            b"The quick brown fox leaps over the lazy dog!!",
        );
        rt(b"aaaaaaaaaaaaaaaaaaaa", b"aaaa bbbb aaaa cccc aaaaaaaa");
    }

    #[test]
    fn roundtrip_self_copy() {
        // Match into already-produced target (overlap, period 3).
        rt(b"", b"abcabcabcabcabcabcabcabc");
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(decode(b"not a delta"), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_truncated() {
        let d = encode(b"some data to truncate");
        for cut in 0..d.len() {
            let _ = decode(&d[..cut]); // must not panic
        }
        assert!(decode(&d[..d.len() - 1]).is_err());
    }

    #[test]
    fn rejects_unsupported_flags() {
        let mut d = encode(b"x");
        // VCD_DECOMPRESS
        d[4] = 1;
        assert!(matches!(decode(&d), Err(Error::Unsupported(_))));
        // VCD_CODETABLE
        d[4] = 2;
        assert!(matches!(decode(&d), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_copy_out_of_range() {
        // COPY addr beyond produced data.
        let mut d = encode(b"abc");
        // locate window, flip inst section to COPY self addr 99:
        // easier: craft by hand
        let _ = &mut d;
        // header(5) win_ind(1) delta_len(1): window enc =
        //   target_len(1) ind(1) dl(1) il(1) al(1) data inst addr
        let enc: &[u8] = &[
            4, // target_len
            0, // indicator
            0, // data len
            2, // inst len
            1, // addr len
            20, 4,  // COPY mode0 size4
            99, // addr
        ];
        let mut d2 = Vec::new();
        d2.extend_from_slice(&[0xD6, 0xC3, 0xC4, 0, 0, 0, enc.len() as u8]);
        d2.extend_from_slice(enc);
        assert!(matches!(decode(&d2), Err(Error::InvalidData(_))));
    }

    #[test]
    fn appheader_skipped() {
        let mut d = encode(b"payload!");
        // insert appheader flag + len + data
        d[4] = VCD_APPHEADER;
        let mut d2 = Vec::new();
        d2.extend_from_slice(&d[..5]);
        d2.push(3);
        d2.extend_from_slice(b"xyz");
        d2.extend_from_slice(&d[5..]);
        assert_eq!(decode(&d2).unwrap(), b"payload!");
    }

    #[test]
    fn bounded_decode() {
        let d = encode(b"0123456789abcdef");
        assert_eq!(decode_bounded(&[], &d, 16).unwrap(), b"0123456789abcdef");
        assert!(matches!(
            decode_bounded(&[], &d, 8),
            Err(Error::OutputLimitExceeded { .. })
        ));
    }

    /// Assemble a stream from a header and raw window bytes.
    fn stream(windows: &[u8]) -> Vec<u8> {
        let mut d = Vec::from(&[0xD6, 0xC3, 0xC4, 0, 0]);
        d.extend_from_slice(windows);
        d
    }

    #[test]
    fn multi_window() {
        // Concatenate the window portions of two one-window streams.
        let d1 = encode(b"first ");
        let d2 = encode(b"second");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        w.extend_from_slice(&d2[5..]);
        assert_eq!(decode(&stream(&w)).unwrap(), b"first second");
    }

    /// Assemble a window: indicator, optional source segment (size,
    /// position), then the delta body length and body.
    fn window(win_ind: u8, seg: Option<(usize, usize)>, enc: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        w.push(win_ind);
        if let Some((size, pos)) = seg {
            write_varint(&mut w, size);
            write_varint(&mut w, pos);
        }
        write_varint(&mut w, enc.len());
        w.extend_from_slice(enc);
        w
    }

    #[test]
    fn vcd_target_window() {
        // RFC 3284 Section 4.2: window 2 takes its source segment from the
        // already-decoded target output of window 1.
        let d1 = encode(b"abcdefgh");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        let enc: &[u8] = &[
            8, // target_len
            0, // delta indicator
            0, 2, 1, // data / inst / addr lengths
            19, 8, // COPY mode 0, size coded separately = 8
            0, // addr = source[0]
        ];
        w.extend_from_slice(&window(VCD_TARGET, Some((8, 0)), enc));
        assert_eq!(decode(&stream(&w)).unwrap(), b"abcdefghabcdefgh");
    }

    #[test]
    fn vcd_target_segment_offset() {
        // The target source segment may start at a nonzero position.
        let d1 = encode(b"abcdef");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        let enc: &[u8] = &[
            3, // target_len
            0, // delta indicator
            0, 2, 1, // data / inst / addr lengths
            19, 3, // COPY mode 0, size coded separately = 3
            0, // addr = source[0] -> "cde"
        ];
        w.extend_from_slice(&window(VCD_TARGET, Some((3, 2)), enc));
        assert_eq!(decode(&stream(&w)).unwrap(), b"abcdefcde");
    }

    #[test]
    fn vcd_target_self_copy_overlap() {
        // Within a VCD_TARGET window, a COPY may still reference the
        // window's own output with overlap (legal per RFC 3284).
        let d1 = encode(b"ab");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        let enc: &[u8] = &[
            5, // target_len = 1 ADD + 4 COPY
            0, // delta indicator
            1, 1, 1,    // data / inst / addr lengths
            b'x', // data
            163,  // combined entry: ADD 1 + COPY 4 mode 0
            2,    // addr = source_len -> target[0], overlaps itself
        ];
        w.extend_from_slice(&window(VCD_TARGET, Some((2, 0)), enc));
        assert_eq!(decode(&stream(&w)).unwrap(), b"abxxxxx");
    }

    #[test]
    fn rejects_target_source_out_of_range() {
        // The VCD_TARGET segment must lie within already-decoded output.
        let d1 = encode(b"ab");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        let enc: &[u8] = &[1, 0, 1, 1, 0, b'z', 2];
        w.extend_from_slice(&window(VCD_TARGET, Some((8, 0)), enc));
        assert!(matches!(decode(&stream(&w)), Err(Error::InvalidData(_))));

        // A leading VCD_TARGET window has no prior output to draw from.
        let w2 = window(VCD_TARGET, Some((1, 0)), enc);
        assert!(matches!(decode(&stream(&w2)), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_target_copy_spanning_boundary() {
        // The same source/target boundary rule as VCD_SOURCE applies.
        let d1 = encode(b"abc");
        let mut w = Vec::new();
        w.extend_from_slice(&d1[5..]);
        let enc: &[u8] = &[
            4, // target_len
            0, // delta indicator
            0, 1, 1,  // data / inst / addr lengths
            20, // COPY mode 0 size 4
            1,  // addr 1: spans source end (3) / target start
        ];
        w.extend_from_slice(&window(VCD_TARGET, Some((3, 0)), enc));
        assert!(matches!(decode(&stream(&w)), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_source_and_target_both_set() {
        let mut d = encode(b"x");
        d[5] = VCD_SOURCE | VCD_TARGET;
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_reserved_header_bits() {
        let mut d = encode(b"x");
        d[4] = 0x80;
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_section_length_mismatch() {
        // Window claiming a data section longer than the delta body.
        let enc: &[u8] = &[4, 0, 99, 1, 0, 0];
        let mut d = stream(&[]);
        d.push(0);
        write_varint(&mut d, enc.len());
        d.extend_from_slice(enc);
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_copy_spanning_source_boundary() {
        // COPY addr 1 size 4 against a 3-byte source: spans S/T boundary.
        let enc: &[u8] = &[
            4, // target_len
            0, // indicator
            0, // data len
            2, // inst len
            1, // addr len
            20, 4, // COPY mode0 size4
            1, // addr 1
        ];
        let mut d = stream(&[]);
        d.push(VCD_SOURCE);
        d.push(3); // source segment size
        d.push(0); // source position
        write_varint(&mut d, enc.len());
        d.extend_from_slice(enc);
        assert!(matches!(
            decode_with_source(b"abc", &d),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn rejects_target_length_mismatch() {
        // Declared target_len 8 but instructions only produce 4 bytes.
        let enc: &[u8] = &[
            8, // target_len
            0, // indicator
            4, // data len
            1, // inst len
            0, // addr len
            b'a', b'b', b'c', b'd', // data
            5,    // ADD size4
        ];
        let mut d = stream(&[]);
        d.push(0);
        write_varint(&mut d, enc.len());
        d.extend_from_slice(enc);
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
    }

    /// Collect the Win_Indicator byte of every window in a stream.
    fn window_indicators(d: &[u8]) -> Vec<u8> {
        let mut inds = Vec::new();
        let mut pos = 5; // skip magic + Header4 + Hdr_Indicator
        while pos < d.len() {
            let win = d[pos];
            pos += 1;
            inds.push(win);
            if win & (VCD_SOURCE | VCD_TARGET) != 0 {
                let _ = read_varint(d, &mut pos).unwrap();
                let _ = read_varint(d, &mut pos).unwrap();
            }
            let delta_len = read_varint(d, &mut pos).unwrap();
            pos += delta_len;
        }
        inds
    }

    #[test]
    fn multi_window_encode_roundtrip() {
        // Target longer than one window with content repeated across
        // window boundaries; VCD_TARGET windows COPY from prior target.
        let mut tgt = Vec::new();
        for i in 0..8usize {
            tgt.extend_from_slice(b"chunk ");
            tgt.push(b'0' + i as u8);
            tgt.extend_from_slice(b": the quick brown fox jumps. ");
        }
        let d = encode_with_windows(b"", &tgt, 64);
        assert_eq!(decode(&d).unwrap(), tgt);
        let inds = window_indicators(&d);
        assert!(inds.len() > 1);
        assert_eq!(inds[0], 0); // no source supplied
        assert!(inds[1..].iter().all(|&w| w == VCD_TARGET));
        // Repetition is encoded as COPYs, not literals.
        assert!(d.len() < tgt.len() / 2);
    }

    #[test]
    fn multi_window_encode_with_source_roundtrip() {
        let src = b"the quick brown fox jumps over the lazy dog";
        let mut tgt = Vec::new();
        tgt.extend_from_slice(b"the quick brown fox leaps. ");
        for i in 0..6usize {
            tgt.extend_from_slice(b"again ");
            tgt.push(b'0' + i as u8);
            tgt.extend_from_slice(b" the quick brown fox jumps. ");
        }
        let d = encode_with_windows(src, &tgt, 48);
        assert_eq!(decode_with_source(src, &d).unwrap(), tgt);
        let inds = window_indicators(&d);
        assert_eq!(inds[0], VCD_SOURCE);
        assert!(inds[1..].iter().all(|&w| w == VCD_TARGET));
    }

    #[test]
    fn multi_window_encode_self_repeating() {
        // Long runs and periodic copies inside VCD_TARGET windows.
        let mut tgt = vec![b'x'; 100];
        tgt.extend_from_slice(b"abcdefgh");
        tgt.extend_from_slice(b"abcdefgh");
        let d = encode_with_windows(b"", &tgt, 16);
        assert_eq!(decode(&d).unwrap(), tgt);
        assert!(window_indicators(&d).contains(&VCD_TARGET));
    }

    #[test]
    fn multi_window_encode_zero_window_len() {
        // window_len 0 is clamped to "do not split": a single window.
        let d = encode_with_windows(b"", b"hello", 0);
        assert_eq!(decode(&d).unwrap(), b"hello");
        assert_eq!(window_indicators(&d).len(), 1);
        // Same for a window covering the whole target.
        let d = encode_with_windows(b"src", b"hello", usize::MAX);
        assert_eq!(decode_with_source(b"src", &d).unwrap(), b"hello");
        assert_eq!(window_indicators(&d), &[VCD_SOURCE]);
    }

    #[test]
    fn multi_window_encode_edge_cases() {
        // Empty target still emits one (empty) window.
        let d = encode_with_windows(b"", b"", 8);
        assert_eq!(decode(&d).unwrap(), b"");
        assert_eq!(window_indicators(&d).len(), 1);
        // One byte per window.
        let d = encode_with_windows(b"", b"ab", 1);
        assert_eq!(decode(&d).unwrap(), b"ab");
        assert_eq!(window_indicators(&d).len(), 2);
    }

    #[test]
    fn vcdiff_rejects_oversized_copy_size() {
        // Regression (fuzz run-1791310069 hang): a COPY whose coded
        // size is ~5.9 GiB must be rejected against the window's
        // declared target length before the self-copy loop runs, not
        // after gigabytes of output accumulate.
        let enc: &[u8] = &[
            2, // target_len
            0, // delta indicator
            1, 7, 1,    // data / inst / addr lengths
            b'x', // data
            2,    // ADD size 1 -> out = "x"
            19,   // COPY mode 0, size coded separately
            0xFF, 0xFF, 0xFF, 0xFF, 0x15, // size varint: 0x15FF_FFFFF
            0,    // addr 0 -> target[0] (self-copy)
        ];
        let mut d = stream(&[]);
        d.push(0); // Win_Indicator: no source
        write_varint(&mut d, enc.len());
        d.extend_from_slice(enc);
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
        // decode_with_source shares the same window decoder.
        assert!(matches!(
            decode_with_source(b"src", &d),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn vcdiff_rejects_oversized_run_size() {
        // Same oversized-size rejection for RUN, before `out` is
        // resized by the coded count.
        let enc: &[u8] = &[
            1, // target_len
            0, // delta indicator
            1, 6, 0,    // data / inst / addr lengths
            b'x', // data (RUN byte)
            0,    // RUN, size coded separately
            0xFF, 0xFF, 0xFF, 0xFF, 0x15, // size varint: 0x15FF_FFFFF
        ];
        let mut d = stream(&[]);
        d.push(0); // Win_Indicator: no source
        write_varint(&mut d, enc.len());
        d.extend_from_slice(enc);
        assert!(matches!(decode(&d), Err(Error::InvalidData(_))));
    }
}
