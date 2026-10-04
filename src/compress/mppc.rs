//! MPPC (Microsoft Point-to-Point Compression, RFC 2118) and the RDP
//! bulk-compression variants ([MS-RDPBCGR] section 3.1.8.4).
//!
//! MPPC is an LZ77 variant with a history buffer, designed for compressing
//! packets one at a time while carrying history state across packets.
//!
//! # RFC 2118 packets ([`Decoder`], [`Encoder`], [`encode`], [`decode`])
//!
//! The RFC 2118 form uses an 8192-byte history. Each packet carries a
//! flags nibble and a 12-bit coherency count (RFC 2118 section 3.1):
//!
//! ```text
//! |A|B|C|D|   Coherency Count (12 bits)   | Compressed Data ...
//! ```
//!
//! - `A` (FLUSHED, `0x8`): history was just initialized to zeroes.
//! - `B` (FRONT, `0x4`): the sender wrapped its history write pointer back
//!   to the front of the buffer.
//! - `C` (COMPRESSED, `0x2`): the data is an LZ token stream; otherwise it
//!   is uncompressed data (which does not update the history — the sender
//!   must flush it and restart with FLUSHED; the RDP variant differs, see
//!   below).
//! - `D` (`0x1`): reserved, must be zero.
//!
//! The token stream is packed MSB-first (RFC 2118 section 4.2):
//!
//! - literal `< 0x80`: the byte itself; literal `>= 0x80`: `10` + 7 bits.
//! - copy offset: `<64` -> `1111` + 6 bits, `64..=319` -> `1110` + 8 bits of
//!   (value - 64), `320..=8191` -> `110` + 13 bits of (value - 320).
//! - match length `3`: `0`; longer lengths are `k` leading ones + `0` +
//!   `k+1` low bits, up to `8191`.
//!
//! Packets carry no length field: a byte string is exactly one packet, and
//! packet boundaries in a real PPP stream come from the link layer. The
//! PPP encapsulation (protocol `0x00FD`, CCP negotiation, Reset-Request
//! handling) is out of scope.
//!
//! # RDP bulk compression ([`RdpDecoder`], [`RdpEncoder`], [`decode_rdp`])
//!
//! [MS-RDPBCGR] section 3.1.8.4 uses MPPC without the RFC 2118 packet
//! header: flags live out-of-band in the `compressedType` byte of the
//! Share Data Header — [`PACKET_COMPRESSED`], [`PACKET_AT_FRONT`],
//! [`PACKET_FLUSHED`] plus a low-nibble CompressionType
//! ([`COMPRESSION_TYPE_MASK`]). Two dictionary variants exist:
//!
//! - [`CompressionType::Rdp4`] (`0x00`, "RDP 4.0", section 3.1.8.4.1):
//!   8 KiB history with the RFC 2118 token tables.
//! - [`CompressionType::Rdp5`] (`0x01`, "RDP 5.0", section 3.1.8.4.2):
//!   64 KiB history with relocated Huffman tables — copy offsets are
//!   `<64` -> `11111` + 6 bits, `64..=319` -> `11110` + 8 bits,
//!   `320..=2367` -> `1110` + 11 bits, `2368..=65535` -> `110` + 16 bits;
//!   match lengths extend the same `k` ones + `0` + `k+1` low bits scheme
//!   up to `k = 14` (`65535`).
//!
//! Unlike RFC 2118, uncompressed RDP packets still feed the history
//! buffer (the sender is required to insert them). The RDP 6.0/6.1 bulk
//! codecs (CompressionType `0x02`/`0x03`, [MS-RDPEGDI]) are a different
//! algorithm and are rejected.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;

/// MPPC history buffer size (RFC 2118 section 2; RDP 4.0).
pub const HISTORY_SIZE: usize = 8192;

/// MPPC history buffer size for the RDP 5.0 ("64K") variant
/// ([MS-RDPBCGR] section 3.1.8.4.2).
pub const HISTORY_SIZE_64K: usize = 65536;

const FLAG_FLUSHED: u8 = 0x8;
const FLAG_FRONT: u8 = 0x4;
const FLAG_COMPRESSED: u8 = 0x2;
const FLAG_RESERVED: u8 = 0x1;

/// RDP `compressedType` flag: the packet payload is an LZ token stream.
pub const PACKET_COMPRESSED: u8 = 0x20;
/// RDP `compressedType` flag: history position restarts at the front.
pub const PACKET_AT_FRONT: u8 = 0x40;
/// RDP `compressedType` flag: the history buffer was reinitialized
/// (zero-filled); the receiver must do the same.
pub const PACKET_FLUSHED: u8 = 0x80;
/// Mask for the CompressionType field of the RDP `compressedType` byte.
pub const COMPRESSION_TYPE_MASK: u8 = 0x0F;
/// Unused high-nibble bit of the RDP `compressedType` byte.
const RDP_FLAG_RESERVED: u8 = 0x10;

const MIN_MATCH: usize = 3;

/// MPPC dictionary variant: selects the history size and the copy-offset
/// / match-length Huffman tables.
///
/// The numeric value is the RDP CompressionType wire code used in the low
/// nibble of the `compressedType` byte ([MS-RDPBCGR] section 3.1.8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    /// RDP 4.0 / RFC 2118: 8192-byte history, `1111`/`1110`/`110` offset
    /// classes, match lengths up to 8191 (wire code `0x00`).
    Rdp4,
    /// RDP 5.0 "64K": 65536-byte history, `11111`/`11110`/`1110`/`110`
    /// offset classes, match lengths up to 65535 (wire code `0x01`).
    Rdp5,
}

impl CompressionType {
    fn history_size(self) -> usize {
        match self {
            Self::Rdp4 => HISTORY_SIZE,
            Self::Rdp5 => HISTORY_SIZE_64K,
        }
    }

    fn max_match(self) -> usize {
        match self {
            Self::Rdp4 => 8191,
            Self::Rdp5 => 65535,
        }
    }

    fn max_offset(self) -> usize {
        match self {
            Self::Rdp4 => 8191,
            Self::Rdp5 => 65535,
        }
    }

    /// Maximum leading-one count `k` of the match-length prefix.
    fn max_len_ones(self) -> u32 {
        match self {
            Self::Rdp4 => 11,
            Self::Rdp5 => 14,
        }
    }

    fn wire_code(self) -> u8 {
        match self {
            Self::Rdp4 => 0x00,
            Self::Rdp5 => 0x01,
        }
    }

    fn from_wire(code: u8) -> Result<Self, Error> {
        match code {
            0x00 => Ok(Self::Rdp4),
            0x01 => Ok(Self::Rdp5),
            _ => Err(Error::InvalidData(
                "mppc: unsupported RDP compression type (RDP6/RDP6.1 are a different codec)",
            )),
        }
    }
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u8,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit: 0,
        }
    }

    fn get(&mut self) -> Result<u32, Error> {
        if self.pos >= self.data.len() {
            return Err(Error::InvalidData("mppc: truncated bitstream"));
        }
        let b = (self.data[self.pos] >> (7 - self.bit)) & 1;
        self.bit += 1;
        if self.bit == 8 {
            self.bit = 0;
            self.pos += 1;
        }
        Ok(b as u32)
    }

    fn get_bits(&mut self, n: u32) -> Result<u32, Error> {
        let mut v = 0;
        for _ in 0..n {
            v = (v << 1) | self.get()?;
        }
        Ok(v)
    }

    /// True when no more token bits remain. Zero bits trailing in the last
    /// byte are padding from the encoder and are ignored; a full trailing
    /// byte is always token data (a `0x00` byte is a literal NUL).
    fn at_end(&self) -> bool {
        if self.pos >= self.data.len() {
            return true;
        }
        self.pos == self.data.len() - 1 && self.bit != 0 && (self.data[self.pos] << self.bit) == 0
    }
}

struct BitWriter {
    out: Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            out: Vec::new(),
            acc: 0,
            nbits: 0,
        }
    }

    fn put(&mut self, bits: u32, n: u32) {
        debug_assert!(n < 32 && bits < (1 << n));
        self.acc = (self.acc << n) | bits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.nbits -= 8;
            self.out.push((self.acc >> self.nbits) as u8);
        }
        self.acc &= (1 << self.nbits) - 1;
    }

    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out.push((self.acc << (8 - self.nbits)) as u8);
        }
        self.out
    }
}

fn put_literal(w: &mut BitWriter, b: u8) {
    if b < 0x80 {
        w.put(b as u32, 8);
    } else {
        w.put(2, 2); // '10'
        w.put((b & 0x7F) as u32, 7);
    }
}

/// Append `data` to the history ring at `pos` (uncompressed packet path
/// and the encoder's bookkeeping).
fn append_history(hist: &mut [u8], pos: &mut usize, data: &[u8]) -> Result<(), Error> {
    if data.len() > hist.len() - *pos {
        // A conformant sender sets AT_FRONT/FLUSHED before overflowing
        // the buffer; treat overflow as malformed input.
        return Err(Error::InvalidData("mppc: history overflow"));
    }
    hist[*pos..*pos + data.len()].copy_from_slice(data);
    *pos += data.len();
    Ok(())
}

/// Push one output byte, recording it in the history buffer.
fn emit(
    hist: &mut [u8],
    pos: &mut usize,
    out: &mut Vec<u8>,
    b: u8,
    max_output: usize,
) -> Result<(), Error> {
    if out.len() >= max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    if *pos >= hist.len() {
        // A conformant sender sets AT_FRONT/FLUSHED before overflowing
        // the buffer; treat mid-packet overflow as malformed input.
        return Err(Error::InvalidData("mppc: history overflow"));
    }
    hist[*pos] = b;
    *pos += 1;
    out.push(b);
    Ok(())
}

fn put_offset(w: &mut BitWriter, ty: CompressionType, off: usize) {
    debug_assert!((1..=ty.max_offset()).contains(&off));
    match ty {
        CompressionType::Rdp4 => {
            if off < 64 {
                w.put(0xF, 4); // '1111'
                w.put(off as u32, 6);
            } else if off < 320 {
                w.put(0xE, 4); // '1110'
                w.put((off - 64) as u32, 8);
            } else {
                w.put(6, 3); // '110'
                w.put((off - 320) as u32, 13);
            }
        }
        CompressionType::Rdp5 => {
            // [MS-RDPBCGR] 3.1.8.4.2: one extra level relocates the
            // two smallest classes, and the top class widens to 16 bits.
            if off < 64 {
                w.put(0x1F, 5); // '11111'
                w.put(off as u32, 6);
            } else if off < 320 {
                w.put(0x1E, 5); // '11110'
                w.put((off - 64) as u32, 8);
            } else if off < 2368 {
                w.put(0xE, 4); // '1110'
                w.put((off - 320) as u32, 11);
            } else {
                w.put(6, 3); // '110'
                w.put((off - 2368) as u32, 16);
            }
        }
    }
}

fn put_length(w: &mut BitWriter, ty: CompressionType, len: usize) {
    debug_assert!((MIN_MATCH..=ty.max_match()).contains(&len));
    if len == 3 {
        w.put(0, 1);
        return;
    }
    // len >= 4: k leading ones + '0' + (k+1) low bits, where 2^(k+1) <=
    // len <= 2^(k+2)-1 (RFC 2118 section 4.2.2).
    let k = 31 - (len as u32).leading_zeros() - 1;
    w.put((1 << (k + 1)) - 2, k + 1); // k ones followed by a '0'
    w.put(len as u32 & ((1 << (k + 1)) - 1), k + 1);
}

/// Decode one packet's compressed token stream into `out`, emitting every
/// produced byte through `hist`/`pos`.
fn decode_tokens(
    ty: CompressionType,
    hist: &mut [u8],
    pos: &mut usize,
    data: &[u8],
    max_output: usize,
) -> Result<Vec<u8>, Error> {
    let mask = hist.len() - 1;
    let mut out = Vec::new();
    let mut bits = Bits::new(data);
    while !bits.at_end() {
        if bits.get()? == 0 {
            let b = bits.get_bits(7)? as u8;
            emit(hist, pos, &mut out, b, max_output)?;
            continue;
        }
        if bits.get()? == 0 {
            // '10' + 7 bits: literal >= 0x80.
            let b = (bits.get_bits(7)? | 0x80) as u8;
            emit(hist, pos, &mut out, b, max_output)?;
            continue;
        }
        // Copy token: leading bits '11', then the offset prefix
        // (RFC 2118 section 4.2.1 / [MS-RDPBCGR] 3.1.8.4.1, 3.1.8.4.2).
        let off = match ty {
            CompressionType::Rdp4 => {
                if bits.get()? == 1 {
                    if bits.get()? == 1 {
                        bits.get_bits(6)? as usize // '1111' + 6 bits: 1..=63
                    } else {
                        bits.get_bits(8)? as usize + 64 // '1110' + 8 bits: 64..=319
                    }
                } else {
                    bits.get_bits(13)? as usize + 320 // '110' + 13 bits: 320..=8191
                }
            }
            CompressionType::Rdp5 => {
                if bits.get()? == 1 {
                    if bits.get()? == 1 {
                        if bits.get()? == 1 {
                            bits.get_bits(6)? as usize // '11111' + 6 bits: 1..=63
                        } else {
                            bits.get_bits(8)? as usize + 64 // '11110' + 8 bits: 64..=319
                        }
                    } else {
                        bits.get_bits(11)? as usize + 320 // '1110' + 11 bits: 320..=2367
                    }
                } else {
                    bits.get_bits(16)? as usize + 2368 // '110' + 16 bits: 2368..=65535
                }
            }
        };
        // Match length: k leading ones + '0', then k+1 low bits; '0'
        // alone encodes 3 (RFC 2118 section 4.2.2). RDP 5.0 extends the
        // same scheme to k = 14 (length 65535).
        let mut k = 0u32;
        while bits.get()? == 1 {
            k += 1;
            if k > ty.max_len_ones() {
                return Err(Error::InvalidData("mppc: bad match length"));
            }
        }
        let len = if k == 0 {
            MIN_MATCH
        } else {
            (1 << (k + 1)) | bits.get_bits(k + 1)? as usize
        };
        for _ in 0..len {
            // Ring-indexed read: the byte (write_pos - offset) mod size.
            let idx = pos.wrapping_sub(off) & mask;
            let b = hist[idx];
            emit(hist, pos, &mut out, b, max_output)?;
        }
    }
    Ok(out)
}

/// MPPC decoder maintaining the protocol history state across packets.
///
/// `decompress` handles one RFC 2118 packet per call; the coherency count
/// is checked against the previous packet and history is carried over per
/// RFC 2118 sections 3 and 4.3. For RDP bulk compression packets use
/// [`RdpDecoder`].
pub struct Decoder {
    hist: Box<[u8]>,
    pos: usize,
    count: u16,
    started: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            hist: alloc::vec![0; HISTORY_SIZE].into_boxed_slice(),
            pos: 0,
            count: 0,
            started: false,
        }
    }

    /// Reset all history and coherency state (as after a CCP Reset-Ack).
    pub fn reset(&mut self) {
        self.hist.fill(0);
        self.pos = 0;
        self.count = 0;
        self.started = false;
    }

    /// Decompress one MPPC packet (`flags nibble | count | data`).
    ///
    /// `max_output` bounds the number of bytes this packet may produce.
    pub fn decompress(&mut self, packet: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
        if packet.len() < 2 {
            return Err(Error::InvalidData("mppc: truncated packet header"));
        }
        let flags = packet[0] >> 4;
        let count = (((packet[0] & 0xF) as u16) << 8) | packet[1] as u16;
        if flags & FLAG_RESERVED != 0 {
            return Err(Error::InvalidData("mppc: reserved flag bit set"));
        }
        if flags & FLAG_FLUSHED != 0 {
            self.hist.fill(0);
            self.pos = 0;
            self.count = count;
            self.started = true;
        } else if !self.started {
            // Tolerate a first packet without FLUSHED by adopting its count.
            self.count = count;
            self.started = true;
        } else if count != self.count {
            return Err(Error::InvalidData("mppc: coherency count mismatch"));
        }
        self.count = self.count.wrapping_add(1) & 0xFFF;

        if flags & FLAG_FRONT != 0 {
            self.pos = 0;
        }

        let data = &packet[2..];
        let mut out = Vec::new();
        if flags & FLAG_COMPRESSED == 0 {
            if data.len() > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            // Uncompressed packets bypass the token decoder and do not
            // update the history: the sender is required to flush history
            // before compressing again (RFC 2118 section 3, "Data
            // Expansion"), and reference decoders (rdesktop, FreeRDP) skip
            // the history update as well.
            out.extend_from_slice(data);
            return Ok(out);
        }

        decode_tokens(
            CompressionType::Rdp4,
            &mut self.hist,
            &mut self.pos,
            data,
            max_output,
        )
    }
}

/// Byte at absolute history position `p` while encoding: positions at
/// or after `pos` are bytes of the packet currently being produced.
fn at(hist: &[u8], pos: usize, data: &[u8], p: usize) -> u8 {
    if p < pos { hist[p] } else { data[p - pos] }
}

/// Greedy LZ tokenization of `data` appended at `pos` in `hist`,
/// searching the history epoch `[epoch_base, pos)` plus the bytes
/// produced so far. Returns the packed token bitstream.
fn encode_body(
    ty: CompressionType,
    hist: &[u8],
    pos: usize,
    epoch_base: usize,
    data: &[u8],
) -> Vec<u8> {
    let mut w = BitWriter::new();
    // Greedy matcher: last-seen position per 3-byte hash, over the
    // current history epoch and the bytes produced so far.
    let mut head = alloc::vec![-1i32; 1 << 15];
    let hash = |a: u8, b: u8, c: u8| -> usize {
        (((a as usize) << 8) ^ ((b as usize) << 4) ^ c as usize) & 0x7FFF
    };
    for p in epoch_base..pos.saturating_sub(MIN_MATCH - 1) {
        head[hash(hist[p], hist[p + 1], hist[p + 2])] = p as i32;
    }

    let mut produced = 0usize;
    while produced < data.len() {
        let wpos = pos + produced;
        let max_len = ty.max_match().min(data.len() - produced);
        let mut best_len = 0usize;
        let mut best_off = 0usize;
        if produced + MIN_MATCH <= data.len() {
            let h = hash(data[produced], data[produced + 1], data[produced + 2]);
            let cand = head[h];
            head[h] = wpos as i32;
            if cand >= 0 {
                let cp = cand as usize;
                // Verify the hash hit before accepting it: different
                // trigrams can share a hash.
                if at(hist, pos, data, cp) == data[produced]
                    && at(hist, pos, data, cp + 1) == data[produced + 1]
                    && at(hist, pos, data, cp + 2) == data[produced + 2]
                {
                    let mut len = MIN_MATCH;
                    while len < max_len && at(hist, pos, data, cp + len) == data[produced + len] {
                        len += 1;
                    }
                    let off = wpos - cp;
                    if off <= ty.max_offset() {
                        best_len = len;
                        best_off = off;
                    }
                }
            }
        }
        if best_len >= MIN_MATCH {
            put_offset(&mut w, ty, best_off);
            put_length(&mut w, ty, best_len);
            for i in 0..best_len {
                let p = produced + i;
                if p + MIN_MATCH <= data.len() {
                    head[hash(data[p], data[p + 1], data[p + 2])] = (pos + p) as i32;
                }
            }
            produced += best_len;
        } else {
            put_literal(&mut w, data[produced]);
            produced += 1;
        }
    }
    w.finish()
}

/// MPPC encoder maintaining the protocol history state across packets.
///
/// `compress` emits one RFC 2118 packet per call. The encoder sets
/// FLUSHED on the first packet after `new`/`reset` and FRONT whenever the
/// payload would not fit in the remaining history space; it falls back to
/// an uncompressed packet when compression would expand the data
/// (RFC 2118 section 3, "Data Expansion"). Match selection is a greedy
/// single-hash lookup, suitable as a correctness baseline. For RDP bulk
/// compression use [`RdpEncoder`].
pub struct Encoder {
    hist: Box<[u8]>,
    pos: usize,
    epoch_base: usize,
    count: u16,
    started: bool,
    pending_flush: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            hist: alloc::vec![0; HISTORY_SIZE].into_boxed_slice(),
            pos: 0,
            epoch_base: 0,
            count: 0,
            started: false,
            pending_flush: false,
        }
    }

    /// Reset all history and coherency state.
    pub fn reset(&mut self) {
        self.hist.fill(0);
        self.pos = 0;
        self.epoch_base = 0;
        self.count = 0;
        self.started = false;
        self.pending_flush = false;
    }

    /// Compress `data` into one MPPC packet (`flags | count | data`).
    ///
    /// `data` must fit in the history window (at most [`HISTORY_SIZE`]
    /// bytes); larger payloads must be split by the caller into separate
    /// packets, matching the link-layer packetization.
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() > HISTORY_SIZE {
            return Err(Error::InvalidData(
                "mppc: packet payload exceeds history size",
            ));
        }
        let mut flags = FLAG_COMPRESSED;
        if !self.started || self.pending_flush {
            // RFC 2118 section 3: after sending an uncompressed packet the
            // sender must flush history before compressing more data and
            // set FLUSHED on that packet.
            flags |= FLAG_FLUSHED;
            self.hist.fill(0);
            self.pos = 0;
            self.epoch_base = 0;
            self.started = true;
            self.pending_flush = false;
        }
        if self.pos + data.len() > HISTORY_SIZE {
            flags |= FLAG_FRONT;
            self.pos = 0;
            self.epoch_base = 0;
        }

        let body = encode_body(
            CompressionType::Rdp4,
            &self.hist,
            self.pos,
            self.epoch_base,
            data,
        );

        // Everything we emitted enters the history, in order.
        self.hist[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();

        let mut packet = Vec::with_capacity(2 + data.len().max(body.len()));
        if body.len() >= data.len() {
            // Data expansion: send uncompressed and flush before the next
            // compressed packet (RFC 2118 section 3).
            flags &= !FLAG_COMPRESSED;
            self.pending_flush = true;
            packet.push((flags << 4) | ((self.count >> 8) as u8 & 0xF));
            packet.push(self.count as u8);
            packet.extend_from_slice(data);
        } else {
            packet.push((flags << 4) | ((self.count >> 8) as u8 & 0xF));
            packet.push(self.count as u8);
            packet.extend_from_slice(&body);
        }
        self.count = self.count.wrapping_add(1) & 0xFFF;
        Ok(packet)
    }
}

/// Encode `input` as a single MPPC packet (FLUSHED, count 0).
///
/// `input` must be at most [`HISTORY_SIZE`] bytes; use [`Encoder`] for
/// multi-packet streams.
pub fn encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    Encoder::new().compress(input)
}

/// Decode a single MPPC packet with a fresh decoder. `input` is the whole
/// packet (`flags | count | data`); packets carry no length field.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a single MPPC packet, bounding total output.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    Decoder::new().decompress(input, max_output)
}

/// MPPC decoder for RDP bulk compression ([MS-RDPBCGR] section 3.1.8.4).
///
/// RDP packets have no in-band header: the `compressedType` byte from the
/// Share Data Header is passed as `flags` to [`decompress`](Self::decompress)
/// and supplies the PACKET_* flag bits plus the CompressionType nibble.
/// The decoder's variant is fixed at construction, matching the
/// negotiated compression type.
///
/// Unlike RFC 2118, an uncompressed RDP packet still feeds its payload
/// into the history buffer — the sender is required to insert it
/// ([MS-RDPBCGR] section 3.1.8.4).
pub struct RdpDecoder {
    ty: CompressionType,
    hist: Box<[u8]>,
    pos: usize,
}

impl RdpDecoder {
    /// Create a decoder for `ty` with a zeroed history buffer.
    pub fn new(ty: CompressionType) -> Self {
        Self {
            ty,
            hist: alloc::vec![0; ty.history_size()].into_boxed_slice(),
            pos: 0,
        }
    }

    /// Reset the history buffer to zeroes and the position to the front,
    /// as on receipt of a [`PACKET_FLUSHED`] packet.
    pub fn reset(&mut self) {
        self.hist.fill(0);
        self.pos = 0;
    }

    /// Decompress one RDP bulk-compression packet.
    ///
    /// `flags` is the `compressedType` byte of the enclosing PDU:
    /// [`PACKET_COMPRESSED`], [`PACKET_AT_FRONT`] and [`PACKET_FLUSHED`]
    /// flag bits plus a low-nibble CompressionType
    /// ([`COMPRESSION_TYPE_MASK`]) which must equal the variant selected
    /// at construction. `data` is the packet payload (the `Data` field),
    /// and `max_output` bounds the number of bytes it may produce.
    pub fn decompress(
        &mut self,
        flags: u8,
        data: &[u8],
        max_output: usize,
    ) -> Result<Vec<u8>, Error> {
        if flags & RDP_FLAG_RESERVED != 0 {
            return Err(Error::InvalidData("mppc: reserved flag bit set"));
        }
        let wire_ty = CompressionType::from_wire(flags & COMPRESSION_TYPE_MASK)?;
        if wire_ty != self.ty {
            return Err(Error::InvalidData("mppc: compression type mismatch"));
        }
        if flags & PACKET_FLUSHED != 0 {
            self.hist.fill(0);
            self.pos = 0;
        }
        if flags & PACKET_AT_FRONT != 0 {
            self.pos = 0;
        }
        if flags & PACKET_COMPRESSED == 0 {
            // Uncompressed RDP packets still update the history buffer.
            if data.len() > max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            append_history(&mut self.hist, &mut self.pos, data)?;
            return Ok(data.to_vec());
        }
        decode_tokens(self.ty, &mut self.hist, &mut self.pos, data, max_output)
    }
}

/// MPPC encoder for RDP bulk compression ([MS-RDPBCGR] section 3.1.8.4).
///
/// [`compress`](Self::compress) emits one packet per call and returns the
/// `compressedType` flag byte and payload separately, matching how an
/// RDP stack supplies the flags out-of-band. [`PACKET_AT_FRONT`] is set
/// whenever the write position (re)starts at the front of the history
/// buffer — including the first packet — and [`PACKET_FLUSHED`] is set on
/// the first packet after [`reset`](Self::reset). When compression would
/// expand the data an uncompressed packet is emitted; unlike RFC 2118 no
/// flush is needed afterwards since uncompressed data enters the history.
pub struct RdpEncoder {
    ty: CompressionType,
    hist: Box<[u8]>,
    pos: usize,
    epoch_base: usize,
    pending_flush: bool,
}

impl RdpEncoder {
    /// Create an encoder for `ty` with a zeroed history buffer.
    pub fn new(ty: CompressionType) -> Self {
        Self {
            ty,
            hist: alloc::vec![0; ty.history_size()].into_boxed_slice(),
            pos: 0,
            epoch_base: 0,
            pending_flush: false,
        }
    }

    /// Reset the encoder history; the next packet carries
    /// [`PACKET_FLUSHED`] so the peer reinitializes its history too.
    pub fn reset(&mut self) {
        self.hist.fill(0);
        self.pos = 0;
        self.epoch_base = 0;
        self.pending_flush = true;
    }

    /// Compress `data` into one RDP packet, returning `(flags, payload)`.
    ///
    /// `flags` is the `compressedType` byte to place in the enclosing
    /// PDU; `payload` is the token stream (or raw data when
    /// [`PACKET_COMPRESSED`] is clear). `data` must fit in the history
    /// window (at most 8192 bytes for [`CompressionType::Rdp4`], 65536
    /// for [`CompressionType::Rdp5`]); larger payloads must be split by
    /// the caller.
    pub fn compress(&mut self, data: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        if data.len() > self.hist.len() {
            return Err(Error::InvalidData(
                "mppc: packet payload exceeds history size",
            ));
        }
        let mut flags = self.ty.wire_code();
        if self.pending_flush {
            flags |= PACKET_FLUSHED;
            self.hist.fill(0);
            self.pos = 0;
            self.epoch_base = 0;
            self.pending_flush = false;
        }
        if self.pos == 0 || self.pos + data.len() > self.hist.len() {
            flags |= PACKET_AT_FRONT;
            self.pos = 0;
            self.epoch_base = 0;
        }

        let body = encode_body(self.ty, &self.hist, self.pos, self.epoch_base, data);

        // Compressed or not, every byte enters the history in order.
        self.hist[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();

        if body.len() >= data.len() {
            // Data expansion: send the payload uncompressed. Unlike the
            // RFC 2118 path no flush follows: the peer inserts the data
            // into its history as well.
            return Ok((flags, data.to_vec()));
        }
        Ok((flags | PACKET_COMPRESSED, body))
    }
}

/// Decode a single RDP bulk-compression packet with a fresh decoder.
///
/// `flags` is the `compressedType` byte; the CompressionType nibble
/// selects the dictionary variant. Packets carrying the RDP6/RDP6.1
/// compression types are rejected (different codec).
pub fn decode_rdp(flags: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
    decode_rdp_bounded(flags, data, usize::MAX)
}

/// Decode a single RDP bulk-compression packet, bounding total output.
pub fn decode_rdp_bounded(flags: u8, data: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let ty = CompressionType::from_wire(flags & COMPRESSION_TYPE_MASK)?;
    RdpDecoder::new(ty).decompress(flags, data, max_output)
}

/// Encode `input` as a single RDP bulk-compression packet with a fresh
/// encoder, returning `(flags, payload)`. `input` must fit the variant's
/// history window; use [`RdpEncoder`] for multi-packet streams.
pub fn encode_rdp(ty: CompressionType, data: &[u8]) -> Result<(u8, Vec<u8>), Error> {
    RdpEncoder::new(ty).compress(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_packets(packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut dec = Decoder::new();
        packets
            .iter()
            .map(|p| dec.decompress(p, 1 << 20).unwrap())
            .collect()
    }

    #[test]
    fn literal_roundtrip() {
        let data = b"hello world";
        let packet = encode(data).unwrap();
        assert_eq!(packet[0] >> 4 & FLAG_FLUSHED, FLAG_FLUSHED);
        assert_eq!(decode(&packet).unwrap(), data);
    }

    #[test]
    fn match_roundtrip() {
        let data = b"abcabcabcabcabcabcabc";
        let packet = encode(data).unwrap();
        assert_eq!(decode(&packet).unwrap(), data);
    }

    #[test]
    fn high_literal_roundtrip() {
        let data: Vec<u8> = (0..=255u8).cycle().take(300).collect();
        let packet = encode(&data).unwrap();
        assert_eq!(decode(&packet).unwrap(), data);
    }

    #[test]
    fn empty_roundtrip() {
        let packet = encode(&[]).unwrap();
        assert_eq!(decode(&packet).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn multi_packet_history() {
        let mut enc = Encoder::new();
        let d1 = b"the quick brown fox jumps over the lazy dog".to_vec();
        let d2 = b"the quick brown fox jumps over the lazy dog".to_vec();
        let p1 = enc.compress(&d1).unwrap();
        let p2 = enc.compress(&d2).unwrap();
        // Second packet reuses history: compressed form should be tiny.
        assert!(p2.len() < d2.len() / 2);
        let outs = run_packets(&[p1, p2]);
        assert_eq!(outs[0], d1);
        assert_eq!(outs[1], d2);
    }

    #[test]
    fn front_wrap() {
        let mut enc = Encoder::new();
        let d1 = alloc::vec![0xAA; 6000];
        let d2 = alloc::vec![0xBB; 4000];
        let p1 = enc.compress(&d1).unwrap();
        let p2 = enc.compress(&d2).unwrap();
        assert_eq!(p2[0] >> 4 & FLAG_FRONT, FLAG_FRONT);
        let outs = run_packets(&[p1, p2]);
        assert_eq!(outs[0], d1);
        assert_eq!(outs[1], d2);
    }

    #[test]
    fn expansion_fallback() {
        // Incompressible data -> uncompressed packet (C clear), still updates history.
        let mut enc = Encoder::new();
        let data: Vec<u8> = (0..200u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let packet = enc.compress(&data).unwrap();
        assert_eq!(packet[0] >> 4 & FLAG_COMPRESSED, 0);
        let mut dec = Decoder::new();
        assert_eq!(dec.decompress(&packet, 1 << 20).unwrap(), data);
    }

    #[test]
    fn coherency_count_checked() {
        let mut enc = Encoder::new();
        let p1 = enc.compress(b"aaaa").unwrap();
        let p2 = enc.compress(b"bbbb").unwrap();
        let mut dec = Decoder::new();
        dec.decompress(&p1, 1 << 20).unwrap();
        dec.decompress(&p2, 1 << 20).unwrap();
        // Replay p2 (count 1) when count 2 is expected.
        assert!(dec.decompress(&p2, 1 << 20).is_err());
    }

    #[test]
    fn reset() {
        let mut enc = Encoder::new();
        enc.compress(b"xyzzy").unwrap();
        enc.reset();
        let packet = enc.compress(b"hello").unwrap();
        assert_eq!(packet[0] >> 4 & FLAG_FLUSHED, FLAG_FLUSHED);
        assert_eq!((packet[0] & 0xF) as u16 * 256 + packet[1] as u16, 0); // count 0
        assert_eq!(decode(&packet).unwrap(), b"hello");
    }

    #[test]
    fn rejects_reserved_flag() {
        assert!(decode(&[0x10, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(decode(&[0x80]).is_err());
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn rejects_truncated_bitstream() {
        // Compressed packet with a truncated token.
        assert!(decode(&[0xA0, 0x00, 0xFF]).is_err());
    }

    #[test]
    fn output_limit() {
        let data = b"abcabcabcabcabcabc";
        let packet = encode(data).unwrap();
        match decode_bounded(&packet, 5) {
            Err(Error::OutputLimitExceeded { limit: 5 }) => {}
            other => panic!("expected OutputLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn payload_too_large() {
        let data = alloc::vec![0u8; HISTORY_SIZE + 1];
        assert!(encode(&data).is_err());
        let mut enc = Encoder::new();
        assert!(enc.compress(&data).is_err());
    }

    #[test]
    fn uncompressed_first_packet_without_flushed() {
        // A decoder tolerates a first packet missing FLUSHED.
        let packet = [0x02u8, 0x07, b'h', b'i'];
        assert_eq!(decode(&packet).unwrap(), b"hi");
    }

    #[test]
    fn known_answer_literal_and_copy() {
        // Hand-built compressed packet (FLUSHED|COMPRESSED, count 0):
        // 'A' literal (01000001) then copy('11' + '1111' + offset(6b=1) +
        // len '10' + 2b 00 = 4) -> "AAAAA".
        // bits: 01000001 | 11 1111 000001 | 10 00 -> 0x41 0xF0 0x60
        let packet = [0xA0u8, 0x00, 0x41, 0xF0, 0x60];
        assert_eq!(decode(&packet).unwrap(), b"AAAAA");
    }

    #[test]
    fn known_answer_mid_offsets() {
        // Build packets exercising all three offset classes via the encoder
        // and verify the decoder resolves them.
        let mut data = Vec::new();
        data.extend_from_slice(b"0123456789");
        data.extend_from_slice(&alloc::vec![0u8; 60]);
        data.extend_from_slice(b"0123456789"); // offset ~70 (class 64..319)
        data.extend_from_slice(&alloc::vec![1u8; 400]);
        data.extend_from_slice(b"0123456789"); // offset ~480 (class 320+)
        let packet = encode(&data).unwrap();
        assert_eq!(decode(&packet).unwrap(), data);
    }

    #[test]
    fn rejects_history_overflow() {
        // FLUSHED|COMPRESSED packet producing 8193 bytes: literal 'A',
        // copy(off=1, len=8191), literal 'B'. The sender must set FRONT
        // instead of overflowing the history buffer.
        let mut w = BitWriter::new();
        put_literal(&mut w, b'A');
        put_offset(&mut w, CompressionType::Rdp4, 1);
        put_length(&mut w, CompressionType::Rdp4, 8191);
        put_literal(&mut w, b'B');
        let mut packet = vec![0xA0u8, 0x00];
        packet.extend_from_slice(&w.finish());
        match decode(&packet) {
            Err(Error::InvalidData(m)) if m.contains("history overflow") => {}
            other => panic!("expected history overflow, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_length_class() {
        // Length class with k > 11 leading ones (more than the 8191
        // maximum) must be rejected.
        let mut w = BitWriter::new();
        put_literal(&mut w, b'A');
        put_offset(&mut w, CompressionType::Rdp4, 1);
        w.put(0xFFF, 12); // 12 leading ones -> k = 12
        w.put(0, 1);
        let mut packet = vec![0xA0u8, 0x00];
        packet.extend_from_slice(&w.finish());
        match decode(&packet) {
            Err(Error::InvalidData(m)) if m.contains("bad match length") => {}
            other => panic!("expected bad match length, got {other:?}"),
        }
    }

    // ---- RDP bulk compression (MS-RDPBCGR 3.1.8.4) ----

    #[test]
    fn rdp5_literal_roundtrip() {
        // Tiny input expands -> uncompressed packet (AT_FRONT only).
        let (flags, body) = encode_rdp(CompressionType::Rdp5, b"hello world").unwrap();
        assert_eq!(flags, PACKET_AT_FRONT | 0x01);
        assert_eq!(decode_rdp(flags, &body).unwrap(), b"hello world");
        // Compressible input -> COMPRESSED.
        let (flags, body) = encode_rdp(CompressionType::Rdp5, b"abababababababababab").unwrap();
        assert_eq!(flags, PACKET_AT_FRONT | PACKET_COMPRESSED | 0x01);
        assert_eq!(decode_rdp(flags, &body).unwrap(), b"abababababababababab");
    }

    #[test]
    fn rdp5_match_roundtrip() {
        let data = b"abcabcabcabcabcabcabc";
        let (flags, body) = encode_rdp(CompressionType::Rdp5, data).unwrap();
        assert_eq!(decode_rdp(flags, &body).unwrap(), data);
    }

    #[test]
    fn rdp5_known_answer() {
        // COMPRESSED|AT_FRONT|type1. Stream: 'A' literal (01000001),
        // copy('11' + '11111' + offset(6b=1) + len '10' + 2b 00 = 4)
        // -> "AAAAA".
        // bits: 01000001 | 11111 000001 | 10 00 -> 0x41 0xF8 0x30
        assert_eq!(decode_rdp(0x61, &[0x41, 0xF8, 0x30]).unwrap(), b"AAAAA");
    }

    #[test]
    fn rdp5_extended_length_class() {
        // 64 KiB of one byte -> literal + copy(len 65535): the
        // '111111111111110' + 15-bit class only exists in RDP 5.0.
        let data = alloc::vec![0xABu8; HISTORY_SIZE_64K];
        let (flags, body) = encode_rdp(CompressionType::Rdp5, &data).unwrap();
        assert!(body.len() < 16);
        assert_eq!(decode_rdp(flags, &body).unwrap(), data);
        // Hand-build a token using the '1111111111110' + 13-bit class:
        // literal 'A', copy(off=1, len=8192) -> 8193 bytes of 'A'.
        let mut w = BitWriter::new();
        put_literal(&mut w, b'A');
        put_offset(&mut w, CompressionType::Rdp5, 1);
        put_length(&mut w, CompressionType::Rdp5, 8192);
        let body = w.finish();
        let expect = alloc::vec![b'A'; 8193];
        assert_eq!(decode_rdp(0x61, &body).unwrap(), expect);
    }

    #[test]
    fn rdp5_far_offset_class() {
        // Push >2368 bytes of filler so a repeat lands in the
        // '110' + 16-bit offset class (2368..=65535).
        let mut data = Vec::new();
        data.extend_from_slice(b"marker-block!");
        for i in 0..4000u32 {
            data.push((i.wrapping_mul(2654435761) >> 24) as u8);
        }
        data.extend_from_slice(b"marker-block!");
        let (flags, body) = encode_rdp(CompressionType::Rdp5, &data).unwrap();
        assert_eq!(decode_rdp(flags, &body).unwrap(), data);
    }

    #[test]
    fn rdp5_multi_packet_wrap() {
        let mut enc = RdpEncoder::new(CompressionType::Rdp5);
        let mut dec = RdpDecoder::new(CompressionType::Rdp5);
        let d1 = alloc::vec![0xAAu8; 60000];
        let d2 = alloc::vec![0xBBu8; 40000];
        let (f1, p1) = enc.compress(&d1).unwrap();
        let (f2, p2) = enc.compress(&d2).unwrap();
        assert_eq!(f1 & PACKET_COMPRESSED, PACKET_COMPRESSED);
        assert_eq!(f2 & PACKET_AT_FRONT, PACKET_AT_FRONT); // wrapped to front
        assert_eq!(dec.decompress(f1, &p1, 1 << 20).unwrap(), d1);
        assert_eq!(dec.decompress(f2, &p2, 1 << 20).unwrap(), d2);
    }

    #[test]
    fn rdp5_uncompressed_updates_history() {
        // Unlike RFC 2118, an uncompressed RDP packet must still feed the
        // history: a later compressed packet may reference it.
        let mut enc = RdpEncoder::new(CompressionType::Rdp5);
        let mut dec = RdpDecoder::new(CompressionType::Rdp5);
        let data: Vec<u8> = (0..300u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 24) as u8)
            .collect();
        let (f1, p1) = enc.compress(&data).unwrap();
        assert_eq!(f1 & PACKET_COMPRESSED, 0); // expansion -> uncompressed
        assert_eq!(dec.decompress(f1, &p1, 1 << 20).unwrap(), data);
        // Second identical chunk compresses against that history.
        let (f2, p2) = enc.compress(&data).unwrap();
        assert_eq!(f2 & PACKET_COMPRESSED, PACKET_COMPRESSED);
        assert!(p2.len() < data.len() / 2);
        assert_eq!(dec.decompress(f2, &p2, 1 << 20).unwrap(), data);
    }

    #[test]
    fn rdp5_flushed_resets() {
        let mut enc = RdpEncoder::new(CompressionType::Rdp5);
        enc.compress(b"xyzzy").unwrap();
        enc.reset();
        let (flags, body) = enc.compress(b"hello").unwrap();
        assert_eq!(flags & PACKET_FLUSHED, PACKET_FLUSHED);
        let mut dec = RdpDecoder::new(CompressionType::Rdp5);
        assert_eq!(dec.decompress(flags, &body, 1 << 20).unwrap(), b"hello");
    }

    #[test]
    fn rdp4_via_rdp_api() {
        // CompressionType 0x00 decodes with the 8 KiB RFC 2118 tables but
        // without the 2-byte packet header.
        let (flags, body) = encode_rdp(CompressionType::Rdp4, b"abcabcabc").unwrap();
        assert_eq!(flags, PACKET_AT_FRONT | PACKET_COMPRESSED);
        assert_eq!(decode_rdp(flags, &body).unwrap(), b"abcabcabc");
    }

    #[test]
    fn rdp_rejects_unsupported_type() {
        // RDP6 (0x02) / RDP6.1 (0x03) are a different codec.
        assert!(decode_rdp(0x22, b"xx").is_err());
        assert!(decode_rdp(0x23, b"xx").is_err());
        assert!(decode_rdp(0x2F, b"xx").is_err());
    }

    #[test]
    fn rdp_rejects_reserved_flag() {
        assert!(decode_rdp(0x11, b"xx").is_err()); // 0x10 reserved bit
    }

    #[test]
    fn rdp_rejects_type_mismatch() {
        let mut dec = RdpDecoder::new(CompressionType::Rdp5);
        // Flags say type 0x00 but the decoder was built for 64K.
        assert!(dec.decompress(0x60, b"xx", 1 << 20).is_err());
    }

    #[test]
    fn rdp5_rejects_bad_length_class() {
        // k = 15 leading ones exceeds the RDP 5.0 maximum (k <= 14).
        let mut w = BitWriter::new();
        put_literal(&mut w, b'A');
        put_offset(&mut w, CompressionType::Rdp5, 1);
        w.put(0x7FFF, 15); // 15 leading ones -> k = 15
        w.put(0, 1);
        match decode_rdp(0x61, &w.finish()) {
            Err(Error::InvalidData(m)) if m.contains("bad match length") => {}
            other => panic!("expected bad match length, got {other:?}"),
        }
    }

    #[test]
    fn rdp5_rejects_history_overflow() {
        // One packet producing 65537 bytes: 'A', copy(off=1, len=65535),
        // literal 'B'.
        let mut w = BitWriter::new();
        put_literal(&mut w, b'A');
        put_offset(&mut w, CompressionType::Rdp5, 1);
        put_length(&mut w, CompressionType::Rdp5, 65535);
        put_literal(&mut w, b'B');
        match decode_rdp(0x61, &w.finish()) {
            Err(Error::InvalidData(m)) if m.contains("history overflow") => {}
            other => panic!("expected history overflow, got {other:?}"),
        }
    }

    #[test]
    fn rdp5_uncompressed_overflow_rejected() {
        // Uncompressed payload larger than the remaining history without
        // AT_FRONT/FLUSHED must error.
        let mut dec = RdpDecoder::new(CompressionType::Rdp5);
        dec.decompress(0x41, &[0x55u8; 100], 1 << 20).unwrap(); // pos=100
        let big = alloc::vec![0u8; HISTORY_SIZE_64K];
        assert!(dec.decompress(0x01, &big, 1 << 20).is_err());
    }

    #[test]
    fn rdp5_output_limit() {
        let (flags, body) = encode_rdp(CompressionType::Rdp5, b"abcabcabcabc").unwrap();
        match decode_rdp_bounded(flags, &body, 5) {
            Err(Error::OutputLimitExceeded { limit: 5 }) => {}
            other => panic!("expected OutputLimitExceeded, got {other:?}"),
        }
    }
}
