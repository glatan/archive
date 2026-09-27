//! MPPC (Microsoft Point-to-Point Compression, RFC 2118).
//!
//! MPPC is an LZ77 variant with an 8192-byte history buffer, designed for
//! compressing PPP datagrams one packet at a time. Each packet carries a
//! flags nibble and a 12-bit coherency count (RFC 2118 section 3):
//!
//! ```text
//! |A|B|C|D|   Coherency Count (12 bits)   | Compressed Data ...
//! ```
//!
//! - `A` (FLUSHED, `0x8`): history was just initialized to zeroes.
//! - `B` (FRONT, `0x4`): the sender wrapped its history write pointer back
//!   to the front of the buffer.
//! - `C` (COMPRESSED, `0x2`): the data is an LZ token stream; otherwise it
//!   is uncompressed data (which still updates the history).
//! - `D` (`0x1`): reserved, must be zero.
//!
//! The token stream is packed MSB-first (RFC 2118 section 4.2.2):
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
//! handling) is out of scope, as is the 64 KiB "big" dictionary variant
//! used by RDP bulk compression.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::Error;

/// MPPC history buffer size (RFC 2118 section 2).
pub const HISTORY_SIZE: usize = 8192;

const FLAG_FLUSHED: u8 = 0x8;
const FLAG_FRONT: u8 = 0x4;
const FLAG_COMPRESSED: u8 = 0x2;
const FLAG_RESERVED: u8 = 0x1;

const MIN_MATCH: usize = 3;
const MAX_OFFSET: usize = 8191;
const MAX_MATCH: usize = 8191;

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

fn put_offset(w: &mut BitWriter, off: usize) {
    debug_assert!((1..=MAX_OFFSET).contains(&off));
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

fn put_length(w: &mut BitWriter, len: usize) {
    debug_assert!((MIN_MATCH..=MAX_MATCH).contains(&len));
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

/// MPPC decoder maintaining the protocol history state across packets.
///
/// `decompress` handles one packet per call; the coherency count is checked
/// against the previous packet and history is carried over per RFC 2118
/// sections 3 and 4.3.
pub struct Decoder {
    hist: Box<[u8; HISTORY_SIZE]>,
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
            hist: Box::new([0; HISTORY_SIZE]),
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

        let mut bits = Bits::new(data);
        while !bits.at_end() {
            if bits.get()? == 0 {
                let b = bits.get_bits(7)? as u8;
                self.emit(&mut out, b, max_output)?;
                continue;
            }
            if bits.get()? == 0 {
                // '10' + 7 bits: literal >= 0x80.
                let b = (bits.get_bits(7)? | 0x80) as u8;
                self.emit(&mut out, b, max_output)?;
                continue;
            }
            // Copy token: leading bits '11', then the offset prefix.
            let off = if bits.get()? == 1 {
                if bits.get()? == 1 {
                    bits.get_bits(6)? as usize // '1111' + 6 bits: 1..=63
                } else {
                    bits.get_bits(8)? as usize + 64 // '1110' + 8 bits: 64..=319
                }
            } else {
                bits.get_bits(13)? as usize + 320 // '110' + 13 bits: 320..=8191
            };
            // Match length: k leading ones + '0', then k+1 low bits; '0'
            // alone encodes 3 (RFC 2118 section 4.2.2).
            let mut k = 0u32;
            while bits.get()? == 1 {
                k += 1;
                if k > 11 {
                    return Err(Error::InvalidData("mppc: bad match length"));
                }
            }
            let len = if k == 0 {
                MIN_MATCH
            } else {
                (1 << (k + 1)) | bits.get_bits(k + 1)? as usize
            };
            for _ in 0..len {
                // Ring-indexed read: the byte (write_pos - offset) mod 8192.
                let idx = self.pos.wrapping_sub(off) & (HISTORY_SIZE - 1);
                let b = self.hist[idx];
                self.emit(&mut out, b, max_output)?;
            }
        }
        Ok(out)
    }

    fn emit(&mut self, out: &mut Vec<u8>, b: u8, max_output: usize) -> Result<(), Error> {
        if out.len() >= max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        if self.pos >= HISTORY_SIZE {
            // A conformant sender sets FRONT before overflowing the
            // buffer; treat mid-packet overflow as malformed input.
            return Err(Error::InvalidData("mppc: history overflow"));
        }
        self.hist[self.pos] = b;
        self.pos += 1;
        out.push(b);
        Ok(())
    }
}

/// MPPC encoder maintaining the protocol history state across packets.
///
/// `compress` emits one packet per call. The encoder sets FLUSHED on the
/// first packet after `new`/`reset` and FRONT whenever the payload would
/// not fit in the remaining history space; it falls back to an
/// uncompressed packet when compression would expand the data (RFC 2118
/// section 3, "Data Expansion"). Match selection is a greedy single-hash
/// lookup, suitable as a correctness baseline.
pub struct Encoder {
    hist: Box<[u8; HISTORY_SIZE]>,
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
            hist: Box::new([0; HISTORY_SIZE]),
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

        let mut w = BitWriter::new();
        // Greedy matcher: last-seen position per 3-byte hash, over the
        // current history epoch and the bytes produced so far.
        let mut head = alloc::vec![-1i32; 1 << 15];
        let hash = |a: u8, b: u8, c: u8| -> usize {
            (((a as usize) << 8) ^ ((b as usize) << 4) ^ c as usize) & 0x7FFF
        };
        for p in self.epoch_base..self.pos.saturating_sub(MIN_MATCH - 1) {
            head[hash(self.hist[p], self.hist[p + 1], self.hist[p + 2])] = p as i32;
        }

        let mut produced = 0usize;
        while produced < data.len() {
            let wpos = self.pos + produced;
            let max_len = MAX_MATCH.min(data.len() - produced);
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
                    if self.at(data, cp) == data[produced]
                        && self.at(data, cp + 1) == data[produced + 1]
                        && self.at(data, cp + 2) == data[produced + 2]
                    {
                        let mut len = MIN_MATCH;
                        while len < max_len && self.at(data, cp + len) == data[produced + len] {
                            len += 1;
                        }
                        let off = wpos - cp;
                        if off <= MAX_OFFSET {
                            best_len = len;
                            best_off = off;
                        }
                    }
                }
            }
            if best_len >= MIN_MATCH {
                put_offset(&mut w, best_off);
                put_length(&mut w, best_len);
                for i in 0..best_len {
                    let p = produced + i;
                    if p + MIN_MATCH <= data.len() {
                        head[hash(data[p], data[p + 1], data[p + 2])] = (self.pos + p) as i32;
                    }
                }
                produced += best_len;
            } else {
                put_literal(&mut w, data[produced]);
                produced += 1;
            }
        }
        let body = w.finish();

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

    /// Byte at absolute history position `p` while encoding: positions at
    /// or after `pos` are bytes of the packet currently being produced.
    fn at(&self, data: &[u8], p: usize) -> u8 {
        if p < self.pos {
            self.hist[p]
        } else {
            data[p - self.pos]
        }
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
}
