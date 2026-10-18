//! Stac LZS (RFC 2395 section 2.2, ANSI X3.241-1994 encoding).
//!
//! LZS is an LZ77 variant with a 2048-byte sliding window, designed for
//! compressing IP datagram payloads one at a time (IPComp, RFC 3173) and
//! PPP packets (RFC 1974). Tokens are packed MSB-first:
//!
//! - literal: `0` + 8-bit raw byte.
//! - copy: `1` + `<Offset>` + `<Length>`. Offsets are `1` + 7 bits
//!   (1..=127) or `0` + 11 bits (1..=2047). Length 2..=7 uses short
//!   prefixes (`00`/`01`/`10`/`1100`/`1101`/`1110`); 8 and above uses
//!   chains of `1111` nibbles (each adding 15) plus a final nibble.
//! - end marker: `110000000` (a copy token with a zero 7-bit offset).
//!   The encoder pads the final byte with `1` bits; after the end marker
//!   any trailing bits or bytes are padding (RFC 2395 section 2.3).
//!
//! A zero offset in the long (11-bit) form is reserved and rejected.
//! History is reset before every datagram and the compressor is flushed
//! after every datagram (RFC 2395 sections 2.1 and 3), so the API is
//! one-shot per datagram: a byte string is exactly one compressed
//! payload. The IPComp/PPP transport framing (CPI negotiation, sequence
//! numbers, `LZS-DCP` history mode) is out of scope.

use alloc::vec::Vec;

use crate::error::Error;

/// LZS sliding window size (RFC 2395 section 1.2).
pub const WINDOW_SIZE: usize = 2048;
/// Largest encodable copy offset (11-bit long form).
pub const MAX_OFFSET: usize = 2047;
/// Minimum match length encoded by the format.
pub const MIN_MATCH: usize = 2;

/// Sanity cap on a single match length. The chained `1111` nibble form
/// is open-ended, but a single match beyond 16 MiB is overwhelmingly
/// likely to be a corrupt or adversarial stream. The encoder splits
/// longer runs into multiple match tokens so its own output always
/// stays within this bound.
const MAX_MATCH: usize = 1 << 24;

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
            return Err(Error::InvalidData("lzs: truncated bitstream"));
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

    /// Flush pending bits, padding the final byte with `1` bits (the
    /// padding follows the end marker and carries no meaning).
    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out
                .push(((self.acc << (8 - self.nbits)) | ((1 << (8 - self.nbits)) - 1)) as u8);
        }
        self.out
    }
}

fn put_offset(w: &mut BitWriter, off: usize) {
    debug_assert!((1..=MAX_OFFSET).contains(&off));
    if off <= 127 {
        w.put(1, 1); // '1' + 7 bits
        w.put(off as u32, 7);
    } else {
        w.put(0, 1); // '0' + 11 bits
        w.put(off as u32, 11);
    }
}

fn put_length(w: &mut BitWriter, len: usize) {
    debug_assert!(len >= MIN_MATCH);
    match len {
        2 => w.put(0, 2),
        3 => w.put(1, 2),
        4 => w.put(2, 2),
        5 => w.put(0xC, 4),
        6 => w.put(0xD, 4),
        7 => w.put(0xE, 4),
        _ => {
            w.put(0xF, 4);
            let mut rest = len - 8;
            // Each '1111' nibble adds 15; the final nibble (< 15) adds
            // its raw value (RFC 2395 section 2.2 length table).
            while rest > 14 {
                w.put(0xF, 4);
                rest -= 15;
            }
            w.put(rest as u32, 4);
        }
    }
}

/// Encode `input` as a single LZS compressed payload, terminated by the
/// end marker and padded to a whole byte.
///
/// Match selection is a greedy single-candidate lookup, suitable as a
/// correctness baseline.
pub fn encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut w = BitWriter::new();
    // Greedy matcher: last-seen position per byte pair.
    let mut head = alloc::vec![-1i32; 1 << 16];
    let key = |a: u8, b: u8| -> usize { ((a as usize) << 8) | b as usize };

    let mut produced = 0usize;
    while produced < input.len() {
        let mut best_len = 0usize;
        let mut best_off = 0usize;
        if produced + MIN_MATCH <= input.len() {
            let k = key(input[produced], input[produced + 1]);
            let cand = head[k];
            head[k] = produced as i32;
            if cand >= 0 {
                let cp = cand as usize;
                // Cap matches at MAX_MATCH so own output stays within
                // the decoder's sanity bound; longer runs continue as
                // a following match token.
                let len = MIN_MATCH
                    + crate::compress::match_ops::match_len(
                        &input[cp + MIN_MATCH..],
                        &input[produced + MIN_MATCH..],
                        (MAX_MATCH - MIN_MATCH).min(input.len() - (produced + MIN_MATCH)),
                    );
                let off = produced - cp;
                if off <= MAX_OFFSET {
                    best_len = len;
                    best_off = off;
                }
            }
        }
        if best_len >= MIN_MATCH {
            w.put(1, 1);
            put_offset(&mut w, best_off);
            put_length(&mut w, best_len);
            for i in 0..best_len {
                let p = produced + i;
                if p + MIN_MATCH <= input.len() {
                    head[key(input[p], input[p + 1])] = p as i32;
                }
            }
            produced += best_len;
        } else {
            w.put(0, 1);
            w.put(input[produced] as u32, 8);
            produced += 1;
        }
    }
    // End marker: '1' (copy) + '1' (short offset) + 7 zero bits.
    w.put(0b110000000, 9);
    Ok(w.finish())
}

/// Decode a single LZS compressed payload. The payload must end with
/// the end marker; trailing bits and bytes after it are ignored as
/// padding (RFC 2395 section 2.3).
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_bounded(input, usize::MAX)
}

/// Decode a single LZS compressed payload, bounding total output.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let mut bits = Bits::new(input);
    let mut out: Vec<u8> = Vec::new();
    loop {
        if bits.get()? == 0 {
            let b = bits.get_bits(8)? as u8;
            if out.len() >= max_output {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            out.push(b);
            continue;
        }
        // Copy token: '1' + offset prefix bit.
        let off = if bits.get()? == 1 {
            let v = bits.get_bits(7)? as usize;
            if v == 0 {
                // End marker '110000000': the stream is complete.
                break;
            }
            v
        } else {
            let v = bits.get_bits(11)? as usize;
            if v == 0 {
                return Err(Error::InvalidData("lzs: reserved zero offset"));
            }
            v
        };
        let len = read_length(&mut bits)?;
        if off > out.len() {
            return Err(Error::InvalidData("lzs: offset exceeds history"));
        }
        if out.len() + len > max_output {
            return Err(Error::OutputLimitExceeded { limit: max_output });
        }
        crate::compress::match_ops::copy_match(&mut out, off, len)
            .map_err(|_| Error::InvalidData("lzs: offset exceeds history"))?;
    }
    Ok(out)
}

fn read_length(bits: &mut Bits<'_>) -> Result<usize, Error> {
    Ok(match bits.get_bits(2)? {
        0 => 2,
        1 => 3,
        2 => 4,
        _ => match bits.get_bits(2)? {
            0 => 5,
            1 => 6,
            2 => 7,
            _ => {
                let mut acc = 8usize;
                loop {
                    let nib = bits.get_bits(4)? as usize;
                    if nib != 0xF {
                        acc += nib;
                        break;
                    }
                    acc += 15;
                    if acc > MAX_MATCH {
                        return Err(Error::InvalidData("lzs: bad match length"));
                    }
                }
                acc
            }
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_emits_only_end_marker() {
        let enc = encode(&[]).unwrap();
        // '110000000' + 7 padding '1' bits = 0xC0 0x7F.
        assert_eq!(enc, vec![0xC0, 0x7F]);
        assert_eq!(decode(&enc).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn literal_only() {
        // 'A' = 0x41 -> '0' + 01000001, then end marker.
        let enc = encode(b"A").unwrap();
        assert_eq!(decode(&enc).unwrap(), b"A");
        assert_eq!(&enc[..1], &[0x20]); // '0' '010' MSB alignment check
    }

    #[test]
    fn hand_built_copy() {
        // '0'+0x41 literal 'A', then '1' '1' + 7-bit off=1, '01' len=3,
        // then end marker, padded with '1's.
        // bits: 0 01000001 | 1 1 0000001 | 01 | 110000000 | 111
        // = 0x20 0xE0 0x5C 0x07
        let data = [0x20u8, 0xE0, 0x5C, 0x07];
        assert_eq!(decode(&data).unwrap(), b"AAAA");
    }

    #[test]
    fn long_offset_form() {
        // 128-byte gap: 'A' literal, 127 literals, then copy off=128
        // (11-bit form '0' + 11 bits), len=2.
        let mut input = vec![b'A'];
        for i in 1..128u8 {
            input.push(b'A' + i % 26);
        }
        input.extend_from_slice(b"A?");
        let enc = encode(&input).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }

    #[test]
    fn long_match_length_chain() {
        // 200 identical bytes: produces a len>=8 chained length code.
        let input = vec![b'x'; 200];
        let enc = encode(&input).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }

    #[test]
    fn length_table_boundaries() {
        for len in 2..=40usize {
            let mut input = Vec::new();
            input.extend_from_slice(b"ab");
            input.extend(core::iter::repeat_n(b'z', len));
            let enc = encode(&input).unwrap();
            assert_eq!(decode(&enc).unwrap(), input, "len={len}");
        }
    }

    #[test]
    fn overlapping_copy() {
        let enc = encode(b"abcabcabcabc").unwrap();
        assert_eq!(decode(&enc).unwrap(), b"abcabcabcabc");
    }

    #[test]
    fn missing_end_marker_is_error() {
        // Single literal 'A', no end marker.
        assert!(decode(&[0x20, 0x80]).is_err());
    }

    #[test]
    fn empty_input_stream_is_error() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn reserved_long_zero_offset() {
        // '1' '0' + 11 zero bits = reserved long-offset 0.
        let data = [0x80u8, 0x00, 0x00];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn offset_exceeds_history() {
        // Literal 'A', then copy with off=2 (> produced=1), len=2.
        // bits: 0 01000001 | 1 1 0000010 | 00 | 110000000 | 111
        let data = [0x20u8, 0xE0, 0x8C, 0x07];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn truncated_match_length_chain() {
        // Literal 'A', copy off=1, then a '1111' nibble chain that is
        // cut off before the terminating nibble.
        let data = [0x20u8, 0xE0, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(decode(&data).is_err());
    }

    #[test]
    fn rejects_match_length_above_cap() {
        // Literal 'A', copy off=1, then a '1111' nibble chain that runs
        // past MAX_MATCH before the terminating nibble.
        let mut w = BitWriter::new();
        w.put(0, 1);
        w.put(b'A' as u32, 8);
        w.put(1, 1);
        w.put(1, 1);
        w.put(1, 7);
        w.put(3, 2); // '11' '11': enter the nibble chain at len=8
        w.put(3, 2);
        for _ in 0..(MAX_MATCH / 15 + 2) {
            w.put(0xF, 4);
        }
        w.put(0, 4);
        w.put(0b110000000, 9);
        assert!(decode(&w.finish()).is_err());
    }

    #[test]
    fn max_match_boundary_roundtrip() {
        // A single run longer than MAX_MATCH must be emitted as several
        // match tokens so the decoder accepts its own output.
        let input = alloc::vec![b'x'; MAX_MATCH + 1024];
        let enc = encode(&input).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }

    #[test]
    fn decode_bounded_limit() {
        let enc = encode(b"hello world hello world").unwrap();
        assert!(matches!(
            decode_bounded(&enc, 4),
            Err(Error::OutputLimitExceeded { .. })
        ));
    }

    #[test]
    fn trailing_padding_bytes_ignored() {
        let enc = encode(b"data").unwrap();
        let mut padded = enc.clone();
        padded.extend_from_slice(&[0xAB, 0xCD]);
        assert_eq!(decode(&padded).unwrap(), b"data");
    }

    #[test]
    fn roundtrip_varied() {
        let mut input = Vec::new();
        for i in 0..4096u32 {
            input.push((i.wrapping_mul(31).wrapping_add(i / 7)) as u8);
        }
        input.extend_from_slice(
            b"the quick brown fox jumps over the lazy dog"
                .repeat(20)
                .as_slice(),
        );
        let enc = encode(&input).unwrap();
        assert!(enc.len() < input.len());
        assert_eq!(decode(&enc).unwrap(), input);
    }

    #[test]
    fn window_distance_cap() {
        // A repetition just beyond MAX_OFFSET must not be encoded as a
        // match at that distance; decode must still roundtrip.
        let mut input = vec![0x55u8; 8];
        input.extend(core::iter::repeat_n(0u8, 2200));
        input.extend_from_slice(&[0x55u8; 8]);
        let enc = encode(&input).unwrap();
        assert_eq!(decode(&enc).unwrap(), input);
    }
}
