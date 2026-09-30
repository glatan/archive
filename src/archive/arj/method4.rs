//! ARJ method 4 ("fastest") decoder: an LZSS sliding window over a
//! 32 KiB (`0x8000`) ring, fed by an MSB-first bit stream of
//! literal/match tokens. There is no end marker — decoding stops once
//! `expected` bytes have been produced.
//!
//! Token format: a length/literal prefix of up to 7 leading one-bits
//! (each contributes `1 << k`) followed by that many suffix bits; a
//! value of 0 selects a literal (next 8 bits). Otherwise a match
//! follows: an offset prefix of up to 4 leading one-bits over an
//! exponent base of 9 (each contributes `1 << (9 + k)`) plus
//! `9 + k` suffix bits; distance = offset + 1, length = value + 2.
//!
//! Ported from the newtua_dos transliteration of XADMaster's
//! `XADARJFastestHandle` (LGPL-3.0-or-later).

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzh::bits::MsbReader;
use crate::error::Error;

/// Decode a method-4 payload to `expected` bytes.
pub(crate) fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 0x8000;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    if expected == 0 {
        return Ok(out);
    }
    let mut ring = vec![b' '; N];
    let mut w = 0usize;
    let mut r = MsbReader::new(input);

    while out.len() < expected {
        // Length/literal prefix: up to 7 one-bits, then `pow` suffix bits.
        let mut val = 0u32;
        let mut pow = 0u32;
        while pow < 7 && r.get(1) != 0 {
            val += 1 << pow;
            pow += 1;
        }
        if pow > 0 {
            val += r.get(pow);
        }
        if r.overran() {
            return Err(Error::InvalidData("arj: truncated method 4 stream"));
        }

        if val == 0 {
            let b = r.get(8) as u8;
            if r.overran() {
                return Err(Error::InvalidData("arj: truncated method 4 stream"));
            }
            out.push(b);
            ring[w] = b;
            w = (w + 1) & (N - 1);
        } else {
            // Offset prefix: up to 4 one-bits over an exponent base of 9.
            let mut offs = 0u32;
            let mut pow = 9u32;
            while pow < 13 && r.get(1) != 0 {
                offs += 1 << pow;
                pow += 1;
            }
            offs += r.get(pow);
            if r.overran() {
                return Err(Error::InvalidData("arj: truncated method 4 stream"));
            }
            let dist = (offs + 1) as usize;
            let len = (val + 2) as usize;
            if dist > N {
                return Err(Error::InvalidData("arj: method 4 distance out of window"));
            }
            let mut src = (w + N - dist) & (N - 1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::lzh::bits::MsbWriter;

    /// Mirror encoder: literals are a 0-bit + 8-bit byte; a match is
    /// the exponent-coded length prefix and offset prefix.
    fn encode_lit(b: u8, w: &mut MsbWriter) {
        w.put(0, 1);
        w.put(b as u32, 8);
    }

    fn encode_match(len: usize, dist: usize, w: &mut MsbWriter) {
        let val = (len - 2) as u32;
        let mut k = 0u32;
        while k < 7 && (1u32 << (k + 1)) - 1 <= val {
            k += 1;
        }
        for _ in 0..k {
            w.put(1, 1);
        }
        if k < 7 {
            w.put(0, 1);
        }
        if k > 0 {
            w.put(val - ((1u32 << k) - 1), k);
        }
        let v = (dist - 1) as u32;
        let mut m = 0u32;
        while m < 4 && v >= 512 * ((1u32 << (m + 1)) - 1) {
            m += 1;
        }
        for _ in 0..m {
            w.put(1, 1);
        }
        if m < 4 {
            w.put(0, 1);
        }
        w.put(v - 512 * ((1u32 << m) - 1), 9 + m);
    }

    #[test]
    fn literals_only() {
        let mut w = MsbWriter::new();
        for &b in b"arj!" {
            encode_lit(b, &mut w);
        }
        assert_eq!(decode(&w.finish(), 4).unwrap(), b"arj!");
    }

    #[test]
    fn match_copies() {
        let mut w = MsbWriter::new();
        for &b in b"abcd" {
            encode_lit(b, &mut w);
        }
        encode_match(5, 4, &mut w); // copy "abcda" wait: dist 4 copies abcd then a
        encode_match(3, 1, &mut w); // overlapping run
        let out = decode(&w.finish(), 12).unwrap();
        assert_eq!(&out[..4], b"abcd");
        assert_eq!(&out[4..9], b"abcda");
        assert_eq!(&out[9..12], b"aaa");
    }

    #[test]
    fn rejects_truncated() {
        let mut w = MsbWriter::new();
        encode_lit(b'x', &mut w);
        let payload = w.finish();
        assert!(decode(&payload[..1], 4).is_err());
        assert!(decode(&[], 1).is_err());
    }
}
