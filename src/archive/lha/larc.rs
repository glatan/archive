//! LArc `-lzs-` and `-lz5-` decoders (old LArc-era LZSS variants
//! carried inside LHA-style member headers).
//!
//! `-lzs-` is a bit-level command stream: a 1 bit introduces an
//! 8-bit literal, a 0 bit introduces an 11-bit absolute ring position
//! and a 4-bit length (+2). The ring is 2048 bytes of spaces with the
//! write head starting 17 bytes before the end.
//!
//! `-lz5-` is byte oriented: a control byte carries eight commands;
//! a set bit is a literal byte, a clear bit is a 2-byte copy command
//! holding a 12-bit absolute ring position and a 4-bit length (+3).
//! The ring is 4096 bytes prefilled with a fixed pattern and the
//! write head starts 18 bytes before the end.
//!
//! `-lz4-` is simply stored data (the `null` decoder), like `-lh0-`.
//!
//! Format references: `-lzs-` is the `EI=11`/`EJ=4` instantiation
//! of Haruhiko Okumura's `lzss.c` (1988, released to the public
//! domain on the author's site; LArc adopted that bitstream
//! verbatim). `-lz5-` is the LArc 4.x byte-oriented variant whose
//! only rights-clear reference is lhasa `lz5_decoder.c` (ISC);
//! behaviour cross-checked against lhasa `lzs_decoder.c` too.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use crate::compress::lzh::bits::MsbReader;

/// Decode `-lzs-` to `expected` bytes.
fn decode_lzs(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 2048;
    const START: usize = 17;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    let mut ring = vec![b' '; N];
    let mut w = N - START;
    let mut r = MsbReader::new(input);
    while out.len() < expected {
        if r.get(1) != 0 {
            let b = r.get(8) as u8;
            out.push(b);
            ring[w] = b;
            w = (w + 1) % N;
        } else {
            let pos = usize::try_from(r.get(11)).unwrap_or(0);
            let len = usize::try_from(r.get(4)).unwrap_or(0) + 2;
            for i in 0..len {
                if out.len() >= expected {
                    break;
                }
                let v = ring[(pos + i) % N];
                out.push(v);
                ring[w] = v;
                w = (w + 1) % N;
            }
        }
        if r.overran() {
            return Err(Error::InvalidData("lha: truncated lzs stream"));
        }
    }
    Ok(out)
}

/// The fixed `-lz5-` ring prefill: 256 runs of 13, ascending and
/// descending byte sequences, then zeros, spaces, zeros (4096 total).
fn lz5_initial() -> Vec<u8> {
    let mut v = Vec::with_capacity(4096);
    for i in 0..256u16 {
        v.extend(core::iter::repeat_n(i as u8, 13));
    }
    for i in 0..256u16 {
        v.push(i as u8);
    }
    for i in 0..256u16 {
        v.push((255 - i) as u8);
    }
    v.extend(core::iter::repeat_n(0u8, 128));
    v.extend(core::iter::repeat_n(b' ', 110));
    v.extend(core::iter::repeat_n(0u8, 18));
    v
}

/// Decode `-lz5-` to `expected` bytes.
fn decode_lz5(input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    const N: usize = 4096;
    const START: usize = 18;
    let mut out = Vec::with_capacity(expected.min(1 << 24));
    let mut ring = lz5_initial();
    let mut w = N - START;
    let mut pos = 0usize;
    while out.len() < expected {
        let bitmap = *input
            .get(pos)
            .ok_or(Error::InvalidData("lha: truncated lz5 stream"))?;
        pos += 1;
        for bit in 0..8 {
            if out.len() >= expected {
                break;
            }
            if bitmap & (1 << bit) != 0 {
                let b = *input
                    .get(pos)
                    .ok_or(Error::InvalidData("lha: truncated lz5 stream"))?;
                pos += 1;
                out.push(b);
                ring[w] = b;
                w = (w + 1) % N;
            } else {
                let pair_end = pos
                    .checked_add(2)
                    .ok_or(Error::InvalidData("lha: truncated lz5 stream"))?;
                let c = input
                    .get(pos..pair_end)
                    .ok_or(Error::InvalidData("lha: truncated lz5 stream"))?;
                pos = pair_end;
                let start = (usize::from(c[1] & 0xf0) << 4) | usize::from(c[0]);
                let len = usize::from(c[1] & 0x0f) + 3;
                for i in 0..len {
                    if out.len() >= expected {
                        break;
                    }
                    let v = ring[(start + i) % N];
                    out.push(v);
                    ring[w] = v;
                    w = (w + 1) % N;
                }
            }
        }
    }
    Ok(out)
}

/// `true` when `method` is handled by this module (`-lzs-`, `-lz5-`;
/// `-lz4-` is stored and handled by the caller).
pub(crate) fn supported(method: &[u8; 5]) -> bool {
    matches!(method, b"-lzs-" | b"-lz5-")
}

/// Decode a LArc payload to `expected` bytes.
pub(crate) fn decode(method: &[u8; 5], input: &[u8], expected: usize) -> Result<Vec<u8>, Error> {
    match method {
        b"-lzs-" => decode_lzs(input, expected),
        b"-lz5-" => decode_lz5(input, expected),
        _ => Err(Error::Unsupported("lha: unsupported method")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_only_larc_compressed_methods() {
        assert!(supported(b"-lzs-"));
        assert!(supported(b"-lz5-"));
        assert!(!supported(b"-lz4-"));
        assert!(!supported(b"-lh5-"));
    }

    #[test]
    fn decode_rejects_unsupported_methods_and_malformed_payloads() {
        assert!(matches!(
            decode(b"-lh5-", &[], 0),
            Err(Error::Unsupported("lha: unsupported method"))
        ));
        assert!(decode(b"-lzs-", &[], 1).is_err());
        assert!(decode(b"-lz5-", &[], 1).is_err());
    }
}
