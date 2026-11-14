//! PackBits run-length encoding (Apple Technical Note TN1023;
//! TIFF 6.0 §9 compression code 32773).
//!
//! Each packet starts with a flag-counter byte `n` (interpreted as signed):
//! `0..=127` copies `n+1` literal bytes, `-127..=-1` repeats the following
//! byte `1-n` times, and `-128` is a reserved no-op.

use alloc::vec::Vec;

use crate::error::Error;

/// Decode a PackBits stream.
///
/// `-128` flag bytes are ignored (no-op), per TIFF §9. Truncated literal
/// or run packets return [`Error::UnexpectedEof`].
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let flag = input[pos] as i8;
        pos += 1;
        match flag {
            0..=127 => {
                let len = flag as usize + 1;
                if pos + len > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                out.extend_from_slice(&input[pos..pos + len]);
                pos += len;
            }
            -128 => {}
            _ => {
                if pos >= input.len() {
                    return Err(Error::UnexpectedEof);
                }
                let byte = input[pos];
                pos += 1;
                let count = 1i16 - flag as i16;
                out.extend(core::iter::repeat_n(byte, count as usize));
            }
        }
    }
    Ok(out)
}

/// Encode `data` as a PackBits stream.
///
/// Runs of three or more identical bytes are emitted as repeat packets;
/// shorter runs and non-repeating data are emitted as literal packets of at
/// most 128 bytes. This matches the behavior documented for the Apple
/// Toolbox `PackBits` call in TN1023.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 127 + 1);
    let mut literal_start = 0usize;
    let mut i = 0usize;
    while i < data.len() {
        let repeated = [data[i]; 127];
        let run = 1 + crate::compress::match_ops::match_len(&data[i + 1..], &repeated, 127);
        if run >= 3 {
            // Flush pending literals.
            flush_literal(&mut out, &data[literal_start..i]);
            // Emit the run in packets of at most 128.
            let mut remaining = run;
            while remaining > 0 {
                let n = remaining.min(128);
                out.push((1i16 - n as i16) as i8 as u8);
                out.push(data[i]);
                remaining -= n;
            }
            i += run;
            literal_start = i;
        } else {
            i += run;
            // Split overly long literal spans.
            if i - literal_start == 128 {
                flush_literal(&mut out, &data[literal_start..i]);
                literal_start = i;
            }
        }
    }
    flush_literal(&mut out, &data[literal_start..]);
    out
}

fn flush_literal(out: &mut Vec<u8>, lit: &[u8]) {
    for chunk in lit.chunks(128) {
        out.push(chunk.len() as u8 - 1);
        out.extend_from_slice(chunk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for data in [
            &b"aaaaabbbccddddddddddxyz"[..],
            &[0xAA; 300],
            b"no runs at all here".as_slice(),
            &[1, 2, 3, 4, 4, 4, 5],
            &[],
            &[7],
        ] {
            let enc = encode(data);
            assert_eq!(decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn literal_packet() {
        // "a b c d" as one literal packet: flag 0x03 + 4 bytes.
        let enc = encode(b"abcd");
        assert_eq!(&enc[..], b"\x03abcd");
    }

    #[test]
    fn repeat_packet() {
        // 5 x 'x': flag = 1-5 = -4 = 0xFC, byte 'x'.
        let enc = encode(b"xxxxx");
        assert_eq!(&enc[..], b"\xfcx");
        // 128-byte run fits one packet.
        let enc128 = encode(&[0x55; 128]);
        assert_eq!(&enc128[..], b"\x81\x55");
        // 129-byte run: one 128-run packet + trailing literal byte.
        let enc129 = encode(&[0x55; 129]);
        assert_eq!(&enc129[..], b"\x81\x55\x00\x55");
    }

    #[test]
    fn literal_packet_splits_at_128() {
        // 129 non-repeating bytes -> 128-byte literal packet + 1-byte packet.
        let data: Vec<u8> = (0..129u16).map(|i| (i % 251) as u8).collect();
        // ensure no 3-byte run exists in the data (all literals)
        let enc = encode(&data);
        let mut flags = Vec::new();
        let mut i = 0;
        while i < enc.len() {
            flags.push(enc[i]);
            let n = enc[i] as i8;
            i += 1 + if n >= 0 {
                n as usize + 1
            } else if n == -128 {
                0
            } else {
                1
            };
        }
        assert_eq!(flags, [127, 0]);
        // -128 (0x80) is never emitted as a flag (TN1023).
        assert!(!flags.contains(&0x80));
        assert_eq!(decode(&enc).unwrap(), data);
    }

    #[test]
    fn two_byte_run_stays_literal() {
        // Runs shorter than 3 are encoded literally.
        let enc = encode(b"aabb");
        assert_eq!(&enc[..], b"\x03aabb");
    }

    #[test]
    fn nop_flag_ignored() {
        // 0x80 flag = no-op.
        assert_eq!(decode(b"\x80\x00x").unwrap(), b"x");
        assert_eq!(decode(b"\x80").unwrap(), b"");
    }

    #[test]
    fn truncated_rejected() {
        assert!(matches!(decode(b"\x05ab"), Err(Error::UnexpectedEof)));
        assert!(matches!(decode(b"\xfc"), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn decode_known_vector() {
        // Hand-computed per TN1023: literal(2)[a b] + repeat(3)[c] + NOP +
        // literal(1)[d].
        let enc = [0x01, b'a', b'b', 0xFE, b'c', 0x80, 0x00, b'd'];
        assert_eq!(decode(&enc).unwrap(), b"abcccd");
    }

    #[test]
    fn tn1023_worked_example() {
        // Apple TN1023 reference vector: unpacked data and its PackBits
        // encoding, reproduced byte-for-byte by the reference encoder.
        let unpacked: [u8; 24] = [
            0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0x22,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        ];
        let packed: &[u8] = &[
            0xFE, 0xAA, 0x02, 0x80, 0x00, 0x2A, 0xFD, 0xAA, 0x03, 0x80, 0x00, 0x2A, 0x22, 0xF7,
            0xAA,
        ];
        assert_eq!(decode(packed).unwrap(), unpacked);
        assert_eq!(encode(&unpacked), packed);
    }

    #[test]
    fn worst_case_bound() {
        // TN1023: MaxdestBytes = srcBytes + (srcBytes+126)/127.
        let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let enc = encode(&data);
        assert!(enc.len() <= data.len() + data.len().div_ceil(127));
    }

    #[test]
    fn truncated_prefix_invariant() {
        // Packets are self-delimiting, so a cut at a packet boundary
        // yields a valid shorter output; every other cut must fail.
        // Invariant: decode(prefix) is Err or a prefix of the full
        // decoded output.
        let data = b"aaabbbbbbbbxyzzzzzzzzzzzzzzzzzzzqrrrr";
        let enc = encode(data);
        let full = decode(&enc).unwrap();
        for cut in 0..enc.len() {
            if let Ok(prefix) = decode(&enc[..cut]) {
                assert!(
                    full.starts_with(&prefix),
                    "cut={cut}: output must be a prefix"
                );
            }
        }
    }
}

// NOTE: a Kani bounded no-panic proof over 16-byte inputs was attempted and
// removed — symbolic output growth through `extend`/`repeat` folds exhausts
// the solver budget even at that size. Malformed-input coverage stays with
// the corrupt fuzz lane.
