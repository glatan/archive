//! Base64 codec ([RFC 4648] section 4).
//!
//! Used by the POSIX.1-2017 uuencode Base64 algorithm (begin-base64).
//! The decoder is canonical: it rejects characters outside the standard
//! alphabet, input whose length is not a multiple of four, misplaced or
//! excessive '=' padding, data after padding, and non-zero pad bits.
//!
//! [RFC 4648]: https://datatracker.ietf.org/doc/html/rfc4648

use alloc::vec::Vec;

use crate::error::Error;

/// Standard Base64 alphabet (RFC 4648 section 4).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode a single Base64 alphabet character to its 6-bit value.
fn dec_char(c: u8) -> Result<u8, Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Error::InvalidData("base64: invalid character")),
    }
}

/// Encode `data` with the standard Base64 alphabet and '=' padding.
///
/// The output contains no line breaks; callers wrap lines as their format
/// requires.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for trio in data.chunks(3) {
        let a = trio[0] as u32;
        let b = *trio.get(1).unwrap_or(&0) as u32;
        let c = *trio.get(2).unwrap_or(&0) as u32;
        out.push(ALPHABET[(a >> 2) as usize]);
        out.push(ALPHABET[(((a << 4) | (b >> 4)) & 0x3F) as usize]);
        if trio.len() == 1 {
            out.push(b'=');
            out.push(b'=');
            continue;
        }
        out.push(ALPHABET[(((b << 2) | (c >> 6)) & 0x3F) as usize]);
        if trio.len() == 2 {
            out.push(b'=');
            continue;
        }
        out.push(ALPHABET[(c & 0x3F) as usize]);
    }
    out
}

/// Decode standard Base64 input to octets.
///
/// Only the canonical form is accepted: '=' padding may appear solely in
/// the final quantum as "xx==" or "xxx=", and the bits not covering input
/// data must be zero.
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    if !input.len().is_multiple_of(4) {
        return Err(Error::InvalidData("base64: bad length"));
    }
    let n_quads = input.len() / 4;
    let mut out = Vec::with_capacity(n_quads * 3);
    let (quads, _) = input.as_chunks::<4>();
    for (i, quad) in quads.iter().enumerate() {
        let last = i + 1 == n_quads;
        let pad = quad.iter().filter(|&&b| b == b'=').count();
        if pad > 0 {
            // Padding is only legal as "xx==" or "xxx=" in the final
            // quantum; anything after '=' is rejected with it.
            let ok = last
                && match pad {
                    1 => quad[3] == b'=',
                    2 => quad[2] == b'=' && quad[3] == b'=',
                    _ => false,
                };
            if !ok {
                return Err(Error::InvalidData("base64: bad padding"));
            }
        }
        let v0 = dec_char(quad[0])? as u32;
        let v1 = dec_char(quad[1])? as u32;
        out.push((v0 << 2 | v1 >> 4) as u8);
        if pad == 2 {
            if v1 & 0x0F != 0 {
                return Err(Error::InvalidData("base64: non-canonical pad bits"));
            }
            continue;
        }
        let v2 = dec_char(quad[2])? as u32;
        out.push((v1 << 4 | v2 >> 2) as u8);
        if pad == 1 {
            if v2 & 0x03 != 0 {
                return Err(Error::InvalidData("base64: non-canonical pad bits"));
            }
            continue;
        }
        let v3 = dec_char(quad[3])? as u32;
        out.push((v2 << 6 | v3) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 section 10 test vectors.
    const VECTORS: &[(&[u8], &[u8])] = &[
        (b"", b""),
        (b"f", b"Zg=="),
        (b"fo", b"Zm8="),
        (b"foo", b"Zm9v"),
        (b"foob", b"Zm9vYg=="),
        (b"fooba", b"Zm9vYmE="),
        (b"foobar", b"Zm9vYmFy"),
    ];

    #[test]
    fn test_rfc4648_vectors() {
        for (plain, coded) in VECTORS {
            assert_eq!(&encode(plain), coded);
            assert_eq!(decode(coded).unwrap(), *plain);
        }
    }

    #[test]
    fn test_roundtrip_binary() {
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&data)).unwrap(), data);
    }

    #[test]
    fn test_rejects_bad_length() {
        assert!(matches!(
            decode(b"Zg="),
            Err(Error::InvalidData("base64: bad length"))
        ));
    }

    #[test]
    fn test_rejects_invalid_character() {
        assert!(matches!(
            decode(b"Zg!~"),
            Err(Error::InvalidData("base64: invalid character"))
        ));
        // Whitespace is not skipped by the canonical codec itself.
        assert!(decode(b"Zm9v\n").is_err());
    }

    #[test]
    fn test_rejects_bad_padding() {
        // '=' must appear only as "xx==" or "xxx=" in the last quantum.
        for bad in [
            &b"=m9v"[..],
            b"Zm=v",
            b"Z===",
            b"====",
            b"Zg==Zg==",
            b"Zm9v====",
        ] {
            assert!(decode(bad).is_err(), "input {bad:?} must be rejected");
        }
    }

    #[test]
    fn test_rejects_noncanonical_pad_bits() {
        // 'h' has non-zero low 4 bits; '9' has non-zero low 2 bits.
        assert!(decode(b"Zh==").is_err());
        assert!(decode(b"Zm9=").is_err());
        // Canonical encodings of the same octets are accepted.
        assert_eq!(decode(b"Zg==").unwrap(), b"f");
        assert_eq!(decode(b"Zm8=").unwrap(), b"fo");
    }

    #[test]
    fn test_empty() {
        assert_eq!(encode(b""), Vec::<u8>::new());
        assert_eq!(decode(b"").unwrap(), Vec::<u8>::new());
    }
}
