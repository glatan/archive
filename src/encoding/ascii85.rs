//! Ascii85 (Adobe `ASCII85Decode` filter, PDF 32000-1:2008 §7.4.3) and the
//! RFC 1924 Base-85 encoding.
//!
//! Adobe Ascii85 maps groups of 4 octets to 5 characters from `!`..`u`
//! (33..=117); the group `0x00000000` may be written as `z`. Streams may be
//! bracketed by `<~` and `~>`; whitespace inside the data is ignored. A final
//! partial group of `n` octets encodes as `n+1` characters.
//!
//! RFC 1924 defines a different fixed-width encoding for exactly 16 octets
//! (20 characters over the alphabet `0-9 A-Z a-z !#$%&()*+-;<=>?@^_`{|}~`).
//! It is exposed separately via [`encode_rfc1924`] / [`decode_rfc1924`].

use alloc::vec::Vec;

use crate::error::Error;

const ADOBE_BASE: u8 = b'!';
const ADOBE_MAX: u8 = b'u';
const ADOBE_SHORTHAND: u8 = b'z';

const RFC1924_ALPHABET: &[u8; 85] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

fn is_ws(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}

fn push_group(out: &mut Vec<u8>, value: u32) {
    let mut digits = [0u8; 5];
    let mut v = value;
    for d in digits.iter_mut().rev() {
        *d = (v % 85) as u8;
        v /= 85;
    }
    for d in digits {
        out.push(d + ADOBE_BASE);
    }
}

/// Encode `data` as an Adobe Ascii85 stream bracketed by `<~` and `~>`.
pub fn encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 4 * 5 + 4);
    out.extend_from_slice(b"<~");
    let (chunks, rem) = data.as_chunks::<4>();
    for chunk in chunks {
        let value = u32::from_be_bytes(*chunk);
        if value == 0 {
            out.push(ADOBE_SHORTHAND);
        } else {
            push_group(&mut out, value);
        }
    }
    if !rem.is_empty() {
        let mut buf = [0u8; 4];
        buf[..rem.len()].copy_from_slice(rem);
        let mut tmp = Vec::with_capacity(5);
        push_group(&mut tmp, u32::from_be_bytes(buf));
        out.extend_from_slice(&tmp[..rem.len() + 1]);
    }
    out.extend_from_slice(b"~>");
    out
}

fn decode_group(out: &mut Vec<u8>, digits: &[u8]) {
    // 85^5-1 exceeds u32::MAX; wrap like reference decoders (u64 accumulate,
    // low 32 bits) rather than rejecting out-of-range groups.
    let mut v: u64 = 0;
    for &d in digits {
        v = v * 85 + u64::from(d - ADOBE_BASE);
    }
    out.extend_from_slice(&(v as u32).to_be_bytes());
}

/// Decode an Adobe Ascii85 stream.
///
/// `<~`/`~>` brackets are optional. Whitespace is ignored; `z` decodes to
/// four zero octets. `y` (a btoa extension) is rejected.
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut i = input;
    if i.starts_with(b"<~") {
        i = &i[2..];
    }
    if i.ends_with(b"~>") {
        i = &i[..i.len() - 2];
    }

    let mut out = Vec::new();
    let mut group = Vec::with_capacity(5);
    for &c in i {
        if is_ws(c) {
            continue;
        }
        if c == b'~' {
            // Stray '>' without opening bracket: reject unless it is the
            // final two bytes, which was stripped above.
            return Err(Error::InvalidData("ascii85: misplaced '~'"));
        }
        if c == ADOBE_SHORTHAND {
            if !group.is_empty() {
                return Err(Error::InvalidData("ascii85: 'z' inside group"));
            }
            out.extend_from_slice(&[0; 4]);
            continue;
        }
        if c == b'y' {
            return Err(Error::Unsupported("ascii85: 'y' is a btoa extension"));
        }
        if !(ADOBE_BASE..=ADOBE_MAX).contains(&c) {
            return Err(Error::InvalidData("ascii85: invalid character"));
        }
        group.push(c);
        if group.len() == 5 {
            decode_group(&mut out, &group);
            group.clear();
        }
    }
    match group.len() {
        0 => {}
        1 => return Err(Error::InvalidData("ascii85: single-char tail")),
        n => {
            let mut padded = [ADOBE_MAX; 5];
            padded[..n].copy_from_slice(&group);
            let mut tmp = Vec::with_capacity(4);
            decode_group(&mut tmp, &padded);
            out.extend_from_slice(&tmp[..n - 1]);
        }
    }
    Ok(out)
}

/// Encode exactly 16 octets as 20 RFC 1924 Base-85 characters.
pub fn encode_rfc1924(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() != 16 {
        return Err(Error::InvalidData("ascii85: rfc1924 requires 16 octets"));
    }
    let mut v = u128::from_be_bytes(data.try_into().unwrap());
    let mut out = vec![0u8; 20];
    for d in out.iter_mut().rev() {
        *d = RFC1924_ALPHABET[(v % 85) as usize];
        v /= 85;
    }
    Ok(out)
}

/// Decode 20 RFC 1924 Base-85 characters back to 16 octets.
///
/// This function does not panic on malformed input.
pub fn decode_rfc1924(input: &[u8]) -> Result<Vec<u8>, Error> {
    let chars: Vec<u8> = input.iter().copied().filter(|&c| !is_ws(c)).collect();
    if chars.len() != 20 {
        return Err(Error::InvalidData("ascii85: rfc1924 requires 20 chars"));
    }
    let mut v: u128 = 0;
    for &c in &chars {
        let idx = RFC1924_ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(Error::InvalidData("ascii85: invalid rfc1924 character"))?;
        v = v * 85 + idx as u128;
    }
    Ok(v.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adobe_roundtrip() {
        for data in [
            &b"Man "[..],
            b"Man is distinguished".as_slice(),
            &[0u8; 8],
            &[1, 2, 3],
            &[],
        ] {
            let enc = encode(data);
            assert_eq!(decode(&enc).unwrap(), data);
        }
    }

    #[test]
    fn adobe_wikipedia_example() {
        // Well-known Ascii85 example: "Man " -> "9jqo^" ... full text.
        let plain = b"Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
        let enc = encode(plain);
        let enc_str = String::from_utf8(enc).unwrap();
        assert!(enc_str.starts_with("<~9jqo^BlbD-BleB1DJ+*+F(f,q"));
        assert!(enc_str.ends_with("~>"));
        assert_eq!(decode(enc_str.as_bytes()).unwrap(), plain);
    }

    #[test]
    fn adobe_z_shorthand() {
        let enc = encode(&[0; 4]);
        assert_eq!(&enc[..], b"<~z~>");
        assert_eq!(decode(b"z").unwrap(), [0; 4]);
        // 'z' may not appear inside a group.
        assert!(!decode(b"zz9jq").is_err());
        assert!(decode(b"9jqz").is_err());
    }

    #[test]
    fn adobe_whitespace_and_no_delims() {
        assert_eq!(decode(b"9j qo^ \nBlbD-").unwrap(), b"Man is d");
        assert!(decode(b"<~9jqo^~>").is_ok());
    }

    #[test]
    fn adobe_rejects_y_and_junk() {
        assert!(matches!(decode(b"y"), Err(Error::Unsupported(_))));
        assert!(matches!(decode(b"x~"), Err(Error::InvalidData(_))));
    }

    #[test]
    fn adobe_partial_tail() {
        // 3-octet tail -> 4 chars; 1-octet tail -> 2 chars; single char rejected.
        let enc = encode(&[0xFF, 0xFE, 0xFD]);
        assert_eq!(enc.len(), 2 + 4 + 2);
        assert_eq!(decode(&enc).unwrap(), [0xFF, 0xFE, 0xFD]);
        assert!(decode(b"!").is_err());
    }

    #[test]
    fn rfc1924_example() {
        // RFC 1924: the IPv6 address 1080:0:0:0:8:800:200C:417A encodes as
        // "4)+k&C#VzJ4br>0wv%Yp" (RFC example text).
        let addr: [u8; 16] = [
            0x10, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x08, 0x00, 0x20, 0x0C, 0x41, 0x7A,
        ];
        let enc = encode_rfc1924(&addr).unwrap();
        assert_eq!(&enc[..], b"4)+k&C#VzJ4br>0wv%Yp");
        assert_eq!(decode_rfc1924(&enc).unwrap(), addr);
    }

    #[test]
    fn rfc1924_lengths() {
        assert!(encode_rfc1924(&[0; 15]).is_err());
        assert!(decode_rfc1924(b"0123456789012345678").is_err());
        assert!(decode_rfc1924(b"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"").is_err());
    }
}
