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
///
/// On x86_64 and aarch64, pairs of 4-byte groups take the vector
/// division path. A zero group is still the single character `z`.
pub fn encode(data: &[u8]) -> Vec<u8> {
    encode_inner(data, true)
}

#[cfg(test)]
fn encode_scalar(data: &[u8]) -> Vec<u8> {
    encode_inner(data, false)
}

fn encode_inner(data: &[u8], wide: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() / 4 * 5 + 4);
    out.extend_from_slice(b"<~");
    let (chunks, rem) = data.as_chunks::<4>();
    let mut i = 0;
    if wide {
        while i + 1 < chunks.len() {
            let a = u32::from_be_bytes(chunks[i]);
            let b = u32::from_be_bytes(chunks[i + 1]);
            let (da, db) = digits_pair(a, b);
            emit_group(&mut out, a, &da);
            emit_group(&mut out, b, &db);
            i += 2;
        }
    }
    for chunk in &chunks[i..] {
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

fn emit_group(out: &mut Vec<u8>, value: u32, digits: &[u8; 5]) {
    if value == 0 {
        out.push(ADOBE_SHORTHAND);
        return;
    }
    for &d in digits {
        out.push(d + ADOBE_BASE);
    }
}

fn digits_pair(a: u32, b: u32) -> ([u8; 5], [u8; 5]) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        digits_pair_sse2(a, b)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        digits_pair_neon(a, b)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    (digits_scalar(a), digits_scalar(b))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn digits_scalar(mut value: u32) -> [u8; 5] {
    let mut digits = [0u8; 5];
    for d in digits.iter_mut().rev() {
        let q = ((u64::from(value) * 3_233_857_729) >> 38) as u32;
        *d = (value - q * 85) as u8;
        value = q;
    }
    digits
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
fn digits_pair_sse2(mut a: u32, mut b: u32) -> ([u8; 5], [u8; 5]) {
    let mut da = [0u8; 5];
    let mut db = [0u8; 5];
    for slot in (0..5).rev() {
        let (qa, ra, qb, rb) = divmod85_sse2(a, b);
        da[slot] = ra;
        db[slot] = rb;
        a = qa;
        b = qb;
    }
    (da, db)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
fn divmod85_sse2(a: u32, b: u32) -> (u32, u8, u32, u8) {
    use core::arch::x86_64::{
        _mm_cvtsi128_si64, _mm_mul_epu32, _mm_set_epi64x, _mm_srli_epi64, _mm_srli_si128,
        _mm_sub_epi64,
    };
    let v = _mm_set_epi64x(i64::from(b), i64::from(a));
    let magic = _mm_set_epi64x(3_233_857_729, 3_233_857_729);
    let q = _mm_srli_epi64(_mm_mul_epu32(v, magic), 38);
    let prod85 = _mm_mul_epu32(q, _mm_set_epi64x(85, 85));
    let r = _mm_sub_epi64(v, prod85);
    let qa = _mm_cvtsi128_si64(q) as u32;
    let ra = _mm_cvtsi128_si64(r) as u8;
    let qb = _mm_cvtsi128_si64(_mm_srli_si128(q, 8)) as u32;
    let rb = _mm_cvtsi128_si64(_mm_srli_si128(r, 8)) as u8;
    (qa, ra, qb, rb)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn digits_pair_neon(mut a: u32, mut b: u32) -> ([u8; 5], [u8; 5]) {
    let mut da = [0u8; 5];
    let mut db = [0u8; 5];
    for slot in (0..5).rev() {
        let (qa, ra, qb, rb) = divmod85_neon(a, b);
        da[slot] = ra;
        db[slot] = rb;
        a = qa;
        b = qb;
    }
    (da, db)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn divmod85_neon(a: u32, b: u32) -> (u32, u8, u32, u8) {
    use core::arch::aarch64::{
        vcreate_u32, vget_lane_u32, vmovl_u32, vmovn_u64, vmull_u32, vshrq_n_u64, vsubq_u64,
    };
    let pair = vcreate_u32(u64::from(a) | (u64::from(b) << 32));
    let magic = vcreate_u32(3_233_857_729 | (3_233_857_729 << 32));
    let q = vshrq_n_u64(vmull_u32(pair, magic), 38);
    let eightyfive = vcreate_u32(85 | (85 << 32));
    let r = vsubq_u64(vmovl_u32(pair), vmull_u32(vmovn_u64(q), eightyfive));
    let qn = vmovn_u64(q);
    let rn = vmovn_u64(r);
    (
        vget_lane_u32(qn, 0),
        vget_lane_u32(rn, 0) as u8,
        vget_lane_u32(qn, 1),
        vget_lane_u32(rn, 1) as u8,
    )
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
        // 85^20 exceeds u128::MAX; reject out-of-range encodings rather
        // than overflowing (which would panic in debug builds).
        v = v
            .checked_mul(85)
            .and_then(|v| v.checked_add(idx as u128))
            .ok_or(Error::InvalidData("ascii85: rfc1924 value out of range"))?;
    }
    Ok(v.to_be_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_matches_scalar_lengths() {
        let patterns = [
            &[][..],
            &[0],
            &[0, 0],
            &[0, 0, 0],
            &[0, 0, 0, 0],
            &[0, 0, 0, 0, 1],
            &[1, 2, 3],
            &[1, 2, 3, 4],
            &[1, 2, 3, 4, 5, 6, 7],
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1],
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        ];
        for data in patterns {
            assert_eq!(encode(data), encode_scalar(data), "{}", data.len());
        }
        let mut mixed = vec![0u8; 4];
        mixed.extend(1u8..=17);
        assert_eq!(encode(&mixed), encode_scalar(&mixed));
    }

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
    fn adobe_group_overflow_wraps() {
        // `uuuuu` is 85^5-1 = 4437053124, which exceeds u32::MAX; like
        // reference decoders the value wraps to the low 32 bits.
        assert_eq!(decode(b"uuuuu").unwrap(), 142_085_828u32.to_be_bytes());
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

    #[test]
    fn rfc1924_overflow_rejected() {
        // 85^20-1 > u128::MAX: twenty `~` digits must be rejected, not
        // overflow (debug panic) or wrap.
        assert!(matches!(
            decode_rfc1924(b"~~~~~~~~~~~~~~~~~~~~"),
            Err(Error::InvalidData(_))
        ));
        // Largest representable value is still accepted.
        assert!(decode_rfc1924(&encode_rfc1924(&[0xFF; 16]).unwrap()).is_ok());
    }

    #[test]
    fn adobe_delimiter_boundaries() {
        // `<~` and `~>` are stripped independently, so each alone —
        // and the empty bracket pair — decodes to empty output.
        assert_eq!(decode(b"<~").unwrap(), b"");
        assert_eq!(decode(b"~>").unwrap(), b"");
        assert_eq!(decode(b"<~~>").unwrap(), b"");
        // A lone '<' is not the opener: it is a data char and a
        // single-char tail is rejected.
        assert!(decode(b"<").is_err());
        // A bare trailing '~' (a '~>' cut in half) is misplaced.
        assert!(decode(b"<~9jqo^~").is_err());
    }

    #[test]
    fn adobe_group_boundary_cuts_yield_prefix() {
        // Groups decode independently, so cutting at a 5-char group
        // boundary yields a valid stream whose output is a prefix of
        // the full decode. Cuts inside a group may still succeed but
        // produce different bytes (padded tail semantics).
        let enc = encode(b"0123456789abcde");
        let full = decode(&enc).unwrap();
        assert_eq!(full, b"0123456789abcde");
        // enc = "<~" + 3*5 chars + 4-char tail + "~>": group
        // boundaries at 2+5k.
        for k in 0..4usize {
            let cut = 2 + 5 * k;
            let d = decode(&enc[..cut]).unwrap();
            assert_eq!(d, &full[..4 * k], "cut={cut}");
        }
    }
}
