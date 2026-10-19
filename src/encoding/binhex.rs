//! BinHex 4.0 (".hqx") encoding: "BinHex 4.0 Definition", Peter N Lewis,
//! Aug 1991 (also RFC 1741 Appendix A).
//!
//! A file is a text document: the literal prefix line
//! "(This file must be converted with BinHex 4.0)", a colon, then a
//! 6-bit-per-character alphabet encoding of an RLE-compressed stream of
//! `header | data fork | resource fork`, each terminated by a CRC-16
//! (poly 0x1021, init 0) computed with a two-zero-byte augmentation.
//! RLE marker `0x90`: `X 90 n` expands X to a total of `n` occurrences;
//! `90 00` is a literal `0x90`.
//!
//! [`decode_parts`](crate::encoding::binhex::decode_parts) decodes a document split into comp.binaries.mac-style
//! segments (Lewis "Parts"): a `<return>--- end of part NN ---<return>`
//! line closes each non-final part and a `<return>---<return>` line marks
//! where data resumes in each non-first part.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc16ccitt::crc16_ccitt_aug;

const ALPHABET: &[u8; 64] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
const PROLOGUE: &[u8] = b"(This file must be converted with BinHex 4.0)";
/// Decoder-side prologue check: the spec only requires matching up to
/// "with BinHex".
const PROLOGUE_PREFIX: &[u8] = b"(This file must be converted with BinHex";
const MAX_NAME: usize = 63;
const RLE_MARKER: u8 = 0x90;

/// One decoded BinHex member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinHexEntry {
    /// Filename (1-63 bytes when encoded).
    pub name: String,
    /// Finder file type (four-character code).
    pub file_type: [u8; 4],
    /// Finder creator signature.
    pub creator: [u8; 4],
    /// Finder flags; OnDesk (0x0001), Invisible (0x4000), and Initted
    /// (0x0100) are cleared on decode per spec.
    pub flags: u16,
    /// Data fork contents.
    pub data: Vec<u8>,
    /// Resource fork contents.
    pub resource: Vec<u8>,
}

// ---------- RLE layer ----------

fn rle_encode(data: &[u8], out: &mut Vec<u8>) {
    let mut i = 0usize;
    while i < data.len() {
        let run = 1 + data[i + 1..].iter().take_while(|&&b| b == data[i]).count();
        if data[i] == RLE_MARKER {
            // First 0x90 must be literal-escaped; each `90 c` marker then
            // expands the previous byte to a total of `c` occurrences.
            out.extend_from_slice(&[RLE_MARKER, 0]);
            let mut rem = run - 1;
            while rem > 0 {
                let c = (rem + 1).min(255);
                out.extend_from_slice(&[RLE_MARKER, c as u8]);
                rem -= c - 1;
            }
        } else if run >= 4 {
            out.push(data[i]);
            let mut rem = run;
            // First marker reaches total `c`; later markers extend by c-1.
            let c = rem.min(255);
            out.extend_from_slice(&[RLE_MARKER, c as u8]);
            rem -= c;
            while rem > 0 {
                let c = (rem + 1).min(255);
                out.extend_from_slice(&[RLE_MARKER, c as u8]);
                rem -= c - 1;
            }
        } else {
            out.extend_from_slice(&data[i..i + run]);
        }
        i += run;
    }
}

fn rle_decode(data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        i += 1;
        if b != RLE_MARKER {
            out.push(b);
            continue;
        }
        if i >= data.len() {
            return Err(Error::InvalidData("binhex: dangling RLE marker"));
        }
        let count = data[i] as usize;
        i += 1;
        if count == 0 {
            out.push(RLE_MARKER);
        } else {
            let prev = *out
                .last()
                .ok_or(Error::InvalidData("binhex: RLE without previous byte"))?;
            // `count` is the total number of occurrences; one was already
            // emitted before the marker.
            out.extend(core::iter::repeat_n(prev, count - 1));
        }
    }
    Ok(out)
}

// ---------- 6-bit text layer ----------

fn dec_char(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|v| v as u8)
}

fn sixbit_decode(chars: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(chars.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &c in chars {
        let v = dec_char(c).ok_or(Error::InvalidData("binhex: invalid character"))?;
        acc = (acc << 6) | v as u32;
        nbits += 6;
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

fn sixbit_encode(data: &[u8], out: &mut Vec<u8>) {
    sixbit_encode_inner(data, out, true);
}

#[cfg(test)]
fn sixbit_encode_scalar(data: &[u8], out: &mut Vec<u8>) {
    sixbit_encode_inner(data, out, false);
}

fn trio_indices(a: u8, b: u8, c: u8) -> [u8; 4] {
    [
        a >> 2,
        ((a & 0x03) << 4) | (b >> 4),
        ((b & 0x0f) << 2) | (c >> 6),
        c & 0x3f,
    ]
}

fn sixbit_encode_inner(data: &[u8], out: &mut Vec<u8>, wide: bool) {
    // First output line holds ':' + 63 characters; later lines 64.
    // Wrap lazily (before the next character, not after filling a line)
    // so the terminating ':' always shares its line with the last data
    // character — Lewis: the final line is 2-65 characters.
    let mut col = 1usize;
    let mut put = |out: &mut Vec<u8>, c: u8| {
        if col == 64 {
            out.push(b'\n');
            col = 0;
        }
        out.push(c);
        col += 1;
    };
    let mut pos = 0;
    if wide {
        while pos + 12 <= data.len() {
            for &v in &indices4(&data[pos..pos + 12]) {
                put(out, ALPHABET[v as usize]);
            }
            pos += 12;
        }
    }
    while pos + 3 <= data.len() {
        for &v in &trio_indices(data[pos], data[pos + 1], data[pos + 2]) {
            put(out, ALPHABET[v as usize]);
        }
        pos += 3;
    }
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in &data[pos..] {
        acc = (acc << 8) | b as u32;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            put(out, ALPHABET[((acc >> nbits) & 0x3F) as usize]);
        }
    }
    if nbits > 0 {
        put(out, ALPHABET[((acc << (6 - nbits)) & 0x3F) as usize]);
    }
    out.extend_from_slice(b":\n");
}

fn indices4(input: &[u8]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        indices4_sse2(input)
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        indices4_neon(input)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let mut out = [0u8; 16];
        for k in 0..4 {
            let i = k * 3;
            out[k * 4..k * 4 + 4].copy_from_slice(&trio_indices(
                input[i],
                input[i + 1],
                input[i + 2],
            ));
        }
        out
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
fn indices4_sse2(input: &[u8]) -> [u8; 16] {
    use core::arch::x86_64::{
        _mm_and_si128, _mm_extract_epi16, _mm_or_si128, _mm_set1_epi16, _mm_setr_epi16,
        _mm_slli_epi16, _mm_srli_epi16,
    };
    let b0 = _mm_setr_epi16(
        i16::from(input[0]),
        i16::from(input[3]),
        i16::from(input[6]),
        i16::from(input[9]),
        0,
        0,
        0,
        0,
    );
    let b1 = _mm_setr_epi16(
        i16::from(input[1]),
        i16::from(input[4]),
        i16::from(input[7]),
        i16::from(input[10]),
        0,
        0,
        0,
        0,
    );
    let b2 = _mm_setr_epi16(
        i16::from(input[2]),
        i16::from(input[5]),
        i16::from(input[8]),
        i16::from(input[11]),
        0,
        0,
        0,
        0,
    );
    let c0 = _mm_srli_epi16(b0, 2);
    let c1 = _mm_or_si128(
        _mm_slli_epi16(_mm_and_si128(b0, _mm_set1_epi16(0x03)), 4),
        _mm_srli_epi16(b1, 4),
    );
    let c2 = _mm_or_si128(
        _mm_slli_epi16(_mm_and_si128(b1, _mm_set1_epi16(0x0f)), 2),
        _mm_srli_epi16(b2, 6),
    );
    let c3 = _mm_and_si128(b2, _mm_set1_epi16(0x3f));
    let mut out = [0u8; 16];
    out[0] = _mm_extract_epi16(c0, 0) as u8;
    out[1] = _mm_extract_epi16(c1, 0) as u8;
    out[2] = _mm_extract_epi16(c2, 0) as u8;
    out[3] = _mm_extract_epi16(c3, 0) as u8;
    out[4] = _mm_extract_epi16(c0, 1) as u8;
    out[5] = _mm_extract_epi16(c1, 1) as u8;
    out[6] = _mm_extract_epi16(c2, 1) as u8;
    out[7] = _mm_extract_epi16(c3, 1) as u8;
    out[8] = _mm_extract_epi16(c0, 2) as u8;
    out[9] = _mm_extract_epi16(c1, 2) as u8;
    out[10] = _mm_extract_epi16(c2, 2) as u8;
    out[11] = _mm_extract_epi16(c3, 2) as u8;
    out[12] = _mm_extract_epi16(c0, 3) as u8;
    out[13] = _mm_extract_epi16(c1, 3) as u8;
    out[14] = _mm_extract_epi16(c2, 3) as u8;
    out[15] = _mm_extract_epi16(c3, 3) as u8;
    out
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn indices4_neon(input: &[u8]) -> [u8; 16] {
    use core::arch::aarch64::{
        vand_u16, vcreate_u16, vdup_n_u16, vget_lane_u16, vorr_u16, vshl_n_u16, vshr_n_u16,
    };
    let pack = |a: u8, b: u8, c: u8, d: u8| {
        vcreate_u16(
            u64::from(a) | (u64::from(b) << 16) | (u64::from(c) << 32) | (u64::from(d) << 48),
        )
    };
    let b0 = pack(input[0], input[3], input[6], input[9]);
    let b1 = pack(input[1], input[4], input[7], input[10]);
    let b2 = pack(input[2], input[5], input[8], input[11]);
    let c0 = vshr_n_u16(b0, 2);
    let c1 = vorr_u16(
        vshl_n_u16(vand_u16(b0, vdup_n_u16(0x03)), 4),
        vshr_n_u16(b1, 4),
    );
    let c2 = vorr_u16(
        vshl_n_u16(vand_u16(b1, vdup_n_u16(0x0f)), 2),
        vshr_n_u16(b2, 6),
    );
    let c3 = vand_u16(b2, vdup_n_u16(0x3f));
    let lane = |v, i: i32| -> u8 {
        match i {
            0 => vget_lane_u16(v, 0) as u8,
            1 => vget_lane_u16(v, 1) as u8,
            2 => vget_lane_u16(v, 2) as u8,
            _ => vget_lane_u16(v, 3) as u8,
        }
    };
    let mut out = [0u8; 16];
    for k in 0..4 {
        out[k * 4] = lane(c0, k as i32);
        out[k * 4 + 1] = lane(c1, k as i32);
        out[k * 4 + 2] = lane(c2, k as i32);
        out[k * 4 + 3] = lane(c3, k as i32);
    }
    out
}

// ---------- fork layer ----------

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn take<'a>(data: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], Error> {
    if *pos + n > data.len() {
        return Err(Error::UnexpectedEof);
    }
    let s = &data[*pos..*pos + n];
    *pos += n;
    Ok(s)
}

fn check_crc(body: &[u8], stored: &[u8]) -> Result<(), Error> {
    let want = u16::from_be_bytes([stored[0], stored[1]]);
    if crc16_ccitt_aug(body) != want {
        return Err(Error::InvalidData("binhex: CRC mismatch"));
    }
    Ok(())
}

// ---------- public API ----------

/// Encode one file as a BinHex 4.0 document.
///
/// # Panics
///
/// Panics if `name` is empty or longer than 63 bytes.
pub fn encode(entry: &BinHexEntry) -> Vec<u8> {
    let name = entry.name.as_bytes();
    assert!(
        !name.is_empty() && name.len() <= MAX_NAME,
        "binhex: bad name"
    );
    assert!(
        entry.data.len() <= u32::MAX as usize && entry.resource.len() <= u32::MAX as usize,
        "binhex: fork too large"
    );

    // Fork layer: header + data fork + resource fork, each with CRC.
    let mut raw = Vec::new();
    raw.push(name.len() as u8);
    raw.extend_from_slice(name);
    raw.push(0);
    raw.extend_from_slice(&entry.file_type);
    raw.extend_from_slice(&entry.creator);
    raw.extend_from_slice(&entry.flags.to_be_bytes());
    raw.extend_from_slice(&(entry.data.len() as u32).to_be_bytes());
    raw.extend_from_slice(&(entry.resource.len() as u32).to_be_bytes());
    raw.extend_from_slice(&crc16_ccitt_aug(&raw).to_be_bytes());
    raw.extend_from_slice(&entry.data);
    raw.extend_from_slice(&crc16_ccitt_aug(&entry.data).to_be_bytes());
    raw.extend_from_slice(&entry.resource);
    raw.extend_from_slice(&crc16_ccitt_aug(&entry.resource).to_be_bytes());

    // RLE then 6-bit text layer.
    let mut rle = Vec::new();
    rle_encode(&raw, &mut rle);
    let mut out = Vec::new();
    out.extend_from_slice(PROLOGUE);
    out.extend_from_slice(b"\r\n:");
    sixbit_encode(&rle, &mut out);
    out
}

/// Decode one BinHex 4.0 document.
///
/// Accepts the canonical prologue (checked only up to "with BinHex",
/// remainder of that line ignored) or a document starting directly with
/// `:`; accepts lines of any length; ignores `<cr><lf><tab><spc>` between
/// data characters; allows one legacy `!` before the terminating colon.
/// Header and fork CRCs are verified. OnDesk/Invisible/Initted finder
/// flag bits are cleared per spec.
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<BinHexEntry, Error> {
    let mut i = 0usize;
    if let Some(m) = input
        .windows(PROLOGUE_PREFIX.len())
        .position(|w| w == PROLOGUE_PREFIX)
    {
        // Skip the rest of the prologue line, then <return> characters.
        i = m + PROLOGUE_PREFIX.len();
        while i < input.len() && !matches!(input[i], b'\r' | b'\n') {
            i += 1;
        }
        while i < input.len() && matches!(input[i], b'\r' | b'\n' | b'\t' | b' ') {
            i += 1;
        }
    } else {
        while i < input.len() && matches!(input[i], b'\r' | b'\n' | b'\t' | b' ') {
            i += 1;
        }
    }
    if i >= input.len() || input[i] != b':' {
        return Err(Error::InvalidData("binhex: missing ':'"));
    }
    i += 1;

    // Collect 6-bit characters until the terminating ':'.
    let mut chars: Vec<u8> = Vec::new();
    let mut trailing_bang = false;
    loop {
        if i >= input.len() {
            return Err(Error::UnexpectedEof);
        }
        let c = input[i];
        i += 1;
        match c {
            b':' => break,
            b'\r' | b'\n' | b'\t' | b' ' => {}
            b'!' => {
                // '!' is alphabet[0], but one legacy '!' may sit just
                // before the final ':'. Treat it as the quirk first; if
                // the fork layer then fails, retry with '!' as data.
                let mut j = i;
                while j < input.len() && matches!(input[j], b'\r' | b'\n' | b'\t' | b' ') {
                    j += 1;
                }
                if j < input.len() && input[j] == b':' {
                    trailing_bang = true;
                    break;
                }
                chars.push(c);
            }
            _ => chars.push(c),
        }
    }

    match decode_body(&chars) {
        Err(err) if trailing_bang => {
            chars.push(b'!');
            decode_body(&chars).map_err(|_| err)
        }
        res => res,
    }
}

fn decode_body(chars: &[u8]) -> Result<BinHexEntry, Error> {
    let raw8 = sixbit_decode(chars)?;
    let raw = rle_decode(&raw8)?;

    // Fork layer.
    let mut p = 0usize;
    let name_len = take(&raw, &mut p, 1)?[0] as usize;
    if !(1..=MAX_NAME).contains(&name_len) {
        return Err(Error::InvalidData("binhex: bad name length"));
    }
    let name = String::from_utf8_lossy(take(&raw, &mut p, name_len)?).into_owned();
    if take(&raw, &mut p, 1)?[0] != 0 {
        return Err(Error::InvalidData("binhex: missing name terminator"));
    }
    let file_type: [u8; 4] = take(&raw, &mut p, 4)?.try_into().unwrap();
    let creator: [u8; 4] = take(&raw, &mut p, 4)?.try_into().unwrap();
    let flags = u16::from_be_bytes(take(&raw, &mut p, 2)?.try_into().unwrap());
    let dlen = be32(take(&raw, &mut p, 4)?) as usize;
    let rlen = be32(take(&raw, &mut p, 4)?) as usize;
    check_crc(&raw[..p], take(&raw, &mut p, 2)?)?;

    let data = take(&raw, &mut p, dlen)?.to_vec();
    check_crc(&data, take(&raw, &mut p, 2)?)?;
    let resource = take(&raw, &mut p, rlen)?.to_vec();
    check_crc(&resource, take(&raw, &mut p, 2)?)?;
    if p != raw.len() {
        return Err(Error::InvalidData("binhex: trailing bytes"));
    }

    Ok(BinHexEntry {
        name,
        file_type,
        creator,
        // OnDesk | Invisible | Initted are cleared per spec.
        flags: flags & !(0x0001 | 0x4000 | 0x0100),
        data,
        resource,
    })
}

// ---------- segmented documents ----------

const END_OF_PART: &[u8] = b"--- end of part";

/// Strip a part's trailing `<return>--- end of part NN ---` marker line,
/// returning the body before it. Everything after the marker is dropped.
fn strip_part_end(part: &[u8]) -> Result<&[u8], Error> {
    let bad = || Error::InvalidData("binhex: bad 'end of part' marker");
    for i in 0..part.len() {
        if !matches!(part[i], b'\r' | b'\n') || !part[i + 1..].starts_with(END_OF_PART) {
            continue;
        }
        // `NN` is one or more digits; the line must close with `---`
        // followed by <return> or the end of the part.
        let rest = part[i + 1 + END_OF_PART.len()..]
            .strip_prefix(b" ")
            .ok_or_else(bad)?;
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return Err(bad());
        }
        let rest = rest[digits..].strip_prefix(b" ---").ok_or_else(bad)?;
        match rest.first().copied() {
            None | Some(b'\r' | b'\n') => return Ok(&part[..i]),
            _ => return Err(bad()),
        }
    }
    Err(Error::InvalidData("binhex: missing 'end of part' marker"))
}

/// Find a non-first part's `<return>---<return>` resume marker and return
/// the data following it. `---` is valid hqx data, so a `<cr>` or `<lf>`
/// is required immediately on each side (part start counts as the
/// preceding one); a longer dash run is not a marker.
fn resume_after_marker(part: &[u8]) -> Result<&[u8], Error> {
    if part.starts_with(b"---") && matches!(part.get(3).copied(), Some(b'\r' | b'\n')) {
        return Ok(&part[4..]);
    }
    for i in 0..part.len().saturating_sub(3) {
        if matches!(part[i], b'\r' | b'\n')
            && part[i + 1..].starts_with(b"---")
            && matches!(part.get(i + 4).copied(), Some(b'\r' | b'\n'))
        {
            return Ok(&part[i + 5..]);
        }
    }
    Err(Error::InvalidData("binhex: missing '---' resume marker"))
}

/// Decode a BinHex 4.0 document split into comp.binaries.mac-style
/// parts, in order. Every part but the last must close with a
/// `<return>--- end of part NN ---` marker line and every part but the
/// first resumes after a `<return>---<return>` line; both are verified,
/// stripped, and the concatenated bodies are passed to [`decode`]. A
/// single-element `parts` is decoded directly (no markers required).
///
/// This function does not panic on malformed input.
pub fn decode_parts(parts: &[&[u8]]) -> Result<BinHexEntry, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidData("binhex: empty part"));
    }
    if parts.len() == 1 {
        return decode(parts[0]);
    }
    let mut joined = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let mut body = *part;
        if i > 0 {
            body = resume_after_marker(body)?;
        }
        if i + 1 < parts.len() {
            body = strip_part_end(body)?;
        }
        joined.extend_from_slice(body);
    }
    decode(&joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_indices(input: &[u8; 12]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for k in 0..4 {
            let i = k * 3;
            out[k * 4..k * 4 + 4].copy_from_slice(&trio_indices(
                input[i],
                input[i + 1],
                input[i + 2],
            ));
        }
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn indices4_sse2_matches_scalar() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(unsafe { indices4_sse2(&input) }, scalar_indices(&input));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn indices4_neon_matches_scalar() {
        let input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        assert_eq!(unsafe { indices4_neon(&input) }, scalar_indices(&input));
    }

    #[test]
    fn vector_matches_scalar_trios() {
        for n in [0, 1, 2, 3, 4, 11, 12, 13, 47, 48, 49, 96, 128] {
            let data: Vec<u8> = (0..n)
                .map(|i| (i as u8).wrapping_mul(3).wrapping_add(1))
                .collect();
            let mut wide = Vec::new();
            let mut scalar = Vec::new();
            sixbit_encode(&data, &mut wide);
            sixbit_encode_scalar(&data, &mut scalar);
            assert_eq!(wide, scalar, "len {n}");
        }
        let zeros = vec![0u8; 64];
        let mut wide = Vec::new();
        let mut scalar = Vec::new();
        sixbit_encode(&zeros, &mut wide);
        sixbit_encode_scalar(&zeros, &mut scalar);
        assert_eq!(wide, scalar);
    }

    fn entry() -> BinHexEntry {
        BinHexEntry {
            name: "sample.hqx".into(),
            file_type: *b"BINA",
            creator: *b"R*ch",
            flags: 0x8000,
            data: b"the data fork says hello".to_vec(),
            resource: b"rsrc!".to_vec(),
        }
    }

    #[test]
    fn alphabet_is_unique() {
        let mut sorted = ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 64);
    }

    #[test]
    fn roundtrip() {
        let e = entry();
        let doc = encode(&e);
        let text = String::from_utf8(doc.clone()).unwrap();
        assert!(text.starts_with("(This file must be converted with BinHex 4.0)"));
        assert!(text.contains("\r\n:"));
        assert!(text.trim_end().ends_with(':'));
        assert_eq!(decode(&doc).unwrap(), e);
    }

    #[test]
    fn empty_forks() {
        let mut e = entry();
        e.data = Vec::new();
        e.resource = Vec::new();
        assert_eq!(decode(&encode(&e)).unwrap(), e);
    }

    #[test]
    fn rle_roundtrip_runs() {
        // Runs of 0x90 and normal bytes, run lengths crossing 255.
        let mut data = vec![0x90u8; 10];
        data.extend_from_slice(&[0xAA; 300]);
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&[0xBB; 4]);
        let mut rle = Vec::new();
        rle_encode(&data, &mut rle);
        assert!(rle.len() < data.len());
        assert_eq!(rle_decode(&rle).unwrap(), data);
        // Literal 0x90 handled.
        assert_eq!(rle_decode(&[0x2B, 0x90, 0x00]).unwrap(), vec![0x2B, 0x90]);
        // 90 00 followed by a run repeats the 0x90.
        assert_eq!(
            rle_decode(&[0x2B, 0x90, 0x00, 0x90, 0x05]).unwrap(),
            vec![0x2B, 0x90, 0x90, 0x90, 0x90, 0x90]
        );
        // Single 0x90 and 0x90 runs inside data.
        for n in [1usize, 2, 3, 10, 300] {
            let data = vec![0x90u8; n];
            let mut rle = Vec::new();
            rle_encode(&data, &mut rle);
            assert_eq!(rle_decode(&rle).unwrap(), data, "n={n}");
        }
        // Normal-byte runs: n <= 3 stays literal, n >= 4 packetizes.
        for n in [1usize, 2, 3, 4] {
            let data = vec![0xBBu8; n];
            let mut rle = Vec::new();
            rle_encode(&data, &mut rle);
            assert_eq!(rle.contains(&RLE_MARKER), n >= 4, "n={n}");
            assert_eq!(rle_decode(&rle).unwrap(), data, "n={n}");
        }
    }

    #[test]
    fn rle_malformed() {
        assert!(rle_decode(&[0x90]).is_err()); // dangling marker
        assert!(rle_decode(&[0x90, 0x05]).is_err()); // no previous byte
    }

    #[test]
    fn rfc1741_examples() {
        // RFC 1741 Appendix A RLE examples.
        assert_eq!(
            rle_decode(&[0x11, 0x22, 0x90, 0x06, 0x33]).unwrap(),
            vec![0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x33]
        );
        assert_eq!(
            rle_decode(&[0x11, 0x22, 0x90, 0x00, 0x33, 0x44]).unwrap(),
            vec![0x11, 0x22, 0x90, 0x33, 0x44]
        );
    }

    #[test]
    fn rejects_invalid_chars() {
        let e = entry();
        let mut doc = encode(&e);
        // Replace a data char (past the ':' that starts the body) with an
        // invalid one.
        let colon = doc.iter().position(|&b| b == b':').unwrap();
        doc[colon + 3] = b'~';
        assert!(decode(&doc).is_err());
    }

    #[test]
    fn rejects_crc_and_truncation() {
        let e = entry();
        let doc = encode(&e);
        // Corrupt a data char -> CRC mismatch.
        let mut bad = doc.clone();
        let n = bad.len();
        bad[n / 2] = ALPHABET[(dec_char(bad[n / 2]).unwrap_or(0) as usize + 1) % 64];
        assert!(decode(&bad).is_err());
        // Truncated (no terminating ':').
        assert!(decode(&doc[..doc.len() - 3]).is_err());
    }

    #[test]
    fn rejects_all_truncations() {
        // The encoded body contains no ':', so the only terminators
        // are the opener and the final colon: every cut before the
        // final colon fails, while cuts that keep it (trailing
        // whitespace may be dropped) succeed.
        let doc = encode(&entry());
        let term = doc.iter().rposition(|&b| b == b':').unwrap();
        let full = decode(&doc).unwrap();
        for cut in 0..doc.len() {
            if cut <= term {
                assert!(
                    decode(&doc[..cut]).is_err(),
                    "cut={cut} unexpectedly decoded"
                );
            } else {
                assert_eq!(decode(&doc[..cut]).unwrap(), full, "cut={cut}");
            }
        }
    }

    #[test]
    fn prologue_variants() {
        let e = entry();
        let doc = encode(&e);
        // Decode must also accept a bare ':...' document.
        let colon = doc.iter().position(|&b| b == b':').unwrap();
        let bare = &doc[colon..];
        assert_eq!(decode(bare).unwrap().data, e.data);
        // Text before the prologue is ignored.
        let mut pre = b"arbitrary preamble text\n".to_vec();
        pre.extend_from_slice(&doc);
        assert_eq!(decode(&pre).unwrap().data, e.data);
        // Legacy '!' right before the terminating colon.
        let end = doc.iter().rposition(|&b| b == b':').unwrap();
        let mut legacy = doc[..end].to_vec();
        legacy.push(b'!');
        legacy.extend_from_slice(&doc[end..]);
        assert_eq!(decode(&legacy).unwrap().data, e.data);
    }

    #[test]
    fn flags_cleared_on_decode() {
        let mut e = entry();
        e.flags = 0xFFFF;
        let d = decode(&encode(&e)).unwrap();
        assert_eq!(d.flags, !(0x0001 | 0x4000 | 0x0100));
    }

    #[test]
    fn sixbit_roundtrip_boundary() {
        for n in [1usize, 2, 3, 4, 5, 61, 62, 63, 64] {
            let data: Vec<u8> = (0..n as u32).map(|v| v as u8).collect();
            let mut out = Vec::new();
            sixbit_encode(&data, &mut out);
            let chars: Vec<u8> = out
                .iter()
                .copied()
                .filter(|&c| c != b':' && c != b'\n')
                .collect();
            assert_eq!(sixbit_decode(&chars).unwrap(), data);
        }
    }

    fn segmented(doc: &[u8], cuts: &[usize]) -> Vec<Vec<u8>> {
        let mut parts = Vec::new();
        let mut prev = 0;
        for (i, &c) in cuts.iter().enumerate() {
            let mut p = doc[prev..c].to_vec();
            p.extend_from_slice(alloc::format!("\r\n--- end of part {} ---\r\n", i + 1).as_bytes());
            parts.push(p);
            prev = c;
        }
        let mut last = b"---\r\n".to_vec();
        last.extend_from_slice(&doc[prev..]);
        parts.push(last);
        // Non-first, non-last parts resume after a "---" line too.
        for i in 1..parts.len() - 1 {
            let mut p = b"---\n".to_vec();
            p.extend_from_slice(&parts[i]);
            parts[i] = p;
        }
        parts
    }

    #[test]
    fn segmented_roundtrip() {
        let e = entry();
        let doc = encode(&e);
        let start = doc.iter().position(|&b| b == b':').unwrap() + 1;
        let end = doc.iter().rposition(|&b| b == b':').unwrap();
        let a = start + (end - start) / 3;
        let b = start + 2 * (end - start) / 3;

        // 2 and 3 part splits; marker lines sit at the seam.
        for cuts in [&[b][..], &[a, b][..]] {
            let parts = segmented(&doc, cuts);
            let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
            assert_eq!(decode_parts(&refs).unwrap(), e, "cuts={cuts:?}");
        }
        // Middle part carrying a news-style preamble before "---".
        let mut parts = segmented(&doc, &[a, b]);
        let mut p = b"From: someone\r\nSubject: part 2/3\r\n\r\n".to_vec();
        p.extend_from_slice(&parts[1]);
        parts[1] = p;
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        assert_eq!(decode_parts(&refs).unwrap(), e);
        // A single element needs no markers.
        assert_eq!(decode_parts(&[&doc[..]]).unwrap(), e);
    }

    #[test]
    fn segmented_marker_boundaries() {
        let e = entry();
        let doc = encode(&e);
        let end = doc.iter().rposition(|&b| b == b':').unwrap();
        let mid = end / 2;
        let (a, b) = (&doc[..mid], &doc[mid..]);

        // <cr>, <lf> and <cr><lf> are all accepted around each marker;
        // the part may also start directly with "---".
        for pre in [b"\r".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            for post in [b"\r".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
                let mut p1 = a.to_vec();
                p1.extend_from_slice(pre);
                p1.extend_from_slice(b"--- end of part 12 ---");
                p1.extend_from_slice(post);
                let mut p2 = b"---".to_vec();
                p2.extend_from_slice(post);
                p2.extend_from_slice(b);
                assert_eq!(decode_parts(&[&p1[..], &p2[..]]).unwrap(), e);
            }
        }
        // Marker at end of part with no trailing <return>; also a
        // "---abc"-style line in the preamble is data, not the marker.
        let mut p1 = a.to_vec();
        p1.extend_from_slice(b"\n--- end of part 1 ---");
        let mut p2 = b"header\n---abc\n---\n".to_vec();
        p2.extend_from_slice(b);
        assert_eq!(decode_parts(&[&p1[..], &p2[..]]).unwrap(), e);
    }

    #[test]
    fn rejects_bad_segment_marker() {
        let e = entry();
        let doc = encode(&e);
        let end = doc.iter().rposition(|&b| b == b':').unwrap();
        let mid = end / 2;
        let (a, b) = (&doc[..mid], &doc[mid..]);
        let mut ok_p2 = b"---\n".to_vec();
        ok_p2.extend_from_slice(b);
        let p1 = |marker: &[u8]| {
            let mut p = a.to_vec();
            p.extend_from_slice(marker);
            p
        };
        // No marker at all; wrong prefix; no digits; no closing dashes;
        // junk after the closing dashes; marker not at a line start.
        for marker in [
            &b"\n"[..],
            &b"\n--- end of file 1 ---\n"[..],
            &b"\n--- end of part ---\n"[..],
            &b"\n--- end of part 1\n"[..],
            &b"\n--- end of part 1 --- extra\n"[..],
            &b"x--- end of part 1 ---\n"[..],
        ] {
            let p = p1(marker);
            assert!(decode_parts(&[&p[..], &ok_p2[..]]).is_err(), "{marker:?}");
        }
        // Part 2 without a resume marker line; a "---" not closed by
        // <return>; a 4-dash line is not a resume marker.
        for p2 in [
            b"Subject: x\n\n".as_slice(),
            b"header\n---tail\n".as_slice(),
            b"header\n----\n".as_slice(),
        ] {
            let mut p = p2.to_vec();
            p.extend_from_slice(b);
            assert!(decode_parts(&[&p1(b"\n--- end of part 1 ---\n")[..], &p[..]]).is_err());
        }
        // Empty input / empty parts.
        assert!(decode_parts(&[]).is_err());
        assert!(decode_parts(&[&p1(b"\n--- end of part 1 ---\n")[..], &[]]).is_err());
        // Segments still decode-checked end to end.
        let mut parts = segmented(&doc, &[mid]);
        let n = parts[1].len();
        parts[1][n - 4] = ALPHABET[(dec_char(parts[1][n - 4]).unwrap_or(0) as usize + 1) % 64];
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        assert!(decode_parts(&refs).is_err());
    }
    #[test]
    fn encode_wraps_at_64_columns() {
        let mut e = entry();
        e.data = (0..400u32).map(|i| (i * 3 % 256) as u8).collect();
        let doc = encode(&e);
        // Data region spans the leading ':' to the terminating ':'.
        let first = doc.iter().position(|&b| b == b':').unwrap();
        let last = doc.iter().rposition(|&b| b == b':').unwrap();
        let lines: Vec<&[u8]> = doc[first..last].split(|&b| b == b'\n').collect();
        // First line = ':' + 63 chars max; later lines 64 chars max.
        assert!(lines.len() >= 3);
        assert!(lines.iter().all(|l| l.len() <= 64));
        assert!(lines.iter().any(|l| l.len() == 64));
        assert_eq!(lines[0][0], b':');
    }

    #[test]
    fn encode_final_colon_on_last_line() {
        // 47 bytes encode to exactly 63 6-bit chars, filling the first
        // line (':' + 63). Lewis requires the final ':' on the same line
        // as the last data character (final line is 2-65 chars), so it
        // must not wrap onto a line of length 1.
        let mut out = Vec::new();
        sixbit_encode(&[0xAA; 47], &mut out);
        assert!(out.ends_with(b":\n"));
        assert!(!out.ends_with(b"\n:\n"));
        // Same invariant through the public encoder for arbitrary sizes.
        for n in [0usize, 1, 47, 48, 95, 96] {
            let mut e = entry();
            e.data = vec![0xAB; n];
            e.resource = Vec::new();
            let doc = encode(&e);
            assert!(
                !doc.windows(3).any(|w| w == b"\n:\n" || w == b"\r:\n"),
                "n={n}"
            );
            assert_eq!(decode(&doc).unwrap(), e, "n={n}");
        }
    }

    #[test]
    fn rejects_bad_name() {
        // Craft documents with a malformed name field (valid CRCs so the
        // name checks themselves are exercised).
        let mk = |name_len: u8, name: &[u8], term: u8| -> Vec<u8> {
            let mut raw = vec![name_len];
            raw.extend_from_slice(name);
            raw.push(term);
            raw.extend_from_slice(&[0; 4 + 4 + 2 + 4 + 4]); // TYPE AUTH FLAG DLEN RLEN
            raw.extend_from_slice(&crc16_ccitt_aug(&raw).to_be_bytes());
            raw.extend_from_slice(&crc16_ccitt_aug(&[]).to_be_bytes()); // data CRC
            raw.extend_from_slice(&crc16_ccitt_aug(&[]).to_be_bytes()); // rsrc CRC
            let mut rle = Vec::new();
            rle_encode(&raw, &mut rle);
            let mut out = vec![b':'];
            sixbit_encode(&rle, &mut out);
            out
        };
        assert!(decode(&mk(0, b"", 0)).is_err()); // empty name
        assert!(decode(&mk(64, &[b'a'; 64], 0)).is_err()); // over 63
        assert!(decode(&mk(4, b"name", b'X')).is_err()); // missing NUL
    }
}
