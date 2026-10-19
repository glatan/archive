//! yEnc binary-to-text encoding (yEnc draft 1.3, "yEncode - A quick and
//! dirty encoding for binaries", Juergen Helbing).
//!
//! Each input byte is rotated by +42 (mod 256); output bytes that are
//! critical (NUL, LF, CR, `=`), a space/TAB in the first or last column, or
//! a dot in the first column are emitted as an escape pair `=` followed by
//! the rotated byte +64. Data is framed by `=ybegin ... name=...` and
//! `=yend` keyword lines; a line may end with an escape pair (length n+1).
//!
//! Single-part documents and individual parts of multipart documents are
//! supported (`part=`/`=ypart`/`pcrc32` verification). [`join_parts`](crate::encoding::yenc::join_parts)
//! concatenates a complete, verified set of decoded parts into the whole
//! file.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32::crc32;

/// Encoder line length (spec-typical value).
const LINE_LEN: usize = 128;

/// One decoded yEnc member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YEncEntry {
    /// `name=` parameter from the `=ybegin` line.
    pub name: String,
    /// Decoded bytes of this document (the part data for multipart parts).
    pub data: Vec<u8>,
    /// `part=` number when the document is one part of a multipart binary.
    pub part: Option<u32>,
    /// `total=` parameter (total part count) from the `=ybegin` line.
    pub total: Option<u32>,
    /// Inclusive byte range of this part within the whole file (`=ypart`).
    pub range: Option<(u64, u64)>,
}

fn push_encoded(out: &mut Vec<u8>, data: &[u8]) {
    push_encoded_rotated(out, data, false);
}

fn push_encoded_scalar(out: &mut Vec<u8>, data: &[u8]) {
    push_encoded_rotated(out, data, true);
}

fn push_encoded_rotated(out: &mut Vec<u8>, data: &[u8], scalar: bool) {
    let mut col = 0usize;
    let mut off = 0usize;
    while off < data.len() {
        let n = (data.len() - off).min(64);
        let mut rotated = [0u8; 64];
        if scalar {
            rotate_scalar(&data[off..off + n], &mut rotated[..n]);
        } else {
            rotate_chunk(&data[off..off + n], &mut rotated[..n]);
        }
        for (i, &c) in rotated[..n].iter().enumerate() {
            // A short final line still has a last column: the decoder
            // strips a trailing space or tab, so that byte must be escaped.
            let last_col = col + 1 >= LINE_LEN || off + i + 1 == data.len();
            let escape = matches!(c, 0 | 10 | 13 | b'=')
                || (col == 0 && matches!(c, b' ' | b'\t' | b'.'))
                || (last_col && matches!(c, b' ' | b'\t'));
            if escape {
                out.push(b'=');
                out.push(c.wrapping_add(64));
                col += 2;
            } else {
                out.push(c);
                col += 1;
            }
            if col >= LINE_LEN {
                out.extend_from_slice(b"\r\n");
                col = 0;
            }
        }
        off += n;
    }
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }
}

fn rotate_scalar(src: &[u8], dst: &mut [u8]) {
    for (s, d) in src.iter().zip(dst.iter_mut()) {
        *d = s.wrapping_add(42);
    }
}

fn rotate_chunk(src: &[u8], dst: &mut [u8]) {
    // Baseline x86_64 and i686 rotate 16 bytes with SSE2. An `x86-64-v3`
    // crate rotates 32 bytes with AVX2. An `x86-64-v4` crate rotates 64
    // bytes with AVX-512BW and leaves 32-byte and 16-byte tails. aarch64
    // uses NEON and wasm32 `simd128` uses a 16-byte add. The line length
    // stays 128, so the rotation width does not cross a line break.
    let mut i = 0;
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_feature = "avx512bw")]
        while i + 64 <= src.len() {
            unsafe { rotate64_avx512(&src[i..i + 64], &mut dst[i..i + 64]) };
            i += 64;
        }
        #[cfg(target_feature = "avx2")]
        while i + 32 <= src.len() {
            unsafe { rotate32_avx2(&src[i..i + 32], &mut dst[i..i + 32]) };
            i += 32;
        }
        while i + 16 <= src.len() {
            unsafe { rotate16_sse2(&src[i..i + 16], &mut dst[i..i + 16]) };
            i += 16;
        }
    }
    #[cfg(all(target_arch = "x86", target_feature = "sse2"))]
    {
        while i + 16 <= src.len() {
            unsafe { rotate16_sse2(&src[i..i + 16], &mut dst[i..i + 16]) };
            i += 16;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        while i + 16 <= src.len() {
            unsafe { rotate16_neon(&src[i..i + 16], &mut dst[i..i + 16]) };
            i += 16;
        }
    }
    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    {
        while i + 16 <= src.len() {
            rotate16_wasm(&src[i..i + 16], &mut dst[i..i + 16]);
            i += 16;
        }
    }
    rotate_scalar(&src[i..], &mut dst[i..]);
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx512bw"), allow(dead_code))]
#[target_feature(enable = "avx512bw")]
fn rotate64_avx512(src: &[u8], dst: &mut [u8]) {
    use core::arch::x86_64::{
        _mm512_add_epi8, _mm512_loadu_si512, _mm512_set1_epi8, _mm512_storeu_si512,
    };
    unsafe {
        let v = _mm512_loadu_si512(src.as_ptr().cast());
        let r = _mm512_add_epi8(v, _mm512_set1_epi8(42));
        _mm512_storeu_si512(dst.as_mut_ptr().cast(), r);
    }
}

#[cfg(target_arch = "x86_64")]
#[cfg_attr(not(target_feature = "avx2"), allow(dead_code))]
#[target_feature(enable = "avx2")]
fn rotate32_avx2(src: &[u8], dst: &mut [u8]) {
    use core::arch::x86_64::{
        _mm256_add_epi8, _mm256_loadu_si256, _mm256_set1_epi8, _mm256_storeu_si256,
    };
    unsafe {
        let v = _mm256_loadu_si256(src.as_ptr().cast());
        let r = _mm256_add_epi8(v, _mm256_set1_epi8(42));
        _mm256_storeu_si256(dst.as_mut_ptr().cast(), r);
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sse2")]
fn rotate16_sse2(src: &[u8], dst: &mut [u8]) {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::{_mm_add_epi8, _mm_loadu_si128, _mm_set1_epi8, _mm_storeu_si128};
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::{_mm_add_epi8, _mm_loadu_si128, _mm_set1_epi8, _mm_storeu_si128};
    unsafe {
        let v = _mm_loadu_si128(src.as_ptr().cast());
        let r = _mm_add_epi8(v, _mm_set1_epi8(42));
        _mm_storeu_si128(dst.as_mut_ptr().cast(), r);
    }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[target_feature(enable = "simd128")]
fn rotate16_wasm(src: &[u8], dst: &mut [u8]) {
    use core::arch::wasm32::{i8x16_add, u8x16_splat, v128_load, v128_store};
    unsafe {
        let v = v128_load(src.as_ptr().cast());
        v128_store(dst.as_mut_ptr().cast(), i8x16_add(v, u8x16_splat(42)));
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
fn rotate16_neon(src: &[u8], dst: &mut [u8]) {
    use core::arch::aarch64::{vaddq_u8, vdupq_n_u8, vld1q_u8, vst1q_u8};
    unsafe {
        let v = vld1q_u8(src.as_ptr());
        vst1q_u8(dst.as_mut_ptr(), vaddq_u8(v, vdupq_n_u8(42)));
    }
}

/// Encode `data` as a single-part yEnc document.
///
/// Emits `=ybegin line=128 size=<n> name=<name>`, the encoded data in
/// CRLF-terminated lines of at most 128+1 characters, and a `=yend` trailer
/// carrying `size` and `crc32`.
///
/// # Panics
///
/// Panics if `name` is empty or contains `\r` or `\n`.
pub fn encode(name: &str, data: &[u8]) -> Vec<u8> {
    encode_inner(name, data, false)
}

#[cfg(test)]
fn encode_scalar(name: &str, data: &[u8]) -> Vec<u8> {
    encode_inner(name, data, true)
}

fn encode_inner(name: &str, data: &[u8], scalar: bool) -> Vec<u8> {
    assert!(
        !name.is_empty() && !name.contains(['\r', '\n']),
        "yenc: bad name"
    );
    let mut out = Vec::new();
    out.extend_from_slice(
        alloc::format!(
            "=ybegin line={LINE_LEN} size={} name={name}\r\n",
            data.len()
        )
        .as_bytes(),
    );
    if scalar {
        push_encoded_scalar(&mut out, data);
    } else {
        push_encoded(&mut out, data);
    }
    out.extend_from_slice(
        alloc::format!("=yend size={} crc32={:08x}\r\n", data.len(), crc32(data)).as_bytes(),
    );
    out
}

/// Encode `data` as one part of a multipart yEnc document.
///
/// `part`/`total` are 1-based; `begin` is the 1-based byte offset of this
/// part in the whole file, and `whole_size` is the size of the whole file.
/// The trailer carries `size=<part size>`, `part`, and `pcrc32` per spec.
///
/// # Panics
///
/// Panics if `name` is empty or contains a newline, `data` is empty,
/// `part` is out of `1..=total`, `begin == 0`, or the part range exceeds
/// `whole_size`.
pub fn encode_part(
    name: &str,
    part: u32,
    total: u32,
    begin: u64,
    data: &[u8],
    whole_size: u64,
) -> Vec<u8> {
    assert!(
        !name.is_empty() && !name.contains(['\r', '\n']),
        "yenc: bad name"
    );
    assert!(part >= 1 && part <= total, "yenc: bad part");
    assert!(begin >= 1 && !data.is_empty(), "yenc: bad begin/data");
    let end = begin + data.len() as u64 - 1;
    assert!(end <= whole_size, "yenc: part outside file");

    let mut out = Vec::new();
    out.extend_from_slice(
        alloc::format!(
            "=ybegin part={part} total={total} line={LINE_LEN} size={whole_size} name={name}\r\n\
             =ypart begin={begin} end={end}\r\n"
        )
        .as_bytes(),
    );
    push_encoded(&mut out, data);
    out.extend_from_slice(
        alloc::format!(
            "=yend size={} part={part} pcrc32={:08x}\r\n",
            data.len(),
            crc32(data)
        )
        .as_bytes(),
    );
    out
}

fn strip_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    // Transports may mangle/append trailing space or tab; decoders strip it.
    while end > 0 && matches!(line[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    &line[..end]
}

fn parse_params<'a>(line: &'a [u8], keyword: &[u8]) -> Vec<(&'a [u8], &'a [u8])> {
    let mut params = Vec::new();
    for tok in line[keyword.len()..].split(|&b| b == b' ') {
        if tok.is_empty() {
            continue;
        }
        if let Some(eq) = tok.iter().position(|&b| b == b'=') {
            params.push((&tok[..eq], &tok[eq + 1..]));
        }
    }
    params
}

fn get_u64<'a>(params: &[(&'a [u8], &'a [u8])], key: &[u8]) -> Option<u64> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| core::str::from_utf8(v).ok()?.parse().ok())
}

fn get_hex32<'a>(params: &[(&'a [u8], &'a [u8])], key: &[u8]) -> Option<u32> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| u32::from_str_radix(core::str::from_utf8(v).ok()?, 16).ok())
}

fn get_name(line: &[u8]) -> Option<&[u8]> {
    // `name=` is always the last parameter; its value runs to end of line.
    // Find the first token-boundary occurrence so a filename that itself
    // contains the substring "name=" does not truncate the value.
    let pat = b"name=";
    for pos in 0..line.len() {
        if line[pos..].starts_with(pat) && (pos == 0 || line[pos - 1] == b' ') {
            return Some(&line[pos + pat.len()..]);
        }
    }
    None
}

fn decode_body(lines: &[&[u8]], out: &mut Vec<u8>) -> Result<(), Error> {
    for &line in lines {
        let line = strip_line(line);
        let mut i = 0usize;
        while i < line.len() {
            if line[i] == b'=' {
                if i + 1 >= line.len() {
                    return Err(Error::InvalidData("yenc: dangling escape"));
                }
                out.push(line[i + 1].wrapping_sub(64).wrapping_sub(42));
                i += 2;
            } else {
                out.push(line[i].wrapping_sub(42));
                i += 1;
            }
        }
    }
    Ok(())
}

/// Decode one yEnc document (single-part or a single multipart part).
///
/// Text outside the `=ybegin`/`=yend` block is ignored; `=ybegin` lines
/// that lack the required `size=`/`name=` parameters are treated as
/// discussion text and skipped per spec. Header/trailer `size=` values,
/// `=ypart` ranges, `part=`/`total=` consistency (`part <= total`, and a
/// last part's `end` must equal the whole-file `size`), `crc32=`, and
/// `pcrc32=` are verified; a mismatch is an error (the spec requires the
/// decoded binary to be discarded then).
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<YEncEntry, Error> {
    let mut lines = input.split(|&b| b == b'\n');

    // Find a complete =ybegin line (size=/name= required; otherwise it is
    // assumed to be part of a text discussion about yEnc).
    let (header, size, name) = loop {
        let line = strip_line(lines.next().ok_or(Error::UnexpectedEof)?);
        if !line.starts_with(b"=ybegin ") {
            continue;
        }
        let params = parse_params(line, b"=ybegin ");
        let name = get_name(line).filter(|n| !n.is_empty());
        match (get_u64(&params, b"size"), name) {
            (Some(s), Some(n)) => break (line, s, n),
            _ => continue,
        }
    };
    let params = parse_params(header, b"=ybegin ");
    let part = get_u64(&params, b"part");
    // (1.2) `total=` declares the total number of parts; the header
    // `part` number must not exceed it. Absence of `total` (pre-1.2
    // writers) is accepted.
    let total = get_u64(&params, b"total");
    if let (Some(p), Some(t)) = (part, total)
        && p > t
    {
        return Err(Error::InvalidData("yenc: part > total"));
    }
    let name = String::from_utf8_lossy(name).into_owned();

    // Multipart: the next line must be =ypart begin=B end=E.
    let mut range = None;
    if part.is_some() {
        let line = strip_line(lines.next().ok_or(Error::UnexpectedEof)?);
        if !line.starts_with(b"=ypart ") {
            return Err(Error::InvalidData("yenc: missing =ypart"));
        }
        let p = parse_params(line, b"=ypart ");
        let begin = get_u64(&p, b"begin").ok_or(Error::InvalidData("yenc: =ypart begin"))?;
        let end = get_u64(&p, b"end").ok_or(Error::InvalidData("yenc: =ypart end"))?;
        if end < begin || end - begin + 1 > size {
            return Err(Error::InvalidData("yenc: =ypart range"));
        }
        // The last part must end at the declared whole-file `size`
        // (begin/end are 1-based byte offsets).
        if part == total && end != size {
            return Err(Error::InvalidData("yenc: last part end != size"));
        }
        range = Some((begin, end));
    }

    // Data lines until =yend.
    let mut body: Vec<&[u8]> = Vec::new();
    let trailer = loop {
        let line = strip_line(lines.next().ok_or(Error::UnexpectedEof)?);
        if line.starts_with(b"=y") {
            if line == b"=yend" || line.starts_with(b"=yend ") {
                break line;
            }
            return Err(Error::InvalidData("yenc: unexpected keyword line"));
        }
        body.push(line);
    };
    let tp = parse_params(trailer, b"=yend");
    let tend_size = get_u64(&tp, b"size").ok_or(Error::InvalidData("yenc: =yend size"))?;

    let mut data = Vec::new();
    decode_body(&body, &mut data)?;

    // Size verification: header/trailer/decoded must agree.
    let expected = match range {
        Some((b, e)) => e - b + 1,
        None => size,
    };
    if tend_size != expected || data.len() as u64 != expected {
        return Err(Error::InvalidData("yenc: size mismatch"));
    }
    // Multipart trailer part number must match the header part.
    if let Some(n) = part
        && get_u64(&tp, b"part") != Some(n)
    {
        return Err(Error::InvalidData("yenc: part mismatch"));
    }
    // Optional integrity checks.
    if let Some(c) = get_hex32(&tp, b"crc32").or_else(|| get_hex32(&tp, b"pcrc32"))
        && c != crc32(&data)
    {
        return Err(Error::InvalidData("yenc: crc32 mismatch"));
    }

    Ok(YEncEntry {
        name,
        data,
        part: part.map(|v| v as u32),
        total: total.map(|v| v as u32),
        range,
    })
}

/// Join decoded multipart parts into the whole file.
///
/// `parts` must be the complete set of [`YEncEntry`] values produced by
/// [`decode`] for one multipart binary, in any order. Every entry must
/// carry `part`/`range` (single-part documents are rejected), all `name`
/// and `total` values must agree, part numbers must be unique, and the
/// `=ypart` ranges must tile the file contiguously starting at byte 1 —
/// a gap means a missing part and is an error. When `total=` is present
/// in the headers the part count must equal it, which also detects a
/// missing final part (undetectable from ranges alone when pre-1.2
/// writers omit `total=`).
///
/// The returned entry carries the shared `name`, the concatenated `data`,
/// and `part`/`total`/`range` set to `None` since it describes the whole
/// file, like a decoded single-part document.
///
/// # Errors
///
/// Returns `Error::InvalidData` for an empty slice, a non-part entry,
/// mismatched `name`/`total`, a `part=` number of 0 or above `total`,
/// a duplicate part number, a `data` length not matching the `=ypart`
/// range, or non-contiguous/overlapping ranges (missing part).
pub fn join_parts(parts: &[YEncEntry]) -> Result<YEncEntry, Error> {
    let first = parts.first().ok_or(Error::InvalidData("yenc: no parts"))?;
    let mut sorted: Vec<&YEncEntry> = Vec::with_capacity(parts.len());
    let mut part_nums: Vec<u32> = Vec::with_capacity(parts.len());
    for e in parts {
        if e.name != first.name {
            return Err(Error::InvalidData("yenc: name mismatch"));
        }
        if e.total != first.total {
            return Err(Error::InvalidData("yenc: total mismatch"));
        }
        let p = e.part.ok_or(Error::InvalidData("yenc: not a part"))?;
        let (begin, end) = e.range.ok_or(Error::InvalidData("yenc: not a part"))?;
        // decode() verifies all of this already; these checks also guard
        // caller-constructed entries.
        if p == 0
            || end < begin
            || e.data.len() as u64 != end - begin + 1
            || first.total.is_some_and(|t| p > t)
        {
            return Err(Error::InvalidData("yenc: bad part"));
        }
        part_nums.push(p);
        sorted.push(e);
    }
    if let Some(t) = first.total
        && parts.len() as u64 != u64::from(t)
    {
        return Err(Error::InvalidData("yenc: missing part"));
    }
    part_nums.sort_unstable();
    if part_nums.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error::InvalidData("yenc: duplicate part"));
    }
    sorted.sort_by_key(|e| e.range.unwrap().0);
    let mut expected = 1u64;
    let mut data = Vec::new();
    for e in &sorted {
        let (begin, end) = e.range.unwrap();
        if begin != expected {
            return Err(Error::InvalidData("yenc: missing part"));
        }
        data.extend_from_slice(&e.data);
        expected = end + 1;
    }
    Ok(YEncEntry {
        name: first.name.clone(),
        data,
        part: None,
        total: None,
        range: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn rotate16_sse2_matches_scalar() {
        let src: Vec<u8> = (0..16).map(|i| i as u8).collect();
        let mut wide = vec![0u8; 16];
        let mut scalar = vec![0u8; 16];
        unsafe { rotate16_sse2(&src, &mut wide) };
        rotate_scalar(&src, &mut scalar);
        assert_eq!(wide, scalar);
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    #[test]
    fn rotate16_wasm_matches_scalar() {
        let src: Vec<u8> = (0..16).map(|i| i as u8).collect();
        let mut wide = vec![0u8; 16];
        let mut scalar = vec![0u8; 16];
        rotate16_wasm(&src, &mut wide);
        rotate_scalar(&src, &mut scalar);
        assert_eq!(wide, scalar);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn rotate16_neon_matches_scalar() {
        let src: Vec<u8> = (0..16).map(|i| i as u8).collect();
        let mut wide = vec![0u8; 16];
        let mut scalar = vec![0u8; 16];
        unsafe { rotate16_neon(&src, &mut wide) };
        rotate_scalar(&src, &mut scalar);
        assert_eq!(wide, scalar);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    #[test]
    fn rotate32_avx2_matches_scalar() {
        let src: Vec<u8> = (0..96).map(|i| i as u8).collect();
        let mut wide = vec![0u8; 32];
        let mut scalar = vec![0u8; 32];
        unsafe { rotate32_avx2(&src[..32], &mut wide) };
        rotate_scalar(&src[..32], &mut scalar);
        assert_eq!(wide, scalar);
        let mut via_chunk = vec![0u8; src.len()];
        let mut all_scalar = vec![0u8; src.len()];
        rotate_chunk(&src, &mut via_chunk);
        rotate_scalar(&src, &mut all_scalar);
        assert_eq!(via_chunk, all_scalar);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512bw"))]
    #[test]
    fn rotate64_avx512_matches_scalar() {
        let src: Vec<u8> = (0..160).map(|i| i as u8).collect();
        let mut wide = vec![0u8; 64];
        let mut scalar = vec![0u8; 64];
        unsafe { rotate64_avx512(&src[..64], &mut wide) };
        rotate_scalar(&src[..64], &mut scalar);
        assert_eq!(wide, scalar);
        let mut via_chunk = vec![0u8; src.len()];
        let mut all_scalar = vec![0u8; src.len()];
        rotate_chunk(&src, &mut via_chunk);
        rotate_scalar(&src, &mut all_scalar);
        assert_eq!(via_chunk, all_scalar);
    }

    #[test]
    fn short_line_trailing_space_or_tab_roundtrips() {
        for data in [b"\x00\xdf".as_slice(), b"\xf6", b"\xdf", b"abc\xdf"] {
            let encoded = encode("fuzz", data);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded.data, data, "data {data:?}");
        }
    }

    #[test]
    fn vector_matches_scalar_lengths_and_escapes() {
        let mut samples: Vec<Vec<u8>> = (0..=8).map(|n| vec![0x41; n]).collect();
        samples.push(vec![0x00, 0x0a, 0x0d, b'=', b'.', b' ', b'\t', 0xff]);
        samples.push(vec![0; 128]);
        samples.push(vec![1; 129]);
        samples.push({
            let mut v = vec![0x20; 200];
            v[0] = b'.';
            v[127] = 0;
            v[128] = b'\n';
            v
        });
        for data in samples {
            assert_eq!(
                encode("n.bin", &data),
                encode_scalar("n.bin", &data),
                "len {}",
                data.len()
            );
        }
    }

    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0..=255u32).cycle().take(1000).map(|v| v as u8).collect();
        let doc = encode("test.bin", &data);
        let e = decode(&doc).unwrap();
        assert_eq!(e.name, "test.bin");
        assert_eq!(e.data, data);
        assert_eq!(e.part, None);
        assert_eq!(e.range, None);
    }

    #[test]
    fn empty_and_small() {
        for data in [&b""[..], b"a", b"\x00\x00\x00"] {
            let e = decode(&encode("f", data)).unwrap();
            assert_eq!(e.data, data);
        }
    }

    #[test]
    fn escapes_critical() {
        // Encoded byte values NUL/LF/CR/'=' must be escape-paired.
        // Input bytes producing them: 214->0, 224->10, 227->13, 19->'='.
        let data = [214u8, 224, 227, 19];
        let doc = encode("c", &data);
        let text = String::from_utf8(doc).unwrap();
        let body = text.lines().nth(1).unwrap();
        assert_eq!(body, "=@=J=M=}");
        assert_eq!(decode(text.as_bytes()).unwrap().data, data);
    }

    #[test]
    fn first_col_space_tab_dot_escaped() {
        // Encoded ' '(32): input 246 -> '=' + '`'(96).
        let doc = encode("c", &[246]);
        let text = String::from_utf8(doc).unwrap();
        assert!(text.contains("\r\n=`"), "doc: {text:?}");
        assert_eq!(decode(text.as_bytes()).unwrap().data, [246]);
        // Encoded '.': input 4 -> '=' + 'n'(110).
        let doc = encode("c", &[4]);
        assert!(String::from_utf8(doc).unwrap().contains("\r\n=n"));
    }

    #[test]
    fn line_length_rule() {
        // A line may only exceed 128 chars by ending on an escape pair.
        let data = [65u8; 500];
        let doc = encode("l", &data);
        for line in String::from_utf8_lossy(&doc).lines() {
            if line.starts_with("=y") {
                continue;
            }
            assert!(line.len() <= LINE_LEN + 1, "line too long: {}", line.len());
            if line.len() == LINE_LEN + 1 {
                assert_eq!(line.as_bytes()[LINE_LEN - 1], b'=');
            }
        }
    }

    #[test]
    fn multipart_roundtrip() {
        let whole: Vec<u8> = (0..300u32).map(|v| v as u8).collect();
        let doc = encode_part("m.bin", 2, 3, 101, &whole[100..200], 300);
        let e = decode(&doc).unwrap();
        assert_eq!(e.name, "m.bin");
        assert_eq!(e.part, Some(2));
        assert_eq!(e.range, Some((101, 200)));
        assert_eq!(e.data, whole[100..200]);
    }

    #[test]
    fn rejects_missing_keywords() {
        assert!(decode(b"no yenc here").is_err());
        // =ybegin without size/name is discussion text -> skipped -> EOF.
        assert!(decode(b"=ybegin just text\n=yend size=0").is_err());
        // Truncated: no =yend.
        assert!(decode(b"=ybegin line=128 size=1 name=x\n*\r\n").is_err());
    }

    #[test]
    fn rejects_size_and_crc_mismatch() {
        let doc = encode("s", b"hello world");
        // Corrupt the declared size (both header and trailer), byte-level
        // because yEnc output is 8-bit, not UTF-8.
        let bad: Vec<u8> = doc
            .windows(7)
            .enumerate()
            .fold(doc.clone(), |mut v, (i, w)| {
                if w == b"size=11" {
                    v[i + 6] = b'0';
                }
                v
            });
        assert!(decode(&bad).is_err());
        // Corrupt one data byte -> crc32 mismatch (crc32 present in =yend).
        let mut doc2 = doc;
        let pos = doc2.iter().position(|&b| b == b'h' + 42).unwrap();
        doc2[pos] ^= 1;
        assert!(decode(&doc2).is_err());
    }

    #[test]
    fn multipart_requires_ypart_and_matching_part() {
        let doc = encode_part("m", 1, 2, 1, b"partdata", 16);
        // Remove the =ypart line (byte-level: yEnc output is 8-bit).
        let bad: Vec<u8> = doc
            .split(|&b| b == b'\n')
            .filter(|l| !l.starts_with(b"=ypart"))
            .collect::<Vec<_>>()
            .join(&b'\n');
        assert!(decode(&bad).is_err());
        // Mismatched trailer part number.
        let pos = doc.windows(13).position(|w| w == b"part=1 pcrc32").unwrap();
        let mut bad2 = doc.clone();
        bad2[pos + 5] = b'2';
        assert!(decode(&bad2).is_err());
    }

    #[test]
    fn multipart_total_validation() {
        // Hand-assembled multipart docs: encode_part() asserts
        // part <= total, so the invalid headers cannot come from it.
        let doc = |begin: &[u8], ypart: &[u8], trailer: &[u8]| {
            let mut v = Vec::new();
            v.extend_from_slice(begin);
            v.push(b'\n');
            v.extend_from_slice(ypart);
            v.push(b'\n');
            push_encoded(&mut v, b"12345678");
            v.extend_from_slice(trailer);
            v.push(b'\n');
            v
        };
        // part > total -> rejected.
        assert!(
            decode(&doc(
                b"=ybegin part=3 total=2 line=128 size=16 name=m",
                b"=ypart begin=1 end=8",
                b"=yend size=8 part=3"
            ))
            .is_err()
        );
        // part == total but =ypart end does not reach `size` -> rejected.
        assert!(
            decode(&doc(
                b"=ybegin part=2 total=2 line=128 size=16 name=m",
                b"=ypart begin=1 end=8",
                b"=yend size=8 part=2"
            ))
            .is_err()
        );
        // Consistent total -> accepted (last part ends at `size`).
        let ok = encode_part("m", 2, 2, 9, b"partdata", 16);
        assert_eq!(decode(&ok).unwrap().range, Some((9, 16)));
        // total absent (pre-1.2 writers) -> accepted.
        assert_eq!(
            decode(&doc(
                b"=ybegin part=1 line=128 size=16 name=m",
                b"=ypart begin=1 end=8",
                b"=yend size=8 part=1"
            ))
            .unwrap()
            .data,
            b"12345678"
        );
    }

    #[test]
    fn ignores_surrounding_text() {
        let doc = encode("t", b"payload!");
        let mut wrapped = b"Subject: blah\nFrom: someone\n\n".to_vec();
        wrapped.extend_from_slice(&doc);
        wrapped.extend_from_slice(b"--sig\n");
        assert_eq!(decode(&wrapped).unwrap().data, b"payload!");
    }

    #[test]
    fn rejects_dangling_escape() {
        assert!(decode(b"=ybegin line=128 size=2 name=x\nab=\n=yend size=2").is_err());
    }

    /// Encode+decode `whole` as one part per `(start, end)` slice of `cuts`.
    fn make_parts(name: &str, whole: &[u8], cuts: &[(usize, usize)]) -> Vec<YEncEntry> {
        let total = cuts.len() as u32;
        cuts.iter()
            .enumerate()
            .map(|(i, &(s, e))| {
                decode(&encode_part(
                    name,
                    i as u32 + 1,
                    total,
                    s as u64 + 1,
                    &whole[s..e],
                    whole.len() as u64,
                ))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn join_parts_roundtrip() {
        let whole: Vec<u8> = (0..300u32).map(|v| v as u8).collect();
        let parts = make_parts("m.bin", &whole, &[(0, 100), (100, 200), (200, 300)]);
        let joined = join_parts(&parts).unwrap();
        assert_eq!(joined.name, "m.bin");
        assert_eq!(joined.data, whole);
        // The joined whole looks like a decoded single-part document.
        assert_eq!(joined.part, None);
        assert_eq!(joined.total, None);
        assert_eq!(joined.range, None);
        // A multipart binary consisting of a single part is accepted.
        let one = make_parts("m.bin", &whole, &[(0, 300)]);
        assert_eq!(join_parts(&one).unwrap().data, whole);
    }

    #[test]
    fn join_parts_detects_missing_part() {
        let whole: Vec<u8> = (0..300u32).map(|v| v as u8).collect();
        let parts = make_parts("m.bin", &whole, &[(0, 100), (100, 200), (200, 300)]);
        // Middle part missing.
        assert!(join_parts(&[parts[0].clone(), parts[2].clone()]).is_err());
        // Final part missing: the remaining ranges tile 1..=200 with no
        // gap, so this is only caught by the `total` count check.
        assert!(join_parts(&parts[..2]).is_err());
        // `total` absent (pre-1.2 writers): an interior gap is still
        // detected via the =ypart ranges.
        let mut e1 = parts[0].clone();
        let mut e3 = parts[2].clone();
        e1.total = None;
        e3.total = None;
        assert!(join_parts(&[e1, e3]).is_err());
        // Empty input.
        assert!(join_parts(&[]).is_err());
    }

    #[test]
    fn join_parts_reorders() {
        let whole: Vec<u8> = (0..300u32).map(|v| v as u8).collect();
        let parts = make_parts("m.bin", &whole, &[(0, 100), (100, 200), (200, 300)]);
        let shuffled = [parts[2].clone(), parts[0].clone(), parts[1].clone()];
        let joined = join_parts(&shuffled).unwrap();
        assert_eq!(joined.data, whole);
    }

    #[test]
    fn join_parts_rejects_name_mismatch() {
        let whole: Vec<u8> = (0..300u32).map(|v| v as u8).collect();
        let mut parts = make_parts("m.bin", &whole, &[(0, 100), (100, 200), (200, 300)]);
        // A part of a different file mixed in.
        parts[1] = decode(&encode_part("other.bin", 2, 3, 101, &whole[100..200], 300)).unwrap();
        assert!(join_parts(&parts).is_err());
        // Duplicate part number is rejected too.
        let mut dup = make_parts("m.bin", &whole, &[(0, 100), (100, 200), (200, 300)]);
        dup[1] = dup[0].clone();
        assert!(join_parts(&dup).is_err());
        // A single-part (non-multipart) entry is rejected.
        let single = decode(&encode("plain.bin", &whole)).unwrap();
        assert!(join_parts(&[single]).is_err());
    }

    #[test]
    fn truncated_before_yend_rejected() {
        // The `=yend` trailer is mandatory: every cut before the
        // trailer line must fail.
        let doc = encode("f.bin", b"yenc boundary test data");
        let yend = doc.windows(5).rposition(|w| w == b"=yend").unwrap();
        for cut in 0..yend {
            assert!(
                decode(&doc[..cut]).is_err(),
                "cut={cut} unexpectedly decoded"
            );
        }
    }

    #[test]
    fn truncated_yend_trailer_boundaries() {
        // `crc32=` is optional: a cut that keeps `=yend size=N` but
        // drops the crc32 parameter still validates by size alone.
        let data = b"yenc boundary test data";
        let doc = encode("f.bin", data);
        let crc_pos = doc.windows(5).rposition(|w| w == b"crc32").unwrap();
        // Drop " crc32=XXXXXXXX\r\n" — `size` remains complete.
        let e = decode(&doc[..crc_pos - 1]).unwrap();
        assert_eq!(e.data, data);
        // Dropping only the trailing CRLF keeps a complete trailer.
        let e = decode(&doc[..doc.len() - 2]).unwrap();
        assert_eq!(e.data, data);
        // A trailer line without `size=` is rejected.
        let size_pos = doc.windows(4).rposition(|w| w == b"size").unwrap();
        assert!(decode(&doc[..size_pos]).is_err());
    }
}
