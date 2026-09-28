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
//! supported (`part=`/`=ypart`/`pcrc32` verification). Joining multiple
//! parts into the whole file is the caller's responsibility.

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
    /// Inclusive byte range of this part within the whole file (`=ypart`).
    pub range: Option<(u64, u64)>,
}

fn push_encoded(out: &mut Vec<u8>, data: &[u8]) {
    let mut col = 0usize;
    for &b in data {
        let c = b.wrapping_add(42);
        let last_col = col + 1 >= LINE_LEN;
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
    if col > 0 {
        out.extend_from_slice(b"\r\n");
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
    push_encoded(&mut out, data);
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
/// `=ypart` ranges, `crc32=`, and `pcrc32=` are verified; a mismatch is an
/// error (the spec requires the decoded binary to be discarded then).
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
    let part = get_u64(&params, b"part").map(|v| v as u32);
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
        && get_u64(&tp, b"part") != Some(n as u64)
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
        part,
        range,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
