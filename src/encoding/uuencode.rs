//! uuencode (POSIX.1-2017 `uuencode` historical algorithm).
//!
//! A file is wrapped in `begin <mode> <name>` / `end` lines. Data is split
//! into lines of at most 45 source bytes; each line starts with a length
//! character (`decoded_len + 0x20`) and encodes three input octets as four
//! output characters `(6-bit value) + 0x20`.
//!
//! The encoder emits the de facto zero representation `` ` `` (0x60) used
//! by GNU sharutils; the decoder accepts both `` ` `` and ` ` (0x20) as the
//! zero value, and accepts the optional zero-length line before `end`.
//! The POSIX Base64 algorithm is also supported: documents wrapped in
//! `begin-base64 <mode> <name>` / `====` lines carry a MIME Base64 body
//! in lines of at most 76 characters.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::base64;

/// Maximum number of source octets encoded on one line (POSIX STDOUT).
const MAX_LINE_OCTETS: usize = 45;

/// Maximum Base64 characters on one begin-base64 body line (POSIX STDOUT).
const MAX_BASE64_LINE: usize = 76;

/// One decoded uuencode member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuEntry {
    /// `decode_pathname` from the `begin` line.
    pub name: String,
    /// Permission bits from the `begin` line (octal).
    pub mode: u32,
    /// Decoded file contents.
    pub data: Vec<u8>,
}

fn enc_char(v: u8) -> u8 {
    let v = v & 0x3F;
    if v == 0 { b'`' } else { v + 0x20 }
}

fn dec_char(c: u8) -> Result<u8, Error> {
    match c {
        b'`' | b' ' => Ok(0),
        0x21..=0x5f => Ok(c - 0x20),
        _ => Err(Error::InvalidData("uuencode: invalid character")),
    }
}

/// Encode `data` as a uuencode document (`begin`/`end` wrapper included).
///
/// `mode` is written as octal permission bits; `name` must not contain
/// newlines (returns empty-line-safe error via [`Error::InvalidData`] at
/// [`encode`] call sites — checked here and returns an error by contract).
///
/// # Panics
///
/// Panics if `name` is empty or contains a newline, or if `mode` exceeds
/// `0o7777`.
pub fn encode(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
    assert!(
        !name.is_empty() && !name.contains('\n'),
        "uuencode: bad name"
    );
    assert!(mode <= 0o7777, "uuencode: bad mode");

    let mut out = Vec::new();
    out.extend_from_slice(b"begin ");
    out.extend_from_slice(alloc::format!("{mode:o}").as_bytes());
    out.push(b' ');
    out.extend_from_slice(name.as_bytes());
    out.push(b'\n');

    for chunk in data.chunks(MAX_LINE_OCTETS) {
        out.push(enc_char(chunk.len() as u8));
        for trio in chunk.chunks(3) {
            let a = trio[0] as u32;
            let b = *trio.get(1).unwrap_or(&0) as u32;
            let c = *trio.get(2).unwrap_or(&0) as u32;
            out.push(enc_char((a >> 2) as u8));
            out.push(enc_char(((a << 4) | (b >> 4)) as u8));
            out.push(enc_char(((b << 2) | (c >> 6)) as u8));
            out.push(enc_char(c as u8));
        }
        out.push(b'\n');
    }

    out.extend_from_slice(b"`\nend\n");
    out
}

/// Encode `data` as a POSIX `begin-base64` uuencode document.
///
/// The body is standard Base64 (RFC 4648 alphabet, `=` padding) wrapped at
/// 76 characters per line and terminated by a `====` line.
///
/// # Panics
///
/// Panics under the same conditions as [`encode`].
pub fn encode_base64(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
    assert!(
        !name.is_empty() && !name.contains('\n'),
        "uuencode: bad name"
    );
    assert!(mode <= 0o7777, "uuencode: bad mode");

    let mut out = Vec::new();
    out.extend_from_slice(b"begin-base64 ");
    out.extend_from_slice(alloc::format!("{mode:o}").as_bytes());
    out.push(b' ');
    out.extend_from_slice(name.as_bytes());
    out.push(b'\n');

    let encoded = base64::encode(data);
    for line in encoded.chunks(MAX_BASE64_LINE) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"====\n");
    out
}

fn next_line<'a>(input: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos >= input.len() {
        return None;
    }
    let end = input[*pos..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| *pos + i)
        .unwrap_or(input.len());
    let line = &input[*pos..end];
    *pos = if end < input.len() {
        end + 1
    } else {
        input.len()
    };
    // Tolerate CRLF.
    Some(line.strip_suffix(b"\r").map_or(line, |l| l))
}

/// Decode a complete uuencode document.
///
/// The input must start with a `begin <mode> <name>` or
/// `begin-base64 <mode> <name>` line; the body is decoded with the matching
/// historical or Base64 algorithm.
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<UuEntry, Error> {
    let mut pos = 0usize;
    let begin = next_line(input, &mut pos).ok_or(Error::UnexpectedEof)?;
    if begin.starts_with(b"begin-base64") {
        let rest = begin
            .strip_prefix(b"begin-base64 ")
            .ok_or(Error::InvalidData("uuencode: bad begin-base64 line"))?;
        let (mode, name) = parse_mode_name(rest)?;
        return decode_base64_body(input, &mut pos, name, mode);
    }
    let rest = begin
        .strip_prefix(b"begin ")
        .ok_or(Error::InvalidData("uuencode: missing begin line"))?;
    let (mode, name) = parse_mode_name(rest)?;

    let mut data = Vec::new();
    loop {
        let line = next_line(input, &mut pos).ok_or(Error::UnexpectedEof)?;
        if line == b"end" {
            return Ok(UuEntry { name, mode, data });
        }
        if line.is_empty() {
            continue; // tolerate blank lines
        }
        let count = dec_char(line[0])? as usize;
        if count == 0 {
            // Zero-length line: the next line must be `end`.
            continue;
        }
        if count > MAX_LINE_OCTETS {
            return Err(Error::InvalidData("uuencode: line too long"));
        }
        let body = &line[1..];
        let needed = count.div_ceil(3) * 4;
        if body.len() < needed {
            return Err(Error::UnexpectedEof);
        }
        let mut produced = 0usize;
        for quad in body[..needed].chunks(4) {
            let v0 = dec_char(quad[0])? as u32;
            let v1 = dec_char(quad[1])? as u32;
            let v2 = dec_char(quad[2])? as u32;
            let v3 = dec_char(quad[3])? as u32;
            data.push((v0 << 2 | v1 >> 4) as u8);
            data.push((v1 << 4 | v2 >> 2) as u8);
            data.push((v2 << 6 | v3) as u8);
            produced += 3;
        }
        // The final quad may cover fewer than three source octets.
        data.truncate(data.len() - (produced - count));
    }
}

/// Parse the `<mode> <name>` fields shared by `begin` and `begin-base64`.
fn parse_mode_name(rest: &[u8]) -> Result<(u32, String), Error> {
    let sp = rest
        .iter()
        .position(|&b| b == b' ')
        .ok_or(Error::InvalidData("uuencode: bad begin line"))?;
    let mode_str = core::str::from_utf8(&rest[..sp])
        .map_err(|_| Error::InvalidData("uuencode: bad mode field"))?;
    let mode =
        u32::from_str_radix(mode_str, 8).map_err(|_| Error::InvalidData("uuencode: bad mode"))?;
    let name = String::from_utf8_lossy(&rest[sp + 1..]).into_owned();
    if name.is_empty() {
        return Err(Error::InvalidData("uuencode: empty name"));
    }
    Ok((mode, name))
}

/// Decode the body of a `begin-base64` document: Base64 lines up to the
/// `====` terminator line (POSIX.1-2017 uuencode Base64 Algorithm).
fn decode_base64_body(
    input: &[u8],
    pos: &mut usize,
    name: String,
    mode: u32,
) -> Result<UuEntry, Error> {
    let mut b64 = Vec::new();
    loop {
        let line = next_line(input, pos).ok_or(Error::UnexpectedEof)?;
        if line == b"====" {
            break;
        }
        if line.is_empty() {
            continue; // tolerate blank lines
        }
        b64.extend_from_slice(line);
    }
    let data = base64::decode(&b64)?;
    Ok(UuEntry { name, mode, data })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_text() {
        let doc = encode("hello.txt", 0o644, b"Hello, world!\n");
        let e = decode(&doc).unwrap();
        assert_eq!(e.name, "hello.txt");
        assert_eq!(e.mode, 0o644);
        assert_eq!(e.data, b"Hello, world!\n");
    }

    #[test]
    fn roundtrip_binary_multiline() {
        let data: Vec<u8> = (0..=255).collect();
        let doc = encode("bin.dat", 0o600, &data);
        let e = decode(&doc).unwrap();
        assert_eq!(e.data, data);
    }

    #[test]
    fn roundtrip_empty() {
        let doc = encode("empty", 0, &[]);
        let e = decode(&doc).unwrap();
        assert!(e.data.is_empty());
        assert_eq!(e.mode, 0);
    }

    #[test]
    fn line_length_respected() {
        let data = vec![0xAA; 200];
        let doc = encode("d", 0o644, &data);
        // Longest encoded line: length char + 60 chars + newline.
        let lines: Vec<&[u8]> = doc.split(|&b| b == b'\n').collect();
        for l in &lines[1..lines.len() - 3] {
            assert!(l.len() <= 61);
        }
        assert_eq!(decode(&doc).unwrap().data, data);
    }

    #[test]
    fn decodes_space_zero_variant() {
        // POSIX allows ' ' (0x20) where GNU writes '`' (0x60).
        let doc = b"begin 644 f\n \nend\n";
        let e = decode(doc).unwrap();
        assert!(e.data.is_empty());
        let mut doc2 = encode("f", 0o644, b"\x00\x00\x00").to_vec();
        // our encoder emits '`'; python emits ' '
        for b in &mut doc2 {
            if *b == b'`' {
                *b = b' ';
            }
        }
        assert_eq!(decode(&doc2).unwrap().data, [0; 3]);
    }

    #[test]
    fn test_base64_roundtrip() {
        let doc = encode_base64("hello.txt", 0o644, b"Hello, world!\n");
        assert!(doc.starts_with(b"begin-base64 644 hello.txt\n"));
        assert!(doc.ends_with(b"====\n"));
        let e = decode(&doc).unwrap();
        assert_eq!(e.name, "hello.txt");
        assert_eq!(e.mode, 0o644);
        assert_eq!(e.data, b"Hello, world!\n");
    }

    #[test]
    fn test_base64_posix_example() {
        // Document laid out per POSIX.1-2017 uuencode Base64 Algorithm.
        let doc = b"begin-base64 755 dir/msg.txt\nSGVsbG8sIHdvcmxkIQ==\n====\n";
        let e = decode(doc).unwrap();
        assert_eq!(e.name, "dir/msg.txt");
        assert_eq!(e.mode, 0o755);
        assert_eq!(e.data, b"Hello, world!");
    }

    #[test]
    fn test_base64_padding_boundaries() {
        // len % 3 == 0, 1, 2 produce no '=', "==", and "=" tails.
        for data in [&b"abc"[..], &b"abcd"[..], &b"abcde"[..]] {
            let doc = encode_base64("f", 0o600, data);
            assert_eq!(decode(&doc).unwrap().data, data);
        }
        let e = decode(b"begin-base64 644 f\nQQ==\n====\n").unwrap();
        assert_eq!(e.data, b"A");
        let e = decode(b"begin-base64 644 f\nQUI=\n====\n").unwrap();
        assert_eq!(e.data, b"AB");
    }

    #[test]
    fn test_base64_multiline() {
        let data: Vec<u8> = (0..=255).collect();
        let doc = encode_base64("bin", 0o644, &data);
        // POSIX caps Base64 body lines at 76 characters.
        for line in doc.split(|&b| b == b'\n') {
            assert!(line.len() <= MAX_BASE64_LINE);
        }
        assert_eq!(decode(&doc).unwrap().data, data);
        // Line breaks inside the body are insignificant to the decoder.
        let doc = b"begin-base64 644 f\nZm9v\nYmE=\n====\n";
        assert_eq!(decode(doc).unwrap().data, b"fooba");
    }

    #[test]
    fn test_base64_empty() {
        let doc = encode_base64("e", 0o644, &[]);
        assert_eq!(&doc[..], &b"begin-base64 644 e\n====\n"[..]);
        let e = decode(&doc).unwrap();
        assert!(e.data.is_empty());
    }

    #[test]
    fn test_base64_rejected() {
        // Character outside the Base64 alphabet.
        assert!(decode(b"begin-base64 644 f\nZm!v\n====\n").is_err());
        // Padding in a non-final quantum (data after '=').
        assert!(decode(b"begin-base64 644 f\nZg==\nZm9v\n====\n").is_err());
        // Malformed begin-base64 header (no mode/name fields).
        assert!(decode(b"begin-base64\nZm9v\n====\n").is_err());
    }

    #[test]
    fn test_base64_rejected_missing_terminator() {
        assert!(matches!(
            decode(b"begin-base64 644 f\nZm9v\n"),
            Err(Error::UnexpectedEof)
        ));
    }

    #[test]
    fn rejects_no_begin() {
        assert!(matches!(decode(b"hello\n"), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_truncated_body() {
        let doc = b"begin 644 f\nM234\n"; // length says 45, body missing
        assert!(matches!(decode(doc), Err(Error::UnexpectedEof)));
    }

    #[test]
    fn rejects_missing_end() {
        let doc = encode("f", 0o644, b"x");
        let cut = &doc[..doc.len() - 4]; // drop "end\n"
        assert!(matches!(decode(cut), Err(Error::UnexpectedEof)));
    }
}
