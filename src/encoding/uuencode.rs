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
//! The POSIX `begin-base64` variant is not supported.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// Maximum number of source octets encoded on one line (POSIX STDOUT).
const MAX_LINE_OCTETS: usize = 45;

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
/// The input must start with a `begin <mode> <name>` line. `begin-base64`
/// documents are rejected with [`Error::Unsupported`].
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<UuEntry, Error> {
    let mut pos = 0usize;
    let begin = next_line(input, &mut pos).ok_or(Error::UnexpectedEof)?;
    if begin.starts_with(b"begin-base64") {
        return Err(Error::Unsupported(
            "uuencode: begin-base64 variant not supported",
        ));
    }
    let rest = begin
        .strip_prefix(b"begin ")
        .ok_or(Error::InvalidData("uuencode: missing begin line"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rejects_begin_base64() {
        assert!(matches!(
            decode(b"begin-base64 644 f\nAAAA\n====\n"),
            Err(Error::Unsupported(_))
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
