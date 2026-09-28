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
    // First output line holds ':' + 63 characters; later lines 64.
    let mut col = 1usize;
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        nbits += 8;
        while nbits >= 6 {
            nbits -= 6;
            out.push(ALPHABET[((acc >> nbits) & 0x3F) as usize]);
            col += 1;
            if col == 64 {
                out.push(b'\n');
                col = 0;
            }
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((acc << (6 - nbits)) & 0x3F) as usize]);
    }
    out.extend_from_slice(b":\n");
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
                // before the final ':' — drop it in that case only.
                let mut j = i;
                while j < input.len() && matches!(input[j], b'\r' | b'\n' | b'\t' | b' ') {
                    j += 1;
                }
                if j < input.len() && input[j] == b':' {
                    break;
                }
                chars.push(c);
            }
            _ => chars.push(c),
        }
    }

    let raw8 = sixbit_decode(&chars)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
