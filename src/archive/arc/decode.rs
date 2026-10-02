//! SEA ARC (`.arc`) archive read and write support.
//!
//! Reference: the ARC file format description published by System
//! Enhancement Associates (arc specification / wotsit "arc" entry).
//! Supported scope:
//!
//! - reading: method 1 (obsolete unpacked), method 2
//!   (stored), method 3 (packed/RLE90), method 4 (squeezed), methods
//!   5-7 (crunched hash-LZW variants), method 8 (crunched), method 9
//!   (squashed), method 0x0a (crushed) and method 0x0b (distilled).
//!   ARC 6.0+ informational/control items (methods 20-39) share the
//!   regular member header and are skipped without producing entries;
//!   methods 12-19 and 40+ are rejected with [`Error::Unsupported`];
//! - writing: methods 1-0x0b entries.
//!
//! Layout: each member starts with `0x1A` and a method byte; method 0
//! marks end of archive. Method-1 records are
//! `[name 13B][size u32le][date u16le][time u16le][crc16 u16le]
//! [data]` — the regular header minus the original-length field;
//! methods >= 2 use
//! `[name 13B][length u32le][date u16le][time u16le][crc16 u16le]
//! [size u32le][data]` where `length` is the stored (compressed) data
//! size and `size` is the original uncompressed size (equal for method
//! 2; for method 3 `length` is the RLE90 packed size). The CRC-16
//! covers the uncompressed data. ARC has no directory entries and
//! names are flat, NUL-padded, at most 12 characters plus a terminator
//! byte.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

use super::{crunch, crush, distill, rle90, squeeze};

pub(crate) const MARKER: u8 = 0x1A;
pub(crate) const NAME_LEN: usize = 13;

/// One decoded ARC member.
#[derive(Debug, Clone)]
pub struct ArcEntry {
    /// File name (no directory component; ARC is flat).
    pub name: String,
    /// Member method byte as read.
    pub method: u8,
    /// DOS date field (0 when absent/unset).
    pub date: u16,
    /// DOS time field (0 when absent/unset).
    pub time: u16,
    /// Data CRC-16 carried in the member header (all methods).
    pub crc16: Option<u16>,
    /// Member payload.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ArcEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn parse_name(raw: &[u8]) -> Result<String, Error> {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    let s = core::str::from_utf8(&raw[..end])
        .map_err(|_| Error::InvalidData("arc: name is not UTF-8"))?;
    if s.contains('/') || s.contains('\\') {
        return Err(Error::InvalidData("arc: path separator in name"));
    }
    Ok(s.into())
}

/// Decode an ARC archive into entries.
pub fn decode(input: &[u8]) -> Result<Vec<ArcEntry>, Error> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos >= input.len() {
            return Ok(entries);
        }
        if input[pos] != MARKER {
            return Err(Error::InvalidData("arc: bad marker"));
        }
        pos += 1;
        if pos >= input.len() {
            return Err(Error::InvalidData("arc: truncated header"));
        }
        let method = input[pos];
        pos += 1;
        if method == 0 {
            return Ok(entries);
        }
        if (20..=39).contains(&method) {
            // ARC 6.0+ informational/control item: same 27-byte
            // header as a regular member (name + length + date/
            // time/crc16/size); the payload is skipped and no
            // entry is produced.
            if pos + NAME_LEN + 14 > input.len() {
                return Err(Error::InvalidData("arc: truncated header"));
            }
            let length = u32le(&input[pos + NAME_LEN..]) as usize;
            pos += NAME_LEN + 14;
            if pos + length > input.len() {
                return Err(Error::InvalidData("arc: truncated member data"));
            }
            pos += length;
            continue;
        }
        if !matches!(method, 1..=0x0b) {
            return Err(Error::Unsupported("arc: unsupported method"));
        }
        if pos + NAME_LEN + 4 > input.len() {
            return Err(Error::InvalidData("arc: truncated header"));
        }
        let name = parse_name(&input[pos..pos + NAME_LEN])?;
        pos += NAME_LEN;
        // Bytes 16-19 hold the stored (compressed) data size.
        let length = u32le(&input[pos..]) as usize;
        pos += 4;
        let (date, time, crc16, size) = if method == 1 {
            // Obsolete unpacked member: the header is the regular
            // member header minus the original-length field (25
            // bytes), so date/time/CRC-16 are still present; the
            // stored size doubles as the original size.
            if pos + 6 > input.len() {
                return Err(Error::InvalidData("arc: truncated header"));
            }
            let date = u16le(&input[pos..]);
            let time = u16le(&input[pos + 2..]);
            let crc = u16le(&input[pos + 4..]);
            pos += 6;
            (date, time, Some(crc), length)
        } else {
            if pos + 10 > input.len() {
                return Err(Error::InvalidData("arc: truncated header"));
            }
            let date = u16le(&input[pos..]);
            let time = u16le(&input[pos + 2..]);
            let crc = u16le(&input[pos + 4..]);
            // Bytes 26-29 hold the original (uncompressed) length.
            let size = u32le(&input[pos + 6..]) as usize;
            pos += 10;
            (date, time, Some(crc), size)
        };
        if pos + length > input.len() {
            return Err(Error::InvalidData("arc: truncated member data"));
        }
        let packed = &input[pos..pos + length];
        pos += length;
        let data = match method {
            3 => {
                // Packed member: RLE90-expand; output must match the
                // declared uncompressed size.
                rle90::decode(packed, size)?
            }
            4 => {
                // Squeezed member: static Huffman over an RLE90 stream.
                squeeze::decode(packed, size)?
            }
            5 => {
                // Crunched (obsolete): quadratic-hash 12-bit LZW, no
                // RLE stage.
                let out = crunch::decode(packed, crunch::CrunchHash::Quadratic, size)?;
                if out.len() != size {
                    return Err(Error::InvalidData("arc: size mismatch"));
                }
                out
            }
            6 => {
                // Crunched: quadratic-hash 12-bit LZW over an RLE90
                // stream. The intermediate RLE stream is bounded at
                // 2x the original size (worst case: all 0x90 literals).
                let s = crunch::decode(
                    packed,
                    crunch::CrunchHash::Quadratic,
                    size.saturating_mul(2),
                )?;
                rle90::decode(&s, size)?
            }
            7 => {
                // Crunched (fast hash): multiplicative-hash 12-bit LZW
                // over an RLE90 stream.
                let s = crunch::decode(
                    packed,
                    crunch::CrunchHash::Multiplicative,
                    size.saturating_mul(2),
                )?;
                rle90::decode(&s, size)?
            }
            8 => {
                // Crunched member: one maxbits byte, then a
                // compress-style dynamic LZW stream, then RLE90.
                let (&maxb, body) = packed
                    .split_first()
                    .ok_or(Error::InvalidData("arc: truncated crunched member"))?;
                let lzw = crate::compress::lzw::decode::decode_body(body, u32::from(maxb), true)?;
                rle90::decode(&lzw, size)?
            }
            9 => {
                // Squashed member: compress-style dynamic LZW (13-bit
                // ceiling), no RLE stage.
                let out = crate::compress::lzw::decode::decode_body(packed, 13, true)?;
                if out.len() != size {
                    return Err(Error::InvalidData("arc: size mismatch"));
                }
                out
            }
            0x0a => {
                // Crushed member: adaptive LZW with usage-based
                // replacement, over an RLE90 stream.
                let s = crush::decode(packed, size.saturating_mul(2))?;
                rle90::decode(&s, size)?
            }
            0x0b => {
                // Distilled member: LZSS + header Huffman; the stream
                // is authoritative on length.
                let out = distill::decode(packed)?;
                if out.len() != size {
                    return Err(Error::InvalidData("arc: size mismatch"));
                }
                out
            }
            _ => {
                // Stored members (methods 1/2): length equals the
                // uncompressed size.
                if packed.len() != size {
                    return Err(Error::InvalidData("arc: size mismatch"));
                }
                packed.to_vec()
            }
        };
        if let Some(c) = crc16
            && crate::util::crc16::crc16(&data) != c
        {
            return Err(Error::InvalidData("arc: CRC-16 mismatch"));
        }
        entries.push(ArcEntry {
            name,
            method,
            date,
            time,
            crc16,
            data,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = crate::archive::arc::encode::encode(&[
            ("HELLO.TXT", b"hi arc"),
            ("DATA.BIN", &[1, 2, 3]),
        ])
        .unwrap();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "HELLO.TXT");
        assert_eq!(e[0].data, b"hi arc");
        assert_eq!(e[0].method, 2);
        assert!(e[1].crc16.is_some());
    }

    /// Build a method-1 member record: name + size + date + time +
    /// crc16 + raw data (the regular header minus the
    /// original-length field).
    fn build_method1_member(name: &str, date: u16, time: u16, data: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&[MARKER, 1]);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        a.extend_from_slice(&field);
        a.extend_from_slice(&(data.len() as u32).to_le_bytes());
        a.extend_from_slice(&date.to_le_bytes());
        a.extend_from_slice(&time.to_le_bytes());
        a.extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        a.extend_from_slice(data);
        a.extend_from_slice(&[MARKER, 0]);
        a
    }

    #[test]
    fn method1_member() {
        // Hand-built method-1 (obsolete unpacked) record.
        let a = build_method1_member("F.B", 0x1234, 0x5678, b"xyz");
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, "F.B");
        assert_eq!(e[0].data, b"xyz");
        assert_eq!(e[0].date, 0x1234);
        assert_eq!(e[0].time, 0x5678);
        assert_eq!(e[0].crc16, Some(crate::util::crc16::crc16(b"xyz")));
    }

    #[test]
    fn method1_rejects_bad_crc() {
        // Method-1 members carry a CRC-16 like every other method.
        let mut a = build_method1_member("F.B", 0, 0, b"xyz");
        let n = a.len();
        a[n - 3] ^= 0xff;
        assert!(decode(&a).is_err());
        // A header cut short inside the date/time/crc16 fields.
        assert!(decode(&a[..2 + NAME_LEN + 4 + 4]).is_err());
    }

    #[test]
    fn method1_roundtrip() {
        let mut enc = crate::archive::arc::encode::ArcEncoder::new();
        enc.add_file_with_method("OLD.TXT", b"raw data", 0, 0, 1)
            .unwrap();
        enc.add_file("NEW.TXT", b"stored", 0, 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "OLD.TXT");
        assert_eq!(e[0].method, 1);
        assert!(e[0].crc16.is_some());
        assert_eq!(e[0].data, b"raw data");
        assert_eq!(e[1].name, "NEW.TXT");
        assert_eq!(e[1].method, 2);
        assert!(e[1].crc16.is_some());
    }

    #[test]
    fn method1_header_layout() {
        // Method-1 record: marker + method=1 + name[13] + size u32le +
        // date + time + crc16 + data. Only the original-length field
        // of the regular header is absent (25-byte header).
        let mut enc = crate::archive::arc::encode::ArcEncoder::new();
        enc.add_file_with_method("F.B", b"xyz", 0x1234, 0x5678, 1)
            .unwrap();
        let a = enc.finish();
        assert_eq!(a[0], MARKER);
        assert_eq!(a[1], 1);
        let mut field = [0u8; NAME_LEN];
        field[..3].copy_from_slice(b"F.B");
        assert_eq!(&a[2..2 + NAME_LEN], &field);
        assert_eq!(&a[2 + NAME_LEN..2 + NAME_LEN + 4], &3u32.to_le_bytes());
        let mut tail = Vec::new();
        tail.extend_from_slice(&0x1234u16.to_le_bytes());
        tail.extend_from_slice(&0x5678u16.to_le_bytes());
        tail.extend_from_slice(&crate::util::crc16::crc16(b"xyz").to_le_bytes());
        assert_eq!(&a[2 + NAME_LEN + 4..2 + NAME_LEN + 10], &tail[..]);
        // Data follows the 25-byte header, then the terminator.
        assert_eq!(&a[2 + NAME_LEN + 10..2 + NAME_LEN + 13], b"xyz");
        assert_eq!(&a[2 + NAME_LEN + 13..], &[MARKER, 0]);
        assert_eq!(a.len(), 2 + NAME_LEN + 10 + 3 + 2);
    }

    #[test]
    fn rejects_unsupported_encode_method() {
        let mut e = crate::archive::arc::encode::ArcEncoder::new();
        for m in [0x0cu8, 0] {
            assert!(matches!(
                e.add_file_with_method("F", b"", 0, 0, m),
                Err(Error::Unsupported(_))
            ));
        }
    }

    #[test]
    fn rejects_compressed_method() {
        // Methods 12-19 (ARC 6.0/7.0, unpublished) and 40+
        // (reserved) remain out of scope; 20-39 are skipped (see
        // skips_info_control_items).
        for m in [0x0cu8, 0x0d, 19, 40, 0x7e, 0xFF] {
            let mut a = Vec::new();
            a.extend_from_slice(&[MARKER, m]);
            a.extend_from_slice(&[0u8; NAME_LEN + 4]);
            assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
        }
    }

    /// Build an ARC 6.0+ informational/control item (methods
    /// 20-39): same header layout as a regular member; the payload
    /// holds sub-type records and is ignored.
    fn build_info_item(method: u8, name: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&[MARKER, method]);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name);
        a.extend_from_slice(&field);
        a.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        a.extend_from_slice(&[0u8; 10]); // date/time/crc16/orig size
        a.extend_from_slice(payload);
        a
    }

    #[test]
    fn skips_info_control_items() {
        // Informational (20-29) and control (30-39) items around a
        // file member are skipped and never surface as entries. The
        // name field is not a file name and may be non-UTF-8.
        let mut a = Vec::new();
        a.extend_from_slice(&build_info_item(20, b"INFO", b"archive info"));
        a.extend_from_slice(&build_info_item(21, &[0xFF, 0xFE], b"file info"));
        let mid = crate::archive::arc::encode::encode(&[("REAL.TXT", b"data")]).unwrap();
        a.extend_from_slice(&mid[..mid.len() - 2]); // strip terminator
        a.extend_from_slice(&build_info_item(30, b"SUBDIR", b"subdir"));
        a.extend_from_slice(&build_info_item(39, b"CTL", &[0xAA; 7]));
        a.extend_from_slice(&[MARKER, 0]);
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "REAL.TXT");
        assert_eq!(e[0].data, b"data");
    }

    #[test]
    fn rejects_truncated_info_item() {
        // Fixed fields cut short inside the item header.
        let mut a = build_info_item(20, b"INFO", b"payload");
        a.truncate(2 + NAME_LEN + 4); // name + length only
        assert!(matches!(decode(&a), Err(Error::InvalidData(_))));
        // Payload shorter than the declared length.
        let mut a = build_info_item(20, b"INFO", b"payload");
        a.pop();
        assert!(matches!(decode(&a), Err(Error::InvalidData(_))));
    }

    /// Build a method-3 member record from raw packed bytes.
    fn build_method3_member(name: &str, orig_size: u32, crc: u16, packed: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&[MARKER, 3]);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        a.extend_from_slice(&field);
        a.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        a.extend_from_slice(&0x1234u16.to_le_bytes());
        a.extend_from_slice(&0x5678u16.to_le_bytes());
        a.extend_from_slice(&crc.to_le_bytes());
        a.extend_from_slice(&orig_size.to_le_bytes());
        a.extend_from_slice(packed);
        a.extend_from_slice(&[MARKER, 0]);
        a
    }

    #[test]
    fn method3_roundtrip() {
        // Runs, a literal marker byte and plain literals mixed.
        let mut data = Vec::new();
        data.extend_from_slice(b"aaabbbbbbbbbbbbbbbbb");
        data.push(0x90);
        data.extend_from_slice(&[0x00; 300]);
        data.extend_from_slice(b"tail");
        let mut enc = crate::archive::arc::encode::ArcEncoder::new();
        enc.add_file_with_method("RLE.BIN", &data, 0x21, 0x42, 3)
            .unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "RLE.BIN");
        assert_eq!(e[0].method, 3);
        assert_eq!(e[0].date, 0x21);
        assert_eq!(e[0].time, 0x42);
        assert_eq!(e[0].data, data);
        assert!(e[0].crc16.is_some());
    }

    #[test]
    fn method3_member() {
        // Hand-built method-3 (packed) member.
        // original: a a a b 0x90 c c          (7 bytes)
        // packed:   'a' 0x90 03 'b' 0x90 00 'c' 0x90 02
        let orig = [b'a', b'a', b'a', b'b', 0x90, b'c', b'c'];
        let packed = [b'a', 0x90, 0x03, b'b', 0x90, 0x00, b'c', 0x90, 0x02];
        let a = build_method3_member(
            "R3.BIN",
            orig.len() as u32,
            crate::util::crc16::crc16(&orig),
            &packed,
        );
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, "R3.BIN");
        assert_eq!(e[0].method, 3);
        assert_eq!(e[0].data, orig);
        assert_eq!(e[0].date, 0x1234);
        assert_eq!(e[0].crc16, Some(crate::util::crc16::crc16(&orig)));
    }

    #[test]
    fn method3_rejects_bad_crc() {
        // Corrupt the leading literal of the packed stream: it still
        // expands to the right size but fails the CRC-16 check.
        let mut enc = crate::archive::arc::encode::ArcEncoder::new();
        enc.add_file_with_method("F", b"aaaaaaaa", 0, 0, 3).unwrap();
        let mut a = enc.finish();
        // Packed data is 3 bytes ('a' 0x90 0x08); flip the leading
        // literal, which sits 5 bytes before the trailing terminator.
        let n = a.len();
        a[n - 5] = b'b';
        assert!(decode(&a).is_err());
    }

    #[test]
    fn method3_rejects_malformed_rle() {
        // Dangling marker: packed stream ends with a lone 0x90.
        let a = build_method3_member("F", 10, 0, &[b'a', 0x90]);
        assert!(decode(&a).is_err());
        // Run count with no preceding literal byte.
        let a = build_method3_member("F", 5, 0, &[0x90, 0x05]);
        assert!(decode(&a).is_err());
        // Expansion does not match the declared uncompressed size.
        let orig = b"aaaa";
        let a = build_method3_member(
            "F",
            10,
            crate::util::crc16::crc16(orig),
            &[b'a', 0x90, 0x04],
        );
        assert!(decode(&a).is_err());
    }

    #[test]
    fn rejects_bad_crc() {
        let mut a = crate::archive::arc::encode::encode(&[("F", b"xyz")]).unwrap();
        // Corrupt one data byte (last byte before terminator).
        let n = a.len();
        a[n - 3] ^= 0xff;
        assert!(decode(&a).is_err());
    }

    #[test]
    fn rejects_bad_name() {
        // Path separators and non-UTF-8 names are refused.
        for name in [
            &b"../ETC"[..],
            &[b'A', 0x5c, b'B', b'.', b'C'][..],
            &[0xFF, 0xFE][..],
        ] {
            let mut a = Vec::new();
            a.extend_from_slice(&[MARKER, 2]);
            let mut field = [0u8; NAME_LEN];
            field[..name.len()].copy_from_slice(name);
            a.extend_from_slice(&field);
            a.extend_from_slice(&[0u8; 4 + 10]); // size + date/time/crc16/orig
            a.extend_from_slice(&[MARKER, 0]);
            assert!(decode(&a).is_err());
        }
    }

    #[test]
    fn rejects_long_name() {
        let mut e = crate::archive::arc::encode::ArcEncoder::new();
        assert!(e.add_file("1234567890123", b"", 0, 0).is_err());
    }
}
