//! SEA ARC (`.arc`) archive read and store-method write support.
//!
//! Reference: the ARC file format description published by System
//! Enhancement Associates (arc specification / wotsit "arc" entry).
//! Supported scope:
//!
//! - reading: method 1 (obsolete unpacked, no CRC) and method 2
//!   (stored). Methods 3 (packed/RLE), 4 (squeezed), 5-8 (crunched /
//!   non-ASCII crunched / crushed / distilled) and any higher method
//!   are rejected with [`Error::Unsupported`];
//! - writing: method 2 (stored) entries only.
//!
//! Layout: each member starts with `0x1A` and a method byte; method 0
//! marks end of archive. Method-1 records are
//! `[name 13B][size u32le][data]`; methods >= 2 use
//! `[name 13B][size u32le][date u16le][time u16le][crc16 u16le]
//! [length u32le][data]` where `size` is the uncompressed size and
//! `length` is the stored data size (equal for method 2). ARC has no
//! directory entries and names are flat, NUL-padded, at most 12
//! characters plus a terminator byte.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

pub(crate) const MARKER: u8 = 0x1A;
pub(crate) const NAME_LEN: usize = 13;

/// One decoded ARC member.
#[derive(Debug, Clone)]
pub struct ArcEntry {
    /// File name (no directory component; ARC is flat).
    pub name: String,
    /// Member method byte as read (1 or 2).
    pub method: u8,
    /// DOS date field (0 when absent/unset).
    pub date: u16,
    /// DOS time field (0 when absent/unset).
    pub time: u16,
    /// Data CRC-16, `None` for method-1 members which carry no CRC.
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
        if method > 2 {
            return Err(Error::Unsupported("arc: unsupported method"));
        }
        if pos + NAME_LEN + 4 > input.len() {
            return Err(Error::InvalidData("arc: truncated header"));
        }
        let name = parse_name(&input[pos..pos + NAME_LEN])?;
        pos += NAME_LEN;
        let size = u32le(&input[pos..]) as usize;
        pos += 4;
        let (date, time, crc16, length) = if method == 1 {
            // Obsolete unpacked member: no date/time/CRC/length fields.
            (0, 0, None, size)
        } else {
            if pos + 10 > input.len() {
                return Err(Error::InvalidData("arc: truncated header"));
            }
            let date = u16le(&input[pos..]);
            let time = u16le(&input[pos + 2..]);
            let crc = u16le(&input[pos + 4..]);
            let length = u32le(&input[pos + 6..]) as usize;
            pos += 10;
            (date, time, Some(crc), length)
        };
        if pos + length > input.len() {
            return Err(Error::InvalidData("arc: truncated member data"));
        }
        let data = input[pos..pos + length].to_vec();
        pos += length;
        if data.len() != size {
            // For stored members length must equal uncompressed size.
            return Err(Error::InvalidData("arc: size mismatch"));
        }
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

    #[test]
    fn method1_member() {
        // Hand-built method-1 (obsolete unpacked) record.
        let mut a = Vec::new();
        a.push(MARKER);
        a.push(1);
        let mut field = [0u8; NAME_LEN];
        field[..3].copy_from_slice(b"F.B");
        a.extend_from_slice(&field);
        a.extend_from_slice(&3u32.to_le_bytes());
        a.extend_from_slice(b"xyz");
        a.extend_from_slice(&[MARKER, 0]);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].name, "F.B");
        assert_eq!(e[0].data, b"xyz");
        assert_eq!(e[0].crc16, None);
    }

    #[test]
    fn rejects_compressed_method() {
        let mut a = Vec::new();
        a.extend_from_slice(&[MARKER, 3]);
        a.extend_from_slice(&[0u8; NAME_LEN + 4]);
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
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
    fn rejects_long_name() {
        let mut e = crate::archive::arc::encode::ArcEncoder::new();
        assert!(e.add_file("1234567890123", b"", 0, 0).is_err());
    }
}
