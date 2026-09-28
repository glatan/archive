//! MacBinary II container format (MacBinary II Standard Proposal,
//! 24-Jul-1987 revision; Stairways "macbinaryii-standard-info.txt").
//!
//! A file is a 128-byte header (Finder metadata + fork lengths) followed
//! by the data fork and the resource fork, each zero-padded to a multiple
//! of 128 bytes. MacBinary II adds bytes 101 (Finder flags low),
//! 120-121 (secondary header length), 122/123 (version), and 124-125
//! (CRC-16/CCITT over the first 124 bytes).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc16ccitt::crc16_ccitt as header_crc;

const HEADER_LEN: usize = 128;
const MAX_NAME: usize = 63;
const MAX_FORK: u64 = 0x007F_FFFF;
const MB2_VERSION: u8 = 129;

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn pad128(n: usize) -> usize {
    n.div_ceil(128) * 128
}

/// One decoded MacBinary member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacBinaryEntry {
    /// Filename (1-63 bytes when encoded).
    pub name: String,
    /// Finder file type (four-character code).
    pub file_type: [u8; 4],
    /// Finder creator signature.
    pub creator: [u8; 4],
    /// Finder flags: high byte = offset 73, low byte = offset 101 (MB II).
    pub finder_flags: u16,
    /// Protected flag (offset 81, low bit).
    pub protected: bool,
    /// Data fork contents.
    pub data: Vec<u8>,
    /// Resource fork contents.
    pub resource: Vec<u8>,
    /// Creation date (Mac epoch: seconds since 1904-01-01).
    pub creation_date: u32,
    /// Modification date (Mac epoch).
    pub modification_date: u32,
    /// True when the header carried a valid MacBinary II CRC (offset 124);
    /// false when it was accepted under the MacBinary I robustness checks.
    pub macbinary2: bool,
}

/// Encode one file as a MacBinary II document.
///
/// Emits the 128-byte header with `version=min_version=129` and a valid
/// CRC-16, followed by the data and resource forks zero-padded to 128.
///
/// # Panics
///
/// Panics if `name` is empty or longer than 63 bytes, or if a fork exceeds
/// `0x7FFFFF` bytes (the spec's robustness limit).
pub fn encode(entry: &MacBinaryEntry) -> Vec<u8> {
    let name = entry.name.as_bytes();
    assert!(
        !name.is_empty() && name.len() <= MAX_NAME,
        "macbinary: bad name"
    );
    assert!(
        entry.data.len() as u64 <= MAX_FORK && entry.resource.len() as u64 <= MAX_FORK,
        "macbinary: fork too large"
    );

    let mut h = [0u8; HEADER_LEN];
    h[1] = name.len() as u8;
    h[2..2 + name.len()].copy_from_slice(name);
    h[65..69].copy_from_slice(&entry.file_type);
    h[69..73].copy_from_slice(&entry.creator);
    h[73] = (entry.finder_flags >> 8) as u8;
    h[81] = entry.protected as u8;
    h[83..87].copy_from_slice(&(entry.data.len() as u32).to_be_bytes());
    h[87..91].copy_from_slice(&(entry.resource.len() as u32).to_be_bytes());
    h[91..95].copy_from_slice(&entry.creation_date.to_be_bytes());
    h[95..99].copy_from_slice(&entry.modification_date.to_be_bytes());
    h[101] = entry.finder_flags as u8;
    h[122] = MB2_VERSION;
    h[123] = MB2_VERSION;
    let crc = header_crc(&h[..124]);
    h[124..126].copy_from_slice(&crc.to_be_bytes());

    let mut out = Vec::with_capacity(
        pad128(HEADER_LEN) + pad128(entry.data.len()) + pad128(entry.resource.len()),
    );
    out.extend_from_slice(&h);
    out.extend_from_slice(&entry.data);
    out.resize(HEADER_LEN + pad128(entry.data.len()), 0);
    out.extend_from_slice(&entry.resource);
    out.resize(
        out.len() + pad128(entry.resource.len()) - entry.resource.len(),
        0,
    );
    out
}

/// Decode one MacBinary document.
///
/// Header validity follows the spec algorithm: bytes 0 and 74 must be
/// zero; a valid CRC-16 over the first 124 bytes identifies MacBinary II
/// (and `min_version` must be `<= 129`), otherwise the MacBinary I
/// robustness checks apply (byte 82 == 0, offsets 101-125 zero, name
/// length 1-63, fork lengths `<= 0x7FFFFF`). A nonzero secondary-header
/// length field skips that many bytes rounded up to 128 before the data
/// fork. A Get Info comment declared at offset 99 is skipped, not
/// returned.
///
/// This function does not panic on malformed input.
pub fn decode(input: &[u8]) -> Result<MacBinaryEntry, Error> {
    if input.len() < HEADER_LEN {
        return Err(Error::UnexpectedEof);
    }
    let h = &input[..HEADER_LEN];
    if h[0] != 0 || h[74] != 0 {
        return Err(Error::InvalidData("macbinary: bad header"));
    }
    let name_len = h[1] as usize;
    if !(1..=MAX_NAME).contains(&name_len) {
        return Err(Error::InvalidData("macbinary: bad name length"));
    }

    let data_len = be32(&h[83..87]) as u64;
    let rsrc_len = be32(&h[87..91]) as u64;
    if data_len > MAX_FORK || rsrc_len > MAX_FORK {
        return Err(Error::InvalidData("macbinary: fork too large"));
    }

    // MacBinary II identification: CRC over the first 124 bytes matches.
    let crc_ok = be16(&h[124..126]) == header_crc(&h[..124]);
    let macbinary2 = if crc_ok {
        let min_version = h[123];
        if min_version > MB2_VERSION {
            return Err(Error::Unsupported("macbinary: version too new"));
        }
        true
    } else {
        // MacBinary I robustness checks.
        if h[82] != 0 || h[101..126].iter().any(|&b| b != 0) {
            return Err(Error::InvalidData("macbinary: not a macbinary file"));
        }
        false
    };

    // Secondary header (skipped, rounded up to 128) then the forks.
    let sec_len = pad128(be16(&h[120..122]) as usize);
    let pos = HEADER_LEN
        .checked_add(sec_len)
        .ok_or(Error::InvalidData("macbinary: size overflow"))?;
    let dlen = data_len as usize;
    let rlen = rsrc_len as usize;
    let data_end = pos
        .checked_add(dlen)
        .ok_or(Error::InvalidData("macbinary: size overflow"))?;
    let data_pad_end = pos
        .checked_add(pad128(dlen))
        .ok_or(Error::InvalidData("macbinary: size overflow"))?;
    let rsrc_end = data_pad_end
        .checked_add(rlen)
        .ok_or(Error::InvalidData("macbinary: size overflow"))?;
    let rsrc_pad_end = data_pad_end
        .checked_add(pad128(rlen))
        .ok_or(Error::InvalidData("macbinary: size overflow"))?;
    // The file itself is the forks padded to 128; missing trailing
    // padding bytes are still a truncated document.
    if rsrc_pad_end > input.len() {
        return Err(Error::UnexpectedEof);
    }
    let data = input[pos..data_end].to_vec();
    let resource = input[data_pad_end..rsrc_end].to_vec();

    // Trailing bytes: only a declared Get Info comment may follow.
    let comment_len = be16(&h[99..101]) as usize;
    let trailing = input.len() - rsrc_pad_end;
    if trailing != 0
        && !(comment_len > 0 && (trailing == comment_len || trailing == pad128(comment_len)))
    {
        return Err(Error::InvalidData("macbinary: trailing garbage"));
    }

    let name = String::from_utf8_lossy(&h[2..2 + name_len]).into_owned();
    Ok(MacBinaryEntry {
        name,
        file_type: [h[65], h[66], h[67], h[68]],
        creator: [h[69], h[70], h[71], h[72]],
        finder_flags: ((h[73] as u16) << 8) | if macbinary2 { h[101] as u16 } else { 0 },
        protected: h[81] & 1 != 0,
        data,
        resource,
        creation_date: be32(&h[91..95]),
        modification_date: be32(&h[95..99]),
        macbinary2,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> MacBinaryEntry {
        MacBinaryEntry {
            name: "sample.bin".into(),
            file_type: *b"BINA",
            creator: *b"R*ch",
            finder_flags: 0x80_01,
            protected: true,
            data: b"data fork payload".to_vec(),
            resource: b"rsrc".to_vec(),
            creation_date: 0x0123_4567,
            modification_date: 0x89ab_cdef,
            macbinary2: true,
        }
    }

    #[test]
    fn roundtrip() {
        let e = entry();
        let doc = encode(&e);
        assert_eq!(doc.len() % 128, 0);
        let d = decode(&doc).unwrap();
        assert_eq!(d, e);
    }

    #[test]
    fn empty_forks() {
        let mut e = entry();
        e.data = Vec::new();
        e.resource = Vec::new();
        assert_eq!(decode(&encode(&e)).unwrap(), e);
    }

    #[test]
    fn name_length_boundary() {
        for n in [1usize, 63] {
            let mut e = entry();
            e.name = "x".repeat(n);
            assert_eq!(decode(&encode(&e)).unwrap().name, e.name);
        }
    }

    #[test]
    fn header_crc_verified() {
        let e = entry();
        let mut doc = encode(&e);
        // Corrupt the type code -> CRC mismatch -> falls back to MB I
        // checks, which fail because MB II region (101-125) is non-zero.
        doc[65] ^= 1;
        assert!(decode(&doc).is_err());
    }

    #[test]
    fn macbinary1_accepted() {
        // Build a MB I header: no CRC, bytes 101-125 all zero.
        let mut e = entry();
        e.finder_flags = 0x80_00; // low byte lives at 101 in MB II only
        let mut doc = encode(&e);
        doc[101..128].fill(0); // clears low flags, versions, CRC
        let d = decode(&doc).unwrap();
        assert!(!d.macbinary2);
        assert_eq!(d.data, e.data);
        assert_eq!(d.finder_flags, 0x8000);
    }

    #[test]
    fn rejects_bad_header() {
        let e = entry();
        for (off, val) in [(0usize, 1u8), (74, 1), (82, 9)] {
            let mut doc = encode(&e);
            doc[off] = val;
            // Byte 82 change also breaks CRC -> MB I path rejects != 0.
            assert!(decode(&doc).is_err(), "off={off}");
        }
        // name len 0 / 64
        for v in [0u8, 64] {
            let mut doc = encode(&e);
            doc[1] = v;
            assert!(decode(&doc).is_err());
        }
    }

    #[test]
    fn rejects_trailing_garbage() {
        let e = entry();
        let mut doc = encode(&e);
        doc.push(0xAA);
        assert!(decode(&doc).is_err());
    }

    #[test]
    fn rejects_truncated() {
        let e = entry();
        let doc = encode(&e);
        assert!(decode(&doc[..127]).is_err());
        assert!(decode(&doc[..doc.len() - 4]).is_err());
    }

    #[test]
    fn rejects_high_min_version() {
        let e = entry();
        let mut doc = encode(&e);
        doc[123] = 200; // min version too new
        // Fix the CRC so the MB II path is taken.
        let crc = header_crc(&doc[..124]);
        doc[124..126].copy_from_slice(&crc.to_be_bytes());
        assert!(matches!(decode(&doc), Err(Error::Unsupported(_))));
    }

    #[test]
    fn secondary_header_skipped() {
        let e = entry();
        let doc = encode(&e);
        // Insert a 130-byte "secondary header" (len 130 -> pad 256) that
        // claims 130 in the field.
        let mut h = doc[..128].to_vec();
        h[120..122].copy_from_slice(&130u16.to_be_bytes());
        let crc = header_crc(&h[..124]);
        h[124..126].copy_from_slice(&crc.to_be_bytes());
        let mut doc2 = h;
        doc2.extend_from_slice(&[0xEE; 256]);
        doc2.extend_from_slice(&doc[128..]);
        let d = decode(&doc2).unwrap();
        assert_eq!(d.data, e.data);
        assert_eq!(d.resource, e.resource);
    }
}
