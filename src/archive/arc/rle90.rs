//! RLE90 — the 0x90 (DLE) run-length packing used by ARC method 3
//! ("packed").
//!
//! Wire format: 0x90 is a run marker. A literal byte b followed by
//! [0x90 n] (n != 0) expands to n copies of b in total — the literal
//! already on the wire counts as the first copy, so n - 1 further
//! copies are emitted ([0x90 0x01] is a degenerate no-op).
//! [0x90 0x00] encodes a literal 0x90 byte. Any byte other than 0x90
//! passes through unchanged.
//!
//! This is the de-facto layout agreed upon by multiple independent
//! implementations (The Unarchiver XADMaster Rle90,
//! compcol::rle90; cf. virtualdub.org/blog2 entry_345). nomarch
//! agrees and is used only as a test-time oracle.

use alloc::vec::Vec;

use crate::error::Error;

/// RLE90 run marker byte (DLE).
const FLAG: u8 = 0x90;

/// Decode an RLE90 stream that must expand to exactly
/// original_size bytes.
pub(crate) fn decode(input: &[u8], original_size: usize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    // A corrupt header can declare a multi-gigabyte size. `with_capacity`
    // aborts when the address space refuses that reservation.
    out.try_reserve_exact(original_size)
        .map_err(|_| Error::InvalidData("arc: uncompressed size too large"))?;
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        i += 1;
        if b != FLAG {
            out.push(b);
        } else {
            if i >= input.len() {
                // Dangling marker: the count byte never arrived.
                return Err(Error::InvalidData("arc: truncated rle90 run"));
            }
            let n = input[i];
            i += 1;
            if n == 0 {
                // Escaped literal marker byte.
                out.push(FLAG);
            } else {
                // Repeat the last emitted byte to n total copies.
                let &last = out
                    .last()
                    .ok_or(Error::InvalidData("arc: rle90 run without literal"))?;
                out.resize(out.len() + (n as usize - 1), last);
            }
        }
        if out.len() > original_size {
            return Err(Error::InvalidData("arc: rle90 expansion exceeds size"));
        }
    }
    if out.len() != original_size {
        return Err(Error::InvalidData("arc: size mismatch"));
    }
    Ok(out)
}

/// Encode input as RLE90. Runs of two or more identical bytes are
/// emitted as [b 0x90 n] chunks where n is the total copy count of
/// the chunk (at most 255 each). A run of marker bytes can never lead
/// a coded run, so each literal 0x90 is escaped as [0x90 0x00].
pub(crate) fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        let mut end = i + 1;
        while end < input.len() && input[end] == b {
            end += 1;
        }
        let count = end - i;
        i = end;
        if b == FLAG {
            for _ in 0..count {
                out.push(FLAG);
                out.push(0);
            }
        } else if count == 1 {
            out.push(b);
        } else {
            // The leading literal b is the first copy; each [0x90 n]
            // tops the run up to n total copies for that chunk.
            out.push(b);
            let mut emitted = 1usize;
            while emitted < count {
                let n = (count - emitted + 1).min(255);
                out.push(FLAG);
                out.push(n as u8);
                emitted += n - 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn roundtrip(data: &[u8]) {
        let packed = encode(data);
        let out = decode(&packed, data.len()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn rle90_roundtrip() {
        roundtrip(&[]);
        roundtrip(b"hello, world!");
        roundtrip(b"aa");
        roundtrip(b"aaaaaaaaaaaaaaaaaaaa");
        // Literal marker bytes.
        roundtrip(&[FLAG]);
        roundtrip(&[FLAG, FLAG, FLAG]);
        roundtrip(&[1, FLAG, 2, FLAG, FLAG, 3]);
        // Runs longer than one 255-count chunk.
        roundtrip(&[0x5A; 255]);
        roundtrip(&[0x5A; 256]);
        roundtrip(&[0x5A; 1000]);
        roundtrip(&[FLAG; 600]);
        // Mixed literals, runs and escapes.
        let mut data = Vec::new();
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&[0xFF; 50]);
        data.extend_from_slice(b"def");
        data.extend_from_slice(&[FLAG; 7]);
        data.extend_from_slice(&[0x00; 300]);
        data.push(FLAG);
        roundtrip(&data);
        // All byte values.
        roundtrip(&(0u8..=255).collect::<Vec<u8>>());
    }

    #[test]
    fn rle90_rejects_unreservable_size() {
        assert!(decode(b"", isize::MAX as usize).is_err());
    }

    #[test]
    fn rle90_known_sequences() {
        // 'a' 0x90 0x04 -> "aaaa"
        assert_eq!(decode(&[b'a', FLAG, 0x04], 4).unwrap(), b"aaaa");
        // 0x90 0x00 -> literal marker
        assert_eq!(decode(&[FLAG, 0x00], 1).unwrap(), vec![FLAG]);
        // 'a' 0x90 0x01 -> degenerate, just "a"
        assert_eq!(decode(&[b'a', FLAG, 0x01], 1).unwrap(), b"a");
        // Consecutive run chunks reuse the last emitted byte:
        // 'a' 0x90 255 tops the first chunk at 255 copies, then
        // 0x90 46 adds 45 more (46 total incl. the remembered byte).
        assert_eq!(
            decode(&[b'a', FLAG, 0xFF, FLAG, 46], 300).unwrap(),
            vec![b'a'; 300]
        );
        assert_eq!(encode(b"aaaa"), vec![b'a', FLAG, 0x04]);
        assert_eq!(encode(&[FLAG]), vec![FLAG, 0x00]);
        assert_eq!(encode(&[FLAG, FLAG]), vec![FLAG, 0x00, FLAG, 0x00]);
        assert_eq!(encode(b"ab"), b"ab");
        assert_eq!(encode(b"aab"), vec![b'a', FLAG, 0x02, b'b']);
        // 300 copies split as 'a' 0x90 255 0x90 46.
        assert_eq!(encode(&[b'a'; 300]), vec![b'a', FLAG, 255, FLAG, 46]);
    }

    #[test]
    fn rle90_rejects_malformed() {
        // Dangling marker at end of stream.
        assert!(decode(&[b'a', FLAG], 10).is_err());
        // Run count with no preceding literal byte.
        assert!(decode(&[FLAG, 0x05], 5).is_err());
        // Expansion shorter / longer than the declared size.
        assert!(decode(b"a", 2).is_err());
        assert!(decode(&[b'a', FLAG, 0x04], 3).is_err());
    }
}
