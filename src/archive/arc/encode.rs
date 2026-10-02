//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{MARKER, NAME_LEN};

/// Encoder for ARC archives supporting methods 1 (obsolete unpacked),
/// 2 (stored), 3 (packed/RLE90), 4 (squeezed), 5/6/7 (crunched
/// hash-LZW), 8 (crunched), 9 (squashed), 0x0a (crushed) and
/// 0x0b (distilled).
pub struct ArcEncoder {
    out: Vec<u8>,
}

impl ArcEncoder {
    pub fn new() -> Self {
        ArcEncoder { out: Vec::new() }
    }

    /// Add a stored (method-2) file entry. `name` must be a flat file
    /// name (no path separators, no NUL) of at most 12 bytes.
    /// `date`/`time` are DOS-format fields written verbatim (0 =
    /// unset).
    pub fn add_file(&mut self, name: &str, data: &[u8], date: u16, time: u16) -> Result<(), Error> {
        self.add_file_with_method(name, data, date, time, 2)
    }

    /// Add a file entry with an explicit method byte. Supported
    /// methods: `1` (obsolete unpacked — the regular member
    /// header minus the original-length field), `2` (stored), `3`
    /// (packed/RLE90), `4` (squeezed), `5`/`6`/`7` (crunched hash-LZW;
    /// 6 and 7 add an RLE90 stage), `8` (crunched), `9` (squashed) and
    /// `0x0a` (crushed = adaptive LZW over an RLE90 stream) and
    /// `0x0b` (distilled = LZSS + header Huffman). Any other
    /// method is rejected with [`Error::Unsupported`].
    pub fn add_file_with_method(
        &mut self,
        name: &str,
        data: &[u8],
        date: u16,
        time: u16,
        method: u8,
    ) -> Result<(), Error> {
        if name.is_empty()
            || name.len() > NAME_LEN - 1
            || name.contains('\0')
            || name.contains('/')
            || name.contains('\\')
        {
            return Err(Error::InvalidData("arc: bad filename"));
        }
        if !matches!(method, 1..=0x0b) {
            return Err(Error::Unsupported("arc: unsupported method"));
        }
        let body = match method {
            1 | 2 => data.to_vec(),
            3 => super::rle90::encode(data),
            4 => super::squeeze::encode(data),
            5 => super::crunch::encode(data, super::crunch::CrunchHash::Quadratic),
            6 => super::crunch::encode(
                &super::rle90::encode(data),
                super::crunch::CrunchHash::Quadratic,
            ),
            7 => super::crunch::encode(
                &super::rle90::encode(data),
                super::crunch::CrunchHash::Multiplicative,
            ),
            8 => {
                // Crunched: maxbits byte (12) then a dynamic-LZW stream
                // over the RLE90-packed data.
                let rle = super::rle90::encode(data);
                let mut b = Vec::with_capacity(rle.len() + 1);
                b.push(12u8);
                b.extend_from_slice(&crate::compress::lzw::encode::encode_body(&rle, 12, true));
                b
            }
            9 => crate::compress::lzw::encode::encode_body(data, 13, true),
            0x0a => {
                // Crushed member: adaptive LZW over the RLE90-packed
                // data.
                super::crush::encode(&super::rle90::encode(data))?
            }
            0x0b => {
                // Distilled member: LZSS + header-serialised Huffman,
                // no RLE stage.
                super::distill::encode(data)?
            }
            _ => unreachable!(),
        };
        self.out.push(MARKER);
        self.out.push(method);
        let mut field = [0u8; NAME_LEN];
        field[..name.len()].copy_from_slice(name.as_bytes());
        self.out.extend_from_slice(&field);
        // The header carries the stored (compressed) size first.
        self.out
            .extend_from_slice(&(body.len() as u32).to_le_bytes());
        self.out.extend_from_slice(&date.to_le_bytes());
        self.out.extend_from_slice(&time.to_le_bytes());
        // The CRC-16 covers the uncompressed data.
        self.out
            .extend_from_slice(&crate::util::crc16::crc16(data).to_le_bytes());
        if method != 1 {
            // Original (uncompressed) file length closes the header;
            // method-1 headers omit this field.
            self.out
                .extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
        self.out.extend_from_slice(&body);
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out.extend_from_slice(&[MARKER, 0]);
        self.out
    }
}

impl Default for ArcEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a method-2 ARC archive from `(name, data)` pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut e = ArcEncoder::new();
    for (name, data) in files {
        e.add_file(name, data, 0, 0)?;
    }
    Ok(e.finish())
}
