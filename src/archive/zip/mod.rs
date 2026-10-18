//! ZIP archive support.
//!
//! Current scope covers baseline read/write support for:
//! - End of Central Directory lookup and emission
//! - ZIP64 EOCD / locator parsing and emission
//! - Central Directory traversal and writing
//! - Local File Header validation and writing
//! - Store/Deflate extraction/encoding, legacy methods (Shrunk, Reduced
//!   factors 1-4, Imploded) and Deflate64 decode and encode
//! - PKWARE DCL Implode (method 10) decode; literal-only encode
//! - Traditional PKZIP and WinZip AES-128/192/256 encrypted entry read/write
//! - Strong Encryption (APPNOTE §7) and Central Directory Encryption
//!   (§4.3.10/§7.5) are detected and rejected as Unsupported: the APPNOTE
//!   states that implementing them requires a separate PKWARE license
//!   agreement (§10.1, see THIRD_PARTY_NOTICES)
//! - Bit 13 Central Directory field masking (APPNOTE §4.4.4)
//! - Data Descriptor validation on the read path
//! - Data Descriptor emission on the write path, including encrypted entries
//! - Unknown-size streaming entry write via `encode::ZipStreamWriter`
//! - Split/spanned (multi-disk) archive read via `decode_parts` and write
//!   via `ZipEncoder::finish_parts`

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

const CP437_HIGH_BYTES: [char; 128] = [
    '\u{00C7}', '\u{00FC}', '\u{00E9}', '\u{00E2}', '\u{00E4}', '\u{00E0}', '\u{00E5}', '\u{00E7}',
    '\u{00EA}', '\u{00EB}', '\u{00E8}', '\u{00EF}', '\u{00EE}', '\u{00EC}', '\u{00C4}', '\u{00C5}',
    '\u{00C9}', '\u{00E6}', '\u{00C6}', '\u{00F4}', '\u{00F6}', '\u{00F2}', '\u{00FB}', '\u{00F9}',
    '\u{00FF}', '\u{00D6}', '\u{00DC}', '\u{00A2}', '\u{00A3}', '\u{00A5}', '\u{20A7}', '\u{0192}',
    '\u{00E1}', '\u{00ED}', '\u{00F3}', '\u{00FA}', '\u{00F1}', '\u{00D1}', '\u{00AA}', '\u{00BA}',
    '\u{00BF}', '\u{2310}', '\u{00AC}', '\u{00BD}', '\u{00BC}', '\u{00A1}', '\u{00AB}', '\u{00BB}',
    '\u{2591}', '\u{2592}', '\u{2593}', '\u{2502}', '\u{2524}', '\u{2561}', '\u{2562}', '\u{2556}',
    '\u{2555}', '\u{2563}', '\u{2551}', '\u{2557}', '\u{255D}', '\u{255C}', '\u{255B}', '\u{2510}',
    '\u{2514}', '\u{2534}', '\u{252C}', '\u{251C}', '\u{2500}', '\u{253C}', '\u{255E}', '\u{255F}',
    '\u{255A}', '\u{2554}', '\u{2569}', '\u{2566}', '\u{2560}', '\u{2550}', '\u{256C}', '\u{2567}',
    '\u{2568}', '\u{2564}', '\u{2565}', '\u{2559}', '\u{2558}', '\u{2552}', '\u{2553}', '\u{256B}',
    '\u{256A}', '\u{2518}', '\u{250C}', '\u{2588}', '\u{2584}', '\u{258C}', '\u{2590}', '\u{2580}',
    '\u{03B1}', '\u{00DF}', '\u{0393}', '\u{03C0}', '\u{03A3}', '\u{03C3}', '\u{00B5}', '\u{03C4}',
    '\u{03A6}', '\u{0398}', '\u{03A9}', '\u{03B4}', '\u{221E}', '\u{03C6}', '\u{03B5}', '\u{2229}',
    '\u{2261}', '\u{00B1}', '\u{2265}', '\u{2264}', '\u{2320}', '\u{2321}', '\u{00F7}', '\u{2248}',
    '\u{00B0}', '\u{2219}', '\u{00B7}', '\u{221A}', '\u{207F}', '\u{00B2}', '\u{25A0}', '\u{00A0}',
];

pub(crate) fn decode_metadata(bytes: &[u8], utf8: bool) -> Result<String, Error> {
    if utf8 {
        return String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::InvalidData("zip: invalid UTF-8 metadata"));
    }

    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte < 0x80 {
            out.push(byte as char);
        } else {
            out.push(CP437_HIGH_BYTES[(byte - 0x80) as usize]);
        }
    }
    Ok(out)
}

pub(crate) fn encode_metadata(text: &str, utf8: bool) -> Result<Vec<u8>, Error> {
    if utf8 {
        return Ok(text.as_bytes().to_vec());
    }

    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii() {
            out.push(ch as u8);
            continue;
        }
        let Some(index) = CP437_HIGH_BYTES
            .iter()
            .position(|&candidate| candidate == ch)
        else {
            return Err(Error::InvalidData(
                "zip: metadata not representable in CP437 without UTF-8 flag",
            ));
        };
        out.push(index as u8 + 0x80);
    }
    Ok(out)
}

/// ZIP archive decoding.
pub mod decode;
/// ZIP archive encoding.
pub mod encode;

mod crypto;
mod dcl_implode;
mod expand;
mod implode;
mod lzmatch;
mod unshrink;

/// Codec struct for trait-based ZIP decode operations.
pub struct ZipCodec;

impl crate::traits::ArchiveDecode for ZipCodec {
    type Entry = decode::ZipEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, Error> {
        decode::decode(input)
    }

    fn for_each_entry<F>(&self, input: &[u8], visit: F) -> Result<(), Error>
    where
        F: FnMut(Self::Entry) -> Result<(), Error>,
    {
        decode::for_each_entry(input, visit)
    }
}

/// Encoder struct for trait-based ZIP encode operations.
pub struct ZipArchiveEncoder {
    inner: encode::ZipEncoder,
}

impl ZipArchiveEncoder {
    /// Create a new trait-based ZIP encoder.
    pub const fn new() -> Self {
        Self {
            inner: encode::ZipEncoder::new(),
        }
    }
}

impl Default for ZipArchiveEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for ZipArchiveEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.inner.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.inner.finish()
    }
}
