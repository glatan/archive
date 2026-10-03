//! Encoding support (see crate-level module docs).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

use super::decode::{BASIC_HDR_SIZE, SIG};

/// Flag base on every member header: path separators translated.
const FLAGS_BASE: u8 = 0x10;
/// Member flag: the packed stream is garbled (password XOR).
const FLAG_GARBLED: u8 = 0x01;
/// Member flag: the file's packed stream continues in the next volume.
const FLAG_CONTINUED: u8 = 0x04;
/// Archive terminator size: signature plus a zero u16 header size.
const TERMINATOR: usize = 4;

/// A file or directory member awaiting serialization.
struct PendingEntry {
    name: String,
    /// ARJ compression method byte (0 stored, 1-3 LZH-static,
    /// 4 fastest LZSS).
    method: u8,
    /// ARJ file type: 0 = binary, 3 = directory.
    file_type: u8,
    mtime: u32,
    /// Uncompressed size; kept whole on every fragment header.
    orig: u32,
    /// CRC-32 of the uncompressed data.
    crc: u32,
    /// Packed stream (stored bytes, an st1 block stream, or the
    /// method-4 bit stream), already garbled when `pmod` is set.
    packed: Vec<u8>,
    /// Garble modifier byte written to the header; `Some` marks the
    /// member garbled (flag 0x01). File entries only.
    pmod: Option<u8>,
}

/// Serialize one header block: signature, u16le size, body (fixed
/// fields + NUL name + NUL comment), body CRC-32, and a zero
/// extended-header size.
fn header_block(fixed: &[u8; BASIC_HDR_SIZE], name: &str, comment: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(fixed);
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(comment.as_bytes());
    body.push(0);
    let mut out = Vec::with_capacity(body.len() + 10);
    out.extend_from_slice(&SIG);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&crate::util::crc32::crc32(&body).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // no ext header
    out
}

/// Fixed basic-header fields for one member fragment. Per the
/// multi-volume convention the orig and crc fields always
/// describe the whole file while packed is this fragment's size.
fn member_fixed(e: &PendingEntry, packed: u32, continued: bool) -> [u8; BASIC_HDR_SIZE] {
    let mut fixed = [0u8; BASIC_HDR_SIZE];
    fixed[0] = BASIC_HDR_SIZE as u8;
    fixed[1] = 10; // archiver version (ARJ 2.x)
    fixed[2] = 1; // min version to extract
    fixed[3] = 2; // host OS: unix
    fixed[4] = FLAGS_BASE
        | if continued { FLAG_CONTINUED } else { 0 }
        | if e.pmod.is_some() { FLAG_GARBLED } else { 0 };
    fixed[5] = e.method;
    fixed[6] = e.file_type;
    fixed[7] = e.pmod.unwrap_or(0); // garble modifier
    fixed[8..12].copy_from_slice(&e.mtime.to_le_bytes());
    fixed[12..16].copy_from_slice(&packed.to_le_bytes());
    fixed[16..20].copy_from_slice(&e.orig.to_le_bytes());
    fixed[20..24].copy_from_slice(&e.crc.to_le_bytes());
    fixed
}

/// The archive main header block (file type 2, empty name).
fn main_header() -> Vec<u8> {
    let mut fixed = [0u8; BASIC_HDR_SIZE];
    fixed[0] = BASIC_HDR_SIZE as u8;
    fixed[1] = 10; // archiver version (ARJ 2.x)
    fixed[2] = 1; // min version to extract
    fixed[3] = 2; // host OS: unix
    fixed[4] = FLAGS_BASE;
    fixed[5] = 2; // security version
    fixed[6] = 2; // file type: main header
    header_block(&fixed, "", "")
}

/// Serialized size of one member header block for a given name length.
fn member_header_len(name_len: usize) -> usize {
    2 + 2 + BASIC_HDR_SIZE + name_len + 2 + 4 + 2
}

/// Encoder for ARJ archives: stored (method 0) entries by default,
/// or methods 1-3 (LZH "st1" static Huffman) and method 4
/// ("fastest" LZSS) via ArjEncoder::with_method, optionally garbled
/// (password XOR, flag 0x01) via ArjEncoder::with_password.
pub struct ArjEncoder {
    entries: Vec<PendingEntry>,
    method: u8,
    /// Garbling password; file entries added while set carry flag
    /// 0x01 and have their packed streams XORed with it.
    password: Option<Vec<u8>>,
    /// Garble modifier byte written to garbled member headers.
    pmod: u8,
}

impl ArjEncoder {
    /// New encoder writing stored (method 0) file entries.
    pub fn new() -> Self {
        ArjEncoder {
            entries: Vec::new(),
            method: 0,
            password: None,
            pmod: 0,
        }
    }

    /// New encoder compressing file entries with the given ARJ
    /// method: 0 (stored), 1-3 (LZH "st1" static Huffman over a
    /// 15-bit window — the three methods share one wire format and
    /// differ only in the declared effort level) or 4 ("fastest"
    /// LZSS); other methods are rejected. The matchers are greedy
    /// and non-optimizing; entries whose compressed stream is not
    /// smaller than the input are written stored instead, as real
    /// ARJ does.
    pub fn with_method(method: u8) -> Result<Self, Error> {
        if method > 4 {
            return Err(Error::InvalidData("arj: supported methods are 0 through 4"));
        }
        Ok(ArjEncoder {
            entries: Vec::new(),
            method,
            password: None,
            pmod: 0,
        })
    }

    /// Enable garbled (password) output: subsequently added file
    /// entries carry flag 0x01 and have their packed stream XORed
    /// with `password[i % len] + pmod` (wrapping), readable via
    /// `decode::decode_with_password{,_bytes}` or
    /// `decode::decode_parts_with_password_bytes`. `pmod` is stored
    /// verbatim as the header's garble-modifier byte. Directory
    /// entries are never garbled. Returns `Error::InvalidData` for
    /// an empty password.
    ///
    /// Chains after `new` or `with_method`:
    /// `ArjEncoder::with_method(2)?.with_password(b"pw", 0x5A)?`.
    pub fn with_password(mut self, password: &[u8], pmod: u8) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::InvalidData("arj: empty password"));
        }
        self.password = Some(password.to_vec());
        self.pmod = pmod;
        Ok(self)
    }

    /// Add a file entry. mtime is written verbatim as the
    /// DOS-format timestamp (0 = unset).
    pub fn add_file(&mut self, name: &str, data: &[u8], mtime: u32) -> Result<(), Error> {
        // The u16 header-size field covers the fixed fields plus the
        // NUL-terminated name and comment strings.
        if name.is_empty()
            || name.contains('\0')
            || name.len() > u16::MAX as usize - BASIC_HDR_SIZE - 2
        {
            return Err(Error::InvalidData("arj: bad filename"));
        }
        let (method, mut packed) = match self.method {
            // Methods 1-3 share the st1 wire format (15-bit window,
            // 5-bit offset count); the method byte only records the
            // requested effort level.
            m @ 1..=3 => {
                let compressed = crate::compress::lzh::st1_enc::encode(15, 5, data);
                if compressed.len() < data.len() {
                    (m, compressed)
                } else {
                    (0, data.to_vec())
                }
            }
            4 => {
                let compressed = super::method4::encode(data);
                if compressed.len() < data.len() {
                    (4, compressed)
                } else {
                    (0, data.to_vec())
                }
            }
            _ => (0, data.to_vec()),
        };
        // Garbling XORs the whole packed stream before any
        // multi-volume fragmentation: decode_parts ungarbles the
        // reassembled blob with the index restarting at 0.
        let pmod = if let Some(pw) = &self.password {
            super::decode::ungarble(&mut packed, pw, self.pmod);
            Some(self.pmod)
        } else {
            None
        };
        self.entries.push(PendingEntry {
            name: name.into(),
            method,
            file_type: 0,
            mtime,
            orig: data.len() as u32,
            crc: crate::util::crc32::crc32(data),
            packed,
            pmod,
        });
        Ok(())
    }

    /// Add a directory entry (file type 3, method 0, no payload).
    pub fn add_dir(&mut self, name: &str, mtime: u32) -> Result<(), Error> {
        if name.is_empty()
            || name.contains('\0')
            || name.len() > u16::MAX as usize - BASIC_HDR_SIZE - 2
        {
            return Err(Error::InvalidData("arj: bad filename"));
        }
        self.entries.push(PendingEntry {
            name: name.into(),
            method: 0,
            file_type: 3,
            mtime,
            orig: 0,
            crc: 0,
            packed: Vec::new(),
            pmod: None, // directories are never garbled
        });
        Ok(())
    }

    /// Emit the archive as a single volume.
    pub fn finish(self) -> Vec<u8> {
        let mut out = main_header();
        for e in &self.entries {
            out.extend_from_slice(&header_block(
                &member_fixed(e, e.packed.len() as u32, false),
                &e.name,
                "",
            ));
            out.extend_from_slice(&e.packed);
        }
        out.extend_from_slice(&SIG);
        out.extend_from_slice(&0u16.to_le_bytes()); // end of archive
        out
    }

    /// Emit the archive as ordered volumes of at most
    /// max_part_size bytes each, suitable for
    /// decode::decode_parts.
    ///
    /// Each volume is a self-contained ARJ segment (its own main
    /// header and terminator). A member whose packed stream does not
    /// fit is fragmented: every fragment repeats the member header —
    /// same name and method, whole-file orig/crc, fragment-size
    /// packed — with flag 0x04 set on all but the last fragment,
    /// which is what the decoder concatenates on.
    ///
    /// Returns Error::InvalidData when max_part_size cannot hold
    /// a volume's main header plus a member header and one payload
    /// byte. A single-volume result is a plain archive that also
    /// decodes via decode::decode.
    pub fn finish_parts(self, max_part_size: usize) -> Result<Vec<Vec<u8>>, Error> {
        let main = main_header();
        if max_part_size < main.len() + TERMINATOR {
            return Err(Error::InvalidData("arj: volume size too small"));
        }
        let mut volumes = Vec::new();
        let mut cur = main.clone();
        for e in &self.entries {
            let hdr_len = member_header_len(e.name.len());
            let mut off = 0usize;
            loop {
                let space = max_part_size.saturating_sub(cur.len() + hdr_len + TERMINATOR);
                if cur.len() + hdr_len + TERMINATOR > max_part_size
                    || (off < e.packed.len() && space == 0)
                {
                    // No room here for the member header (or any
                    // payload): close this volume and retry fresh.
                    if cur.len() == main.len() {
                        return Err(Error::InvalidData("arj: volume size too small"));
                    }
                    cur.extend_from_slice(&SIG);
                    cur.extend_from_slice(&0u16.to_le_bytes());
                    volumes.push(core::mem::replace(&mut cur, main.clone()));
                    continue;
                }
                let n = (e.packed.len() - off).min(space);
                let continued = off + n < e.packed.len();
                cur.extend_from_slice(&header_block(
                    &member_fixed(e, n as u32, continued),
                    &e.name,
                    "",
                ));
                cur.extend_from_slice(&e.packed[off..off + n]);
                off += n;
                if continued {
                    // Continued fragments conventionally end a volume.
                    cur.extend_from_slice(&SIG);
                    cur.extend_from_slice(&0u16.to_le_bytes());
                    volumes.push(core::mem::replace(&mut cur, main.clone()));
                } else {
                    break;
                }
            }
        }
        cur.extend_from_slice(&SIG);
        cur.extend_from_slice(&0u16.to_le_bytes());
        volumes.push(cur);
        Ok(volumes)
    }
}

impl Default for ArjEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a method-0 ARJ archive from (name, data) pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    let mut e = ArjEncoder::new();
    for (name, data) in files {
        e.add_file(name, data, 0)?;
    }
    Ok(e.finish())
}
