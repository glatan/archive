//! Encoding support (see crate-level module docs).

use alloc::vec::Vec;

use crate::error::Error;

/// OS id byte written into level-1/2 headers.
const OS_ID: u8 = b'U';
/// Extended header type for the level-2 header CRC-16.
const EXT_HEADER_CRC: u8 = 0x00;
/// Extended header type for the filename (level 1/2).
const EXT_FILENAME: u8 = 0x01;
/// Extended header type for the directory path (level 1/2).
const EXT_DIRNAME: u8 = 0x02;
/// Maximum basename length stored in the level-1 basic name field
/// (255 - `I_LEVEL1_HEADER_SIZE` 27 + 2 in reference LHa).
const LEVEL1_NAME_LIMIT: usize = 230;
/// Level-3 total header size cap, matching the decoder (1 MiB).
const LEVEL3_HEADER_MAX: usize = 1024 * 1024;

/// Wire form of one entry awaiting serialization: method tag,
/// uncompressed size, original-data CRC-16, timestamp, and the
/// packed payload bytes (compressed or stored).
struct Member<'a> {
    method: &'a [u8; 5],
    orig: usize,
    crc: u16,
    packed: &'a [u8],
    mtime: u32,
}

/// Encoder for LHA archives at header level 0, 1, 2, or 3, storing
/// file entries by default or compressing them with the
/// static-Huffman methods `-lh4-` through `-lh7-` (see
/// [LhaEncoder::with_method]).
pub struct LhaEncoder {
    out: Vec<u8>,
    level: u8,
    method: [u8; 5],
}

impl LhaEncoder {
    /// New encoder emitting header level 0 with `-lh0-` (stored)
    /// file entries.
    pub fn new() -> Self {
        LhaEncoder {
            out: Vec::new(),
            level: 0,
            method: *b"-lh0-",
        }
    }

    /// New encoder emitting header level `level` (0, 1, 2, or 3).
    ///
    /// Level 1 keeps the basename in the basic name field when it fits
    /// (at most 230 bytes; longer names move to extended header `0x01`)
    /// and appends a `crc16 + OS id` trailer plus the extended-header
    /// chain (directory components in `0x02`, separated by raw `0xff`).
    /// Its `header size` covers the basic header only and its packed-size
    /// field carries a skip size (packed data + extended-header bytes).
    /// Level 2 uses a `u16` header size covering the whole header
    /// (including the size field itself), no header checksum, a
    /// UNIX-time `mtime`, a `0x00` header-CRC extension block, and
    /// carries the filename only through extended headers.
    /// Level 3 is the 32-bit variant of level 2: it opens with a
    /// `u16` word-size field (always 4), stores a `u32` total header
    /// size at offset 24, and uses `u32` size fields in the
    /// extended-header chain, lifting the level-2 limit of ~64 KiB
    /// per extended header (total header capped at 1 MiB).
    pub fn with_level(level: u8) -> Result<Self, Error> {
        if level > 3 {
            return Err(Error::InvalidData("lha: header level must be 0-3"));
        }
        Ok(LhaEncoder {
            out: Vec::new(),
            level,
            method: *b"-lh0-",
        })
    }

    /// Select the compression method used for `add_file` payloads:
    /// `-lh0-` (stored, the default), the stored-alias tags `-lz4-`
    /// and `-pm0-`, or one of the static-Huffman
    /// "st1" methods `-lh4-`, `-lh5-`, `-lh6-`, `-lh7-` (window sizes
    /// 16/16/64/128 KiB). Other methods are rejected with
    /// [Error::Unsupported]. Entries whose compressed stream is not
    /// smaller than the input are written `-lh0-` instead, as real
    /// LHA does. Directory entries always use `-lhd-`.
    ///
    /// ```
    /// let mut e = archive::archive::lha::encode::LhaEncoder::new()
    ///     .with_method(b"-lh5-")
    ///     .unwrap();
    /// ```
    pub fn with_method(mut self, method: &[u8; 5]) -> Result<Self, Error> {
        match method {
            b"-lh0-" | b"-lz4-" | b"-pm0-" | b"-lh4-" | b"-lh5-" | b"-lh6-" | b"-lh7-" => {
                self.method = *method;
            }
            _ => return Err(Error::Unsupported("lha: unsupported write method")),
        }
        Ok(self)
    }

    /// Add a file entry, stored or compressed with the method chosen
    /// by [LhaEncoder::with_method] (`-lh0-` by default). `name` must
    /// be non-empty UTF-8 and contain no NUL or `'\\'` (path
    /// components are `'/'`-separated; the level-0 wire encoding
    /// stores `'\\'`). `mtime` is written verbatim as the DOS-format
    /// timestamp for levels 0/1, or as UNIX seconds for levels 2/3
    /// (0 is a valid "unset" value).
    pub fn add_file(&mut self, name: &str, data: &[u8], mtime: u32) -> Result<(), Error> {
        let st1_params = match &self.method {
            b"-lh4-" | b"-lh5-" => Some((14, 4)),
            b"-lh6-" => Some((16, 5)),
            b"-lh7-" => Some((17, 5)),
            _ => None,
        };
        // Compress when a st1 method is selected, but keep the stored
        // form when it does not win (real LHA does the same). The
        // stored-alias tags (-lz4-, -pm0-) write the raw payload too.
        let (method, packed): ([u8; 5], Vec<u8>) = match st1_params {
            Some((hist_bits, offset_bits)) => {
                let compressed =
                    crate::compress::lzh::st1_enc::encode(hist_bits, offset_bits, data);
                if compressed.len() < data.len() {
                    (self.method, compressed)
                } else {
                    (*b"-lh0-", data.to_vec())
                }
            }
            None => (self.method, data.to_vec()),
        };
        self.entry(&method, name, Some(data), &packed, mtime)
    }

    /// Add a `-lhd-` directory marker (no payload).
    pub fn add_dir(&mut self, name: &str, mtime: u32) -> Result<(), Error> {
        self.entry(b"-lhd-", name, None, &[], mtime)
    }

    fn entry(
        &mut self,
        method: &[u8; 5],
        name: &str,
        data: Option<&[u8]>,
        packed: &[u8],
        mtime: u32,
    ) -> Result<(), Error> {
        let name = name.trim_end_matches('/');
        if name.is_empty() || name.contains('\0') || name.contains('\\') {
            return Err(Error::InvalidData("lha: bad filename"));
        }
        let is_dir = method == b"-lhd-";
        // Directory entries store the whole path (trailing separator) in
        // the directory part and leave the filename component empty.
        let (dir, base) = if is_dir {
            (name, "")
        } else {
            match name.rsplit_once('/') {
                Some((d, b)) => (d, b),
                None => ("", name),
            }
        };
        if !is_dir && base.is_empty() {
            return Err(Error::InvalidData("lha: bad filename"));
        }
        // `data` carries the uncompressed bytes (original size + CRC);
        // `packed` is the wire payload (compressed or stored).
        let m = Member {
            method,
            orig: data.unwrap_or(&[]).len(),
            crc: crate::util::crc16::crc16(data.unwrap_or(&[])),
            packed,
            mtime,
        };
        match self.level {
            0 => self.emit_level0(&m, name, is_dir),
            1 => self.emit_level1(&m, dir, base),
            2 => self.emit_level2(&m, dir, base),
            _ => self.emit_level3(&m, dir, base),
        }
    }

    fn emit_level0(&mut self, m: &Member<'_>, name: &str, is_dir: bool) -> Result<(), Error> {
        // Basic name fields separate components with a raw 0xff byte;
        // directory entries carry a trailing separator.
        let mut wire_name: Vec<u8> = name
            .bytes()
            .map(|b| if b == b'/' { 0xff } else { b })
            .collect();
        if is_dir {
            wire_name.push(0xff);
        }
        if wire_name.len() > 255 {
            return Err(Error::InvalidData("lha: bad filename"));
        }
        // hdr_size counts method..crc16 inclusive.
        let hsize = 5 + 4 + 4 + 4 + 1 + 1 + 1 + wire_name.len() + 2;
        if hsize > u8::MAX as usize {
            return Err(Error::InvalidData("lha: header too large"));
        }
        let mut hdr = Vec::with_capacity(hsize + 2);
        hdr.push(hsize as u8);
        hdr.push(0); // checksum placeholder
        hdr.extend_from_slice(m.method);
        hdr.extend_from_slice(&(m.packed.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(m.orig as u32).to_le_bytes());
        hdr.extend_from_slice(&m.mtime.to_le_bytes());
        // 0x10 = MS-DOS directory attribute, 0x20 = archive
        hdr.push(if is_dir { 0x10 } else { 0x20 });
        hdr.push(0); // level 0
        hdr.push(wire_name.len() as u8);
        hdr.extend_from_slice(&wire_name);
        hdr.extend_from_slice(&m.crc.to_le_bytes());
        hdr[1] = hdr[2..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(m.packed);
        Ok(())
    }

    fn emit_level1(&mut self, m: &Member<'_>, dir: &str, base: &str) -> Result<(), Error> {
        // The basename goes in the basic name field when it fits;
        // longer names move to an extended `0x01` block instead.
        let base_fits = base.len() <= LEVEL1_NAME_LIMIT;
        let mut exts = Vec::new();
        if !base_fits {
            push_ext(&mut exts, EXT_FILENAME, base.as_bytes())?;
        }
        if !dir.is_empty() {
            push_ext(&mut exts, EXT_DIRNAME, &dir_wire(dir))?;
        }
        // hsize covers the basic header only, ending at the first
        // `u16` extended-header size field (the block contents and
        // terminator follow it). The packed-size field is a skip size:
        // payload + extended-header bytes after the basic header.
        let hsize = 25 + if base_fits { base.len() } else { 0 };
        let skip = m.packed.len() + exts.len();
        let mut hdr = Vec::with_capacity(hsize + exts.len() + 4);
        hdr.push(hsize as u8);
        hdr.push(0); // checksum placeholder
        hdr.extend_from_slice(m.method);
        hdr.extend_from_slice(&(skip as u32).to_le_bytes());
        hdr.extend_from_slice(&(m.orig as u32).to_le_bytes());
        hdr.extend_from_slice(&m.mtime.to_le_bytes());
        hdr.push(0x20); // attribute
        hdr.push(1); // level 1
        hdr.push(if base_fits { base.len() as u8 } else { 0 });
        if base_fits {
            hdr.extend_from_slice(base.as_bytes());
        }
        hdr.extend_from_slice(&m.crc.to_le_bytes());
        hdr.push(OS_ID);
        hdr.extend_from_slice(&exts);
        hdr.extend_from_slice(&0u16.to_le_bytes()); // ext terminator
        hdr[1] = hdr[2..2 + hsize]
            .iter()
            .fold(0u8, |a, &b| a.wrapping_add(b));
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(m.packed);
        Ok(())
    }

    fn emit_level2(&mut self, m: &Member<'_>, dir: &str, base: &str) -> Result<(), Error> {
        // Level-2 extended headers start with a `0x00` header-CRC-16
        // block (patched below), then the filename block (always
        // present), then the directory block when the name has one.
        let mut exts = Vec::new();
        push_ext(&mut exts, EXT_HEADER_CRC, &[0, 0])?;
        push_ext(&mut exts, EXT_FILENAME, base.as_bytes())?;
        if !dir.is_empty() {
            push_ext(&mut exts, EXT_DIRNAME, &dir_wire(dir))?;
        }
        // hsize covers the whole header including the u16 size field
        // and the extended-header terminator. A one-byte padding is
        // appended when the total would end on a zero low byte, which
        // would look like the end-of-archive marker.
        let mut hsize = 2 + 5 + 4 + 4 + 4 + 1 + 1 + 2 + 1 + exts.len() + 2;
        let pad = hsize & 0xff == 0;
        if pad {
            hsize += 1;
        }
        if hsize > u16::MAX as usize {
            return Err(Error::InvalidData("lha: header too large"));
        }
        let mut hdr = Vec::with_capacity(hsize);
        hdr.extend_from_slice(&(hsize as u16).to_le_bytes());
        hdr.extend_from_slice(m.method);
        hdr.extend_from_slice(&(m.packed.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&(m.orig as u32).to_le_bytes());
        hdr.extend_from_slice(&m.mtime.to_le_bytes());
        hdr.push(0x20); // reserved
        hdr.push(2); // level 2
        hdr.extend_from_slice(&m.crc.to_le_bytes());
        hdr.push(OS_ID);
        hdr.extend_from_slice(&exts);
        hdr.extend_from_slice(&0u16.to_le_bytes()); // ext terminator
        if pad {
            hdr.push(0);
        }
        // header CRC-16 covers the whole header with the CRC field
        // zeroed (still the placeholder value here).
        let hcrc = crate::util::crc16::crc16(&hdr);
        hdr[27..29].copy_from_slice(&hcrc.to_le_bytes());
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(m.packed);
        Ok(())
    }

    fn emit_level3(&mut self, m: &Member<'_>, dir: &str, base: &str) -> Result<(), Error> {
        // Level-3 extended headers use u32 size fields; like level 2
        // the chain starts with a `0x00` header-CRC block (patched
        // below), then the filename block (always present, empty for
        // `-lhd-` directory entries), then the directory block when
        // the name has one.
        let mut exts = Vec::new();
        push_ext32(&mut exts, EXT_HEADER_CRC, &[0, 0])?;
        push_ext32(&mut exts, EXT_FILENAME, base.as_bytes())?;
        if !dir.is_empty() {
            push_ext32(&mut exts, EXT_DIRNAME, &dir_wire(dir))?;
        }
        let plen = u32::try_from(m.packed.len())
            .map_err(|_| Error::InvalidData("lha: payload too large"))?;
        let olen =
            u32::try_from(m.orig).map_err(|_| Error::InvalidData("lha: payload too large"))?;
        // hsize counts the whole header from offset 0: the 28 bytes of
        // fixed fields (word size through this u32 size field), the
        // extended-header chain, and its u32 terminator. The decoder
        // caps it at 1 MiB like the reference implementations.
        let hsize = 28 + exts.len() + 4;
        if hsize > LEVEL3_HEADER_MAX {
            return Err(Error::InvalidData("lha: header too large"));
        }
        let mut hdr = Vec::with_capacity(hsize);
        hdr.extend_from_slice(&4u16.to_le_bytes()); // word size
        hdr.extend_from_slice(m.method);
        hdr.extend_from_slice(&plen.to_le_bytes());
        hdr.extend_from_slice(&olen.to_le_bytes());
        hdr.extend_from_slice(&m.mtime.to_le_bytes()); // UNIX time
        hdr.push(0x20); // reserved
        hdr.push(3); // level 3
        hdr.extend_from_slice(&m.crc.to_le_bytes());
        hdr.push(OS_ID);
        hdr.extend_from_slice(&(hsize as u32).to_le_bytes());
        hdr.extend_from_slice(&exts);
        hdr.extend_from_slice(&0u32.to_le_bytes()); // ext terminator
        // header CRC-16 covers the whole header with the CRC field
        // zeroed (still the placeholder value here); it is the payload
        // of the first extended block, at offsets 33..35.
        let hcrc = crate::util::crc16::crc16(&hdr);
        hdr[33..35].copy_from_slice(&hcrc.to_le_bytes());
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(m.packed);
        Ok(())
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.out.push(0); // end-of-archive mark
        self.out
    }
}

/// Wire form of a directory path for extended header `0x02`:
/// components separated by raw `0xff` bytes, with a trailing `0xff`
/// (matching reference LHa, which stores the directory part including
/// its delimiter).
fn dir_wire(dir: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(dir.len() + 1);
    for comp in dir.split('/') {
        v.extend_from_slice(comp.as_bytes());
        v.push(0xff);
    }
    v
}

/// Append one extended header: `u16 size` (including the size field and
/// the type byte) + `u8 type` + payload.
fn push_ext(out: &mut Vec<u8>, ty: u8, payload: &[u8]) -> Result<(), Error> {
    let size = payload.len() + 3;
    if size > u16::MAX as usize {
        return Err(Error::InvalidData("lha: extended header too large"));
    }
    out.extend_from_slice(&(size as u16).to_le_bytes());
    out.push(ty);
    out.extend_from_slice(payload);
    Ok(())
}

/// Level-3 variant of [`push_ext`]: `u32 size` (including the size
/// field and the type byte) + `u8 type` + payload.
fn push_ext32(out: &mut Vec<u8>, ty: u8, payload: &[u8]) -> Result<(), Error> {
    let size = u32::try_from(payload.len() + 5)
        .map_err(|_| Error::InvalidData("lha: extended header too large"))?;
    out.extend_from_slice(&size.to_le_bytes());
    out.push(ty);
    out.extend_from_slice(payload);
    Ok(())
}

impl Default for LhaEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a level-0 `-lh0-` archive from `(name, data)` pairs.
pub fn encode(files: &[(&str, &[u8])]) -> Result<Vec<u8>, Error> {
    encode_level(files, 0)
}

/// Encode a `-lh0-` archive at header `level` (0, 1, 2, or 3) from
/// `(name, data)` pairs. Filenames use DOS mtime 0 (level 0/1) or UNIX
/// mtime 0 (levels 2/3).
pub fn encode_level(files: &[(&str, &[u8])], level: u8) -> Result<Vec<u8>, Error> {
    let mut e = LhaEncoder::with_level(level)?;
    for (name, data) in files {
        e.add_file(name, data, 0)?;
    }
    Ok(e.finish())
}
