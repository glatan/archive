//! ARJ archive reading: stored, LZH-static (methods 1-3), and
//! "fastest" (method 4) members, ARJ32 no-data pseudo-methods
//! 8/9, chapter labels (file type 5), garbled (password)
//! entries, and multi-volume archives via [`decode_parts`](crate::archive::arj::decode::decode_parts)
//! (with `std`, `volume_paths` discovers the `.arj`/`.aNN`
//! sibling volumes).
//!
//! Reference: ARJ technical note (ARJ 2.x file format description).
//!
//! Layout: each header starts with the two-byte signature `0x60 0xEA`
//! followed by a `u16le` header size (0 = end of archive). The basic
//! header is a 28-30 byte fixed block, then a NUL-terminated
//! filename, a NUL-terminated comment, and a `u32le` CRC-32 of the
//! header bytes starting at `first_hdr_size`. File data follows the
//! header CRC (and any extended header block, which is skipped). The
//! main (first) header describes the archive itself and carries no
//! data.
//!
//! Fixed-field order inside the basic header (all little-endian):
//! first_hdr_size(1), version(1), min_version(1), host_os(1),
//! arj_flags(1), method(1), file_type(1), reserved/garble-modifier
//! (1), dos_time(4), packed_size(4), original_size(4), crc32(4),
//! filespec_pos(2), access_mode(2), host_data(2).
//!
//! Flag bits: 0x01 garbled (password XOR on the packed stream),
//! 0x04 continued into the next volume (split file), 0x08 extended
//! file-start-position field present inside `first_hdr_size`,
//! 0x40 secured (ARJ security envelope — rejected as Unsupported).

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

pub(crate) const SIG: [u8; 2] = [0x60, 0xEA];
/// Minimum basic-header size (old ARJ writers stop at byte 27).
pub(crate) const BASIC_HDR_SIZE: usize = 30;

/// One decoded ARJ entry. The archive-level main header is not
/// returned as an entry.
#[derive(Debug, Clone)]
pub struct ArjEntry {
    /// File or directory name.
    pub name: String,
    /// Compression method byte (0 stored, 1-3 LZH-static, 4 fastest,
    /// 8-9 ARJ32 no-data pseudo-methods).
    pub method: u8,
    /// ARJ file type: 0 = binary, 1 = text, 3 = directory,
    /// 4 = volume label, 5 = chapter label.
    pub file_type: u8,
    /// `true` for directory entries (file type 3).
    pub is_dir: bool,
    /// DOS-format timestamp as stored in the header.
    pub mtime: u32,
    /// CRC-32 of the uncompressed file data.
    pub crc32: u32,
    /// Entry payload (empty for directories, labels, and
    /// no-data members).
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for ArjEntry {
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

fn read_cstr(b: &[u8]) -> Result<(&str, usize), Error> {
    match b.iter().position(|&c| c == 0) {
        Some(end) => Ok((
            core::str::from_utf8(&b[..end])
                .map_err(|_| Error::InvalidData("arj: name is not UTF-8"))?,
            end + 1,
        )),
        None => Err(Error::InvalidData("arj: unterminated string")),
    }
}

/// One parsed member header plus the extent of its packed data
/// within the volume.
struct Frag {
    name: String,
    flags: u8,
    method: u8,
    file_type: u8,
    /// Garble password modifier byte.
    pmod: u8,
    mtime: u32,
    crc: u32,
    orig: usize,
    /// Packed-data extent inside the volume buffer.
    data_off: usize,
    data_len: usize,
}

/// Parse one ARJ header block starting at . Returns
///  where  is the offset just
/// past the header CRC and the (possibly empty) extended header.
fn parse_header(input: &[u8], pos: usize) -> Result<(usize, [u8; BASIC_HDR_SIZE], String), Error> {
    if pos + 4 > input.len() || input[pos..pos + 2] != SIG {
        return Err(Error::InvalidData("arj: bad signature"));
    }
    let hsize = u16le(&input[pos + 2..]) as usize;
    if hsize == 0 {
        return Err(Error::InvalidData("arj: empty header"));
    }
    // hsize counts bytes from first_hdr_size through the comment NUL.
    if pos + 4 + hsize > input.len() || hsize < 28 {
        return Err(Error::InvalidData("arj: truncated header"));
    }
    let body = &input[pos + 4..pos + 4 + hsize];
    let first = body[0] as usize;
    // The fixed block is  bytes (28 minimum; 30 with host
    // data; 34+ with the extended file-position field).
    if first > hsize || first < 28 {
        return Err(Error::InvalidData("arj: bad first header size"));
    }
    let mut fixed = [0u8; BASIC_HDR_SIZE];
    fixed[..first.min(BASIC_HDR_SIZE)].copy_from_slice(&body[..first.min(BASIC_HDR_SIZE)]);
    let (name, nlen) = read_cstr(&body[first..])?;
    let (_comment, clen) = read_cstr(&body[first + nlen..])?;
    if first + nlen + clen > hsize {
        return Err(Error::InvalidData("arj: strings exceed header"));
    }
    let crc_off = pos + 4 + hsize;
    if crc_off + 4 > input.len() {
        return Err(Error::InvalidData("arj: truncated header crc"));
    }
    let stored_crc = u32le(&input[crc_off..]);
    let actual = crate::util::crc32::crc32(&input[pos + 4..pos + 4 + hsize]);
    if stored_crc != actual {
        return Err(Error::InvalidData("arj: header CRC-32 mismatch"));
    }
    // The u16 extended-header size always follows the header CRC;
    // 0 means none, otherwise that many bytes plus a u32 CRC.
    let mut end = crc_off + 4;
    if end + 2 > input.len() {
        return Err(Error::InvalidData("arj: truncated ext size"));
    }
    let ext = u16le(&input[end..]) as usize;
    if ext > 0 {
        if end + 2 + ext + 4 > input.len() {
            return Err(Error::InvalidData("arj: truncated ext header"));
        }
        end += 2 + ext + 4;
    } else {
        end += 2;
    }
    Ok((end, fixed, name.into()))
}

/// Parse all member headers of one volume, returning them in order.
/// The first (main) header is skipped.
fn parse_volume(input: &[u8]) -> Result<Vec<Frag>, Error> {
    let mut frags = Vec::new();
    let mut pos = 0usize;
    let mut first = true;
    loop {
        if pos + 4 > input.len() {
            return Err(Error::InvalidData("arj: truncated signature"));
        }
        if input[pos..pos + 2] != SIG {
            return Err(Error::InvalidData("arj: bad signature"));
        }
        let hsize = u16le(&input[pos + 2..]) as usize;
        if hsize == 0 {
            return Ok(frags); // end of archive
        }
        let (end, fixed, name) = parse_header(input, pos)?;
        if fixed[4] & 0x40 != 0 {
            return Err(Error::Unsupported("arj: security-envelope entry"));
        }
        if first {
            // Main header: file_type 2, no payload.
            first = false;
            pos = end;
            continue;
        }
        let packed = u32le(&fixed[12..]) as usize;
        if end + packed > input.len() {
            return Err(Error::InvalidData("arj: truncated entry data"));
        }
        frags.push(Frag {
            name,
            flags: fixed[4],
            method: fixed[5],
            file_type: fixed[6],
            pmod: fixed[7],
            mtime: u32le(&fixed[8..]),
            crc: u32le(&fixed[20..]),
            orig: u32le(&fixed[16..]) as usize,
            data_off: end,
            data_len: packed,
        });
        pos = end + packed;
    }
}

/// De-garble a packed stream: byte `i` is XORed with
/// `password[i % len].wrapping_add(modifier)`. Semantics follow
/// XADMaster's ARJPasswordModifier + XOR handle behavior. The
/// transform is symmetric, so the encoder reuses it to garble output.
pub(crate) fn ungarble(data: &mut [u8], password: &[u8], pmod: u8) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= password[i % password.len()].wrapping_add(pmod);
    }
}

/// Decode one complete (assembled) member's packed data.
fn decode_member(f: &Frag, packed: &[u8], password: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut buf;
    let packed = if f.flags & 0x01 != 0 {
        let pw = password
            .filter(|p| !p.is_empty())
            .ok_or(Error::Unsupported("arj: garbled entry needs a password"))?;
        buf = packed.to_vec();
        ungarble(&mut buf, pw, f.pmod);
        &buf[..]
    } else {
        packed
    };
    let data = match f.method {
        0 => {
            if packed.len() != f.orig {
                return Err(Error::InvalidData("arj: size mismatch"));
            }
            packed.to_vec()
        }
        1..=3 => crate::compress::lzh::st1::decode(15, 5, packed, f.orig)?,
        4 => super::method4::decode(packed, f.orig)?,
        // ARJ32 "no data, no CRC": payload-less member whose CRC
        // field is not meaningful, so the CRC check is skipped.
        8 => {
            if f.orig != 0 || !packed.is_empty() {
                return Err(Error::InvalidData("arj: no-data entry with payload"));
            }
            return Ok(Vec::new());
        }
        // ARJ32 "no data": payload-less member; the shared checks
        // verify orig == 0 and the CRC of the empty payload.
        9 => Vec::new(),
        _ => return Err(Error::Unsupported("arj: unsupported method")),
    };
    if data.len() != f.orig {
        return Err(Error::InvalidData("arj: size mismatch"));
    }
    if crate::util::crc32::crc32(&data) != f.crc {
        return Err(Error::InvalidData("arj: data CRC-32 mismatch"));
    }
    Ok(data)
}

/// Decode one or more ARJ volumes, reassembling files whose flag
/// 0x04 marks them as continued into the next volume.
fn decode_parts_impl(parts: &[&[u8]], password: Option<&[u8]>) -> Result<Vec<ArjEntry>, Error> {
    decode_parts_bounded(parts, password, usize::MAX)
}

/// [`decode_parts_impl`] with a total decoded-payload budget: a member
/// whose declared original size exceeds the remaining budget fails
/// with [`Error::OutputLimitExceeded`] before its data is materialized.
fn decode_parts_bounded(
    parts: &[&[u8]],
    password: Option<&[u8]>,
    max_output: usize,
) -> Result<Vec<ArjEntry>, Error> {
    let mut entries = Vec::new();
    let mut emitted = 0usize;
    // Packed-data fragments of the entry currently being assembled.
    // Non-split members finalize on their single fragment.
    let mut pending: Vec<(Frag, &[u8])> = Vec::new();

    for part in parts {
        for f in parse_volume(part)? {
            let slice = &part[f.data_off..f.data_off + f.data_len];
            if let Some(first) = pending.first()
                && first.0.name != f.name
            {
                return Err(Error::InvalidData("arj: multi-volume name mismatch"));
            }
            let split_continues = f.flags & 0x04 != 0;
            pending.push((f, slice));
            if split_continues {
                continue;
            }
            let head = &pending[0].0;
            let mut blob = Vec::new();
            for (_, d) in &pending {
                blob.extend_from_slice(d);
            }
            // Directories, volume labels, and chapter labels
            // (file types 3-5) carry no decodable payload.
            let is_meta = matches!(head.file_type, 3..=5);
            if !is_meta && head.orig > max_output.saturating_sub(emitted) {
                return Err(Error::OutputLimitExceeded { limit: max_output });
            }
            let data = if is_meta {
                Vec::new()
            } else {
                decode_member(head, &blob, password)?
            };
            emitted = emitted.saturating_add(data.len());
            entries.push(ArjEntry {
                name: head.name.clone(),
                method: head.method,
                file_type: head.file_type,
                is_dir: head.file_type == 3,
                mtime: head.mtime,
                crc32: head.crc,
                data,
            });
            pending.clear();
        }
    }
    if !pending.is_empty() {
        return Err(Error::InvalidData("arj: multi-volume archive truncated"));
    }
    Ok(entries)
}

/// Decode an ARJ archive into entries.
pub fn decode(input: &[u8]) -> Result<Vec<ArjEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    decode_parts_impl(&[input], None)
}

/// Decode with a maximum total payload size limit across all entries.
///
/// A member whose declared original size exceeds the remaining output
/// budget is rejected with [`Error::OutputLimitExceeded`] before its
/// data is materialized.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<ArjEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    decode_parts_bounded(&[input], None, max_output)
}

/// [`decode_bounded`] for archives whose entries are garbled with a
/// password.
pub fn decode_bounded_with_password(
    input: &[u8],
    password: &str,
    max_output: usize,
) -> Result<Vec<ArjEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    decode_parts_bounded(&[input], Some(password.as_bytes()), max_output)
}

/// Decode an ARJ archive into entries using a password for garbled
/// entries.
pub fn decode_with_password(input: &[u8], password: &str) -> Result<Vec<ArjEntry>, Error> {
    decode_with_password_bytes(input, password.as_bytes())
}

/// Decode an ARJ archive into entries using a password for garbled
/// entries.
pub fn decode_with_password_bytes(input: &[u8], password: &[u8]) -> Result<Vec<ArjEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    decode_parts_impl(&[input], Some(password))
}

/// Decode a multi-volume ARJ archive from its volume buffers, in
/// order. With `std`, `volume_paths` discovers the `.arj`/`.aNN`
/// sibling files for this call.
pub fn decode_parts(parts: &[&[u8]]) -> Result<Vec<ArjEntry>, Error> {
    decode_parts_impl(parts, None)
}

/// [`decode_parts`] with a password for garbled entries.
pub fn decode_parts_with_password_bytes(
    parts: &[&[u8]],
    password: &[u8],
) -> Result<Vec<ArjEntry>, Error> {
    decode_parts_impl(parts, Some(password))
}

/// Enumerate the volume paths of a multi-volume archive whose first
/// volume is `first` (conventionally `name.arj`).
///
/// The result always starts with `first` itself; then same-stem
/// siblings `name.a01`, `name.a02`, … `name.a99` are appended in
/// order while the files exist, stopping at the first missing
/// number. Reading the returned paths and feeding their contents to
/// [`decode_parts`] or [`decode_parts_with_password_bytes`]
/// reassembles the archive without the caller tracking volumes.
///
/// ```text
/// let paths = decode::volume_paths(first);
/// let bufs: Vec<Vec<u8>> = paths.iter()
///     .map(std::fs::read).collect::<std::io::Result<_>>()?;
/// let parts: Vec<&[u8]> = bufs.iter().map(Vec::as_slice).collect();
/// let entries = decode::decode_parts(&parts)?;
/// ```
#[cfg(feature = "std")]
pub fn volume_paths(first: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = alloc::vec![first.to_path_buf()];
    for n in 1..=99u32 {
        let next = first.with_extension(format!("a{n:02}"));
        if !next.is_file() {
            break;
        }
        out.push(next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = crate::archive::arj::encode::encode(&[
            ("hello.txt", b"hi arj"),
            ("d/f.bin", &[9, 8, 7]),
        ])
        .unwrap();
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name, "hello.txt");
        assert_eq!(e[0].data, b"hi arj");
        assert_eq!(e[1].name, "d/f.bin");
        assert_eq!(e[0].method, 0);
    }

    #[test]
    fn dir_entry() {
        let mut enc = crate::archive::arj::encode::ArjEncoder::new();
        enc.add_dir("sub", 0).unwrap();
        enc.add_file("sub/a", b"q", 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert!(e[0].is_dir);
        assert_eq!(e[0].file_type, 3);
    }

    /// Offset of the second (first file) header in `a`.
    fn second_header_off(a: &[u8]) -> usize {
        let h1 = u16le(&a[2..]) as usize;
        4 + h1 + 4 + 2
    }

    /// Patch the fixed fields of the second (first file) header
    /// and rewrite its header CRC.
    fn patch_second(a: &mut [u8], patch: impl Fn(&mut [u8])) {
        let second = second_header_off(a);
        patch(&mut a[second + 4..second + 4 + BASIC_HDR_SIZE]);
        let bsize = u16le(&a[second + 2..]) as usize;
        let crc = crate::util::crc32::crc32(&a[second + 4..second + 4 + bsize]);
        a[second + 4 + bsize..second + 8 + bsize].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn rejects_unsupported_method() {
        // Methods 5-7 were never assigned; 10+ are reserved.
        for method in [5u8, 6, 7, 10, u8::MAX] {
            let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
            patch_second(&mut a, |h| h[5] = method);
            assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
        }
    }

    #[test]
    fn test_arj_method8_9_no_data() {
        // ARJ32 pseudo-methods on payload-less members:
        // 8 = "no data, no CRC" (CRC field ignored),
        // 9 = "no data" (CRC covers the empty payload).
        let mut a = crate::archive::arj::encode::encode(&[("empty", b"")]).unwrap();
        patch_second(&mut a, |h| {
            h[5] = 8;
            h[20..24].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        });
        let e = decode(&a).unwrap();
        assert_eq!(e[0].method, 8);
        assert!(e[0].data.is_empty());

        let mut a = crate::archive::arj::encode::encode(&[("empty", b"")]).unwrap();
        patch_second(&mut a, |h| h[5] = 9);
        let e = decode(&a).unwrap();
        assert_eq!(e[0].method, 9);
        assert!(e[0].data.is_empty());

        // Method 9 still verifies the empty payload's CRC.
        let mut a = crate::archive::arj::encode::encode(&[("empty", b"")]).unwrap();
        patch_second(&mut a, |h| {
            h[5] = 9;
            h[20..24].copy_from_slice(&1u32.to_le_bytes());
        });
        assert!(matches!(decode(&a), Err(Error::InvalidData(_))));

        // A payload-bearing member tagged method 8 is rejected.
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        patch_second(&mut a, |h| h[5] = 8);
        assert!(matches!(decode(&a), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_arj_chapter_label() {
        // file_type 5 is a chapter label: a non-file header
        // conventionally named <<<NNN>>>, carrying no payload.
        let mut a = crate::archive::arj::encode::encode(&[("<<<001>>>", b"")]).unwrap();
        patch_second(&mut a, |h| h[6] = 5);
        let e = decode(&a).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "<<<001>>>");
        assert_eq!(e[0].file_type, 5);
        assert!(!e[0].is_dir);
        assert!(e[0].data.is_empty());
    }

    #[test]
    fn st1_methods_roundtrip() {
        // Compressible payload producing real matches.
        let mut data = Vec::new();
        for i in 0..300u32 {
            data.extend_from_slice(b"arj static huffman payload ");
            data.extend_from_slice(&i.to_le_bytes());
        }
        // Methods 1-3 share the st1 wire format (15-bit window).
        for method in [1u8, 2, 3] {
            let mut enc = crate::archive::arj::encode::ArjEncoder::with_method(method).unwrap();
            enc.add_file("f.bin", &data, 0).unwrap();
            let a = enc.finish();
            let e = decode(&a).unwrap();
            assert_eq!(e.len(), 1);
            assert_eq!(e[0].method, method);
            assert_eq!(e[0].data, data);
            // The compressed member must beat a stored archive.
            let mut stored = crate::archive::arj::encode::ArjEncoder::new();
            stored.add_file("f.bin", &data, 0).unwrap();
            assert!(a.len() < stored.finish().len());
        }
    }

    #[test]
    fn st1_incompressible_falls_back_to_stored() {
        let mut s = 0x243F_6A88u32;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                (s >> 24) as u8
            })
            .collect();
        let mut enc = crate::archive::arj::encode::ArjEncoder::with_method(2).unwrap();
        enc.add_file("rand.bin", &data, 0).unwrap();
        let e = decode(&enc.finish()).unwrap();
        assert_eq!(e[0].method, 0);
        assert_eq!(e[0].data, data);
    }

    #[test]
    fn encoder_rejects_unsupported_method() {
        use crate::archive::arj::encode::ArjEncoder;
        for m in [0u8, 1, 2, 3, 4] {
            assert!(ArjEncoder::with_method(m).is_ok());
        }
        for m in [5u8, 9, u8::MAX] {
            assert!(ArjEncoder::with_method(m).is_err());
        }
    }

    #[test]
    fn rejects_bad_header_crc() {
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        let second = second_header_off(&a);
        let bsize = u16le(&a[second + 2..]) as usize;
        a[second + 4 + bsize] ^= 0xff;
        assert!(decode(&a).is_err());
    }

    #[test]
    fn rejects_garbled_without_password() {
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        patch_second(&mut a, |h| h[4] |= 0x01); // garbled flag
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_security_envelope() {
        let mut a = crate::archive::arj::encode::encode(&[("f", b"x")]).unwrap();
        patch_second(&mut a, |h| h[4] |= 0x40); // secured flag
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
        assert!(matches!(decode_parts(&[&a]), Err(Error::Unsupported(_))));
    }

    #[test]
    fn garbled_roundtrip() {
        // Stored and compressed members written garbled decode with
        // the matching password; the wire carries flag 0x01 + pmod.
        let payload = b"garbled payload payload payload".repeat(20);
        for method in [0u8, 2] {
            let mut enc = crate::archive::arj::encode::ArjEncoder::with_method(method)
                .unwrap()
                .with_password(b"secret", 0x5A)
                .unwrap();
            enc.add_file("g.bin", &payload, 0).unwrap();
            let a = enc.finish();
            let second = second_header_off(&a);
            assert_eq!(a[second + 4 + 4] & 0x01, 0x01); // garbled flag
            assert_eq!(a[second + 4 + 7], 0x5A); // pmod byte
            let e = decode_with_password_bytes(&a, b"secret").unwrap();
            assert_eq!(e[0].name, "g.bin");
            assert_eq!(e[0].data, payload);
        }
    }

    #[test]
    fn garbled_write_requires_password_decode() {
        let mut enc = crate::archive::arj::encode::ArjEncoder::new()
            .with_password(b"secret", 0x11)
            .unwrap();
        enc.add_file("g.bin", b"hidden data", 0).unwrap();
        let a = enc.finish();
        // No password: Unsupported, as for foreign garbled archives.
        assert!(matches!(decode(&a), Err(Error::Unsupported(_))));
        // Wrong password de-garbles to garbage: data CRC mismatch.
        assert!(decode_with_password_bytes(&a, b"wrong").is_err());
        // An empty password is rejected by the encoder.
        assert!(
            crate::archive::arj::encode::ArjEncoder::new()
                .with_password(b"", 0)
                .is_err()
        );
    }

    #[test]
    fn garbled_multi_volume_roundtrip() {
        // Garbling applies to the whole packed stream before
        // fragmentation, so split members reassemble correctly.
        let mut enc = crate::archive::arj::encode::ArjEncoder::new()
            .with_password(b"pw", 0x00)
            .unwrap();
        let data: Vec<u8> = (0u8..200).map(|i| i.wrapping_mul(29)).collect();
        enc.add_file("s.bin", &data, 0).unwrap();
        let parts = enc.finish_parts(120).unwrap();
        assert!(parts.len() > 1);
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let e = decode_parts_with_password_bytes(&refs, b"pw").unwrap();
        assert_eq!(e[0].data, data);
    }

    /// A member's declared `orig` is checked against the remaining
    /// budget before its data is materialized (same declared-size
    /// mechanism as the LHA `-pm1-` resource-oracle finding in fuzz
    /// run-1791677246).
    #[test]
    fn decode_bounded_enforces_declared_orig() {
        let a = crate::archive::arj::encode::encode(&[("f.bin", b"data")]).unwrap();
        let e = decode_bounded(&a, 4).unwrap();
        assert_eq!(e[0].data, b"data");
        let err = decode_bounded(&a, 3).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
        // The password entry point applies the same budget.
        let err = decode_bounded_with_password(&a, "unused", 3).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
    }

    #[cfg(feature = "std")]
    #[test]
    fn volume_paths_discovers_siblings() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("archive_arj_vol_{uniq}"));
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("x.arj");
        std::fs::write(&first, b"v1").unwrap();
        std::fs::write(dir.join("x.a01"), b"v2").unwrap();
        // A gap at .a02 stops discovery: .a03 must not be returned.
        std::fs::write(dir.join("x.a03"), b"v4").unwrap();
        let paths = volume_paths(&first);
        assert_eq!(paths, [first, dir.join("x.a01")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_all_truncations() {
        // The archive ends with a `60 EA 00 00` terminator header, so
        // no proper non-empty prefix is a complete archive: every cut
        // must fail, either at bounds checks or CRC verification.
        // (Empty input is explicitly a valid empty archive.)
        let a = crate::archive::arj::encode::encode(&[
            ("one.txt", b"first entry data"),
            ("two.bin", &[1, 2, 3, 4, 5, 6]),
        ])
        .unwrap();
        for cut in 1..a.len() {
            assert!(decode(&a[..cut]).is_err(), "cut={cut} unexpectedly decoded");
        }
    }
}
