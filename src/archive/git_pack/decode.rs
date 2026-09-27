//! Git pack file (`pack-*.pack` v2) and index (`pack-*.idx` v2) decode.
//!
//! Object entries are parsed sequentially; `OFS_DELTA` bases are
//! resolved by pack offset and `REF_DELTA` bases by object name within
//! the same pack (thin packs are rejected). The trailing pack
//! checksum (SHA-1 of all preceding bytes) is verified.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::adler32::adler32;
use crate::util::bitreader::BitReader;
use crate::util::sha1::sha1;

use super::{ObjectId, ObjectType, hex_id, object_id};

const TRAILER_LEN: usize = 20;
/// Bound on delta-chain length (git caps delta depth at 50; keep headroom).
const MAX_DELTA_DEPTH: usize = 64;

/// One decoded object from a pack file.
#[derive(Debug, Clone)]
pub struct GitPackEntry {
    /// Lower-case hex object ID.
    name: String,
    /// Raw 20-byte object ID.
    id: ObjectId,
    object_type: ObjectType,
    data: Vec<u8>,
    /// Byte offset of the entry's object header inside the pack.
    pack_offset: u64,
}

impl GitPackEntry {
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }
    /// Raw object ID (SHA-1).
    pub fn object_id(&self) -> &ObjectId {
        &self.id
    }
    /// Offset of this entry's object header in the pack file.
    pub fn pack_offset(&self) -> u64 {
        self.pack_offset
    }
}

impl crate::traits::ArchiveEntry for GitPackEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Raw entry as parsed before delta resolution.
struct RawEntry {
    /// Byte offset of the entry header in the pack.
    offset: u64,
    /// Inflated size field value (uncompressed size; delta payload size for deltas).
    _size: u64,
    /// Undeltified object type, or a delta base reference.
    kind: RawKind,
    /// Inflated (zlib-decompressed) payload.
    payload: Vec<u8>,
}

enum RawKind {
    Full(ObjectType),
    /// Base entry `offset` bytes before this entry's header.
    OfsDelta(u64),
    /// Base object ID (must be present in the same pack).
    RefDelta(ObjectId),
}

fn invalid(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

/// Decode a complete pack file. The trailing pack checksum is verified.
pub fn decode(input: &[u8]) -> Result<Vec<GitPackEntry>, Error> {
    let raws = parse_entries(input)?;
    resolve(input, raws)
}

fn parse_entries(input: &[u8]) -> Result<Vec<RawEntry>, Error> {
    if input.len() < 12 + TRAILER_LEN {
        return Err(invalid("git-pack: truncated header"));
    }
    if &input[..4] != b"PACK" {
        return Err(invalid("git-pack: bad signature"));
    }
    let version = u32::from_be_bytes(input[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Unsupported(
            "git-pack: only version 2 packs supported",
        ));
    }
    let count = u32::from_be_bytes(input[8..12].try_into().unwrap()) as usize;
    let body_end = input.len() - TRAILER_LEN;

    let mut raws = Vec::with_capacity(count.min(1 << 20));
    let mut pos = 12usize;
    for _ in 0..count {
        if pos >= body_end {
            return Err(invalid("git-pack: truncated object table"));
        }
        let offset = pos as u64;
        // Object header: (cont|type:3|size:4) then 7-bit size chunks.
        let mut b = input[pos];
        pos += 1;
        let type_code = (b >> 4) & 0x7;
        let mut size = (b & 0xF) as u64;
        let mut shift = 4u32;
        while b & 0x80 != 0 {
            if pos >= body_end || shift > 60 {
                return Err(invalid("git-pack: truncated object header"));
            }
            b = input[pos];
            pos += 1;
            size |= ((b & 0x7F) as u64) << shift;
            shift += 7;
        }
        let kind = match type_code {
            1..=4 => RawKind::Full(ObjectType::from_code(type_code)?),
            6 => {
                // OFS_DELTA: "offset encoding" — 7-bit chunks, for
                // n >= 2 bytes add 2^7 + ... + 2^(7*(n-1)).
                if pos >= body_end {
                    return Err(invalid("git-pack: truncated ofs-delta"));
                }
                let mut b = input[pos];
                pos += 1;
                let mut n = (b & 0x7F) as u64;
                while b & 0x80 != 0 {
                    if pos >= body_end {
                        return Err(invalid("git-pack: truncated ofs-delta"));
                    }
                    b = input[pos];
                    pos += 1;
                    n = n
                        .checked_add(1)
                        .and_then(|v| v.checked_shl(7))
                        .map(|v| v | (b & 0x7F) as u64)
                        .ok_or_else(|| invalid("git-pack: ofs-delta offset overflow"))?;
                }
                if n == 0 || n > offset {
                    return Err(invalid("git-pack: invalid ofs-delta base"));
                }
                RawKind::OfsDelta(n)
            }
            7 => {
                // REF_DELTA: 20-byte base object name.
                if pos + TRAILER_LEN > body_end {
                    return Err(invalid("git-pack: truncated ref-delta"));
                }
                let mut id = [0u8; 20];
                id.copy_from_slice(&input[pos..pos + 20]);
                pos += 20;
                RawKind::RefDelta(id)
            }
            _ => return Err(invalid("git-pack: invalid object type")),
        };
        let (payload, used) = zlib_decode(&input[pos..body_end])?;
        pos += used;
        raws.push(RawEntry {
            offset,
            _size: size,
            kind,
            payload,
        });
    }
    if pos != body_end {
        return Err(invalid("git-pack: trailing bytes before checksum"));
    }
    Ok(raws)
}

/// Decode a self-terminating zlib stream at the start of `input`,
/// returning `(payload, bytes_consumed)`.
fn zlib_decode(input: &[u8]) -> Result<(Vec<u8>, usize), Error> {
    if input.len() < 2 {
        return Err(invalid("git-pack: truncated zlib stream"));
    }
    let cmf = input[0];
    let flg = input[1];
    if cmf & 0x0F != 8 || (cmf >> 4) > 7 {
        return Err(invalid("git-pack: bad zlib header"));
    }
    if !((cmf as u16) << 8 | flg as u16).is_multiple_of(31) {
        return Err(invalid("git-pack: bad zlib FCHECK"));
    }
    if flg & 0x20 != 0 {
        return Err(Error::Unsupported("git-pack: zlib preset dictionary"));
    }
    let mut reader = BitReader::new(&input[2..]);
    let mut out = Vec::new();
    deflate::decode::decode_stream(&mut reader, &mut out)
        .map_err(|_| invalid("git-pack: corrupt deflate stream"))?;
    let used = reader.byte_position();
    let trailer = 2 + used;
    if input.len() < trailer + 4 {
        return Err(invalid("git-pack: truncated zlib trailer"));
    }
    let expected = u32::from_be_bytes(input[trailer..trailer + 4].try_into().unwrap());
    let actual = adler32(&out);
    if actual != expected {
        return Err(Error::ChecksumMismatch { expected, actual });
    }
    Ok((out, trailer + 4))
}

fn resolve(input: &[u8], raws: Vec<RawEntry>) -> Result<Vec<GitPackEntry>, Error> {
    // Verify the pack checksum (SHA-1 of everything before the trailer).
    let trailer = input.len() - TRAILER_LEN;
    if sha1(&input[..trailer]) != input[trailer..] {
        return Err(Error::InvalidData("git-pack: pack checksum mismatch"));
    }

    // Byte offset of each entry -> index, for OFS_DELTA bases.
    let offset_index: BTreeMap<u64, usize> = raws
        .iter()
        .enumerate()
        .map(|(i, r)| (r.offset, i))
        .collect();
    // Object ID -> index, filled as full objects are resolved; needed
    // for REF_DELTA bases that appear later in the pack.
    let mut resolved: Vec<Option<(ObjectType, Vec<u8>)>> = (0..raws.len()).map(|_| None).collect();
    let mut resolving = alloc::vec![false; raws.len()];

    // First resolve all non-delta objects so every possible REF_DELTA
    // base name is known.
    let mut name_index: BTreeMap<ObjectId, usize> = BTreeMap::new();
    for (i, raw) in raws.iter().enumerate() {
        if let RawKind::Full(t) = raw.kind {
            name_index.insert(object_id(t, &raw.payload), i);
        }
    }

    fn resolve_at(
        i: usize,
        raws: &[RawEntry],
        offset_index: &BTreeMap<u64, usize>,
        name_index: &BTreeMap<ObjectId, usize>,
        resolved: &mut [Option<(ObjectType, Vec<u8>)>],
        resolving: &mut [bool],
        depth: usize,
    ) -> Result<(), Error> {
        if resolved[i].is_some() {
            return Ok(());
        }
        if depth > MAX_DELTA_DEPTH {
            return Err(invalid("git-pack: delta chain too deep"));
        }
        if resolving[i] {
            return Err(invalid("git-pack: delta cycle"));
        }
        resolving[i] = true;
        let base_idx = match &raws[i].kind {
            RawKind::Full(t) => {
                resolved[i] = Some((*t, raws[i].payload.clone()));
                resolving[i] = false;
                return Ok(());
            }
            RawKind::OfsDelta(back) => {
                let base_off = raws[i].offset - back;
                *offset_index
                    .get(&base_off)
                    .ok_or_else(|| invalid("git-pack: ofs-delta base missing"))?
            }
            RawKind::RefDelta(id) => *name_index
                .get(id)
                .ok_or_else(|| invalid("git-pack: thin pack (ref-delta base missing)"))?,
        };
        resolve_at(
            base_idx,
            raws,
            offset_index,
            name_index,
            resolved,
            resolving,
            depth + 1,
        )?;
        let (bt, bdata) = resolved[base_idx].clone().unwrap();
        let out = apply_delta(&bdata, &raws[i].payload)?;
        resolved[i] = Some((bt, out));
        resolving[i] = false;
        Ok(())
    }

    let mut entries = Vec::with_capacity(raws.len());
    for i in 0..raws.len() {
        resolve_at(
            i,
            &raws,
            &offset_index,
            &name_index,
            &mut resolved,
            &mut resolving,
            0,
        )?;
        let (t, data) = resolved[i].take().unwrap();
        let id = object_id(t, &data);
        entries.push(GitPackEntry {
            name: hex_id(&id),
            id,
            object_type: t,
            data,
            pack_offset: raws[i].offset,
        });
    }
    Ok(entries)
}

/// Read one "size encoding" varint (7-bit little-endian chunks, MSB
/// continuation), returning `(value, bytes_consumed)`.
fn read_size(data: &[u8], mut pos: usize) -> Result<(u64, usize), Error> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() || shift > 63 {
            return Err(invalid("git-pack: truncated delta header"));
        }
        let b = data[pos];
        pos += 1;
        v |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok((v, pos));
        }
        shift += 7;
    }
}

/// Apply a git delta instruction stream to `base`.
///
/// Delta data: `size_of_base` and `size_of_result` size-encoded
/// varints, then copy (`1xxxxxxx`) and insert (`0xxxxxxx`, nonzero)
/// instructions until the result is complete.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, Error> {
    let (src_size, pos) = read_size(delta, 0)?;
    if src_size as usize != base.len() {
        return Err(invalid("git-pack: delta base size mismatch"));
    }
    let (dst_size, mut pos) = read_size(delta, pos)?;
    let mut out = Vec::with_capacity(dst_size.min(1 << 28) as usize);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd & 0x80 != 0 {
            // Copy from base: offset 4 optional bytes, size 3 optional
            // bytes (little-endian); size 0 means 0x10000.
            let mut off = 0usize;
            let mut sz = 0usize;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(invalid("git-pack: truncated copy instruction"));
                    }
                    off |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            for i in 0..3 {
                if cmd & (0x10 << i) != 0 {
                    if pos >= delta.len() {
                        return Err(invalid("git-pack: truncated copy instruction"));
                    }
                    sz |= (delta[pos] as usize) << (8 * i);
                    pos += 1;
                }
            }
            if sz == 0 {
                sz = 0x10000;
            }
            if off.checked_add(sz).is_none_or(|end| end > base.len()) {
                return Err(invalid("git-pack: copy out of base bounds"));
            }
            out.extend_from_slice(&base[off..off + sz]);
        } else if cmd != 0 {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err(invalid("git-pack: truncated insert instruction"));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err(invalid("git-pack: reserved delta instruction"));
        }
        if out.len() > dst_size as usize {
            return Err(invalid("git-pack: delta output overflow"));
        }
    }
    if out.len() != dst_size as usize {
        return Err(invalid("git-pack: delta result size mismatch"));
    }
    Ok(out)
}

// ============================================================
// pack-*.idx (version 2) read support
// ============================================================

const IDX_MAGIC: [u8; 4] = [0xFF, 0x74, 0x4F, 0x63];

/// One row of a v2 pack index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdxEntry {
    /// Object ID (binary).
    pub id: ObjectId,
    /// Hex object name.
    pub name: String,
    /// CRC32 of the object's packed entry data.
    pub crc32: u32,
    /// Byte offset of the entry's object header in the pack.
    pub offset: u64,
}

/// Decode a version-2 `.idx` file, verifying both trailing checksums.
///
/// `pack` must be the corresponding `.pack` file contents (used to
/// verify the embedded pack checksum). The idx checksum covers the
/// whole file before its own trailer.
pub fn decode_idx(input: &[u8], pack: &[u8]) -> Result<Vec<IdxEntry>, Error> {
    if input.len() < 8 + 256 * 4 + 2 * TRAILER_LEN {
        return Err(invalid("git-pack: truncated idx"));
    }
    if input[..4] != IDX_MAGIC {
        return Err(invalid("git-pack: bad idx magic"));
    }
    let version = u32::from_be_bytes(input[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Unsupported("git-pack: only idx version 2 supported"));
    }
    let trailer = input.len() - TRAILER_LEN;
    if sha1(&input[..trailer]) != input[trailer..] {
        return Err(invalid("git-pack: idx checksum mismatch"));
    }
    let pack_sum = &input[trailer - TRAILER_LEN..trailer];
    if pack.len() < TRAILER_LEN || pack_sum != &pack[pack.len() - TRAILER_LEN..] {
        return Err(invalid("git-pack: idx pack checksum mismatch"));
    }

    let mut fanout = [0u32; 256];
    for (i, f) in fanout.iter_mut().enumerate() {
        *f = u32::from_be_bytes(input[8 + i * 4..12 + i * 4].try_into().unwrap());
    }
    for w in fanout.windows(2) {
        if w[0] > w[1] {
            return Err(invalid("git-pack: idx fanout not monotonic"));
        }
    }
    let n = fanout[255] as usize;

    let names_at = 8 + 256 * 4;
    let crcs_at = names_at + n * 20;
    let offs_at = crcs_at + n * 4;
    let large_at = offs_at + n * 4;
    if large_at > trailer - TRAILER_LEN {
        return Err(invalid("git-pack: truncated idx tables"));
    }
    let n_large = (trailer - TRAILER_LEN - large_at) / 8;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut id = [0u8; 20];
        id.copy_from_slice(&input[names_at + i * 20..names_at + i * 20 + 20]);
        let crc32 = u32::from_be_bytes(
            input[crcs_at + i * 4..crcs_at + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let off32 = u32::from_be_bytes(
            input[offs_at + i * 4..offs_at + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
        let offset = if off32 & 0x8000_0000 != 0 {
            let li = (off32 & 0x7FFF_FFFF) as usize;
            if li >= n_large {
                return Err(invalid("git-pack: idx large-offset index out of range"));
            }
            u64::from_be_bytes(
                input[large_at + li * 8..large_at + li * 8 + 8]
                    .try_into()
                    .unwrap(),
            )
        } else {
            off32 as u64
        };
        entries.push(IdxEntry {
            id,
            name: hex_id(&id),
            crc32,
            offset,
        });
    }
    Ok(entries)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::zlib;
    use crate::traits::ArchiveEntry;

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Object header bytes for `type_code` + `size`.
    fn obj_header(type_code: u8, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = (type_code << 4) | (size as u8 & 0xF);
        let mut s = size >> 4;
        if s != 0 {
            first |= 0x80;
        }
        out.push(first);
        while s != 0 {
            let mut b = (s as u8) & 0x7F;
            s >>= 7;
            if s != 0 {
                b |= 0x80;
            }
            out.push(b);
        }
        out
    }

    fn pack(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"PACK");
        p.extend_from_slice(&be32(2));
        p.extend_from_slice(&be32(entries.len() as u32));
        for e in entries {
            p.extend_from_slice(e);
        }
        let sum = crate::util::sha1::sha1(&p);
        p.extend_from_slice(&sum);
        p
    }

    /// ofs-delta "offset encoding" for `n`.
    fn ofs_offset(n: u64) -> Vec<u8> {
        // Reconstruct: write n then encode like the decoder reverses.
        let mut chunks = alloc::vec::Vec::new();
        let mut v = n;
        chunks.push((v & 0x7F) as u8);
        v >>= 7;
        while v != 0 {
            v -= 1;
            chunks.push((v & 0x7F) as u8);
            v >>= 7;
        }
        chunks.reverse();
        for i in 0..chunks.len() - 1 {
            chunks[i] |= 0x80;
        }
        chunks
    }

    fn blob_entry(data: &[u8]) -> Vec<u8> {
        let mut e = obj_header(3, data.len() as u64);
        e.extend_from_slice(&zlib::encode::encode(data));
        e
    }

    #[test]
    fn ofs_delta_handbuilt() {
        let base = b"0123456789abcdef";
        let base_e = blob_entry(base);
        // Delta: src=16, dst=4, copy off=4 len=3 ("456"), insert 'x'
        let delta = [16u8, 4, 0x91, 4, 3, 1, b'x'];
        let mut de = obj_header(6, delta.len() as u64);
        // base entry is `base_e.len()` bytes back
        de.extend_from_slice(&ofs_offset(base_e.len() as u64));
        de.extend_from_slice(&zlib::encode::encode(&delta));
        let p = pack(&[base_e, de]);
        let entries = decode(&p).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].data(), b"456x");
        assert_eq!(entries[1].object_type(), ObjectType::Blob);
    }

    #[test]
    fn thin_pack_rejected() {
        // REF_DELTA whose base ID is not in the pack.
        let delta = [4u8, 1, 0x90, 1]; // src=4,dst=1,copy off0 len1
        let mut de = obj_header(7, delta.len() as u64);
        de.extend_from_slice(&[0xAA; 20]);
        de.extend_from_slice(&zlib::encode::encode(&delta));
        let p = pack(&[de]);
        assert!(matches!(decode(&p), Err(Error::InvalidData(_))));
    }

    #[test]
    fn delta_chain_depth() {
        // ofs-delta chained twice: base -> d1 -> d2
        let base = b"zz";
        let e0 = blob_entry(base);
        let d1 = [2u8, 2, 0x90, 2]; // copy whole base
        let mut e1 = obj_header(6, d1.len() as u64);
        e1.extend_from_slice(&ofs_offset(e0.len() as u64));
        e1.extend_from_slice(&zlib::encode::encode(&d1));
        let d2 = [2u8, 1, 0x90, 1];
        let mut e2 = obj_header(6, d2.len() as u64);
        e2.extend_from_slice(&ofs_offset(e1.len() as u64));
        e2.extend_from_slice(&zlib::encode::encode(&d2));
        let p = pack(&[e0, e1, e2]);
        let entries = decode(&p).unwrap();
        assert_eq!(entries[2].data(), b"z");
    }

    #[test]
    fn ofs_delta_bad_base() {
        // ofs pointing before offset 12 (header region)
        let delta = [1u8, 1, 0x90, 0, 1];
        let mut de = obj_header(6, delta.len() as u64);
        de.extend_from_slice(&ofs_offset(5));
        de.extend_from_slice(&zlib::encode::encode(&delta));
        let p = pack(&[de]);
        assert!(decode(&p).is_err());
    }
}
