//! Git pack file (`pack-*.pack` v2/v3) and index (`pack-*.idx` v1/v2)
//! decode.
//!
//! Object entries are parsed sequentially; `OFS_DELTA` bases are
//! resolved by pack offset and `REF_DELTA` bases by object name within
//! the same pack (thin packs are rejected). The trailing pack
//! checksum (SHA-1 for v2, SHA-256 for v3 packs) is verified. v3 packs
//! use 32-byte object names throughout (REF_DELTA bases, entry IDs).
//!
//! [`decode_idx`] reads checksummed v2 indexes; [`decode_idx_v1`]
//! reads the legacy v1 format (its trailing idx checksum is
//! verified; the embedded pack checksum is parsed only).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;
use crate::util::adler32::adler32;
use crate::util::bitreader::BitReader;
use crate::util::sha1::sha1;
use crate::util::sha256::sha256;

use super::{ObjectId, ObjectType, hex_id, object_id_with_kind};

const SHA1_LEN: usize = 20;
const SHA256_LEN: usize = 32;

/// Object-hash algorithm implied by the pack version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    /// SHA-1 (pack v2, 20-byte names/trailer).
    Sha1,
    /// SHA-256 (pack v3, 32-byte names/trailer).
    Sha256,
}

impl HashKind {
    pub(crate) fn id_len(self) -> usize {
        match self {
            Self::Sha1 => SHA1_LEN,
            Self::Sha256 => SHA256_LEN,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1(data).to_vec(),
            Self::Sha256 => sha256(data).to_vec(),
        }
    }
}
/// Bound on delta-chain length (git caps delta depth at 50; keep headroom).
const MAX_DELTA_DEPTH: usize = 64;

/// One decoded object from a pack file.
#[derive(Debug, Clone)]
pub struct GitPackEntry {
    /// Lower-case hex object ID.
    name: String,
    /// Raw object ID (20 bytes for v2/SHA-1, 32 for v3/SHA-256).
    id: Vec<u8>,
    object_type: ObjectType,
    data: Vec<u8>,
    /// Byte offset of the entry's object header inside the pack.
    pack_offset: u64,
}

impl GitPackEntry {
    pub fn object_type(&self) -> ObjectType {
        self.object_type
    }
    /// Raw object ID (`HashKind` length: 20 bytes v2, 32 bytes v3).
    pub fn object_id(&self) -> &[u8] {
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
    RefDelta(Vec<u8>),
}

fn invalid(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

/// Decode a complete pack file. The trailing pack checksum is verified.
pub fn decode(input: &[u8]) -> Result<Vec<GitPackEntry>, Error> {
    let (kind, raws) = parse_entries(input)?;
    resolve(input, kind, raws)
}

fn parse_entries(input: &[u8]) -> Result<(HashKind, Vec<RawEntry>), Error> {
    if input.len() < 12 + SHA1_LEN {
        return Err(invalid("git-pack: truncated header"));
    }
    if &input[..4] != b"PACK" {
        return Err(invalid("git-pack: bad signature"));
    }
    let version = u32::from_be_bytes(input[4..8].try_into().unwrap());
    let kind = match version {
        2 => HashKind::Sha1,
        3 => HashKind::Sha256,
        _ => {
            return Err(Error::Unsupported(
                "git-pack: only version 2/3 packs supported",
            ));
        }
    };
    let count = u32::from_be_bytes(input[8..12].try_into().unwrap()) as usize;
    let body_end = input
        .len()
        .checked_sub(kind.id_len())
        .ok_or(invalid("git-pack: truncated header"))?;

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
                // REF_DELTA: base object name (hash-length bytes).
                let hlen = kind.id_len();
                if pos + hlen > body_end {
                    return Err(invalid("git-pack: truncated ref-delta"));
                }
                let id = input[pos..pos + hlen].to_vec();
                pos += hlen;
                RawKind::RefDelta(id)
            }
            _ => return Err(invalid("git-pack: invalid object type")),
        };
        let (payload, used) = zlib_decode(&input[pos..body_end])?;
        pos += used;
        // The size field is the inflated object size for undeltified
        // entries and the delta data size for delta entries; either
        // way it must equal the decompressed payload length.
        if size != payload.len() as u64 {
            return Err(invalid("git-pack: object size field mismatch"));
        }
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
    Ok((kind, raws))
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

fn resolve(input: &[u8], kind: HashKind, raws: Vec<RawEntry>) -> Result<Vec<GitPackEntry>, Error> {
    // Verify the pack checksum (hash of everything before the trailer).
    let trailer = input.len() - kind.id_len();
    if kind.digest(&input[..trailer]) != input[trailer..] {
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

    // Object ID -> index, filled as objects resolve. REF_DELTA bases
    // may themselves be delta entries, whose names are only known
    // once their content has been resolved.
    let mut name_index: BTreeMap<Vec<u8>, usize> = BTreeMap::new();

    fn resolve_at(
        i: usize,
        raws: &[RawEntry],
        offset_index: &BTreeMap<u64, usize>,
        name_index: &BTreeMap<Vec<u8>, usize>,
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
                .get(id.as_slice())
                .ok_or_else(|| invalid("git-pack: thin pack (ref-delta base missing)"))?,
        };
        let r = resolve_at(
            base_idx,
            raws,
            offset_index,
            name_index,
            resolved,
            resolving,
            depth + 1,
        );
        resolving[i] = false;
        r?;
        let (bt, bdata) = resolved[base_idx].clone().unwrap();
        let out = apply_delta(&bdata, &raws[i].payload)?;
        resolved[i] = Some((bt, out));
        Ok(())
    }

    // Resolve in passes: every pass inserts freshly resolved object
    // IDs into the name index, so REF_DELTA chains onto delta entries
    // converge in at most raws.len() passes. A pass with no progress
    // surfaces the first error (thin pack, cycle, corrupt delta).
    loop {
        let mut progress = false;
        let mut first_err = None;
        for i in 0..raws.len() {
            if resolved[i].is_some() {
                continue;
            }
            match resolve_at(
                i,
                &raws,
                &offset_index,
                &name_index,
                &mut resolved,
                &mut resolving,
                0,
            ) {
                Ok(()) => {
                    let (t, data) = resolved[i].as_ref().unwrap();
                    name_index.insert(object_id_with_kind(kind, *t, data), i);
                    progress = true;
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if !progress {
            if let Some(e) = first_err {
                return Err(e);
            }
            break;
        }
    }

    let mut entries = Vec::with_capacity(raws.len());
    for i in 0..raws.len() {
        let (t, data) = resolved[i].take().unwrap();
        let id = object_id_with_kind(kind, t, &data);
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
    let dst_len = crate::util::bounded::declared_output_len(dst_size)?;
    let mut out = Vec::with_capacity(dst_len.min(1 << 28));
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
        if out.len() > dst_len {
            return Err(invalid("git-pack: delta output overflow"));
        }
    }
    if out.len() != dst_len {
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
    /// Object ID (binary; 20 bytes for SHA-1, 32 for SHA-256).
    pub id: Vec<u8>,
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
    decode_idx_with_kind(input, pack, HashKind::Sha1)
}

/// Decode a version-2 `.idx` file for a SHA-256 (v3) pack:
/// 32-byte object names and SHA-256 trailer checksums.
pub fn decode_idx_v2_sha256(input: &[u8], pack: &[u8]) -> Result<Vec<IdxEntry>, Error> {
    decode_idx_with_kind(input, pack, HashKind::Sha256)
}

fn decode_idx_with_kind(input: &[u8], pack: &[u8], hash: HashKind) -> Result<Vec<IdxEntry>, Error> {
    let hl = hash.id_len();
    if input.len() < 8 + 256 * 4 + 2 * hl {
        return Err(invalid("git-pack: truncated idx"));
    }
    if input[..4] != IDX_MAGIC {
        return Err(invalid("git-pack: bad idx magic"));
    }
    let version = u32::from_be_bytes(input[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::Unsupported("git-pack: only idx version 2 supported"));
    }
    let trailer = input.len() - hl;
    if hash.digest(&input[..trailer]) != input[trailer..] {
        return Err(invalid("git-pack: idx checksum mismatch"));
    }
    let pack_sum = &input[trailer - hl..trailer];
    if pack.len() < hl || pack_sum != &pack[pack.len() - hl..] {
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
    let crcs_at = names_at + n * hl;
    let offs_at = crcs_at + n * 4;
    let large_at = offs_at + n * 4;
    if large_at > trailer - hl {
        return Err(invalid("git-pack: truncated idx tables"));
    }
    let n_large = (trailer - hl - large_at) / 8;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let id = input[names_at + i * hl..names_at + i * hl + hl].to_vec();
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
            name: hex_id(&id),
            id,
            crc32,
            offset,
        });
    }
    Ok(entries)
}

/// Decode a version-1 `.idx` file (legacy, no magic).
///
/// Layout: 256-entry fanout table, `fanout[255]` rows of
/// `u32 offset + 20-byte SHA-1` sorted by object name, then a
/// 40-byte trailer holding the pack checksum (parsed but not
/// verified — the pack itself is not an input) and the idx
/// checksum (SHA-1 of all preceding bytes, verified). v1 has no
/// CRC32 table, so `crc32` is reported as 0.
pub fn decode_idx_v1(input: &[u8]) -> Result<Vec<IdxEntry>, Error> {
    if input.len() < 256 * 4 + 2 * SHA1_LEN {
        return Err(invalid("git-pack: truncated idx"));
    }
    if input[..4] == IDX_MAGIC {
        return Err(invalid("git-pack: v2 idx passed to v1 decoder"));
    }
    // Trailer: 20-byte pack checksum then the 20-byte idx checksum
    // (SHA-1 of everything before itself). The pack checksum cannot
    // be verified without the .pack bytes.
    let idx_sum_at = input.len() - SHA1_LEN;
    if sha1(&input[..idx_sum_at]) != input[idx_sum_at..] {
        return Err(invalid("git-pack: idx v1 checksum mismatch"));
    }
    let entries_end = idx_sum_at - SHA1_LEN;
    let mut fanout = [0u32; 256];
    for (i, f) in fanout.iter_mut().enumerate() {
        *f = u32::from_be_bytes(input[i * 4..i * 4 + 4].try_into().unwrap());
    }
    for w in fanout.windows(2) {
        if w[0] > w[1] {
            return Err(invalid("git-pack: idx fanout not monotonic"));
        }
    }
    let n = fanout[255] as usize;
    let table_end = n
        .checked_mul(24)
        .and_then(|b| b.checked_add(256 * 4))
        .ok_or_else(|| invalid("git-pack: idx v1 size mismatch"))?;
    if table_end != entries_end {
        return Err(invalid("git-pack: idx v1 size mismatch"));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let at = 256 * 4 + i * 24;
        let offset = u32::from_be_bytes(input[at..at + 4].try_into().unwrap()) as u64;
        let id: ObjectId = input[at + 4..at + 24].try_into().unwrap();
        entries.push(IdxEntry {
            id: id.to_vec(),
            name: hex_id(&id),
            crc32: 0,
            offset,
        });
    }
    for w in entries.windows(2) {
        if w[0].id > w[1].id {
            return Err(invalid("git-pack: idx v1 names not sorted"));
        }
    }
    Ok(entries)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_delta_rejects_declared_output_above_limit() {
        let delta = [0x00, 0x81, 0x80, 0x80, 0x80, 0x04];
        let err = apply_delta(b"", &delta).unwrap_err();
        assert!(matches!(err, Error::OutputLimitExceeded { .. }));
    }
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
        pack_version(2, entries)
    }

    fn pack_version(version: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"PACK");
        p.extend_from_slice(&be32(version));
        p.extend_from_slice(&be32(entries.len() as u32));
        for e in entries {
            p.extend_from_slice(e);
        }
        let sum = match version {
            2 => crate::util::sha1::sha1(&p).to_vec(),
            3 => crate::util::sha256::sha256(&p).to_vec(),
            _ => p[..0].to_vec(),
        };
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
    fn ref_delta_chained_onto_delta() {
        // REF_DELTA whose base is itself a REF_DELTA entry: valid
        // self-contained pack (gitformat-pack "The base object could
        // also be deltified if it's in the same pack").
        let base = b"0123456789abcdef";
        let base_e = blob_entry(base);
        // d1: copy base[4..7] + insert x -> "456x" (type Blob).
        let d1 = [16u8, 4, 0x91, 4, 3, 1, b'x'];
        let base_id = object_id_with_kind(HashKind::Sha1, ObjectType::Blob, base);
        let mut e1 = obj_header(7, d1.len() as u64);
        e1.extend_from_slice(&base_id);
        e1.extend_from_slice(&zlib::encode::encode(&d1));
        // d2: base is the resolved d1 object ("456x"):
        // copy [1..2] + insert z -> "5z".
        let d2 = [4u8, 2, 0x91, 1, 1, 1, b'z'];
        let d1_id = object_id_with_kind(HashKind::Sha1, ObjectType::Blob, b"456x");
        let mut e2 = obj_header(7, d2.len() as u64);
        e2.extend_from_slice(&d1_id);
        e2.extend_from_slice(&zlib::encode::encode(&d2));
        let p = pack(&[base_e, e1, e2]);
        let entries = decode(&p).unwrap();
        assert_eq!(entries[1].data(), b"456x");
        assert_eq!(entries[2].data(), b"5z");
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
    fn tag_object_accepted() {
        // type code 4 (tag) is a valid undeltified object type.
        let mut e = obj_header(4, 3);
        e.extend_from_slice(&zlib::encode::encode(b"tag"));
        let p = pack(&[e]);
        let entries = decode(&p).unwrap();
        assert_eq!(entries[0].object_type(), ObjectType::Tag);
        assert_eq!(entries[0].data(), b"tag");
    }

    #[test]
    fn bad_object_type_rejected() {
        for tc in [0u8, 5] {
            let mut e = obj_header(tc, 1);
            e.extend_from_slice(&zlib::encode::encode(b"x"));
            let p = pack(&[e]);
            assert!(
                matches!(decode(&p), Err(Error::InvalidData(_))),
                "type {tc}"
            );
        }
    }

    #[test]
    fn object_size_field_mismatch() {
        // Header claims 5 but the zlib payload is 1 byte.
        let mut e = obj_header(3, 5);
        e.extend_from_slice(&zlib::encode::encode(b"x"));
        let p = pack(&[e]);
        assert!(matches!(decode(&p), Err(Error::InvalidData(_))));
    }

    /// Build a v2 idx over `entries` ((id, crc32, offset)) for `pack`.
    fn build_idx(entries: &[(ObjectId, u32, u64)], pack: &[u8]) -> Vec<u8> {
        let mut sorted: Vec<(ObjectId, u32, u64)> = entries.to_vec();
        sorted.sort_by_key(|e| e.0);
        let mut idx = Vec::new();
        idx.extend_from_slice(&[0xFF, 0x74, 0x4F, 0x63]);
        idx.extend_from_slice(&2u32.to_be_bytes());
        let mut fanout = [0u32; 256];
        for e in &sorted {
            fanout[e.0[0] as usize] += 1;
        }
        let mut acc = 0u32;
        for f in fanout.iter_mut() {
            acc += *f;
            idx.extend_from_slice(&acc.to_be_bytes());
        }
        for e in &sorted {
            idx.extend_from_slice(&e.0);
        }
        for e in &sorted {
            idx.extend_from_slice(&e.1.to_be_bytes());
        }
        let mut large: Vec<u64> = Vec::new();
        for e in &sorted {
            if e.2 >= 0x8000_0000 {
                idx.extend_from_slice(&((0x8000_0000u32) | large.len() as u32).to_be_bytes());
                large.push(e.2);
            } else {
                idx.extend_from_slice(&(e.2 as u32).to_be_bytes());
            }
        }
        for off in large {
            idx.extend_from_slice(&off.to_be_bytes());
        }
        idx.extend_from_slice(&pack[pack.len() - 20..]);
        let sum = crate::util::sha1::sha1(&idx);
        idx.extend_from_slice(&sum);
        idx
    }

    #[test]
    fn idx_large_offset_table() {
        // One entry with a normal offset and one past 2^31, forcing
        // the 64-bit large-offset table path in both directions.
        let base = blob_entry(b"data");
        let p = pack(&[base]);
        let entries = [
            ([0x10; 20], 0xAABB, 12u64),
            ([0x20; 20], 0xCCDD, 0x8000_0005u64),
            ([0x30; 20], 0xEEFF, 64u64),
        ];
        let idx = build_idx(&entries, &p);
        let decoded = decode_idx(&idx, &p).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].offset, 12);
        assert_eq!(decoded[1].offset, 0x8000_0005);
        assert_eq!(decoded[2].offset, 64);
        // Encoder-side: GitPackEncoder output feeds encode_idx via
        // finish_with_index on small packs; the large path is covered
        // by build_idx/decode_idx roundtrip above plus encode_idx's
        // symmetric logic.
    }

    #[test]
    fn idx_bad_checksums_rejected() {
        let p = pack(&[blob_entry(b"d")]);
        let idx = build_idx(&[([0x10; 20], 1, 12)], &p);
        // Corrupt the idx trailing checksum.
        let mut bad = idx.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        assert!(decode_idx(&bad, &p).is_err());
        // Corrupt the embedded pack checksum while keeping the idx
        // checksum valid (recompute the trailer).
        let mut bad2 = idx.clone();
        bad2[n - 40] ^= 0xFF;
        let n2 = bad2.len();
        let sum = crate::util::sha1::sha1(&bad2[..n2 - 20]);
        bad2[n2 - 20..].copy_from_slice(&sum);
        assert!(matches!(decode_idx(&bad2, &p), Err(Error::InvalidData(_))));
        // Mismatched pack argument also fails.
        let p2 = pack(&[blob_entry(b"other")]);
        assert!(decode_idx(&idx, &p2).is_err());
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

    #[test]
    fn v3_pack_roundtrip() {
        // v3: SHA-256 trailer + 32-byte names.
        let entries_data: &[&[u8]] = &[b"blob one", b"blob two"];
        let packed: Vec<Vec<u8>> = entries_data.iter().map(|d| blob_entry(d)).collect();
        let p = pack_version(3, &packed);
        let entries = decode(&p).unwrap();
        assert_eq!(entries.len(), 2);
        for (e, data) in entries.iter().zip(entries_data.iter()) {
            assert_eq!(e.data(), *data);
            assert_eq!(e.object_id().len(), 32);
            assert_eq!(e.name().len(), 64);
            let want = object_id_with_kind(HashKind::Sha256, e.object_type(), e.data());
            assert_eq!(e.object_id(), want.as_slice());
            assert_eq!(e.name(), hex_id(&want));
        }
    }

    #[test]
    fn v3_ref_delta_handbuilt() {
        // v3 REF_DELTA base names are 32 bytes.
        let base = b"0123456789abcdef";
        let base_e = blob_entry(base);
        let base_id = object_id_with_kind(HashKind::Sha256, ObjectType::Blob, base);
        // Delta: src=16, dst=3, copy off=0 len=3.
        let delta = [16u8, 3, 0x90, 3];
        let mut de = obj_header(7, delta.len() as u64);
        de.extend_from_slice(&base_id);
        de.extend_from_slice(&zlib::encode::encode(&delta));
        let p = pack_version(3, &[base_e, de]);
        let entries = decode(&p).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].data(), b"012");
        assert_eq!(entries[1].object_id().len(), 32);
    }

    #[test]
    fn v3_bad_checksum_rejected() {
        let mut p = pack_version(3, &[blob_entry(b"x")]);
        let n = p.len();
        p[n - 1] ^= 0xFF;
        assert!(decode(&p).is_err());
    }

    #[test]
    fn v1_pack_still_rejected() {
        let mut p = Vec::new();
        p.extend_from_slice(b"PACK");
        p.extend_from_slice(&be32(1));
        p.extend_from_slice(&be32(0));
        p.extend_from_slice(&[0u8; 32]);
        assert!(matches!(decode(&p), Err(Error::Unsupported(_))));
    }

    /// Build a v1 idx: 256-entry fanout, sorted `u32 offset +
    /// 20-byte id` rows, then the 40-byte trailer (`pack_sum` +
    /// idx checksum over everything before it).
    fn build_idx_v1(rows: &[(u32, ObjectId)], pack_sum: &[u8; 20]) -> Vec<u8> {
        let mut sorted = rows.to_vec();
        sorted.sort_by_key(|r| r.1);
        let mut idx = Vec::new();
        let mut fanout = [0u32; 256];
        for r in &sorted {
            fanout[r.1[0] as usize] += 1;
        }
        let mut acc = 0u32;
        for f in &fanout {
            acc += f;
            idx.extend_from_slice(&acc.to_be_bytes());
        }
        for r in &sorted {
            idx.extend_from_slice(&be32(r.0));
            idx.extend_from_slice(&r.1);
        }
        idx.extend_from_slice(pack_sum);
        let sum = sha1(&idx);
        idx.extend_from_slice(&sum);
        idx
    }

    /// Build a v1 idx body (fanout + rows) with an explicit fanout
    /// table, then append a trailer with a valid idx checksum.
    fn idx_v1_with_fanout(fanout: &[u32; 256], rows: &[(u32, ObjectId)]) -> Vec<u8> {
        let mut idx = Vec::new();
        for f in fanout {
            idx.extend_from_slice(&be32(*f));
        }
        for r in rows {
            idx.extend_from_slice(&be32(r.0));
            idx.extend_from_slice(&r.1);
        }
        idx.extend_from_slice(&[0xCC; 20]);
        let sum = sha1(&idx);
        idx.extend_from_slice(&sum);
        idx
    }

    #[test]
    fn decode_idx_v1_handbuilt() {
        // v1: fanout + N x (u32 offset + 20B sha1) + 40B trailer,
        // name-sorted.
        let lo: ObjectId = [0x10; 20];
        let hi: ObjectId = [0x80; 20];
        let idx = build_idx_v1(&[(100, lo), (200, hi)], &[0xCC; 20]);
        // Trailer layout: pack checksum then idx checksum.
        let n = idx.len();
        assert_eq!(idx[n - 40..n - 20], [0xCC; 20]);
        assert_eq!(sha1(&idx[..n - 20]).as_slice(), &idx[n - 20..]);

        let entries = decode_idx_v1(&idx).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].offset, 100);
        assert_eq!(entries[0].crc32, 0);
        assert_eq!(entries[0].name, hex_id(&lo));
        assert_eq!(entries[1].offset, 200);
        assert_eq!(entries[1].name, hex_id(&hi));
    }

    #[test]
    fn decode_idx_v1_trailer_verified() {
        let idx = build_idx_v1(&[(100, [0x10; 20])], &[0xCC; 20]);
        assert_eq!(decode_idx_v1(&idx).unwrap().len(), 1);
        // Corrupted idx checksum is rejected.
        let mut bad = idx.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        assert!(decode_idx_v1(&bad).is_err());
        // Missing trailer (rows only, the historical strict-length
        // form) is rejected: the spec mandates the 40-byte trailer.
        let rows_only = &idx[..idx.len() - 40];
        assert!(decode_idx_v1(rows_only).is_err());
        // Trailing garbage makes the size check fail even with a
        // recomputed idx checksum.
        let mut garbage = idx[..idx.len() - 20].to_vec();
        garbage.extend_from_slice(b"junk");
        let sum = sha1(&garbage);
        garbage.extend_from_slice(&sum);
        assert!(decode_idx_v1(&garbage).is_err());
    }

    #[test]
    fn decode_idx_v1_rejects_bad_input() {
        // Truncated.
        assert!(decode_idx_v1(&[0u8; 100]).is_err());
        // Non-monotonic fanout (idx checksum valid so the structural
        // check is what fires).
        let mut fanout = [0u32; 256];
        fanout[0] = 2;
        assert!(decode_idx_v1(&idx_v1_with_fanout(&fanout, &[])).is_err());
        // Size mismatch (fanout says 1 but the entry table is empty).
        let mut fanout = [0u32; 256];
        fanout[255] = 1;
        assert!(decode_idx_v1(&idx_v1_with_fanout(&fanout, &[])).is_err());
        // Unsorted names.
        let mut fanout = [0u32; 256];
        fanout[255] = 2;
        let rows = [(0u32, [0xFF; 20]), (4u32, [0x00; 20])];
        assert!(decode_idx_v1(&idx_v1_with_fanout(&fanout, &rows)).is_err());
    }
}
