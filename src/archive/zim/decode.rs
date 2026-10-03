//! ZIM archive decoding.
//!
//! Parses the ZIM header, path pointer list, directory entries, and
//! cluster pointer list, extracts entry content from stored,
//! xz-compressed, or zstd-compressed clusters, and verifies the
//! trailing 16-byte MD5 archive checksum when present.
//!
//! Legacy zlib (id 2) and bzip2 (id 3) clusters are decoded when the
//! `zlib` / `bzip2` features are enabled, respectively; otherwise they
//! return [`Error::Unsupported`].

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::md5::md5;

const MAGIC: u32 = 0x044D_495A; // 72173914

const CLUSTER_NONE: u8 = 1;
const CLUSTER_ZLIB: u8 = 2;
const CLUSTER_BZIP2: u8 = 3;
const CLUSTER_XZ: u8 = 4;
const CLUSTER_ZSTD: u8 = 5;

const MIMETYPE_REDIRECT: u16 = 0xffff;
const MIMETYPE_LINKTARGET: u16 = 0xfffe;
const MIMETYPE_DELETED: u16 = 0xfffd;

/// A decoded ZIM entry.
#[derive(Debug, Clone)]
pub struct ZimEntry {
    /// Entry name in `N/path` form (namespace character + path).
    pub name: String,
    /// Uncompressed entry contents.
    pub data: Vec<u8>,
    /// MIME type string from the archive's MIME type list; empty for
    /// redirect entries (which carry no MIME index on the wire).
    pub mime_type: String,
    /// Entry title (the dirent title field, falling back to the bare
    /// path when the stored title is empty, per the ZIM spec).
    pub title: String,
    /// Index of this entry's dirent in archive order.
    index: u32,
}

impl crate::traits::ArchiveEntry for ZimEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

struct Dirent {
    /// Cluster number (content entries only).
    cluster: u32,
    /// Blob number inside the cluster.
    blob: u32,
    /// Redirect target entry index (`MIMETYPE_REDIRECT` only).
    redirect: Option<u32>,
    /// Skip this entry entirely (deprecated linktarget/deleted).
    skip: bool,
    /// MIME type list index (content entries only).
    mime_idx: u16,
    name: String,
    /// Path without the namespace prefix (title fallback).
    bare_path: String,
    /// Dirent title field (may be empty).
    title: String,
}

fn le_u16(data: &[u8], off: usize) -> Result<u16, Error> {
    let bytes = data
        .get(off..off + 2)
        .ok_or(Error::InvalidData("zim: truncated"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], off: usize) -> Result<u32, Error> {
    let bytes = data
        .get(off..off + 4)
        .ok_or(Error::InvalidData("zim: truncated"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn le_u64(data: &[u8], off: usize) -> Result<u64, Error> {
    let bytes = data
        .get(off..off + 8)
        .ok_or(Error::InvalidData("zim: truncated"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_asciiz(data: &[u8], off: usize) -> Result<(String, usize), Error> {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end >= data.len() {
        return Err(Error::InvalidData("zim: unterminated string"));
    }
    Ok((
        String::from_utf8_lossy(&data[off..end]).into_owned(),
        end + 1,
    ))
}

fn parse_dirent(input: &[u8], pos: usize) -> Result<Dirent, Error> {
    let mimetype = le_u16(input, pos)?;
    let namespace = *input
        .get(pos + 3)
        .ok_or(Error::InvalidData("zim: truncated dirent"))?;

    let empty = || Dirent {
        cluster: 0,
        blob: 0,
        redirect: None,
        skip: true,
        mime_idx: 0,
        name: String::new(),
        bare_path: String::new(),
        title: String::new(),
    };

    if mimetype == MIMETYPE_LINKTARGET || mimetype == MIMETYPE_DELETED {
        return Ok(empty());
    }

    if mimetype == MIMETYPE_REDIRECT {
        let redirect = le_u32(input, pos + 8)?;
        let (path, next) = read_asciiz(input, pos + 12)?;
        let (title, _) = read_asciiz(input, next).unwrap_or_default();
        return Ok(Dirent {
            redirect: Some(redirect),
            skip: false,
            name: format!("{}/{}", namespace as char, path),
            bare_path: path,
            title,
            ..empty()
        });
    }

    let cluster = le_u32(input, pos + 8)?;
    let blob = le_u32(input, pos + 12)?;
    let (path, next) = read_asciiz(input, pos + 16)?;
    let (title, _) = read_asciiz(input, next).unwrap_or_default();
    Ok(Dirent {
        cluster,
        blob,
        skip: false,
        mime_idx: mimetype,
        name: format!("{}/{}", namespace as char, path),
        bare_path: path,
        title,
        ..empty()
    })
}

fn read_offset(data: &[u8], pos: usize, offset_size: usize) -> Result<u64, Error> {
    if offset_size == 8 {
        le_u64(data, pos)
    } else {
        Ok(u64::from(le_u32(data, pos)?))
    }
}

/// Decompress a cluster (data region between `start` and `end`) and
/// extract blob number `blob`.
fn extract_blob(
    input: &[u8],
    start: usize,
    end: usize,
    blob: u32,
    major: u16,
) -> Result<Vec<u8>, Error> {
    let info = *input
        .get(start)
        .ok_or(Error::InvalidData("zim: truncated cluster"))?;
    let comp = info & 0x0f;
    let extended = info & 0x10 != 0;
    if extended && major != 6 {
        return Err(Error::InvalidData(
            "zim: extended cluster requires major version 6",
        ));
    }
    let raw = input
        .get(start + 1..end)
        .ok_or(Error::InvalidData("zim: truncated cluster"))?;
    let cluster_data: Vec<u8> = match comp {
        CLUSTER_NONE => raw.to_vec(),
        #[cfg(feature = "zlib")]
        CLUSTER_ZLIB => crate::compress::zlib::decode::decode(raw)
            .map_err(|_| Error::InvalidData("zim: zlib cluster decode failed"))?,
        #[cfg(not(feature = "zlib"))]
        CLUSTER_ZLIB => {
            return Err(Error::Unsupported(
                "zim: zlib cluster (enable zlib feature)",
            ));
        }
        #[cfg(feature = "bzip2")]
        CLUSTER_BZIP2 => crate::compress::bzip2::decode::decode(raw)
            .map_err(|_| Error::InvalidData("zim: bzip2 cluster decode failed"))?,
        #[cfg(not(feature = "bzip2"))]
        CLUSTER_BZIP2 => {
            return Err(Error::Unsupported(
                "zim: bzip2 cluster (enable bzip2 feature)",
            ));
        }
        CLUSTER_XZ => crate::compress::xz::decode::decode(raw)
            .map_err(|_| Error::InvalidData("zim: xz cluster decode failed"))?,
        CLUSTER_ZSTD => crate::compress::zstd::decode::decode(raw)
            .map_err(|_| Error::InvalidData("zim: zstd cluster decode failed"))?,
        _ => {
            return Err(Error::Unsupported("zim: unsupported cluster compression"));
        }
    };

    let offset_size = if extended { 8usize } else { 4usize };
    let first_off = read_offset(&cluster_data, 0, offset_size)? as usize;
    if !first_off.is_multiple_of(offset_size) {
        return Err(Error::InvalidData("zim: bad blob offset alignment"));
    }
    let n_offsets = first_off / offset_size;
    if n_offsets == 0 {
        return Err(Error::InvalidData("zim: empty cluster"));
    }
    let n_blobs = n_offsets - 1;
    let blob_idx = blob as usize;
    if blob_idx >= n_blobs {
        return Err(Error::InvalidData("zim: blob index out of range"));
    }
    let b0 = read_offset(&cluster_data, blob_idx * offset_size, offset_size)? as usize;
    let b1 = read_offset(&cluster_data, (blob_idx + 1) * offset_size, offset_size)? as usize;
    cluster_data
        .get(b0..b1)
        .map(|s| s.to_vec())
        .ok_or(Error::InvalidData("zim: blob offset out of range"))
}

/// Decode a split ZIM archive (`.zimaa`, `.zimab`, ...) into a list
/// of entries. Only the first part carries the header; the parts are
/// byte-concatenated and decoded as a single archive.
///
/// Returns [`Error::InvalidData`] when `parts` is empty or any part
/// after the first is empty.
pub fn decode_parts(parts: &[&[u8]]) -> Result<Vec<ZimEntry>, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidData("zim: empty part"));
    }
    if parts.len() == 1 {
        return decode(parts[0]);
    }
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut input = Vec::with_capacity(total);
    for p in parts {
        input.extend_from_slice(p);
    }
    decode(&input)
}

/// Decode a ZIM archive into a list of entries.
///
/// Redirect entries are resolved to their target's content.
/// Entry names are exposed as `N/path` (namespace prefix).
///
/// When the archive carries a trailing 16-byte MD5 checksum
/// (`checksumPos` at `len - 16`), it is verified over all
/// preceding bytes; archives without the digest are tolerated.
pub fn decode(input: &[u8]) -> Result<Vec<ZimEntry>, Error> {
    if input.len() < 80 {
        return Err(Error::InvalidData("zim: input too short"));
    }
    if le_u32(input, 0)? != MAGIC {
        return Err(Error::InvalidData("zim: bad magic"));
    }
    let major = le_u16(input, 4)?;
    let _minor = le_u16(input, 6)?;
    if major != 5 && major != 6 {
        return Err(Error::Unsupported("zim: unsupported major version"));
    }

    let entry_count = le_u32(input, 24)? as usize;
    let cluster_count = le_u32(input, 28)? as usize;
    let path_ptr_pos = le_u64(input, 32)? as usize;
    let _title_ptr_pos = le_u64(input, 40)? as usize;
    let cluster_ptr_pos = le_u64(input, 48)? as usize;
    let mime_list_pos = le_u64(input, 56)? as usize;
    let checksum_pos = le_u64(input, 72)? as usize;

    // MIME type list: ASCIIZ sequence ending with an empty string.
    let mut mime_list = Vec::new();
    {
        let mut mpos = mime_list_pos;
        loop {
            let (m, next) = read_asciiz(input, mpos)?;
            if m.is_empty() {
                break;
            }
            mime_list.push(m);
            mpos = next;
        }
    }
    let mime_type_of =
        |idx: u16| -> String { mime_list.get(idx as usize).cloned().unwrap_or_default() };

    let cluster_ptr_end = cluster_ptr_pos
        .checked_add(cluster_count * 8)
        .ok_or(Error::InvalidData("zim: cluster pointer overflow"))?;
    if cluster_ptr_end > input.len() {
        return Err(Error::InvalidData("zim: truncated cluster pointer list"));
    }
    let path_ptr_end = path_ptr_pos
        .checked_add(entry_count * 8)
        .ok_or(Error::InvalidData("zim: path pointer overflow"))?;
    if path_ptr_end > input.len() {
        return Err(Error::InvalidData("zim: truncated path pointer list"));
    }

    // Cluster offsets; end of last cluster is checksumPos (16 bytes before
    // archive end) or the input end.
    let mut cluster_offsets = Vec::with_capacity(cluster_count);
    for i in 0..cluster_count {
        cluster_offsets.push(le_u64(input, cluster_ptr_pos + i * 8)? as usize);
    }

    let cluster_end = |i: usize| -> usize {
        if i + 1 < cluster_offsets.len() {
            cluster_offsets[i + 1]
        } else if checksum_pos != 0 && checksum_pos <= input.len() {
            checksum_pos
        } else {
            input.len()
        }
    };

    let mut dirents = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let pos = le_u64(input, path_ptr_pos + i * 8)? as usize;
        dirents.push(parse_dirent(input, pos)?);
    }

    let mut entries = Vec::new();
    for (i, d) in dirents.iter().enumerate() {
        if d.skip {
            continue;
        }
        let index = i as u32;
        let resolved = if let Some(target) = d.redirect {
            let idx = target as usize;
            dirents
                .get(idx)
                .ok_or(Error::InvalidData("zim: redirect target out of range"))?
        } else {
            d
        };
        if resolved.skip || resolved.redirect.is_some() {
            continue; // redirect to deprecated entry or chained redirect: skip
        }
        let ci = resolved.cluster as usize;
        if ci >= cluster_offsets.len() {
            return Err(Error::InvalidData("zim: cluster index out of range"));
        }
        let data = extract_blob(
            input,
            cluster_offsets[ci],
            cluster_end(ci),
            resolved.blob,
            major,
        )?;
        let _ = i;
        entries.push(ZimEntry {
            name: d.name.clone(),
            data,
            index,
            mime_type: if d.redirect.is_some() {
                String::new()
            } else {
                mime_type_of(d.mime_idx)
            },
            title: if d.title.is_empty() {
                d.bare_path.clone()
            } else {
                d.title.clone()
            },
        });
    }

    // Archive checksum: checksumPos points to the trailing 16-byte MD5
    // over all preceding bytes. Verify it when present; archives without
    // the trailing digest (checksumPos not at end - 16) are tolerated.
    if checksum_pos != 0
        && checksum_pos + 16 == input.len()
        && md5(&input[..checksum_pos]) != input[checksum_pos..]
    {
        return Err(Error::InvalidData("zim: archive checksum mismatch"));
    }
    Ok(entries)
}

/// Dirent name (`N/path` form) of the v0 title index listing entry.
const TITLE_ORDERED_LISTING: &str = "X/listing/titleordered/v0";

/// Build a dirent-index -> title-rank map from the
/// `X/listing/titleordered/v0` listing entry. Returns `None` when the
/// entry is absent or its payload is not a u32 index list.
fn title_order_rank(entries: &[ZimEntry]) -> Option<alloc::collections::BTreeMap<u32, u32>> {
    let listing = entries.iter().find(|e| e.name == TITLE_ORDERED_LISTING)?;
    if listing.data.is_empty() || !listing.data.len().is_multiple_of(4) {
        return None;
    }
    let mut rank = alloc::collections::BTreeMap::new();
    for (i, idx) in listing.data.as_chunks::<4>().0.iter().enumerate() {
        rank.insert(u32::from_le_bytes(*idx), i as u32);
    }
    Some(rank)
}

/// Decode a ZIM archive into a list of entries ordered by title.
///
/// The `X/listing/titleordered/v0` listing entry (a u32 dirent-index
/// list in title order) is preferred; the header's `titlePtrPos`
/// title pointer list is obsolete per the ZIM spec and only used as a
/// fallback. When both are absent or malformed, entries keep the
/// default path order returned by [`decode`].
pub fn decode_title_order(input: &[u8]) -> Result<Vec<ZimEntry>, Error> {
    let mut entries = decode(input)?;
    if input.len() < 80 {
        return Ok(entries);
    }
    if let Some(rank) = title_order_rank(&entries) {
        entries.sort_by_key(|e| rank.get(&e.index).copied().unwrap_or(u32::MAX));
        return Ok(entries);
    }
    let entry_count = le_u32(input, 24)? as usize;
    let title_ptr_pos = le_u64(input, 40)? as usize;
    let end = title_ptr_pos.saturating_add(entry_count * 4);
    if title_ptr_pos == 0 || end > input.len() {
        return Ok(entries);
    }
    // rank[dirent index] = position in the title-sorted order.
    let mut rank = alloc::collections::BTreeMap::new();
    for i in 0..entry_count {
        let idx = le_u32(input, title_ptr_pos + i * 4)?;
        rank.insert(idx, i as u32);
    }
    entries.sort_by_key(|e| rank.get(&e.index).copied().unwrap_or(u32::MAX));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Minimal ZIM builder: single mime list, dirents, one stored/xz cluster.
    struct ZimBuilder {
        major: u16,
        entries: Vec<DirentSpec>,
        /// (compression info byte, raw cluster payload)
        clusters: Vec<(u8, Vec<u8>)>,
        /// Extra MIME list entries after the default "text/html".
        extra_mimes: Vec<&'static str>,
        /// dirent index -> stored title (empty = fallback to path).
        titles: alloc::collections::BTreeMap<usize, &'static str>,
        /// dirent index -> MIME list index (default 0).
        mime_idx: alloc::collections::BTreeMap<usize, u16>,
        /// title pointer list override (u32 dirent indices).
        title_ptrs: Option<Vec<u32>>,
    }

    enum DirentSpec {
        Content {
            cluster: u32,
            blob: u32,
            ns: u8,
            path: &'static str,
        },
        Redirect {
            index: u32,
            ns: u8,
            path: &'static str,
        },
        /// Deprecated entry (`MIMETYPE_LINKTARGET` / `MIMETYPE_DELETED`).
        Deprecated {
            mimetype: u16,
            ns: u8,
            path: &'static str,
        },
    }

    impl ZimBuilder {
        fn new() -> Self {
            Self {
                major: 5,
                entries: Vec::new(),
                clusters: Vec::new(),
                extra_mimes: Vec::new(),
                titles: alloc::collections::BTreeMap::new(),
                mime_idx: alloc::collections::BTreeMap::new(),
                title_ptrs: None,
            }
        }

        fn build(&self) -> Vec<u8> {
            let mut mime = Vec::new();
            mime.extend_from_slice(b"text/html\0");
            for m in &self.extra_mimes {
                mime.extend_from_slice(m.as_bytes());
                mime.push(0);
            }
            mime.push(0); // terminator

            let mut dirent_buf = Vec::new();
            let mut dirent_offsets = Vec::new();
            for (ei, e) in self.entries.iter().enumerate() {
                dirent_offsets.push(dirent_buf.len());
                let title = self.titles.get(&ei).copied().unwrap_or("");
                match e {
                    DirentSpec::Content {
                        cluster,
                        blob,
                        ns,
                        path,
                    } => {
                        let mi = self.mime_idx.get(&ei).copied().unwrap_or(0);
                        dirent_buf.extend_from_slice(&mi.to_le_bytes());
                        dirent_buf.push(0); // param len
                        dirent_buf.push(*ns);
                        dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
                        dirent_buf.extend_from_slice(&cluster.to_le_bytes());
                        dirent_buf.extend_from_slice(&blob.to_le_bytes());
                        dirent_buf.extend_from_slice(path.as_bytes());
                        dirent_buf.push(0);
                        dirent_buf.extend_from_slice(title.as_bytes());
                        dirent_buf.push(0);
                    }
                    DirentSpec::Redirect { index, ns, path } => {
                        dirent_buf.extend_from_slice(&0xffffu16.to_le_bytes());
                        dirent_buf.push(0);
                        dirent_buf.push(*ns);
                        dirent_buf.extend_from_slice(&0u32.to_le_bytes());
                        dirent_buf.extend_from_slice(&index.to_le_bytes());
                        dirent_buf.extend_from_slice(path.as_bytes());
                        dirent_buf.push(0);
                        dirent_buf.extend_from_slice(title.as_bytes());
                        dirent_buf.push(0);
                    }
                    DirentSpec::Deprecated { mimetype, ns, path } => {
                        dirent_buf.extend_from_slice(&mimetype.to_le_bytes());
                        dirent_buf.push(0); // param len
                        dirent_buf.push(*ns);
                        dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
                        dirent_buf.extend_from_slice(path.as_bytes());
                        dirent_buf.push(0);
                        dirent_buf.push(0); // empty title
                    }
                }
            }
            let dirent_base = 80 + mime.len();

            let mut path_ptrs = Vec::new();
            for o in &dirent_offsets {
                path_ptrs.extend_from_slice(&((dirent_base + o) as u64).to_le_bytes());
            }

            let mut cluster_ptrs = Vec::new();
            // cluster data laid out after dirents + path ptrs + title ptrs + cluster ptrs
            let path_ptr_pos = dirent_base + dirent_buf.len();
            let title_ptr_pos = path_ptr_pos + path_ptrs.len();
            let cluster_ptr_pos = title_ptr_pos + self.entries.len() * 4;
            let mut cluster_area = Vec::new();
            for (info, payload) in &self.clusters {
                cluster_ptrs.extend_from_slice(
                    &((cluster_ptr_pos + self.clusters.len() * 8 + cluster_area.len()) as u64)
                        .to_le_bytes(),
                );
                cluster_area.push(*info);
                cluster_area.extend_from_slice(payload);
            }
            let checksum_pos =
                (cluster_ptr_pos + self.clusters.len() * 8 + cluster_area.len()) as u64;

            let mut out = Vec::new();
            out.extend_from_slice(&MAGIC.to_le_bytes());
            out.extend_from_slice(&self.major.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // minor
            out.extend_from_slice(&[0u8; 16]); // uuid
            out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.clusters.len() as u32).to_le_bytes());
            out.extend_from_slice(&(path_ptr_pos as u64).to_le_bytes());
            out.extend_from_slice(&(title_ptr_pos as u64).to_le_bytes());
            out.extend_from_slice(&(cluster_ptr_pos as u64).to_le_bytes());
            out.extend_from_slice(&80u64.to_le_bytes()); // mimeListPos
            out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // mainPage
            out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // layoutPage
            out.extend_from_slice(&checksum_pos.to_le_bytes());
            out.extend_from_slice(&mime);
            out.extend_from_slice(&dirent_buf);
            out.extend_from_slice(&path_ptrs);
            match &self.title_ptrs {
                Some(ptrs) => {
                    for &i in ptrs {
                        out.extend_from_slice(&i.to_le_bytes());
                    }
                }
                None => {
                    out.extend_from_slice(&vec![0u8; self.entries.len() * 4]); // unused
                }
            }
            out.extend_from_slice(&cluster_ptrs);
            out.extend_from_slice(&cluster_area);
            out
        }
    }

    /// Stored cluster containing one blob .
    fn stored_cluster(blobs: &[&[u8]]) -> Vec<u8> {
        let n = blobs.len();
        let mut out = Vec::new();
        let mut off = (n + 1) * 4;
        for b in blobs {
            out.extend_from_slice(&(off as u32).to_le_bytes());
            off += b.len();
        }
        out.extend_from_slice(&(off as u32).to_le_bytes());
        for b in blobs {
            out.extend_from_slice(b);
        }
        out
    }

    /// Extended (8-byte offset) stored cluster payload.
    fn stored_cluster_extended(blobs: &[&[u8]]) -> Vec<u8> {
        let n = blobs.len();
        let mut out = Vec::new();
        let mut off = (n + 1) * 8;
        for b in blobs {
            out.extend_from_slice(&(off as u64).to_le_bytes());
            off += b.len();
        }
        out.extend_from_slice(&(off as u64).to_le_bytes());
        for b in blobs {
            out.extend_from_slice(b);
        }
        out
    }

    #[test]
    fn parses_basic_zim() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "index.html",
        });
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"hello zim"])));
        let data = b.build();
        let entries = decode(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "C/index.html");
        assert_eq!(entries[0].data, b"hello zim");
    }

    #[test]
    fn parses_xz_cluster() {
        let blob_data = b"xz compressed blob";
        let cluster_plain = stored_cluster(&[blob_data]);
        let compressed = crate::compress::xz::encode::encode(&cluster_plain);
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "a",
        });
        b.clusters.push((CLUSTER_XZ, compressed));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data, blob_data);
    }

    #[test]
    fn parses_multi_blob_cluster() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 1,
            ns: b'C',
            path: "second",
        });
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"one", b"two", b"three"])));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data, b"two");
    }

    #[test]
    fn resolves_redirect() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "target",
        });
        b.entries.push(DirentSpec::Redirect {
            index: 0,
            ns: b'C',
            path: "alias",
        });
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"content"])));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].name, "C/alias");
        assert_eq!(entries[1].data, b"content");
        assert_eq!(entries[1].mime_type, "");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((CLUSTER_NONE, stored_cluster(&[b"d"])));
        let mut data = b.build();
        data[0] = 0xFF;
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut b = ZimBuilder::new();
        b.major = 4;
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((CLUSTER_NONE, stored_cluster(&[b"d"])));
        assert!(matches!(decode(&b.build()), Err(Error::Unsupported(_))));
    }

    /// Legacy bzip2 id stays Unsupported without the bzip2 feature.
    #[cfg(not(feature = "bzip2"))]
    #[test]
    fn rejects_bzip_cluster() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((3, stored_cluster(&[b"d"]))); // legacy bzip2 id
        assert!(matches!(decode(&b.build()), Err(Error::Unsupported(_))));
    }

    /// With the bzip2 feature, id 3 decodes; corrupt data is InvalidData.
    #[cfg(feature = "bzip2")]
    #[test]
    fn rejects_bzip_cluster() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters
            .push((CLUSTER_BZIP2, vec![0xde, 0xad, 0xbe, 0xef]));
        assert!(matches!(decode(&b.build()), Err(Error::InvalidData(_))));
    }

    /// Legacy zlib id stays Unsupported without the zlib feature.
    #[cfg(not(feature = "zlib"))]
    #[test]
    fn rejects_zlib_cluster() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((2, stored_cluster(&[b"d"]))); // legacy zlib id
        assert!(matches!(decode(&b.build()), Err(Error::Unsupported(_))));
    }

    /// With the zlib feature, id 2 decodes; corrupt data is InvalidData.
    #[cfg(feature = "zlib")]
    #[test]
    fn rejects_zlib_cluster() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters
            .push((CLUSTER_ZLIB, vec![0xde, 0xad, 0xbe, 0xef]));
        assert!(matches!(decode(&b.build()), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_unknown_cluster_compression() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((15, stored_cluster(&[b"d"]))); // unassigned comp id
        assert!(matches!(decode(&b.build()), Err(Error::Unsupported(_))));
    }

    #[cfg(feature = "zlib")]
    #[test]
    fn parses_zlib_cluster() {
        let blob_data = b"zlib compressed blob";
        let cluster_plain = stored_cluster(&[blob_data]);
        let compressed = crate::compress::zlib::encode::encode(&cluster_plain);
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "a",
        });
        b.clusters.push((CLUSTER_ZLIB, compressed));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data, blob_data);
    }

    #[cfg(feature = "bzip2")]
    #[test]
    fn parses_bzip2_cluster() {
        let blob_data = b"bzip2 compressed blob";
        let cluster_plain = stored_cluster(&[blob_data]);
        let compressed = crate::compress::bzip2::encode::encode(&cluster_plain);
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "a",
        });
        b.clusters.push((CLUSTER_BZIP2, compressed));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data, blob_data);
    }

    #[test]
    fn skips_deprecated_linktarget_and_deleted_entries() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "first",
        });
        b.entries.push(DirentSpec::Deprecated {
            mimetype: MIMETYPE_LINKTARGET,
            ns: b'C',
            path: "linktarget",
        });
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 1,
            ns: b'C',
            path: "second",
        });
        b.entries.push(DirentSpec::Deprecated {
            mimetype: MIMETYPE_DELETED,
            ns: b'C',
            path: "deleted",
        });
        // Redirect pointing at a deprecated entry is skipped as well.
        b.entries.push(DirentSpec::Redirect {
            index: 3,
            ns: b'C',
            path: "alias-to-deleted",
        });
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"one", b"two"])));
        let entries = decode(&b.build()).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["C/first", "C/second"]);
        assert_eq!(entries[0].data, b"one");
        assert_eq!(entries[1].data, b"two");
    }

    #[test]
    fn rejects_extended_cluster_below_major6() {
        let mut b = ZimBuilder::new();
        b.major = 5;
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters
            .push((0x10 | CLUSTER_NONE, stored_cluster_extended(&[b"d"])));
        match decode(&b.build()) {
            Err(Error::InvalidData(msg)) => {
                assert_eq!(msg, "zim: extended cluster requires major version 6")
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn parses_extended_cluster_major6() {
        let mut b = ZimBuilder::new();
        b.major = 6;
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "a",
        });
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 1,
            ns: b'C',
            path: "b",
        });
        b.clusters.push((
            0x10 | CLUSTER_NONE,
            stored_cluster_extended(&[b"extended one", b"extended two"]),
        ));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "C/a");
        assert_eq!(entries[0].data, b"extended one");
        assert_eq!(entries[1].name, "C/b");
        assert_eq!(entries[1].data, b"extended two");
    }

    #[test]
    fn rejects_truncated() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((CLUSTER_NONE, stored_cluster(&[b"data"])));
        let data = b.build();
        assert!(decode(&data[..40]).is_err());
    }

    #[test]
    fn rejects_blob_out_of_range() {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 5,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((CLUSTER_NONE, stored_cluster(&[b"only"])));
        assert!(decode(&b.build()).is_err());
    }

    /// Build an archive carrying a real trailing MD5 checksum.
    fn build_with_md5() -> Vec<u8> {
        let mut b = ZimBuilder::new();
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "x",
        });
        b.clusters.push((CLUSTER_NONE, stored_cluster(&[b"data"])));
        let mut data = b.build();
        data.extend_from_slice(&md5(&data));
        data
    }

    #[test]
    fn verifies_archive_md5() {
        let data = build_with_md5();
        let entries = decode(&data).unwrap();
        assert_eq!(entries[0].data, b"data");
    }

    #[test]
    fn rejects_bad_archive_md5() {
        let mut data = build_with_md5();
        let last = data.len() - 1;
        data[last] ^= 0x01;
        assert!(decode(&data).is_err());
    }

    #[test]
    fn rejects_tampered_content_via_md5() {
        // Corrupt a payload byte: structure still parses, checksum catches it.
        let mut data = build_with_md5();
        let n = data.len();
        data[n - 18] ^= 0xff; // inside the cluster, before the digest
        assert!(decode(&data).is_err());
    }
    #[test]
    fn split_parts_roundtrip() {
        let mut enc = crate::archive::zim::encode::ZimEncoder::new();
        enc.add_file("index.html", b"<html>split</html>");
        enc.add_file("a.txt", b"split me");
        let data = enc.finish().unwrap();
        let whole = decode(&data).unwrap();
        // Split at awkward boundaries (inside header / mid-entry).
        let a = data.len() / 3;
        let bnd = 2 * data.len() / 3;
        let parts = [&data[..a], &data[a..bnd], &data[bnd..]];
        let entries = decode_parts(&parts).unwrap();
        assert_eq!(entries.len(), whole.len());
        for (e, w) in entries.iter().zip(whole.iter()) {
            assert_eq!(e.name(), w.name());
            assert_eq!(e.data(), w.data());
        }
    }

    #[test]
    fn split_parts_rejects_empty() {
        let mut enc = crate::archive::zim::encode::ZimEncoder::new();
        enc.add_file("x", b"1");
        let data = enc.finish().unwrap();
        assert!(matches!(decode_parts(&[]), Err(Error::InvalidData(_))));
        assert!(matches!(
            decode_parts(&[&data[..10], &[]]),
            Err(Error::InvalidData(_))
        ));
        // Single part behaves like decode().
        assert_eq!(
            decode_parts(&[&data]).unwrap().len(),
            decode(&data).unwrap().len()
        );
    }
    #[test]
    fn exposes_mime_type_and_title() {
        let mut b = ZimBuilder::new();
        b.extra_mimes.push("text/plain");
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 0,
            ns: b'C',
            path: "index.html",
        });
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 1,
            ns: b'C',
            path: "note.txt",
        });
        b.mime_idx.insert(1, 1);
        b.titles.insert(0, "The Index");
        b.clusters.push((1, stored_cluster(&[b"<html>", b"note"])));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].mime_type, "text/html");
        assert_eq!(entries[0].title, "The Index");
        assert_eq!(entries[1].mime_type, "text/plain");
        // Empty title falls back to the bare path.
        assert_eq!(entries[1].title, "note.txt");
    }

    #[test]
    fn title_order_uses_title_pointer_list() {
        let mut b = ZimBuilder::new();
        for (i, p) in ["aaa", "zzz", "mmm"].iter().enumerate() {
            b.entries.push(DirentSpec::Content {
                cluster: 0,
                blob: i as u32,
                ns: b'C',
                path: p,
            });
        }
        // Title order: zzz's title "AA" sorts first, mmm "BB" second.
        b.titles.insert(1, "AA");
        b.titles.insert(2, "BB");
        b.title_ptrs = Some(vec![1, 2, 0]);
        b.clusters.push((1, stored_cluster(&[b"a", b"z", b"m"])));
        let data = b.build();
        let by_title = decode_title_order(&data).unwrap();
        assert_eq!(
            by_title.iter().map(|e| e.name()).collect::<Vec<_>>(),
            vec!["C/zzz", "C/mmm", "C/aaa"]
        );
        // Path order is unchanged for decode().
        let by_path = decode(&data).unwrap();
        assert_eq!(
            by_path.iter().map(|e| e.name()).collect::<Vec<_>>(),
            vec!["C/aaa", "C/zzz", "C/mmm"]
        );
        // Absent title list keeps path order.
        b.title_ptrs = None;
        let data2 = b.build();
        let e = decode_title_order(&data2).unwrap();
        assert_eq!(e[0].name(), "C/aaa");
    }

    #[test]
    fn title_order_falls_back_on_invalid_list() {
        let mut b = ZimBuilder::new();
        for (i, p) in ["bbb", "aaa", "ccc"].iter().enumerate() {
            b.entries.push(DirentSpec::Content {
                cluster: 0,
                blob: i as u32,
                ns: b'C',
                path: p,
            });
        }
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"b", b"a", b"c"])));
        b.title_ptrs = Some(vec![2, 0, 1]);

        let built = b.build();
        let path_order: Vec<_> = decode(&built)
            .unwrap()
            .into_iter()
            .map(|e| e.name().to_string())
            .collect();

        // titlePtrPos = 0 (absent): path order.
        let mut absent = b.build();
        absent[40..48].copy_from_slice(&0u64.to_le_bytes());
        let e = decode_title_order(&absent).unwrap();
        assert_eq!(e.iter().map(|e| e.name()).collect::<Vec<_>>(), path_order);

        // titlePtrPos out of range: path order.
        let mut oob = b.build();
        let oob_pos = (oob.len() + 8) as u64;
        oob[40..48].copy_from_slice(&oob_pos.to_le_bytes());
        let e = decode_title_order(&oob).unwrap();
        assert_eq!(e.iter().map(|e| e.name()).collect::<Vec<_>>(), path_order);
    }

    /// Pack a title-sorted dirent index list as the
    /// `X/listing/titleordered/v0` blob payload (u32 LE).
    fn title_listing_blob(order: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        for &i in order {
            out.extend_from_slice(&i.to_le_bytes());
        }
        out
    }

    /// Builder with three `C/` content dirents plus an
    /// `X/listing/titleordered/v0` dirent whose blob is `listing`.
    /// Dirent indices: 0=aaa, 1=bbb, 2=ccc, 3=listing.
    fn builder_with_listing(listing: &[u8]) -> ZimBuilder {
        let mut b = ZimBuilder::new();
        for (i, p) in ["aaa", "bbb", "ccc"].iter().enumerate() {
            b.entries.push(DirentSpec::Content {
                cluster: 0,
                blob: i as u32,
                ns: b'C',
                path: p,
            });
        }
        b.entries.push(DirentSpec::Content {
            cluster: 0,
            blob: 3,
            ns: b'X',
            path: "listing/titleordered/v0",
        });
        b.clusters
            .push((CLUSTER_NONE, stored_cluster(&[b"a", b"b", b"c", listing])));
        b
    }

    #[test]
    fn title_order_uses_x_listing_v0() {
        // Listing says title order is ccc, aaa, bbb (dirents 2, 0, 1).
        let b = builder_with_listing(&title_listing_blob(&[2, 0, 1]));
        let data = b.build();
        let by_title = decode_title_order(&data).unwrap();
        assert_eq!(
            by_title.iter().map(|e| e.name()).collect::<Vec<_>>(),
            vec!["C/ccc", "C/aaa", "C/bbb", "X/listing/titleordered/v0"]
        );
        // decode() is unaffected and keeps path order.
        let by_path = decode(&data).unwrap();
        assert_eq!(by_path[0].name(), "C/aaa");
    }

    #[test]
    fn title_order_prefers_listing_over_titleptrpos() {
        let mut b = builder_with_listing(&title_listing_blob(&[2, 0, 1]));
        // Contradicting titlePtrPos order: the v0 listing wins.
        b.title_ptrs = Some(vec![0, 1, 2, 3]);
        let data = b.build();
        let by_title = decode_title_order(&data).unwrap();
        assert_eq!(
            by_title.iter().map(|e| e.name()).collect::<Vec<_>>(),
            vec!["C/ccc", "C/aaa", "C/bbb", "X/listing/titleordered/v0"]
        );
    }

    #[test]
    fn title_order_falls_back_when_listing_malformed() {
        // Payload is not a multiple of 4: not a valid u32 index list,
        // so the titlePtrPos list applies instead.
        let mut b = builder_with_listing(&[0x02, 0x00, 0x00]);
        b.title_ptrs = Some(vec![1, 0, 2, 3]);
        let data = b.build();
        let by_title = decode_title_order(&data).unwrap();
        assert_eq!(
            by_title.iter().map(|e| e.name()).collect::<Vec<_>>(),
            vec!["C/bbb", "C/aaa", "C/ccc", "X/listing/titleordered/v0"]
        );
    }
}
