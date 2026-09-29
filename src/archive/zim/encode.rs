//! ZIM archive (`.zim`) encode — format v5/v6, single cluster.
//!
//! [`ZimEncoder`] writes a minimal valid ZIM file: one cluster
//! holding every queued file as a blob, path/title pointer lists,
//! a MIME type list, and the trailing MD5 archive checksum
//! (openZIM wiki "ZIM file format": Header, Directory Entries,
//! Clusters). [`ZimEncoder::with_version`] selects major
//! version 6, which permits extended (8-byte offset) clusters
//! emitted via [`ZimEncoder::with_extended_cluster`].
//! Redirect dirents (`0xffff`, [`ZimEncoder::add_redirect`])
//! and deprecated linktarget/deleted dirents
//! (`0xfffe`/`0xfffd`, [`ZimEncoder::add_deprecated`])
//! can also be emitted, mainly to produce fixtures exercising
//! reader-side skip/resolution paths. Split archives and
//! fulltext indexes are not emitted.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::md5;

const MAGIC: u32 = 0x044D_495A;
const CLUSTER_NONE: u8 = 1;
const CLUSTER_XZ: u8 = 4;
const CLUSTER_ZSTD: u8 = 5;
const CLUSTER_EXTENDED: u8 = 0x10;

const MIMETYPE_REDIRECT: u16 = 0xffff;
const MIMETYPE_LINKTARGET: u16 = 0xfffe;
const MIMETYPE_DELETED: u16 = 0xfffd;

/// Cluster compression applied to the single blob cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZimCompression {
    /// Stored (`1`).
    None,
    /// xz / LZMA2 (`4`).
    Xz,
    /// zstd (`5`).
    Zstd,
}

/// ZIM format major version emitted by [`ZimEncoder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZimVersion {
    /// Version 5 (default); extended clusters are not permitted.
    V5,
    /// Version 6; permits extended (8-byte offset) clusters.
    V6,
}

impl ZimVersion {
    fn major(self) -> u16 {
        match self {
            ZimVersion::V5 => 5,
            ZimVersion::V6 => 6,
        }
    }
}

/// Deprecated dirent kind emitted by [`ZimEncoder::add_deprecated`].
///
/// Readers ignore these dirents entirely; emitting them is only
/// useful to produce legacy-format fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZimDeprecated {
    /// Linktarget entry (`0xfffe`).
    Linktarget,
    /// Deleted entry (`0xfffd`).
    Deleted,
}

/// Kind of a queued directory entry.
enum EntryKind {
    /// Content blob stored in cluster 0.
    Content(Vec<u8>),
    /// Redirect target `(namespace, path)` in split
    /// `N/path` form, resolved to a dirent index at
    /// `finish`.
    Redirect(u8, String),
    /// Deprecated mimetype marker (`0xfffe` / `0xfffd`).
    Deprecated(u16),
}

/// One queued directory entry.
struct Queued {
    ns: u8,
    path: String,
    kind: EntryKind,
}

/// Encoder for minimal v5/v6 ZIM archives.
///
/// Every [`add_file`](Self::add_file) name is written as a
/// `N/path` entry; a leading `X/` prefix supplies the
/// namespace byte, otherwise namespace `C` is used. All
/// blobs share one cluster in path-sorted dirent order.
pub struct ZimEncoder {
    compression: ZimCompression,
    version: ZimVersion,
    extended: bool,
    mime_type: String,
    entries: Vec<Queued>,
}

impl ZimEncoder {
    /// New encoder producing a stored cluster.
    pub fn new() -> Self {
        Self::with_compression(ZimCompression::None)
    }

    /// New encoder with the given cluster compression.
    pub fn with_compression(compression: ZimCompression) -> Self {
        Self {
            compression,
            version: ZimVersion::V5,
            extended: false,
            mime_type: String::from("application/octet-stream"),
            entries: Vec::new(),
        }
    }

    /// Select the emitted format major version
    /// (default [`ZimVersion::V5`]).
    pub fn with_version(mut self, version: ZimVersion) -> Self {
        self.version = version;
        self
    }

    /// Emit an extended cluster: 8-byte blob offsets and the
    /// cluster info extended bit (`0x10`). Only valid
    /// together with [`ZimVersion::V6`];
    /// [`finish`](Self::finish) rejects the combination
    /// otherwise.
    pub fn with_extended_cluster(mut self) -> Self {
        self.extended = true;
        self
    }

    /// Override the MIME type recorded for every entry
    /// (default `application/octet-stream`).
    pub fn with_mime_type(mut self, mime: &str) -> Self {
        self.mime_type = String::from(mime);
        self
    }

    /// Queue one file.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        let (ns, path) = split_name(name);
        self.entries.push(Queued {
            ns,
            path: String::from(path),
            kind: EntryKind::Content(data.to_vec()),
        });
    }

    /// Queue a redirect entry (`0xffff`): `name`
    /// resolves to the content of the `N/path` entry
    /// `target`, which must be a content entry queued with
    /// [`add_file`](Self::add_file). The target dirent index
    /// is resolved at [`finish`](Self::finish); a missing or
    /// non-content target is rejected there.
    pub fn add_redirect(&mut self, name: &str, target: &str) {
        let (ns, path) = split_name(name);
        let (tns, tpath) = split_name(target);
        self.entries.push(Queued {
            ns,
            path: String::from(path),
            kind: EntryKind::Redirect(tns, String::from(tpath)),
        });
    }

    /// Queue a deprecated dirent (`0xfffe` linktarget or
    /// `0xfffd` deleted). Readers skip these entries
    /// entirely; this exists mainly to produce legacy-format
    /// fixtures.
    pub fn add_deprecated(&mut self, name: &str, kind: ZimDeprecated) {
        let (ns, path) = split_name(name);
        let mimetype = match kind {
            ZimDeprecated::Linktarget => MIMETYPE_LINKTARGET,
            ZimDeprecated::Deleted => MIMETYPE_DELETED,
        };
        self.entries.push(Queued {
            ns,
            path: String::from(path),
            kind: EntryKind::Deprecated(mimetype),
        });
    }

    /// Serialize the archive.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] if a queued name is empty, has
    /// a NUL byte, a redirect target does not name a queued
    /// content entry, an extended cluster was requested below
    /// major version 6, or the archive exceeds u32 field limits.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        if self.extended && self.version != ZimVersion::V6 {
            return Err(Error::InvalidData(
                "zim: extended cluster requires major version 6",
            ));
        }
        for e in &self.entries {
            if e.path.is_empty() || e.path.as_bytes().contains(&0) {
                return Err(Error::InvalidData("zim: invalid entry path"));
            }
        }
        if self.mime_type.as_bytes().contains(&0) {
            return Err(Error::InvalidData("zim: invalid mime type"));
        }
        // Dirent order is path order so the path pointer list is
        // sorted by construction.
        self.entries
            .sort_by(|a, b| (a.ns, &a.path).cmp(&(b.ns, &b.path)));

        // MIME type list (ASCIIZ sequence, empty-string terminator).
        let mut mime = Vec::new();
        mime.extend_from_slice(self.mime_type.as_bytes());
        mime.push(0);
        mime.push(0);

        // Content entries keyed by `(namespace, path)` map to
        // their dirent index for redirect target resolution.
        let mut dirent_index: BTreeMap<(u8, &str), u32> = BTreeMap::new();
        for (i, e) in self.entries.iter().enumerate() {
            if matches!(e.kind, EntryKind::Content(_)) {
                dirent_index.insert((e.ns, e.path.as_str()), i as u32);
            }
        }

        // Directory entries: content entries are blob i of
        // cluster 0 (i counts content entries only).
        let mut dirent_buf = Vec::new();
        let mut dirent_offsets = Vec::with_capacity(self.entries.len());
        let mut blob = 0u32;
        for e in &self.entries {
            dirent_offsets.push(dirent_buf.len());
            match &e.kind {
                EntryKind::Content(_) => {
                    dirent_buf.extend_from_slice(&0u16.to_le_bytes()); // mime index 0
                    dirent_buf.push(0); // param len
                    dirent_buf.push(e.ns);
                    dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
                    dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // cluster 0
                    dirent_buf.extend_from_slice(&blob.to_le_bytes());
                    blob += 1;
                }
                EntryKind::Redirect(tns, tpath) => {
                    let target = dirent_index
                        .get(&(*tns, tpath.as_str()))
                        .copied()
                        .ok_or(Error::InvalidData("zim: redirect target missing"))?;
                    dirent_buf.extend_from_slice(&MIMETYPE_REDIRECT.to_le_bytes());
                    dirent_buf.push(0); // param len
                    dirent_buf.push(e.ns);
                    dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
                    dirent_buf.extend_from_slice(&target.to_le_bytes());
                }
                EntryKind::Deprecated(mimetype) => {
                    dirent_buf.extend_from_slice(&mimetype.to_le_bytes());
                    dirent_buf.push(0); // param len
                    dirent_buf.push(e.ns);
                    dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
                }
            }
            dirent_buf.extend_from_slice(e.path.as_bytes());
            dirent_buf.push(0);
            // Title = path for content/redirect entries; deprecated
            // dirents carry an empty title.
            if !matches!(e.kind, EntryKind::Deprecated(_)) {
                dirent_buf.extend_from_slice(e.path.as_bytes());
            }
            dirent_buf.push(0);
        }
        let dirent_base = 80 + mime.len();

        // Path pointer list: u64 dirent offsets in path order.
        let mut path_ptrs = Vec::new();
        for o in &dirent_offsets {
            path_ptrs.extend_from_slice(&((dirent_base + o) as u64).to_le_bytes());
        }
        let path_ptr_pos = dirent_base + dirent_buf.len();

        // Title pointer list: u32 dirent indices sorted by the
        // emitted title (path for content/redirect, empty for
        // deprecated entries).
        let mut title_order: Vec<u32> = (0..self.entries.len() as u32).collect();
        title_order.sort_by_key(|&i| {
            let e = &self.entries[i as usize];
            let title = match e.kind {
                EntryKind::Deprecated(_) => "",
                _ => e.path.as_str(),
            };
            (title, e.ns, e.path.as_str())
        });
        let title_ptr_pos = path_ptr_pos + path_ptrs.len();
        let mut title_ptrs = Vec::new();
        for i in &title_order {
            title_ptrs.extend_from_slice(&i.to_le_bytes());
        }

        // Cluster: info byte + (compressed) offset table + blobs.
        let blobs: Vec<&[u8]> = self
            .entries
            .iter()
            .filter_map(|e| match &e.kind {
                EntryKind::Content(data) => Some(data.as_slice()),
                _ => None,
            })
            .collect();
        let off_size = if self.extended { 8usize } else { 4 };
        let max_off = if self.extended {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        let mut payload = Vec::new();
        let mut off = (blobs.len() + 1) as u64 * off_size as u64;
        for data in &blobs {
            if off > max_off {
                return Err(Error::InvalidData("zim: blob offset overflow"));
            }
            payload.extend_from_slice(&off.to_le_bytes()[..off_size]);
            off += data.len() as u64;
        }
        if off > max_off {
            return Err(Error::InvalidData("zim: cluster too large"));
        }
        payload.extend_from_slice(&off.to_le_bytes()[..off_size]);
        for data in &blobs {
            payload.extend_from_slice(data);
        }
        let base = match self.compression {
            ZimCompression::None => CLUSTER_NONE,
            ZimCompression::Xz => CLUSTER_XZ,
            ZimCompression::Zstd => CLUSTER_ZSTD,
        };
        let info = if self.extended {
            base | CLUSTER_EXTENDED
        } else {
            base
        };
        let cluster = match self.compression {
            ZimCompression::None => payload,
            ZimCompression::Xz => crate::compress::xz::encode::encode(&payload),
            ZimCompression::Zstd => crate::compress::zstd::encode::encode(&payload),
        };

        let cluster_ptr_pos = title_ptr_pos + title_ptrs.len();
        let cluster_data_pos = cluster_ptr_pos + 8;
        let checksum_pos = cluster_data_pos + 1 + cluster.len();

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&self.version.major().to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&[0u8; 16]); // uuid
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // clusterCount
        out.extend_from_slice(&(path_ptr_pos as u64).to_le_bytes());
        out.extend_from_slice(&(title_ptr_pos as u64).to_le_bytes());
        out.extend_from_slice(&(cluster_ptr_pos as u64).to_le_bytes());
        out.extend_from_slice(&80u64.to_le_bytes()); // mimeListPos
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // mainPage
        out.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // layoutPage
        out.extend_from_slice(&(checksum_pos as u64).to_le_bytes());
        out.extend_from_slice(&mime);
        out.extend_from_slice(&dirent_buf);
        out.extend_from_slice(&path_ptrs);
        out.extend_from_slice(&title_ptrs);
        out.extend_from_slice(&(cluster_data_pos as u64).to_le_bytes());
        out.push(info);
        out.extend_from_slice(&cluster);
        // Trailing MD5 archive checksum over all preceding bytes.
        out.extend_from_slice(&md5::md5(&out));
        Ok(out)
    }
}

/// Split `N/path` into namespace byte and path; default
/// namespace `C`.
fn split_name(name: &str) -> (u8, &str) {
    let b = name.as_bytes();
    if b.len() >= 2 && b[1] == b'/' {
        (b[0], &name[2..])
    } else {
        (b'C', name)
    }
}

impl Default for ZimEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for ZimEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::zim::decode::decode;
    use crate::traits::ArchiveEntry;

    #[test]
    fn stored_roundtrip() {
        let mut enc = ZimEncoder::new();
        enc.add_file("C/index.html", b"<html>hi</html>");
        enc.add_file("A/meta.txt", b"metadata");
        let zim = enc.finish().unwrap();
        let entries = decode(&zim).unwrap();
        assert_eq!(entries.len(), 2);
        let a = entries.iter().find(|e| e.name() == "A/meta.txt").unwrap();
        assert_eq!(a.data(), b"metadata");
        let c = entries.iter().find(|e| e.name() == "C/index.html").unwrap();
        assert_eq!(c.data(), b"<html>hi</html>");
    }

    #[test]
    fn xz_and_zstd_roundtrip() {
        for comp in [ZimCompression::Xz, ZimCompression::Zstd] {
            let mut enc = ZimEncoder::with_compression(comp);
            let data = b"compress me compress me ".repeat(200);
            enc.add_file("big.txt", &data);
            let entries = decode(&enc.finish().unwrap()).unwrap();
            assert_eq!(entries[0].data(), data.as_slice());
        }
    }

    #[test]
    fn default_namespace_is_c() {
        let mut enc = ZimEncoder::new();
        enc.add_file("plain.txt", b"x");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries[0].name(), "C/plain.txt");
    }

    #[test]
    fn rejects_bad_paths() {
        let mut enc = ZimEncoder::new();
        enc.add_file("C/", b"x");
        assert!(enc.finish().is_err());
        let mut enc = ZimEncoder::new();
        enc.add_file("C/a\0b", b"x");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn emits_md5_checksum() {
        let mut enc = ZimEncoder::new();
        enc.add_file("f", b"data");
        let zim = enc.finish().unwrap();
        let checksum_pos = u64::from_le_bytes(zim[72..80].try_into().unwrap()) as usize;
        assert_eq!(checksum_pos, zim.len() - 16);
        assert_eq!(
            &zim[checksum_pos..],
            md5::md5(&zim[..checksum_pos]).as_slice()
        );
    }

    /// Cluster info byte of the emitted archive's single cluster.
    fn cluster_info(zim: &[u8]) -> u8 {
        let cluster_ptr_pos = u64::from_le_bytes(zim[48..56].try_into().unwrap()) as usize;
        let cluster_pos = u64::from_le_bytes(
            zim[cluster_ptr_pos..cluster_ptr_pos + 8]
                .try_into()
                .unwrap(),
        ) as usize;
        zim[cluster_pos]
    }

    #[test]
    fn v6_extended_cluster_roundtrip() {
        let mut enc = ZimEncoder::new()
            .with_version(ZimVersion::V6)
            .with_extended_cluster();
        enc.add_file("C/a.txt", b"alpha");
        enc.add_file("C/b.txt", b"beta");
        let zim = enc.finish().unwrap();
        assert_eq!(u16::from_le_bytes([zim[4], zim[5]]), 6);
        let info = cluster_info(&zim);
        assert_eq!(info & 0x0f, CLUSTER_NONE);
        assert_ne!(info & CLUSTER_EXTENDED, 0);
        let entries = decode(&zim).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"alpha");
        assert_eq!(entries[1].data(), b"beta");
    }

    #[test]
    fn v6_plain_cluster_roundtrip() {
        // Major 6 without the extended flag keeps 4-byte offsets.
        let mut enc = ZimEncoder::new().with_version(ZimVersion::V6);
        enc.add_file("f", b"data");
        let zim = enc.finish().unwrap();
        assert_eq!(cluster_info(&zim) & CLUSTER_EXTENDED, 0);
        assert_eq!(decode(&zim).unwrap()[0].data(), b"data");
    }

    #[test]
    fn extended_cluster_requires_v6() {
        let mut enc = ZimEncoder::new().with_extended_cluster();
        enc.add_file("f", b"x");
        match enc.finish() {
            Err(Error::InvalidData(msg)) => {
                assert_eq!(msg, "zim: extended cluster requires major version 6")
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn redirect_roundtrip() {
        let mut enc = ZimEncoder::new();
        enc.add_file("C/target.html", b"real content");
        enc.add_redirect("C/alias.html", "C/target.html");
        let zim = enc.finish().unwrap();
        let entries = decode(&zim).unwrap();
        assert_eq!(entries.len(), 2);
        let alias = entries.iter().find(|e| e.name() == "C/alias.html").unwrap();
        assert_eq!(alias.data(), b"real content");
        assert_eq!(alias.mime_type, "");
        let target = entries
            .iter()
            .find(|e| e.name() == "C/target.html")
            .unwrap();
        assert_eq!(target.data(), b"real content");
    }

    #[test]
    fn redirect_missing_target_rejected() {
        let mut enc = ZimEncoder::new();
        enc.add_file("C/a", b"1");
        enc.add_redirect("C/b", "C/nope");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn redirect_to_non_content_rejected() {
        // A redirect target that is itself a redirect or a
        // deprecated dirent is rejected: decode would skip it.
        let mut enc = ZimEncoder::new();
        enc.add_file("C/a", b"1");
        enc.add_redirect("C/b", "C/a");
        enc.add_redirect("C/c", "C/b");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));

        let mut enc = ZimEncoder::new();
        enc.add_file("C/a", b"1");
        enc.add_deprecated("C/old", ZimDeprecated::Deleted);
        enc.add_redirect("C/b", "C/old");
        assert!(matches!(enc.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn deprecated_entries_skipped_on_decode() {
        let mut enc = ZimEncoder::new();
        enc.add_file("C/keep", b"kept");
        enc.add_deprecated("C/gone", ZimDeprecated::Deleted);
        enc.add_deprecated("C/lt", ZimDeprecated::Linktarget);
        let zim = enc.finish().unwrap();
        // entryCount counts all dirents; decode skips deprecated.
        assert_eq!(u32::from_le_bytes(zim[24..28].try_into().unwrap()), 3);
        let entries = decode(&zim).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "C/keep");
        assert_eq!(entries[0].data(), b"kept");
    }

    #[test]
    fn v6_extended_with_redirect_and_deprecated() {
        let mut enc = ZimEncoder::with_compression(ZimCompression::Zstd)
            .with_version(ZimVersion::V6)
            .with_extended_cluster();
        enc.add_file("C/target", b"payload");
        enc.add_redirect("C/alias", "C/target");
        enc.add_deprecated("C/dead", ZimDeprecated::Linktarget);
        let zim = enc.finish().unwrap();
        let entries = decode(&zim).unwrap();
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(e.data(), b"payload");
        }
    }
}
