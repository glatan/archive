//! ZIM archive (`.zim`) encode — format v5, single cluster.
//!
//! [`ZimEncoder`] writes a minimal valid ZIM file: one cluster
//! holding every queued file as a blob, path/title pointer lists,
//! a MIME type list, and the trailing MD5 archive checksum
//! (openZIM wiki "ZIM file format": Header, Directory Entries,
//! Clusters). Extended (8-byte offset) clusters, split archives,
//! redirect/deprecated entries, and fulltext indexes are not
//! emitted.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::md5;

const MAGIC: u32 = 0x044D_495A;
const CLUSTER_NONE: u8 = 1;
const CLUSTER_XZ: u8 = 4;
const CLUSTER_ZSTD: u8 = 5;

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

/// Encoder for minimal v5 ZIM archives.
///
/// Every [`add_file`](Self::add_file) name is written as a
/// `N/path` entry; a leading `X/` prefix supplies the namespace
/// byte, otherwise namespace `C` is used. All blobs share one
/// cluster in queue order.
pub struct ZimEncoder {
    compression: ZimCompression,
    mime_type: String,
    /// (namespace byte, path, data).
    files: Vec<(u8, String, Vec<u8>)>,
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
            mime_type: String::from("application/octet-stream"),
            files: Vec::new(),
        }
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
        self.files.push((ns, String::from(path), data.to_vec()));
    }

    /// Serialize the archive.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] if a queued name is empty, has a NUL
    /// byte, or the file exceeds u32 field limits.
    pub fn finish(mut self) -> Result<Vec<u8>, Error> {
        for (_, path, _) in &self.files {
            if path.is_empty() || path.as_bytes().contains(&0) {
                return Err(Error::InvalidData("zim: invalid entry path"));
            }
        }
        if self.mime_type.as_bytes().contains(&0) {
            return Err(Error::InvalidData("zim: invalid mime type"));
        }
        // Dirent order is path order so the path pointer list is
        // sorted by construction.
        self.files.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));

        // MIME type list (ASCIIZ sequence, empty-string terminator).
        let mut mime = Vec::new();
        mime.extend_from_slice(self.mime_type.as_bytes());
        mime.push(0);
        mime.push(0);

        // Directory entries: every file is blob i of cluster 0.
        let mut dirent_buf = Vec::new();
        let mut dirent_offsets = Vec::with_capacity(self.files.len());
        for (i, (ns, path, _)) in self.files.iter().enumerate() {
            dirent_offsets.push(dirent_buf.len());
            dirent_buf.extend_from_slice(&0u16.to_le_bytes()); // mime index 0
            dirent_buf.push(0); // param len
            dirent_buf.push(*ns);
            dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // revision
            dirent_buf.extend_from_slice(&0u32.to_le_bytes()); // cluster 0
            dirent_buf.extend_from_slice(&(i as u32).to_le_bytes()); // blob i
            dirent_buf.extend_from_slice(path.as_bytes());
            dirent_buf.push(0);
            dirent_buf.extend_from_slice(path.as_bytes()); // title = path
            dirent_buf.push(0);
        }
        let dirent_base = 80 + mime.len();

        // Path pointer list: u64 dirent offsets in path order.
        let mut path_ptrs = Vec::new();
        for o in &dirent_offsets {
            path_ptrs.extend_from_slice(&((dirent_base + o) as u64).to_le_bytes());
        }
        let path_ptr_pos = dirent_base + dirent_buf.len();

        // Title pointer list: u32 dirent indices sorted by title
        // (title == path here).
        let mut title_order: Vec<u32> = (0..self.files.len() as u32).collect();
        title_order.sort_by_key(|&i| (&self.files[i as usize].0, &self.files[i as usize].1));
        let title_ptr_pos = path_ptr_pos + path_ptrs.len();
        let mut title_ptrs = Vec::new();
        for i in &title_order {
            title_ptrs.extend_from_slice(&i.to_le_bytes());
        }

        // Cluster: info byte + (compressed) offset table + blobs.
        let mut payload = Vec::new();
        let n = self.files.len();
        let mut off = (n + 1) * 4;
        for (_, _, data) in &self.files {
            if off > u32::MAX as usize {
                return Err(Error::InvalidData("zim: blob offset overflow"));
            }
            payload.extend_from_slice(&(off as u32).to_le_bytes());
            off += data.len();
        }
        if off > u32::MAX as usize {
            return Err(Error::InvalidData("zim: cluster too large"));
        }
        payload.extend_from_slice(&(off as u32).to_le_bytes());
        for (_, _, data) in &self.files {
            payload.extend_from_slice(data);
        }
        let (info, cluster) = match self.compression {
            ZimCompression::None => (CLUSTER_NONE, payload),
            ZimCompression::Xz => (CLUSTER_XZ, crate::compress::xz::encode::encode(&payload)),
            ZimCompression::Zstd => (
                CLUSTER_ZSTD,
                crate::compress::zstd::encode::encode(&payload),
            ),
        };

        let cluster_ptr_pos = title_ptr_pos + title_ptrs.len();
        let cluster_data_pos = cluster_ptr_pos + 8;
        let checksum_pos = cluster_data_pos + 1 + cluster.len();

        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&5u16.to_le_bytes()); // major v5
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&[0u8; 16]); // uuid
        out.extend_from_slice(&(self.files.len() as u32).to_le_bytes());
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

/// Split `N/path` into namespace byte and path; default namespace `C`.
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
}
