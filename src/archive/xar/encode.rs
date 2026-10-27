//! XAR archive encode.
//!
//! Produces a spec-conformant XAR: 28-byte header (cksum_alg = sha1),
//! a zlib-compressed XML table of contents, and a heap holding the
//! SHA-1 of the compressed TOC followed by each file's
//! `application/x-gzip` (zlib-compressed) data run. Paths containing
//! '/' are emitted as nested `<file>` directory elements, matching
//! the reference library's tree structure.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::sha1::sha1;

/// Encoder for XAR archives.
pub struct XarEncoder {
    /// (path, is_dir, data, mode) in insertion order.
    entries: Vec<(String, bool, Vec<u8>, Option<String>)>,
}

impl XarEncoder {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a file at `path` ('/'-separated) with `data` contents.
    pub fn add_file(&mut self, path: &str, data: &[u8]) {
        self.entries.push((
            path.trim_matches('/').to_string(),
            false,
            data.to_vec(),
            None,
        ));
    }

    /// Add a file with an octal mode string (e.g. "0644").
    pub fn add_file_with_mode(&mut self, path: &str, data: &[u8], mode: &str) {
        self.entries.push((
            path.trim_matches('/').to_string(),
            false,
            data.to_vec(),
            Some(mode.to_string()),
        ));
    }

    /// Add an explicit directory entry.
    pub fn add_directory(&mut self, path: &str) {
        self.entries
            .push((path.trim_matches('/').to_string(), true, Vec::new(), None));
    }

    /// Finalize and return the archive bytes.
    pub fn finish(self) -> Vec<u8> {
        // Build the directory/file tree and assign heap data runs.
        // Heap layout: [sha1 of compressed TOC (20)] [file data runs].
        let mut heap_runs: Vec<(usize, Vec<u8>)> = Vec::new(); // (entry idx, zlib data)
        let mut heap_len = 20usize;
        for (i, (_, is_dir, data, _)) in self.entries.iter().enumerate() {
            if !is_dir {
                let z = crate::compress::zlib::encode::encode(data);
                heap_runs.push((i, z));
                heap_len += heap_runs.last().unwrap().1.len();
            }
        }

        // Emit TOC XML.
        let mut toc = String::new();
        toc.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xar>\n <toc>\n");
        toc.push_str("  <checksum style=\"sha1\">\n   <size>20</size>\n   <offset>0</offset>\n  </checksum>\n");
        // Assign data offsets.
        let mut offsets: Vec<(u64, u64)> = Vec::with_capacity(heap_runs.len());
        let mut off = 20u64;
        for (_, z) in &heap_runs {
            offsets.push((off, z.len() as u64));
            off += z.len() as u64;
        }
        let runs_by_index: BTreeMap<usize, (u64, u64, &[u8])> = heap_runs
            .iter()
            .zip(offsets.iter().copied())
            .map(|((index, data), (offset, length))| (*index, (offset, length, data.as_slice())))
            .collect();
        let mut id = 0u32;
        // Emit the entry tree: parents derived from '/' components.
        emit_tree(&self.entries, &runs_by_index, &mut toc, 2, &mut id);
        drop(runs_by_index);
        toc.push_str(" </toc>\n</xar>\n");

        let toc_packed = crate::compress::zlib::encode::encode(toc.as_bytes());

        // Heap.
        let mut heap = Vec::with_capacity(heap_len);
        heap.extend_from_slice(&sha1(&toc_packed));
        for (_, z) in heap_runs {
            heap.extend_from_slice(&z);
        }

        // Header.
        let mut out = Vec::with_capacity(28 + toc_packed.len() + heap.len());
        out.extend_from_slice(b"xar!");
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(toc_packed.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&toc_packed);
        out.extend_from_slice(&heap);
        out
    }
}

impl Default for XarEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for XarEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.finish())
    }
}

/// Emit `<file>` elements for `entries`, grouping by path prefix into
/// nested directory elements. `runs` yields (heap data run, (offset,
/// length)) for each non-directory entry in order.
fn emit_tree<'a>(
    entries: &'a [(String, bool, Vec<u8>, Option<String>)],
    runs: &BTreeMap<usize, (u64, u64, &'a [u8])>,
    toc: &mut String,
    indent: usize,
    id: &mut u32,
) {
    // Build a tree once (borrowed views).
    #[derive(Default)]
    struct Dir<'a> {
        files: Vec<usize>,             // entry indices, files only
        dirs: Vec<(&'a str, Dir<'a>)>, // name -> subtree, insertion order
        /// Name to child index. Valid while `insert` builds the tree.
        /// `dirs` stays in insertion order and is not reordered from this map.
        by_name: BTreeMap<&'a str, usize>,
    }
    fn insert<'a>(root: &mut Dir<'a>, parts: &[&'a str], idx: usize, is_dir: bool) {
        if parts.is_empty() {
            return;
        }
        if parts.len() == 1 {
            if is_dir {
                // Leaf directory: materialize the subtree node.
                if !root.by_name.contains_key(parts[0]) {
                    let at = root.dirs.len();
                    root.by_name.insert(parts[0], at);
                    root.dirs.push((parts[0], Dir::default()));
                }
            } else {
                root.files.push(idx);
            }
            return;
        }
        let (head, rest) = parts.split_first().unwrap();
        let i = match root.by_name.get(head).copied() {
            Some(i) => i,
            None => {
                let at = root.dirs.len();
                root.by_name.insert(head, at);
                root.dirs.push((head, Dir::default()));
                at
            }
        };
        insert(&mut root.dirs[i].1, rest, idx, is_dir);
    }

    let mut root = Dir::default();
    for (i, (path, is_dir, _, _)) in entries.iter().enumerate() {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if !parts.is_empty() {
            insert(&mut root, &parts, i, *is_dir);
        }
    }

    fn emit_dir<'a>(
        dir: &Dir<'a>,
        name: Option<&'a str>,
        entries: &'a [(String, bool, Vec<u8>, Option<String>)],
        runs: &BTreeMap<usize, (u64, u64, &'a [u8])>,
        toc: &mut String,
        indent: usize,
        id: &mut u32,
    ) {
        let pad = " ".repeat(indent);
        if let Some(n) = name {
            *id += 1;
            toc.push_str(&alloc::format!("{pad}<file id=\"{id}\">\n"));
            toc.push_str(&alloc::format!("{pad} <name>{}</name>\n", xml_escape(n)));
            toc.push_str(&alloc::format!("{pad} <type>directory</type>\n"));
        }
        for &i in &dir.files {
            let (path, _, data, mode) = &entries[i];
            let fname = path.rsplit('/').next().unwrap_or(path);
            let &(doff, dlen, zdata) = runs.get(&i).expect("heap run for file entry");
            *id += 1;
            toc.push_str(&alloc::format!("{pad}<file id=\"{id}\">\n"));
            toc.push_str(&alloc::format!(
                "{pad} <name>{}</name>\n",
                xml_escape(fname)
            ));
            toc.push_str(&alloc::format!("{pad} <type>file</type>\n"));
            if let Some(m) = mode {
                toc.push_str(&alloc::format!("{pad} <mode>{m}</mode>\n"));
            }
            let extracted = crate::util::sha1::sha1(data);
            let archived = crate::util::sha1::sha1(zdata);
            toc.push_str(&alloc::format!("{pad} <data>\n"));
            toc.push_str(&alloc::format!(
                "{pad}  <extracted-checksum style=\"sha1\">{}</extracted-checksum>\n",
                hex(&extracted)
            ));
            toc.push_str(&alloc::format!(
                "{pad}  <archived-checksum style=\"sha1\">{}</archived-checksum>\n",
                hex(&archived)
            ));
            toc.push_str(&alloc::format!(
                "{pad}  <encoding style=\"application/x-gzip\"/>\n"
            ));
            toc.push_str(&alloc::format!("{pad}  <size>{}</size>\n", data.len()));
            toc.push_str(&alloc::format!("{pad}  <offset>{}</offset>\n", doff));
            toc.push_str(&alloc::format!("{pad}  <length>{}</length>\n", dlen));
            toc.push_str(&alloc::format!("{pad} </data>\n"));
            toc.push_str(&alloc::format!("{pad}</file>\n"));
        }
        for (dn, sub) in &dir.dirs {
            emit_dir(sub, Some(dn), entries, runs, toc, indent + 1, id);
        }
        if name.is_some() {
            toc.push_str(&alloc::format!("{pad}</file>\n"));
        }
    }

    emit_dir(&root, None, entries, runs, toc, indent, id);
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for v in b {
        s.push(char::from_digit((v >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((v & 0xF) as u32, 16).unwrap());
    }
    s
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::xar::decode;

    #[test]
    fn xml_escape_escapes_special_characters() {
        assert_eq!(xml_escape("a&b<c>d\"e"), "a&amp;b&lt;c&gt;d&quot;e");
        assert_eq!(hex(&[0x00, 0x0F, 0xA5, 0xFF]), "000fa5ff");
    }

    #[test]
    fn encoder_roundtrips_files_modes_and_directories() {
        let mut encoder = XarEncoder::new();
        encoder.add_file("dir/a & b.txt", b"hello xar");
        encoder.add_file_with_mode("mode.bin", b"x", "0644");
        encoder.add_directory("empty");
        let image = encoder.finish();
        let entries = decode::decode(&image).unwrap();
        let file = entries
            .iter()
            .find(|entry| entry.name == "dir/a & b.txt")
            .unwrap();
        assert_eq!(file.data, b"hello xar");
        assert_eq!(file.file_type, "file");

        let mode = entries
            .iter()
            .find(|entry| entry.name == "mode.bin")
            .unwrap();
        assert_eq!(mode.data, b"x");
        assert_eq!(mode.mode.as_deref(), Some("0644"));

        let dir = entries.iter().find(|entry| entry.name == "empty").unwrap();
        assert!(dir.is_dir);
        assert_eq!(dir.file_type, "directory");
    }
}
