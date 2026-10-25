//! Deterministic corpus generation.
//!
//! Large inputs are generated under `target/bench` and never committed.

use std::fs;
use std::path::{Path, PathBuf};

use crate::helpers;

pub const CORPORA: &[&str] = &["text", "run", "random", "periodic"];

pub fn generate(label: &str, size: usize) -> Vec<u8> {
    match label {
        "text" => helpers::generate_text_data(size),
        "run" => helpers::generate_run_data(size),
        "random" => helpers::generate_binary_data(size),
        "periodic" => helpers::generate_periodic_data(size),
        _ => panic!("unknown corpus `{label}`"),
    }
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ArchiveTree {
    pub root: PathBuf,
    pub entries: Vec<TreeEntry>,
}

impl ArchiveTree {
    pub fn total_bytes(&self) -> usize {
        self.entries.iter().map(|entry| entry.data.len()).sum()
    }

    pub fn manifest(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = self
            .entries
            .iter()
            .map(|entry| (entry.name.clone(), fnv1a64(&entry.data)))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

/// Build a fixed archive tree. Entry names include the `tree/` prefix so
/// the same base directory can be passed to the helper and reference tools.
pub fn build_tree(dir: &Path, file_count: usize, file_size: usize) -> std::io::Result<ArchiveTree> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    let mut entries = Vec::new();

    for i in 0..file_count {
        let (relative, size) = match i % 10 {
            0 => (format!("file_{i:03}.txt"), file_size),
            1 => (format!("sub/file_{i:03}.txt"), file_size),
            2 => (format!("nested/deep/file_{i:03}.txt"), file_size / 2),
            3 => (format!("file_{i:03}.bin"), file_size),
            4 if i == 4 => ("empty.bin".to_owned(), 0),
            _ => (format!("sub/file_{i:03}.txt"), file_size),
        };
        let data = if relative.ends_with(".bin") {
            let mut bytes = generate("random", size);
            // Give each binary file a distinct prefix without changing size.
            for (j, byte) in bytes.iter_mut().take(8).enumerate() {
                *byte = (i as u8).wrapping_add(j as u8);
            }
            bytes
        } else if size == 0 {
            Vec::new()
        } else {
            let mut bytes = generate("text", size + i * 13);
            bytes.truncate(size);
            for (j, byte) in bytes.iter_mut().take(16).enumerate() {
                *byte = b"entry-"[j % 6].wrapping_add((i % 32) as u8);
            }
            bytes
        };

        let path = dir.join(&relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &data)?;
        entries.push(TreeEntry {
            name: format!("tree/{relative}"),
            data,
        });
    }

    Ok(ArchiveTree {
        root: dir.to_path_buf(),
        entries,
    })
}

/// FNV-1a, matching the helper's payload manifest hashes.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
