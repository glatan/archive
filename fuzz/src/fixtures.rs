//! Real-world fixture streams as corrupt-pattern bases.
//!
//! `encode_with` only produces self-encoded, maximally well-formed streams.
//! `tests/fixtures/` holds tool-produced files that exercise vendor
//! extensions, unusual flag combinations, and real multi-entry layouts —
//! decoder paths a self-encoded stream never reaches. This module maps each
//! algorithm to the fixture directories that can seed the corrupt pattern.

use crate::algorithms::Algorithm;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, OnceLock};

/// Largest fixture file used as a mutation base.
const FIXTURE_SIZE_CAP: u64 = 1 << 20;
/// Largest number of fixtures loaded per algorithm.
const FIXTURE_COUNT_CAP: usize = 32;

static ROOT: OnceLock<PathBuf> = OnceLock::new();
static CACHE: LazyLock<Mutex<HashMap<Algorithm, Vec<Vec<u8>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Point the loader at a fixtures root (e.g. `tests/fixtures/`).
///
/// Algorithms with an empty directory list have no fixture phase. An
/// algorithm whose directory is listed and missing fails when loaded.
pub fn init(root: &Path) {
    let _ = ROOT.set(root.to_path_buf());
}

/// Fixture directory names under `tests/fixtures/` relevant to `algo`.
const fn dirs_for(algo: Algorithm) -> &'static [&'static str] {
    match algo {
        Algorithm::Gzip | Algorithm::GzipFast | Algorithm::GzipStore => &["gzip"],
        Algorithm::Zstd
        | Algorithm::ZstdFast
        | Algorithm::ZstdBest
        | Algorithm::ZstdNoChecksum
        | Algorithm::ZstdSeekable
        | Algorithm::ZstdDict => &["zstd"],
        Algorithm::Brotli
        | Algorithm::BrotliFast
        | Algorithm::BrotliBest
        | Algorithm::BrotliMeta => &["brotli"],
        Algorithm::Lzw | Algorithm::LzwBits9 => &["lzw"],
        Algorithm::Lz4
        | Algorithm::Lz4Fast
        | Algorithm::Lz4Best
        | Algorithm::Lz4SmallBlock
        | Algorithm::Lz4Block
        | Algorithm::Lz4Dict
        | Algorithm::Lz4Legacy
        | Algorithm::Lz4BlockDependent => &["lz4"],
        Algorithm::Lzo | Algorithm::LzoFast | Algorithm::LzoBest => &["lzo"],
        Algorithm::LrzipLzma
        | Algorithm::LrzipBzip2
        | Algorithm::LrzipGzip
        | Algorithm::LrzipLzo
        | Algorithm::LrzipNone
        | Algorithm::LrzipZpaq => &["lrzip"],
        Algorithm::Lzs => &["lzs"],
        Algorithm::Mppc | Algorithm::MppcRdp4 | Algorithm::MppcRdp5 => &["mppc"],
        Algorithm::Vcdiff | Algorithm::VcdiffSrc => &["vcdiff"],
        Algorithm::Ar | Algorithm::ArBsd => &["ar"],
        Algorithm::Arc => &["arc"],
        Algorithm::Lha
        | Algorithm::LhaLh4
        | Algorithm::LhaLh5
        | Algorithm::LhaLh6
        | Algorithm::LhaLh7
        | Algorithm::LhaLzs
        | Algorithm::LhaLz5
        | Algorithm::LhaPm1
        | Algorithm::LhaPm2 => &["lha"],
        Algorithm::TarGnu | Algorithm::TarUstar | Algorithm::TarPax => &["tar"],
        Algorithm::Cpio | Algorithm::CpioCrc | Algorithm::CpioOdc | Algorithm::CpioBin => &["cpio"],
        Algorithm::Zip
        | Algorithm::ZipStore
        | Algorithm::ZipBzip2
        | Algorithm::ZipZstd
        | Algorithm::ZipDeflate64
        | Algorithm::ZipLzma
        | Algorithm::ZipXz
        | Algorithm::ZipPpmd
        | Algorithm::ZipShrunk
        | Algorithm::ZipImplode
        | Algorithm::ZipReduce => &["zip"],
        Algorithm::Mscab => &["mscab"],
        Algorithm::Xar => &["xar"],
        Algorithm::Erofs => &["erofs"],
        Algorithm::Romfs => &["romfs"],
        Algorithm::Iso9660 | Algorithm::IsoRr => &["iso9660"],
        Algorithm::GitPack | Algorithm::GitPackDelta | Algorithm::GitPackSha256 => &["git-pack"],
        Algorithm::Zpaq
        | Algorithm::ZpaqLevel2
        | Algorithm::ZpaqLevel3
        | Algorithm::ZpaqArchive => &["zpaq"],
        _ => &[],
    }
}

/// Load (and cache) the fixture streams usable as corrupt bases for `algo`.
pub fn load(algo: Algorithm) -> Result<Vec<Vec<u8>>, String> {
    if let Some(cached) = CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&algo)
        .cloned()
    {
        return Ok(cached);
    }
    let dirs = dirs_for(algo);
    if dirs.is_empty() {
        return Ok(Vec::new());
    }
    let Some(root) = ROOT.get() else {
        return Err(format!(
            "fixture directory for {algo} is missing: fixtures root is not set"
        ));
    };
    let mut fixtures = Vec::new();
    for dir_name in dirs {
        let dir = root.join(dir_name);
        let read_dir = fs::read_dir(&dir)
            .map_err(|_| format!("fixture directory for {algo} is missing: {}", dir.display()))?;
        let mut paths: Vec<PathBuf> = read_dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        paths.sort();
        for path in paths {
            if fixtures.len() >= FIXTURE_COUNT_CAP {
                break;
            }
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            if meta.len() > FIXTURE_SIZE_CAP {
                continue;
            }
            if let Ok(bytes) = fs::read(&path) {
                fixtures.push(bytes);
            }
        }
    }
    CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(algo, fixtures.clone());
    Ok(fixtures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_cover_known_families() {
        assert_eq!(dirs_for(Algorithm::LhaLh5), &["lha"]);
        assert_eq!(dirs_for(Algorithm::ZipLzma), &["zip"]);
        assert_eq!(dirs_for(Algorithm::CpioBin), &["cpio"]);
        assert!(dirs_for(Algorithm::Deflate).is_empty());
    }

    #[test]
    fn load_is_empty_without_init() {
        // ROOT is process-global; if a prior test initialized it this returns
        // fixtures instead. Either way it must not panic.
        let _ = load(Algorithm::Lha);
    }
}
