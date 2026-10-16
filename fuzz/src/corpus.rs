use crate::algorithms::Algorithm;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::IndexedRandom;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Salt XORed into the run seed for corpus sampling so selection is
/// deterministic per run but independent of the main input-generation rng.
const CORPUS_SAMPLE_SEED_SALT: u64 = 0x636f_7270_7573_5f63;
/// Salt for the eviction-pick rng inside [CorpusDirState].
const CORPUS_EVICT_SEED_SALT: u64 = 0x6576_6963_745f_7374;

/// Result of loading the on-disk corpus for a bounded run.
pub struct LoadedCorpus {
    /// Content-deduped union of adopted corpus entries.
    pub pool: Vec<Vec<u8>>,
    /// Per-algorithm .bin file names present on disk after loading (and any
    /// pruning). Seeds the in-memory accounting used by bounded saves, so it
    /// covers every file on disk, including entries the size filter skipped,
    /// which keeps dedupe and the entry cap consistent with the directory.
    pub dir_names: HashMap<Algorithm, Vec<String>>,
}

pub fn load_union_corpus(
    root: &Path,
    algorithms: &[Algorithm],
    min_size: usize,
    max_size: usize,
    max_entries: usize,
    seed: u64,
) -> LoadedCorpus {
    let mut seen = HashSet::new();
    let mut pool = Vec::new();
    let mut dir_names = HashMap::new();

    for &algo in algorithms {
        let (entries, names) =
            load_algorithm_corpus(root, algo, min_size, max_size, max_entries, seed);
        dir_names.insert(algo, names);
        for data in entries {
            let hash = blake3::hash(&data).to_hex().to_string();
            if seen.insert(hash) {
                pool.push(data);
            }
        }
    }

    LoadedCorpus { pool, dir_names }
}

fn load_algorithm_corpus(
    root: &Path,
    algo: Algorithm,
    min_size: usize,
    max_size: usize,
    max_entries: usize,
    seed: u64,
) -> (Vec<Vec<u8>>, Vec<String>) {
    let dir = algorithm_corpus_dir(root, algo);
    let Ok(read_dir) = fs::read_dir(&dir) else {
        return (Vec::new(), Vec::new());
    };

    // Names are sorted so sampling is deterministic regardless of readdir order.
    let mut all_bin: Vec<String> = Vec::new();
    let mut eligible: Vec<String> = Vec::new();
    for entry in read_dir.filter_map(Result::ok) {
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        all_bin.push(name.clone());
        let in_range = entry
            .metadata()
            .map(|m| (min_size..=max_size).contains(&(m.len() as usize)))
            .unwrap_or(false);
        if in_range {
            eligible.push(name);
        }
    }
    all_bin.sort();
    eligible.sort();

    // `max_entries == 0` means unlimited: adopt everything, delete nothing.
    // Pruning is governed by the total .bin count: in-range names are kept
    // first and the remaining budget goes to out-of-range names, so size
    // flags never delete more files than the entry cap requires.
    let capped = max_entries > 0 && all_bin.len() > max_entries;
    let (mut kept, pool_names): (Vec<String>, Vec<String>) = if capped {
        let mut rng = StdRng::seed_from_u64(seed ^ algo_sample_salt(algo));
        let adopted: Vec<String> = eligible
            .sample(&mut rng, eligible.len().min(max_entries))
            .cloned()
            .collect();
        let mut kept = adopted.clone();
        if kept.len() < max_entries {
            let eligible_set: HashSet<&str> = eligible.iter().map(String::as_str).collect();
            let ineligible: Vec<&String> = all_bin
                .iter()
                .filter(|n| !eligible_set.contains(n.as_str()))
                .collect();
            kept.extend(
                ineligible
                    .sample(&mut rng, max_entries - kept.len())
                    .map(|name| (*name).clone()),
            );
        }
        (kept, adopted)
    } else {
        (Vec::new(), eligible)
    };
    kept.sort();

    // Pruning makes oversized directories converge to the cap after one run.
    if capped {
        let kept_set: HashSet<&str> = kept.iter().map(String::as_str).collect();
        for name in &all_bin {
            if !kept_set.contains(name.as_str()) {
                let _ = fs::remove_file(dir.join(name));
            }
        }
    }

    let mut entries = Vec::new();
    for name in &pool_names {
        if let Ok(data) = fs::read(dir.join(name)) {
            entries.push(data);
        }
    }
    // Files left on disk (eligible or not) all count toward the cap for
    // subsequent bounded saves.
    let dir_names = if capped { kept.clone() } else { all_bin };
    (entries, dir_names)
}

fn algo_sample_salt(algo: Algorithm) -> u64 {
    let mut h = CORPUS_SAMPLE_SEED_SALT;
    for &b in algo.name().as_bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// In-memory accounting of the `.bin` files in one algorithm's corpus
/// directory. [`save_corpus_entry_bounded`] uses it to enforce the entry cap
/// without rescanning the directory on every save.
pub struct CorpusDirState {
    names: Vec<String>,
    /// Per-algorithm rng for eviction picks. The main run rng decides the
    /// input sequence and must stay reproducible for a given --seed.
    rng: StdRng,
}

impl CorpusDirState {
    pub fn new(names: Vec<String>, algo: Algorithm, run_seed: u64) -> Self {
        Self {
            names,
            rng: StdRng::seed_from_u64(run_seed ^ CORPUS_EVICT_SEED_SALT ^ algo_sample_salt(algo)),
        }
    }
}

pub fn save_corpus_entry(
    root: &Path,
    algo: Algorithm,
    label: &str,
    data: &[u8],
) -> Result<Option<PathBuf>, String> {
    let dir = algorithm_corpus_dir(root, algo);
    fs::create_dir_all(&dir).map_err(|e| format!("create corpus dir failed: {e}"))?;

    let file_name = corpus_file_name(label, data);
    let path = dir.join(&file_name);
    if path.symlink_metadata().is_ok() {
        return Ok(None);
    }

    fs::write(&path, data).map_err(|e| format!("write corpus entry failed: {e}"))?;
    Ok(Some(path))
}

/// Bounded variant of [`save_corpus_entry`]: keeps at most `max_entries` files
/// (`max_entries == 0` means unlimited) in the algorithm's corpus directory.
/// At the cap, a random tracked entry is evicted before writing so new
/// observations still land on disk. The caller holds the per-algorithm lock,
/// so `state` is authoritative for the directory's contents.
pub fn save_corpus_entry_bounded(
    root: &Path,
    algo: Algorithm,
    label: &str,
    data: &[u8],
    state: &mut CorpusDirState,
    max_entries: usize,
) -> Result<Option<PathBuf>, String> {
    let file_name = corpus_file_name(label, data);
    // Check before evicting so a dedupe hit does not cost an eviction.
    if state.names.iter().any(|n| n == &file_name) {
        return Ok(None);
    }

    let dir = algorithm_corpus_dir(root, algo);
    fs::create_dir_all(&dir).map_err(|e| format!("create corpus dir failed: {e}"))?;
    let path = dir.join(&file_name);
    // An untracked on-disk entry (written externally between load and now,
    // or a symlink) must not be overwritten; fs::write would follow links.
    if path.symlink_metadata().is_ok() {
        // Track it so the file counts toward the cap and can be evicted
        // later, but never overwrite it.
        state.names.push(file_name);
        return Ok(None);
    }

    if max_entries > 0 && state.names.len() >= max_entries {
        let idx = state.rng.random_range(0..state.names.len());
        let victim = state.names[idx].clone();
        match fs::remove_file(dir.join(&victim)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("evict corpus entry {victim} failed: {e}"));
            }
            _ => {}
        }
        state.names.swap_remove(idx);
    }

    fs::write(&path, data).map_err(|e| format!("write corpus entry failed: {e}"))?;
    state.names.push(file_name);
    Ok(Some(path))
}

fn corpus_file_name(label: &str, data: &[u8]) -> String {
    let hash = blake3::hash(data).to_hex().to_string();
    let prefix = sanitize_component(label);
    if prefix.is_empty() {
        format!("{}.bin", &hash[..16])
    } else {
        format!("{}_{}.bin", prefix, &hash[..16])
    }
}

pub fn algorithm_corpus_dir(root: &Path, algo: Algorithm) -> PathBuf {
    root.join(algo.name())
}

fn sanitize_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CorpusDirState, algorithm_corpus_dir, corpus_file_name, load_union_corpus,
        save_corpus_entry, save_corpus_entry_bounded,
    };
    use crate::algorithms::Algorithm;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "archive-fuzz-corpus-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn save_and_load_corpus_deduplicates_by_content() {
        let tmp = temp_dir("dedup");

        save_corpus_entry(&tmp, Algorithm::Gzip, "seed", b"hello").unwrap();
        save_corpus_entry(&tmp, Algorithm::Zip, "seed", b"hello").unwrap();

        let union = load_union_corpus(&tmp, &[Algorithm::Gzip, Algorithm::Zip], 0, 16, 0, 0);
        assert_eq!(union.pool.len(), 1);
        assert_eq!(
            algorithm_corpus_dir(&tmp, Algorithm::Gzip)
                .file_name()
                .unwrap(),
            "gzip"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bounded_save_evicts_random_slots_at_cap() {
        let tmp = temp_dir("bounded");
        let mut state = CorpusDirState::new(Vec::new(), Algorithm::Gzip, 1);

        for i in 0..8u8 {
            save_corpus_entry_bounded(&tmp, Algorithm::Gzip, "novel", &[i], &mut state, 4).unwrap();
        }

        let count = std::fs::read_dir(algorithm_corpus_dir(&tmp, Algorithm::Gzip))
            .unwrap()
            .count();
        assert_eq!(count, 4);

        // The cap accounts for what is actually on disk.
        let names: Vec<String> = std::fs::read_dir(algorithm_corpus_dir(&tmp, Algorithm::Gzip))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .collect();
        for name in &names {
            assert!(state.names.contains(name));
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bounded_save_dedupes_without_evicting() {
        let tmp = temp_dir("dedup-evict");
        let mut state = CorpusDirState::new(Vec::new(), Algorithm::Gzip, 1);

        for i in 0..3u8 {
            save_corpus_entry_bounded(&tmp, Algorithm::Gzip, "novel", &[i], &mut state, 3).unwrap();
        }
        // At the cap now; a duplicate of an existing entry must not evict.
        let existing: Vec<String> = state.names.clone();
        let data = [0u8];
        let result =
            save_corpus_entry_bounded(&tmp, Algorithm::Gzip, "novel", &data, &mut state, 3)
                .unwrap();
        assert!(result.is_none());
        assert_eq!(state.names.len(), 3);
        for name in &existing {
            assert!(
                algorithm_corpus_dir(&tmp, Algorithm::Gzip)
                    .join(name)
                    .exists()
            );
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_samples_and_prunes_to_cap() {
        let tmp = temp_dir("prune");
        for i in 0..10u8 {
            save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[i]).unwrap();
        }

        let loaded = load_union_corpus(&tmp, &[Algorithm::Gzip], 0, 16, 4, 7);
        assert_eq!(loaded.pool.len(), 4);
        assert_eq!(loaded.dir_names[&Algorithm::Gzip].len(), 4);
        let remaining = std::fs::read_dir(algorithm_corpus_dir(&tmp, Algorithm::Gzip))
            .unwrap()
            .count();
        assert_eq!(remaining, 4);

        // Same seed reproduces the same sample: rebuild the pre-prune dir,
        // otherwise the second load would trivially adopt all 4 survivors.
        let _ = std::fs::remove_dir_all(algorithm_corpus_dir(&tmp, Algorithm::Gzip));
        for i in 0..10u8 {
            save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[i]).unwrap();
        }
        let again = load_union_corpus(&tmp, &[Algorithm::Gzip], 0, 16, 4, 7);
        assert_eq!(
            again.dir_names[&Algorithm::Gzip],
            loaded.dir_names[&Algorithm::Gzip]
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_unlimited_keeps_everything() {
        let tmp = temp_dir("unlimited");
        for i in 0..10u8 {
            save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[i]).unwrap();
        }

        let loaded = load_union_corpus(&tmp, &[Algorithm::Gzip], 0, 16, 0, 7);
        assert_eq!(loaded.pool.len(), 10);
        assert_eq!(
            std::fs::read_dir(algorithm_corpus_dir(&tmp, Algorithm::Gzip))
                .unwrap()
                .count(),
            10
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_tracks_all_disk_names_not_only_adopted() {
        let tmp = temp_dir("statenames");
        save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[1, 2, 3]).unwrap();
        save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[4, 5, 6]).unwrap();
        let dir = algorithm_corpus_dir(&tmp, Algorithm::Gzip);
        // Out-of-range entry: skipped by the pool but tracked for the cap.
        std::fs::write(dir.join("novel_toolarge.bin"), vec![0u8; 64]).unwrap();

        let loaded = load_union_corpus(&tmp, &[Algorithm::Gzip], 0, 16, 10, 7);
        assert_eq!(loaded.pool.len(), 2);
        assert_eq!(loaded.dir_names[&Algorithm::Gzip].len(), 3);
        assert!(
            loaded.dir_names[&Algorithm::Gzip]
                .iter()
                .any(|n| n == "novel_toolarge.bin")
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn bounded_save_does_not_overwrite_untracked_disk_entry() {
        let tmp = temp_dir("untracked");
        let mut state = CorpusDirState::new(Vec::new(), Algorithm::Gzip, 1);
        let dir = algorithm_corpus_dir(&tmp, Algorithm::Gzip);
        std::fs::create_dir_all(&dir).unwrap();
        let data = [9u8; 4];
        let name = corpus_file_name("novel", &data);
        std::fs::write(dir.join(&name), b"planted").unwrap();

        let result =
            save_corpus_entry_bounded(&tmp, Algorithm::Gzip, "novel", &data, &mut state, 4)
                .unwrap();
        assert!(result.is_none());
        assert_eq!(std::fs::read(dir.join(&name)).unwrap(), b"planted");
        // The untracked file now counts toward the cap.
        assert_eq!(state.names.len(), 1);
        assert_eq!(state.names[0], name);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_prefers_in_range_and_fills_cap_with_out_of_range() {
        let tmp = temp_dir("fill");
        for i in 0..5u8 {
            save_corpus_entry(&tmp, Algorithm::Gzip, "novel", &[i]).unwrap();
        }
        let dir = algorithm_corpus_dir(&tmp, Algorithm::Gzip);
        for i in 0..5u8 {
            std::fs::write(dir.join(format!("novel_big{i}.bin")), vec![0u8; 64]).unwrap();
        }

        // 10 files, cap 6, all 5 eligible must survive; one big file joins.
        let loaded = load_union_corpus(&tmp, &[Algorithm::Gzip], 0, 16, 6, 7);
        assert_eq!(loaded.pool.len(), 5);
        assert_eq!(loaded.dir_names[&Algorithm::Gzip].len(), 6);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            6,
            "exactly the cap should remain, not just the eligible entries"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
