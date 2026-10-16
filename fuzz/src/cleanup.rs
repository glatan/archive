//! Removal of accumulated fuzz artifacts under the failure output directory
//! (`fuzz/failures/`) and the corpus directory (`fuzz/corpus/`).

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

/// Totals reported by [`clean_dir`].
#[derive(Debug, Default)]
pub struct CleanStats {
    /// Removed top-level entries (files and directories).
    pub entries: usize,
    /// Total size in bytes of the removed contents.
    pub bytes: u64,
}

/// Remove every entry inside `dir` except `.gitkeep` and the `keep_latest`
/// newest `run-*` directories, keeping `dir` itself.
///
/// Missing directories are treated as already clean. `dir` must denote a
/// directory when it exists.
pub fn clean_dir(dir: &Path, keep_latest: usize) -> Result<CleanStats, String> {
    // symlink_metadata keeps a symlinked path from being cleaned through:
    // wiping via a link could erase an unrelated tree.
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return Ok(CleanStats::default());
    };
    if !meta.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("read {} failed: {e}", dir.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("read {} failed: {e}", dir.display()))?;

    // `run-<epoch>` and collision form `run-<epoch>-<n>` sort by recency.
    let keep: HashSet<OsString> = if keep_latest > 0 {
        let mut runs: Vec<(u64, u64, OsString)> = entries
            .iter()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| {
                let name = e.file_name();
                parse_run_dir(name.to_str()?).map(|key| (key.0, key.1, name))
            })
            .collect();
        runs.sort_by_key(|a| std::cmp::Reverse((a.0, a.1)));
        runs.into_iter()
            .take(keep_latest)
            .map(|(.., name)| name)
            .collect()
    } else {
        HashSet::new()
    };

    let mut stats = CleanStats::default();
    for entry in entries {
        let name = entry.file_name();
        if name.to_str() == Some(".gitkeep") || keep.contains(&name) {
            continue;
        }
        let path = entry.path();
        stats.bytes += entry_size(&path)?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            fs::remove_dir_all(&path)
                .map_err(|e| format!("remove {} failed: {e}", path.display()))?;
        } else {
            fs::remove_file(&path).map_err(|e| format!("remove {} failed: {e}", path.display()))?;
        }
        stats.entries += 1;
    }
    Ok(stats)
}

/// Parse `run-<epoch>` or `run-<epoch>-<n>` directory names into a sortable
/// `(epoch, n)` recency key.
fn parse_run_dir(name: &str) -> Option<(u64, u64)> {
    let rest = name.strip_prefix("run-")?;
    match rest.split_once('-') {
        Some((epoch, suffix)) => Some((epoch.parse().ok()?, suffix.parse().ok()?)),
        None => Some((rest.parse().ok()?, 0)),
    }
}

fn entry_size(path: &Path) -> Result<u64, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("stat {} failed: {e}", path.display()))?;
    if !meta.is_dir() {
        return Ok(meta.len());
    }
    let mut total = 0;
    for entry in fs::read_dir(path).map_err(|e| format!("read {} failed: {e}", path.display()))? {
        let entry = entry.map_err(|e| format!("read {} failed: {e}", path.display()))?;
        total += entry_size(&entry.path())?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::clean_dir;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "archive-fuzz-clean-test-{tag}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn clean_dir_removes_contents_but_keeps_gitkeep_and_dir() {
        let tmp = temp_dir("basic");
        fs::write(tmp.join(".gitkeep"), b"").unwrap();
        fs::write(tmp.join("replay.bin"), b"12345").unwrap();
        let run = tmp.join("run-1");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("failure-a.bin"), b"abc").unwrap();
        fs::write(run.join("failure-a.json"), b"{}").unwrap();

        let stats = clean_dir(&tmp, 0).unwrap();
        assert_eq!(stats.entries, 2);
        assert_eq!(stats.bytes, 5 + 3 + 2);

        let remaining: Vec<_> = fs::read_dir(&tmp).unwrap().collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].as_ref().unwrap().file_name(), ".gitkeep");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn clean_dir_on_missing_dir_is_noop() {
        let tmp = temp_dir("missing").join("does-not-exist");
        let stats = clean_dir(&tmp, 0).unwrap();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.bytes, 0);
    }

    #[test]
    fn clean_dir_rejects_non_directory() {
        let tmp = temp_dir("file");
        let file = tmp.join("not-a-dir");
        fs::write(&file, b"x").unwrap();

        assert!(clean_dir(&file, 0).is_err());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn clean_dir_removes_symlinks_without_touching_targets() {
        use std::os::unix::fs::symlink;

        let tmp = temp_dir("symlink");
        // Targets outside the cleaned directory must survive.
        let outside = tmp.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep.bin"), b"precious").unwrap();
        let file_target = tmp.join("outside-file.bin");
        fs::write(&file_target, b"precious").unwrap();

        let dir = tmp.join("input");
        fs::create_dir_all(&dir).unwrap();
        symlink(&outside, dir.join("dir-link")).unwrap();
        symlink(&file_target, dir.join("file-link")).unwrap();
        // A self-referential link must not make the size walk recurse.
        symlink(".", dir.join("self-link")).unwrap();
        fs::write(dir.join("real.bin"), b"data").unwrap();

        let stats = clean_dir(&dir, 0).unwrap();
        assert_eq!(stats.entries, 4);

        // Targets are preserved; only the links and real entries were removed.
        assert!(outside.join("keep.bin").exists());
        assert!(file_target.exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn clean_dir_keep_latest_preserves_newest_run_dirs() {
        let tmp = temp_dir("keep");
        for name in ["run-1000", "run-2000", "run-2000-1", "run-3000"] {
            let run = tmp.join(name);
            fs::create_dir_all(&run).unwrap();
            fs::write(run.join("summary.json"), b"{}").unwrap();
        }
        fs::write(tmp.join("stray.bin"), b"x").unwrap();

        let stats = clean_dir(&tmp, 2).unwrap();
        // run-3000 and run-2000-1 stay; run-2000, run-1000 and stray.bin go.
        assert_eq!(stats.entries, 3);
        assert!(tmp.join("run-3000").exists());
        assert!(tmp.join("run-2000-1").exists());
        assert!(!tmp.join("run-2000").exists());
        assert!(!tmp.join("run-1000").exists());
        assert!(!tmp.join("stray.bin").exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn clean_dir_keep_latest_ignores_non_run_entries() {
        let tmp = temp_dir("keep-nonrun");
        fs::create_dir_all(tmp.join("run-1000")).unwrap();
        fs::create_dir_all(tmp.join("run-2000")).unwrap();
        // Directory that starts with "run-" but is not a run dir is not kept.
        fs::create_dir_all(tmp.join("run-notes")).unwrap();
        // A *file* named like a run dir is not kept either.
        fs::write(tmp.join("run-9999"), b"x").unwrap();

        let stats = clean_dir(&tmp, 1).unwrap();
        assert_eq!(stats.entries, 3);
        assert!(tmp.join("run-2000").exists());
        assert!(!tmp.join("run-1000").exists());
        assert!(!tmp.join("run-notes").exists());
        assert!(!tmp.join("run-9999").exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn clean_dir_rejects_symlinked_root() {
        use std::os::unix::fs::symlink;

        let tmp = temp_dir("rootlink");
        let real = tmp.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("keep.bin"), b"x").unwrap();
        let link = tmp.join("link");
        symlink(&real, &link).unwrap();

        assert!(clean_dir(&link, 0).is_err());
        assert!(real.join("keep.bin").exists());

        let _ = fs::remove_dir_all(&tmp);
    }
}
