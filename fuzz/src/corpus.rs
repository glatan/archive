use crate::algorithms::Algorithm;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn load_union_corpus(
    root: &Path,
    algorithms: &[Algorithm],
    min_size: usize,
    max_size: usize,
) -> Vec<Vec<u8>> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for &algo in algorithms {
        for data in load_algorithm_corpus(root, algo, min_size, max_size) {
            let hash = blake3::hash(&data).to_hex().to_string();
            if seen.insert(hash) {
                entries.push(data);
            }
        }
    }

    entries
}

pub fn load_algorithm_corpus(
    root: &Path,
    algo: Algorithm,
    min_size: usize,
    max_size: usize,
) -> Vec<Vec<u8>> {
    let dir = algorithm_corpus_dir(root, algo);
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for entry in read_dir.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let Ok(data) = fs::read(&path) else {
            continue;
        };
        if data.len() < min_size || data.len() > max_size {
            continue;
        }
        entries.push(data);
    }
    entries
}

pub fn save_corpus_entry(
    root: &Path,
    algo: Algorithm,
    label: &str,
    data: &[u8],
) -> Result<Option<PathBuf>, String> {
    let dir = algorithm_corpus_dir(root, algo);
    fs::create_dir_all(&dir).map_err(|e| format!("create corpus dir failed: {e}"))?;

    let hash = blake3::hash(data).to_hex().to_string();
    let prefix = sanitize_component(label);
    let file_name = if prefix.is_empty() {
        format!("{}.bin", &hash[..16])
    } else {
        format!("{}_{}.bin", prefix, &hash[..16])
    };
    let path = dir.join(file_name);
    if path.exists() {
        return Ok(None);
    }

    fs::write(&path, data).map_err(|e| format!("write corpus entry failed: {e}"))?;
    Ok(Some(path))
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
    use super::{algorithm_corpus_dir, load_union_corpus, save_corpus_entry};
    use crate::algorithms::Algorithm;

    #[test]
    fn save_and_load_corpus_deduplicates_by_content() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-corpus-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        save_corpus_entry(&tmp, Algorithm::Gzip, "seed", b"hello").unwrap();
        save_corpus_entry(&tmp, Algorithm::Zip, "seed", b"hello").unwrap();

        let union = load_union_corpus(&tmp, &[Algorithm::Gzip, Algorithm::Zip], 0, 16);
        assert_eq!(union.len(), 1);
        assert_eq!(
            algorithm_corpus_dir(&tmp, Algorithm::Gzip)
                .file_name()
                .unwrap(),
            "gzip"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
