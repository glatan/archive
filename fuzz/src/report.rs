//! Logging, failure persistence, and summary reporting.
//!
//! Progress is logged to stderr as each test completes. On failure, the
//! original input data and a JSON metadata file are saved to the output
//! directory so the issue can be reproduced deterministically.

use crate::algorithms::Algorithm;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Which side of the encode/decode pipeline is handled by an external tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestPattern {
    /// Both encode and decode are performed by our library.
    Self_,
    /// External tool encodes, our library decodes.
    OriginalCompress,
    /// Our library encodes, external tool decodes.
    OriginalDecompress,
    /// Our library encodes, the stream is mutated deterministically, then our
    /// library must decode it without panicking or producing unbounded output.
    Corrupt,
}

impl TestPattern {
    /// Human-readable label used in log lines and file names.
    pub const fn label(self) -> &'static str {
        match self {
            TestPattern::Self_ => "self",
            TestPattern::OriginalCompress => "original-compress",
            TestPattern::OriginalDecompress => "original-decompress",
            TestPattern::Corrupt => "corrupt",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "self" => Some(Self::Self_),
            "original-compress" => Some(Self::OriginalCompress),
            "original-decompress" => Some(Self::OriginalDecompress),
            "corrupt" => Some(Self::Corrupt),
            _ => None,
        }
    }
}

impl std::fmt::Display for TestPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// JSON-serializable record written for each failure.
#[derive(Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub algorithm: String,
    pub pattern: String,
    pub seed: u64,
    pub iteration: u64,
    pub data_size: usize,
    #[serde(default)]
    pub original_size: usize,
    pub data_sha3_512: String,
    pub data_blake3: String,
    pub error: String,
    pub timestamp: String,
    #[serde(default)]
    pub case_label: Option<String>,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub bin_file: String,
    /// Sidecar holding the exact mutated encoded stream that triggered a
    /// corrupt-pattern failure; empty for other patterns.
    #[serde(default)]
    pub mut_file: Option<String>,
    /// Mutation descriptor (e.g. `self/truncate@42`) for corrupt failures.
    #[serde(default)]
    pub mutation: Option<String>,
}

/// All context needed to report and persist a single test failure.
pub struct FailureInfo<'a> {
    pub algo: Algorithm,
    pub pattern: TestPattern,
    pub seed: u64,
    pub iteration: u64,
    pub data: &'a [u8],
    pub original_size: usize,
    pub fingerprint: &'a crate::checksum::DataFingerprint,
    pub error: &'a str,
    pub case_label: Option<String>,
    pub signature: String,
    /// For corrupt failures: the minimized mutated encoded stream to persist
    /// as a `.mut.bin` sidecar.
    pub mutated_stream: Option<&'a [u8]>,
    /// Mutation descriptor (e.g. `fixture#3/truncate@42`).
    pub mutation: Option<String>,
}

/// Aggregate pass/fail counters, broken down by [`TestPattern`].
#[derive(Debug, Default)]
pub struct Stats {
    pub counts: HashMap<TestPattern, u64>,
    pub failures: HashMap<TestPattern, u64>,
    pub known_issues: HashMap<TestPattern, u64>,
    pub duplicates: HashMap<TestPattern, u64>,
}

impl Stats {
    pub fn record_pass(&mut self, pattern: TestPattern) {
        *self.counts.entry(pattern).or_insert(0) += 1;
    }

    pub fn record_failure(&mut self, pattern: TestPattern) {
        *self.counts.entry(pattern).or_insert(0) += 1;
        *self.failures.entry(pattern).or_insert(0) += 1;
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn total_failures(&self) -> u64 {
        self.failures.values().sum()
    }

    pub fn record_known_issue(&mut self, pattern: TestPattern) {
        *self.counts.entry(pattern).or_insert(0) += 1;
        *self.known_issues.entry(pattern).or_insert(0) += 1;
    }

    pub fn record_duplicate(&mut self, pattern: TestPattern) {
        *self.duplicates.entry(pattern).or_insert(0) += 1;
    }
}

/// Log a single test result (OK or FAIL) to stderr.
pub fn log_progress(
    algo: Algorithm,
    pattern: TestPattern,
    iteration: u64,
    data_size: usize,
    elapsed_secs: u64,
    duration_secs: u64,
    ok: bool,
) {
    log_progress_status(
        algo,
        pattern,
        iteration,
        data_size,
        elapsed_secs,
        duration_secs,
        if ok { "OK" } else { "FAIL" },
    );
}

/// Log a single test result with a custom status.
pub fn log_progress_status(
    algo: Algorithm,
    pattern: TestPattern,
    iteration: u64,
    data_size: usize,
    elapsed_secs: u64,
    duration_secs: u64,
    status: &str,
) {
    let now = chrono_now();
    eprintln!(
        "[{now}] {algo} {pattern} #{iteration} {status} (size={data_size}, {elapsed_secs}s/{duration_secs}s)"
    );
}

/// Write a failure report as a single JSON line to stdout.
pub fn emit_failure_json(info: &FailureInfo) {
    let report = failure_report(info, String::new(), None);
    if let Ok(json) = serde_json::to_string(&report) {
        println!("{json}");
    }
}

/// Persist the raw input data (`.bin`) and a JSON metadata file (`.json`)
/// into `output_dir` so the failure can be reproduced later.
pub fn save_failure(output_dir: &Path, info: &FailureInfo) {
    let _ = fs::create_dir_all(output_dir);

    let pattern_str = info.pattern.label().replace('-', "_");
    let signature_fragment =
        sanitize_filename_component(&info.signature.chars().take(16).collect::<String>());
    let case_fragment = info
        .case_label
        .as_deref()
        .map(sanitize_filename_component)
        .filter(|label| !label.is_empty())
        .map(|label| format!("_{label}"))
        .unwrap_or_default();
    let base = format!(
        "{}_{pattern_str}_{}{}_{signature_fragment}",
        info.algo, info.iteration, case_fragment
    );

    // Save input data
    let bin_path = output_dir.join(format!("{base}.bin"));
    if let Ok(mut f) = fs::File::create(&bin_path) {
        let _ = f.write_all(info.data);
    }

    // Save the mutated encoded stream that triggered a corrupt failure so
    // replay and regression generation can target it directly.
    let mut_file = info.mutated_stream.map(|bytes| {
        let name = format!("{base}.mut.bin");
        if let Ok(mut f) = fs::File::create(output_dir.join(&name)) {
            let _ = f.write_all(bytes);
        }
        name
    });

    // Save metadata
    let json_path = output_dir.join(format!("{base}.json"));
    let meta = failure_report(info, format!("{base}.bin"), mut_file);
    if let Ok(json) = serde_json::to_string_pretty(&meta)
        && let Ok(mut f) = fs::File::create(&json_path)
    {
        let _ = f.write_all(json.as_bytes());
    }
}

fn failure_report(info: &FailureInfo, bin_file: String, mut_file: Option<String>) -> FailureReport {
    FailureReport {
        algorithm: info.algo.name().to_string(),
        pattern: info.pattern.label().to_string(),
        seed: info.seed,
        iteration: info.iteration,
        data_size: info.data.len(),
        original_size: info.original_size,
        data_sha3_512: hex_encode(&info.fingerprint.sha3_512),
        data_blake3: hex_encode(&info.fingerprint.blake3),
        error: info.error.to_string(),
        timestamp: iso_now(),
        case_label: info.case_label.clone(),
        signature: info.signature.clone(),
        bin_file,
        mut_file,
        mutation: info.mutation.clone(),
    }
}

/// Print a human-readable summary table to stderr at the end of a run.
pub fn print_summary(duration_secs: u64, algorithms: usize, stats: &Stats) {
    eprintln!();
    eprintln!("=== Fuzz Test Summary ===");
    eprintln!(
        "Duration: {duration_secs}s | Algorithms: {algorithms} | Total: {}",
        stats.total()
    );

    let patterns = [
        TestPattern::Self_,
        TestPattern::OriginalCompress,
        TestPattern::OriginalDecompress,
        TestPattern::Corrupt,
    ];
    for p in &patterns {
        let count = stats.counts.get(p).copied().unwrap_or(0);
        let fail = stats.failures.get(p).copied().unwrap_or(0);
        let known = stats.known_issues.get(p).copied().unwrap_or(0);
        let dup = stats.duplicates.get(p).copied().unwrap_or(0);
        eprintln!(
            "  {:25} {:>6}  (fail: {}, known: {}, dup: {})",
            p.label(),
            count,
            fail,
            known,
            dup
        );
    }

    if stats.total_failures() > 0 {
        eprintln!("Failures saved to output directory");
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn chrono_now() -> String {
    // Simple HH:MM:SS from system time
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn iso_now() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple ISO 8601 UTC
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;

    // Days since epoch to Y-M-D (simplified)
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn create_run_dir(output_root: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(output_root).map_err(|e| format!("create output dir failed: {e}"))?;
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for suffix in 0..1000u32 {
        let name = if suffix == 0 {
            format!("run-{epoch}")
        } else {
            format!("run-{epoch}-{suffix}")
        };
        let run_dir = output_root.join(name);
        if !run_dir.exists() {
            fs::create_dir_all(&run_dir).map_err(|e| format!("create run dir failed: {e}"))?;
            return Ok(run_dir);
        }
    }

    Err("could not allocate unique run directory".to_string())
}

#[derive(Serialize)]
struct RunManifest {
    timestamp: String,
    seed: u64,
    duration_seconds: u64,
    pattern: String,
    min_size: usize,
    max_size: usize,
    algorithms: Vec<String>,
    available_tools: Vec<String>,
}

pub struct RunManifestInfo<'a> {
    pub seed: u64,
    pub duration_seconds: u64,
    pub pattern: &'a str,
    pub min_size: usize,
    pub max_size: usize,
    pub algorithms: &'a [Algorithm],
    pub available_tools: &'a HashSet<Algorithm>,
}

pub fn write_run_manifest(run_dir: &Path, info: RunManifestInfo<'_>) -> Result<(), String> {
    let mut algorithm_names: Vec<_> = info
        .algorithms
        .iter()
        .map(|algo| algo.name().to_string())
        .collect();
    algorithm_names.sort();
    algorithm_names.dedup();

    let mut tool_names: Vec<_> = info
        .available_tools
        .iter()
        .map(|algo| algo.name().to_string())
        .collect();
    tool_names.sort();

    let manifest = RunManifest {
        timestamp: iso_now(),
        seed: info.seed,
        duration_seconds: info.duration_seconds,
        pattern: info.pattern.to_string(),
        min_size: info.min_size,
        max_size: info.max_size,
        algorithms: algorithm_names,
        available_tools: tool_names,
    };
    write_json(run_dir.join("manifest.json"), &manifest)
}

#[derive(Serialize, Deserialize)]
struct PatternSummary {
    pattern: String,
    count: u64,
    failures: u64,
    known_issues: u64,
    duplicates: u64,
}

/// Print the saved `summary.json` of a past run (a run directory or the file
/// itself) to stderr. Read-only; used by `archive-fuzz summary`.
pub fn print_summary_file(path: &Path) -> Result<(), String> {
    let file = if path.is_dir() {
        path.join("summary.json")
    } else {
        path.to_path_buf()
    };
    let text =
        fs::read_to_string(&file).map_err(|e| format!("read {} failed: {e}", file.display()))?;
    let summary: RunSummary =
        serde_json::from_str(&text).map_err(|e| format!("parse {} failed: {e}", file.display()))?;

    eprintln!("=== Fuzz Test Summary ===");
    eprintln!(
        "Timestamp: {} | Duration: {}s | Total: {} (fail: {}, dup: {})",
        summary.timestamp,
        summary.duration_seconds,
        summary.total,
        summary.total_failures,
        summary.total_duplicates
    );
    for p in &summary.patterns {
        eprintln!(
            "  {:25} {:>6}  (fail: {}, known: {}, dup: {})",
            p.pattern, p.count, p.failures, p.known_issues, p.duplicates
        );
    }

    if !summary.failure_buckets.is_empty() {
        eprintln!();
        eprintln!("Failure buckets:");
        let mut buckets: Vec<_> = summary.failure_buckets.iter().collect();
        buckets.sort_by(|a, b| b.1.cmp(a.1));
        for (signature, count) in buckets.iter().take(10) {
            eprintln!("  {count:>4}x {signature}");
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct RunSummary {
    timestamp: String,
    duration_seconds: u64,
    total: u64,
    total_failures: u64,
    total_duplicates: u64,
    patterns: Vec<PatternSummary>,
    failure_buckets: BTreeMap<String, u64>,
}

pub fn write_run_summary(
    run_dir: &Path,
    duration_seconds: u64,
    stats: &Stats,
    failure_buckets: &HashMap<String, u64>,
) -> Result<(), String> {
    let patterns = [
        TestPattern::Self_,
        TestPattern::OriginalCompress,
        TestPattern::OriginalDecompress,
        TestPattern::Corrupt,
    ]
    .into_iter()
    .map(|pattern| PatternSummary {
        pattern: pattern.label().to_string(),
        count: stats.counts.get(&pattern).copied().unwrap_or(0),
        failures: stats.failures.get(&pattern).copied().unwrap_or(0),
        known_issues: stats.known_issues.get(&pattern).copied().unwrap_or(0),
        duplicates: stats.duplicates.get(&pattern).copied().unwrap_or(0),
    })
    .collect();

    let mut sorted_buckets = BTreeMap::new();
    for (signature, count) in failure_buckets {
        sorted_buckets.insert(signature.clone(), *count);
    }

    let summary = RunSummary {
        timestamp: iso_now(),
        duration_seconds,
        total: stats.total(),
        total_failures: stats.total_failures(),
        total_duplicates: stats.duplicates.values().sum(),
        patterns,
        failure_buckets: sorted_buckets,
    };
    write_json(run_dir.join("summary.json"), &summary)
}

#[derive(Serialize)]
struct MatrixRow {
    algorithm: String,
    external_tool_available: bool,
    self_enabled: bool,
    corrupt_enabled: bool,
    original_compress_enabled: bool,
    original_decompress_enabled: bool,
    special_cases: Vec<String>,
}

pub fn write_matrix_report(
    run_dir: &Path,
    algorithms: &[Algorithm],
    available_tools: &HashSet<Algorithm>,
) -> Result<(), String> {
    let rows: Vec<_> = algorithms
        .iter()
        .map(|&algo| {
            let has_tool = available_tools.contains(&algo);
            let no_external = matches!(
                algo,
                Algorithm::Deflate
                    | Algorithm::Zlib
                    | Algorithm::Zpaq
                    | Algorithm::TarGnu
                    | Algorithm::TarUstar
                    | Algorithm::TarPax
                    | Algorithm::Cpio
                    | Algorithm::CpioCrc
            );
            MatrixRow {
                algorithm: algo.name().to_string(),
                external_tool_available: has_tool,
                self_enabled: true,
                corrupt_enabled: true,
                original_compress_enabled: has_tool && !no_external,
                original_decompress_enabled: has_tool && !no_external,
                special_cases: crate::algorithms::special_case_labels(algo)
                    .iter()
                    .map(|label| (*label).to_string())
                    .collect(),
            }
        })
        .collect();

    write_json(run_dir.join("matrix.json"), &rows)
}

pub struct LoadedFailure {
    pub report: FailureReport,
    pub data: Vec<u8>,
}

pub fn load_failure(path: &Path) -> Result<LoadedFailure, String> {
    let (json_path, bin_path) = companion_paths(path)?;
    let report: FailureReport = serde_json::from_slice(
        &fs::read(&json_path).map_err(|e| format!("read failure json failed: {e}"))?,
    )
    .map_err(|e| format!("parse failure json failed: {e}"))?;
    let data = fs::read(&bin_path).map_err(|e| format!("read failure bin failed: {e}"))?;
    // `mut_file` is joined onto the artifact directory by replay/export —
    // reject anything but a bare filename so a crafted report cannot make
    // the harness read or copy files outside that directory.
    if let Some(name) = &report.mut_file
        && !is_bare_name(name)
    {
        return Err(format!("invalid mut_file name in report: {name:?}"));
    }
    Ok(LoadedFailure { report, data })
}

/// A file name that is safe to join onto an artifact directory: exactly
/// one normal path component, no separators or `..`.
fn is_bare_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// Metadata of a `hang-*.json` watchdog artifact. Deliberately not a
/// [`FailureReport`]: the process died before one could be written, so
/// only identification fields exist.
#[derive(Debug)]
pub struct HangMeta {
    pub algorithm: String,
    pub pattern: String,
    pub iteration: u64,
    pub bin_file: String,
}

/// Load a watchdog hang artifact (`hang-*.json`). Returns `Err` for any
/// other file, including valid failure reports.
pub fn load_hang(path: &Path) -> Result<HangMeta, String> {
    #[derive(Deserialize)]
    struct RawHang {
        kind: String,
        algorithm: String,
        pattern: String,
        iteration: u64,
        bin_file: String,
    }
    let raw: RawHang = serde_json::from_slice(
        &fs::read(path).map_err(|e| format!("read hang report failed: {e}"))?,
    )
    .map_err(|e| format!("parse hang report failed: {e}"))?;
    if raw.kind != "hang" {
        return Err(format!("{} is not a hang report", path.display()));
    }
    if !is_bare_name(&raw.bin_file) {
        return Err(format!(
            "invalid bin_file name in hang report: {:?}",
            raw.bin_file
        ));
    }
    Ok(HangMeta {
        algorithm: raw.algorithm,
        pattern: raw.pattern,
        iteration: raw.iteration,
        bin_file: raw.bin_file,
    })
}

pub fn failure_signature(algo: Algorithm, pattern: TestPattern, error: &str) -> String {
    format!(
        "{}|{}|{}",
        algo.name(),
        pattern.label(),
        normalize_error(error)
    )
}

fn companion_paths(path: &Path) -> Result<(PathBuf, PathBuf), String> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    let stem = path
        .file_stem()
        .ok_or_else(|| "failure path must have a file stem".to_string())?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    match extension {
        "json" => Ok((
            path.to_path_buf(),
            parent.join(format!("{}.bin", stem.to_string_lossy())),
        )),
        "bin" => Ok((
            parent.join(format!("{}.json", stem.to_string_lossy())),
            path.to_path_buf(),
        )),
        _ => Err("failure path must point to a .json or .bin artifact".to_string()),
    }
}

fn sanitize_filename_component(input: &str) -> String {
    input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '-',
        })
        .collect()
}

fn normalize_error(error: &str) -> String {
    // A trailing " @ <file>:<line>" panic location is appended verbatim after
    // normalization so distinct panic sites keep distinct signatures.
    let (error, location) = match error.rsplit_once(" @ ") {
        Some((body, loc))
            if loc.rsplit_once(':').is_some_and(|(f, n)| {
                f.ends_with(".rs") && n.bytes().all(|b| b.is_ascii_digit())
            }) =>
        {
            (body, Some(loc))
        }
        _ => (error, None),
    };

    let mut out = String::with_capacity(error.len());
    let mut in_digits = false;
    let mut last_was_space = false;

    for ch in error.chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push('#');
                in_digits = true;
            }
            last_was_space = false;
            continue;
        }
        in_digits = false;
        let normalized = if ch.is_whitespace() {
            ' '
        } else {
            ch.to_ascii_lowercase()
        };
        if normalized == ' ' {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(normalized);
            last_was_space = false;
        }
    }

    let trimmed = out.trim();
    match location {
        Some(loc) => format!("{trimmed} @ {loc}"),
        None => trimmed.to_string(),
    }
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<(), String> {
    let json =
        serde_json::to_vec_pretty(value).map_err(|e| format!("serialize json failed: {e}"))?;
    fs::write(path, json).map_err(|e| format!("write json failed: {e}"))
}

const fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::{FailureInfo, TestPattern, failure_signature, load_failure, save_failure};
    use crate::algorithms::Algorithm;
    use crate::checksum;

    #[test]
    fn normalizes_numeric_noise_in_signatures() {
        let a = failure_signature(
            Algorithm::Gzip,
            TestPattern::OriginalCompress,
            "Checksum mismatch expected 123 actual 456",
        );
        let b = failure_signature(
            Algorithm::Gzip,
            TestPattern::OriginalCompress,
            "checksum mismatch expected 999 actual 111",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn can_load_saved_failure_pair() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-report-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let data = b"replay me";
        let fingerprint = checksum::fingerprint(data);
        let info = FailureInfo {
            algo: Algorithm::Gzip,
            pattern: TestPattern::Self_,
            seed: 7,
            iteration: 1,
            data,
            original_size: data.len(),
            fingerprint: &fingerprint,
            error: "boom 42",
            case_label: Some("case".to_string()),
            signature: failure_signature(Algorithm::Gzip, TestPattern::Self_, "boom 42"),
            mutated_stream: None,
            mutation: None,
        };
        save_failure(&tmp, &info);

        let json = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .unwrap();
        let loaded = load_failure(&json).unwrap();
        assert_eq!(loaded.report.algorithm, "gzip");
        assert_eq!(loaded.data, data);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn print_summary_file_reads_run_dir_and_file() {
        use super::{Stats, print_summary_file, write_run_summary};
        use std::collections::HashMap;

        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-summary-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let run_dir = tmp.join("run-1");
        std::fs::create_dir_all(&run_dir).unwrap();
        let stats = Stats {
            counts: HashMap::new(),
            failures: HashMap::new(),
            known_issues: HashMap::new(),
            duplicates: HashMap::new(),
        };
        write_run_summary(&run_dir, 5, &stats, &HashMap::new()).unwrap();

        assert!(print_summary_file(&run_dir).is_ok());
        assert!(print_summary_file(&run_dir.join("summary.json")).is_ok());
        assert!(print_summary_file(&tmp.join("missing")).is_err());
        std::fs::write(tmp.join("bad.json"), b"not json").unwrap();
        assert!(print_summary_file(&tmp.join("bad.json")).is_err());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
