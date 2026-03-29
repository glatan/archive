//! Core fuzz-test runner.
//!
//! Drives the main loop: generate or mutate inputs, run each selected algorithm
//! through the applicable test patterns, verify integrity via dual-hash
//! fingerprinting, and record/report any failures.

use crate::algorithms::{self, Algorithm};
use crate::checksum;
use crate::corpus;
use crate::datagen;
use crate::external;
use crate::known_issues;
use crate::minimizer;
use crate::report::{self, FailureInfo, Stats, TestPattern};
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternFilter {
    All,
    Self_,
    OriginalCompress,
    OriginalDecompress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    Time,
    CoverageGuided,
}

pub struct RunConfig {
    pub algorithms: Vec<Algorithm>,
    pub duration: Duration,
    pub pattern: PatternFilter,
    pub mode: RunMode,
    pub min_size: usize,
    pub max_size: usize,
    pub seed: u64,
    pub jobs: usize,
    pub output_dir: String,
    pub corpus_dir: String,
}

struct RunState<'a> {
    config: &'a RunConfig,
    available_tools: &'a HashSet<Algorithm>,
    start: Instant,
    duration_secs: u64,
    run_dir: PathBuf,
    corpus_root: PathBuf,
    failure_buckets: Mutex<HashMap<String, u64>>,
    observations: Mutex<HashSet<String>>,
    corpus_pool: Mutex<Vec<Vec<u8>>>,
}

struct TestOutcome {
    decoded: Vec<u8>,
    encoded_size: usize,
    elapsed_millis: u128,
}

const MIN_RUNTIME_ORACLE_MS: u128 = 2_000;
const RUNTIME_SIZE_DIVISOR: usize = 32;
const MAX_ENCODED_SIZE_MULTIPLIER: usize = 128;
const MAX_ENCODED_SIZE_ABSOLUTE: usize = 16 * 1024 * 1024;

pub fn run(config: &RunConfig) -> Stats {
    let available_tools = external::check_available_tools();
    let mut rng = StdRng::seed_from_u64(config.seed);
    let stats = Mutex::new(Stats::default());
    let start = Instant::now();
    let duration_secs = config.duration.as_secs();
    let output_dir = Path::new(&config.output_dir);
    let run_dir = report::create_run_dir(output_dir).unwrap_or_else(|err| {
        panic!(
            "failed to create run directory under {}: {err}",
            output_dir.display()
        )
    });
    report::write_run_manifest(
        &run_dir,
        report::RunManifestInfo {
            seed: config.seed,
            duration_seconds: duration_secs,
            pattern: pattern_label(config.pattern),
            min_size: config.min_size,
            max_size: config.max_size,
            algorithms: &config.algorithms,
            available_tools: &available_tools,
        },
    )
    .unwrap_or_else(|err| panic!("failed to write run manifest: {err}"));
    report::write_matrix_report(&run_dir, &config.algorithms, &available_tools)
        .unwrap_or_else(|err| panic!("failed to write matrix report: {err}"));

    let corpus_root = PathBuf::from(&config.corpus_dir);
    let mut corpus_pool: Vec<Vec<u8>> = datagen::structured_cases(config.min_size, config.max_size)
        .into_iter()
        .map(|case| case.data)
        .collect();
    corpus_pool.extend(corpus::load_union_corpus(
        &corpus_root,
        &config.algorithms,
        config.min_size,
        config.max_size,
    ));

    eprintln!("[info] run directory: {}", run_dir.display());
    eprintln!("[info] corpus directory: {}", corpus_root.display());
    eprintln!("[info] execution mode: {}", mode_label(config.mode));
    eprintln!("[info] jobs: {}", config.jobs.max(1));

    for &algo in &config.algorithms {
        match algo {
            Algorithm::Deflate
            | Algorithm::GzipStore
            | Algorithm::Zlib
            | Algorithm::Zpaq
            | Algorithm::ZpaqLevel2
            | Algorithm::ZpaqLevel3
            | Algorithm::Lz4SmallBlock
            | Algorithm::Snappy
            | Algorithm::Rzip
            | Algorithm::ZipBzip2
            | Algorithm::ZipZstd => {}
            _ => {
                let status = if available_tools.contains(&algo) {
                    "available"
                } else {
                    "NOT FOUND (external tests skipped)"
                };
                eprintln!("[info] {algo}: external tool {status}");
            }
        }
    }
    eprintln!();

    let state = RunState {
        config,
        available_tools: &available_tools,
        start,
        duration_secs,
        run_dir,
        corpus_root,
        failure_buckets: Mutex::new(HashMap::new()),
        observations: Mutex::new(HashSet::new()),
        corpus_pool: Mutex::new(corpus_pool),
    };

    let mut iteration: u64 = 0;
    run_special_cases(&state, &stats, &mut iteration);
    for case in datagen::structured_cases(config.min_size, config.max_size) {
        if start.elapsed() >= config.duration {
            break;
        }
        process_input(
            &state,
            &stats,
            &case.data,
            iteration,
            Some(case.label.as_str()),
        );
        iteration += 1;
    }

    while start.elapsed() < config.duration {
        let data = match config.mode {
            RunMode::Time => datagen::generate(&mut rng, config.min_size, config.max_size),
            RunMode::CoverageGuided => next_guided_input(&state, &mut rng),
        };
        process_input(&state, &stats, &data, iteration, None);
        iteration += 1;
    }

    let final_stats = stats.into_inner().unwrap_or_default();
    report::print_summary(duration_secs, config.algorithms.len(), &final_stats);
    report::write_run_summary(
        &state.run_dir,
        duration_secs,
        &final_stats,
        &state
            .failure_buckets
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
    .unwrap_or_else(|err| panic!("failed to write run summary: {err}"));
    final_stats
}

fn process_input(
    state: &RunState,
    stats: &Mutex<Stats>,
    data: &[u8],
    iteration: u64,
    case_label: Option<&str>,
) {
    if state.config.algorithms.is_empty() {
        return;
    }

    let jobs = state.config.jobs.max(1).min(state.config.algorithms.len());
    if jobs <= 1 {
        for &algo in &state.config.algorithms {
            if state.start.elapsed() >= state.config.duration {
                break;
            }
            run_iteration(state, algo, data, iteration, case_label, stats);
        }
        return;
    }

    let chunk_size = state.config.algorithms.len().div_ceil(jobs);
    thread::scope(|scope| {
        for chunk in state.config.algorithms.chunks(chunk_size) {
            let case_label_owned = case_label.map(ToOwned::to_owned);
            scope.spawn(move || {
                for &algo in chunk {
                    if state.start.elapsed() >= state.config.duration {
                        break;
                    }
                    run_iteration(
                        state,
                        algo,
                        data,
                        iteration,
                        case_label_owned.as_deref(),
                        stats,
                    );
                }
            });
        }
    });
}

fn run_iteration(
    state: &RunState,
    algo: Algorithm,
    data: &[u8],
    iteration: u64,
    case_label: Option<&str>,
    stats: &Mutex<Stats>,
) {
    maybe_record_observation(state, algo, data, case_label);
    let patterns = get_patterns(algo, state.config.pattern, state.available_tools);

    for pattern in patterns {
        let elapsed = state.start.elapsed().as_secs();
        match execute_case(algo, pattern, data) {
            Ok(outcome) => {
                if let Err(oracle_error) =
                    check_resource_oracles(algo, pattern, data.len(), &outcome)
                {
                    report::log_progress(
                        algo,
                        pattern,
                        iteration,
                        data.len(),
                        elapsed,
                        state.duration_secs,
                        false,
                    );
                    let fingerprint = checksum::fingerprint(data);
                    let info = FailureInfo {
                        algo,
                        pattern,
                        seed: state.config.seed,
                        iteration,
                        data,
                        original_size: data.len(),
                        fingerprint: &fingerprint,
                        error: &oracle_error,
                        case_label: case_label.map(ToOwned::to_owned),
                        signature: report::failure_signature(algo, pattern, &oracle_error),
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(pattern);
                    handle_failure_artifact(state, stats, elapsed, &info);
                    continue;
                }
                report::log_progress(
                    algo,
                    pattern,
                    iteration,
                    data.len(),
                    elapsed,
                    state.duration_secs,
                    true,
                );
                stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_pass(pattern);
            }
            Err(error_str) => {
                if let Some(reason) = known_issues::classify(algo, pattern, data, &error_str) {
                    report::log_progress_status(
                        algo,
                        pattern,
                        iteration,
                        data.len(),
                        elapsed,
                        state.duration_secs,
                        "KNOWN",
                    );
                    eprintln!("       ↳ filtered known issue: {reason}");
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_known_issue(pattern);
                    continue;
                }

                report::log_progress(
                    algo,
                    pattern,
                    iteration,
                    data.len(),
                    elapsed,
                    state.duration_secs,
                    false,
                );

                let original_size = data.len();
                let original_signature = report::failure_signature(algo, pattern, &error_str);
                let minimized = minimizer::minimize_failure(data, |candidate| {
                    reproduces_signature(algo, pattern, candidate, &original_signature)
                });
                let minimized_error = execute_case(algo, pattern, &minimized)
                    .err()
                    .unwrap_or(error_str.clone());
                let minimized_signature =
                    report::failure_signature(algo, pattern, &minimized_error);
                let fingerprint = checksum::fingerprint(&minimized);
                let info = FailureInfo {
                    algo,
                    pattern,
                    seed: state.config.seed,
                    iteration,
                    data: &minimized,
                    original_size,
                    fingerprint: &fingerprint,
                    error: &minimized_error,
                    case_label: case_label.map(ToOwned::to_owned),
                    signature: minimized_signature,
                };

                stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_failure(pattern);
                handle_failure_artifact(state, stats, elapsed, &info);
            }
        }
    }
}

fn execute_case(algo: Algorithm, pattern: TestPattern, data: &[u8]) -> Result<TestOutcome, String> {
    let fingerprint = checksum::fingerprint(data);
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_single_test(algo, pattern, data)
    }));
    let elapsed_millis = started.elapsed().as_millis();

    match result {
        Ok(Ok((decoded, encoded_size))) => {
            checksum::verify(&fingerprint, &decoded).map_err(|e| e.to_string())?;
            Ok(TestOutcome {
                decoded,
                encoded_size,
                elapsed_millis,
            })
        }
        Ok(Err(err)) => Err(err.to_string()),
        Err(panic_info) => {
            if let Some(s) = panic_info.downcast_ref::<String>() {
                Err(format!("PANIC: {s}"))
            } else if let Some(s) = panic_info.downcast_ref::<&str>() {
                Err(format!("PANIC: {s}"))
            } else {
                Err("PANIC: unknown".to_string())
            }
        }
    }
}

fn reproduces_signature(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    signature: &str,
) -> bool {
    match execute_case(algo, pattern, data) {
        Ok(_) => false,
        Err(err) => report::failure_signature(algo, pattern, &err) == signature,
    }
}

fn run_special_cases(state: &RunState, stats: &Mutex<Stats>, iteration: &mut u64) {
    let payloads = datagen::structured_cases(state.config.min_size, state.config.max_size);
    let payload = payloads
        .iter()
        .find(|case| !case.data.is_empty())
        .map(|case| case.data.as_slice())
        .unwrap_or(b"special metadata payload" as &[u8]);

    for &algo in &state.config.algorithms {
        for &label in algorithms::special_case_labels(algo) {
            if state.start.elapsed() >= state.config.duration {
                return;
            }
            let elapsed = state.start.elapsed().as_secs();
            match algorithms::run_special_case(algo, label, payload) {
                Ok(decoded) if decoded == payload => {
                    report::log_progress_status(
                        algo,
                        TestPattern::Self_,
                        *iteration,
                        payload.len(),
                        elapsed,
                        state.duration_secs,
                        "SPECIAL",
                    );
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_pass(TestPattern::Self_);
                    let _ = harvest_corpus_entry(state, algo, label, payload);
                }
                Ok(_) => {
                    let error = format!("special case {label} decoded payload mismatch");
                    let fingerprint = checksum::fingerprint(payload);
                    let info = FailureInfo {
                        algo,
                        pattern: TestPattern::Self_,
                        seed: state.config.seed,
                        iteration: *iteration,
                        data: payload,
                        original_size: payload.len(),
                        fingerprint: &fingerprint,
                        error: &error,
                        case_label: Some(format!("special-{label}")),
                        signature: report::failure_signature(algo, TestPattern::Self_, &error),
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(TestPattern::Self_);
                    handle_failure_artifact(state, stats, elapsed, &info);
                }
                Err(error) => {
                    report::log_progress_status(
                        algo,
                        TestPattern::Self_,
                        *iteration,
                        payload.len(),
                        elapsed,
                        state.duration_secs,
                        "SPECIAL-FAIL",
                    );
                    let fingerprint = checksum::fingerprint(payload);
                    let info = FailureInfo {
                        algo,
                        pattern: TestPattern::Self_,
                        seed: state.config.seed,
                        iteration: *iteration,
                        data: payload,
                        original_size: payload.len(),
                        fingerprint: &fingerprint,
                        error: &error,
                        case_label: Some(format!("special-{label}")),
                        signature: report::failure_signature(algo, TestPattern::Self_, &error),
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(TestPattern::Self_);
                    handle_failure_artifact(state, stats, elapsed, &info);
                }
            }
            *iteration += 1;
        }
    }
}

/// Minimum reasonable encoded size for a given algorithm.
///
/// Used as the floor for the encoded-size oracle to avoid false positives on
/// formats that have large mandatory structural overhead even for empty input.
const fn min_encoded_floor(algo: Algorithm) -> usize {
    match algo {
        // GNU tar always writes at least 20 blocks (the default blocking factor)
        // of 512 bytes each = 10240 bytes, regardless of archive content.
        Algorithm::TarGnu | Algorithm::TarPax | Algorithm::TarUstar => 10240,
        _ => 4096,
    }
}

fn check_resource_oracles(
    algo: Algorithm,
    pattern: TestPattern,
    input_size: usize,
    outcome: &TestOutcome,
) -> Result<(), String> {
    let max_runtime = MIN_RUNTIME_ORACLE_MS.max((input_size / RUNTIME_SIZE_DIVISOR) as u128);
    if outcome.elapsed_millis > max_runtime {
        return Err(format!(
            "resource oracle: runtime too high for {algo} {pattern}: {}ms > {}ms",
            outcome.elapsed_millis, max_runtime
        ));
    }

    let encoded_limit = input_size
        .saturating_mul(MAX_ENCODED_SIZE_MULTIPLIER)
        .clamp(min_encoded_floor(algo), MAX_ENCODED_SIZE_ABSOLUTE);
    if outcome.encoded_size > encoded_limit {
        return Err(format!(
            "resource oracle: encoded size too large for {algo} {pattern}: {} > {}",
            outcome.encoded_size, encoded_limit
        ));
    }

    let decoded_limit = input_size
        .saturating_mul(MAX_ENCODED_SIZE_MULTIPLIER)
        .max(4096);
    if outcome.decoded.len() > decoded_limit {
        return Err(format!(
            "resource oracle: decoded size too large for {algo} {pattern}: {} > {}",
            outcome.decoded.len(),
            decoded_limit
        ));
    }

    Ok(())
}

fn handle_failure_artifact(
    state: &RunState,
    stats: &Mutex<Stats>,
    elapsed: u64,
    info: &FailureInfo,
) {
    let duplicate_count = {
        let mut buckets = state
            .failure_buckets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let count = buckets.entry(info.signature.clone()).or_insert(0);
        *count += 1;
        *count
    };

    if duplicate_count == 1 {
        report::emit_failure_json(info);
        report::save_failure(&state.run_dir, info);
        let label = format!(
            "failure-{}",
            info.case_label.as_deref().unwrap_or("generated")
        );
        let _ = harvest_corpus_entry(state, info.algo, &label, info.data);
    } else {
        report::log_progress_status(
            info.algo,
            info.pattern,
            info.iteration,
            info.data.len(),
            elapsed,
            state.duration_secs,
            "DUP",
        );
        eprintln!(
            "       ↳ duplicate failure bucket count={} signature={}",
            duplicate_count, info.signature
        );
        stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .record_duplicate(info.pattern);
    }
}

fn maybe_record_observation(
    state: &RunState,
    algo: Algorithm,
    data: &[u8],
    case_label: Option<&str>,
) {
    let Some(signature) = observation_signature(algo, data) else {
        return;
    };

    let inserted = state
        .observations
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(signature);
    if !inserted {
        return;
    }

    let label = case_label.unwrap_or("novel");
    let _ = harvest_corpus_entry(state, algo, label, data);
}

fn harvest_corpus_entry(
    state: &RunState,
    algo: Algorithm,
    label: &str,
    data: &[u8],
) -> Result<(), String> {
    if let Some(path) = corpus::save_corpus_entry(&state.corpus_root, algo, label, data)? {
        state
            .corpus_pool
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(data.to_vec());
        eprintln!("[corpus] saved {} -> {}", algo.name(), path.display());
    }
    Ok(())
}

fn observation_signature(algo: Algorithm, data: &[u8]) -> Option<String> {
    let encoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        algorithms::encode_with(algo, data)
    }))
    .ok()?;
    let prefix = encoded
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    Some(format!(
        "{}|in:{}|enc:{}|ratio:{}|head:{}",
        algo.name(),
        size_bucket(data.len()),
        size_bucket(encoded.len()),
        ratio_bucket(data.len(), encoded.len()),
        prefix
    ))
}

fn next_guided_input(state: &RunState, rng: &mut StdRng) -> Vec<u8> {
    let maybe_base: Option<Vec<u8>> = {
        let pool = state.corpus_pool.lock().unwrap_or_else(|e| e.into_inner());
        if pool.is_empty() {
            None
        } else {
            Some(pool[rng.random_range(0..pool.len())].clone())
        }
    };

    match maybe_base {
        Some(base) => datagen::mutate(rng, &base, state.config.min_size, state.config.max_size),
        None => datagen::generate(rng, state.config.min_size, state.config.max_size),
    }
}

fn get_patterns(
    algo: Algorithm,
    filter: PatternFilter,
    available_tools: &HashSet<Algorithm>,
) -> Vec<TestPattern> {
    let has_tool = available_tools.contains(&algo);
    let no_external = matches!(
        algo,
        Algorithm::Deflate
            | Algorithm::GzipStore
            | Algorithm::Zlib
            | Algorithm::Zpaq
            | Algorithm::ZpaqLevel2
            | Algorithm::ZpaqLevel3
            | Algorithm::Lz4SmallBlock
            | Algorithm::Snappy
            | Algorithm::Rzip
            | Algorithm::ZipBzip2
            | Algorithm::ZipZstd
    );

    match filter {
        PatternFilter::All => {
            let mut patterns = vec![TestPattern::Self_];
            if has_tool && !no_external {
                patterns.push(TestPattern::OriginalCompress);
                patterns.push(TestPattern::OriginalDecompress);
            }
            patterns
        }
        PatternFilter::Self_ => vec![TestPattern::Self_],
        PatternFilter::OriginalCompress if has_tool && !no_external => {
            vec![TestPattern::OriginalCompress]
        }
        PatternFilter::OriginalDecompress if has_tool && !no_external => {
            vec![TestPattern::OriginalDecompress]
        }
        _ => Vec::new(),
    }
}

fn run_single_test(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
) -> Result<(Vec<u8>, usize), String> {
    match pattern {
        TestPattern::Self_ => {
            let encoded = algorithms::encode_with(algo, data);
            let encoded_size = encoded.len();
            algorithms::decode_with(algo, &encoded)
                .map(|decoded| (decoded, encoded_size))
                .map_err(|e| format!("{e}"))
        }
        TestPattern::OriginalCompress => {
            let compressed = external::compress(algo, data)?;
            let encoded_size = compressed.len();
            algorithms::decode_with(algo, &compressed)
                .map(|decoded| (decoded, encoded_size))
                .map_err(|e| format!("{e}"))
        }
        TestPattern::OriginalDecompress => {
            let encoded = algorithms::encode_with(algo, data);
            let encoded_size = encoded.len();
            external::decompress(algo, &encoded).map(|decoded| (decoded, encoded_size))
        }
    }
}

pub fn replay_failure(path: &Path) -> Result<(), String> {
    let loaded = report::load_failure(path)?;
    let algo = Algorithm::from_name(&loaded.report.algorithm).ok_or_else(|| {
        format!(
            "unknown algorithm in failure report: {}",
            loaded.report.algorithm
        )
    })?;
    let pattern = TestPattern::from_label(&loaded.report.pattern).ok_or_else(|| {
        format!(
            "unknown pattern in failure report: {}",
            loaded.report.pattern
        )
    })?;

    eprintln!(
        "[replay] algorithm={} pattern={} seed={} iteration={} size={} original_size={}",
        loaded.report.algorithm,
        loaded.report.pattern,
        loaded.report.seed,
        loaded.report.iteration,
        loaded.data.len(),
        loaded.report.original_size.max(loaded.data.len())
    );

    match execute_case(algo, pattern, &loaded.data) {
        Ok(_) => {
            eprintln!("[replay] success: failure no longer reproduces");
            Ok(())
        }
        Err(err) => Err(format!("replay reproduced error: {err}")),
    }
}

const fn pattern_label(pattern: PatternFilter) -> &'static str {
    match pattern {
        PatternFilter::All => "all",
        PatternFilter::Self_ => "self",
        PatternFilter::OriginalCompress => "original-compress",
        PatternFilter::OriginalDecompress => "original-decompress",
    }
}

const fn mode_label(mode: RunMode) -> &'static str {
    match mode {
        RunMode::Time => "time",
        RunMode::CoverageGuided => "coverage-guided",
    }
}

const fn size_bucket(len: usize) -> &'static str {
    match len {
        0 => "0",
        1..=3 => "1-3",
        4..=7 => "4-7",
        8..=15 => "8-15",
        16..=31 => "16-31",
        32..=63 => "32-63",
        64..=127 => "64-127",
        128..=255 => "128-255",
        256..=511 => "256-511",
        512..=1023 => "512-1023",
        1024..=4095 => "1k-4k",
        4096..=16383 => "4k-16k",
        16384..=65535 => "16k-64k",
        65536..=262143 => "64k-256k",
        _ => "256k+",
    }
}

fn ratio_bucket(input_len: usize, encoded_len: usize) -> &'static str {
    if input_len == 0 {
        return "empty";
    }
    let ratio = (encoded_len as f64) / (input_len as f64);
    if ratio < 0.25 {
        "lt-0.25"
    } else if ratio < 0.5 {
        "lt-0.5"
    } else if ratio < 0.75 {
        "lt-0.75"
    } else if ratio < 1.0 {
        "lt-1.0"
    } else if ratio < 1.5 {
        "lt-1.5"
    } else {
        "ge-1.5"
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PatternFilter, RunConfig, RunMode, RunState, get_patterns, handle_failure_artifact,
        observation_signature,
    };
    use crate::algorithms::Algorithm;
    use crate::checksum;
    use crate::report::{FailureInfo, Stats, TestPattern};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[test]
    fn new_archive_targets_get_external_patterns_when_tools_exist() {
        let available: HashSet<_> = [
            Algorithm::Ar,
            Algorithm::ArBsd,
            Algorithm::Zip,
            Algorithm::SevenZ,
        ]
        .into_iter()
        .collect();
        assert_eq!(
            get_patterns(Algorithm::Zip, PatternFilter::All, &available),
            vec![
                TestPattern::Self_,
                TestPattern::OriginalCompress,
                TestPattern::OriginalDecompress,
            ]
        );
    }

    #[test]
    fn duplicate_failures_are_bucketed_once() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-runner-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();

        let config = RunConfig {
            algorithms: vec![Algorithm::Gzip],
            duration: Duration::from_secs(1),
            pattern: PatternFilter::Self_,
            mode: RunMode::Time,
            min_size: 0,
            max_size: 16,
            seed: 1,
            jobs: 1,
            output_dir: tmp.display().to_string(),
            corpus_dir: tmp.join("corpus").display().to_string(),
        };
        let available_tools = HashSet::new();
        let state = RunState {
            config: &config,
            available_tools: &available_tools,
            start: Instant::now(),
            duration_secs: 1,
            run_dir: PathBuf::from(&tmp),
            corpus_root: tmp.join("corpus"),
            failure_buckets: Mutex::new(HashMap::new()),
            observations: Mutex::new(HashSet::new()),
            corpus_pool: Mutex::new(Vec::new()),
        };

        let data = b"boom";
        let fingerprint = checksum::fingerprint(data);
        let info = FailureInfo {
            algo: Algorithm::Gzip,
            pattern: TestPattern::Self_,
            seed: 1,
            iteration: 0,
            data,
            original_size: data.len(),
            fingerprint: &fingerprint,
            error: "checksum mismatch 1 2",
            case_label: Some("case".to_string()),
            signature: crate::report::failure_signature(
                Algorithm::Gzip,
                TestPattern::Self_,
                "checksum mismatch 1 2",
            ),
        };

        let stats = Mutex::new(Stats::default());
        stats.lock().unwrap().record_failure(TestPattern::Self_);
        handle_failure_artifact(&state, &stats, 0, &info);
        stats.lock().unwrap().record_failure(TestPattern::Self_);
        handle_failure_artifact(&state, &stats, 0, &info);

        let json_count = std::fs::read_dir(&tmp)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .count();
        assert_eq!(json_count, 1);
        assert_eq!(
            stats
                .lock()
                .unwrap()
                .duplicates
                .get(&TestPattern::Self_)
                .copied(),
            Some(1)
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn observation_signature_is_stable() {
        let a = observation_signature(Algorithm::Gzip, b"aaaa").unwrap();
        let b = observation_signature(Algorithm::Gzip, b"aaaa").unwrap();
        assert_eq!(a, b);
    }
}
