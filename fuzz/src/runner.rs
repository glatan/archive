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
use crate::fixtures;
use crate::known_issues;
use crate::minimizer;
use crate::report::{self, FailureInfo, Stats, TestPattern};
use crate::watchdog;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::{HashMap, HashSet, hash_map::Entry};
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
    Corrupt,
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
    pub fixtures_dir: String,
    /// Per-algorithm cap on corpus entries; `0` means unlimited.
    pub corpus_max_entries: usize,
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
    /// Per-algorithm on-disk corpus accounting for bounded saves. Per-algorithm
    /// locks keep `--jobs > 1` harvests from serializing on one global mutex.
    corpus_state: HashMap<Algorithm, Mutex<corpus::CorpusDirState>>,
    /// Count of harvest pushes admitted into corpus_pool under the cap;
    /// pool.len() cannot serve because load-adopted entries share the pool.
    /// The bound is global across algorithms while the on-disk cap stays
    /// per-algorithm.
    harvested_corpus: Mutex<usize>,
}

struct TestOutcome {
    decoded: Vec<u8>,
    encoded_size: usize,
    elapsed_millis: u128,
}

/// A case failure. For the corrupt pattern it also carries the exact mutated
/// encoded stream that triggered the failure, so the artifact can store it as
/// a `.mut.bin` sidecar and replay/minimization can target it directly.
struct CaseError {
    message: String,
    mutated_stream: Option<Vec<u8>>,
    mutation: Option<String>,
}

impl CaseError {
    fn simple(message: String) -> Self {
        Self {
            message,
            mutated_stream: None,
            mutation: None,
        }
    }
}

impl From<String> for CaseError {
    fn from(message: String) -> Self {
        Self::simple(message)
    }
}

thread_local! {
    /// Panic source location recorded by [`install_panic_hook`] for the
    /// current worker thread, consumed by [`panic_message`].
    static LAST_PANIC_LOC: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Chain a panic hook that records `file:line` of every panic so failure
/// signatures can distinguish independent panic sites. Idempotent.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            LAST_PANIC_LOC.with(|cell| {
                *cell.borrow_mut() = info
                    .location()
                    .map(|loc| format!("{}:{}", loc.file(), loc.line()));
            });
            default_hook(info);
        }));
    });
}

const MIN_RUNTIME_ORACLE_MS: u128 = 2_000;
const RUNTIME_SIZE_DIVISOR: usize = 32;
const MAX_ENCODED_SIZE_MULTIPLIER: usize = 128;
const MAX_ENCODED_SIZE_ABSOLUTE: usize = 16 * 1024 * 1024;
/// Upper bound on wall-clock time spent minimizing a single failure input.
const MINIMIZE_BUDGET: Duration = Duration::from_secs(120);

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
    watchdog::init(&run_dir);
    let stale = watchdog::count_stale_breadcrumbs(output_dir);
    if stale > 0 {
        eprintln!(
            "[warn] found {stale} stale in-flight breadcrumbs under {} \
             (a previous run or replay aborted mid-case; ignore if another run is active)",
            output_dir.display()
        );
    }
    fixtures::init(Path::new(&config.fixtures_dir));
    install_panic_hook();
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
    // Loading prunes oversized corpus dirs down to the cap; the adopted file
    // names it reports seed the in-memory accounting for bounded saves, so the
    // state always reflects the post-prune directory.
    let loaded = corpus::load_union_corpus(
        &corpus_root,
        &config.algorithms,
        config.min_size,
        config.max_size,
        config.corpus_max_entries,
        config.seed,
    );
    corpus_pool.extend(loaded.pool);
    let corpus_state = loaded
        .dir_names
        .into_iter()
        .map(|(algo, names)| {
            (
                algo,
                Mutex::new(corpus::CorpusDirState::new(names, algo, config.seed)),
            )
        })
        .collect();

    eprintln!("[info] run directory: {}", run_dir.display());
    eprintln!("[info] corpus directory: {}", corpus_root.display());
    if config.corpus_max_entries > 0 {
        eprintln!(
            "[info] corpus cap: {} entries per algorithm",
            config.corpus_max_entries
        );
    }
    eprintln!("[info] execution mode: {}", mode_label(config.mode));
    eprintln!("[info] jobs: {}", config.jobs.max(1));

    for &algo in &config.algorithms {
        if external::has_tool_spec(algo) {
            let status = if available_tools.contains(&algo) {
                "available"
            } else {
                "NOT FOUND (external tests skipped)"
            };
            eprintln!("[info] {algo}: external tool {status}");
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
        corpus_state,
        harvested_corpus: Mutex::new(0),
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
    let patterns = match get_patterns(algo, state.config.pattern, state.available_tools) {
        Ok(patterns) => patterns,
        Err(error) => {
            let elapsed = state.start.elapsed().as_secs();
            let pattern = match state.config.pattern {
                PatternFilter::OriginalCompress => TestPattern::OriginalCompress,
                _ => TestPattern::OriginalDecompress,
            };
            let fingerprint = checksum::fingerprint(data);
            let info = FailureInfo {
                algo,
                pattern,
                seed: state.config.seed,
                iteration,
                data,
                original_size: data.len(),
                fingerprint: &fingerprint,
                error: &error,
                case_label: case_label.map(ToOwned::to_owned),
                signature: report::failure_signature(algo, pattern, &error),
                mutated_stream: None,
                mutation: None,
            };
            stats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_failure(pattern);
            handle_failure_artifact(state, stats, elapsed, &info, false);
            return;
        }
    };

    for pattern in patterns {
        let elapsed = state.start.elapsed().as_secs();
        match execute_case(algo, pattern, data, iteration) {
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
                        mutated_stream: None,
                        mutation: None,
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(pattern);
                    handle_failure_artifact(state, stats, elapsed, &info, false);
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
            Err(case_err) => {
                if let Some(reason) = known_issues::classify(algo, pattern, data, &case_err.message)
                {
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
                let error_str = case_err.message.clone();
                let original_signature = report::failure_signature(algo, pattern, &error_str);
                // Atomically claim the signature bucket so a duplicate
                // failure — including one raised by another job — skips
                // minimization. The entry stays at 0 until the artifact for
                // this occurrence is recorded below.
                let duplicate_count = {
                    let mut buckets = state
                        .failure_buckets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    match buckets.entry(original_signature.clone()) {
                        Entry::Occupied(mut entry) => {
                            *entry.get_mut() += 1;
                            Some(*entry.get())
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(0);
                            None
                        }
                    }
                };
                if let Some(count) = duplicate_count {
                    report::log_progress_status(
                        algo,
                        pattern,
                        iteration,
                        data.len(),
                        elapsed,
                        state.duration_secs,
                        "DUP",
                    );
                    eprintln!(
                        "       ↳ duplicate failure bucket count={count} signature={original_signature}"
                    );
                    let mut stats = stats.lock().unwrap_or_else(|e| e.into_inner());
                    stats.record_failure(pattern);
                    stats.record_duplicate(pattern);
                    continue;
                }

                // A corrupt failure is caused by the mutated encoded stream,
                // not by the original input: minimize the reproducer itself
                // and keep the original input as provenance in `.bin`.
                let minimized_mutated = case_err.mutated_stream.as_ref().map(|mutated| {
                    let decoded_limit = corrupt_decoded_limit(algo, original_size);
                    // Minimization probes the mutated stream directly —
                    // outside the per-case guard — so it needs its own
                    // in-flight entry; each probe refreshes it via
                    // note_data without further file I/O.
                    let _inflight = watchdog::enter(algo, pattern, iteration, mutated);
                    minimizer::minimize_failure(
                        mutated,
                        |candidate| {
                            reproduces_corrupt_signature(
                                algo,
                                candidate,
                                &original_signature,
                                decoded_limit,
                            )
                        },
                        MINIMIZE_BUDGET,
                    )
                });
                let minimized = if minimized_mutated.is_some() {
                    data.to_vec()
                } else {
                    let _inflight = watchdog::enter(algo, pattern, iteration, data);
                    minimizer::minimize_failure(
                        data,
                        |candidate| {
                            reproduces_signature(
                                algo,
                                pattern,
                                candidate,
                                iteration,
                                &original_signature,
                            )
                        },
                        MINIMIZE_BUDGET,
                    )
                };
                let minimized_error = match &minimized_mutated {
                    Some(mutated) => {
                        let _inflight = watchdog::enter(algo, pattern, iteration, mutated);
                        corrupt_probe(algo, mutated, corrupt_decoded_limit(algo, original_size))
                            .err()
                            .unwrap_or_else(|| error_str.clone())
                    }
                    None => execute_case(algo, pattern, &minimized, iteration)
                        .err()
                        .map(|e| e.message)
                        .unwrap_or_else(|| error_str.clone()),
                };
                let minimized_signature =
                    report::failure_signature(algo, pattern, &minimized_error);
                // The claim covers `minimized_signature` only if minimization
                // preserved the signature; otherwise release the placeholder
                // so the real signature is bucketed on its own.
                let claimed = minimized_signature == original_signature;
                if !claimed {
                    let mut buckets = state
                        .failure_buckets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if buckets.get(&original_signature) == Some(&0) {
                        buckets.remove(&original_signature);
                    }
                }
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
                    mutated_stream: minimized_mutated.as_deref(),
                    mutation: case_err.mutation.clone(),
                };

                stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record_failure(pattern);
                handle_failure_artifact(state, stats, elapsed, &info, claimed);
            }
        }
    }
}

/// MPPC is a packet codec: one packet carries at most `history` bytes of
/// payload, so cap the input instead of misrepresenting larger inputs.
///
/// Other encoders have format-level size ceilings too (e.g. cramfs's 24-bit
/// file-size field ~16 MiB, iso9660 u32::MAX, mscfb-v3 2 GiB streams) — all
/// unreachable at the default `--max-size` of 1 MiB, but candidates for this
/// table if the limit is ever raised.
fn packet_cap(algo: Algorithm) -> usize {
    match algo {
        Algorithm::Mppc | Algorithm::MppcRdp4 => archive::compress::mppc::HISTORY_SIZE,
        Algorithm::MppcRdp5 => archive::compress::mppc::HISTORY_SIZE_64K,
        _ => usize::MAX,
    }
}

fn execute_case(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    iteration: u64,
) -> Result<TestOutcome, CaseError> {
    let data = &data[..data.len().min(packet_cap(algo))];
    // Register before any library call so a hang or uncatchable abort leaves
    // a persisted breadcrumb the watchdog (or a post-mortem) can identify.
    let _inflight = watchdog::enter(algo, pattern, iteration, data);
    let fingerprint = checksum::fingerprint(data);
    let started = Instant::now();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_single_test(algo, pattern, data)
    }));
    let elapsed_millis = started.elapsed().as_millis();

    match result {
        Ok(Ok((decoded, encoded_size))) => {
            checksum::verify(&fingerprint, &decoded)
                .map_err(|e| CaseError::simple(e.to_string()))?;
            Ok(TestOutcome {
                decoded,
                encoded_size,
                elapsed_millis,
            })
        }
        Ok(Err(err)) => Err(err),
        Err(panic_info) => Err(CaseError::simple(format!(
            "PANIC: {}",
            panic_message(panic_info.as_ref())
        ))),
    }
}

fn panic_message(panic_info: &dyn std::any::Any) -> String {
    let msg = if let Some(s) = panic_info.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = panic_info.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "unknown".to_string()
    };
    // Append the panic site so signatures distinguish independent panic
    // locations instead of collapsing them into one normalized bucket.
    match LAST_PANIC_LOC.with(|cell| cell.borrow_mut().take()) {
        Some(loc) => format!("{msg} @ {loc}"),
        None => msg,
    }
}

fn reproduces_signature(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
    iteration: u64,
    signature: &str,
) -> bool {
    match execute_case(algo, pattern, data, iteration) {
        Ok(_) => false,
        Err(err) => report::failure_signature(algo, pattern, &err.message) == signature,
    }
}

/// Whether decoding `candidate` (a mutated encoded stream) still fails with
/// the same signature, used to minimize corrupt-pattern reproducers.
fn reproduces_corrupt_signature(
    algo: Algorithm,
    candidate: &[u8],
    signature: &str,
    decoded_limit: usize,
) -> bool {
    match corrupt_probe(algo, candidate, decoded_limit) {
        Ok(()) => false,
        Err(err) => report::failure_signature(algo, TestPattern::Corrupt, &err) == signature,
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
            // Special cases may panic or hang inside library encode/decode;
            // capture panics as failures and leave a watchdog breadcrumb.
            let payload = &payload[..payload.len().min(packet_cap(algo))];
            let _inflight = watchdog::enter(algo, TestPattern::Self_, *iteration, payload);
            let case_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                algorithms::run_special_case(algo, label, payload)
            }))
            .unwrap_or_else(|panic| Err(format!("PANIC: {}", panic_message(panic.as_ref()))));
            match case_result {
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
                        mutated_stream: None,
                        mutation: None,
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(TestPattern::Self_);
                    handle_failure_artifact(state, stats, elapsed, &info, false);
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
                        mutated_stream: None,
                        mutation: None,
                    };
                    stats
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_failure(TestPattern::Self_);
                    handle_failure_artifact(state, stats, elapsed, &info, false);
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
        // cmpsc always emits a fixed 4KiB alphabet dictionary plus a 6-byte
        // header even for empty input, and deb wraps payloads in an ar
        // archive holding two tar members; both exceed 4KiB of structural
        // overhead on tiny inputs.
        Algorithm::Cmpsc | Algorithm::Deb => 8192,
        // ISO9660 needs ~21 sectors of mandatory structure even for an
        // empty image (16-sector system area, volume descriptor set and
        // terminator, plus both path tables): ~43008 bytes minimum.
        Algorithm::Iso9660 | Algorithm::IsoRr => 45056,
        // MSCFB v4 uses 4096-byte sectors and emits at least five of them
        // (header, FAT, directory, MiniFAT, mini stream) once a stream is
        // stored: 20480 bytes observed for a single-byte input. Six sectors
        // leaves headroom for metadata growth.
        Algorithm::MscfbV4 => 24576,
        _ => 4096,
    }
}

fn check_resource_oracles(
    algo: Algorithm,
    pattern: TestPattern,
    input_size: usize,
    outcome: &TestOutcome,
) -> Result<(), String> {
    // The corrupt pattern runs a fixed schedule of many decode attempts, so
    // per-case wall time scales with the schedule rather than input size and
    // the runtime oracle would false-positive on heavy decoders. Genuine
    // stalls are covered by the watchdog; oversized decode output is checked
    // per attempt inside `run_corrupt_case`.
    if pattern != TestPattern::Corrupt {
        let max_runtime = MIN_RUNTIME_ORACLE_MS.max((input_size / RUNTIME_SIZE_DIVISOR) as u128);
        if outcome.elapsed_millis > max_runtime {
            return Err(format!(
                "resource oracle: runtime too high for {algo} {pattern}: {}ms > {}ms",
                outcome.elapsed_millis, max_runtime
            ));
        }
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

    // For the corrupt pattern `decoded` echoes the input verbatim, so the
    // decoded-size check can never fire; mutated-decode output is bounded by
    // `run_corrupt_case` itself.
    let decoded_limit = input_size
        .saturating_mul(MAX_ENCODED_SIZE_MULTIPLIER)
        .max(4096);
    if pattern != TestPattern::Corrupt && outcome.decoded.len() > decoded_limit {
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
    claimed: bool,
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

    // A claimed signature belongs to this occurrence: duplicate counts may
    // already have been recorded while minimization was in flight, but the
    // artifact must still be saved here.
    if claimed || duplicate_count == 1 {
        report::emit_failure_json(info);
        report::save_failure(&state.run_dir, info);
        let label = format!(
            "failure-{}",
            info.case_label.as_deref().unwrap_or("generated")
        );
        let _ = harvest_corpus_entry(state, info.algo, &label, info.data);
        // For corrupt failures the minimized mutated stream is itself an
        // interesting seed: harvesting it feeds dense encoded-structure
        // inputs back into guided mutation.
        if let Some(mutated) = info.mutated_stream {
            let _ = harvest_corpus_entry(state, info.algo, &format!("{label}-mut"), mutated);
        }
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
    // Sign and harvest the same capped view `execute_case` runs on; the
    // uncapped input would panic packet-codec encoders inside
    // `observation_signature` and silently drop the observation.
    let data = &data[..data.len().min(packet_cap(algo))];
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
    let max_entries = state.config.corpus_max_entries;
    let saved = match state.corpus_state.get(&algo) {
        Some(algo_state) if max_entries > 0 => {
            // Lock order is one-directional: corpus_state, then
            // harvested_corpus / corpus_pool below. Nothing locks in reverse.
            let mut dir_state = algo_state.lock().unwrap_or_else(|e| e.into_inner());
            corpus::save_corpus_entry_bounded(
                &state.corpus_root,
                algo,
                label,
                data,
                &mut dir_state,
                max_entries,
            )?
        }
        _ => corpus::save_corpus_entry(&state.corpus_root, algo, label, data)?,
    };

    if let Some(path) = saved {
        // The cap bounds harvest pushes only; entries adopted at load are
        // already bounded by the per-algorithm directory cap. Counting pushes
        // rather than pool.len() keeps a large adopted corpus from starving
        // new observations for the whole run.
        if max_entries == 0 {
            state
                .corpus_pool
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(data.to_vec());
        } else {
            let mut harvested = state
                .harvested_corpus
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if *harvested < max_entries {
                state
                    .corpus_pool
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(data.to_vec());
                *harvested += 1;
            }
        }
        eprintln!("[corpus] saved {} -> {}", algo.name(), path.display());
    }
    Ok(())
}

fn observation_signature(algo: Algorithm, data: &[u8]) -> Option<String> {
    // Cap here too so a direct call on an oversized packet-codec input
    // produces a signature instead of panicking inside `encode_with`.
    let data = &data[..data.len().min(packet_cap(algo))];
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
) -> Result<Vec<TestPattern>, String> {
    let has_tool = available_tools.contains(&algo);

    match filter {
        PatternFilter::All => {
            // Every algorithm runs self and corrupt, including level aliases.
            // original-* is added when that algorithm's tool is installed.
            // An explicit original-* pattern still fails if the tool is absent.
            let mut patterns = vec![TestPattern::Self_, TestPattern::Corrupt];
            if has_tool {
                patterns.push(TestPattern::OriginalCompress);
                patterns.push(TestPattern::OriginalDecompress);
            }
            Ok(patterns)
        }
        PatternFilter::Self_ => Ok(vec![TestPattern::Self_]),
        PatternFilter::Corrupt => Ok(vec![TestPattern::Corrupt]),
        PatternFilter::OriginalCompress | PatternFilter::OriginalDecompress if has_tool => {
            Ok(vec![match filter {
                PatternFilter::OriginalCompress => TestPattern::OriginalCompress,
                _ => TestPattern::OriginalDecompress,
            }])
        }
        PatternFilter::OriginalCompress | PatternFilter::OriginalDecompress => {
            Err(format!("external tool for {algo} is not available"))
        }
    }
}

fn run_single_test(
    algo: Algorithm,
    pattern: TestPattern,
    data: &[u8],
) -> Result<(Vec<u8>, usize), CaseError> {
    match pattern {
        TestPattern::Self_ => {
            let encoded = algorithms::encode_with(algo, data);
            let encoded_size = encoded.len();
            // mtree is a metadata-only manifest: the generated spec carries
            // no payload, so verify it decodes and echo the input back as
            // the round-trip result.
            if algo == Algorithm::Mtree {
                algorithms::decode_with(algo, &encoded)
                    .map(|_| (data.to_vec(), encoded_size))
                    .map_err(|e| CaseError::simple(format!("{e}")))
            } else {
                algorithms::decode_with(algo, &encoded)
                    .map_err(|e| CaseError::simple(format!("{e}")))
                    .and_then(|decoded| {
                        algorithms::check_prefixed_decode_into(algo, &encoded, None)
                            .map_err(CaseError::simple)?;
                        Ok((decoded, encoded_size))
                    })
            }
        }
        TestPattern::OriginalCompress => {
            let compressed = external::compress(algo, data)?;
            let encoded_size = compressed.len();
            algorithms::decode_with(algo, &compressed)
                .map(|decoded| (decoded, encoded_size))
                .map_err(|e| CaseError::simple(format!("{e}")))
        }
        TestPattern::OriginalDecompress => {
            let encoded = algorithms::encode_with(algo, data);
            let encoded_size = encoded.len();
            external::decompress(algo, &encoded)
                .map(|decoded| (decoded, encoded_size))
                .map_err(CaseError::from)
        }
        TestPattern::Corrupt => run_corrupt_case(algo, data),
    }
}

/// Number of randomly mutated decode attempts per corrupt-pattern case.
const CORRUPT_ATTEMPTS: usize = 4;
/// Interior truncation offsets sampled for streams too large to sweep
/// exhaustively; fixed edge and near-tail offsets are added on top.
const TRUNCATION_POINTS: usize = 24;
/// Head/tail byte span treated as field territory for boundary-value writes.
const BOUNDARY_FIELD_SPAN: usize = 32;
/// Boundary values written (little-endian u32) into field positions.
const BOUNDARY_VALUES: [u32; 4] = [0, 0xFF, 0xFFFF, 0xFFFF_FFFF];

/// Decode-mutation robustness check: encode the input, then feed the decoder
/// deterministic corruptions — random mutations, prefix truncations, and
/// boundary-value writes into head/tail field regions — plus one rotating
/// real tool-produced fixture under the same schedule. Every corruption must
/// be handled without a panic and without emitting a suspiciously large
/// output; graceful `Err` results are the expected outcome for most
/// mutations. On failure the exact mutated stream and a mutation descriptor
/// are returned in [`CaseError`] so the artifact stores a directly
/// replayable `.mut.bin` reproducer.
fn run_corrupt_case(algo: Algorithm, data: &[u8]) -> Result<(Vec<u8>, usize), CaseError> {
    let encoded = algorithms::encode_with(algo, data);
    let encoded_size = encoded.len();
    let mut rng = StdRng::seed_from_u64(corrupt_seed(data));
    let mutated_cap = encoded_size.saturating_add(256).clamp(1, 16 << 20);
    let decoded_limit = corrupt_decoded_limit(algo, data.len());

    let check = |candidate: &[u8], mutation: String, limit: usize| -> Result<(), CaseError> {
        corrupt_probe(algo, candidate, limit).map_err(|message| CaseError {
            message,
            mutated_stream: Some(candidate.to_vec()),
            mutation: Some(mutation),
        })
    };

    // Applies the full corruption schedule to `base`, whose bytes came from
    // `origin` ("self" for the encoded stream, "fixture" for a real file).
    let sweep = |rng: &mut StdRng,
                 base: &[u8],
                 origin: &str,
                 cap: usize,
                 limit: usize|
     -> Result<(), CaseError> {
        for attempt in 0..CORRUPT_ATTEMPTS {
            let candidate = datagen::mutate(rng, base, 0, cap);
            check(&candidate, format!("{origin}/mutate#{attempt}"), limit)?;
        }

        // Prefix truncations: every offset for small streams, a
        // deterministic sample (edges + log-spaced interior) for larger.
        for n in truncation_points(base.len()) {
            check(&base[..n], format!("{origin}/truncate@{n}"), limit)?;
        }

        // Boundary-value writes into the head/tail field region where
        // length, magic, offset, and checksum fields typically live.
        for pos in field_positions(base.len()) {
            for &value in &BOUNDARY_VALUES {
                let mut candidate = base.to_vec();
                candidate[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
                check(
                    &candidate,
                    format!("{origin}/boundary@{pos}=0x{value:08x}"),
                    limit,
                )?;
            }
        }
        Ok(())
    };

    sweep(&mut rng, &encoded, "self", mutated_cap, decoded_limit)?;
    for (index, base) in algorithms::extra_corrupt_bases(algo).iter().enumerate() {
        let origin = format!("extra#{index}");
        let cap = base.len().saturating_add(256).clamp(1, 16 << 20);
        sweep(&mut rng, base, &origin, cap, decoded_limit)?;
    }

    // A real tool-produced fixture exercises decoder paths a self-encoded
    // stream never reaches (vendor extensions, unusual flags, real
    // multi-entry layouts). Rotate deterministically through the corpus.
    let fixture_list = fixtures::load(algo).map_err(|message| CaseError {
        message,
        mutated_stream: None,
        mutation: Some("fixtures".to_string()),
    })?;
    if !fixture_list.is_empty() {
        let index = rng.random_range(0..fixture_list.len());
        let fixture = fixture_list[index].clone();
        let origin = format!("fixture#{index}");
        // Baseline the pristine fixture first. A panic is a finding in its
        // own right; a graceful reject means the file is not a decodable
        // stream for this algorithm (the corpus also carries loose test
        // data such as *.expected files), so probing its mutations would
        // only produce more rejects.
        match decode_outcome(algo, &fixture) {
            Err(message) => {
                return Err(CaseError {
                    message,
                    mutated_stream: Some(fixture),
                    mutation: Some(format!("{origin}/pristine")),
                });
            }
            Ok(DecodeOutcome::Rejected) => {}
            Ok(DecodeOutcome::Decoded(pristine_size)) => {
                // Bound mutated decodes by the fixture's own dimensions: a
                // large fixture legitimately decodes far more than the
                // small fuzz input that selected it. The algorithm hard
                // cap still wins over a large pristine output: for
                // modeled zpaq the decode itself is the expensive part,
                // and hitting the cap is a graceful `Err`, not a false
                // positive.
                let fixture_limit = corrupt_decoded_limit(algo, fixture.len())
                    .max(pristine_size.saturating_mul(4))
                    .min(corrupt_output_hard_cap(algo));
                let fixture_cap = fixture.len().saturating_add(256).clamp(1, 16 << 20);
                sweep(&mut rng, &fixture, &origin, fixture_cap, fixture_limit)?;
            }
        }
    }

    // Echo the input so fingerprint verification passes, same as mtree.
    Ok((data.to_vec(), encoded_size))
}

/// Decoder robustness bound for a corrupt-pattern input: decoded output
/// larger than this is treated as a resource-exhaustion failure.
pub(crate) fn corrupt_decoded_limit(algo: Algorithm, input_len: usize) -> usize {
    input_len
        .saturating_mul(256)
        .clamp(64 << 10, 64 << 20)
        .min(corrupt_output_hard_cap(algo))
}

/// Hard cap on the corrupt-pattern decode limit for the modeled ZPAQ
/// family (`zpaq`, `zpaq-level2`, `zpaq-level3`, `zpaq-archive`).
///
/// Every modeled byte costs ~8 arithmetic bit-decodes plus predictor /
/// HCOMP / PCOMP work. Measured under the `fuzz` profile: ~149 ns per
/// decoded byte on the `zpaq_corrupt_ff_fill_hang` corrupt stream
/// (which decodes ~1.3e9 bytes while emitting none — run-1791781005
/// watchdog hang) and ~279 ns per emitted byte on the pristine
/// `jidac-m3-heavy-pcomp` fixture. The generic 64 MiB ceiling can
/// therefore take tens of seconds in the worst case; 1 MiB decodes in
/// ~0.3 s on real streams, leaving orders of magnitude of headroom
/// under the watchdog's 60 s budget floor.
const ZPAQ_CORRUPT_LIMIT: usize = 1 << 20;

/// Per-algorithm ceiling applied on top of [`corrupt_decoded_limit`]'s
/// formula result (and over the fixture phase's pristine-output
/// allowance). Most codecs keep the generic bound; modeled ZPAQ
/// decoders are capped at [`ZPAQ_CORRUPT_LIMIT`] because their
/// per-decoded-byte cost makes larger limits unreachable inside the
/// watchdog hang budget. `lrzip-zpaq` shares the cap: its library decode
/// honors a finite block `u_len` and rejects `usize::MAX`, but a corrupt
/// `chunk_bytes` of 4..=8 can still declare a huge finite `u_len`. The
/// harness ceiling is applied on top.
fn corrupt_output_hard_cap(algo: Algorithm) -> usize {
    match algo {
        Algorithm::Zpaq
        | Algorithm::ZpaqLevel2
        | Algorithm::ZpaqLevel3
        | Algorithm::ZpaqArchive
        | Algorithm::LrzipZpaq => ZPAQ_CORRUPT_LIMIT,
        _ => usize::MAX,
    }
}

/// Outcome of a single decoder call on a (possibly corrupted) stream.
enum DecodeOutcome {
    /// Decoded successfully; carries the output size.
    Decoded(usize),
    /// The decoder returned a graceful error — the expected result for
    /// most malformed inputs.
    Rejected,
}

/// Run the decoder on `candidate`, catching panics. Also used to baseline
/// pristine fixtures before corrupting them. The in-flight watchdog entry
/// is pointed at these bytes so a hang reports the exact reproducer rather
/// than the pre-mutation input.
fn decode_outcome(algo: Algorithm, candidate: &[u8]) -> Result<DecodeOutcome, String> {
    watchdog::note_data(candidate);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        algorithms::decode_with(algo, candidate)
    })) {
        Ok(Ok(decoded)) => Ok(DecodeOutcome::Decoded(decoded.len())),
        Ok(Err(_)) => Ok(DecodeOutcome::Rejected),
        Err(panic_info) => Err(format!("PANIC: {}", panic_message(panic_info.as_ref()))),
    }
}

/// Probe a mutated encoded stream: the decoder must return (`Ok` or `Err`)
/// without panicking and must not decode beyond `decoded_limit`. Codecs
/// whose stream does not carry an output length are probed through their
/// bounded decode API so oversized output is capped at the limit rather
/// than materialized.
fn corrupt_probe(algo: Algorithm, candidate: &[u8], decoded_limit: usize) -> Result<(), String> {
    watchdog::note_data(candidate);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let decoded = algorithms::decode_bounded_with(algo, candidate, decoded_limit);
        if let Ok(decoded) = &decoded
            && decoded.len() > decoded_limit
        {
            return Err(format!(
                "resource oracle: corrupt decode produced {} bytes > {decoded_limit}",
                decoded.len()
            ));
        }
        algorithms::check_prefixed_decode_into(algo, candidate, Some(decoded_limit))?;
        Ok(())
    })) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(message)) => Err(message),
        Err(panic_info) => Err(format!("PANIC: {}", panic_message(panic_info.as_ref()))),
    }
}

/// Deterministic truncation offsets for a stream of `len` bytes.
fn truncation_points(len: usize) -> Vec<usize> {
    const FULL_SWEEP_LIMIT: usize = 64;
    if len <= FULL_SWEEP_LIMIT {
        return (0..len).collect();
    }
    let mut points: Vec<usize> = vec![0, 1, 2, 3, 4, 8, 16, 32];
    // Log-spaced interior points plus near-tail offsets.
    let mut n = FULL_SWEEP_LIMIT;
    while n < len && points.len() < TRUNCATION_POINTS {
        points.push(n);
        n = n.saturating_mul(2);
    }
    for offset in 1..=8usize {
        if let Some(n) = len.checked_sub(offset)
            && n > 0
        {
            points.push(n);
        }
    }
    points.push(len / 2);
    points.sort_unstable();
    points.dedup();
    points
}

/// Byte offsets where boundary values are written: every 4-byte-aligned
/// position within [`BOUNDARY_FIELD_SPAN`] of the head and of the tail.
fn field_positions(len: usize) -> Vec<usize> {
    if len < 4 {
        return Vec::new();
    }
    let mut positions: Vec<usize> = (0..len.min(BOUNDARY_FIELD_SPAN))
        .step_by(4)
        .filter(|&pos| pos + 4 <= len)
        .collect();
    // Tail slots covering the final BOUNDARY_FIELD_SPAN bytes, anchored at
    // the last writable u32 so the stream end (trailer checksums and size
    // fields) is always covered.
    let tail_low = len.saturating_sub(BOUNDARY_FIELD_SPAN);
    let mut pos = len - 4;
    loop {
        if pos + 4 <= tail_low {
            break;
        }
        positions.push(pos);
        if pos < 4 {
            break;
        }
        pos -= 4;
    }
    positions.sort_unstable();
    positions.dedup();
    positions
}

/// Deterministic seed for the corrupt pattern so `replay` and the
/// minimizer re-derive identical mutations for a given input.
fn corrupt_seed(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in data.iter().take(4096) {
        hash = (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    for &b in data.iter().rev().take(4096) {
        hash = (hash ^ u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    hash ^ (data.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Replay a single artifact or every `*.json` artifact in a directory.
/// Returns `Err` when at least one recorded failure still reproduces.
pub fn replay_path(path: &Path, fixtures_dir: &Path) -> Result<(), String> {
    // `replay foo.mut.bin` names a corrupt sidecar directly; resolve it
    // to the companion artifact so the report metadata is loaded too.
    let resolved;
    let path = if path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().ends_with(".mut.bin"))
    {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        resolved = path.with_file_name(format!("{}.json", name.trim_end_matches(".mut.bin")));
        resolved.as_path()
    } else {
        path
    };
    if !path.is_dir() {
        return replay_failure(path, fixtures_dir);
    }
    let mut artifacts: Vec<PathBuf> = std::fs::read_dir(path)
        .map_err(|e| format!("read replay dir {} failed: {e}", path.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    artifacts.sort();
    if artifacts.is_empty() {
        return Err(format!(
            "no failure artifacts (*.json) in {}",
            path.display()
        ));
    }
    let mut reproduced = 0usize;
    let mut unavailable = 0usize;
    let mut attempted = 0usize;
    let mut skipped = 0usize;
    for artifact in &artifacts {
        // Skip non-failure JSON files co-located in run directories
        // (manifest/summary/matrix, in-flight breadcrumbs); watchdog hang
        // reports are replayable through their own schema.
        let replayable =
            report::load_failure(artifact).is_ok() || report::load_hang(artifact).is_ok();
        if !replayable {
            skipped += 1;
            continue;
        }
        attempted += 1;
        eprintln!("[replay-dir] {}", artifact.display());
        match replay_failure(artifact, fixtures_dir) {
            Ok(()) => {}
            // Errors from inside the library call mean the failure still
            // reproduces; load/read failures mean the artifact itself is
            // unusable, which must not masquerade as a live bug.
            Err(err) if err.starts_with("replay ") => {
                reproduced += 1;
                eprintln!("[replay-dir]   {err}");
            }
            Err(err) => {
                unavailable += 1;
                eprintln!("[replay-dir]   not replayable: {err}");
            }
        }
    }
    if attempted == 0 {
        return Err(format!(
            "no failure artifacts (*.json with companion .bin) in {}",
            path.display()
        ));
    }
    let cleared = attempted - reproduced - unavailable;
    eprintln!(
        "[replay-dir] {attempted} artifacts: {reproduced} reproduced, {cleared} no longer reproduce, {unavailable} not replayable ({skipped} non-failure files skipped)"
    );
    if reproduced == 0 {
        Ok(())
    } else {
        Err(format!("{reproduced} failures still reproduce"))
    }
}

pub fn replay_failure(path: &Path, fixtures_dir: &Path) -> Result<(), String> {
    let loaded = match report::load_failure(path) {
        Ok(loaded) => loaded,
        // A `hang-*.json` artifact is not a FailureReport — the process
        // died before one could be written — so it needs its own loader.
        Err(load_err) => return replay_hang_artifact(path, load_err),
    };
    // Replaying a hang artifact can itself hang; enable the watchdog so the
    // process aborts with evidence instead of blocking forever.
    watchdog::init(path.parent().unwrap_or_else(|| Path::new(".")));
    fixtures::init(fixtures_dir);
    install_panic_hook();
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

    // A corrupt failure stores the exact mutated stream in a `.mut.bin`
    // sidecar: replay decodes it directly instead of re-deriving mutations,
    // so replay does not depend on fixtures or the encode path at all.
    if let Some(mut_file) = &loaded.report.mut_file {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut_path = dir.join(mut_file);
        let mutated = std::fs::read(&mut_path)
            .map_err(|e| format!("read mutated stream {} failed: {e}", mut_path.display()))?;
        eprintln!(
            "[replay] mutated stream {} ({} bytes, mutation: {})",
            mut_file,
            mutated.len(),
            loaded.report.mutation.as_deref().unwrap_or("unknown")
        );
        let limit = corrupt_decoded_limit(algo, loaded.report.original_size.max(loaded.data.len()));
        // Register in-flight so a replayed hang aborts with evidence
        // instead of blocking forever.
        let _inflight = watchdog::enter(
            algo,
            TestPattern::Corrupt,
            loaded.report.iteration,
            &mutated,
        );
        return match corrupt_probe(algo, &mutated, limit) {
            Ok(()) => {
                eprintln!("[replay] success: failure no longer reproduces");
                Ok(())
            }
            Err(err) => Err(replay_verdict(
                algo,
                TestPattern::Corrupt,
                &loaded.report.signature,
                &err,
            )),
        };
    }

    match execute_case(algo, pattern, &loaded.data, loaded.report.iteration) {
        Ok(_) => {
            eprintln!("[replay] success: failure no longer reproduces");
            Ok(())
        }
        Err(err) => Err(replay_verdict(
            algo,
            pattern,
            &loaded.report.signature,
            &err.message,
        )),
    }
}

/// Compare a replayed failure against the recorded signature. A matching
/// signature is a clean reproduction; a *different* signature means the
/// original bug may be fixed but another one fires on the same input, which
/// still counts as a reproduced failure with a distinct message.
fn replay_verdict(algo: Algorithm, pattern: TestPattern, recorded: &str, error: &str) -> String {
    let signature = report::failure_signature(algo, pattern, error);
    if !recorded.is_empty() && signature != recorded {
        format!("replay produced a different failure signature: {signature} (recorded: {recorded})")
    } else {
        format!("replay reproduced error: {error}")
    }
}

/// Replay a watchdog hang artifact. The recorded `.bin` holds the in-flight
/// bytes at hang time — for `corrupt` that is the mutated encoded stream,
/// for other patterns the original fuzz input. The watchdog is armed again
/// so a still-hanging input aborts with fresh evidence.
fn replay_hang_artifact(path: &Path, load_err: String) -> Result<(), String> {
    let meta = report::load_hang(path).map_err(|_| load_err)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    watchdog::init(dir);
    install_panic_hook();
    let algo = Algorithm::from_name(&meta.algorithm)
        .ok_or_else(|| format!("unknown algorithm in hang report: {}", meta.algorithm))?;
    let pattern = TestPattern::from_label(&meta.pattern)
        .ok_or_else(|| format!("unknown pattern in hang report: {}", meta.pattern))?;
    let data = std::fs::read(dir.join(&meta.bin_file))
        .map_err(|e| format!("read hang input failed: {e}"))?;
    eprintln!(
        "[replay] hang artifact: algorithm={} pattern={} iteration={} size={}",
        meta.algorithm,
        meta.pattern,
        meta.iteration,
        data.len()
    );
    if pattern == TestPattern::Corrupt {
        // The recorded bytes are the decoder input itself. Replay through
        // the same bounded probe the corrupt case used — a plain
        // decode_outcome would skip the output cap and could re-hang on
        // streams that emit unbounded output from finite input.
        let _inflight = watchdog::enter(algo, pattern, meta.iteration, &data);
        let limit = corrupt_decoded_limit(algo, data.len());
        return match corrupt_probe(algo, &data, limit) {
            Ok(_) => {
                eprintln!("[replay] success: hang no longer reproduces");
                Ok(())
            }
            Err(err) => Err(format!("replay reproduced error: {err}")),
        };
    }
    match execute_case(algo, pattern, &data, meta.iteration) {
        Ok(_) => {
            eprintln!("[replay] success: hang no longer reproduces");
            Ok(())
        }
        Err(err) => Err(format!("replay reproduced error: {}", err.message)),
    }
}

const fn pattern_label(pattern: PatternFilter) -> &'static str {
    match pattern {
        PatternFilter::All => "all",
        PatternFilter::Self_ => "self",
        PatternFilter::OriginalCompress => "original-compress",
        PatternFilter::OriginalDecompress => "original-decompress",
        PatternFilter::Corrupt => "corrupt",
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
        PatternFilter, RunConfig, RunMode, RunState, ZPAQ_CORRUPT_LIMIT, corrupt_decoded_limit,
        corrupt_output_hard_cap, get_patterns, handle_failure_artifact, observation_signature,
        panic_message,
    };
    use crate::algorithms::Algorithm;
    use crate::checksum;
    use crate::report::{FailureInfo, Stats, TestPattern};
    use std::collections::{HashMap, HashSet};
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    #[test]
    fn panic_message_uses_the_payload_text() {
        let payload = std::panic::catch_unwind(|| panic!("attempt to add with overflow"))
            .expect_err("closure must panic");
        let message = panic_message(payload.as_ref());
        assert!(
            message.starts_with("attempt to add with overflow"),
            "panic payload was lost: {message}"
        );
    }

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
        let with_tools = get_patterns(Algorithm::Zip, PatternFilter::All, &available).unwrap();
        let without_tools =
            get_patterns(Algorithm::Zip, PatternFilter::All, &HashSet::new()).unwrap();
        assert_eq!(
            with_tools,
            vec![
                TestPattern::Self_,
                TestPattern::Corrupt,
                TestPattern::OriginalCompress,
                TestPattern::OriginalDecompress,
            ]
        );
        assert_eq!(
            without_tools,
            vec![TestPattern::Self_, TestPattern::Corrupt]
        );
        let alias_tools: HashSet<_> = [Algorithm::ZstdFast].into_iter().collect();
        assert!(crate::algorithms::is_level_alias(Algorithm::ZstdFast));
        assert_eq!(
            get_patterns(Algorithm::ZstdFast, PatternFilter::All, &alias_tools).unwrap(),
            with_tools
        );
        assert_eq!(
            get_patterns(Algorithm::ZstdFast, PatternFilter::All, &HashSet::new()).unwrap(),
            without_tools
        );
        assert!(
            get_patterns(
                Algorithm::Zip,
                PatternFilter::OriginalCompress,
                &HashSet::new()
            )
            .is_err()
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
            fixtures_dir: tmp.join("fixtures").display().to_string(),
            corpus_max_entries: 0,
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
            corpus_state: HashMap::new(),
            harvested_corpus: Mutex::new(0),
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
            mutated_stream: None,
            mutation: None,
        };

        let stats = Mutex::new(Stats::default());
        stats.lock().unwrap().record_failure(TestPattern::Self_);
        handle_failure_artifact(&state, &stats, 0, &info, false);
        stats.lock().unwrap().record_failure(TestPattern::Self_);
        handle_failure_artifact(&state, &stats, 0, &info, false);

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

    /// Inputs larger than one MPPC packet's history used to panic inside
    /// `encode_with`, get swallowed by `catch_unwind`, and silently skip the
    /// observation. The signature path must cap them like `execute_case`.
    #[test]
    fn observation_signature_caps_mppc_input() {
        let over_rdp4_cap = vec![0u8; 54014];
        assert!(observation_signature(Algorithm::Mppc, &over_rdp4_cap).is_some());
        assert!(observation_signature(Algorithm::MppcRdp4, &over_rdp4_cap).is_some());
        // The signature must match the truncated packet the codec sees.
        assert_eq!(
            observation_signature(Algorithm::Mppc, &over_rdp4_cap),
            observation_signature(Algorithm::Mppc, &over_rdp4_cap[..8192])
        );
        let over_rdp5_cap = vec![0u8; 70000];
        assert!(observation_signature(Algorithm::MppcRdp5, &over_rdp5_cap).is_some());
        assert_eq!(
            observation_signature(Algorithm::MppcRdp5, &over_rdp5_cap),
            observation_signature(Algorithm::MppcRdp5, &over_rdp5_cap[..65536])
        );
    }

    /// Modeled ZPAQ decoders cap the corrupt decode limit far below the
    /// generic 64 MiB ceiling: the decode itself is the expensive part,
    /// so the limit must fit inside the watchdog hang budget. Other
    /// algorithms keep the previous `len*256` clamped formula.
    #[test]
    fn corrupt_decoded_limit_caps_modeled_zpaq() {
        const ZPAQ_ALGOS: [Algorithm; 5] = [
            Algorithm::Zpaq,
            Algorithm::ZpaqLevel2,
            Algorithm::ZpaqLevel3,
            Algorithm::ZpaqArchive,
            Algorithm::LrzipZpaq,
        ];
        for algo in ZPAQ_ALGOS {
            assert_eq!(corrupt_output_hard_cap(algo), ZPAQ_CORRUPT_LIMIT);
            assert!(corrupt_decoded_limit(algo, 16 << 20) <= ZPAQ_CORRUPT_LIMIT);
            // Small inputs keep the 64 KiB floor.
            assert_eq!(corrupt_decoded_limit(algo, 1), 64 << 10);
        }
        assert_eq!(corrupt_decoded_limit(Algorithm::Gzip, 16 << 20), 64 << 20);
        assert_eq!(corrupt_decoded_limit(Algorithm::Gzip, 1), 64 << 10);
        assert_eq!(corrupt_decoded_limit(Algorithm::Gzip, 4096), 4096 * 256);
    }
}
