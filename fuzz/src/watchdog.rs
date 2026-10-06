//! Per-case hang detection.
//!
//! Library calls run under `catch_unwind`, which catches panics but cannot
//! stop an infinite loop or an allocation-growth stall. This module records
//! every in-flight case in a persisted breadcrumb file *before* the library
//! call, so a hung — or even aborting — case leaves evidence of what was
//! running. A background watchdog thread reports and aborts the process when
//! a case exceeds the time budget.
//!
//! The breadcrumb lives under the run directory as `inflight-<worker>.{json,bin}`
//! and is removed when the case finishes, so a clean run leaves no residue.

use crate::algorithms::Algorithm;
use crate::report::TestPattern;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Baseline hang threshold; scaled up by input size in [`hang_budget`].
const HANG_TIMEOUT: Duration = Duration::from_secs(60);
/// Upper bound on the scaled budget: a probe on the largest allowed input
/// must still abort within minutes, not hours.
const MAX_HANG_BUDGET: Duration = Duration::from_secs(300);
/// Persist the full input in the breadcrumb only below this size; larger
/// inputs are kept in memory for the watchdog and fall back to the descriptor
/// alone if the process aborts before it can report.
const BREADCRUMB_DATA_CAP: usize = 512 * 1024;

struct InflightEntry {
    algo: Algorithm,
    pattern: TestPattern,
    iteration: u64,
    started: Instant,
    data: Vec<u8>,
}

static INFLIGHT: LazyLock<Mutex<HashMap<u64, InflightEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static RUN_DIR: OnceLock<PathBuf> = OnceLock::new();
static WORKER_SEQ: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static WORKER_ID: u64 = WORKER_SEQ.fetch_add(1, Ordering::Relaxed);
}

/// Activate the watchdog. Breadcrumbs and hang artifacts are written under
/// `run_dir`. Must be called once per process; later calls are no-ops.
pub fn init(run_dir: &Path) {
    if RUN_DIR.set(run_dir.to_path_buf()).is_ok() {
        thread::spawn(watchdog_loop);
    }
}

/// Scale the hang budget with input size. The runtime oracle allows up to
/// `input_size / 32` ms of work; the watchdog stays well above it so slow but
/// legitimate decodes are never reported as hangs.
fn hang_budget(data_size: usize) -> Duration {
    HANG_TIMEOUT
        .max(Duration::from_millis((data_size / 4) as u64))
        .min(MAX_HANG_BUDGET)
}

/// Update the in-memory data snapshot of this worker's in-flight case
/// without touching the breadcrumb files, and restart the hang budget.
/// The corrupt pattern probes hundreds of mutated candidates per case;
/// per-candidate file I/O would be prohibitive, and the budget must be
/// per-probe — a case that makes steady progress is not a hang, so each
/// new candidate resets the clock. A probe stuck inside the library call
/// still reports the exact bytes via the watchdog's hang report.
pub fn note_data(data: &[u8]) {
    let worker = WORKER_ID.with(|id| *id);
    if let Some(entry) = INFLIGHT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_mut(&worker)
    {
        entry.data.clear();
        entry.data.extend_from_slice(data);
        entry.started = Instant::now();
    }
}

/// Register an in-flight case. Returns a guard that deregisters and removes
/// the breadcrumb on drop. A no-op before [`init`].
#[must_use = "the guard unregisters the in-flight case on drop; bind it to a variable"]
pub fn enter(algo: Algorithm, pattern: TestPattern, iteration: u64, data: &[u8]) -> CaseGuard {
    let Some(dir) = RUN_DIR.get() else {
        return CaseGuard::inactive();
    };
    let worker = WORKER_ID.with(|id| *id);

    // A nested call — e.g. a minimizer probe inside a wrapped block, which
    // re-enters via execute_case — must not rewrite or delete the outer
    // breadcrumb. Refresh the in-memory entry and return a guard that owns
    // nothing; its drop is then a no-op and the outer entry survives.
    {
        let mut map = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = map.get_mut(&worker) {
            entry.algo = algo;
            entry.pattern = pattern;
            entry.iteration = iteration;
            entry.data.clear();
            entry.data.extend_from_slice(data);
            entry.started = Instant::now();
            return CaseGuard::inactive();
        }
    }

    let json_path = dir.join(format!("inflight-{worker}.json"));
    let bin_path = dir.join(format!("inflight-{worker}.bin"));

    // Persist before the library call so an uncatchable abort (OOM, stack
    // overflow, SIGSEGV) still leaves evidence of the in-flight case.
    let desc = format!(
        "{{\"algorithm\":\"{algo}\",\"pattern\":\"{}\",\"iteration\":{iteration},\"data_size\":{},\"worker\":{worker}}}\n",
        pattern.label(),
        data.len()
    );
    let _ = fs::write(&json_path, desc);
    if data.len() <= BREADCRUMB_DATA_CAP {
        let _ = fs::write(&bin_path, data);
    }

    INFLIGHT.lock().unwrap_or_else(|e| e.into_inner()).insert(
        worker,
        InflightEntry {
            algo,
            pattern,
            iteration,
            started: Instant::now(),
            data: data.to_vec(),
        },
    );
    CaseGuard {
        worker,
        json_path,
        bin_path,
    }
}

pub struct CaseGuard {
    worker: u64,
    json_path: PathBuf,
    bin_path: PathBuf,
}

impl CaseGuard {
    fn inactive() -> Self {
        Self {
            worker: 0,
            json_path: PathBuf::new(),
            bin_path: PathBuf::new(),
        }
    }
}

impl Drop for CaseGuard {
    fn drop(&mut self) {
        if self.json_path.as_os_str().is_empty() {
            return;
        }
        INFLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.worker);
        let _ = fs::remove_file(&self.json_path);
        let _ = fs::remove_file(&self.bin_path);
    }
}

fn watchdog_loop() {
    loop {
        thread::sleep(Duration::from_secs(1));
        let now = Instant::now();
        let mut guard = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        let hung: Vec<u64> = guard
            .iter()
            .filter(|(_, e)| now.duration_since(e.started) > hang_budget(e.data.len()))
            .map(|(id, _)| *id)
            .collect();
        if hung.is_empty() {
            continue;
        }

        let suspects: Vec<String> = guard
            .iter()
            .map(|(id, e)| {
                format!(
                    "{{\"worker\":{id},\"algorithm\":\"{}\",\"pattern\":\"{}\",\"iteration\":{},\"data_size\":{},\"elapsed_ms\":{}}}",
                    e.algo,
                    e.pattern.label(),
                    e.iteration,
                    e.data.len(),
                    now.duration_since(e.started).as_millis()
                )
            })
            .collect();
        // Move the hung entries out and drop the lock *before* any file
        // I/O: a stalled fs::write while holding INFLIGHT would block every
        // worker's note_data/enter and delay the abort.
        let hung_entries: Vec<(u64, InflightEntry)> = hung
            .iter()
            .filter_map(|id| guard.remove(id).map(|entry| (*id, entry)))
            .collect();
        drop(guard);
        for (id, entry) in &hung_entries {
            report_hang(*id, entry, &suspects, now);
        }
        eprintln!(
            "[watchdog] {} case(s) exceeded the hang budget; aborting run (suspects recorded)",
            hung.len()
        );
        // Deliberately no stdout/stderr flush: a worker blocked on a full
        // pipe holds the line-buffer lock, and acquiring it here would
        // deadlock the watchdog before it can abort.
        std::process::exit(3);
    }
}

fn report_hang(worker: u64, entry: &InflightEntry, suspects: &[String], now: Instant) {
    let Some(dir) = RUN_DIR.get() else { return };
    let stem = dir.join(format!("hang-w{worker}-i{}", entry.iteration));
    let _ = fs::write(stem.with_extension("bin"), &entry.data);
    let report = format!(
        "{{\"kind\":\"hang\",\"algorithm\":\"{}\",\"pattern\":\"{}\",\"iteration\":{},\"data_size\":{},\"elapsed_ms\":{},\"bin_file\":\"{}.bin\",\"inflight\":[{}]}}\n",
        entry.algo,
        entry.pattern.label(),
        entry.iteration,
        entry.data.len(),
        now.duration_since(entry.started).as_millis(),
        stem.file_name().unwrap_or_default().to_string_lossy(),
        suspects.join(",")
    );
    let _ = fs::write(stem.with_extension("json"), report);
    eprintln!(
        "[watchdog] hang: {} {} iteration={} size={} elapsed={}ms",
        entry.algo,
        entry.pattern.label(),
        entry.iteration,
        entry.data.len(),
        now.duration_since(entry.started).as_millis()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enter_registers_and_cleans_up() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-watchdog-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        init(&tmp);
        // RUN_DIR is process-global and whichever test won init owns it,
        // so assert on this thread's INFLIGHT entry rather than the files.
        let worker = WORKER_ID.with(|id| *id);
        {
            let _guard = enter(Algorithm::Gzip, TestPattern::Self_, 7, b"data");
            assert!(
                INFLIGHT
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(&worker),
                "enter must register an in-flight entry"
            );
        }
        assert!(
            !INFLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&worker),
            "guard drop must deregister the entry"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn note_data_refreshes_budget_and_data() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-watchdog-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        init(&tmp);
        {
            let _guard = enter(Algorithm::Gzip, TestPattern::Self_, 1, b"original");
            let worker = WORKER_ID.with(|id| *id);
            // Backdate the entry so a refresh is observable.
            INFLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_mut(&worker)
                .unwrap()
                .started = Instant::now() - Duration::from_secs(3600);
            note_data(b"mutated candidate");
            let map = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            let entry = map.get(&worker).unwrap();
            assert_eq!(entry.data, b"mutated candidate");
            assert!(entry.started.elapsed() < Duration::from_secs(60));
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn note_data_without_entry_is_noop() {
        let worker = WORKER_ID.with(|id| *id);
        note_data(b"nobody home");
        assert!(
            !INFLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&worker),
            "note_data must not create an entry on its own"
        );
    }

    #[test]
    fn nested_enter_does_not_delete_outer_entry() {
        let tmp = std::env::temp_dir().join(format!(
            "archive-fuzz-watchdog-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        init(&tmp);
        let worker = WORKER_ID.with(|id| *id);
        let outer = enter(Algorithm::Gzip, TestPattern::Self_, 1, b"outer");
        {
            let inner = enter(Algorithm::Gzip, TestPattern::Corrupt, 2, b"inner");
            // A nested enter is in-memory only: it must not own files.
            assert!(inner.json_path.as_os_str().is_empty());
            let map = INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
            assert_eq!(map.get(&worker).unwrap().data, b"inner");
        }
        // The inner guard owned nothing; the outer entry survives its drop.
        assert!(
            INFLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&worker)
        );
        drop(outer);
        assert!(
            !INFLIGHT
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains_key(&worker)
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn hang_budget_is_bounded() {
        assert_eq!(hang_budget(0), HANG_TIMEOUT);
        assert!(hang_budget(usize::MAX) <= MAX_HANG_BUDGET);
    }
}
