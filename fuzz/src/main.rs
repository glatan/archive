//! Fuzz tester for the `archive` crate.
//!
//! Performs encode→decode round-trip testing, external tool cross-validation,
//! and special-case matrix verification across all supported formats.
//!
//! See `fuzz/README.md` for usage, test patterns, artifact structure, and
//! regression workflow.

mod algorithms;
mod checksum;
mod cleanup;
mod corpus;
mod datagen;
mod external;
mod fixtures;
mod known_issues;
mod minimizer;
mod regression;
mod report;
mod runner;
mod watchdog;

use algorithms::Algorithm;
use clap::{Args, Parser, Subcommand, ValueEnum};
use runner::{PatternFilter, RunConfig, RunMode};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ModeArg {
    Time,
    CoverageGuided,
}

#[derive(Parser)]
#[command(
    name = "archive-fuzz",
    about = "Fuzz tester for archive compression and archive formats"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Artifact directory layout shared by `run` (writer) and `clean` (remover).
#[derive(Args)]
struct ArtifactDirs {
    /// Directory holding per-run failure artifacts
    #[arg(long, default_value = "fuzz/failures/")]
    failures_dir: String,

    /// Corpus directory used for guided runs and harvested interesting inputs
    #[arg(long, default_value = "fuzz/corpus/")]
    corpus_dir: String,
}

#[derive(Subcommand)]
enum Command {
    /// Run fuzz testing
    Run(RunArgs),

    /// Replay a saved failure artifact (.json/.bin pair) or a directory of them
    Replay(ReplayArgs),

    /// Export a saved failure artifact into a fixture plus regression template
    ExportRegression(ExportArgs),

    /// Import a saved failure artifact into tests/fixtures + tests/integration/generated
    ImportRegression(ImportArgs),

    /// Remove all artifacts from the failure and corpus directories (keeps the
    /// directories and their .gitkeep)
    Clean(CleanArgs),

    /// Print a past run's saved summary (run directory or summary.json)
    Summary(SummaryArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Target algorithm (all, or comma-separated names). See Algorithm::ALL for the full list.
    #[arg(short, long, default_value = "all")]
    algorithm: String,

    /// Duration in seconds
    #[arg(short, long, default_value_t = 60)]
    duration: u64,

    /// Test pattern (all/self/original-compress/original-decompress/corrupt)
    #[arg(short, long, default_value = "all")]
    pattern: String,

    /// Minimum data size in bytes
    #[arg(long, default_value_t = 0)]
    min_size: usize,

    /// Maximum data size in bytes
    #[arg(long, default_value_t = 1_048_576)]
    max_size: usize,

    /// Random seed for reproducibility
    #[arg(long)]
    seed: Option<u64>,

    #[command(flatten)]
    dirs: ArtifactDirs,

    /// Fixtures directory whose real tool-produced files seed corrupt bases
    #[arg(long, default_value = "tests/fixtures/")]
    fixtures_dir: String,

    /// Input generation mode
    #[arg(long, value_enum, default_value_t = ModeArg::Time)]
    mode: ModeArg,

    /// Parallel job count across algorithms
    #[arg(long, default_value_t = 1)]
    jobs: usize,

    /// Per-algorithm cap on corpus entries (0 = unlimited). At the cap, new
    /// observations evict random existing entries; oversized corpus dirs are
    /// pruned down to the cap at load time
    #[arg(long, default_value_t = 1024)]
    corpus_max_entries: usize,
}

#[derive(Args)]
struct ReplayArgs {
    /// Artifact path (.json, .mut.bin sidecar, or a directory of artifacts)
    path: String,

    /// Fixtures directory used for fixture-backed corrupt replays
    #[arg(long, default_value = "tests/fixtures/")]
    fixtures_dir: String,
}

#[derive(Args)]
struct ExportArgs {
    /// Failure artifact .json to export
    path: String,

    /// Output directory for exported regression fixtures/templates
    #[arg(long, default_value = "tests/fixtures/fuzz/generated/")]
    regression_dir: String,
}

#[derive(Args)]
struct ImportArgs {
    /// Failure artifact .json to import
    path: String,
}

#[derive(Args)]
struct CleanArgs {
    #[command(flatten)]
    dirs: ArtifactDirs,

    /// Keep the N newest `run-*` directories in the failures directory
    /// (recency is the numeric epoch suffix, including collision suffixes)
    #[arg(long, conflicts_with = "corpus_only")]
    keep_latest: Option<usize>,

    /// Clean only the failures directory
    #[arg(long, conflicts_with = "corpus_only")]
    failures_only: bool,

    /// Clean only the corpus directory
    #[arg(long)]
    corpus_only: bool,
}

#[derive(Args)]
struct SummaryArgs {
    /// Run directory (uses its summary.json) or a summary.json path
    path: String,
}

fn main() {
    match Cli::parse().command {
        Command::Clean(args) => clean(&args),
        Command::Summary(args) => summary(args),
        Command::ExportRegression(args) => export(args),
        Command::ImportRegression(args) => import(args),
        Command::Replay(args) => replay(args),
        Command::Run(args) => run(args),
    }
}

fn clean(args: &CleanArgs) {
    let keep = args.keep_latest.unwrap_or(0);
    // Compare canonical paths so differently-spelled aliases of the same
    // directory are not cleaned twice; a second pass would ignore
    // keep-latest and delete the retained run dirs.
    let failures_key = std::fs::canonicalize(&args.dirs.failures_dir)
        .unwrap_or_else(|_| PathBuf::from(&args.dirs.failures_dir));
    let corpus_key = std::fs::canonicalize(&args.dirs.corpus_dir)
        .unwrap_or_else(|_| PathBuf::from(&args.dirs.corpus_dir));
    let mut targets: Vec<(&str, usize)> = Vec::new();
    if !args.corpus_only {
        targets.push((args.dirs.failures_dir.as_str(), keep));
    }
    if !args.failures_only && corpus_key != failures_key {
        if corpus_key.starts_with(&failures_key) {
            eprintln!(
                "[warn] skipping {}: nested inside {} (its clean would defeat --keep-latest)",
                args.dirs.corpus_dir, args.dirs.failures_dir
            );
        } else if failures_key.starts_with(&corpus_key) {
            eprintln!(
                "[warn] skipping {}: it contains {} (its clean would defeat --keep-latest)",
                args.dirs.corpus_dir, args.dirs.failures_dir
            );
        } else {
            targets.push((args.dirs.corpus_dir.as_str(), 0));
        }
    }

    let mut ok = true;
    for (dir, keep_latest) in targets {
        match cleanup::clean_dir(Path::new(dir), keep_latest) {
            Ok(stats) => eprintln!(
                "cleaned {}: removed {} entries ({} bytes)",
                dir, stats.entries, stats.bytes
            ),
            Err(err) => {
                eprintln!("clean failed: {err}");
                ok = false;
            }
        }
    }
    if !ok {
        std::process::exit(1);
    }
}

fn export(args: ExportArgs) {
    match regression::export_failure(Path::new(&args.path), Path::new(&args.regression_dir)) {
        Ok((fixture, template)) => {
            eprintln!("exported fixture: {}", fixture.display());
            eprintln!("exported template: {}", template.display());
        }
        Err(err) => {
            eprintln!("regression export failed: {err}");
            std::process::exit(1);
        }
    }
}

fn import(args: ImportArgs) {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."));
    match regression::import_failure(Path::new(&args.path), repo_root) {
        Ok((fixture, test, mod_file)) => {
            eprintln!("imported fixture: {}", fixture.display());
            eprintln!("imported test: {}", test.display());
            eprintln!("updated module index: {}", mod_file.display());
        }
        Err(err) => {
            eprintln!("regression import failed: {err}");
            std::process::exit(1);
        }
    }
}

fn summary(args: SummaryArgs) {
    if let Err(err) = report::print_summary_file(Path::new(&args.path)) {
        eprintln!("summary failed: {err}");
        std::process::exit(1);
    }
}

fn replay(args: ReplayArgs) {
    if let Err(err) = runner::replay_path(Path::new(&args.path), Path::new(&args.fixtures_dir)) {
        eprintln!("replay failed: {err}");
        std::process::exit(1);
    }
}

fn run(args: RunArgs) {
    let algorithms = parse_algorithms(&args.algorithm);
    let pattern = parse_pattern(&args.pattern);
    let seed = args.seed.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    });

    eprintln!("=== Archive Fuzz Tester ===");
    eprintln!(
        "Algorithms: {}",
        algorithms
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("Duration: {}s", args.duration);
    eprintln!("Pattern: {}", args.pattern);
    eprintln!("Size range: {}..{}", args.min_size, args.max_size);
    eprintln!("Seed: {seed}");
    eprintln!(
        "Mode: {}",
        match args.mode {
            ModeArg::Time => "time",
            ModeArg::CoverageGuided => "coverage-guided",
        }
    );
    eprintln!("Jobs: {}", args.jobs.max(1));
    eprintln!("Failures: {}", args.dirs.failures_dir);
    eprintln!("Corpus: {}", args.dirs.corpus_dir);
    eprintln!();

    let config = RunConfig {
        algorithms,
        duration: Duration::from_secs(args.duration),
        pattern,
        mode: match args.mode {
            ModeArg::Time => RunMode::Time,
            ModeArg::CoverageGuided => RunMode::CoverageGuided,
        },
        min_size: args.min_size,
        max_size: args.max_size,
        seed,
        jobs: args.jobs.max(1),
        output_dir: args.dirs.failures_dir,
        corpus_dir: args.dirs.corpus_dir,
        fixtures_dir: args.fixtures_dir,
        corpus_max_entries: args.corpus_max_entries,
    };

    let stats = runner::run(&config);

    if stats.total_failures() > 0 {
        std::process::exit(1);
    }
}

fn parse_algorithms(s: &str) -> Vec<Algorithm> {
    if s == "all" {
        return Algorithm::ALL.to_vec();
    }
    s.split(',')
        .map(|name| {
            Algorithm::from_name(name.trim()).unwrap_or_else(|| panic!("Unknown algorithm: {name}"))
        })
        .collect()
}

fn parse_pattern(s: &str) -> PatternFilter {
    match s {
        "all" => PatternFilter::All,
        "self" => PatternFilter::Self_,
        "original-compress" => PatternFilter::OriginalCompress,
        "original-decompress" => PatternFilter::OriginalDecompress,
        "corrupt" => PatternFilter::Corrupt,
        _ => panic!("Unknown pattern: {s}"),
    }
}
