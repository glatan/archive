//! Fuzz tester for the `archive` crate.
//!
//! Performs encode→decode round-trip testing, external tool cross-validation,
//! and special-case matrix verification across all supported formats.
//!
//! See `fuzz/README.md` for usage, test patterns, artifact structure, and
//! regression workflow.

mod algorithms;
mod checksum;
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
use clap::{Parser, ValueEnum};
use runner::{PatternFilter, RunConfig, RunMode};
use std::path::Path;
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

    /// Output directory for failure data
    #[arg(short, long, default_value = "fuzz/failures/")]
    output: String,

    /// Corpus directory used for guided runs and harvested interesting inputs
    #[arg(long, default_value = "fuzz/corpus/")]
    corpus_dir: String,

    /// Fixtures directory whose real tool-produced files seed corrupt bases
    #[arg(long, default_value = "tests/fixtures/")]
    fixtures_dir: String,

    /// Input generation mode
    #[arg(long, value_enum, default_value_t = ModeArg::Time)]
    mode: ModeArg,

    /// Parallel job count across algorithms
    #[arg(long, default_value_t = 1)]
    jobs: usize,

    /// Replay a saved failure artifact (.json/.bin pair) or a directory of them
    #[arg(long)]
    replay: Option<String>,

    /// Export a saved failure artifact into a fixture plus regression template
    #[arg(long)]
    export_regression: Option<String>,

    /// Output directory for exported regression fixtures/templates
    #[arg(long, default_value = "tests/fixtures/fuzz/generated/")]
    regression_dir: String,

    /// Import a saved failure artifact into tests/fixtures + tests/integration/generated
    #[arg(long)]
    import_regression: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(path) = cli.export_regression.as_deref() {
        match regression::export_failure(Path::new(path), Path::new(&cli.regression_dir)) {
            Ok((fixture, template)) => {
                eprintln!("exported fixture: {}", fixture.display());
                eprintln!("exported template: {}", template.display());
                return;
            }
            Err(err) => {
                eprintln!("regression export failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if let Some(path) = cli.import_regression.as_deref() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| Path::new("."));
        match regression::import_failure(Path::new(path), repo_root) {
            Ok((fixture, test, mod_file)) => {
                eprintln!("imported fixture: {}", fixture.display());
                eprintln!("imported test: {}", test.display());
                eprintln!("updated module index: {}", mod_file.display());
                return;
            }
            Err(err) => {
                eprintln!("regression import failed: {err}");
                std::process::exit(1);
            }
        }
    }

    if let Some(path) = cli.replay.as_deref() {
        match runner::replay_path(Path::new(path), Path::new(&cli.fixtures_dir)) {
            Ok(()) => return,
            Err(err) => {
                eprintln!("replay failed: {err}");
                std::process::exit(1);
            }
        }
    }

    let algorithms = parse_algorithms(&cli.algorithm);
    let pattern = parse_pattern(&cli.pattern);
    let seed = cli.seed.unwrap_or_else(|| {
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
    eprintln!("Duration: {}s", cli.duration);
    eprintln!("Pattern: {}", cli.pattern);
    eprintln!("Size range: {}..{}", cli.min_size, cli.max_size);
    eprintln!("Seed: {seed}");
    eprintln!(
        "Mode: {}",
        match cli.mode {
            ModeArg::Time => "time",
            ModeArg::CoverageGuided => "coverage-guided",
        }
    );
    eprintln!("Jobs: {}", cli.jobs.max(1));
    eprintln!("Output: {}", cli.output);
    eprintln!("Corpus: {}", cli.corpus_dir);
    eprintln!();

    let config = RunConfig {
        algorithms,
        duration: Duration::from_secs(cli.duration),
        pattern,
        mode: match cli.mode {
            ModeArg::Time => RunMode::Time,
            ModeArg::CoverageGuided => RunMode::CoverageGuided,
        },
        min_size: cli.min_size,
        max_size: cli.max_size,
        seed,
        jobs: cli.jobs.max(1),
        output_dir: cli.output,
        corpus_dir: cli.corpus_dir,
        fixtures_dir: cli.fixtures_dir,
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
