//! Cross-implementation performance comparison harness.
//!
//! Run with:
//! `cargo bench --all-features --bench compare -- --quick`
//!
//! The harness times our implementation through the internal benchmark
//! helper (library-level timing), our CLI (end-to-end), and reference
//! command-line tools. Results are written to `target/bench/compare/`.

#[path = "helpers/mod.rs"]
mod helpers;

#[path = "compare/catalog.rs"]
mod catalog;
#[path = "compare/corpus.rs"]
mod corpus;
#[path = "compare/fixtures.rs"]
mod fixtures;
#[path = "compare/model.rs"]
mod model;
#[path = "compare/report.rs"]
mod report;
#[path = "compare/runner.rs"]
mod runner;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use model::{Case, Kind};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match parse_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };

    let cases = catalog::cases();
    if args.iter().any(|arg| arg == "--list") {
        print_list(&cases);
        return;
    }
    if args.iter().any(|arg| arg == "--list-markdown") {
        print_markdown(&cases);
        return;
    }
    if !config.helper_bin.exists() {
        eprintln!(
            "error: benchmark helper not found at {}; build it with `cargo build --release -p archive-cli --bin archive-bench-helper`",
            config.helper_bin.display()
        );
        std::process::exit(2);
    }

    let selected = select_cases(&cases, &config);
    if selected.is_empty() {
        eprintln!("error: no cases matched the filters");
        std::process::exit(2);
    }
    if let Err(error) = fixtures::ensure_for(&selected) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }

    let run_id = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0),
        std::process::id()
    );
    let out_dir = config
        .output_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/bench/compare").join(format!("run-{run_id}")));
    if let Err(error) = std::fs::create_dir_all(&out_dir) {
        eprintln!("error: create {}: {error}", out_dir.display());
        std::process::exit(1);
    }
    let work_dir = config
        .work_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/bench/work"));
    let runner_config = runner::Config {
        quick: config.quick,
        corpora: config.corpora.clone(),
        iterations: config.iterations,
        warmup: config.warmup,
        size_override: config.size_override,
        helper_bin: config.helper_bin,
        archive_bin: config.archive_bin,
        refs_dir: config.refs_dir,
        work_dir: work_dir.join(format!("run-{run_id}")),
        skip_cli: config.skip_cli,
        skip_ref: config.skip_ref,
        timeout: std::time::Duration::from_secs(config.timeout),
    };

    let mut results = Vec::new();
    for case in &selected {
        if !case.ours_lib && !case.ours_cli && case.reference.is_none() {
            eprintln!(
                "skip {}: no implementation or reference available",
                case.label
            );
            continue;
        }
        let corpora: Vec<&str> = if case.kind == Kind::Archive {
            vec![""]
        } else {
            runner_config.corpora.iter().map(String::as_str).collect()
        };
        for corpus in corpora {
            eprintln!(
                "run {} [{}] {}",
                case.label,
                if corpus.is_empty() { "archive" } else { corpus },
                if runner_config.quick { "quick" } else { "full" }
            );
            let result = runner::run_case(case, &runner_config, corpus);
            if let Some(error) = &result.error {
                eprintln!("  error: {error}");
            }
            results.push(result);
        }
    }

    if let Err(error) = report::write_report(
        &results,
        &selected,
        &runner_config,
        &out_dir,
        config.baseline.as_deref(),
    ) {
        eprintln!("error: write report: {error}");
        std::process::exit(1);
    }
    println!("report: {}", out_dir.join("report.md").display());
    println!("json:   {}", out_dir.join("result.json").display());
}

#[derive(Debug)]
struct Args {
    quick: bool,
    corpora: Vec<String>,
    iterations: usize,
    warmup: usize,
    size_override: Option<usize>,
    helper_bin: PathBuf,
    archive_bin: Option<PathBuf>,
    refs_dir: PathBuf,
    work_dir: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    skip_cli: bool,
    skip_ref: bool,
    timeout: u64,
    baseline: Option<PathBuf>,
    kind: Option<Kind>,
    format_filter: Vec<String>,
}

const USAGE: &str = "\
usage: cargo bench --all-features --bench compare -- [options]
  --quick                 use quick sizes and fewer iterations (default)
  --full                  use full sizes
  --iterations N          timed iterations per measurement
  --warmup N              warmup iterations
  --size BYTES            override the input size
  --corpus LIST           text,run,random,periodic or all (default: text)
  --format LIST           case ids/formats to run (comma separated)
  --kind codec|archive    restrict to one kind
  --helper-bin PATH       archive-bench-helper binary
  --archive-bin PATH      archive CLI binary
  --refs-dir PATH         built reference binaries (default: target/bench/refs)
  --work-dir PATH         scratch directory
  --output-dir PATH       report directory
  --skip-cli              do not run our CLI
  --skip-ref              do not run reference tools
  --timeout SECS          per-process timeout (default: 600)
  --baseline PATH         previous result.json for delta reporting
  --list                  list catalog cases
  --list-markdown         print the catalog as a Markdown coverage matrix
";

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args {
        quick: true,
        corpora: vec!["text".to_owned()],
        iterations: 0,
        warmup: 1,
        size_override: None,
        helper_bin: default_helper_bin(),
        archive_bin: default_archive_bin(),
        refs_dir: PathBuf::from("target/bench/refs"),
        work_dir: None,
        output_dir: None,
        skip_cli: false,
        skip_ref: false,
        timeout: 600,
        baseline: None,
        kind: None,
        format_filter: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--quick" => parsed.quick = true,
            "--full" => parsed.quick = false,
            "--iterations" => {
                i += 1;
                parsed.iterations = args
                    .get(i)
                    .ok_or("--iterations requires a value")?
                    .parse()
                    .map_err(|_| "--iterations must be an integer")?;
            }
            "--warmup" => {
                i += 1;
                parsed.warmup = args
                    .get(i)
                    .ok_or("--warmup requires a value")?
                    .parse()
                    .map_err(|_| "--warmup must be an integer")?;
            }
            "--size" => {
                i += 1;
                parsed.size_override = Some(
                    args.get(i)
                        .ok_or("--size requires a value")?
                        .parse()
                        .map_err(|_| "--size must be an integer")?,
                );
            }
            "--corpus" => {
                i += 1;
                let value = args.get(i).ok_or("--corpus requires a value")?;
                parsed.corpora = if value == "all" {
                    corpus::CORPORA
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect()
                } else {
                    value.split(',').map(str::to_owned).collect()
                };
            }
            "--format" => {
                i += 1;
                parsed.format_filter = args
                    .get(i)
                    .ok_or("--format requires a value")?
                    .split(',')
                    .map(str::to_owned)
                    .collect();
            }
            "--kind" => {
                i += 1;
                parsed.kind = Some(match args.get(i).map(String::as_str) {
                    Some("codec") => Kind::Codec,
                    Some("archive") => Kind::Archive,
                    _ => return Err("--kind must be codec or archive".to_owned()),
                });
            }
            "--helper-bin" => {
                i += 1;
                parsed.helper_bin =
                    PathBuf::from(args.get(i).ok_or("--helper-bin requires a value")?);
            }
            "--archive-bin" => {
                i += 1;
                parsed.archive_bin = Some(PathBuf::from(
                    args.get(i).ok_or("--archive-bin requires a value")?,
                ));
            }
            "--refs-dir" => {
                i += 1;
                parsed.refs_dir = PathBuf::from(args.get(i).ok_or("--refs-dir requires a value")?);
            }
            "--work-dir" => {
                i += 1;
                parsed.work_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--work-dir requires a value")?,
                ));
            }
            "--output-dir" => {
                i += 1;
                parsed.output_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--output-dir requires a value")?,
                ));
            }
            "--skip-cli" => parsed.skip_cli = true,
            "--skip-ref" => parsed.skip_ref = true,
            "--baseline" => {
                i += 1;
                parsed.baseline = Some(PathBuf::from(
                    args.get(i).ok_or("--baseline requires a value")?,
                ));
            }
            "--timeout" => {
                i += 1;
                parsed.timeout = args
                    .get(i)
                    .ok_or("--timeout requires a value")?
                    .parse()
                    .map_err(|_| "--timeout must be an integer")?;
            }
            "--list" | "--list-markdown" | "--bench" => {}
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }
    if parsed.iterations == 0 {
        parsed.iterations = if parsed.quick { 2 } else { 5 };
    }
    if parsed.timeout == 0 {
        return Err("--timeout must be greater than zero".to_owned());
    }
    for label in &parsed.corpora {
        if !corpus::CORPORA.contains(&label.as_str()) {
            return Err(format!(
                "unknown corpus `{label}`; expected one of: {}",
                corpus::CORPORA.join(", ")
            ));
        }
    }
    Ok(parsed)
}

fn default_helper_bin() -> PathBuf {
    for candidate in [
        "target/release/archive-bench-helper",
        "target/debug/archive-bench-helper",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("target/release/archive-bench-helper")
}

fn default_archive_bin() -> Option<PathBuf> {
    for candidate in ["target/release/archive", "target/debug/archive"] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn select_cases(cases: &[Case], args: &Args) -> Vec<Case> {
    cases
        .iter()
        .filter(|case| args.kind.is_none_or(|kind| case.kind == kind))
        .filter(|case| {
            args.format_filter.is_empty()
                || args
                    .format_filter
                    .iter()
                    .any(|filter| filter == case.id || filter == case.format)
        })
        .cloned()
        .collect()
}

fn print_markdown(cases: &[Case]) {
    println!("# Benchmark reference matrix");
    println!();
    println!("Generated from the benchmark catalog. Regenerate with:");
    println!();
    println!("```sh");
    println!(
        "cargo bench --all-features --bench compare -- --list-markdown > docs/bench/reference-matrix.md"
    );
    println!("```");
    println!();
    println!("Status below is catalog-level. Runtime availability (for example a");
    println!("missing reference binary) is recorded in the generated report.");
    println!();
    println!(
        "| id | format | kind | status | reference | version | build flags / provenance | note |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for case in cases {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |",
            case.id,
            if case.format.is_empty() {
                case.label
            } else {
                case.format
            },
            match case.kind {
                Kind::Codec => "codec",
                Kind::Archive => "archive",
            },
            case.status(),
            case.reference.map_or("—", |reference| reference.name),
            case.reference.map_or("—", |reference| reference.version),
            case.reference.map_or("—", |reference| reference.build),
            case.note.unwrap_or(""),
        );
    }
}

fn print_list(cases: &[Case]) {
    println!(
        "{:<16} {:<8} {:<14} {:<24}",
        "id", "kind", "status", "reference"
    );
    for case in cases {
        println!(
            "{:<16} {:<8} {:<14} {:<24}",
            case.id,
            match case.kind {
                Kind::Codec => "codec",
                Kind::Archive => "archive",
            },
            case.status(),
            case.reference.map_or("—", |reference| reference.name),
        );
    }
}
