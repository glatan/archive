//! Markdown and JSON report generation.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

use crate::model::{Case, CaseResult, Kind, Measurement};
use crate::runner::Config;

pub fn write_report(
    results: &[CaseResult],
    cases: &[Case],
    cfg: &Config,
    out_dir: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(out_dir)?;
    let json = build_json(results, cases, cfg);
    fs::write(
        out_dir.join("result.json"),
        serde_json::to_vec_pretty(&json).unwrap(),
    )?;
    fs::write(
        out_dir.join("report.md"),
        build_markdown(results, cases, cfg, &json),
    )?;
    Ok(())
}

fn build_json(results: &[CaseResult], cases: &[Case], cfg: &Config) -> Value {
    let result_values: Vec<Value> = results
        .iter()
        .map(|result| {
            json!({
                "case": result.case.id,
                "label": result.case.label,
                "kind": match result.case.kind { Kind::Codec => "codec", Kind::Archive => "archive" },
                "status": result.case.status(),
                "corpus": result.corpus,
                "input_len": result.input_len,
                "error": result.error,
                "encode": op_json(result.encode.as_ref()),
                "decode": op_json(result.decode.as_ref()),
            })
        })
        .collect();
    json!({
        "schema_version": 1,
        "generated_at": now_string(),
        "environment": environment(),
        "build": build_info(),
        "config": {
            "quick": cfg.quick,
            "corpora": cfg.corpora,
            "iterations": cfg.iterations,
            "warmup": cfg.warmup,
            "size_override": cfg.size_override,
        },
        "cases": cases.iter().map(|case| json!({
            "id": case.id,
            "label": case.label,
            "kind": match case.kind { Kind::Codec => "codec", Kind::Archive => "archive" },
            "format": case.format,
            "status": case.status(),
            "reference": case.reference.map(|reference| json!({
                "name": reference.name,
                "version": reference.version,
                "build": reference.build,
            })),
            "note": case.note,
        })).collect::<Vec<_>>(),
        "results": result_values,
    })
}

fn op_json(op: Option<&crate::model::OpResult>) -> Value {
    let Some(op) = op else {
        return Value::Null;
    };
    json!({
        "ours_lib": measurement_json(op.ours_lib.as_ref()),
        "ours_cli": measurement_json(op.ours_cli.as_ref()),
        "reference": measurement_json(op.reference.as_ref()),
        "reference_on_ours": measurement_json(op.reference_on_ours.as_ref()),
        "cross_decode_ok": op.cross_decode_ok,
        "note": op.note,
    })
}

fn measurement_json(measurement: Option<&Measurement>) -> Value {
    let Some(measurement) = measurement else {
        return Value::Null;
    };
    json!({
        "samples_ns": measurement.samples_ns,
        "median_ns": measurement.median_ns(),
        "output_len": measurement.output_len,
        "hash": measurement.hash,
    })
}

fn build_markdown(results: &[CaseResult], cases: &[Case], cfg: &Config, json: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Performance comparison");
    let _ = writeln!(out);
    let _ = writeln!(out, "Generated: {}", now_string());
    let _ = writeln!(out);
    let _ = writeln!(out, "## Environment");
    let _ = writeln!(out);
    let _ = writeln!(out, "```");
    let _ = writeln!(out, "{}", json["environment"].as_str().unwrap_or(""));
    let _ = writeln!(out, "{}", json["build"].as_str().unwrap_or(""));
    let _ = writeln!(
        out,
        "mode: {} (iterations={}, warmup={}, size_override={:?})",
        if cfg.quick { "quick" } else { "full" },
        cfg.iterations,
        cfg.warmup,
        cfg.size_override
    );
    let _ = writeln!(out, "```");
    let _ = writeln!(out);

    let _ = writeln!(out, "## Method");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- `ours-lib`: in-process timing via the benchmark helper; process startup and input I/O are outside the timed region."
    );
    let _ = writeln!(
        out,
        "- `ours-cli`: `archive compress` / `archive test`; process startup and file I/O are included."
    );
    let _ = writeln!(
        out,
        "- `ref-cli`: reference command; process startup and file I/O are included. Decode timing writes to `/dev/null` or a temporary directory."
    );
    let _ = writeln!(
        out,
        "- Throughput is decimal MB/s (1e6 bytes/s) using the median sample. `ref/ours` is the reference throughput divided by ours; values above 1 mean the reference is faster."
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Codec results");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| format | corpus | size | ours-lib enc MB/s | ours-cli enc MB/s | ref enc MB/s | lib/ref enc | cli/ref enc | ours-lib dec MB/s | ours-cli dec MB/s | ref dec MB/s | lib/ref dec | cli/ref dec | ours ratio | ref ratio | CV | status / note |"
    );
    let _ = writeln!(
        out,
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"
    );
    for result in results
        .iter()
        .filter(|result| result.case.kind == Kind::Codec)
    {
        let encode = result.encode.as_ref();
        let decode = result.decode.as_ref();
        let ours_enc = encode.and_then(|op| op.ours_lib.as_ref());
        let cli_enc = encode.and_then(|op| op.ours_cli.as_ref());
        let ref_enc = encode.and_then(|op| op.reference.as_ref());
        let ours_dec = decode.and_then(|op| op.ours_lib.as_ref());
        let cli_dec = decode.and_then(|op| op.ours_cli.as_ref());
        let ref_dec = decode.and_then(|op| op.reference.as_ref());
        let ours_ratio =
            ours_enc.map(|measurement| ratio(measurement.output_len, result.input_len));
        let ref_ratio = ref_enc.map(|measurement| ratio(measurement.output_len, result.input_len));
        let note = result
            .error
            .as_deref()
            .or_else(|| encode.and_then(|op| op.note.as_deref()))
            .or_else(|| decode.and_then(|op| op.note.as_deref()))
            .or(result.case.note)
            .unwrap_or("");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            esc(result.case.label),
            esc(&result.corpus),
            bytes(result.input_len),
            throughput(ours_enc, result.input_len, true),
            throughput(cli_enc, result.input_len, true),
            throughput(ref_enc, result.input_len, true),
            speed_ratio(ours_enc, ref_enc, result.input_len, true),
            speed_ratio(cli_enc, ref_enc, result.input_len, true),
            throughput(ours_dec, result.input_len, false),
            throughput(cli_dec, result.input_len, false),
            throughput(ref_dec, result.input_len, false),
            speed_ratio(ours_dec, ref_dec, result.input_len, false),
            speed_ratio(cli_dec, ref_dec, result.input_len, false),
            ours_ratio.map_or("—".to_owned(), |value| format!("{value:.3}")),
            ref_ratio.map_or("—".to_owned(), |value| format!("{value:.3}")),
            cv(ours_enc, ref_enc),
            esc(note),
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Archive results");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| format | size | ours-lib pack MB/s | ours-cli pack MB/s | ref pack MB/s | lib/ref pack | cli/ref pack | ours-lib extract MB/s | ours-cli extract MB/s | ref extract MB/s | lib/ref extract | cli/ref extract | ours ratio | ref ratio | status / note |"
    );
    let _ = writeln!(
        out,
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"
    );
    for result in results
        .iter()
        .filter(|result| result.case.kind == Kind::Archive)
    {
        let encode = result.encode.as_ref();
        let decode = result.decode.as_ref();
        let ours_enc = encode.and_then(|op| op.ours_lib.as_ref());
        let cli_enc = encode.and_then(|op| op.ours_cli.as_ref());
        let ref_enc = encode.and_then(|op| op.reference.as_ref());
        let ours_dec = decode.and_then(|op| op.ours_lib.as_ref());
        let cli_dec = decode.and_then(|op| op.ours_cli.as_ref());
        let ref_dec = decode.and_then(|op| op.reference.as_ref());
        let ours_ratio =
            ours_enc.map(|measurement| ratio(measurement.output_len, result.input_len));
        let ref_ratio = ref_enc.map(|measurement| ratio(measurement.output_len, result.input_len));
        let note = result
            .error
            .as_deref()
            .or_else(|| encode.and_then(|op| op.note.as_deref()))
            .or_else(|| decode.and_then(|op| op.note.as_deref()))
            .or(result.case.note)
            .unwrap_or("");
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            esc(result.case.label),
            bytes(result.input_len),
            throughput(ours_enc, result.input_len, true),
            throughput(cli_enc, result.input_len, true),
            throughput(ref_enc, result.input_len, true),
            speed_ratio(ours_enc, ref_enc, result.input_len, true),
            speed_ratio(cli_enc, ref_enc, result.input_len, true),
            throughput(ours_dec, result.input_len, false),
            throughput(cli_dec, result.input_len, false),
            throughput(ref_dec, result.input_len, false),
            speed_ratio(ours_dec, ref_dec, result.input_len, false),
            speed_ratio(cli_dec, ref_dec, result.input_len, false),
            ours_ratio.map_or("—".to_owned(), |value| format!("{value:.3}")),
            ref_ratio.map_or("—".to_owned(), |value| format!("{value:.3}")),
            esc(note),
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Reference build provenance");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| reference | binary | package / version | compiler / build flags |"
    );
    let _ = writeln!(out, "|---|---|---|---|");
    let mut seen = std::collections::BTreeSet::new();
    for case in cases {
        let Some(reference) = case.reference else {
            continue;
        };
        if !seen.insert(reference.binary_id) {
            continue;
        }
        let path = ref_binary_path(cfg, reference.binary_id);
        let package = path
            .as_deref()
            .map(package_version)
            .unwrap_or_else(|| "<not found>".to_owned());
        let compiler = path
            .as_deref()
            .map(|path| command_line("readelf", &["-p", ".comment", &path.display().to_string()]))
            .map(|value| value.replace('\n', " "))
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            esc(reference.name),
            esc(path
                .as_deref()
                .map(|path| path.display().to_string())
                .as_deref()
                .unwrap_or("—")),
            esc(&package),
            esc(&format!("{}; {}", reference.build, compiler.trim())),
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Coverage and reference provenance");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| case | kind | status | reference | version | build flags / provenance | note |"
    );
    let _ = writeln!(out, "|---|---|---|---|---|---|---|");
    for case in cases {
        let reference = case.reference;
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            esc(case.label),
            match case.kind {
                Kind::Codec => "codec",
                Kind::Archive => "archive",
            },
            case.status(),
            esc(reference.map_or("—", |spec| spec.name)),
            esc(reference.map_or("—", |spec| spec.version)),
            esc(reference.map_or("—", |spec| spec.build)),
            esc(case.note.unwrap_or("")),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "## Notes");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Cross-decode is verified in both directions where a reference decoder exists. A `cross_decode_ok=false` row is a correctness failure, not a performance result."
    );
    let _ = writeln!(
        out,
        "- Archive metadata (timestamps, permissions, extra fields) differs between writers; compare archive sizes with that caveat."
    );
    let _ = writeln!(
        out,
        "- Do not compare absolute numbers across machines. Use the `ref/ours` ratios for a machine-independent view."
    );
    let _ = writeln!(out);
    out
}

fn throughput(measurement: Option<&Measurement>, input_len: usize, encode: bool) -> String {
    let Some(measurement) = measurement else {
        return "—".to_owned();
    };
    let median = measurement.median_ns();
    if median == 0 {
        return "—".to_owned();
    }
    let bytes = if encode {
        input_len
    } else if measurement.output_len > 0 {
        measurement.output_len
    } else {
        input_len
    };
    let mb_s = bytes as f64 / (median as f64 / 1e9) / 1e6;
    format!("{mb_s:.1}")
}

fn cv(ours: Option<&Measurement>, reference: Option<&Measurement>) -> String {
    let Some(ours) = ours else {
        return "—".to_owned();
    };
    if ours.samples_ns.len() < 2 {
        return "—".to_owned();
    }
    let value = cv_percent(ours);
    match reference {
        Some(reference) if reference.samples_ns.len() >= 2 => {
            format!("{value:.1}/{:.1}%", cv_percent(reference))
        }
        Some(_) => format!("{value:.1}/—"),
        None => format!("{value:.1}%"),
    }
}

fn cv_percent(measurement: &Measurement) -> f64 {
    if measurement.samples_ns.len() < 2 {
        return 0.0;
    }
    let mean = measurement
        .samples_ns
        .iter()
        .map(|&value| value as f64)
        .sum::<f64>()
        / measurement.samples_ns.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = measurement
        .samples_ns
        .iter()
        .map(|&value| {
            let delta = value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / (measurement.samples_ns.len() - 1) as f64;
    variance.sqrt() / mean * 100.0
}

fn speed_ratio(
    ours: Option<&Measurement>,
    reference: Option<&Measurement>,
    input_len: usize,
    encode: bool,
) -> String {
    let (Some(ours), Some(reference)) = (ours, reference) else {
        return "—".to_owned();
    };
    let ours_speed = speed(ours, input_len, encode);
    let ref_speed = speed(reference, input_len, encode);
    if ours_speed <= 0.0 {
        "—".to_owned()
    } else {
        format!("{:.2}", ref_speed / ours_speed)
    }
}

fn speed(measurement: &Measurement, input_len: usize, encode: bool) -> f64 {
    let median = measurement.median_ns();
    if median == 0 {
        return 0.0;
    }
    let bytes = if encode {
        input_len
    } else if measurement.output_len > 0 {
        measurement.output_len
    } else {
        input_len
    };
    bytes as f64 / (median as f64 / 1e9)
}

fn ratio(output_len: usize, input_len: usize) -> f64 {
    if input_len == 0 {
        0.0
    } else {
        output_len as f64 / input_len as f64
    }
}

fn bytes(value: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if value >= MIB {
        format!("{:.1} MiB", value as f64 / MIB as f64)
    } else if value >= KIB {
        format!("{:.1} KiB", value as f64 / KIB as f64)
    } else {
        format!("{value} B")
    }
}

fn esc(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn ref_binary_path(cfg: &Config, binary_id: &str) -> Option<PathBuf> {
    let built = cfg.refs_dir.join("bin").join(binary_id);
    if built.exists() {
        return Some(built);
    }
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {binary_id}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn package_version(path: &Path) -> String {
    for (program, args) in [
        ("pacman", vec!["-Qo", &path.display().to_string()]),
        ("dpkg", vec!["-S", &path.display().to_string()]),
    ] {
        let output = Command::new(program).args(args).output();
        if let Ok(output) = output
            && output.status.success()
        {
            return String::from_utf8_lossy(&output.stdout).trim().to_owned();
        }
    }
    "<unknown package>".to_owned()
}

fn environment() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "git: {}", command_line("git", &["rev-parse", "HEAD"]));
    let _ = writeln!(out, "rustc:\n{}", command_line("rustc", &["-vV"]));
    let _ = writeln!(out, "uname: {}", command_line("uname", &["-a"]));
    let _ = writeln!(out, "nproc: {}", command_line("nproc", &[]));
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("model name"))
                .map(|line| line.split(':').nth(1).unwrap_or("").trim().to_owned())
        })
        .unwrap_or_default();
    let _ = writeln!(out, "cpu: {cpu}");
    out
}

fn build_info() -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "ours: cargo bench profile (release defaults; opt-level=3, lto=false, codegen-units=16 unless overridden)"
    );
    let _ = writeln!(
        out,
        "target: {} (compile-time target features: {})",
        std::env::consts::ARCH,
        option_env!("CARGO_CFG_TARGET_FEATURE").unwrap_or("<unknown>")
    );
    let _ = writeln!(
        out,
        "RUSTFLAGS: {}",
        std::env::var("RUSTFLAGS").unwrap_or_else(|_| "<unset>".to_owned())
    );
    let _ = writeln!(
        out,
        "CARGO_PROFILE_BENCH_*: lto={:?} codegen_units={:?}",
        std::env::var("CARGO_PROFILE_BENCH_LTO").ok(),
        std::env::var("CARGO_PROFILE_BENCH_CODEGEN_UNITS").ok()
    );
    out
}

fn command_line(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "<unavailable>".to_owned())
}

fn now_string() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            let timestamp = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            format!("{timestamp} (unix:{seconds})")
        })
        .unwrap_or_else(|| format!("unix:{seconds}"))
}
