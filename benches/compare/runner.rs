#![allow(clippy::collapsible_if)]

//! Benchmark execution: corpus setup, helper/CLI/reference timing, checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde_json::Value;

use crate::corpus::{self, ArchiveTree};
use crate::model::{
    Case, CaseResult, Kind, Measurement, OpResult, OutputMode, RefCommand, RefSpec,
};

#[derive(Debug, Clone)]
pub struct Config {
    pub quick: bool,
    pub corpora: Vec<String>,
    pub iterations: usize,
    pub warmup: usize,
    pub size_override: Option<usize>,
    pub helper_bin: PathBuf,
    pub archive_bin: Option<PathBuf>,
    pub refs_dir: PathBuf,
    pub work_dir: PathBuf,
    pub skip_cli: bool,
    pub skip_ref: bool,
}

impl Config {
    pub fn size(&self, case: &Case) -> usize {
        self.size_override.unwrap_or(if self.quick {
            case.size.quick
        } else {
            case.size.full
        })
    }
}

pub fn run_case(case: &Case, cfg: &Config, corpus_label: &str) -> CaseResult {
    let mut result = CaseResult {
        case: *case,
        corpus: corpus_label.to_owned(),
        input_len: 0,
        encode: None,
        decode: None,
        error: None,
    };
    if case.kind == Kind::Archive {
        run_archive_case(case, cfg, &mut result);
    } else {
        run_codec_case(case, cfg, corpus_label, &mut result);
    }
    result
}

fn run_codec_case(case: &Case, cfg: &Config, corpus_label: &str, result: &mut CaseResult) {
    let size = cfg.size(case);
    let data = corpus::generate(corpus_label, size);
    result.input_len = data.len();
    let dir = cfg
        .work_dir
        .join("codec")
        .join(sanitize(case.id))
        .join(sanitize(corpus_label));
    if let Err(error) = fs::create_dir_all(&dir) {
        result.error = Some(format!("create work dir: {error}"));
        return;
    }
    let input = dir.join("input.bin");
    if let Err(error) = fs::write(&input, &data) {
        result.error = Some(format!("write input: {error}"));
        return;
    }
    let expected_hash = corpus::fnv1a64(&data);

    let ours_encoded = dir.join("ours.enc");
    let ref_encoded = dir.join("ref.enc");
    let mut encode = OpResult::default();
    let mut decode = OpResult::default();

    if case.encode {
        if case.ours_lib {
            match helper_codec(cfg, "encode", case, &input, &ours_encoded) {
                Ok(measurement) => encode.ours_lib = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-lib encode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_codec_encode(cfg, case, &input, &ours_encoded) {
                Ok(measurement) => encode.ours_cli = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-cli encode: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.encode {
                    match run_ref_encode(cfg, &reference, &command, &input, &ref_encoded) {
                        Ok(measurement) => encode.reference = Some(measurement),
                        Err(error) => append_note(&mut encode, format!("ref encode: {error}")),
                    }
                } else {
                    append_note(&mut encode, "reference has no encoder".to_owned());
                }
            }
        }
    }

    let common = if ref_encoded.exists() {
        ref_encoded.clone()
    } else if ours_encoded.exists() {
        ours_encoded.clone()
    } else {
        result.encode = Some(encode);
        result.error = Some("no encoded stream produced".to_owned());
        return;
    };

    if case.decode {
        if case.ours_lib {
            let ours_decoded = dir.join("ours.dec");
            match helper_codec_decode(cfg, case, &common, &ours_decoded) {
                Ok(measurement) => {
                    if measurement.hash != expected_hash {
                        decode.note =
                            Some("ours-lib decode hash mismatch on common stream".to_owned());
                    }
                    decode.ours_lib = Some(measurement);
                }
                Err(error) => append_note(&mut decode, format!("ours-lib decode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_codec_decode(cfg, case, &common) {
                Ok(measurement) => decode.ours_cli = Some(measurement),
                Err(error) => append_note(&mut decode, format!("ours-cli decode: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let verify = dir.join("ref.dec");
                    match run_ref_decode(cfg, &reference, &command, &common, &verify) {
                        Ok(measurement) => {
                            if measurement.hash != expected_hash {
                                decode.note = Some(
                                    "reference decode hash mismatch on common stream".to_owned(),
                                );
                            }
                            decode.reference = Some(measurement);
                        }
                        Err(error) => append_note(&mut decode, format!("ref decode: {error}")),
                    }
                } else {
                    append_note(&mut decode, "reference has no decoder".to_owned());
                }
            }
        }

        if !cfg.skip_ref && case.ours_lib && ours_encoded.exists() {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let cross = dir.join("ref-on-ours.dec");
                    match run_ref_verify(cfg, &reference, &command, &ours_encoded, &cross) {
                        Ok(measurement) => {
                            let ok = measurement.hash == expected_hash;
                            decode.reference_on_ours = Some(measurement);
                            decode.cross_decode_ok = Some(ok);
                            if !ok {
                                decode.note = Some(
                                    "reference could not reproduce the input from our stream"
                                        .to_owned(),
                                );
                            }
                        }
                        Err(error) => append_note(&mut decode, format!("cross-decode: {error}")),
                    }
                }
            }
        } else if case.reference.is_none() && decode.ours_lib.is_some() {
            decode.cross_decode_ok = Some(
                decode
                    .ours_lib
                    .as_ref()
                    .is_some_and(|measurement| measurement.hash == expected_hash),
            );
        }
    }

    result.encode = Some(encode);
    result.decode = Some(decode);
}

fn run_archive_case(case: &Case, cfg: &Config, result: &mut CaseResult) {
    let dir = cfg.work_dir.join("archive").join(sanitize(case.id));
    let tree_dir = dir.join("tree");
    let file_count = if cfg.quick { 24 } else { 120 };
    let file_size = if cfg.quick { 4 * 1024 } else { 16 * 1024 };
    let tree = match corpus::build_tree(&tree_dir, file_count, file_size) {
        Ok(tree) => tree,
        Err(error) => {
            result.error = Some(format!("build archive tree: {error}"));
            return;
        }
    };
    result.input_len = tree.total_bytes();
    let expected = tree.manifest();

    let ours_encoded = dir.join(format!("ours.{}", archive_extension(case.format)));
    let ref_encoded = dir.join(format!("ref.{}", archive_extension(case.format)));
    let mut encode = OpResult::default();
    let mut decode = OpResult::default();

    if case.encode {
        if case.ours_lib {
            match helper_archive_encode(cfg, case, &tree, &ours_encoded) {
                Ok(measurement) => encode.ours_lib = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-lib encode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_archive_encode(cfg, case, &tree, &ours_encoded) {
                Ok(measurement) => encode.ours_cli = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-cli encode: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.encode {
                    match run_ref_encode(cfg, &reference, &command, &tree.root, &ref_encoded) {
                        Ok(measurement) => encode.reference = Some(measurement),
                        Err(error) => append_note(&mut encode, format!("ref encode: {error}")),
                    }
                } else {
                    append_note(&mut encode, "reference has no encoder".to_owned());
                }
            }
        }
    }

    let common = if ref_encoded.exists() {
        ref_encoded.clone()
    } else if ours_encoded.exists() {
        ours_encoded.clone()
    } else {
        result.encode = Some(encode);
        result.error = Some("no archive produced".to_owned());
        return;
    };

    if case.decode {
        let ours_manifest = dir.join("ours-manifest.json");
        if case.ours_lib {
            match helper_read(cfg, case, &common, &ours_manifest) {
                Ok(measurement) => {
                    let ok = manifest_matches(&ours_manifest, &expected);
                    decode.ours_lib = Some(measurement);
                    if !ok {
                        decode.note = Some("ours-lib archive manifest mismatch".to_owned());
                    }
                }
                Err(error) => append_note(&mut decode, format!("ours-lib decode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_archive_decode(cfg, case, &common) {
                Ok(measurement) => decode.ours_cli = Some(measurement),
                Err(error) => append_note(&mut decode, format!("ours-cli decode: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let ref_dir = dir.join("ref-out");
                    match run_ref_decode(cfg, &reference, &command, &common, &ref_dir) {
                        Ok(measurement) => {
                            let ok = dir_manifest_matches(&ref_dir, &expected);
                            decode.reference = Some(measurement);
                            if !ok {
                                decode.note =
                                    Some("reference extraction manifest mismatch".to_owned());
                            }
                        }
                        Err(error) => append_note(&mut decode, format!("ref decode: {error}")),
                    }
                } else {
                    append_note(&mut decode, "reference has no decoder".to_owned());
                }
            }
        }

        if !cfg.skip_ref && case.ours_lib && ours_encoded.exists() {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let cross_dir = dir.join("ref-on-ours");
                    match run_ref_verify(cfg, &reference, &command, &ours_encoded, &cross_dir) {
                        Ok(measurement) => {
                            let ok = dir_manifest_matches(&cross_dir, &expected);
                            decode.reference_on_ours = Some(measurement);
                            decode.cross_decode_ok = Some(ok);
                            if !ok {
                                decode.note = Some(
                                    "reference could not reproduce the tree from our archive"
                                        .to_owned(),
                                );
                            }
                        }
                        Err(error) => append_note(&mut decode, format!("cross-decode: {error}")),
                    }
                }
            }
        }
    }

    result.encode = Some(encode);
    result.decode = Some(decode);
}

// ---------------------------------------------------------------------------
// Helper process
// ---------------------------------------------------------------------------

fn helper_codec(
    cfg: &Config,
    op: &str,
    case: &Case,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    let mut args = vec![
        "codec".to_owned(),
        op.to_owned(),
        "--format".to_owned(),
        case.format.to_owned(),
        "--input".to_owned(),
        input.display().to_string(),
        "--output".to_owned(),
        output.display().to_string(),
        "--warmup".to_owned(),
        cfg.warmup.to_string(),
        "--iterations".to_owned(),
        cfg.iterations.to_string(),
    ];
    if let Some(level) = case.level {
        args.push("--level".to_owned());
        args.push(level.to_string());
    }
    if let Some(backend) = case.backend {
        args.push("--backend".to_owned());
        args.push(backend.to_owned());
    }
    run_helper(cfg, &args, output)
}

fn helper_codec_decode(
    cfg: &Config,
    case: &Case,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    helper_codec(cfg, "decode", case, input, output)
}

fn helper_archive_encode(
    cfg: &Config,
    case: &Case,
    tree: &ArchiveTree,
    output: &Path,
) -> Result<Measurement, String> {
    let args = vec![
        "archive".to_owned(),
        "encode".to_owned(),
        "--format".to_owned(),
        case.format.to_owned(),
        "--input".to_owned(),
        tree.root.display().to_string(),
        "--output".to_owned(),
        output.display().to_string(),
        "--base-dir".to_owned(),
        tree.root
            .parent()
            .map(|path| path.display().to_string())
            .unwrap_or_default(),
        "--warmup".to_owned(),
        cfg.warmup.to_string(),
        "--iterations".to_owned(),
        cfg.iterations.to_string(),
    ];
    run_helper(cfg, &args, output)
}

fn helper_read(
    cfg: &Config,
    case: &Case,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    let args = vec![
        "read".to_owned(),
        "--format".to_owned(),
        case.format.to_owned(),
        "--input".to_owned(),
        input.display().to_string(),
        "--output".to_owned(),
        output.display().to_string(),
        "--warmup".to_owned(),
        cfg.warmup.to_string(),
        "--iterations".to_owned(),
        cfg.iterations.to_string(),
    ];
    run_helper(cfg, &args, output)
}

fn run_helper(cfg: &Config, args: &[String], output: &Path) -> Result<Measurement, String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let _ = fs::remove_file(output);
    let output_process = Command::new(&cfg.helper_bin)
        .args(args)
        .output()
        .map_err(|error| format!("spawn {}: {error}", cfg.helper_bin.display()))?;
    if !output_process.status.success() {
        return Err(format!(
            "helper failed: {}",
            String::from_utf8_lossy(&output_process.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_slice(&output_process.stdout)
        .map_err(|error| format!("parse helper JSON: {error}"))?;
    let samples = value
        .get("samples_ns")
        .and_then(Value::as_array)
        .ok_or_else(|| "helper omitted samples_ns".to_owned())?
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    Ok(Measurement {
        samples_ns: samples,
        output_len: value.get("output_len").and_then(Value::as_u64).unwrap_or(0) as usize,
        hash: value
            .get("output_hash")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

// ---------------------------------------------------------------------------
// Our CLI
// ---------------------------------------------------------------------------

fn cli_codec_encode(
    cfg: &Config,
    case: &Case,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    let archive = cfg.archive_bin.as_ref().ok_or("archive CLI not found")?;
    let cli_format = case.cli_format.ok_or("CLI format not exposed")?;
    let mut args = vec![
        "compress".to_owned(),
        cli_format.to_owned(),
        input.display().to_string(),
        "-o".to_owned(),
        output.display().to_string(),
    ];
    if let Some(level) = case.level {
        args.push("--level".to_owned());
        args.push(level.to_string());
    }
    if let Some(backend) = case.backend {
        args.push("--backend".to_owned());
        args.push(backend.to_owned());
    }
    measure_process(archive, &args, output, cfg, true)
}

fn cli_codec_decode(cfg: &Config, case: &Case, input: &Path) -> Result<Measurement, String> {
    let archive = cfg.archive_bin.as_ref().ok_or("archive CLI not found")?;
    let cli_format = case.cli_format.ok_or("CLI format not exposed")?;
    let args = vec![
        "test".to_owned(),
        input.display().to_string(),
        "--format".to_owned(),
        cli_format.to_owned(),
    ];
    measure_process(archive, &args, Path::new("/dev/null"), cfg, false)
}

fn cli_archive_encode(
    cfg: &Config,
    case: &Case,
    tree: &ArchiveTree,
    output: &Path,
) -> Result<Measurement, String> {
    let archive = cfg.archive_bin.as_ref().ok_or("archive CLI not found")?;
    let base = tree.root.parent().ok_or("archive tree has no parent")?;
    let args = vec![
        "pack".to_owned(),
        case.format.to_owned(),
        tree.root.display().to_string(),
        "-o".to_owned(),
        output.display().to_string(),
        "--base-dir".to_owned(),
        base.display().to_string(),
    ];
    measure_process(archive, &args, output, cfg, true)
}

fn cli_archive_decode(cfg: &Config, case: &Case, input: &Path) -> Result<Measurement, String> {
    let archive = cfg.archive_bin.as_ref().ok_or("archive CLI not found")?;
    let args = vec![
        "test".to_owned(),
        input.display().to_string(),
        "--format".to_owned(),
        case.format.to_owned(),
    ];
    measure_process(archive, &args, Path::new("/dev/null"), cfg, false)
}

fn measure_process(
    program: &Path,
    args: &[String],
    output: &Path,
    cfg: &Config,
    remove_output: bool,
) -> Result<Measurement, String> {
    let mut samples = Vec::with_capacity(cfg.iterations);
    for _ in 0..cfg.warmup {
        run_process(program, args, remove_output.then_some(output))?;
    }
    for _ in 0..cfg.iterations {
        let start = Instant::now();
        run_process(program, args, remove_output.then_some(output))?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let (output_len, hash) = if remove_output && output.exists() {
        measure_file(output)?
    } else {
        (0, 0)
    };
    Ok(Measurement {
        samples_ns: samples,
        output_len,
        hash,
    })
}

fn run_process(program: &Path, args: &[String], remove: Option<&Path>) -> Result<(), String> {
    if let Some(path) = remove {
        let _ = fs::remove_file(path);
    }
    let status = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("spawn {}: {error}", program.display()))?;
    if !status.success() {
        return Err(format!(
            "{} exited with {}",
            program.display(),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reference processes
// ---------------------------------------------------------------------------

fn run_ref_encode(
    cfg: &Config,
    spec: &RefSpec,
    command: &RefCommand,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    let mut samples = Vec::with_capacity(cfg.iterations);
    for _ in 0..cfg.warmup {
        run_ref_once(cfg, spec, command, input, output)?;
    }
    for _ in 0..cfg.iterations {
        let start = Instant::now();
        run_ref_once(cfg, spec, command, input, output)?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let (output_len, hash) = measure_output(output, command.output)?;
    Ok(Measurement {
        samples_ns: samples,
        output_len,
        hash,
    })
}

fn run_ref_decode(
    cfg: &Config,
    spec: &RefSpec,
    command: &RefCommand,
    input: &Path,
    verify_output: &Path,
) -> Result<Measurement, String> {
    let timing_output = timing_output_path(cfg, command.output, verify_output);
    let mut samples = Vec::with_capacity(cfg.iterations);
    for _ in 0..cfg.warmup {
        run_ref_once(cfg, spec, command, input, &timing_output)?;
    }
    for _ in 0..cfg.iterations {
        let start = Instant::now();
        run_ref_once(cfg, spec, command, input, &timing_output)?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    cleanup_timing_output(command.output, &timing_output);
    run_ref_once(cfg, spec, command, input, verify_output)?;
    let (output_len, hash) = measure_output(verify_output, command.output)?;
    Ok(Measurement {
        samples_ns: samples,
        output_len,
        hash,
    })
}

fn run_ref_verify(
    cfg: &Config,
    spec: &RefSpec,
    command: &RefCommand,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    run_ref_once(cfg, spec, command, input, output)?;
    let (output_len, hash) = measure_output(output, command.output)?;
    Ok(Measurement {
        samples_ns: Vec::new(),
        output_len,
        hash,
    })
}

fn run_ref_once(
    cfg: &Config,
    spec: &RefSpec,
    command: &RefCommand,
    input: &Path,
    output: &Path,
) -> Result<(), String> {
    let program = resolve_program(cfg, spec, command);
    let input = absolute_path(input);
    let output = absolute_path(output);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    match command.output {
        OutputMode::Dir => {
            let _ = fs::remove_dir_all(&output);
            fs::create_dir_all(&output).map_err(|error| error.to_string())?;
        }
        OutputMode::Arg | OutputMode::None => {
            let _ = fs::remove_file(&output);
        }
        OutputMode::Stdout => {
            if output != Path::new("/dev/null") {
                let _ = fs::remove_file(&output);
            }
        }
    }

    let mut process = Command::new(&program);
    for arg in command.args {
        process.arg(
            arg.replace("{input}", &input.display().to_string())
                .replace("{output}", &output.display().to_string()),
        );
    }
    process.stdout(Stdio::null()).stderr(Stdio::null());
    if matches!(command.output, OutputMode::Stdout) {
        let file = fs::File::create(&output).map_err(|error| error.to_string())?;
        process.stdout(Stdio::from(file));
    }
    let status = process
        .status()
        .map_err(|error| format!("spawn {}: {error}", program.display()))?;
    if !status.success() {
        return Err(format!(
            "{} exited with {}",
            program.display(),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn timing_output_path(cfg: &Config, mode: OutputMode, verify_output: &Path) -> PathBuf {
    match mode {
        OutputMode::Stdout => PathBuf::from("/dev/null"),
        OutputMode::Dir => cfg.work_dir.join("timing-dir"),
        OutputMode::Arg | OutputMode::None => {
            let _ = verify_output;
            cfg.work_dir.join("timing-output")
        }
    }
}

fn cleanup_timing_output(mode: OutputMode, path: &Path) {
    match mode {
        OutputMode::Dir => {
            let _ = fs::remove_dir_all(path);
        }
        OutputMode::Arg | OutputMode::None => {
            let _ = fs::remove_file(path);
        }
        OutputMode::Stdout => {}
    }
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if path.exists() {
        return fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    match path.file_name() {
        Some(name) => base.join(name),
        None => base,
    }
}

fn resolve_program(cfg: &Config, spec: &RefSpec, command: &RefCommand) -> PathBuf {
    let built = cfg.refs_dir.join("bin").join(spec.binary_id);
    if built.exists() {
        built
    } else {
        PathBuf::from(command.program)
    }
}

fn measure_output(path: &Path, mode: OutputMode) -> Result<(usize, u64), String> {
    if matches!(mode, OutputMode::Dir) {
        let manifest = read_dir_manifest(path)?;
        let len = manifest.iter().map(|(_, len, _)| *len).sum();
        Ok((len, combined_manifest_hash(&manifest)))
    } else {
        measure_file(path)
    }
}

fn measure_file(path: &Path) -> Result<(usize, u64), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok((bytes.len(), corpus::fnv1a64(&bytes)))
}

fn dir_manifest_matches(dir: &Path, expected: &[(String, u64)]) -> bool {
    let Ok(manifest) = read_dir_manifest(dir) else {
        return false;
    };
    let actual: Vec<(String, u64)> = manifest
        .into_iter()
        .map(|(name, _, hash)| (name, hash))
        .collect();
    actual == expected
}

fn manifest_matches(path: &Path, expected: &[(String, u64)]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let Some(entries) = value.get("entries").and_then(Value::as_array) else {
        return false;
    };
    let mut actual: Vec<(String, u64)> = entries
        .iter()
        .filter_map(|entry| {
            Some((
                entry.get("name")?.as_str()?.to_owned(),
                entry.get("hash")?.as_u64()?,
            ))
        })
        .collect();
    actual.sort_by(|a, b| a.0.cmp(&b.0));
    actual == expected
}

fn read_dir_manifest(dir: &Path) -> Result<Vec<(String, usize, u64)>, String> {
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, usize, u64)>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            walk(root, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            let relative = relative.strip_prefix("./").unwrap_or(&relative).to_owned();
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            out.push((relative, bytes.len(), corpus::fnv1a64(&bytes)));
        }
    }
    Ok(())
}

fn combined_manifest_hash(manifest: &[(String, usize, u64)]) -> u64 {
    let mut bytes = Vec::new();
    for (name, len, hash) in manifest {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(*len as u64).to_le_bytes());
        bytes.extend_from_slice(&hash.to_le_bytes());
    }
    corpus::fnv1a64(&bytes)
}

fn append_note(result: &mut OpResult, note: String) {
    match &mut result.note {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&note);
        }
        None => result.note = Some(note),
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn archive_extension(format: &str) -> &'static str {
    match format {
        "tar" => "tar",
        "cpio" => "cpio",
        "ar" => "a",
        "zip" => "zip",
        "7z" => "7z",
        "zpaq" => "zpaq",
        "lha" => "lzh",
        "arj" => "arj",
        "arc" => "arc",
        "git-pack" => "pack",
        "xar" => "xar",
        "deb" => "deb",
        "rpm" => "rpm",
        "mscab" => "cab",
        "zim" => "zim",
        "mtree" => "mtree",
        "warc" => "warc",
        _ => "bin",
    }
}
