#![allow(clippy::collapsible_if)]

//! Benchmark execution: corpus setup, helper/CLI/reference timing, checks.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

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
    pub timeout: Duration,
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
        status: case.status().to_owned(),
    };
    if case.kind == Kind::Archive {
        run_archive_case(case, cfg, &mut result);
    } else {
        run_codec_case(case, cfg, corpus_label, &mut result);
    }
    result.status = runtime_status(case, cfg, &result);
    result
}

fn runtime_status(case: &Case, cfg: &Config, result: &CaseResult) -> String {
    let has_reference = result
        .encode
        .as_ref()
        .is_some_and(|op| op.reference.is_some())
        || result
            .decode
            .as_ref()
            .is_some_and(|op| op.reference.is_some());
    let has_ours = result
        .encode
        .as_ref()
        .is_some_and(|op| op.ours_lib.is_some() || op.ours_cli.is_some())
        || result
            .decode
            .as_ref()
            .is_some_and(|op| op.ours_lib.is_some() || op.ours_cli.is_some());
    let ref_expected_missing = case.reference.is_some()
        && !cfg.skip_ref
        && ((case.encode
            && case
                .reference
                .is_some_and(|reference| reference.encode.is_some())
            && result
                .encode
                .as_ref()
                .is_none_or(|op| op.reference.is_none()))
            || (case.decode
                && case
                    .reference
                    .is_some_and(|reference| reference.decode.is_some())
                && result
                    .decode
                    .as_ref()
                    .is_none_or(|op| op.reference.is_none())));
    let cross_failed = [result.encode.as_ref(), result.decode.as_ref()]
        .into_iter()
        .flatten()
        .any(|op| {
            op.cross_decode_ok == Some(false)
                || op.note.as_deref().is_some_and(|note| {
                    note.contains("manifest mismatch") || note.contains("hash mismatch")
                })
        });
    let expected_ours_missing = (case.encode
        && ((case.ours_lib
            && result
                .encode
                .as_ref()
                .is_some_and(|op| op.ours_lib.is_none()))
            || (case.ours_cli
                && !cfg.skip_cli
                && result
                    .encode
                    .as_ref()
                    .is_some_and(|op| op.ours_cli.is_none()))))
        || (case.decode
            && ((case.ours_lib
                && result
                    .decode
                    .as_ref()
                    .is_some_and(|op| op.ours_lib.is_none()))
                || (case.ours_cli
                    && !cfg.skip_cli
                    && result
                        .decode
                        .as_ref()
                        .is_some_and(|op| op.ours_cli.is_none()))));
    if cross_failed {
        "failed".to_owned()
    } else if expected_ours_missing || ref_expected_missing {
        if has_ours || has_reference {
            "partial".to_owned()
        } else {
            "failed".to_owned()
        }
    } else if has_reference {
        "measured".to_owned()
    } else if has_ours {
        "ours-only".to_owned()
    } else if case.ours_lib || case.ours_cli {
        "failed".to_owned()
    } else {
        "unavailable".to_owned()
    }
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

    let ours_lib_encoded = dir.join("ours-lib.enc");
    let ours_cli_encoded = dir.join("ours-cli.enc");
    let ref_encoded = dir.join("ref.enc");
    let mut encode = OpResult::default();
    let mut decode = OpResult::default();

    if case.encode {
        if case.ours_lib {
            match helper_codec(cfg, "encode", case, &input, &ours_lib_encoded) {
                Ok(measurement) => encode.ours_lib = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-lib encode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_codec_encode(cfg, case, &input, &ours_cli_encoded) {
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

    let common = if encode.reference.is_some() && ref_encoded.exists() {
        ref_encoded.clone()
    } else if encode.ours_lib.is_some() && ours_lib_encoded.exists() {
        ours_lib_encoded.clone()
    } else if encode.ours_cli.is_some() && ours_cli_encoded.exists() {
        ours_cli_encoded.clone()
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

        if !cfg.skip_ref && case.ours_lib && ours_lib_encoded.exists() {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let cross = dir.join("ref-on-ours.dec");
                    match run_ref_verify(cfg, &reference, &command, &ours_lib_encoded, &cross) {
                        Ok(measurement) => {
                            let ok = measurement.hash == expected_hash;
                            decode.reference_on_ours = Some(measurement);
                            merge_cross(&mut decode, ok);
                            if !ok {
                                decode.note = Some(
                                    "reference could not reproduce the input from our stream"
                                        .to_owned(),
                                );
                            }
                        }
                        Err(error) => {
                            append_note(&mut decode, format!("cross-decode: {error}"));
                            if !error.contains("not found") {
                                merge_cross(&mut decode, false);
                            }
                        }
                    }
                }
            }
        }
        if case.reference.is_none() && decode.ours_lib.is_some() {
            let ok = decode
                .ours_lib
                .as_ref()
                .is_some_and(|measurement| measurement.hash == expected_hash);
            merge_cross(&mut decode, ok);
        }
        if case.decode && case.ours_cli && !cfg.skip_cli && ours_cli_encoded.exists() {
            let cli_cross = dir.join("cli-cross.dec");
            let verified = if !cfg.skip_ref {
                case.reference
                    .and_then(|reference| reference.decode.map(|command| (reference, command)))
                    .map(|(reference, command)| {
                        run_ref_verify(cfg, &reference, &command, &ours_cli_encoded, &cli_cross)
                            .map(|measurement| measurement.hash == expected_hash)
                    })
                    .unwrap_or_else(|| {
                        helper_codec_decode(cfg, case, &ours_cli_encoded, &cli_cross)
                            .map(|measurement| measurement.hash == expected_hash)
                    })
            } else {
                helper_codec_decode(cfg, case, &ours_cli_encoded, &cli_cross)
                    .map(|measurement| measurement.hash == expected_hash)
            };
            match verified {
                Ok(ok) => merge_cross(&mut decode, ok),
                Err(error) => {
                    append_note(&mut decode, format!("ours-cli cross-decode: {error}"));
                    if !error.contains("not found") {
                        merge_cross(&mut decode, false);
                    }
                }
            }
        }
    }

    result.encode = Some(encode);
    result.decode = Some(decode);
}

fn run_archive_fixture_case(case: &Case, cfg: &Config, fixture: &str, result: &mut CaseResult) {
    let fixture_path = Path::new(fixture);
    let bytes = match fs::read(fixture_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            result.error = Some(format!("read fixture {fixture}: {error}"));
            return;
        }
    };
    result.input_len = bytes.len();
    let dir = cfg.work_dir.join("archive").join(sanitize(case.id));
    if let Err(error) = fs::create_dir_all(&dir) {
        result.error = Some(format!("create work dir: {error}"));
        return;
    }
    let mut decode = OpResult::default();
    if case.decode {
        let ours_manifest = dir.join("ours-manifest.json");
        if case.ours_lib {
            let read = if case.raw {
                helper_raw_archive_read(cfg, case, fixture_path, &ours_manifest)
            } else {
                helper_read(cfg, case, fixture_path, &ours_manifest)
            };
            match read {
                Ok(measurement) => decode.ours_lib = Some(measurement),
                Err(error) => append_note(&mut decode, format!("ours-lib decode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            let cli_out = dir.join("cli-out");
            match cli_archive_decode(cfg, case, fixture_path, &cli_out) {
                Ok(measurement) => decode.ours_cli = Some(measurement),
                Err(error) => append_note(&mut decode, format!("ours-cli extract: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let ref_dir = dir.join("ref-out");
                    match run_ref_decode(cfg, &reference, &command, fixture_path, &ref_dir) {
                        Ok(measurement) => decode.reference = Some(measurement),
                        Err(error) => append_note(&mut decode, format!("ref decode: {error}")),
                    }
                }
            }
        }
        append_note(
            &mut decode,
            "fixture decode; content is not compared with a generated tree".to_owned(),
        );
    }
    result.decode = Some(decode);
}

fn uses_self_base(case: &Case) -> bool {
    matches!(case.format, "ar" | "arc" | "lha" | "arj")
}

fn archive_base_dir(case: &Case, tree: &ArchiveTree) -> PathBuf {
    if uses_self_base(case) {
        tree.root.clone()
    } else {
        tree.root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| tree.root.clone())
    }
}

fn expected_manifest(case: &Case, tree: &ArchiveTree) -> Vec<(String, usize, u64)> {
    let mut manifest = tree.manifest();
    if uses_self_base(case) {
        for entry in &mut manifest {
            if let Some(stripped) = entry.0.strip_prefix("tree/") {
                entry.0 = stripped.to_owned();
            }
        }
    }
    manifest
}

fn run_archive_case(case: &Case, cfg: &Config, result: &mut CaseResult) {
    if let Some(fixture) = case.fixture {
        run_archive_fixture_case(case, cfg, fixture, result);
        return;
    }
    let dir = cfg.work_dir.join("archive").join(sanitize(case.id));
    let tree_dir = dir.join("tree");
    let file_count = if cfg.quick { 64 } else { 200 };
    let file_size = if cfg.quick { 8 * 1024 } else { 32 * 1024 };
    let tree = match if case.format == "ar" {
        corpus::build_flat_tree(&tree_dir, file_count, file_size)
    } else if case.format == "arc" {
        corpus::build_short_tree(&tree_dir, file_count, file_size)
    } else {
        corpus::build_tree(&tree_dir, file_count, file_size)
    } {
        Ok(tree) => tree,
        Err(error) => {
            result.error = Some(format!("build archive tree: {error}"));
            return;
        }
    };
    result.input_len = tree.total_bytes();
    let expected = expected_manifest(case, &tree);

    let ours_lib_encoded = dir.join(format!("ours-lib.{}", archive_extension(case.format)));
    let ours_cli_encoded = dir.join(format!("ours-cli.{}", archive_extension(case.format)));
    let ref_encoded = dir.join(format!("ref.{}", archive_extension(case.format)));
    let mut encode = OpResult::default();
    let mut decode = OpResult::default();

    if case.encode {
        if case.ours_lib {
            match helper_archive_encode(cfg, case, &tree, &ours_lib_encoded) {
                Ok(measurement) => encode.ours_lib = Some(measurement),
                Err(error) => append_note(&mut encode, format!("ours-lib encode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            match cli_archive_encode(cfg, case, &tree, &ours_cli_encoded) {
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

    let common = if encode.reference.is_some() && ref_encoded.exists() {
        ref_encoded.clone()
    } else if encode.ours_lib.is_some() && ours_lib_encoded.exists() {
        ours_lib_encoded.clone()
    } else if encode.ours_cli.is_some() && ours_cli_encoded.exists() {
        ours_cli_encoded.clone()
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
                    let ok = manifest_matches_for(case, &ours_manifest, &expected);
                    decode.ours_lib = Some(measurement);
                    if !ok {
                        decode.note = Some("ours-lib archive manifest mismatch".to_owned());
                    }
                }
                Err(error) => append_note(&mut decode, format!("ours-lib decode: {error}")),
            }
        }
        if case.ours_cli && !cfg.skip_cli {
            let cli_out = dir.join("cli-out");
            match cli_archive_decode(cfg, case, &common, &cli_out) {
                Ok(measurement) => {
                    let ok = dir_manifest_matches_for(case, &cli_out, &expected);
                    decode.ours_cli = Some(measurement);
                    if !ok {
                        decode.note = Some("ours-cli extraction manifest mismatch".to_owned());
                    }
                }
                Err(error) => append_note(&mut decode, format!("ours-cli extract: {error}")),
            }
        }
        if !cfg.skip_ref {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let ref_dir = dir.join("ref-out");
                    match run_ref_decode(cfg, &reference, &command, &common, &ref_dir) {
                        Ok(measurement) => {
                            let ok = dir_manifest_matches_for(case, &ref_dir, &expected);
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

        if !cfg.skip_ref && case.ours_lib && ours_lib_encoded.exists() {
            if let Some(reference) = case.reference {
                if let Some(command) = reference.decode {
                    let cross_dir = dir.join("ref-on-ours");
                    match run_ref_verify(cfg, &reference, &command, &ours_lib_encoded, &cross_dir) {
                        Ok(measurement) => {
                            let ok = dir_manifest_matches_for(case, &cross_dir, &expected);
                            decode.reference_on_ours = Some(measurement);
                            merge_cross(&mut decode, ok);
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

    if case.decode && case.ours_cli && !cfg.skip_cli && ours_cli_encoded.exists() {
        let cli_cross = dir.join("cli-cross");
        let verified = if !cfg.skip_ref {
            case.reference
                .and_then(|reference| reference.decode.map(|command| (reference, command)))
                .map(|(reference, command)| {
                    run_ref_verify(cfg, &reference, &command, &ours_cli_encoded, &cli_cross)
                        .map(|_| dir_manifest_matches_for(case, &cli_cross, &expected))
                })
                .unwrap_or_else(|| {
                    helper_read(cfg, case, &ours_cli_encoded, &dir.join("cli-cross.json"))
                        .map(|_| manifest_matches_for(case, &dir.join("cli-cross.json"), &expected))
                })
        } else {
            helper_read(cfg, case, &ours_cli_encoded, &dir.join("cli-cross.json"))
                .map(|_| manifest_matches_for(case, &dir.join("cli-cross.json"), &expected))
        };
        match verified {
            Ok(ok) => {
                merge_cross(&mut decode, ok);
                if !ok {
                    append_note(
                        &mut decode,
                        "ours-cli archive did not round-trip".to_owned(),
                    );
                }
            }
            Err(error) => {
                append_note(&mut decode, format!("ours-cli cross-decode: {error}"));
                if !error.contains("not found") {
                    merge_cross(&mut decode, false);
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
    let mut args = if case.raw {
        vec!["raw".to_owned(), "codec".to_owned()]
    } else {
        vec!["codec".to_owned()]
    };
    args.push(op.to_owned());
    args.extend([
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
    ]);
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
        archive_base_dir(case, tree).display().to_string(),
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

fn helper_raw_archive_read(
    cfg: &Config,
    case: &Case,
    input: &Path,
    output: &Path,
) -> Result<Measurement, String> {
    let args = vec![
        "raw".to_owned(),
        "archive".to_owned(),
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

fn read_stdout(pipe: Option<std::process::ChildStdout>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}

fn read_stderr(pipe: Option<std::process::ChildStderr>) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    }
    Ok(bytes)
}

fn run_helper(cfg: &Config, args: &[String], output: &Path) -> Result<Measurement, String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let _ = fs::remove_file(output);
    let mut child = Command::new(&cfg.helper_bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", cfg.helper_bin.display()))?;
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_thread = std::thread::spawn(move || read_stdout(stdout_pipe));
    let stderr_thread = std::thread::spawn(move || read_stderr(stderr_pipe));
    let status = wait_status(&mut child, cfg.timeout)?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| "helper stdout reader panicked".to_owned())??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "helper stderr reader panicked".to_owned())??;
    if !status.success() {
        return Err(format!(
            "helper failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        ));
    }
    let value: Value =
        serde_json::from_slice(&stdout).map_err(|error| format!("parse helper JSON: {error}"))?;
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
    let cli_format = if cli_format == "lzsa2" {
        "lzsa"
    } else {
        cli_format
    };
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
    let base = archive_base_dir(case, tree);
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

fn cli_archive_decode(
    cfg: &Config,
    case: &Case,
    input: &Path,
    out_dir: &Path,
) -> Result<Measurement, String> {
    let archive = cfg.archive_bin.as_ref().ok_or("archive CLI not found")?;
    if !case.cli_extract {
        let args = vec![
            "test".to_owned(),
            input.display().to_string(),
            "--format".to_owned(),
            case.format.to_owned(),
        ];
        return measure_process(archive, &args, Path::new("/dev/null"), cfg, false);
    }
    let args = vec![
        "extract".to_owned(),
        input.display().to_string(),
        "--format".to_owned(),
        case.format.to_owned(),
        "--out".to_owned(),
        out_dir.display().to_string(),
        "--overwrite".to_owned(),
    ];
    measure_process_dir(archive, &args, out_dir, cfg)
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
        run_process(program, args, remove_output.then_some(output), cfg.timeout)?;
    }
    for _ in 0..cfg.iterations {
        let start = Instant::now();
        run_process(program, args, remove_output.then_some(output), cfg.timeout)?;
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

fn measure_process_dir(
    program: &Path,
    args: &[String],
    out_dir: &Path,
    cfg: &Config,
) -> Result<Measurement, String> {
    let mut samples = Vec::with_capacity(cfg.iterations);
    for _ in 0..cfg.warmup {
        run_process_dir(program, args, out_dir, cfg.timeout)?;
    }
    for _ in 0..cfg.iterations {
        let start = Instant::now();
        run_process_dir(program, args, out_dir, cfg.timeout)?;
        samples.push(start.elapsed().as_nanos() as u64);
    }
    let manifest = read_dir_manifest(out_dir)?;
    Ok(Measurement {
        samples_ns: samples,
        output_len: manifest.iter().map(|(_, len, _)| *len).sum(),
        hash: combined_manifest_hash(&manifest),
    })
}

fn run_process_dir(
    program: &Path,
    args: &[String],
    out_dir: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let _ = fs::remove_dir_all(out_dir);
    fs::create_dir_all(out_dir).map_err(|error| error.to_string())?;
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", program.display()))?;
    let status = wait_status(&mut child, timeout)?;
    if !status.success() {
        return Err(format!(
            "{} exited with {}",
            program.display(),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn run_process(
    program: &Path,
    args: &[String],
    remove: Option<&Path>,
    timeout: Duration,
) -> Result<(), String> {
    if let Some(path) = remove {
        let _ = fs::remove_file(path);
    }
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", program.display()))?;
    let status = wait_status(&mut child, timeout)?;
    if !status.success() {
        return Err(format!(
            "{} exited with {}",
            program.display(),
            status.code().unwrap_or(-1)
        ));
    }
    Ok(())
}

fn wait_status(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
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
    require_program(cfg, spec, command)?;
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
    require_program(cfg, spec, command)?;
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
    require_program(cfg, spec, command)?;
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
    let refs_bin = absolute_path(&cfg.refs_dir.join("bin"));
    if refs_bin.exists() {
        if let Some(path) = std::env::var_os("PATH") {
            let mut paths = vec![refs_bin];
            paths.extend(std::env::split_paths(&path));
            if let Ok(joined) = std::env::join_paths(paths) {
                process.env("PATH", joined);
            }
        }
    }
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
    let mut child = process
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", program.display()))?;
    let status = wait_status(&mut child, cfg.timeout)?;
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

fn resolve_program(cfg: &Config, _spec: &RefSpec, command: &RefCommand) -> PathBuf {
    let built = cfg.refs_dir.join("bin").join(command.program);
    if built.exists() {
        built
    } else {
        PathBuf::from(command.program)
    }
}

fn require_program(cfg: &Config, spec: &RefSpec, command: &RefCommand) -> Result<(), String> {
    if !program_exists(cfg, command.program) {
        return Err(format!(
            "reference binary `{}` not found; run `make bench-refs` or install it",
            command.program
        ));
    }
    if command.program == "bash" && !program_exists(cfg, spec.binary_id) {
        return Err(format!(
            "reference binary `{}` not found; run `make bench-refs` or install it",
            spec.binary_id
        ));
    }
    Ok(())
}

fn program_exists(cfg: &Config, program: &str) -> bool {
    if cfg.refs_dir.join("bin").join(program).exists() {
        return true;
    }
    Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

fn dir_manifest_matches(dir: &Path, expected: &[(String, usize, u64)]) -> bool {
    let Ok(manifest) = read_dir_manifest(dir) else {
        return false;
    };
    let actual: Vec<(String, usize, u64)> = manifest.into_iter().collect();
    let expected: Vec<(String, usize, u64)> = expected.to_vec();
    actual == expected
}

fn manifest_matches_for(case: &Case, path: &Path, expected: &[(String, usize, u64)]) -> bool {
    if case.format == "git-pack" {
        manifest_data_matches(path, expected)
    } else {
        manifest_matches(path, expected)
    }
}

fn dir_manifest_matches_for(case: &Case, dir: &Path, expected: &[(String, usize, u64)]) -> bool {
    if case.format == "git-pack" {
        dir_manifest_data_matches(dir, expected)
    } else {
        dir_manifest_matches(dir, expected)
    }
}

fn manifest_data_matches(path: &Path, expected: &[(String, usize, u64)]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let Some(entries) = value.get("entries").and_then(Value::as_array) else {
        return false;
    };
    let mut actual: Vec<(usize, u64)> = entries
        .iter()
        .filter_map(|entry| {
            Some((
                entry.get("len")?.as_u64()? as usize,
                entry.get("hash")?.as_u64()?,
            ))
        })
        .collect();
    let mut expected: Vec<(usize, u64)> = expected
        .iter()
        .map(|(_, len, hash)| (*len, *hash))
        .collect();
    actual.sort_unstable();
    actual.dedup();
    expected.sort_unstable();
    expected.dedup();
    actual == expected
}

fn dir_manifest_data_matches(dir: &Path, expected: &[(String, usize, u64)]) -> bool {
    let Ok(manifest) = read_dir_manifest(dir) else {
        return false;
    };
    let mut actual: Vec<(usize, u64)> = manifest
        .into_iter()
        .map(|(_, len, hash)| (len, hash))
        .collect();
    let mut expected: Vec<(usize, u64)> = expected
        .iter()
        .map(|(_, len, hash)| (*len, *hash))
        .collect();
    actual.sort_unstable();
    actual.dedup();
    expected.sort_unstable();
    expected.dedup();
    actual == expected
}

fn manifest_matches(path: &Path, expected: &[(String, usize, u64)]) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    let Some(entries) = value.get("entries").and_then(Value::as_array) else {
        return false;
    };
    let mut actual: Vec<(String, usize, u64)> = entries
        .iter()
        .filter_map(|entry| {
            Some((
                entry.get("name")?.as_str()?.to_owned(),
                entry.get("len")?.as_u64()? as usize,
                entry.get("hash")?.as_u64()?,
            ))
        })
        .collect();
    actual.sort_by(|a, b| a.0.cmp(&b.0));
    let expected: Vec<(String, usize, u64)> = expected.to_vec();
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

fn merge_cross(result: &mut OpResult, ok: bool) {
    result.cross_decode_ok = Some(result.cross_decode_ok.unwrap_or(true) && ok);
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
