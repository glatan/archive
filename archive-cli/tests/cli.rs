#![cfg(feature = "json")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_dir(prefix: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let serial = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "archive_cli_test_{prefix}_{}_{serial}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_archive"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn pack_list_extract_roundtrip() {
    let dir = temp_dir("roundtrip");
    std::fs::write(dir.join("input.txt"), b"cli integration payload").unwrap();

    let pack = run(&dir, &["pack", "tar", "input.txt", "-o", "archive.tar"]);
    assert!(pack.status.success(), "pack failed: {}", stderr(&pack));

    let list = run(&dir, &["list", "archive.tar", "--json", "--no-pager"]);
    assert!(list.status.success(), "list failed: {}", stderr(&list));
    let report: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        report.to_string().contains("input.txt"),
        "listing does not mention input.txt: {report}"
    );

    let inspect = run(&dir, &["inspect", "archive.tar", "--json"]);
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        stderr(&inspect)
    );
    let report: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
    assert!(
        report.to_string().contains("input.txt"),
        "inspection does not mention input.txt: {report}"
    );

    let extract = run(&dir, &["extract", "archive.tar", "--out", "out"]);
    assert!(
        extract.status.success(),
        "extract failed: {}",
        stderr(&extract)
    );
    assert_eq!(
        std::fs::read(dir.join("out/input.txt")).unwrap(),
        b"cli integration payload"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compress_and_test_json_roundtrip() {
    let dir = temp_dir("compress");
    let payload = b"cli compress payload ".repeat(64);
    std::fs::write(dir.join("input.bin"), &payload).unwrap();

    let compress = run(
        &dir,
        &["compress", "gzip", "input.bin", "-o", "input.bin.gz"],
    );
    assert!(
        compress.status.success(),
        "compress failed: {}",
        stderr(&compress)
    );

    let test = run(&dir, &["test", "input.bin.gz", "--json"]);
    assert!(test.status.success(), "test failed: {}", stderr(&test));
    let report: serde_json::Value = serde_json::from_slice(&test.stdout).unwrap();
    assert_eq!(report["ok"], true, "unexpected test report: {report}");

    let extract = run(&dir, &["extract", "input.bin.gz", "--out", "out"]);
    assert!(
        extract.status.success(),
        "extract failed: {}",
        stderr(&extract)
    );
    assert_eq!(std::fs::read(dir.join("out/input.bin")).unwrap(), payload);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_option_combination_uses_unsupported_exit_code() {
    let dir = temp_dir("exit-codes");
    std::fs::write(dir.join("input.txt"), b"payload").unwrap();
    let pack = run(&dir, &["pack", "tar", "input.txt", "-o", "archive.tar"]);
    assert!(pack.status.success(), "pack failed: {}", stderr(&pack));

    let output = run(
        &dir,
        &["list", "archive.tar", "--tree", "--json", "--no-pager"],
    );
    assert_eq!(output.status.code(), Some(2), "unexpected exit status");
    assert!(
        stderr(&output).contains("human-readable only"),
        "unexpected error: {}",
        stderr(&output)
    );

    let missing = run(&dir, &["list", "missing.tar", "--no-pager"]);
    assert_eq!(missing.status.code(), Some(1), "unexpected exit status");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_creates_zip_directory_entries() {
    let dir = temp_dir("zip-dir");
    let mut encoder = archive::archive::zip::encode::ZipEncoder::new();
    encoder.add_file("dir/", b"");
    encoder.add_file("dir/file.txt", b"zip directory payload");
    encoder.add_file("empty-dir/", b"");
    std::fs::write(dir.join("archive.zip"), encoder.finish().unwrap()).unwrap();

    let extract = run(&dir, &["extract", "archive.zip", "--out", "out"]);
    assert!(
        extract.status.success(),
        "extract failed: {}",
        stderr(&extract)
    );
    assert!(dir.join("out/dir").is_dir());
    assert!(dir.join("out/empty-dir").is_dir());
    assert_eq!(
        std::fs::read(dir.join("out/dir/file.txt")).unwrap(),
        b"zip directory payload"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_rejects_parent_directory_entries() {
    let dir = temp_dir("path-traversal");
    let mut encoder = archive::archive::tar::encode::TarEncoder::new();
    encoder.add_file("../escape.txt", b"must not escape");
    std::fs::write(dir.join("evil.tar"), encoder.finish()).unwrap();

    let output = run(&dir, &["extract", "evil.tar", "--out", "out"]);
    assert!(
        !output.status.success(),
        "extraction of ../escape.txt unexpectedly succeeded"
    );
    assert!(
        !dir.join("escape.txt").exists(),
        "archive entry escaped the output directory"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
