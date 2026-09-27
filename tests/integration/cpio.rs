use super::*;

// ============================================================
// Cpio tests
// ============================================================

#[test]
fn test_cpio_decode_single_file() {
    let cpio_data = include_bytes!("../fixtures/cpio/single_file.cpio");
    let entries = cpio::decode::decode(cpio_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "cpio_hello.txt");
    assert_eq!(entries[0].data, b"Hello from cpio!");
}

#[test]
fn test_cpio_directories_only_roundtrip() {
    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_directory("dir1", 0o755);
    encoder.add_directory("dir2", 0o700);
    let cpio_data = encoder.finish();
    let entries = cpio::decode::decode(&cpio_data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "dir1");
    assert!(entries[0].header.is_directory());
    assert_eq!(entries[1].name, "dir2");
    assert!(entries[1].header.is_directory());
}

#[test]
fn test_cpio_empty_archive_roundtrip() {
    let archive = cpio::encode::CpioEncoder::new().finish();
    let entries = cpio::decode::decode(&archive).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_cpio_decode_reader_roundtrip_integration() {
    use std::io::Cursor;

    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_file("reader.txt", b"reader payload");
    encoder.add_directory("reader-dir", 0o755);
    let archive = encoder.finish();

    let entries = cpio::decode::decode_reader(Cursor::new(&archive)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "reader.txt");
    assert_eq!(entries[0].data, b"reader payload");
    assert_eq!(entries[1].name, "reader-dir");
    assert!(entries[1].header.is_directory());
}

#[test]
fn test_cpio_newcrc_roundtrip_and_checksum_detection() {
    let mut encoder = cpio::encode::CpioEncoder::new_crc();
    encoder.add_file("crc.txt", b"crc payload");
    let archive = encoder.finish();
    let entries = cpio::decode::decode(&archive).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "crc.txt");
    assert_eq!(entries[0].data, b"crc payload");
    assert!(entries[0].header.format.is_crc());

    let mut corrupted = archive.clone();
    let data_offset = 110 + 8 + 1 + 1;
    corrupted[data_offset] ^= 0x01;
    assert!(matches!(
        cpio::decode::decode(&corrupted),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_cpio_odc_roundtrip_integration() {
    let mut encoder = cpio::encode::CpioEncoder::new_odc();
    encoder.add_file("a", b"1");
    encoder.add_file("bbb", b"22");
    let archive = encoder.finish();

    let entries = cpio::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].header.format, cpio::header::CpioFormat::Odc);
    assert_eq!(entries[0].name, "a");
    assert_eq!(entries[0].data, b"1");
    assert_eq!(entries[1].header.format, cpio::header::CpioFormat::Odc);
    assert_eq!(entries[1].name, "bbb");
    assert_eq!(entries[1].data, b"22");
}

#[test]
fn test_cpio_symlink_hardlink_and_device_roundtrip() {
    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.set_next_ino(42);
    encoder.add_file("original.txt", b"payload");
    encoder.add_hardlink("link.txt", 42);
    encoder.add_symlink("symlink.txt", "target.txt");
    encoder.add_device("null", cpio::header::S_IFCHR | 0o666, 1, 3);
    let archive = encoder.finish();

    let entries = cpio::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].header.ino, 42);
    assert_eq!(entries[1].header.ino, 42);
    assert_eq!(entries[1].data, b"");
    assert!(entries[2].header.is_symlink());
    assert_eq!(entries[2].symlink_target(), Some("target.txt"));
    assert_eq!(entries[3].header.rdevmajor, 1);
    assert_eq!(entries[3].header.rdevminor, 3);
}

#[test]
fn test_cpio_decode_system_newc_archive() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cpio_cmd) = cpio_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cpio_decode_{uniq}"));
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    std::fs::write(dir.join("sys.txt"), b"system cpio payload").unwrap();
    std::fs::write(dir.join("nested/child.txt"), b"nested payload").unwrap();

    let mut child = Command::new(cpio_cmd)
        .current_dir(&dir)
        .args(["-o", "-H", "newc"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"sys.txt\nnested\nnested/child.txt\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "system cpio create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let entries = cpio::decode::decode(&output.stdout).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "sys.txt");
    assert_eq!(entries[0].data, b"system cpio payload");
    assert_eq!(entries[1].name, "nested");
    assert!(entries[1].header.is_directory());
    assert_eq!(entries[2].name, "nested/child.txt");
    assert_eq!(entries[2].data, b"nested payload");

    let _ = std::fs::remove_file(dir.join("nested/child.txt"));
    let _ = std::fs::remove_dir(dir.join("nested"));
    let _ = std::fs::remove_file(dir.join("sys.txt"));
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_cpio_encode_newc_system_extract_compat() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cpio_cmd) = cpio_binary() else {
        return;
    };

    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_directory("nested", 0o755);
    encoder.add_file("nested/child.txt", b"child payload");
    encoder.add_file("root.txt", b"root payload");
    let archive = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cpio_extract_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let mut child = Command::new(cpio_cmd)
        .current_dir(&dir)
        .args(["-id"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&archive).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "system cpio extract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(dir.join("root.txt")).unwrap(),
        b"root payload"
    );
    assert_eq!(
        std::fs::read(dir.join("nested/child.txt")).unwrap(),
        b"child payload"
    );

    let _ = std::fs::remove_file(dir.join("nested/child.txt"));
    let _ = std::fs::remove_dir(dir.join("nested"));
    let _ = std::fs::remove_file(dir.join("root.txt"));
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_cpio_encode_newcrc_system_extract_compat() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cpio_cmd) = cpio_binary() else {
        return;
    };

    let mut encoder = cpio::encode::CpioEncoder::new_crc();
    encoder.add_file("crc.txt", b"crc extract payload");
    let archive = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cpio_crc_extract_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let mut child = Command::new(cpio_cmd)
        .current_dir(&dir)
        .args(["-id"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&archive).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "system cpio crc extract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(dir.join("crc.txt")).unwrap(),
        b"crc extract payload"
    );

    let _ = std::fs::remove_file(dir.join("crc.txt"));
    let _ = std::fs::remove_dir(&dir);
}

// ============================================================
// cpio `bin` (SVR4 binary) tests
// ============================================================
//
// The `bin_*.cpio` fixtures were produced by GNU cpio 2.15
// (`cpio -o -H bin`) and are used as known-answer decode tests.

#[test]
fn test_cpio_bin_decode_fixture_multi() {
    let data = include_bytes!("../fixtures/cpio/bin_multi.cpio");
    let entries = cpio::decode::decode(data).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e.header.format == cpio::header::CpioFormat::Bin)
    );

    assert_eq!(entries[0].name, "data.bin");
    let mut expected0 = vec![b'a'; 29];
    expected0.extend_from_slice(b"bbbbbbb");
    assert_eq!(entries[0].data, expected0);
    assert_eq!(entries[0].header.mode & 0o170000, 0o100000);

    assert_eq!(entries[1].name, "hello.txt");
    assert_eq!(entries[1].data, b"hello cpio bin format\n");

    assert_eq!(entries[2].name, "odd.bin");
    assert_eq!(entries[2].data, b"x");
}

#[test]
fn test_cpio_bin_decode_fixture_mixed() {
    let data = include_bytes!("../fixtures/cpio/bin_mixed.cpio");
    let entries = cpio::decode::decode(data).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e.header.format == cpio::header::CpioFormat::Bin)
    );

    assert_eq!(entries[0].name, "subdir/nested.txt");
    assert_eq!(entries[0].data, b"nested file content\n");

    assert_eq!(entries[1].name, "link.txt");
    assert!(entries[1].header.is_symlink());
    assert_eq!(entries[1].symlink_target(), Some("hello.txt"));

    assert_eq!(entries[2].name, "hello.txt");
    assert_eq!(entries[2].data, b"hello cpio bin format\n");
}

#[test]
fn test_cpio_bin_roundtrip_integration() {
    let mut encoder = cpio::encode::CpioEncoder::new_bin();
    encoder.add_file("a", b"1");
    encoder.add_file("bbb", b"22");
    encoder.add_symlink("ln", "a");
    let archive = encoder.finish();

    let entries = cpio::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(
        entries
            .iter()
            .all(|e| e.header.format == cpio::header::CpioFormat::Bin)
    );
    assert_eq!(entries[0].name, "a");
    assert_eq!(entries[0].data, b"1");
    assert_eq!(entries[1].name, "bbb");
    assert_eq!(entries[1].data, b"22");
    assert_eq!(entries[2].symlink_target(), Some("a"));
}

#[test]
fn test_cpio_bin_decode_system_archive() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cpio_cmd) = cpio_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cpio_bin_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sys.bin"), b"system bin payload").unwrap();

    let mut child = Command::new(cpio_cmd)
        .current_dir(&dir)
        .args(["-o", "-H", "bin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"sys.bin\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "system cpio -H bin create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let entries = cpio::decode::decode(&output.stdout).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].header.format, cpio::header::CpioFormat::Bin);
    assert_eq!(entries[0].name, "sys.bin");
    assert_eq!(entries[0].data, b"system bin payload");

    let _ = std::fs::remove_file(dir.join("sys.bin"));
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_cpio_bin_extract_with_system() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cpio_cmd) = cpio_binary() else {
        return;
    };

    let mut encoder = cpio::encode::CpioEncoder::new_bin();
    encoder.add_file("bin.txt", b"bin extract payload");
    let archive = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cpio_bin_extract_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let mut child = Command::new(cpio_cmd)
        .current_dir(&dir)
        .args(["-id"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&archive).unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "system cpio bin extract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(dir.join("bin.txt")).unwrap(),
        b"bin extract payload"
    );

    let _ = std::fs::remove_file(dir.join("bin.txt"));
    let _ = std::fs::remove_dir(&dir);
}
