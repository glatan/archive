use super::*;

// ============================================================
// ar tests
// ============================================================

#[test]
fn test_ar_roundtrip_gnu() {
    let mut encoder = ar::encode::ArEncoder::new();
    encoder.add_file("hello.txt", b"Hello from ar!");
    let archive = encoder.finish().unwrap();
    let entries = ar::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].data, b"Hello from ar!");
}

#[test]
fn test_ar_empty_archive_roundtrip() {
    let archive = ar::encode::ArEncoder::new().finish().unwrap();
    let entries = ar::decode::decode(&archive).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_ar_decode_system_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_ar_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("one.txt"), b"one").unwrap();
    std::fs::write(dir.join("two.txt"), b"two").unwrap();
    let archive_path = dir.join("sample.a");

    let output = Command::new("ar")
        .current_dir(&dir)
        .args(["cr", "sample.a", "one.txt", "two.txt"])
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "ar cr failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let archive = std::fs::read(&archive_path).unwrap();
        let entries = ar::decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "one.txt");
        assert_eq!(entries[0].data, b"one");
        assert_eq!(entries[1].name, "two.txt");
        assert_eq!(entries[1].data, b"two");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(dir.join("one.txt"));
    let _ = std::fs::remove_file(dir.join("two.txt"));
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_ar_gnu_system_compat() {
    use std::process::Command;

    let mut encoder = ar::encode::ArEncoder::new();
    encoder.add_file("very long filename.txt", b"GNU ar compat");
    let archive = encoder.finish().unwrap();

    let dir = unique_temp_dir("ar_gnu");
    let path = dir.join("compat.a");
    std::fs::write(&path, &archive).unwrap();
    let output = match Command::new("ar").args(["t"]).arg(&path).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("failed to run ar: {error}"),
    };
    assert!(
        output.status.success(),
        "ar t failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("very long filename.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_ar_empty_archive_system_list_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_empty_{uniq}.a"));
    let archive = ar::encode::ArEncoder::new().finish().unwrap();
    std::fs::write(&path, &archive).unwrap();

    let output = Command::new("ar").args(["t"]).arg(&path).output();
    let _ = std::fs::remove_file(&path);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "ar t failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn test_ar_gnu_system_extract_content_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_gnu_extract_{uniq}.a"));

    let mut encoder = ar::encode::ArEncoder::new();
    encoder.add_file("very long filename.txt", b"GNU ar extract payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&path, &archive).unwrap();

    let output = Command::new("ar")
        .args(["p"])
        .arg(&path)
        .arg("very long filename.txt")
        .output();
    let _ = std::fs::remove_file(&path);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "ar p failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, b"GNU ar extract payload");
    }
}

#[test]
fn test_ar_bsd_system_compat() {
    use std::process::Command;

    let mut encoder = ar::encode::ArEncoder::new_bsd();
    encoder.add_file("this_is_a_long_name.txt", b"BSD ar compat");
    let archive = encoder.finish().unwrap();

    let dir = unique_temp_dir("ar_bsd");
    let path = dir.join("compat.a");
    std::fs::write(&path, &archive).unwrap();
    let output = match Command::new("bsdtar").args(["-tf"]).arg(&path).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("failed to run bsdtar: {error}"),
    };
    assert!(
        output.status.success(),
        "bsdtar -tf failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("this_is_a_long_name.txt"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_ar_decode_reader_roundtrip_integration() {
    use std::io::Cursor;

    let mut encoder = ar::encode::ArEncoder::new();
    encoder.add_file("reader.txt", b"reader payload");
    let archive = encoder.finish().unwrap();

    let entries = ar::decode::decode_reader(Cursor::new(&archive)).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "reader.txt");
    assert_eq!(entries[0].data, b"reader payload");
}

#[test]
fn test_ar_add_entry_preserves_metadata() {
    let mut encoder = ar::encode::ArEncoder::new_bsd();
    encoder.add_file_with_options(
        "meta.txt",
        b"meta payload",
        &ar::encode::ArEntryOptions {
            mtime: 1234,
            uid: 12,
            gid: 34,
            mode: 0o100755,
        },
    );
    let archive = encoder.finish().unwrap();
    let entries = ar::decode::decode(&archive).unwrap();

    let mut reencoder = ar::encode::ArEncoder::new_bsd();
    reencoder.add_entry(&entries[0]);
    let rebuilt = reencoder.finish().unwrap();
    let rebuilt_entries = ar::decode::decode(&rebuilt).unwrap();

    assert_eq!(rebuilt_entries.len(), 1);
    assert_eq!(rebuilt_entries[0].name, "meta.txt");
    assert_eq!(rebuilt_entries[0].data, b"meta payload");
    assert_eq!(rebuilt_entries[0].header.mtime, 1234);
    assert_eq!(rebuilt_entries[0].header.uid, 12);
    assert_eq!(rebuilt_entries[0].header.gid, 34);
    assert_eq!(rebuilt_entries[0].header.mode, 0o100755);
}

#[test]
fn test_ar_roundtrip_multiple_long_names_bsd() {
    let mut encoder = ar::encode::ArEncoder::new_bsd();
    encoder.add_file("this_is_a_long_name.txt", b"first");
    encoder.add_file("another_long_name.bin", b"second");
    let archive = encoder.finish().unwrap();

    let entries = ar::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "this_is_a_long_name.txt");
    assert_eq!(entries[0].data, b"first");
    assert_eq!(entries[1].name, "another_long_name.bin");
    assert_eq!(entries[1].data, b"second");
}

#[test]
fn test_ar_decode_rejects_invalid_header_trailer() {
    let mut encoder = ar::encode::ArEncoder::new();
    encoder.add_file("broken.txt", b"broken");
    let mut archive = encoder.finish().unwrap();
    archive[8 + 58] ^= 0x01;

    assert!(matches!(
        ar::decode::decode(&archive),
        Err(archive::error::Error::InvalidData(
            "ar: invalid file header trailer"
        ))
    ));
}

#[test]
fn test_ar_decode_gnu_thin_fixture() {
    // Bytes produced by `ar rcT` (binutils): the `//` member holds the
    // string table payload, regular members are header-only.
    let archive = include_bytes!("../fixtures/ar/thin_gnu.a");
    let entries = ar::decode::decode(archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.is_thin));
    assert_eq!(entries[0].name, "thinmem1.txt");
    assert_eq!(entries[0].header.size, 4);
    assert!(entries[0].data.is_empty());
    assert_eq!(entries[1].name, "thinmem2.txt");
    assert_eq!(entries[1].header.size, 5);
    assert!(entries[1].data.is_empty());
}

#[test]
fn test_ar_thin_system_list_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_thin_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    // Thin members are filesystem references: GNU `ar` resolves them
    // relative to its working directory.
    std::fs::write(dir.join("one.txt"), b"1234").unwrap();
    std::fs::write(dir.join("two.txt"), b"12345").unwrap();

    let mut encoder = ar::encode::ArEncoder::new_thin();
    encoder.add_file("one.txt", b"1234");
    encoder.add_file("two.txt", b"12345");
    let archive_path = dir.join("thin.a");
    std::fs::write(&archive_path, encoder.finish().unwrap()).unwrap();

    let output = Command::new("ar")
        .args(["tv", "thin.a"])
        .current_dir(&dir)
        .output();
    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(dir.join("one.txt"));
    let _ = std::fs::remove_file(dir.join("two.txt"));
    let _ = std::fs::remove_dir(&dir);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "ar tv failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let listing = String::from_utf8_lossy(&result.stdout);
        assert!(listing.contains("one.txt"));
        assert!(listing.contains("two.txt"));
        assert!(listing.contains(" 4 "));
        assert!(listing.contains(" 5 "));
    }
}
