use super::*;

// ============================================================
// Tar tests
// ============================================================

#[test]
fn test_tar_decode_single_file() {
    let tar_data = include_bytes!("../fixtures/tar/single_file.tar");
    let entries = tar::decode::decode(tar_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].header.name, "hello.txt");
    assert_eq!(entries[0].data, b"Hello from tar!");
}

#[test]
fn test_tar_empty_archive_roundtrip() {
    let tar_data = tar::encode::TarEncoder::new().finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn test_tar_decode_multi_file() {
    let tar_data = include_bytes!("../fixtures/tar/multi_file.tar");
    let entries = tar::decode::decode(tar_data).unwrap();
    assert!(
        entries.len() >= 3,
        "expected at least 3 entries, got {}",
        entries.len()
    );

    let a = entries
        .iter()
        .find(|e| e.header.name.contains("a.txt"))
        .unwrap();
    assert_eq!(a.data, b"File A content");

    let b = entries
        .iter()
        .find(|e| e.header.name.contains("b.txt"))
        .unwrap();
    assert_eq!(b.data, b"File B content");

    let nested = entries
        .iter()
        .find(|e| e.header.name.contains("nested.txt"))
        .unwrap();
    assert_eq!(nested.data, b"Nested file");
}

// ============================================================
// Tar format-specific tests
// ============================================================

/// Decode a UStar-format tar archive produced by `tar --format=ustar`.
#[test]
fn test_tar_decode_ustar_fixture() {
    let tar_data = include_bytes!("../fixtures/tar/ustar_simple.tar");
    let entries = tar::decode::decode(tar_data).unwrap();
    let hello = entries
        .iter()
        .find(|e| e.header.name == "hello.txt")
        .unwrap();
    assert_eq!(hello.data, b"Hello from UStar!");
    let data = entries
        .iter()
        .find(|e| e.header.name == "data.txt")
        .unwrap();
    assert_eq!(data.data, b"UStar content");
}

/// Decode a GNU-format tar archive containing a file whose path exceeds
/// 100 bytes, exercising the GNU LongName extension header.
#[test]
fn test_tar_decode_gnu_longname_fixture() {
    let tar_data = include_bytes!("../fixtures/tar/gnu_longname.tar");
    let entries = tar::decode::decode(tar_data).unwrap();

    let short = entries
        .iter()
        .find(|e| e.header.name == "short.txt")
        .unwrap();
    assert_eq!(short.data, b"Short name content");

    let long = entries
        .iter()
        .find(|e| e.header.name.contains("file_with_a_really_long_name"))
        .unwrap();
    assert_eq!(long.data, b"Long name content");
    assert!(
        long.header.name.len() > 100,
        "filename should exceed 100 bytes"
    );
}

/// Decode a PAX-format tar archive produced by `tar --format=posix`.
#[test]
fn test_tar_decode_pax_fixture() {
    let tar_data = include_bytes!("../fixtures/tar/pax_extended.tar");
    let entries = tar::decode::decode(tar_data).unwrap();
    let hello = entries
        .iter()
        .find(|e| e.header.name == "hello.txt")
        .unwrap();
    assert_eq!(hello.data, b"Hello from PAX");
    let data = entries
        .iter()
        .find(|e| e.header.name == "data.txt")
        .unwrap();
    assert_eq!(data.data, b"PAX data content");
}

/// Round-trip test: GNU-mode encoder → decoder for files with long names.
#[test]
fn test_tar_gnu_longname_roundtrip() {
    let long_name = "a/".repeat(60) + "file.txt"; // >100 bytes
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file(&long_name, b"long name data");
    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].header.name, long_name);
    assert_eq!(entries[0].data, b"long name data");
}

/// Round-trip test: PAX-mode encoder → decoder.
#[test]
fn test_tar_pax_roundtrip() {
    let mut encoder = tar::encode::TarEncoder::new_pax();
    encoder.add_file("pax_file.txt", b"PAX round-trip data");
    encoder.add_directory("pax_dir/", 0o755);
    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].header.name, "pax_file.txt");
    assert_eq!(entries[0].data, b"PAX round-trip data");
    assert_eq!(entries[1].header.name, "pax_dir/");
}

/// PAX encoder with a long filename (>100 bytes) should produce a valid archive
/// that our decoder can read back correctly.
#[test]
fn test_tar_pax_longname_roundtrip() {
    let long_name = "deeply/nested/".repeat(10) + "document.txt";
    assert!(long_name.len() > 100);
    let mut encoder = tar::encode::TarEncoder::new_pax();
    encoder.add_file(&long_name, b"PAX long name content");
    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].header.name, long_name);
    assert_eq!(entries[0].data, b"PAX long name content");
}

/// Verify that the system `tar` tool can list and extract archives produced
/// by our GNU-mode encoder.
#[test]
fn test_tar_gnu_system_compat() {
    use std::process::Command;

    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("hello.txt", b"Hello from Rust tar encoder");
    let tar_data = encoder.finish();

    let tmp = std::env::temp_dir().join("archive_test_gnu_compat.tar");
    std::fs::write(&tmp, &tar_data).unwrap();

    let output = Command::new("tar").args(["-tf"]).arg(&tmp).output();
    let _ = std::fs::remove_file(&tmp);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "tar -tf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let listing = String::from_utf8_lossy(&result.stdout);
        assert!(listing.contains("hello.txt"));
    }
}

#[test]
fn test_tar_empty_archive_system_list_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let archive = tar::encode::TarEncoder::new().finish();
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!("archive_test_empty_{uniq}.tar"));
    std::fs::write(&tmp, &archive).unwrap();

    let output = Command::new("tar").args(["-tf"]).arg(&tmp).output();
    let _ = std::fs::remove_file(&tmp);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "tar -tf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
    }
}

/// Verify that the system `tar` tool can extract a GNU longname archive
/// produced by our encoder.
#[test]
fn test_tar_gnu_longname_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let long_name = "gnu-prefix/".repeat(12) + "deep/file.txt";
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file(&long_name, b"GNU longname extract payload");
    let tar_data = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("archive_test_gnu_extract_{uniq}"));
    let archive_path = root.join("gnu.tar");
    let out_dir = root.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&archive_path, &tar_data).unwrap();

    let output = Command::new("tar")
        .args([
            "-xf",
            archive_path.to_str().unwrap(),
            "-C",
            out_dir.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "tar -xf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let extracted = std::fs::read(out_dir.join(&long_name)).unwrap();
        assert_eq!(extracted, b"GNU longname extract payload");
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// Verify that the system `tar` tool can list and extract archives produced
/// by our PAX-mode encoder.
#[test]
fn test_tar_pax_system_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let long_name = "prefix/".repeat(20) + "file.txt";
    let long_uname = "owner-name-".repeat(4);
    let long_gname = "group-name-".repeat(4);
    let mut encoder = tar::encode::TarEncoder::new_pax();
    encoder.add_file_with_options(
        b"PAX system compat test",
        &tar::encode::TarEntryOptions {
            name: long_name.clone(),
            uname: long_uname.clone(),
            gname: long_gname.clone(),
            ..Default::default()
        },
    );
    let tar_data = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tmp = std::env::temp_dir().join(format!("archive_test_pax_compat_{uniq}.tar"));
    std::fs::write(&tmp, &tar_data).unwrap();

    let output = Command::new("tar").args(["-tvf"]).arg(&tmp).output();
    let _ = std::fs::remove_file(&tmp);

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "tar -tvf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let listing = String::from_utf8_lossy(&result.stdout);
        assert!(listing.contains(&long_name));
        assert!(listing.contains(&long_uname));
        assert!(listing.contains(&long_gname));
    }
}

#[test]
fn test_tar_pax_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let long_name = "extract-prefix/".repeat(12) + "deep/file.txt";
    let mut encoder = tar::encode::TarEncoder::new_pax();
    encoder.add_file_with_options(
        b"PAX extract payload",
        &tar::encode::TarEntryOptions {
            name: long_name.clone(),
            ..Default::default()
        },
    );
    let tar_data = encoder.finish();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("archive_test_pax_extract_{uniq}"));
    let archive_path = root.join("pax.tar");
    let out_dir = root.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(&archive_path, &tar_data).unwrap();

    let output = Command::new("tar")
        .args([
            "-xf",
            archive_path.to_str().unwrap(),
            "-C",
            out_dir.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "tar -xf failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let extracted = std::fs::read(out_dir.join(&long_name)).unwrap();
        assert_eq!(extracted, b"PAX extract payload");
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn test_tar_directories_only_roundtrip() {
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_directory("dir1/", 0o755);
    encoder.add_directory("dir2/", 0o700);
    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].header.name, "dir1/");
    assert_eq!(entries[1].header.name, "dir2/");
}

#[test]
fn test_tar_decode_reader_roundtrip_integration() {
    use std::io::Cursor;

    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("reader.txt", b"reader payload");
    encoder.add_directory("reader-dir/", 0o755);
    let tar_data = encoder.finish();

    let entries = tar::decode::decode_reader(Cursor::new(&tar_data)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].header.name, "reader.txt");
    assert_eq!(entries[0].data, b"reader payload");
    assert_eq!(entries[1].header.name, "reader-dir/");
}

#[test]
fn test_tar_link_entries_roundtrip() {
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file_with_options(
        b"",
        &tar::encode::TarEntryOptions {
            name: "symlink.txt".into(),
            file_type: tar::header::FileType::SymLink,
            link_name: "target.txt".into(),
            ..Default::default()
        },
    );
    encoder.add_file_with_options(
        b"",
        &tar::encode::TarEntryOptions {
            name: "hardlink.txt".into(),
            file_type: tar::header::FileType::HardLink,
            link_name: "target.txt".into(),
            ..Default::default()
        },
    );

    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].header.file_type, tar::header::FileType::SymLink);
    assert_eq!(entries[0].header.link_name, "target.txt");
    assert_eq!(entries[1].header.file_type, tar::header::FileType::HardLink);
    assert_eq!(entries[1].header.link_name, "target.txt");
}

#[test]
fn test_tar_pax_sparse_roundtrip_integration() {
    let mut encoder = tar::encode::TarEncoder::new_pax();
    encoder
        .add_sparse_file("sparse.bin", b"HELLOWORLD", &[(0, 5), (2048, 5)], 4096)
        .unwrap();

    let tar_data = encoder.finish();
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].header.name, "sparse.bin");
    assert_eq!(entries[0].header.size, 4096);
    assert_eq!(entries[0].header.sparse_map, vec![(0, 5), (2048, 5)]);
    assert_eq!(entries[0].data, b"HELLOWORLD");
}

#[test]
fn test_tar_gnu_sparse_roundtrip() {
    let mut encoder = tar::encode::TarEncoder::new();
    encoder
        .add_sparse_file("sparse.bin", b"HELLOWORLD", &[(0, 5), (2048, 5)], 4096)
        .unwrap();

    let tar_data = encoder.finish();
    // typeflag 'S' in the entry header
    assert_eq!(tar_data[156], b'S');
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].header.file_type,
        tar::header::FileType::GnuSparse
    );
    assert_eq!(entries[0].header.name, "sparse.bin");
    assert_eq!(entries[0].header.size, 4096);
    assert_eq!(entries[0].header.sparse_map, vec![(0, 5), (2048, 5)]);
    assert_eq!(entries[0].data, b"HELLOWORLD");
}

#[test]
fn test_tar_gnu_sparse_extended_map() {
    // Six extents exceed the four inline header slots and force a
    // 512-byte extended sparse block.
    let map: Vec<(u64, u64)> = (0..6).map(|i| (i * 4096, 16)).collect();
    let data = vec![0xABu8; 96];
    let mut encoder = tar::encode::TarEncoder::new();
    encoder
        .add_sparse_file("big.bin", &data, &map, 6 * 4096)
        .unwrap();

    let tar_data = encoder.finish();
    assert_eq!(tar_data[482], 1); // isextended
    let entries = tar::decode::decode(&tar_data).unwrap();
    assert_eq!(entries[0].header.sparse_map, map);
    assert_eq!(entries[0].data, data);
}

#[test]
fn test_tar_gnu_sparse_long_name() {
    // The old 'S' layout has no prefix field; long names must come
    // through a GNU LongName header.
    let name = format!("{}/{}", "d".repeat(80), "f".repeat(80));
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_sparse_file(&name, b"X", &[(0, 1)], 10).unwrap();
    let entries = tar::decode::decode(&encoder.finish()).unwrap();
    assert_eq!(entries[0].header.name, name);
}

#[test]
fn test_tar_gnu_sparse_oracle() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_tar = Command::new("tar")
        .arg("--version")
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if !has_tar {
        return;
    }
    let map: Vec<(u64, u64)> = vec![(0, 5), (2048, 5), (8192, 6), (16384, 5), (20480, 5)];
    let data: Vec<u8> = (0..26u32).map(|i| b'A' + (i % 26) as u8).collect();
    let mut encoder = tar::encode::TarEncoder::new();
    encoder
        .add_sparse_file("sparse.bin", &data, &map, 24581)
        .unwrap();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_gnu_sparse_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.tar");
    std::fs::write(&path, encoder.finish()).unwrap();
    let output = Command::new("tar")
        .args(["-xf", path.to_str().unwrap(), "-C"])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "tar extract failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let got = std::fs::read(dir.join("sparse.bin")).unwrap();
    // GNU tar expands the holes; rebuild the expected logical file.
    let mut want = vec![0u8; 24581];
    let mut off = 0usize;
    for (o, l) in &map {
        want[*o as usize..*o as usize + *l as usize].copy_from_slice(&data[off..off + *l as usize]);
        off += *l as usize;
    }
    assert_eq!(got, want);
}

#[test]
fn test_tar_decode_rejects_truncated_archive() {
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("truncated.txt", b"truncate me");
    let tar_data = encoder.finish();
    let truncated = &tar_data[..512];

    assert!(matches!(
        tar::decode::decode(truncated),
        Err(archive::error::Error::UnexpectedEof)
    ));
}
