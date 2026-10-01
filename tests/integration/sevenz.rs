use super::*;

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_encode_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_encode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encoded.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.add_file("hello.txt", b"hello sevenz");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "hello.txt"])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"hello sevenz");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

/// System `7z` generates an archive with a legacy codec (`-m0=<method>`) and
/// this crate decodes it.
#[cfg(feature = "sevenz")]
fn system_method_decode_compat(method: &str, payload: &[u8]) {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_{method}_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let input_path = dir.join("method.txt");
    let archive_path = dir.join(format!("method-{method}.7z"));
    std::fs::write(&input_path, payload).unwrap();

    let created = Command::new(cmd)
        .args([
            "a",
            "-t7z",
            &format!("-m0={method}"),
            archive_path.to_str().unwrap(),
            "method.txt",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    if !created.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        panic!(
            "{cmd} a -t7z -m0={method} failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
    }

    let archive = std::fs::read(&archive_path).unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "method.txt");
    assert_eq!(entries[0].data, payload);

    let _ = std::fs::remove_dir_all(&dir);
}

/// This crate encodes an archive with a legacy codec and system `7z`
/// extracts it.
#[cfg(feature = "sevenz")]
fn encoded_method_system_extract_compat(method: sevenz::encode::SevenZMethod, payload: &[u8]) {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_enc_{method:?}_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encoded.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(method);
    encoder.add_file("method.txt", payload);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "method.txt"])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_deflate_method_system_decode_compat() {
    system_method_decode_compat(
        "Deflate",
        b"system deflate method payload payload payload payload",
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_deflate64_method_system_decode_compat() {
    system_method_decode_compat(
        "Deflate64",
        b"system deflate64 method payload payload payload payload",
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_bzip2_method_system_decode_compat() {
    system_method_decode_compat(
        "BZip2",
        b"system bzip2 method payload payload payload payload",
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_deflate_method_system_extract_compat() {
    encoded_method_system_extract_compat(
        sevenz::encode::SevenZMethod::Deflate {
            level: archive::compress::deflate::encode::Level::Default,
        },
        b"crate deflate method payload payload payload",
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_deflate64_method_system_extract_compat() {
    encoded_method_system_extract_compat(
        sevenz::encode::SevenZMethod::Deflate64,
        b"crate deflate64 method payload payload payload",
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_bzip2_method_system_extract_compat() {
    encoded_method_system_extract_compat(
        sevenz::encode::SevenZMethod::Bzip2 { level: 9 },
        b"crate bzip2 method payload payload payload",
    );
}

/// System `7z` creates a Copy archive whose header fields exceed 0x4000 and
/// therefore use multiple little-endian UINT64 extension bytes; this crate
/// decodes it. Regression coverage for the UINT64 extension-byte endianness
/// fix (the pack size 500123 = 0x7A19B is encoded as `c7 9b a1` by 7z).
#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_large_copy_method_system_decode_compat() {
    let payload: Vec<u8> = (0..500_123u32).map(|i| (i % 251) as u8).collect();
    system_method_decode_compat("Copy", &payload);
}

/// This crate encodes a Copy archive with multi-extension-byte UINT64
/// header fields and system `7z` extracts it.
#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_large_copy_method_system_extract_compat() {
    let payload: Vec<u8> = (0..500_123u32).map(|i| (i % 251) as u8).collect();
    encoded_method_system_extract_compat(sevenz::encode::SevenZMethod::Copy, &payload);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_empty_archive_roundtrip_and_system_list() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let archive = sevenz::encode::SevenZEncoder::new().finish().unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert!(entries.is_empty());

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_empty_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("empty.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_decode_system_created_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let input_path = dir.join("system-created.txt");
    let archive_path = dir.join("system-created.7z");
    std::fs::write(&input_path, b"system sevenz payload").unwrap();

    let created = Command::new(cmd)
        .args([
            "a",
            "-t7z",
            archive_path.to_str().unwrap(),
            "system-created.txt",
        ])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{cmd} a -t7z failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );

    let archive = std::fs::read(&archive_path).unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "system-created.txt");
    assert_eq!(entries[0].data, b"system sevenz payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_multi_file_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_multi_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("multi.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.add_file("alpha.txt", b"alpha sevenz payload");
    encoder.add_file("nested/beta.bin", b"beta sevenz payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("alpha.txt"));
    assert!(listing.contains("nested/beta.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            archive_path.to_str().unwrap(),
            "nested/beta.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"beta sevenz payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Copy);
    encoder.set_two_folder_split(1);
    encoder.add_file("folder0.txt", b"first folder payload");
    encoder.add_file("folder1.txt", b"second folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.txt"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_multi_folder_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_multi_folder_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("multi-folder.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Copy);
    encoder.add_file("f0.txt", b"folder one");
    encoder.add_file("f1.txt", b"folder two");
    encoder.add_file("f2.txt", b"folder three");
    encoder.add_file("f3.txt", b"folder four");
    // Three solid folders: [0], [1], [2,3].
    encoder.set_folder_splits(&[1, 2]);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "f3.txt"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"folder four");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_encrypted_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-encrypted.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.add_file("folder0.txt", b"first encrypted folder payload");
    encoder.add_file("folder1.txt", b"second encrypted folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second encrypted folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-encoded-header.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_encoded_header(true);
    encoder.add_file("folder0.txt", b"first header folder payload");
    encoder.add_file("folder1.txt", b"second header folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.txt"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second header folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_copy_method_roundtrip_integration() {
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Copy);
    encoder.add_file("copy.bin", b"copy method payload");

    let archive = encoder.finish().unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "copy.bin");
    assert_eq!(entries[0].data, b"copy method payload");
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_ppmd_method_roundtrip_integration() {
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.add_file("ppmd.txt", b"ppmd payload ppmd payload ppmd payload");

    let archive = encoder.finish().unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "ppmd.txt");
    assert_eq!(entries[0].data, b"ppmd payload ppmd payload ppmd payload");
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_add_entry_with_filters_roundtrip() {
    let mut source = sevenz::encode::SevenZEncoder::new();
    source.add_file(
        "source.bin",
        &[0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF],
    );
    let source_archive = source.finish().unwrap();
    let source_entries = sevenz::decode::decode(&source_archive).unwrap();

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_entry(source_entries[0].clone());

    let archive = encoder.finish().unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "source.bin");
    assert_eq!(entries[0].data, source_entries[0].data);
    assert_eq!(entries[0].attributes, source_entries[0].attributes);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_delta_filter_roundtrip_integration() {
    let input: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("delta.bin", &input);

    let archive = encoder.finish().unwrap();
    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "delta.bin");
    assert_eq!(entries[0].data, input);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_ppmd_method_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_ppmd_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("ppmd.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.add_file("ppmd.txt", b"ppmd payload ppmd payload ppmd payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "ppmd.txt"])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"ppmd payload ppmd payload ppmd payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_ppmd_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload = b"ppmd encoded header payload ppmd encoded header payload";
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_encoded_header(true);
    encoder.add_file("ppmd-header.txt", payload);
    let archive = encoder.finish().unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "ppmd-header.txt");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_ppmd_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("ppmd-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("ppmd-header.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            archive_path.to_str().unwrap(),
            "ppmd-header.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_ppmd_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload = b"ppmd encrypted encoded header payload";
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.add_file("ppmd-secret.txt", payload);
    let archive = encoder.finish().unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "ppmd-secret.txt");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_ppmd_enc_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("ppmd-encrypted-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("ppmd-secret.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "ppmd-secret.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_x86_bcj_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload = [
        0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0x90,
    ];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.set_encoded_header(true);
    encoder.add_file("bcj-header.bin", &payload);
    let archive = encoder.finish().unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "bcj-header.bin");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_bcj_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("bcj-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("bcj-header.bin"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "bcj-header.bin"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_delta_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.set_encoded_header(true);
    encoder.add_file("delta-header.bin", &payload);
    let archive = encoder.finish().unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "delta-header.bin");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_delta_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("delta-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("delta-header.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            archive_path.to_str().unwrap(),
            "delta-header.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_x86_bcj_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload = [
        0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0x90,
    ];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_password("secret");
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.set_encoded_header(true);
    encoder.add_file("bcj-secret.bin", &payload);
    let archive = encoder.finish().unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "bcj-secret.bin");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_bcj_enc_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("bcj-encrypted-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("bcj-secret.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "bcj-secret.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_delta_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_password("secret");
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.set_encoded_header(true);
    encoder.add_file("delta-secret.bin", &payload);
    let archive = encoder.finish().unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "delta-secret.bin");
    assert_eq!(entries[0].data, payload);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_delta_enc_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("delta-encrypted-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("delta-secret.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "delta-secret.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_x86_bcj_filter_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_bcj_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("bcj.7z");

    let payload = [
        0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0x90,
    ];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_file("bcj.bin", &payload);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "bcj.bin"])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_delta_filter_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_delta_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("delta.7z");

    let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("delta.bin", &payload);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "delta.bin"])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_ppmd_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_ppmd_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-ppmd.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_two_folder_split(1);
    encoder.add_file("folder0.txt", b"first ppmd folder payload");
    encoder.add_file("folder1.txt", b"second ppmd folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.txt"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second ppmd folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.add_file("folder0.txt", b"first encrypted header folder payload");
    encoder.add_file("folder1.txt", b"second encrypted header folder payload");
    let archive = encoder.finish().unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "folder0.txt");
    assert_eq!(entries[0].data, b"first encrypted header folder payload");
    assert_eq!(entries[1].name, "folder1.txt");
    assert_eq!(entries[1].data, b"second encrypted header folder payload");

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_enc_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-encrypted-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second encrypted header folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_x86_bcj_filter_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_bcj_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-bcj.7z");

    let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
    let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.bin"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_delta_filter_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_delta_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-delta.7z");

    let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
    let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.bin"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_x86_bcj_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_bcj_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-bcj-encoded-header.7z");

    let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
    let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_encoded_header(true);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.bin"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_delta_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_delta_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-delta-encoded-header.7z");

    let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
    let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_encoded_header(true);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.bin"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_ppmd_encrypted_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_ppmd_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-ppmd-encrypted.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.add_file("folder0.txt", b"first encrypted ppmd folder payload");
    encoder.add_file("folder1.txt", b"second encrypted ppmd folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "folder0.txt");
    assert_eq!(entries[0].data, b"first encrypted ppmd folder payload");
    assert_eq!(entries[1].name, "folder1.txt");
    assert_eq!(entries[1].data, b"second encrypted ppmd folder payload");

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"second encrypted ppmd folder payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_ppmd_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_ppmd_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-ppmd-encoded-header.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_two_folder_split(1);
    encoder.set_encoded_header(true);
    encoder.add_file("folder0.txt", b"first ppmd encoded-header folder payload");
    encoder.add_file("folder1.txt", b"second ppmd encoded-header folder payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, b"first ppmd encoded-header folder payload");
    assert_eq!(
        entries[1].data,
        b"second ppmd encoded-header folder payload"
    );

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args(["e", "-so", archive_path.to_str().unwrap(), "folder1.txt"])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(
        extracted.stdout,
        b"second ppmd encoded-header folder payload"
    );

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_ppmd_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "archive_test_sevenz_two_folder_ppmd_enc_hdr_{uniq}"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-ppmd-encrypted-encoded-header.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_method(sevenz::encode::SevenZMethod::Ppmd {
        order: 6,
        mem_size: 1 << 20,
    });
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.add_file(
        "folder0.txt",
        b"first encrypted ppmd encoded-header folder payload",
    );
    encoder.add_file(
        "folder1.txt",
        b"second encrypted ppmd encoded-header folder payload",
    );
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].data,
        b"first encrypted ppmd encoded-header folder payload"
    );
    assert_eq!(
        entries[1].data,
        b"second encrypted ppmd encoded-header folder payload"
    );

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.txt"));
    assert!(listing.contains("folder1.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(
        extracted.stdout,
        b"second encrypted ppmd encoded-header folder payload"
    );

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_x86_bcj_encrypted_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_bcj_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-bcj-encrypted.7z");

    let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
    let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_delta_encrypted_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_delta_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-delta-encrypted.7z");

    let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
    let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_x86_bcj_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("archive_test_sevenz_two_folder_bcj_enc_hdr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-bcj-encrypted-encoded-header.7z");

    let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
    let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::X86Bcj]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_two_folder_delta_encrypted_encoded_header_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "archive_test_sevenz_two_folder_delta_enc_hdr_{uniq}"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("two-folder-delta-encrypted-encoded-header.7z");

    let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
    let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_two_folder_split(1);
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.set_filters(vec![sevenz::encode::SevenZFilter::Delta { distance: 4 }]);
    encoder.add_file("folder0.bin", &payload0);
    encoder.add_file("folder1.bin", &payload1);
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, payload0);
    assert_eq!(entries[1].data, payload1);

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("folder0.bin"));
    assert!(listing.contains("folder1.bin"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "folder1.bin",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so -psecret failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, payload1);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_encrypted_archive_system_extract_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_password_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encrypted.7z");

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_password("secret");
    encoder.add_file("secret.txt", b"encrypted sevenz system payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "secret.txt",
        ])
        .output()
        .unwrap();

    assert!(
        extracted.status.success(),
        "{cmd} encrypted extract failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"encrypted sevenz system payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_encoded_header_roundtrip_and_system_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_encoded_header(true);
    encoder.add_file("encoded-header.txt", b"encoded header sevenz payload");
    let archive = encoder.finish().unwrap();

    let entries = sevenz::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "encoded-header.txt");
    assert_eq!(entries[0].data, b"encoded header sevenz payload");

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sevenz_encoded_header_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("encoded-header.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            archive_path.to_str().unwrap(),
            "encoded-header.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} e -so failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"encoded header sevenz payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_encrypted_encoded_header_roundtrip_and_system_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_password("secret");
    encoder.set_encoded_header(true);
    encoder.add_file(
        "secret-header.txt",
        b"encrypted encoded header sevenz payload",
    );
    let archive = encoder.finish().unwrap();

    assert!(sevenz::decode::decode(&archive).is_err());
    let entries = sevenz::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "secret-header.txt");
    assert_eq!(entries[0].data, b"encrypted encoded header sevenz payload");

    let Some(cmd) = sevenz_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "archive_test_sevenz_encrypted_encoded_header_{uniq}"
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encrypted-encoded-header.7z");
    std::fs::write(&archive_path, &archive).unwrap();

    let listed = Command::new(cmd)
        .args(["l", "-psecret", archive_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{cmd} l -psecret failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(String::from_utf8_lossy(&listed.stdout).contains("secret-header.txt"));

    let extracted = Command::new(cmd)
        .args([
            "e",
            "-so",
            "-psecret",
            archive_path.to_str().unwrap(),
            "secret-header.txt",
        ])
        .output()
        .unwrap();
    assert!(
        extracted.status.success(),
        "{cmd} encrypted extract failed: {}",
        String::from_utf8_lossy(&extracted.stderr)
    );
    assert_eq!(extracted.stdout, b"encrypted encoded header sevenz payload");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "sevenz")]
#[test]
fn test_sevenz_password_bytes_roundtrip_and_failures() {
    let password = b"secret";
    let mut encoder = sevenz::encode::SevenZEncoder::new();
    encoder.set_password_bytes(password);
    encoder.add_file("secret.bin", b"encrypted integration payload");

    let archive = encoder.finish().unwrap();

    let entries = sevenz::decode::decode_with_password_bytes(&archive, password).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "secret.bin");
    assert_eq!(entries[0].data, b"encrypted integration payload");

    assert!(matches!(
        sevenz::decode::decode(&archive),
        Err(archive::error::Error::Unsupported(
            "7z: encrypted archive requires a password"
        ))
    ));
    assert!(sevenz::decode::decode_with_password_bytes(&archive, b"wrong").is_err());
}
