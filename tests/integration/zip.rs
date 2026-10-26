use super::*;

#[cfg(feature = "zip")]
fn find_signature(bytes: &[u8], signature: [u8; 4]) -> usize {
    bytes
        .windows(signature.len())
        .position(|window| window == signature)
        .unwrap()
}

// ============================================================
// ZIP tests
// ============================================================

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_system_deflate_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_deflate_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("one.txt"), b"one").unwrap();
    std::fs::write(dir.join("two.txt"), b"two").unwrap();
    let archive_path = dir.join("sample.zip");

    let output = Command::new("zip")
        .current_dir(&dir)
        .args(["-q", "sample.zip", "one.txt", "two.txt"])
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "zip failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let archive = std::fs::read(&archive_path).unwrap();
        let entries = zip::decode::decode(&archive).unwrap();
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

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_system_store_archive() {
    use std::process::Command;

    let dir = unique_temp_dir("zip_store");
    let path = dir.join("stored.zip");
    std::fs::write(dir.join("stored.txt"), b"stored zip entry").unwrap();

    let output = match Command::new("zip")
        .current_dir(&dir)
        .args(["-0", "-q", path.to_str().unwrap(), "stored.txt"])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("failed to run zip: {error}"),
    };
    assert!(
        output.status.success(),
        "zip -0 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = std::fs::read(&path).unwrap();
    let entries = zip::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "stored.txt");
    assert_eq!(entries[0].data, b"stored zip entry");

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_encode_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_encode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("encoded.zip");

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file("deflated.txt", b"deflated payload deflated payload");
    encoder.add_file_stored("stored.txt", b"stored payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("deflated.txt"));
        assert!(names.contains("stored.txt"));

        let deflated = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "deflated.txt"])
            .output()
            .unwrap();
        assert!(deflated.status.success());
        assert_eq!(deflated.stdout, b"deflated payload deflated payload");

        let stored = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "stored.txt"])
            .output()
            .unwrap();
        assert!(stored.status.success());
        assert_eq!(stored.stdout, b"stored payload");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_encode_data_descriptor_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_dd_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("descriptor.zip");

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "descriptor.txt",
        b"descriptor payload descriptor payload",
        &zip::encode::ZipEntryOptions {
            use_data_descriptor: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let mut archive = Vec::new();
    let written = encoder.finish_to(&mut archive).unwrap();
    assert_eq!(written, archive.len());
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("descriptor.txt"));

        let extracted = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "descriptor.txt"])
            .output()
            .unwrap();
        assert!(extracted.status.success());
        assert_eq!(extracted.stdout, b"descriptor payload descriptor payload");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_stream_writer_system_unzip_compat() {
    use std::io::Cursor;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_stream_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("streamed.zip");

    let mut writer = zip::encode::ZipStreamWriter::new(Vec::new());
    writer
        .write_file_from_reader(
            "streamed.txt",
            Cursor::new(b"streamed payload streamed payload".as_slice()),
            &zip::encode::ZipEntryOptions::default(),
        )
        .unwrap();
    writer
        .write_file_from_reader(
            "stored.bin",
            Cursor::new([0x10, 0x20, 0x30, 0x40]),
            &zip::encode::ZipEntryOptions {
                compression: zip::encode::ZipCompression::Store,
                ..zip::encode::ZipEntryOptions::default()
            },
        )
        .unwrap();
    let archive = writer.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("streamed.txt"));
        assert!(names.contains("stored.bin"));

        let streamed = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "streamed.txt"])
            .output()
            .unwrap();
        assert!(streamed.status.success());
        assert_eq!(streamed.stdout, b"streamed payload streamed payload");

        let stored = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "stored.bin"])
            .output()
            .unwrap();
        assert!(stored.status.success());
        assert_eq!(stored.stdout, [0x10, 0x20, 0x30, 0x40]);
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_system_traditional_encrypted_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_trad_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("secret.txt"), b"traditional secret payload").unwrap();
    let archive_path = dir.join("traditional.zip");

    let output = Command::new("zip")
        .current_dir(&dir)
        .args(["-q", "-P", "secret", "traditional.zip", "secret.txt"])
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "zip -P failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let archive = std::fs::read(&archive_path).unwrap();
        let entries = zip::decode::decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, b"traditional secret payload");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(dir.join("secret.txt"));
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_encode_traditional_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_trad_encode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("traditional.zip");

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.set_traditional_password("secret");
    encoder.add_file("secret.txt", b"traditional payload traditional payload");
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("secret.txt"));

        let extracted = Command::new("unzip")
            .args([
                "-P",
                "secret",
                "-p",
                archive_path.to_str().unwrap(),
                "secret.txt",
            ])
            .output()
            .unwrap();
        assert!(extracted.status.success());
        assert_eq!(extracted.stdout, b"traditional payload traditional payload");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_encode_traditional_data_descriptor_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_trad_dd_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("traditional-dd.zip");

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.set_traditional_password("secret");
    encoder.add_file_with_options(
        "secret.txt",
        b"traditional descriptor payload",
        &zip::encode::ZipEntryOptions {
            use_data_descriptor: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("secret.txt"));

        let extracted = Command::new("unzip")
            .args([
                "-P",
                "secret",
                "-p",
                archive_path.to_str().unwrap(),
                "secret.txt",
            ])
            .output()
            .unwrap();
        assert!(extracted.status.success());
        assert_eq!(extracted.stdout, b"traditional descriptor payload");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_encode_aes_data_descriptor_roundtrip() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.set_password("secret");
    encoder.add_file_with_options(
        "secret.txt",
        b"aes descriptor payload",
        &zip::encode::ZipEntryOptions {
            use_data_descriptor: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();

    let entries = zip::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "secret.txt");
    assert_eq!(entries[0].data, b"aes descriptor payload");
    assert_ne!(entries[0].header.flags & (1 << 3), 0);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_reader_finish_to_roundtrip() {
    use std::io::Cursor;

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file("alpha.txt", b"alpha payload");
    encoder.add_file_stored("beta.bin", &[0xDE, 0xAD, 0xBE, 0xEF]);

    let mut archive = Vec::new();
    let written = encoder.finish_to(&mut archive).unwrap();
    assert_eq!(written, archive.len());

    let entries = zip::decode::decode_reader(Cursor::new(&archive)).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "alpha.txt");
    assert_eq!(entries[0].data, b"alpha payload");
    assert_eq!(entries[1].name, "beta.bin");
    assert_eq!(entries[1].data, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_aes_roundtrip_and_password_failure() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.set_password("secret");
    encoder.add_file("secret.txt", b"secret payload secret payload");
    encoder.add_file_stored("stored.bin", &[0x10, 0x20, 0x30, 0x40]);
    let archive = encoder.finish().unwrap();

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::Unsupported(
            "zip: encrypted entry requires a password"
        ))
    ));

    let entries = zip::decode::decode_with_password(&archive, "secret").unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "secret.txt");
    assert_eq!(entries[0].data, b"secret payload secret payload");
    assert_eq!(entries[0].header.compression_method, 8);
    assert_eq!(entries[1].name, "stored.bin");
    assert_eq!(entries[1].data, &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(entries[1].header.compression_method, 0);

    assert!(matches!(
        zip::decode::decode_with_password(&archive, "wrong"),
        Err(archive::error::Error::InvalidData(
            "zip: invalid AES password"
        ))
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_detects_checksum_mismatch() {
    let name = "stored.txt";
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        name,
        b"stored zip checksum payload",
        &zip::encode::ZipEntryOptions {
            compression: zip::encode::ZipCompression::Store,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let mut archive = encoder.finish().unwrap();

    let data_offset = 30 + name.len();
    archive[data_offset] ^= 0x01;

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_detects_size_mismatch() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_stored("size.txt", b"zip size payload");
    let mut archive = encoder.finish().unwrap();

    let cd_offset = find_signature(&archive, [0x50, 0x4B, 0x01, 0x02]);
    let size_offset = cd_offset + 24;
    let original = u32::from_le_bytes(archive[size_offset..size_offset + 4].try_into().unwrap());
    archive[size_offset..size_offset + 4].copy_from_slice(&(original + 1).to_le_bytes());

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::SizeMismatch { .. })
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_detects_data_descriptor_mismatch() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "descriptor.txt",
        b"descriptor payload",
        &zip::encode::ZipEntryOptions {
            use_data_descriptor: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let mut archive = encoder.finish().unwrap();

    let descriptor_offset = find_signature(&archive, [0x50, 0x4B, 0x07, 0x08]);
    archive[descriptor_offset + 8] ^= 0x01;

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::InvalidData(
            "zip: invalid data descriptor"
        ))
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_utf8_metadata_roundtrip_via_reader() {
    use std::io::Cursor;

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "日本語.txt",
        "UTF-8 payload".as_bytes(),
        &zip::encode::ZipEntryOptions {
            comment: "メタデータ".into(),
            utf8: true,
            mod_time: 0x1234,
            mod_date: 0x5678,
            ..zip::encode::ZipEntryOptions::default()
        },
    );

    let mut archive = Vec::new();
    let written = encoder.finish_to(&mut archive).unwrap();
    assert_eq!(written, archive.len());

    let entries = zip::decode::decode_reader(Cursor::new(&archive)).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "日本語.txt");
    assert_eq!(entries[0].data, b"UTF-8 payload");
    assert_eq!(entries[0].header.comment, "メタデータ");
    assert_eq!(entries[0].header.mod_time, 0x1234);
    assert_eq!(entries[0].header.mod_date, 0x5678);
    assert_ne!(entries[0].header.flags & (1 << 11), 0);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_cp437_metadata_roundtrip_without_utf8_flag() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "café.txt",
        b"cp437 payload",
        &zip::encode::ZipEntryOptions {
            comment: "ö comment".into(),
            utf8: false,
            ..zip::encode::ZipEntryOptions::default()
        },
    );

    let archive = encoder.finish().unwrap();
    let entries = zip::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "café.txt");
    assert_eq!(entries[0].data, b"cp437 payload");
    assert_eq!(entries[0].header.comment, "ö comment");
    assert_eq!(entries[0].header.flags & (1 << 11), 0);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_add_entry_roundtrip_preserves_metadata() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "source.txt",
        b"source payload",
        &zip::encode::ZipEntryOptions {
            comment: "source comment".into(),
            mod_time: 0x1111,
            mod_date: 0x2222,
            utf8: false,
            compression: zip::encode::ZipCompression::Store,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();
    let entries = zip::decode::decode(&archive).unwrap();

    let mut reencoder = zip::encode::ZipEncoder::new();
    reencoder.add_entry(&entries[0]);
    let rebuilt = reencoder.finish().unwrap();
    let rebuilt_entries = zip::decode::decode(&rebuilt).unwrap();

    assert_eq!(rebuilt_entries.len(), 1);
    assert_eq!(rebuilt_entries[0].name, "source.txt");
    assert_eq!(rebuilt_entries[0].data, b"source payload");
    assert_eq!(rebuilt_entries[0].header.comment, "source comment");
    assert_eq!(rebuilt_entries[0].header.mod_time, 0x1111);
    assert_eq!(rebuilt_entries[0].header.mod_date, 0x2222);
    assert_eq!(rebuilt_entries[0].header.flags & (1 << 11), 0);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_force_zip64_roundtrip() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "zip64.txt",
        b"forced zip64 payload",
        &zip::encode::ZipEntryOptions {
            force_zip64: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );

    let archive = encoder.finish().unwrap();
    assert!(archive.windows(4).any(|w| w == [0x50, 0x4B, 0x06, 0x06]));
    assert!(archive.windows(4).any(|w| w == [0x50, 0x4B, 0x06, 0x07]));

    let entries = zip::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "zip64.txt");
    assert_eq!(entries[0].data, b"forced zip64 payload");
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_force_zip64_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_zip64_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("zip64.zip");

    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "zip64.txt",
        b"forced zip64 payload for unzip",
        &zip::encode::ZipEntryOptions {
            force_zip64: true,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();
    std::fs::write(&archive_path, &archive).unwrap();

    let listing = Command::new("unzip")
        .args(["-Z1", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("zip64.txt"));

        let extracted = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), "zip64.txt"])
            .output()
            .unwrap();
        assert!(extracted.status.success());
        assert_eq!(extracted.stdout, b"forced zip64 payload for unzip");
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_detects_local_and_central_name_mismatch() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file("alpha.txt", b"name mismatch payload");
    let mut archive = encoder.finish().unwrap();

    archive[30] ^= 0x01;

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::InvalidData(
            "zip: local and central names differ"
        ))
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_decode_detects_invalid_local_file_header_signature() {
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file("broken.txt", b"broken header payload");
    let mut archive = encoder.finish().unwrap();

    archive[0] ^= 0x01;

    assert!(matches!(
        zip::decode::decode(&archive),
        Err(archive::error::Error::InvalidData(
            "zip: invalid local file header"
        ))
    ));
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_legacy_methods_roundtrip() {
    // Roundtrip the legacy methods (1-6, 9) through ZipEncoder and our decoder.
    let payload: &[u8] = b"the quick brown fox jumps over the lazy dog.         the quick brown fox jumps over the lazy dog. the quick brown fox.";

    let cases: &[(&str, zip::encode::ZipCompression, u16)] = &[
        ("shrunk.txt", zip::encode::ZipCompression::Shrunk, 1),
        ("reduce1.txt", zip::encode::ZipCompression::Reduce(1), 2),
        ("reduce2.txt", zip::encode::ZipCompression::Reduce(2), 3),
        ("reduce3.txt", zip::encode::ZipCompression::Reduce(3), 4),
        ("reduce4.txt", zip::encode::ZipCompression::Reduce(4), 5),
        ("implode.txt", zip::encode::ZipCompression::Implode, 6),
        ("deflate64.txt", zip::encode::ZipCompression::Deflate64, 9),
    ];

    for &(name, compression, method) in cases {
        let mut encoder = zip::encode::ZipEncoder::new();
        encoder.add_file_with_options(
            name,
            payload,
            &zip::encode::ZipEntryOptions {
                compression,
                ..zip::encode::ZipEntryOptions::default()
            },
        );
        let archive = encoder.finish().unwrap();
        let entries = zip::decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, name);
        assert_eq!(entries[0].data, payload, "method {method}");
        assert_eq!(entries[0].header.compression_method, method);
    }
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_legacy_methods_unar_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_legacy_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let payload: &[u8] = b"the quick brown fox jumps over the lazy dog.         the quick brown fox jumps over the lazy dog. the quick brown fox.";

    // unar (XADMaster) supports Shrink, Implode and Deflate64 but not Reduce.
    let unar_cases: &[(&str, zip::encode::ZipCompression)] = &[
        ("shrunk.txt", zip::encode::ZipCompression::Shrunk),
        ("implode.txt", zip::encode::ZipCompression::Implode),
        ("deflate64.txt", zip::encode::ZipCompression::Deflate64),
    ];
    // Info-ZIP unzip is compiled COPYRIGHT_CLEAN in most distributions and
    // therefore does not implement Reduce; use it only for the methods it
    // supports. Reduce is covered by the hwzip reference fixtures and the
    // mirror roundtrip test.
    let unzip_cases: &[(&str, zip::encode::ZipCompression)] = &[
        ("shrunk2.txt", zip::encode::ZipCompression::Shrunk),
        ("implode2.txt", zip::encode::ZipCompression::Implode),
        ("deflate64b.txt", zip::encode::ZipCompression::Deflate64),
    ];

    for &(name, compression) in unar_cases {
        let archive_path = dir.join(format!("{name}.zip"));
        let mut encoder = zip::encode::ZipEncoder::new();
        encoder.add_file_with_options(
            name,
            payload,
            &zip::encode::ZipEntryOptions {
                compression,
                ..zip::encode::ZipEntryOptions::default()
            },
        );
        std::fs::write(&archive_path, encoder.finish().unwrap()).unwrap();

        let out_dir = dir.join(format!("{name}.out"));
        std::fs::create_dir_all(&out_dir).unwrap();
        let extracted = Command::new("unar")
            .args([
                "-quiet",
                "-output-directory",
                out_dir.to_str().unwrap(),
                archive_path.to_str().unwrap(),
            ])
            .output();
        match extracted {
            Ok(result) => {
                assert!(
                    result.status.success(),
                    "unar failed on {name}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let data = std::fs::read(out_dir.join(name)).unwrap();
                assert_eq!(data, payload, "unar mismatch on {name}");
            }
            Err(_) => {
                eprintln!("unar not available; skipping unar oracle checks");
                break;
            }
        }
    }

    for &(name, compression) in unzip_cases {
        let archive_path = dir.join(format!("{name}.zip"));
        let mut encoder = zip::encode::ZipEncoder::new();
        encoder.add_file_with_options(
            name,
            payload,
            &zip::encode::ZipEntryOptions {
                compression,
                ..zip::encode::ZipEntryOptions::default()
            },
        );
        std::fs::write(&archive_path, encoder.finish().unwrap()).unwrap();

        let extracted = Command::new("unzip")
            .args(["-p", archive_path.to_str().unwrap(), name])
            .output();
        match extracted {
            Ok(result) => {
                assert!(
                    result.status.success(),
                    "unzip failed on {name}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(result.stdout, payload, "unzip mismatch on {name}");
            }
            Err(_) => {
                eprintln!("unzip not available; skipping unzip oracle checks");
                break;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_legacy_methods_hwzip_compat() {
    // Decode archives produced by the hwzip reference implementation
    // (public domain, https://www.hanshq.net/zip2.html). This is the Reduce
    // oracle: neither unar nor the commonly installed COPYRIGHT_CLEAN Info-ZIP
    // unzip implements methods 2-5. Our encoders for Shrink/Reduce/Implode
    // were also verified to expand correctly under hwzip.
    let expected = std::fs::read("tests/fixtures/zip/payload.bin").unwrap();
    for fixture in ["hw_shrink.zip", "hw_reduce.zip", "hw_implode.zip"] {
        let archive = std::fs::read(format!("tests/fixtures/zip/{fixture}")).unwrap();
        let entries = zip::decode::decode(&archive).unwrap();
        assert_eq!(entries.len(), 1, "{fixture}");
        assert_eq!(entries[0].data, expected, "{fixture}");
    }
}

#[cfg(all(feature = "zip", feature = "cmpsc"))]
#[test]
fn test_zip_method16_encode_roundtrip() {
    // Method 16 (IBM z/OS CMPSC). No commonly available system `unzip`
    // implements it, so coverage is a crate-internal encode -> decode
    // roundtrip. The encoder emits the alphabet-only (uncompressed) CMPSC
    // stream from `compress::cmpsc::encode`, mirroring the lzxd
    // uncompressed-encoder precedent.
    let payload: &[u8] = b"cmpsc method 16 payload payload payload";
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "cmpsc.bin",
        payload,
        &zip::encode::ZipEntryOptions {
            compression: zip::encode::ZipCompression::Cmpsc,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();
    let entries = zip::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "cmpsc.bin");
    assert_eq!(entries[0].data, payload);
    assert_eq!(entries[0].header.compression_method, 16);
}

#[cfg(all(feature = "zip", feature = "cmpsc"))]
#[test]
fn test_zip_method16_encode_header_fields() {
    // Both the local file header and the central directory record must carry
    // compression method 16, and the entry payload must start with the
    // APPNOTE method-16 dictionary header
    // `[version=1][flags|symsize][u32be dict len]`.
    let payload: &[u8] = b"header fields";
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "cmpsc.bin",
        payload,
        &zip::encode::ZipEntryOptions {
            compression: zip::encode::ZipCompression::Cmpsc,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();

    // Local file header: compression method is the u16 at offset 8.
    let local = find_signature(&archive, [0x50, 0x4b, 0x03, 0x04]);
    assert_eq!(
        u16::from_le_bytes(archive[local + 8..local + 10].try_into().unwrap()),
        16
    );
    // Central directory record: compression method is the u16 at offset 10.
    let central = find_signature(&archive, [0x50, 0x4b, 0x01, 0x02]);
    assert_eq!(
        u16::from_le_bytes(archive[central + 10..central + 12].try_into().unwrap()),
        16
    );

    // Local header layout: sig(4) ver(2) flags(2) method(2) time(2) date(2)
    // crc(4) csize(4) usize(4) name_len(2) extra_len(2) then name + extra +
    // compressed data.
    let name_len = u16::from_le_bytes(archive[local + 26..local + 28].try_into().unwrap()) as usize;
    let extra_len =
        u16::from_le_bytes(archive[local + 28..local + 30].try_into().unwrap()) as usize;
    let data = &archive[local + 30 + name_len + extra_len..];
    // version=1, flags 0x80 (expansion dictionary present) | symsize 9,
    // then the 512-entry alphabet dictionary length as u32be.
    assert_eq!(&data[..2], &[1, 0x89]);
    assert_eq!(&data[2..6], &4096u32.to_be_bytes());
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_method10_encode_roundtrip() {
    // Method 10 (PKWARE DCL Implode). The crate emits a literal-only
    // stream; coverage is a crate-internal encode -> decode roundtrip
    // plus a check that both headers carry method 10.
    let payload: &[u8] = b"dcl implode payload payload payload";
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_with_options(
        "dcl.bin",
        payload,
        &zip::encode::ZipEntryOptions {
            compression: zip::encode::ZipCompression::DclImplode,
            ..zip::encode::ZipEntryOptions::default()
        },
    );
    let archive = encoder.finish().unwrap();

    // Local file header: compression method is the u16 at offset 8.
    let local = find_signature(&archive, [0x50, 0x4b, 0x03, 0x04]);
    assert_eq!(
        u16::from_le_bytes(archive[local + 8..local + 10].try_into().unwrap()),
        10
    );
    // Central directory record: compression method is the u16 at offset 10.
    let central = find_signature(&archive, [0x50, 0x4b, 0x01, 0x02]);
    assert_eq!(
        u16::from_le_bytes(archive[central + 10..central + 12].try_into().unwrap()),
        10
    );

    let entries = zip::decode::decode(&archive).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "dcl.bin");
    assert_eq!(entries[0].data, payload);
    assert_eq!(entries[0].header.compression_method, 10);
}

#[cfg(feature = "zip")]
#[test]
fn test_zip_finish_parts_system_unzip_compat() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_zip_parts_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    // Entries sized so that 300-byte segments force several splits,
    // including one through stored entry data.
    let a_payload = vec![0x41u8; 400];
    let b_payload = b"deflated payload deflated payload".to_vec();
    let mut encoder = zip::encode::ZipEncoder::new();
    encoder.add_file_stored("a.bin", &a_payload);
    encoder.add_file("b.txt", &b_payload);
    // Info-ZIP unzip requires the central directory to begin on the last
    // disk; the compat layout keeps the whole CD + EOCD tail on it.
    let parts = encoder
        .finish_parts_with(
            300,
            &zip::encode::ZipSplitOptions {
                central_directory_on_last_segment: true,
            },
        )
        .unwrap();
    assert!(parts.len() > 1, "expected multiple segments");

    // PKWARE split naming (APPNOTE §8.3): name.z01 ... name.zNN, name.zip.
    let last = parts.len() - 1;
    for (index, part) in parts.iter().enumerate() {
        let path = if index == last {
            dir.join("split.zip")
        } else {
            dir.join(format!("split.z{:02}", index + 1))
        };
        std::fs::write(&path, part).unwrap();
    }
    let zip_path = dir.join("split.zip");

    // Crate-internal check: the segment set decodes via decode_parts.
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let entries = zip::decode::decode_parts(&slices).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "a.bin");
    assert_eq!(entries[0].data, a_payload);
    assert_eq!(entries[1].name, "b.txt");
    assert_eq!(entries[1].data, b_payload);

    // System oracle: unzip resolves .z01.. siblings of the .zip segment.
    let listing = Command::new("unzip")
        .args(["-Z1", zip_path.to_str().unwrap()])
        .output();

    if let Ok(result) = listing {
        assert!(
            result.status.success(),
            "unzip -Z1 failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let names = String::from_utf8_lossy(&result.stdout);
        assert!(names.contains("a.bin"), "listing: {names}");
        assert!(names.contains("b.txt"), "listing: {names}");
    }

    // Info-ZIP cannot extract multi-disk archives at all (even zip -s
    // output): use 7z as the extraction oracle. It resolves .z01..
    // siblings of the .zip segment.
    let sevenz = Command::new("7z").output();
    if sevenz.is_ok() {
        for (name, payload) in [("a.bin", &a_payload), ("b.txt", &b_payload)] {
            let extracted = Command::new("7z")
                .args(["x", "-so", zip_path.to_str().unwrap(), name])
                .output()
                .unwrap();
            assert!(
                extracted.status.success(),
                "7z x -so {name} failed: {}",
                String::from_utf8_lossy(&extracted.stderr)
            );
            assert_eq!(&extracted.stdout, payload, "7z mismatch on {name}");
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
