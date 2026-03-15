use super::*;

// ============================================================
// Combined: tar.gz
// ============================================================

#[test]
fn test_tar_gz_decode() {
    let tar_gz_data = include_bytes!("../fixtures/combined/multi_file.tar.gz");
    let tar_data = gzip::decode::decode(tar_gz_data).unwrap();
    let entries = tar::decode::decode(&tar_data).unwrap();

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
// Tar + Zstd roundtrip
// ============================================================

#[test]
fn test_tar_zst_roundtrip() {
    // Create a tar archive, compress with zstd, decompress, decode, and verify.
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("alpha.txt", b"Alpha content");
    encoder.add_file("beta.txt", b"Beta content here");
    encoder.add_directory("subdir/", 0o755);
    encoder.add_file("subdir/gamma.txt", b"Gamma nested");
    let tar_data = encoder.finish();

    let compressed = zstd::encode::encode(&tar_data);
    let decompressed = zstd::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, tar_data);

    let entries = tar::decode::decode(&decompressed).unwrap();
    assert_eq!(entries.len(), 4);

    assert_eq!(entries[0].header.name, "alpha.txt");
    assert_eq!(entries[0].data, b"Alpha content");
    assert_eq!(entries[1].header.name, "beta.txt");
    assert_eq!(entries[1].data, b"Beta content here");
    assert_eq!(entries[3].header.name, "subdir/gamma.txt");
    assert_eq!(entries[3].data, b"Gamma nested");
}

// ============================================================
// Cpio + Gzip roundtrip
// ============================================================

#[test]
fn test_cpio_gz_roundtrip() {
    // Create a cpio archive, compress with gzip, decompress, decode, and verify.
    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_file("first.txt", b"First file data");
    encoder.add_file("second.txt", b"Second file data");
    encoder.add_directory("mydir", 0o755);
    let cpio_data = encoder.finish();

    let compressed = gzip::encode::encode(
        &cpio_data,
        archive::compress::deflate::encode::Level::Default,
    );
    let decompressed = gzip::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, cpio_data);

    let entries = cpio::decode::decode(&decompressed).unwrap();
    assert_eq!(entries.len(), 3);

    assert_eq!(entries[0].name, "first.txt");
    assert_eq!(entries[0].data, b"First file data");
    assert_eq!(entries[1].name, "second.txt");
    assert_eq!(entries[1].data, b"Second file data");
    assert_eq!(entries[2].name, "mydir");
    assert!(entries[2].header.is_directory());
}

// ============================================================
// Format mismatch: tar data decoded as cpio
// ============================================================

#[test]
fn test_format_mismatch_tar_as_cpio() {
    // Valid tar data should NOT be decodable as cpio. The cpio decoder should
    // return an error (not panic) because the tar magic bytes ("ustar") do not
    // match the cpio magic ("070701" / "070702").
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("test.txt", b"Hello, tar!");
    let tar_data = encoder.finish();

    let result = cpio::decode::decode(&tar_data);
    assert!(
        result.is_err(),
        "decoding tar data as cpio should produce an error, got: {:?}",
        result
    );
}

#[test]
fn test_cpio_zst_roundtrip() {
    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_file("hello.txt", b"Hello from cpio.zst!");
    encoder.add_file("world.txt", b"World!");
    let cpio_data = encoder.finish();

    let zst_data = zstd::encode::encode(&cpio_data);
    let decoded_cpio = zstd::decode::decode(&zst_data).unwrap();
    let entries = cpio::decode::decode(&decoded_cpio).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].data, b"Hello from cpio.zst!");
    assert_eq!(entries[1].name, "world.txt");
    assert_eq!(entries[1].data, b"World!");
}

// ============================================================
// C-6: Additional integration tests
// ============================================================

#[test]
fn test_tar_gz_encode_decode_roundtrip() {
    // C-6 #24: tar.gz encode → decode roundtrip
    let mut encoder = tar::encode::TarEncoder::new();
    encoder.add_file("readme.txt", b"Read me!");
    encoder.add_file("data.bin", &[0xDE, 0xAD, 0xBE, 0xEF]);
    encoder.add_directory("subdir/", 0o755);
    let tar_data = encoder.finish();

    let gz_data = gzip::encode::encode(
        &tar_data,
        archive::compress::deflate::encode::Level::Default,
    );
    let decompressed = gzip::decode::decode(&gz_data).unwrap();
    assert_eq!(decompressed, tar_data);

    let entries = tar::decode::decode(&decompressed).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].header.name, "readme.txt");
    assert_eq!(entries[0].data, b"Read me!");
    assert_eq!(entries[1].header.name, "data.bin");
    assert_eq!(entries[1].data, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_format_mismatch_cpio_as_tar() {
    // C-6 #25: cpio data decoded as tar should fail (reverse of existing test)
    let mut encoder = cpio::encode::CpioEncoder::new();
    encoder.add_file("test.txt", b"Hello, cpio!");
    let cpio_data = encoder.finish();

    let result = tar::decode::decode(&cpio_data);
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|e| e.is_empty()),
        "decoding cpio data as tar should produce an error or empty result, got: {:?}",
        result
    );
}
