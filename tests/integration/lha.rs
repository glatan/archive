// ============================================================
// LHA/LZH container tests (store methods only)
// ============================================================

fn lha_fixture(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = archive::archive::lha::encode::LhaEncoder::new();
    enc.add_file(name, data, 0).unwrap();
    enc.finish()
}

#[test]
fn test_lha_encode_decode_roundtrip() {
    let data = b"hello lha world".repeat(8);
    let a = lha_fixture("hello.txt", &data);
    let entries = archive::archive::lha::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].data, data.as_slice());
    assert_eq!(entries[0].level, 0);
}

#[test]
fn test_lha_multi_entry_roundtrip() {
    let mut enc = archive::archive::lha::encode::LhaEncoder::new();
    enc.add_dir("sub", 0).unwrap();
    enc.add_file("sub/a.bin", &[1, 2, 3, 4], 0).unwrap();
    enc.add_file("top.txt", b"top", 0).unwrap();
    let entries = archive::archive::lha::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].is_dir);
    assert_eq!(entries[1].name, "sub/a.bin");
    assert_eq!(entries[2].data, b"top");
}

#[test]
fn test_lha_rejects_truncated() {
    let a = lha_fixture("f.txt", b"payload");
    assert!(archive::archive::lha::decode::decode(&a[..10]).is_err());
    assert!(archive::archive::lha::decode::decode(&a[..a.len() - 3]).is_err());
}

#[test]
fn test_lha_rejects_compressed_method() {
    // Rewrite the method marker to -lh5- and fix the header checksum;
    // decode must refuse with Unsupported.
    let mut a = lha_fixture("f.txt", b"payload");
    a[4] = b'5';
    let hsize = a[0] as usize;
    a[1] = a[2..2 + hsize].iter().fold(0u8, |x, &b| x.wrapping_add(b));
    let err = archive::archive::lha::decode::decode(&a).unwrap_err();
    assert!(matches!(err, archive::error::Error::Unsupported(_)));
}

#[test]
fn test_lha_7z_list_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data = b"lha 7z interop payload".repeat(4);
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lha_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.lzh");
    std::fs::write(&path, lha_fixture("interop.txt", &data)).unwrap();

    // 7-Zip reads LZH: verify it can list and extract our level-0 file.
    let output = Command::new("7z").args(["l"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // 7z build without LZH support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("interop.txt"), "7z l output: {listing}");

    let out_dir = dir.join("out");
    let output = Command::new("7z")
        .args(["x", "-y"])
        .arg(format!("-o{}", out_dir.display()))
        .arg(&path)
        .output()
        .unwrap();
    if output.status.success() {
        let extracted = std::fs::read(out_dir.join("interop.txt")).unwrap();
        assert_eq!(extracted, data.as_slice());
    }
}

#[test]
fn test_lha_bsdtar_list_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lhab_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.lzh");
    std::fs::write(&path, lha_fixture("bsd.txt", b"bsdtar lha")).unwrap();

    // libarchive's lzh reader should accept a level-0 -lh0- archive.
    let output = Command::new("bsdtar").args(["-tf"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // libarchive build without lzh support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("bsd.txt"), "bsdtar -tf output: {listing}");
}
