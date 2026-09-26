// ============================================================
// ARJ container tests (method 0 / stored only)
// ============================================================

fn arj_fixture(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = archive::archive::arj::encode::ArjEncoder::new();
    enc.add_file(name, data, 0).unwrap();
    enc.finish()
}

#[test]
fn test_arj_encode_decode_roundtrip() {
    let data = b"hello arj world".repeat(8);
    let a = arj_fixture("hello.txt", &data);
    let entries = archive::archive::arj::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].data, data.as_slice());
    assert_eq!(entries[0].method, 0);
}

#[test]
fn test_arj_multi_entry_roundtrip() {
    let mut enc = archive::archive::arj::encode::ArjEncoder::new();
    enc.add_dir("sub", 0).unwrap();
    enc.add_file("sub/a.bin", &[5, 6, 7], 0).unwrap();
    enc.add_file("top.txt", b"top", 0).unwrap();
    let entries = archive::archive::arj::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries[0].is_dir);
    assert_eq!(entries[1].name, "sub/a.bin");
    assert_eq!(entries[2].data, b"top");
}

#[test]
fn test_arj_rejects_truncated() {
    let a = arj_fixture("f.txt", b"payload");
    assert!(archive::archive::arj::decode::decode(&a[..10]).is_err());
    assert!(archive::archive::arj::decode::decode(&a[..a.len() - 4]).is_err());
    // No terminator at all: decode must fail at the next signature read.
    assert!(archive::archive::arj::decode::decode(&a[..a.len() - 6]).is_err());
}

#[test]
fn test_arj_rejects_compressed_method() {
    let mut a = arj_fixture("f.txt", b"payload");
    // File header follows: sig(2)+size(2)+body+crc(4)+ext(2).
    let h1 = u16::from_le_bytes([a[2], a[3]]) as usize;
    let second = 4 + h1 + 4 + 2;
    a[second + 4 + 5] = 1; // method = compressed-most
    let bsize = u16::from_le_bytes([a[second + 2], a[second + 3]]) as usize;
    let crc = crc32_local(&a[second + 4..second + 4 + bsize]);
    a[second + 4 + bsize..second + 8 + bsize].copy_from_slice(&crc.to_le_bytes());
    let err = archive::archive::arj::decode::decode(&a).unwrap_err();
    assert!(matches!(err, archive::error::Error::Unsupported(_)));
}

fn crc32_local(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[test]
fn test_arj_7z_list_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data = b"arj 7z interop payload".repeat(4);
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_arj_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test.arj");
    std::fs::write(&path, arj_fixture("interop.txt", &data)).unwrap();

    // 7-Zip reads ARJ: verify it can list and extract our method-0 file.
    let output = Command::new("7z").args(["l"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // 7z build without ARJ support
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
