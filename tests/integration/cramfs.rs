use super::*;

// ============================================================
// cramfs integration tests (mkfs.cramfs / fsck.cramfs interop)
// ============================================================

/// Build a small source tree and produce a cramfs image with the real
/// mkfs.cramfs tool, returning (workdir, image bytes). Caller removes
/// the workdir.
fn mkfs_image() -> (std::path::PathBuf, Vec<u8>) {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cramfs_{uniq}"));
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("dir1/sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello cramfs").unwrap();
    std::fs::write(src.join("dir1/file.bin"), b"nested data").unwrap();
    std::fs::write(src.join("empty.txt"), b"").unwrap();
    let big: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(src.join("dir1/sub/big.dat"), &big).unwrap();
    std::os::unix::fs::symlink("dir1/file.bin", src.join("alink")).unwrap();

    let img_path = dir.join("test.cramfs");
    let out = Command::new("mkfs.cramfs")
        .arg(&src)
        .arg(&img_path)
        .output()
        .expect("mkfs.cramfs");
    assert!(
        out.status.success(),
        "mkfs.cramfs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let image = std::fs::read(&img_path).unwrap();
    (dir, image)
}

fn cleanup(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn test_cramfs_decode_mkfs_image() {
    let (dir, image) = mkfs_image();
    let img = cramfs::decode::decode(&image).unwrap();
    // mkfs.cramfs always emits FSID_VERSION_2 and a valid fsid.crc.
    assert_eq!(img.fsid_crc_ok, Some(true));

    let find = |path: &str| {
        img.entries
            .iter()
            .find(|e| e.name == path)
            .unwrap_or_else(|| panic!("missing entry {path}"))
    };
    assert_eq!(find("hello.txt").data, b"hello cramfs");
    assert_eq!(find("dir1/file.bin").data, b"nested data");
    assert_eq!(find("empty.txt").data, b"");
    let big_expect: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(find("dir1/sub/big.dat").data, big_expect);
    let link = find("alink");
    assert_eq!(link.kind, cramfs::decode::CramfsKind::Symlink);
    assert_eq!(link.data, b"dir1/file.bin");
    assert_eq!(find("dir1").kind, cramfs::decode::CramfsKind::Directory);
    assert_eq!(find("dir1/sub").kind, cramfs::decode::CramfsKind::Directory);
    cleanup(&dir);
}

#[test]
fn test_cramfs_fsid_crc_mismatch_is_informational() {
    let (dir, mut image) = mkfs_image();
    // Corrupt the fsid.crc field itself: the image must still decode
    // (the kernel ignores fsid), only the informational flag flips.
    image[32] ^= 0xFF;
    let img = cramfs::decode::decode(&image).unwrap();
    assert_eq!(img.fsid_crc_ok, Some(false));
    assert!(!img.entries.is_empty());
    cleanup(&dir);
}

#[test]
fn test_cramfs_fsck_extract_matches_decode() {
    use std::process::Command;

    let (dir, image) = mkfs_image();
    let img = cramfs::decode::decode(&image).unwrap();

    // Cross-validate: the real fsck.cramfs extractor must produce the
    // same files our decoder reports.
    let ext = dir.join("ext");
    let out = Command::new("fsck.cramfs")
        .arg(format!("--extract={}", ext.display()))
        .arg(dir.join("test.cramfs"))
        .output()
        .expect("fsck.cramfs");
    assert!(
        out.status.success(),
        "fsck.cramfs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for e in &img.entries {
        match e.kind {
            cramfs::decode::CramfsKind::File => {
                let disk = std::fs::read(ext.join(&e.name)).unwrap();
                assert_eq!(disk, e.data, "file {} mismatch", e.name);
            }
            cramfs::decode::CramfsKind::Symlink => {
                let target = std::fs::read_link(ext.join(&e.name)).unwrap();
                assert_eq!(
                    target.as_os_str().as_encoded_bytes(),
                    &e.data[..],
                    "symlink {} mismatch",
                    e.name
                );
            }
            cramfs::decode::CramfsKind::Directory => {
                assert!(ext.join(&e.name).is_dir(), "missing dir {}", e.name);
            }
            _ => {}
        }
    }
    cleanup(&dir);
}
