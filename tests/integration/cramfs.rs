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

fn fsck_available() -> bool {
    std::process::Command::new("fsck.cramfs").output().is_ok()
}

/// Build a small image with our encoder, returning its bytes.
fn encoded_image() -> Vec<u8> {
    let mut enc = cramfs::encode::CramfsEncoder::new();
    enc.set_name("rustfs");
    enc.add_dir("dir1/sub");
    enc.add_file("hello.txt", b"hello cramfs");
    enc.add_file("dir1/file.bin", b"nested data");
    enc.add_file("empty.txt", b"");
    let big: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    enc.add_file("dir1/sub/big.dat", &big);
    enc.add_symlink("alink", "dir1/file.bin");
    enc.finish().unwrap()
}

#[test]
fn test_cramfs_encode_fsck_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    if !fsck_available() {
        eprintln!("fsck.cramfs not found, skipping");
        return;
    }
    let image = encoded_image();
    // Sanity: our own decoder accepts it and the fsid CRC verifies.
    let img = cramfs::decode::decode(&image).unwrap();
    assert_eq!(img.fsid_crc_ok, Some(true));
    assert_eq!(img.name, "rustfs");

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_cramfs_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let img_path = dir.join("enc.cramfs");
    std::fs::write(&img_path, &image).unwrap();
    let ext = dir.join("ext");
    // The real checker validates superblock, CRC, and inode layout;
    // --extract additionally decompresses every block.
    let out = Command::new("fsck.cramfs")
        .arg(format!("--extract={}", ext.display()))
        .arg(&img_path)
        .output()
        .expect("fsck.cramfs");
    assert!(
        out.status.success(),
        "fsck.cramfs rejected our image: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(ext.join("hello.txt")).unwrap(),
        b"hello cramfs"
    );
    assert_eq!(
        std::fs::read(ext.join("dir1/file.bin")).unwrap(),
        b"nested data"
    );
    assert_eq!(std::fs::read(ext.join("empty.txt")).unwrap(), b"");
    let big_expect: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        std::fs::read(ext.join("dir1/sub/big.dat")).unwrap(),
        big_expect
    );
    assert_eq!(
        std::fs::read_link(ext.join("alink"))
            .unwrap()
            .as_os_str()
            .as_encoded_bytes(),
        b"dir1/file.bin"
    );
    cleanup(&dir);
}

#[test]
fn test_cramfs_mkfs_image_reencode_roundtrip() {
    // Decode a real mkfs.cramfs image, re-encode every entry with our
    // encoder, and require an identical decoded view.
    let (dir, image) = mkfs_image();
    let img = cramfs::decode::decode(&image).unwrap();

    let mut enc = cramfs::encode::CramfsEncoder::new();
    for e in &img.entries {
        let opts = cramfs::encode::CramfsEntryOptions {
            mode: e.mode & 0o7777,
            uid: e.uid,
            gid: e.gid,
        };
        match e.kind {
            cramfs::decode::CramfsKind::File => {
                enc.add_file_with_options(&e.name, &e.data, &opts);
            }
            cramfs::decode::CramfsKind::Directory => {
                enc.add_dir_with_options(&e.name, &opts);
            }
            cramfs::decode::CramfsKind::Symlink => {
                enc.add_symlink(&e.name, core::str::from_utf8(&e.data).unwrap());
            }
            _ => {}
        }
    }
    let image2 = enc.finish().unwrap();
    let img2 = cramfs::decode::decode(&image2).unwrap();
    assert_eq!(img2.fsid_crc_ok, Some(true));
    assert_eq!(img.entries.len(), img2.entries.len());
    for (a, b) in img.entries.iter().zip(&img2.entries) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.mode, b.mode);
        assert_eq!(a.data, b.data);
    }
    cleanup(&dir);
}
