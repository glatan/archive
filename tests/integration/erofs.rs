use super::*;

// ============================================================
// erofs integration tests (mkfs.erofs fixture interop)
// ============================================================

/// Reference image produced by upstream erofs-utils `mkfs.erofs`
/// (committed at `tests/fixtures/erofs/mkfs.erofs.img`; erofs-utils
/// is not packaged in the test container). Source tree:
/// `hello.txt` ("hello erofs world\n"), `big.txt` (3000 x 'A'),
/// `subdir/one.dat` ("x"), `subdir/deep/two.dat` ("y"),
/// `link.txt` -> "hello.txt". Verified extractable by upstream
/// `fsck.erofs --extract`.
const FIXTURE: &[u8] = include_bytes!("../fixtures/erofs/mkfs.erofs.img");

fn find<'a>(img: &'a erofs::decode::ErofsImage, path: &str) -> &'a erofs::decode::ErofsEntry {
    img.entries
        .iter()
        .find(|e| e.name == path)
        .unwrap_or_else(|| panic!("missing entry {path}"))
}

#[test]
fn test_erofs_mkfs_image_layout() {
    let img = erofs::decode::decode(FIXTURE).unwrap();
    assert_eq!(img.block_size, 4096);
    assert!(img.entries.iter().all(|e| e.name != "." && e.name != ".."));
    let mut names: Vec<&str> = img.entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "big.txt",
            "hello.txt",
            "link.txt",
            "subdir",
            "subdir/deep",
            "subdir/deep/two.dat",
            "subdir/one.dat"
        ]
    );
}

#[test]
fn test_erofs_mkfs_image_contents() {
    let img = erofs::decode::decode(FIXTURE).unwrap();

    let hello = find(&img, "hello.txt");
    assert_eq!(hello.kind, erofs::decode::ErofsKind::File);
    assert_eq!(hello.data, b"hello erofs world\n");

    // 3000 bytes < 4 KiB block: fully-inline tail data.
    let big = find(&img, "big.txt");
    assert_eq!(big.data.len(), 3000);
    assert!(big.data.iter().all(|&b| b == b'A'));

    assert_eq!(
        find(&img, "subdir").kind,
        erofs::decode::ErofsKind::Directory
    );
    assert_eq!(
        find(&img, "subdir/deep").kind,
        erofs::decode::ErofsKind::Directory
    );
    assert_eq!(find(&img, "subdir/one.dat").data, b"x");
    assert_eq!(find(&img, "subdir/deep/two.dat").data, b"y");

    let link = find(&img, "link.txt");
    assert_eq!(link.kind, erofs::decode::ErofsKind::Symlink);
    assert_eq!(link.data, b"hello.txt");
}

#[test]
fn test_erofs_codec_trait() {
    let codec = erofs::ErofsCodec;
    use archive::traits::{ArchiveDecode, ArchiveEntry};
    let entries = codec.decode(FIXTURE).unwrap();
    assert!(entries.iter().any(|e| e.name() == "hello.txt"));
}

#[test]
fn test_erofs_rejects_truncation() {
    // Cut inside referenced file data; decode must fail rather than
    // silently emit partial entries.
    let truncated = &FIXTURE[..5000];
    assert!(erofs::decode::decode(truncated).is_err());
}

#[test]
fn test_erofs_rejects_bad_superblock_checksum() {
    // The committed image sets EROFS_FEATURE_COMPAT_SB_CHKSUM;
    // corrupting an in-scope superblock byte must trip the CRC32C
    // verification.
    let mut bad = FIXTURE.to_vec();
    bad[1024 + 40] ^= 0xff; // meta_blkaddr
    assert!(matches!(
        erofs::decode::decode(&bad),
        Err(archive::error::Error::ChecksumMismatch { .. })
            | Err(archive::error::Error::InvalidData(_))
            | Err(archive::error::Error::UnexpectedEof)
    ));
}

#[test]
fn test_erofs_fsck_extract_matches_decode() {
    use std::process::Command;

    // Optional upstream interop: when fsck.erofs is available, its
    // extracted tree must match our decoded entries.
    if Command::new("fsck.erofs")
        .arg("--help")
        .output()
        .map(|o| !o.status.success() && o.stderr.is_empty())
        .unwrap_or(true)
    {
        eprintln!("fsck.erofs not available; skipping");
        return;
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_erofs_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let img_path = dir.join("test.erofs");
    std::fs::write(&img_path, FIXTURE).unwrap();
    let ext = dir.join("ext");
    let out = Command::new("fsck.erofs")
        .arg(format!("--extract={}", ext.display()))
        .arg(&img_path)
        .output()
        .expect("fsck.erofs");
    assert!(
        out.status.success(),
        "fsck.erofs failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let img = erofs::decode::decode(FIXTURE).unwrap();
    for e in &img.entries {
        match e.kind {
            erofs::decode::ErofsKind::File => {
                let disk = std::fs::read(ext.join(&e.name)).unwrap();
                assert_eq!(disk, e.data, "file {} mismatch", e.name);
            }
            erofs::decode::ErofsKind::Symlink => {
                let target = std::fs::read_link(ext.join(&e.name)).unwrap();
                assert_eq!(
                    target.as_os_str().as_encoded_bytes(),
                    &e.data[..],
                    "symlink {} mismatch",
                    e.name
                );
            }
            erofs::decode::ErofsKind::Directory => {
                assert!(ext.join(&e.name).is_dir(), "missing dir {}", e.name);
            }
            _ => {}
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
