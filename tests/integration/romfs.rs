use super::*;

// ============================================================
// romfs integration tests (genromfs fixture interop)
// ============================================================

/// Reference image produced by upstream genromfs 0.5.2, committed at
/// `tests/fixtures/romfs/genromfs.romfs` (genromfs is not packaged in
/// the test container, so the image is checked in).
const FIXTURE: &[u8] = include_bytes!("../fixtures/romfs/genromfs.romfs");

fn find<'a>(img: &'a romfs::decode::RomfsImage, path: &str) -> &'a romfs::decode::RomfsEntry {
    img.entries
        .iter()
        .find(|e| e.name == path)
        .unwrap_or_else(|| panic!("missing entry {path}"))
}

#[test]
fn test_romfs_genromfs_image_layout() {
    let img = romfs::decode::decode(FIXTURE).unwrap();
    assert_eq!(img.name, "testvol");
    // '.' and '..' helper headers must not surface as entries.
    assert!(img.entries.iter().all(|e| e.name != "." && e.name != ".."));
    // every entry carries a full path
    assert!(img.entries.iter().any(|e| e.name == "dir1/sub/big.dat"));
}

#[test]
fn test_romfs_genromfs_image_contents() {
    let img = romfs::decode::decode(FIXTURE).unwrap();
    assert_eq!(find(&img, "hello.txt").data, b"hello romfs");
    assert_eq!(find(&img, "dir1/file.bin").data, b"nested");
    assert_eq!(find(&img, "dir1/sub/big.dat").data.len(), 5000);
    // multi-block file decodes correctly (5000 bytes spans several
    // 16-byte aligned regions)
    let big = &find(&img, "dir1/sub/big.dat").data;
    assert!(big.iter().any(|&b| b != 0));

    // symlink target preserved verbatim
    let link = find(&img, "symlink");
    assert_eq!(link.kind, romfs::decode::RomfsKind::Symlink);
    assert_eq!(link.data, b"dir1/file.bin");

    // hard link resolves to the target's data
    let hl = find(&img, "hardlink.txt");
    assert_eq!(hl.kind, romfs::decode::RomfsKind::Hardlink);
    assert_eq!(hl.data, b"hello romfs");

    // executable bit propagates to mode
    assert_ne!(find(&img, "exec.sh").mode & 0o111, 0);
    assert_eq!(find(&img, "hello.txt").mode & 0o111, 0);
}

#[test]
fn test_romfs_codec_trait() {
    let codec = romfs::RomfsCodec;
    use archive::traits::{ArchiveDecode, ArchiveEntry};
    let entries = codec.decode(FIXTURE).unwrap();
    assert!(entries.iter().any(|e| e.name() == "hello.txt"));
}

#[test]
fn test_romfs_rejects_truncated_image() {
    // declared image size larger than the input
    assert!(romfs::decode::decode(&FIXTURE[..3000]).is_err());
    // shorter than superblock
    assert!(romfs::decode::decode(&FIXTURE[..8]).is_err());
}

#[test]
fn test_romfs_rejects_corrupt_checksum() {
    let mut img = FIXTURE.to_vec();
    // corrupt a byte inside the first 512 bytes outside the checksum
    // field: longword sum over the checked region no longer cancels
    img[40] ^= 0xFF;
    assert!(romfs::decode::decode(&img).is_err());
}

#[test]
fn test_romfs_encoder_roundtrip() {
    let mut enc = romfs::encode::RomfsEncoder::new().with_volume_name("enc");
    enc.add_file("a.txt", b"aaa");
    enc.add_directory("d");
    enc.add_file("d/b.txt", b"bbb");
    enc.add_symlink("s", "d/b.txt");
    enc.add_hardlink("h.txt", "a.txt");
    enc.add_char_device("dev/null", 1, 3);
    let img = enc.finish().unwrap();
    let dec = romfs::decode::decode(&img).unwrap();
    assert_eq!(dec.name, "enc");
    assert_eq!(find(&dec, "a.txt").data, b"aaa");
    assert_eq!(find(&dec, "d/b.txt").data, b"bbb");
    assert_eq!(find(&dec, "s").data, b"d/b.txt");
    let h = find(&dec, "h.txt");
    assert_eq!(h.kind, romfs::decode::RomfsKind::Hardlink);
    assert_eq!(h.data, b"aaa");
    assert_eq!(find(&dec, "dev/null").dev, Some((1, 3)));
}

#[test]
fn test_romfs_encoder_trait() {
    use archive::traits::{ArchiveEncode, ArchiveEntry};
    let mut enc = romfs::RomfsArchiveEncoder::new();
    enc.add_file("t.txt", b"trait");
    let img = enc.finish().unwrap();
    let codec = romfs::RomfsCodec;
    use archive::traits::ArchiveDecode;
    let entries = codec.decode(&img).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name(), "t.txt");
    assert_eq!(entries[0].data(), b"trait");
}

/// `fsck.romfs` (from the genromfs package) validates superblock and
/// per-header checksums and walks the header tree; skipped when the
/// tool is not installed.
#[test]
fn test_romfs_encoder_fsck_romfs_oracle() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    if Command::new("fsck.romfs").output().is_err() {
        return;
    }
    let mut enc = romfs::encode::RomfsEncoder::new().with_volume_name("oracle");
    enc.add_file("hello.txt", b"hello romfs");
    enc.add_file("dir1/file.bin", b"nested");
    enc.add_symlink("symlink", "dir1/file.bin");
    enc.add_hardlink("hardlink.txt", "hello.txt");
    enc.add_executable_file("exec.sh", b"#!/bin/sh\n");
    let img = enc.finish().unwrap();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_romfs_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let image_path = dir.join("enc.romfs");
    std::fs::write(&image_path, &img).unwrap();
    let output = Command::new("fsck.romfs")
        .arg("-f")
        .arg(&image_path)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        output.status.success(),
        "fsck.romfs rejected encoder output: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
