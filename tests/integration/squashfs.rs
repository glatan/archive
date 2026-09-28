use super::*;

// ============================================================
// SquashFS image tests
// ============================================================

#[test]
fn test_squashfs_decode_mksquashfs_image() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    for comp in ["gzip", "zstd", "xz", "lz4", "lzo"] {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("archive_test_sqfs_{comp}_{uniq}"));
        let src_dir = dir.join("src");
        std::fs::create_dir_all(src_dir.join("sub")).unwrap();
        std::fs::write(src_dir.join("hello.txt"), b"hello squashfs").unwrap();
        std::fs::write(src_dir.join("sub/data.bin"), [7u8; 5000]).unwrap();

        let image_path = dir.join("test.sqfs");
        let output = Command::new("mksquashfs")
            .arg(&src_dir)
            .arg(&image_path)
            .args([
                "-comp",
                comp,
                "-b",
                "4096",
                "-noappend",
                "-no-xattrs",
                "-no-progress",
            ])
            .output();

        if let Ok(result) = output {
            assert!(
                result.status.success(),
                "mksquashfs -comp {comp} failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let image = std::fs::read(&image_path).unwrap();
            let decoded = squashfs::decode::decode(&image).unwrap();

            let names: Vec<_> = decoded.entries.iter().map(|e| e.name.as_str()).collect();
            assert!(
                names.contains(&"hello.txt"),
                "entries missing hello.txt in {comp} image: {names:?}"
            );
            let file = decoded
                .entries
                .iter()
                .find(|e| e.name == "hello.txt")
                .unwrap();
            assert_eq!(file.data, b"hello squashfs");

            let bin = decoded
                .entries
                .iter()
                .find(|e| e.name == "sub/data.bin")
                .expect("sub/data.bin missing");
            assert_eq!(bin.data.len(), 5000);
            assert!(bin.data.iter().all(|&b| b == 7));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn test_squashfs_encoder_roundtrip() {
    let mut enc = squashfs::encode::SquashfsEncoder::new();
    enc.add_file("hello.txt", b"hello squashfs");
    enc.add_file("sub/data.bin", &[7u8; 5000]);
    enc.add_file("empty", b"");
    let image = enc.finish().unwrap();
    let decoded = squashfs::decode::decode(&image).unwrap();
    let f = decoded
        .entries
        .iter()
        .find(|e| e.name == "sub/data.bin")
        .unwrap();
    assert_eq!(f.data.len(), 5000);
    assert!(f.data.iter().all(|&b| b == 7));
}

#[test]
fn test_squashfs_encoder_unsquashfs_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    for comp in [
        squashfs::decode::SquashfsCompression::Gzip,
        squashfs::decode::SquashfsCompression::Xz,
        squashfs::decode::SquashfsCompression::Lz4,
        squashfs::decode::SquashfsCompression::Lzo,
        squashfs::decode::SquashfsCompression::Zstd,
    ] {
        let mut enc = squashfs::encode::SquashfsEncoder::new()
            .with_compression(comp)
            .with_block_size(8192)
            .with_mtime(1_700_000_000);
        enc.add_file("big.bin", &payload);
        enc.add_file("sub/note.txt", b"note");
        let image = enc.finish().unwrap();

        // internal roundtrip
        let decoded = squashfs::decode::decode(&image).unwrap();
        assert_eq!(
            decoded
                .entries
                .iter()
                .find(|e| e.name == "big.bin")
                .unwrap()
                .data,
            payload
        );

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("archive_test_sqfs_w_{uniq}"));
        std::fs::create_dir_all(&dir).unwrap();
        let image_path = dir.join("enc.sqfs");
        std::fs::write(&image_path, &image).unwrap();
        let dest = dir.join("out");

        let output = Command::new("unsquashfs")
            .arg("-d")
            .arg(&dest)
            .arg("-no-progress")
            .arg(&image_path)
            .output();
        if let Ok(result) = output {
            assert!(
                result.status.success(),
                "unsquashfs failed for {comp:?}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(std::fs::read(dest.join("big.bin")).unwrap(), payload);
            assert_eq!(std::fs::read(dest.join("sub/note.txt")).unwrap(), b"note");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn test_squashfs_encoder_symlink_fragments_ids() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut enc = squashfs::encode::SquashfsEncoder::new()
        .with_block_size(4096)
        .with_fragments();
    let tail_a: Vec<u8> = (0..5000u32).map(|i| (i % 11) as u8).collect();
    enc.add_file("a.bin", &tail_a);
    enc.add_file_owned("owned.bin", b"owned", 1000, 200);
    enc.add_symlink("link", "/a.bin");
    let image = enc.finish().unwrap();

    // internal roundtrip
    let decoded = squashfs::decode::decode(&image).unwrap();
    assert_eq!(
        decoded
            .entries
            .iter()
            .find(|e| e.name == "a.bin")
            .unwrap()
            .data,
        tail_a
    );
    assert_eq!(
        decoded
            .entries
            .iter()
            .find(|e| e.name == "link")
            .unwrap()
            .data,
        b"/a.bin"
    );

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_sqfs_ext_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let image_path = dir.join("ext.sqfs");
    std::fs::write(&image_path, &image).unwrap();
    let dest = dir.join("out");

    let output = Command::new("unsquashfs")
        .arg("-d")
        .arg(&dest)
        .arg("-no-progress")
        .arg(&image_path)
        .output();
    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "unsquashfs failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(std::fs::read(dest.join("a.bin")).unwrap(), tail_a);
        // unsquashfs materializes the symlink; verify its target.
        let target = std::fs::read_link(dest.join("link")).unwrap();
        assert_eq!(target, std::path::Path::new("/a.bin"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
