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
