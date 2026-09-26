// ============================================================
// mtree manifest tests
// ============================================================

#[test]
fn test_mtree_decode_basic() {
    let text = "#mtree\n\
/set type=file uid=0 gid=0 mode=644\n\
./hello.txt size=5\n\
dir type=dir mode=755\n\
inner.txt size=3\n\
..\n";
    let entries = archive::archive::mtree::decode::decode(text.as_bytes()).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].size, Some(5));
    assert_eq!(entries[1].name, "dir");
    assert_eq!(entries[2].name, "dir/inner.txt");
}

#[test]
fn test_mtree_bsdtar_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_mtree_{uniq}"));
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello mtree").unwrap();
    std::fs::write(src.join("sub/data.bin"), [9u8; 64]).unwrap();

    let mtree_path = dir.join("test.mtree");
    // bsdtar can emit an mtree manifest for a directory tree.
    let output = Command::new("bsdtar")
        .args(["-cf"])
        .arg(&mtree_path)
        .arg("--format=mtree")
        .arg("-C")
        .arg(&src)
        .arg(".")
        .output();
    let Ok(result) = output else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    if !result.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return; // bsdtar mtree write unsupported in this build
    }

    let manifest = std::fs::read(&mtree_path);
    let _ = std::fs::remove_dir_all(&dir);
    let manifest = manifest.unwrap();
    let entries = archive::archive::mtree::decode::decode(&manifest).unwrap();

    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"hello.txt"), "names: {names:?}");
    assert!(names.contains(&"sub"), "names: {names:?}");
    assert!(names.contains(&"sub/data.bin"), "names: {names:?}");
    let hello = entries.iter().find(|e| e.name == "hello.txt").unwrap();
    assert_eq!(hello.size, Some(11));
}
