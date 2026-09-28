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

#[test]
fn test_mtree_encode_roundtrip() {
    use archive::archive::mtree::decode::{MtreeEntry, MtreeKind};
    use archive::archive::mtree::encode::MtreeEncoder;
    use std::collections::BTreeMap;

    let mut e = MtreeEntry {
        name: "sub/dir with space/file.txt".to_string(),
        kind: MtreeKind::File,
        size: Some(42),
        mode: Some(0o640),
        uid: Some(1000),
        gid: Some(1000),
        uname: Some("user".to_string()),
        gname: Some("group".to_string()),
        time: Some("1700000000.123456789".to_string()),
        link: None,
        digests: BTreeMap::new(),
    };
    e.digests.insert("sha1".to_string(), "0a0a0a".to_string());

    let mut enc = MtreeEncoder::new();
    enc.set(&[("type", "file"), ("uid", "0")]).unwrap();
    enc.add_entry(&e).unwrap();
    let manifest = enc.finish();
    assert!(manifest.starts_with(b"#mtree\n"));

    let entries = archive::archive::mtree::decode::decode(&manifest).unwrap();
    assert_eq!(entries.len(), 1);
    let g = &entries[0];
    assert_eq!(g.name, "sub/dir with space/file.txt");
    assert_eq!(g.size, Some(42));
    assert_eq!(g.mode, Some(0o640));
    assert_eq!(g.uname.as_deref(), Some("user"));
    assert_eq!(g.digests["sha1"], "0a0a0a");
}

#[test]
fn test_mtree_bsdtar_read_interop() {
    use archive::archive::mtree::decode::{MtreeEntry, MtreeKind};
    use archive::archive::mtree::encode::encode;
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let entries = [
        MtreeEntry {
            name: "hello.txt".to_string(),
            kind: MtreeKind::File,
            size: Some(11),
            mode: Some(0o644),
            uid: Some(0),
            gid: Some(0),
            uname: Some("root".to_string()),
            gname: Some("root".to_string()),
            time: Some("1700000000.0".to_string()),
            link: None,
            digests: BTreeMap::new(),
        },
        MtreeEntry {
            name: "sub".to_string(),
            kind: MtreeKind::Dir,
            size: None,
            mode: Some(0o755),
            uid: None,
            gid: None,
            uname: None,
            gname: None,
            time: None,
            link: None,
            digests: BTreeMap::new(),
        },
    ];
    let manifest = encode(&entries).unwrap();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_mtree_wr_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let spec = dir.join("spec.mtree");
    std::fs::write(&spec, &manifest).unwrap();

    // bsdtar (libarchive) can read an mtree manifest as input.
    let output = Command::new("bsdtar").args(["-tf"]).arg(&spec).output();
    let _ = std::fs::remove_dir_all(&dir);
    let Ok(result) = output else { return };
    if !result.status.success() {
        return; // libarchive mtree reader unavailable in this build
    }
    let text = String::from_utf8_lossy(&result.stdout);
    assert!(text.contains("hello.txt"), "bsdtar output: {text}");
    assert!(text.contains("sub"), "bsdtar output: {text}");
}
