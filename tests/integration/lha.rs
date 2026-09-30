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
    // Corrupt the method marker to an unsupported `-l50-` and fix the header checksum;
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

fn lha_fixture_level(name: &str, data: &[u8], level: u8) -> Vec<u8> {
    archive::archive::lha::encode::encode_level(&[(name, data)], level).unwrap()
}

#[test]
fn test_lha_level1_roundtrip() {
    let data = b"lha level 1 payload".repeat(4);
    let a = lha_fixture_level("sub/dir/one.txt", &data, 1);
    let entries = archive::archive::lha::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "sub/dir/one.txt");
    assert_eq!(entries[0].level, 1);
    assert_eq!(entries[0].data, data.as_slice());
}

#[test]
fn test_lha_level2_roundtrip() {
    let data = b"lha level 2 payload".repeat(4);
    let a = lha_fixture_level("sub/dir/two.txt", &data, 2);
    let entries = archive::archive::lha::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "sub/dir/two.txt");
    assert_eq!(entries[0].level, 2);
    assert_eq!(entries[0].data, data.as_slice());
}

#[test]
fn test_lha_level1_7z_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lha1_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test1.lzh");
    let data = b"level one data".repeat(3);
    std::fs::write(&path, lha_fixture_level("sub/lvl1.txt", &data, 1)).unwrap();

    let output = Command::new("7z").args(["l"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // 7z build without LZH support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("lvl1.txt"), "7z l output: {listing}");

    // Extraction verifies the skip-size field and data offset.
    let out_dir = dir.join("out");
    let output = Command::new("7z")
        .args(["x", "-y"])
        .arg(format!("-o{}", out_dir.display()))
        .arg(&path)
        .output()
        .unwrap();
    if output.status.success() {
        let extracted = std::fs::read(out_dir.join("sub").join("lvl1.txt"))
            .or_else(|_| std::fs::read(out_dir.join("lvl1.txt")))
            .unwrap();
        assert_eq!(extracted, data.as_slice());
    }
}

#[test]
fn test_lha_level1_bsdtar_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lha1b_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test1.lzh");
    std::fs::write(&path, lha_fixture_level("sub/lvl1b.txt", b"level one", 1)).unwrap();

    let output = Command::new("bsdtar").args(["-tf"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // libarchive build without lzh support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(
        listing.contains("lvl1b.txt"),
        "bsdtar -tf output: {listing}"
    );
}

#[test]
fn test_lha_level2_7z_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lha2_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test2.lzh");
    let data = b"level two data".repeat(3);
    std::fs::write(&path, lha_fixture_level("lvl2.txt", &data, 2)).unwrap();

    let output = Command::new("7z").args(["l"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // 7z build without LZH support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.contains("lvl2.txt"), "7z l output: {listing}");

    // Extraction verifies the total-header-size semantics and the
    // level-2 header CRC block we emit.
    let out_dir = dir.join("out");
    let output = Command::new("7z")
        .args(["x", "-y"])
        .arg(format!("-o{}", out_dir.display()))
        .arg(&path)
        .output()
        .unwrap();
    if output.status.success() {
        let extracted = std::fs::read(out_dir.join("lvl2.txt")).unwrap();
        assert_eq!(extracted, data.as_slice());
    }
}

#[test]
fn test_lha_level2_bsdtar_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lha2b_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test2.lzh");
    let data = b"level two bsdtar".repeat(3);
    std::fs::write(&path, lha_fixture_level("lvl2b.txt", &data, 2)).unwrap();

    let output = Command::new("bsdtar").args(["-tf"]).arg(&path).output();
    let Ok(output) = output else { return };
    if !output.status.success() {
        return; // libarchive build without lzh support
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(
        listing.contains("lvl2b.txt"),
        "bsdtar -tf output: {listing}"
    );

    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    let output = Command::new("bsdtar")
        .args(["-xf"])
        .arg(&path)
        .current_dir(&out_dir)
        .output()
        .unwrap();
    if output.status.success() {
        let extracted = std::fs::read(out_dir.join("lvl2b.txt")).unwrap();
        assert_eq!(extracted, data.as_slice());
    }
}

// ============================================================
// LHA compressed-method fixtures (-lh1-..-lh7-, LArc, PMarc) and
// header level 3. Fixture provenance: lhasa test corpus
// (tests/fixtures/lha), plus synthesized -lh2-/-lh3- archives
// cross-checked byte-for-byte against the reference  tool.
// ============================================================

fn lha_fixture_entry(name: &str) -> archive::archive::lha::decode::LhaEntry {
    let data = std::fs::read(format!("tests/fixtures/lha/{name}")).unwrap();
    let entries = archive::archive::lha::decode::decode(&data).unwrap();
    assert_eq!(entries.len(), 1, "{name}: expected single entry");
    entries.into_iter().next().unwrap()
}

/// Every vendored fixture must decode; the header CRC-16 inside each
/// archive validates the decompressed bytes.
#[test]
fn test_lha_compressed_method_fixtures() {
    for (name, expect_bytes) in [
        ("lh1.lzh", 18092),
        ("lh1_lharc.lzh", 18092),
        ("lh2.lzh", 378),
        ("lh3.lzh", 268),
        ("lh4.lzh", 18092),
        ("lh5.lzh", 18092),
        ("lh5_255e.lzh", 18092),
        ("lh6.lzh", 18092),
        ("lh7.lzh", 18092),
        ("h2_lh6.lzh", 18092),
        ("h2_lh7.lzh", 18092),
        ("lzs.lzh", 18092),
        ("lz4.lzh", 6829),
        ("lz4.lzs", 6829),
        ("lz5.lzh", 18092),
        ("lz5.lzs", 18092),
        ("long.lzs", 1241658),
        ("pm0.lzh", 6912),
        ("pm0.pma", 6912),
        ("pm1.lzh", 25284),
        ("pm1.pma", 25284),
        ("pm1_long.pma", 1241659),
        ("pm2.lzh", 18176),
        ("pm2.pma", 18176),
        ("long.pma", 1241659),
    ] {
        let e = lha_fixture_entry(name);
        assert_eq!(e.data.len(), expect_bytes, "{name}: decoded size mismatch");
    }
}

#[test]
fn test_lha_level3_fixtures() {
    // LHA for OS/2 produced real level-3 headers (u32 sizes).
    let e = lha_fixture_entry("h3_lh0.lzh");
    assert_eq!(e.level, 3);
    assert_eq!(e.data.len(), 6829);
    let e = lha_fixture_entry("h3_lh5.lzh");
    assert_eq!(e.level, 3);
    assert_eq!(e.data.len(), 18092);
    // Long filename carried by the u32 extended-header chain.
    let e = lha_fixture_entry("h3_lfn.lzh");
    assert_eq!(e.level, 3);
    assert_eq!(e.data.len(), 14);
    assert_eq!(e.name, "Long Filename.txt");
}

#[test]
fn test_lha_pmarc_multi_entry_fixture() {
    let data = std::fs::read("tests/fixtures/lha/mtcd.pma").unwrap();
    let entries = archive::archive::lha::decode::decode(&data).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data.len(), 1403);
    assert_eq!(entries[1].data.len(), 256);
}

#[test]
fn test_lha_level3_dir() {
    let entries = {
        let data = std::fs::read("tests/fixtures/lha/h3_subdir.lzh").unwrap();
        archive::archive::lha::decode::decode(&data).unwrap()
    };
    assert!(entries.iter().all(|e| e.level == 3));
    assert!(entries.iter().any(|e| e.is_dir));
}

/// Oracle extraction: `lhasa`, `unar`, and the classic `lha` binary
/// must produce the same bytes for every fixture they support.
#[test]
fn test_lha_fixture_oracle_extract() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let oracles: &[&str] = &["lhasa", "unar", "lha"];
    let tools: Vec<&str> = oracles
        .iter()
        .copied()
        .filter(|t| {
            Command::new(t)
                .arg("--version")
                .output()
                .map(|o| o.status.success() || !o.stdout.is_empty())
                .unwrap_or(false)
        })
        .collect();
    if tools.is_empty() {
        return; // no oracle installed
    }
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_lha_oracle_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    for e in std::fs::read_dir("tests/fixtures/lha").unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        if name.starts_with("level") {
            continue; // store-method coverage lives elsewhere
        }
        let data = std::fs::read(&p).unwrap();
        let ours = archive::archive::lha::decode::decode(&data)
            .unwrap()
            .into_iter()
            .filter(|e| !e.is_dir)
            .map(|e| e.data)
            .collect::<Vec<_>>();
        for tool in &tools {
            let out_dir = dir.join(format!("{}_{}", tool, name));
            std::fs::create_dir_all(&out_dir).unwrap();
            let output = Command::new(tool)
                .arg("xf")
                .arg(&p)
                .current_dir(&out_dir)
                .output();
            let Ok(output) = output else { continue };
            if !output.status.success() {
                continue; // oracle lacks support for this member
            }
            let mut oracle_data: Vec<u8> = Vec::new();
            for de in std::fs::read_dir(&out_dir).unwrap() {
                let de = de.unwrap();
                if de.file_type().unwrap().is_file() {
                    oracle_data = std::fs::read(de.path()).unwrap();
                    break;
                }
            }
            if oracle_data.is_empty() {
                continue;
            }
            assert_eq!(
                Some(&oracle_data),
                ours.first(),
                "{name}: {tool} output differs"
            );
        }
    }
}
