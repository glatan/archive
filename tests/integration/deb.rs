use super::*;

// ============================================================
// Debian binary package (.deb) tests
// ============================================================

fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut enc = tar::encode::TarEncoder::new();
    for (name, data) in files {
        enc.add_file(name, data);
    }
    enc.finish()
}

fn make_deb_named(control_name: &str, control: &[u8], data_name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = ar::encode::ArEncoder::new();
    enc.add_file("debian-binary", b"2.0\n");
    enc.add_file(control_name, control);
    enc.add_file(data_name, data);
    enc.finish().unwrap()
}

#[test]
fn test_deb_decode_minimal() {
    let control = make_tar(&[("./control", b"Package: demo\nVersion: 1.0\n")]);
    let data = make_tar(&[("./usr/bin/demo", b"#!/bin/sh\n")]);
    let deb = make_deb_named("control.tar", &control, "data.tar", &data);

    let package = deb::decode::decode(&deb).unwrap();
    assert_eq!(package.version, "2.0");
    assert_eq!(package.members.len(), 3);

    let control_entries = package.control_entries().unwrap();
    assert_eq!(control_entries.len(), 1);
    assert_eq!(control_entries[0].header.name, "./control");

    let data_entries = package.data_entries().unwrap();
    assert_eq!(data_entries.len(), 1);
    assert_eq!(data_entries[0].header.name, "./usr/bin/demo");
    assert_eq!(data_entries[0].data, b"#!/bin/sh\n");
}

#[test]
fn test_deb_decode_compressed_members() {
    use archive::compress::deflate::encode::Level;
    use deb::decode::DebCompression;

    let payload = make_tar(&[("./file", b"compressed payload bytes payload payload")]);
    let cases: Vec<(&str, Vec<u8>, DebCompression)> = vec![
        ("data.tar", payload.clone(), DebCompression::None),
        (
            "data.tar.gz",
            gzip::encode::encode(&payload, Level::Default),
            DebCompression::Gzip,
        ),
        (
            "data.tar.xz",
            xz::encode::encode(&payload),
            DebCompression::Xz,
        ),
        (
            "data.tar.zst",
            zstd::encode::encode(&payload),
            DebCompression::Zstd,
        ),
        (
            "data.tar.bz2",
            bzip2::encode::encode(&payload),
            DebCompression::Bzip2,
        ),
        (
            "data.tar.lzma",
            lzma_alone::encode::encode(&payload),
            DebCompression::Lzma,
        ),
        (
            "data.tar.Z",
            lzw::encode::encode(&payload),
            DebCompression::Lzw,
        ),
    ];

    for (name, member_bytes, expected) in cases {
        let deb = make_deb_named("control.tar", &payload, name, &member_bytes);
        let package =
            deb::decode::decode(&deb).unwrap_or_else(|e| panic!("decode failed for {name}: {e}"));
        let member = package.data_member().unwrap();
        assert_eq!(member.compression, Some(expected), "member {name}");
        let entries = package.data_entries().unwrap();
        assert_eq!(entries[0].data, b"compressed payload bytes payload payload");
    }
}

#[test]
fn test_deb_decode_rejects_invalid_layout() {
    // first member is not debian-binary
    let mut enc = ar::encode::ArEncoder::new();
    enc.add_file("data.tar", b"d");
    enc.add_file("debian-binary", b"2.0\n");
    enc.add_file("control.tar", b"c");
    assert!(deb::decode::decode(&enc.finish().unwrap()).is_err());

    // missing data member
    let mut enc = ar::encode::ArEncoder::new();
    enc.add_file("debian-binary", b"2.0\n");
    enc.add_file("control.tar", b"c");
    assert!(deb::decode::decode(&enc.finish().unwrap()).is_err());
}

#[test]
fn test_deb_decode_system_built_package() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_deb_system_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), b"system deb payload").unwrap();
    std::fs::write(dir.join("debian-binary"), b"2.0\n").unwrap();

    // Build control.tar.gz / data.tar.gz with system tar+gzip and assemble with ar.
    let control = Command::new("tar")
        .current_dir(&dir)
        .args(["-czf", "control.tar.gz", "debian-binary"])
        .output();
    let data = Command::new("tar")
        .current_dir(&dir)
        .args(["-czf", "data.tar.gz", "payload.txt"])
        .output();
    let assembled = Command::new("ar")
        .current_dir(&dir)
        .args([
            "cr",
            "system.deb",
            "debian-binary",
            "control.tar.gz",
            "data.tar.gz",
        ])
        .output();

    if let (Ok(control), Ok(data), Ok(assembled)) = (control, data, assembled) {
        assert!(
            control.status.success() && data.status.success() && assembled.status.success(),
            "system tool failed: {} {} {}",
            String::from_utf8_lossy(&control.stderr),
            String::from_utf8_lossy(&data.stderr),
            String::from_utf8_lossy(&assembled.stderr)
        );
        let deb = std::fs::read(dir.join("system.deb")).unwrap();
        let package = deb::decode::decode(&deb).unwrap();
        assert_eq!(package.version, "2.0");
        assert_eq!(
            package.data_member().unwrap().compression,
            Some(deb::decode::DebCompression::Gzip)
        );
        let entries = package.data_entries().unwrap();
        assert!(
            entries
                .iter()
                .any(|entry| entry.header.name.contains("payload.txt"))
        );
        let payload_entry = entries
            .iter()
            .find(|entry| entry.header.name.contains("payload.txt"))
            .unwrap();
        assert_eq!(payload_entry.data, b"system deb payload");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_deb_crate_built_extracted_by_bsdtar() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_deb_bsdtar_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let data = make_tar(&[("./usr/share/doc/readme", b"bsdtar interop")]);
    let deb = make_deb_named("control.tar", &data, "data.tar", &data);
    let deb_path = dir.join("crate.deb");
    std::fs::write(&deb_path, &deb).unwrap();

    // bsdtar reads the ar container; extracting the data.tar member must
    // yield byte-identical tar bytes.
    let output = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&deb_path)
        .arg("data.tar")
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "bsdtar failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, data);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_deb_encoder_roundtrip() {
    use deb::decode::DebCompression;
    use deb::encode::DebEncoder;

    let mut enc = DebEncoder::new().compression(DebCompression::Gzip);
    enc.add_control_file("./control", b"Package: demo\nVersion: 1.0\nDepends: none\n");
    enc.add_control_file("./conffiles", b"/etc/demo.conf\n");
    enc.add_data_file("./usr/bin/demo", b"#!/bin/sh\necho demo\n");
    enc.add_data_file("./etc/demo.conf", b"key=value\n");
    enc.add_extra_member("_gpgorigin", b"sig");

    let package = deb::decode::decode(&enc.finish().unwrap()).unwrap();
    assert_eq!(package.version, "2.0");
    assert_eq!(package.members.len(), 4);
    assert_eq!(package.members[0].name, "debian-binary");
    assert_eq!(package.members[1].name, "control.tar.gz");
    assert_eq!(package.members[2].name, "data.tar.gz");
    assert_eq!(package.members[3].name, "_gpgorigin");

    let control = package.control_entries().unwrap();
    assert_eq!(control.len(), 2);
    assert!(control[0].header.name.contains("control"));

    let data = package.data_entries().unwrap();
    assert_eq!(data.len(), 2);
    assert!(data.iter().any(|e| e.data == b"key=value\n"));
}

#[test]
fn test_deb_encoder_bsdtar_interop() {
    use deb::decode::DebCompression;
    use deb::encode::DebEncoder;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut enc = DebEncoder::new().data_compression(DebCompression::None);
    enc.add_control_file("./control", b"Package: demo\n");
    enc.add_data_file("./usr/share/doc/readme", b"deb encoder interop");
    let deb = enc.finish().unwrap();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_deb_enc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let deb_path = dir.join("crate.deb");
    std::fs::write(&deb_path, &deb).unwrap();

    // bsdtar extracts data.tar byte-identically.
    let out = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&deb_path)
        .arg("data.tar")
        .output();
    if let Ok(result) = out {
        assert!(
            result.status.success(),
            "bsdtar failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        // The member is an uncompressed tar; re-decode its payload.
        let entries = tar::decode::decode(&result.stdout).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data, b"deb encoder interop");
    }

    // GNU ar lists members in order.
    let out = Command::new("ar").args(["t"]).arg(&deb_path).output();
    if let Ok(result) = out {
        assert!(
            result.status.success(),
            "ar failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = String::from_utf8_lossy(&result.stdout);
        let names: Vec<&str> = text.lines().collect();
        assert_eq!(
            names,
            ["debian-binary", "control.tar", "data.tar"],
            "ar listing: {names:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
