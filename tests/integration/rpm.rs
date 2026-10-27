use super::*;

// ============================================================
// RPM package (.rpm) tests
// ============================================================

const HEADER_MAGIC: [u8; 8] = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0];
const LEAD_SIZE: usize = 96;

/// Build one RPM header structure section.
fn build_header(tags: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut index = Vec::new();
    let mut data = Vec::new();
    for &(tag, ty, bytes) in tags {
        // Element count per type: CHAR/INT8/BIN count bytes, INT16/32/64
        // count elements, STRING_ARRAY counts NUL-separated strings,
        // STRING/I18NSTRING hold exactly one.
        let count = match ty {
            1 | 2 | 7 => bytes.len() as u32,
            3 => (bytes.len() / 2) as u32,
            4 => (bytes.len() / 4) as u32,
            5 => (bytes.len() / 8) as u32,
            8 => bytes.iter().filter(|&&b| b == 0).count() as u32,
            _ => 1,
        };
        index.extend_from_slice(&tag.to_be_bytes());
        index.extend_from_slice(&ty.to_be_bytes());
        index.extend_from_slice(&(data.len() as u32).to_be_bytes());
        index.extend_from_slice(&count.to_be_bytes());
        data.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC);
    out.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(&index);
    out.extend_from_slice(&data);
    out
}

/// 16-byte BIN region trailer for the immutable-region tag.
fn region_trailer(tag: u32) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&tag.to_be_bytes());
    t.extend_from_slice(&7u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.extend_from_slice(&16u32.to_be_bytes());
    t
}

/// Minimal .rpm fixture: lead + signature + header + payload bytes.
fn make_rpm(payload: &[u8], compressor: Option<&str>, tags: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut lead = vec![0u8; LEAD_SIZE];
    lead[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    lead[4] = 4;
    let name = b"demo-1.0-1";
    lead[10..10 + name.len()].copy_from_slice(name);
    lead[76..78].copy_from_slice(&1u16.to_be_bytes());
    lead[78..80].copy_from_slice(&5u16.to_be_bytes());

    let mut sig = build_header(&[(62, 7, &region_trailer(62))]);
    while !sig.len().is_multiple_of(8) {
        sig.push(0);
    }

    let trailer = region_trailer(63);
    let mut header_tags = vec![(63, 7, trailer.as_slice()), (1000, 6, b"demo\0".as_slice())];
    if let Some(compressor) = compressor {
        header_tags.push((1125, 6, compressor.as_bytes()));
    }
    header_tags.extend_from_slice(tags);
    // Index entries must be sorted by tag number.
    header_tags.sort_by_key(|(tag, _, _)| *tag);
    let header = build_header(&header_tags);

    let mut rpm = lead;
    rpm.extend_from_slice(&sig);
    rpm.extend_from_slice(&header);
    rpm.extend_from_slice(payload);
    rpm
}

fn make_cpio(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut enc = cpio::encode::CpioEncoder::new();
    for (name, data) in files {
        enc.add_file(name, data);
    }
    enc.finish()
}

#[test]
fn test_rpm_decode_uncompressed_payload() {
    let payload = make_cpio(&[("./usr/bin/demo", b"#!/bin/sh\n")]);
    let rpm = make_rpm(&payload, Some("none\0"), &[]);

    let package = rpm::decode::decode(&rpm).unwrap();
    assert_eq!(package.lead.name, "demo-1.0-1");
    assert_eq!(package.name().unwrap().unwrap(), "demo");
    assert_eq!(
        package.payload_compressor().unwrap(),
        rpm::decode::RpmCompression::None
    );
    let entries = package.payload_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "./usr/bin/demo");
    assert_eq!(entries[0].data, b"#!/bin/sh\n");
}

#[test]
fn test_rpm_decode_gzip_payload() {
    let payload = make_cpio(&[("./usr/share/doc/readme", b"gzip rpm payload")]);
    let compressed = gzip::encode::encode(&payload, deflate::encode::Level::Default);
    let rpm = make_rpm(&compressed, Some("gzip\0"), &[]);

    let package = rpm::decode::decode(&rpm).unwrap();
    assert_eq!(
        package.payload_compressor().unwrap(),
        rpm::decode::RpmCompression::Gzip
    );
    let entries = package.payload_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].data, b"gzip rpm payload");
}

#[test]
fn test_rpm_decode_xz_and_zstd_payloads() {
    let payload = make_cpio(&[("./x", b"data")]);

    let compressed = xz::encode::encode(&payload);
    let rpm = make_rpm(&compressed, Some("xz\0"), &[]);
    let entries = rpm::decode::decode(&rpm)
        .unwrap()
        .payload_entries()
        .unwrap();
    assert_eq!(entries[0].data, b"data");

    let compressed = zstd::encode::encode(&payload);
    let rpm = make_rpm(&compressed, Some("zstd\0"), &[]);
    let entries = rpm::decode::decode(&rpm)
        .unwrap()
        .payload_entries()
        .unwrap();
    assert_eq!(entries[0].data, b"data");
}

#[test]
fn test_rpm_decode_stripped_payload() {
    // v6-style stripped cpio: 07070X + 8-hex file index, sizes from
    // LONGFILESIZES tag.
    let mut payload = Vec::new();
    payload.extend_from_slice(b"07070X");
    payload.extend_from_slice(b"00000000");
    payload.extend_from_slice(&[0; 2]);
    payload.extend_from_slice(b"AAAA");
    payload.extend_from_slice(b"07070X");
    payload.extend_from_slice(b"ffffffff");

    let mut sizes = Vec::new();
    sizes.extend_from_slice(&4i64.to_be_bytes());
    let rpm = make_rpm(
        &payload,
        Some("none\0"),
        &[
            (1117, 8, b"file.bin\0".as_slice()), // RPMTAG_BASENAMES
            (5008, 5, &sizes),                   // RPMTAG_LONGFILESIZES
        ],
    );

    let package = rpm::decode::decode(&rpm).unwrap();
    let entries = package.payload_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_index, Some(0));
    assert_eq!(entries[0].name, "file.bin");
    assert_eq!(entries[0].data, b"AAAA");
}

#[test]
fn test_rpm_decode_system_compressed_payload() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    if !command_available("cpio", &["--version"]) {
        return;
    }

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rpm_system_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("file.txt"), b"system rpm payload").unwrap();

    // Payload cpio built by system cpio, compressed by system gzip.
    let cpio_out = Command::new("sh")
        .current_dir(&dir)
        .args(["-c", "echo file.txt | cpio -o -H newc > payload.cpio"])
        .output();
    let gzip_out = Command::new("gzip")
        .current_dir(&dir)
        .args(["-kf", "payload.cpio"])
        .output();

    if let (Ok(cpio_out), Ok(gzip_out)) = (cpio_out, gzip_out) {
        assert!(
            cpio_out.status.success() && gzip_out.status.success(),
            "system tool failed: {} {}",
            String::from_utf8_lossy(&cpio_out.stderr),
            String::from_utf8_lossy(&gzip_out.stderr)
        );
        let payload = std::fs::read(dir.join("payload.cpio.gz")).unwrap();
        let rpm = make_rpm(&payload, Some("gzip\0"), &[]);
        let entries = rpm::decode::decode(&rpm)
            .unwrap()
            .payload_entries()
            .unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.name.contains("file.txt"))
            .expect("system cpio payload entry");
        assert_eq!(entry.data, b"system rpm payload");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_rpm_crate_built_read_by_bsdtar() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rpm_bsdtar_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let payload = make_cpio(&[("./pkg.txt", b"bsdtar rpm interop")]);
    let compressed = gzip::encode::encode(&payload, deflate::encode::Level::Default);
    let rpm = make_rpm(&compressed, Some("gzip\0"), &[]);
    let rpm_path = dir.join("crate.rpm");
    std::fs::write(&rpm_path, &rpm).unwrap();

    // bsdtar (libarchive) reads .rpm directly; extracting the payload member
    // must yield the original file content.
    let output = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&rpm_path)
        .output();

    if let Ok(result) = output {
        assert!(
            result.status.success(),
            "bsdtar failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result
                .stdout
                .windows(b"bsdtar rpm interop".len())
                .any(|w| w == b"bsdtar rpm interop"),
            "bsdtar output missing payload"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================
// RPM encode tests
// ============================================================

#[test]
fn test_rpm_encode_decode_roundtrip() {
    use archive::archive::rpm::decode::{RpmCompression, decode};
    use archive::archive::rpm::encode::{RpmEncoder, RpmTagValue};

    let mut enc = RpmEncoder::new()
        .lead_name("demo-1.0-1")
        .unwrap()
        .name("demo")
        .version("1.0")
        .release("1")
        .arch("x86_64")
        .header_tag(1028, RpmTagValue::Int32(vec![12, 34]))
        .unwrap()
        .header_tag(
            1117,
            RpmTagValue::StrArray(vec!["demo".into(), "readme.txt".into()]),
        )
        .unwrap()
        .header_tag(
            1118,
            RpmTagValue::StrArray(vec!["./usr/bin".into(), "./etc".into()]),
        )
        .unwrap();
    enc.add_file("./usr/bin/demo", b"#!/bin/sh\nexit 0\n");
    enc.add_file("./etc/readme.txt", b"read me\n");
    let bytes = enc.finish().unwrap();

    // Lead structure.
    assert_eq!(&bytes[..4], &[0xed, 0xab, 0xee, 0xdb]);
    assert_eq!(bytes[4], 4);

    let pkg = decode(&bytes).unwrap();
    assert_eq!(pkg.lead.name, "demo-1.0-1");
    assert_eq!(pkg.name().unwrap().unwrap(), "demo");
    assert_eq!(pkg.arch().unwrap().unwrap(), "x86_64");
    assert_eq!(pkg.payload_compressor().unwrap(), RpmCompression::Gzip);
    assert_eq!(pkg.header.get_i32s(1028).unwrap().unwrap(), vec![12, 34]);

    let entries = pkg.payload_entries().unwrap();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["./etc/readme.txt", "./usr/bin/demo"]);
}

#[test]
fn test_rpm_encode_uncompressed_roundtrip() {
    use archive::archive::rpm::decode::{RpmCompression, decode};
    use archive::archive::rpm::encode::RpmEncoder;

    let mut enc = RpmEncoder::new().compression(RpmCompression::None);
    enc.add_file("./plain.txt", b"no compression");
    let pkg = decode(&enc.finish().unwrap()).unwrap();
    assert_eq!(pkg.payload_compressor().unwrap(), RpmCompression::None);
    let entries = pkg.payload_entries().unwrap();
    assert_eq!(entries[0].data, b"no compression");
}

#[test]
fn test_rpm_encode_read_by_bsdtar() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use archive::archive::rpm::encode::RpmEncoder;

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rpm_enc_bsdtar_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();

    let mut enc = RpmEncoder::new()
        .lead_name("crate-1.0-1")
        .unwrap()
        .name("crate");
    enc.add_file("./pkg.txt", b"bsdtar rpm encoder interop");
    let rpm_path = dir.join("crate.rpm");
    std::fs::write(&rpm_path, enc.finish().unwrap()).unwrap();

    if let Ok(result) = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&rpm_path)
        .output()
    {
        assert!(
            result.status.success(),
            "bsdtar failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            result
                .stdout
                .windows(b"bsdtar rpm encoder interop".len())
                .any(|w| w == b"bsdtar rpm encoder interop"),
            "bsdtar output missing payload"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A stripped (`07070X`) payload package built by the crate decodes
/// back through `payload_entries` and is accepted by bsdtar when it
/// understands the stripped cpio variant.
#[test]
fn test_rpm_stripped_encoder_roundtrip_and_bsdtar() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut enc = rpm::encode::RpmEncoder::new()
        .lead_name("stripdemo-2.0-1")
        .unwrap()
        .name("stripdemo")
        .version("2.0")
        .release("1")
        .stripped_payload();
    enc.add_file("usr/bin/stripdemo", b"#!/bin/sh\necho stripped\n");
    enc.add_file("usr/share/doc/readme", b"stripped payload readme");
    let bytes = enc.finish().unwrap();

    let pkg = rpm::decode::decode(&bytes).unwrap();
    let entries = pkg.payload_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "usr/bin/stripdemo");
    assert_eq!(entries[0].file_index, Some(0));
    assert_eq!(entries[1].name, "usr/share/doc/readme");

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rpm_stripped_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let rpm_path = dir.join("stripped.rpm");
    std::fs::write(&rpm_path, &bytes).unwrap();

    let output = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&rpm_path)
        .output();
    // bsdtar without stripped-cpio support simply fails; that is
    // tolerated (decoder roundtrip above is the oracle).
    if let Ok(result) = output
        && result.status.success()
    {
        assert!(
            result
                .stdout
                .windows(b"echo stripped".len())
                .any(|w| w == b"echo stripped"),
            "bsdtar output missing stripped payload: {}",
            String::from_utf8_lossy(&result.stdout)
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// A v6 package built by `RpmEncoder::v6` carries the required tag
/// set, verifies through `verify_digests`, and is handed to the
/// system `rpm`/`bsdtar` tools when available (graceful skip).
#[test]
fn test_rpm_v6_encoder_roundtrip_and_system_oracle() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut enc = rpm::encode::RpmEncoder::new()
        .lead_name("v6demo-1.0-1")
        .unwrap()
        .name("v6demo")
        .version("1.0")
        .release("1")
        .v6()
        .mime_types(&["text/plain", "application/octet-stream"]);
    enc.add_file("usr/bin/v6demo", b"#!/bin/sh\necho v6\n");
    enc.add_file("usr/share/doc/v6demo/readme", b"v6 required tags");
    enc.add_file("etc/v6demo.conf", b"opt=1\n");
    let bytes = enc.finish().unwrap();

    let pkg = rpm::decode::decode(&bytes).unwrap();
    // v6 identity and required Header tags (format_v6.html).
    assert_eq!(pkg.lead.major, 4);
    assert_eq!(pkg.header.get_i32s(5114).unwrap().unwrap(), [6]); // RPMFORMAT
    assert_eq!(pkg.header.get_string(5062).unwrap().unwrap(), "utf-8"); // ENCODING
    assert_eq!(pkg.header.get_i32s(5011).unwrap().unwrap(), [8]); // FILEDIGESTALGO SHA-256
    assert_eq!(
        pkg.header.get_strings(1035).unwrap().unwrap().len(),
        3 // FILEDIGESTS, one per file
    );
    assert!(pkg.header.find(5092).is_some()); // PAYLOADSHA256
    assert!(pkg.header.find(5097).is_some()); // PAYLOADSHA256ALT
    assert!(pkg.header.find(5121).is_some()); // PAYLOADSHA512
    assert!(pkg.header.find(5122).is_some()); // PAYLOADSHA512ALT
    assert!(pkg.header.find(5112).is_some()); // PAYLOADSIZE
    assert!(pkg.header.find(5113).is_some()); // PAYLOADSIZEALT
    assert_eq!(
        pkg.header.get_strings(5116).unwrap().unwrap(),
        ["text/plain", "application/octet-stream"] // MIMEDICT
    );
    assert_eq!(
        pkg.header.get_i32s(5115).unwrap().unwrap(),
        [0, 1, 1] // FILEMIMEINDEX
    );
    // Signature: region 62 + SHA256 (272) + zeroed RESERVED (999) last.
    let sig_tags: Vec<u32> = pkg.signature.entries.iter().map(|e| e.tag).collect();
    assert_eq!(sig_tags, [62, 272, 999]);
    assert!(
        pkg.signature
            .get_bin(999)
            .unwrap()
            .unwrap()
            .iter()
            .all(|&b| b == 0)
    );
    let checks = pkg.verify_digests().unwrap();
    assert!(!checks.is_empty());
    assert!(checks.iter().all(|c| c.matches()), "{checks:?}");

    let entries = pkg.payload_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].name, "usr/share/doc/v6demo/readme");
    assert_eq!(entries[1].data, b"v6 required tags");

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rpm_v6_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let rpm_path = dir.join("v6demo.rpm");
    std::fs::write(&rpm_path, &bytes).unwrap();

    // bsdtar (libarchive) extraction oracle; versions without
    // stripped-cpio support may fail — tolerated.
    if let Ok(result) = Command::new("bsdtar")
        .args(["-xOf"])
        .arg(&rpm_path)
        .output()
        && result.status.success()
    {
        assert!(
            result
                .stdout
                .windows(b"v6 required tags".len())
                .any(|w| w == b"v6 required tags"),
            "bsdtar output missing v6 payload: {}",
            String::from_utf8_lossy(&result.stdout)
        );
    }
    // system rpm(8) query oracle; v6 support depends on the installed
    // version — any outcome (including non-zero exit) is tolerated.
    let _ = Command::new("rpm").args(["-qip"]).arg(&rpm_path).output();

    std::fs::remove_dir_all(&dir).ok();
}
