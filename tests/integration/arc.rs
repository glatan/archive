// ============================================================
// SEA ARC container tests (methods 1-0x0b)
// ============================================================

use super::require_external_tools;

fn arc_fixture(name: &str, data: &[u8]) -> Vec<u8> {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file(name, data, 0, 0).unwrap();
    enc.finish()
}

#[test]
fn test_arc_encode_decode_roundtrip() {
    let data = b"hello arc world".repeat(8);
    let a = arc_fixture("HELLO.TXT", &data);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "HELLO.TXT");
    assert_eq!(entries[0].data, data.as_slice());
    assert_eq!(entries[0].method, 2);
    assert!(entries[0].crc16.is_some());
}

#[test]
fn test_arc_multi_entry_roundtrip() {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file("A.BIN", &[5, 6, 7], 0, 0).unwrap();
    enc.add_file("TOP.TXT", b"top", 0, 0).unwrap();
    let entries = archive::archive::arc::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "A.BIN");
    assert_eq!(entries[1].data, b"top");
}

#[test]
fn test_arc_rejects_truncated() {
    let a = arc_fixture("F.TXT", b"payload");
    assert!(archive::archive::arc::decode::decode(&a[..10]).is_err());
    assert!(archive::archive::arc::decode::decode(&a[..a.len() - 3]).is_err());
}

#[test]
fn test_arc_rejects_compressed_method() {
    // Methods 12-19 (ARC 6.0/7.0, unpublished) and 40+ (reserved)
    // remain out of scope and refused; 20-39 items are skipped.
    for m in [0x0cu8, 0x0d, 19, 40, 0x7e, 0xFF] {
        let mut a = Vec::new();
        a.extend_from_slice(&[0x1a, m]);
        a.extend_from_slice(&[0u8; 17]); // name + size
        a.extend_from_slice(&[0x1a, 0]);
        let err = archive::archive::arc::decode::decode(&a).unwrap_err();
        assert!(matches!(err, archive::error::Error::Unsupported(_)));
    }
}

/// Build an ARC 6.0+ informational/control item (methods 20-39),
/// which uses the regular member header layout.
fn arc_info_item(method: u8, payload: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, method]);
    a.extend_from_slice(&[0u8; 13]); // name (ignored)
    a.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    a.extend_from_slice(&[0u8; 10]); // date/time/crc16/orig size
    a.extend_from_slice(payload);
    a
}

#[test]
fn test_arc_skips_info_control_items() {
    // ARC 6.0+ informational/control items (methods 20-39) mixed
    // with file members are skipped and never listed.
    let mut a = Vec::new();
    a.extend_from_slice(&arc_info_item(20, b"archive description"));
    let stored = arc_fixture("REAL.TXT", b"payload");
    a.extend_from_slice(&stored[..stored.len() - 2]); // strip terminator
    a.extend_from_slice(&arc_info_item(30, b"subdir marker"));
    a.extend_from_slice(&arc_info_item(39, &[0xAA; 5]));
    a.extend_from_slice(&[0x1a, 0]);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "REAL.TXT");
    assert_eq!(entries[0].data, b"payload");

    // A truncated item header is still an error.
    let mut a = arc_info_item(20, b"abc");
    a.truncate(2 + 13 + 4);
    assert!(archive::archive::arc::decode::decode(&a).is_err());
}

/// CRC-16/ARC (poly 0x8005, reflected, init 0x0000, xorout 0) — the
/// member CRC used by ARC methods >= 2, computed over the
/// uncompressed data.
fn arc_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// Build a method-3 member record from raw packed bytes.
fn arc_method3_fixture(name: &str, orig_size: u32, crc: u16, packed: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, 3]);
    let mut field = [0u8; 13];
    field[..name.len()].copy_from_slice(name.as_bytes());
    a.extend_from_slice(&field);
    a.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    a.extend_from_slice(&0x1234u16.to_le_bytes()); // date
    a.extend_from_slice(&0x5678u16.to_le_bytes()); // time
    a.extend_from_slice(&crc.to_le_bytes());
    a.extend_from_slice(&orig_size.to_le_bytes());
    a.extend_from_slice(packed);
    a.extend_from_slice(&[0x1a, 0]);
    a
}

#[test]
fn test_arc_method3_encode_decode_roundtrip() {
    // Runs, a literal 0x90 byte and plain literals mixed.
    let mut data = Vec::new();
    data.extend_from_slice(b"aaabbbbbbbbbbbbbbbbb");
    data.push(0x90);
    data.extend_from_slice(&[0x00; 300]);
    data.extend_from_slice(b"tail");
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file_with_method("RLE.BIN", &data, 0x21, 0x42, 3)
        .unwrap();
    let entries = archive::archive::arc::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "RLE.BIN");
    assert_eq!(entries[0].method, 3);
    assert_eq!(entries[0].data, data);
    assert!(entries[0].crc16.is_some());
}

#[test]
fn test_arc_method3_member() {
    // Hand-built method-3 (packed) member.
    // original: a a a b 0x90 c c          (7 bytes)
    // packed:   'a' 0x90 03 'b' 0x90 00 'c' 0x90 02
    let orig = [b'a', b'a', b'a', b'b', 0x90, b'c', b'c'];
    let packed = [b'a', 0x90, 0x03, b'b', 0x90, 0x00, b'c', 0x90, 0x02];
    let crc = arc_crc16(&orig);
    let a = arc_method3_fixture("R3.BIN", orig.len() as u32, crc, &packed);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].name, "R3.BIN");
    assert_eq!(entries[0].method, 3);
    assert_eq!(entries[0].data, orig);
    assert_eq!(entries[0].date, 0x1234);
    assert_eq!(entries[0].crc16, Some(crc));
}

#[test]
fn test_arc_method3_rejects_bad_crc() {
    // Packed 'a' 0x90 0x08 expands to 8 bytes; corrupting the leading
    // literal keeps the size but breaks the CRC-16.
    let a = arc_method3_fixture("F", 8, 0, &[b'b', 0x90, 0x08]);
    assert!(archive::archive::arc::decode::decode(&a).is_err());
}

#[test]
fn test_arc_method3_rejects_malformed_rle() {
    // Dangling marker at end of the packed stream.
    let a = arc_method3_fixture("F", 10, 0, &[b'a', 0x90]);
    assert!(archive::archive::arc::decode::decode(&a).is_err());
    // Run count with no preceding literal byte.
    let a = arc_method3_fixture("F", 5, 0, &[0x90, 0x05]);
    assert!(archive::archive::arc::decode::decode(&a).is_err());
    // Expansion does not match the declared uncompressed size.
    let a = arc_method3_fixture("F", 10, 0, &[b'a', 0x90, 0x04]);
    assert!(archive::archive::arc::decode::decode(&a).is_err());
}

#[test]
fn test_arc_method1_encode_decode_roundtrip() {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file_with_method("OLD.TXT", b"obsolete", 0, 0, 1)
        .unwrap();
    enc.add_file("NEW.TXT", b"stored", 0, 0).unwrap();
    let entries = archive::archive::arc::decode::decode(&enc.finish()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "OLD.TXT");
    assert_eq!(entries[0].method, 1);
    assert!(entries[0].crc16.is_some());
    assert_eq!(entries[0].data, b"obsolete");
    assert_eq!(entries[1].method, 2);
    assert!(entries[1].crc16.is_some());
}

#[test]
fn test_arc_method1_header_layout() {
    // Method-1 record: marker + method=1 + name[13] + size u32le +
    // date + time + crc16 + data. Only the original-length field of
    // the regular header is absent (25-byte header).
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file_with_method("F.B", b"xyz", 0x1234, 0x5678, 1)
        .unwrap();
    let a = enc.finish();
    assert_eq!(a[0], 0x1a);
    assert_eq!(a[1], 1);
    let mut name = [0u8; 13];
    name[..3].copy_from_slice(b"F.B");
    assert_eq!(&a[2..15], &name);
    assert_eq!(&a[15..19], &3u32.to_le_bytes());
    assert_eq!(&a[19..21], &0x1234u16.to_le_bytes());
    assert_eq!(&a[21..23], &0x5678u16.to_le_bytes());
    assert_eq!(&a[23..25], &arc_crc16(b"xyz").to_le_bytes());
    assert_eq!(&a[25..28], b"xyz");
    assert_eq!(&a[28..], &[0x1a, 0]);
    assert_eq!(a.len(), 30);
}

#[test]
fn test_arc_rejects_unsupported_encode_method() {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    for method in [0x0cu8, 0x0d] {
        let err = enc
            .add_file_with_method("F.TXT", b"x", 0, 0, method)
            .unwrap_err();
        assert!(matches!(err, archive::error::Error::Unsupported(_)));
    }
}

#[test]
fn test_arc_method1_member() {
    // Obsolete unpacked member: name[13] + size + date + time +
    // crc16 + raw data (the regular header minus the original-length
    // field).
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, 1]);
    let mut name = [0u8; 13];
    name[..7].copy_from_slice(b"OLD.TXT");
    a.extend_from_slice(&name);
    a.extend_from_slice(&4u32.to_le_bytes());
    a.extend_from_slice(&0x1234u16.to_le_bytes());
    a.extend_from_slice(&0x5678u16.to_le_bytes());
    a.extend_from_slice(&arc_crc16(b"data").to_le_bytes());
    a.extend_from_slice(b"data");
    a.extend_from_slice(&[0x1a, 0]);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].name, "OLD.TXT");
    assert_eq!(entries[0].data, b"data");
    assert_eq!(entries[0].date, 0x1234);
    assert_eq!(entries[0].crc16, Some(arc_crc16(b"data")));
}

#[test]
fn test_arc_method1_rejects_bad_crc() {
    // Method-1 members carry a CRC-16 and a corrupt payload is
    // rejected through the same check as the other methods.
    let mut a = arc_fixture_with_method(1, b"xyz");
    let n = a.len();
    a[n - 3] ^= 0xff;
    assert!(archive::archive::arc::decode::decode(&a).is_err());
    // A header cut short inside the date/time/crc16 fields.
    assert!(archive::archive::arc::decode::decode(&a[..2 + 13 + 4 + 4]).is_err());
}

#[test]
fn test_arc_rejects_bad_name() {
    // Names containing path separators and non-UTF-8 names are
    // refused by the decoder.
    for name in [
        &b"../ETC"[..],
        &[b'A', 0x5c, b'B', b'.', b'C'][..],
        &[0xff, 0xfe][..],
    ] {
        let mut a = Vec::new();
        a.extend_from_slice(&[0x1a, 2]);
        let mut field = [0u8; 13];
        field[..name.len()].copy_from_slice(name);
        a.extend_from_slice(&field);
        a.extend_from_slice(&[0u8; 4 + 10]); // size + date/time/crc16/orig
        a.extend_from_slice(&[0x1a, 0]);
        assert!(archive::archive::arc::decode::decode(&a).is_err());
    }
}

// ============================================================
// ARC methods 4/8/9 (squeezed/crunched/squashed)
// ============================================================

#[test]
fn test_arc_decode_crunched_fixture() {
    // fix8.arc was produced by Debian  5.21q (): rnd.bin
    // is stored (method 2), text.txt is crunched (method 8).
    let archive = include_bytes!("../fixtures/arc/fix8.arc");
    let text = include_bytes!("../fixtures/arc/text.txt");
    let rnd = include_bytes!("../fixtures/arc/rnd.bin");
    let entries = archive::archive::arc::decode::decode(archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "rnd.bin");
    assert_eq!(entries[0].method, 2);
    assert_eq!(entries[0].data, rnd.as_slice());
    assert_eq!(entries[1].name, "text.txt");
    assert_eq!(entries[1].method, 8);
    assert_eq!(entries[1].data, text.as_slice());
}

#[test]
fn test_arc_decode_squashed_fixture() {
    // fix9.arc was produced by Debian  5.21q (): the same
    // members but text.txt is squashed (method 9).
    let archive = include_bytes!("../fixtures/arc/fix9.arc");
    let text = include_bytes!("../fixtures/arc/text.txt");
    let rnd = include_bytes!("../fixtures/arc/rnd.bin");
    let entries = archive::archive::arc::decode::decode(archive).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "rnd.bin");
    assert_eq!(entries[0].data, rnd.as_slice());
    assert_eq!(entries[1].name, "text.txt");
    assert_eq!(entries[1].method, 9);
    assert_eq!(entries[1].data, text.as_slice());
}

#[test]
fn test_arc_compressed_encode_decode_roundtrip() {
    let data = b"the quick brown fox jumps over the lazy dog. ".repeat(40);
    for method in [4u8, 5, 6, 7, 8, 9, 0x0a, 0x0b] {
        let mut enc = archive::archive::arc::encode::ArcEncoder::new();
        enc.add_file_with_method("A.TXT", &data, 0, 0, method)
            .unwrap();
        enc.add_file("B.BIN", &[0u8, 1, 2, 3], 0, 0).unwrap();
        let entries = archive::archive::arc::decode::decode(&enc.finish()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].method, method, "method {method}");
        assert_eq!(entries[0].data, data.as_slice(), "method {method}");
        assert_eq!(entries[1].method, 2);
        assert_eq!(entries[1].data, &[0u8, 1, 2, 3]);
    }
}

/// Build an in-memory ARC with one member using the given method.
fn arc_fixture_with_method(method: u8, data: &[u8]) -> Vec<u8> {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    enc.add_file_with_method("PAYLD.TXT", data, 0, 0, method)
        .unwrap();
    enc.finish()
}

#[test]
fn test_arc_method5_6_7_edge_roundtrip() {
    // Empty member, single byte, and a long run (RLE90 stage for 6/7).
    for method in [5u8, 6, 7, 0x0a, 0x0b] {
        for data in [&b""[..], &b"x"[..], &[0u8; 600][..]] {
            let a = arc_fixture_with_method(method, data);
            let entries = archive::archive::arc::decode::decode(&a).unwrap();
            assert_eq!(entries[0].method, method);
            assert_eq!(entries[0].data, data, "method {method}");
        }
    }
}

#[test]
fn test_arc_method0a_encode_roundtrip() {
    // Crushed: adaptive LZW + RLE90. Exercise the literal-bit switch
    // (dense strings) and the eviction sweep (table overflow).
    let mut big = b"abcdefghij".repeat(4000).to_vec();
    big.extend((0..50000usize).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
    let a = arc_fixture_with_method(0x0a, &big);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].method, 0x0a);
    assert_eq!(entries[0].data, big);
}

#[test]
fn test_arc_encode_extracted_by_oracle() {
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    // Extract our encoded archives with every independent decoder
    // available in the test image: ,  and .
    let mut oracles: Vec<String> = Vec::new();
    for name in ["arc", "nomarch", "unar"] {
        if Command::new(name).arg("--version").output().is_ok()
            || Command::new(name).arg("-h").output().is_ok()
            || Command::new(name).output().is_ok()
        {
            oracles.push(name.to_string());
        }
    }
    if oracles.is_empty() {
        eprintln!("no arc oracle (arc/nomarch/unar) installed; skipped");
        return;
    }

    let data = b"oracle extraction payload payload payload ".repeat(64);
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // Per-method oracle support: all three decoders read the
    // obsolete unpacked (method-1) header. nomarch never implemented
    // the method-7 hash variant (development-only), so 5/6 are
    // checked against arc+nomarch and 7 against arc alone. Method
    // 0x0a (crushed) is only understood by unar.
    let cases: &[(u8, &[&str])] = &[
        (1, &["arc", "nomarch", "unar"]),
        (4, &["arc", "nomarch", "unar"]),
        (5, &["arc", "nomarch"]),
        (6, &["arc", "nomarch"]),
        (7, &["arc"]),
        (8, &["arc", "nomarch", "unar"]),
        (9, &["arc", "nomarch", "unar"]),
        (0x0a, &["unar"]),
    ];
    for &(method, tools) in cases {
        let archive = arc_fixture_with_method(method, &data);
        for oracle in &oracles {
            if !tools.contains(&oracle.as_str()) {
                continue;
            }
            let dir =
                std::env::temp_dir().join(format!("archive_arc_oracle_{uniq}_{oracle}_{method}"));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("m{method}.arc"));
            std::fs::write(&path, &archive).unwrap();
            let out_dir = dir.join("out");
            std::fs::create_dir_all(&out_dir).unwrap();

            let extracted = match oracle.as_str() {
                //  extracts to the cwd with the member's case
                // preserved;  lowercases by default (use -U).
                "arc" => {
                    let status = Command::new("arc")
                        .arg("x")
                        .arg(&path)
                        .current_dir(&out_dir)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap();
                    status.success()
                        && std::fs::read(out_dir.join("PAYLD.TXT"))
                            .map(|d| d == data)
                            .unwrap_or(false)
                }
                "nomarch" => {
                    let output = Command::new("nomarch")
                        .args(["-U", "-p"])
                        .arg(&path)
                        .output()
                        .unwrap();
                    output.status.success() && output.stdout == data
                }
                "unar" => {
                    let status = Command::new("unar")
                        .arg("-o")
                        .arg(&out_dir)
                        .arg(&path)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .unwrap();
                    status.success()
                        && std::fs::read(out_dir.join(format!("m{method}")).join("PAYLD.TXT"))
                            .or_else(|_| std::fs::read(out_dir.join("PAYLD.TXT")))
                            .map(|d| d == data)
                            .unwrap_or(false)
                }
                _ => unreachable!(),
            };
            assert!(extracted, "{oracle} extraction failed for method {method}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

// ============================================================
// ARC methods 5-7/0x0a/0x0b (crunched-hash/crushed/distilled) decode
// ============================================================

/// Build a single-member ARC archive around a pre-compressed payload.
fn arc_packed_fixture(method: u8, orig: &[u8], packed: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, method]);
    let mut name = [0u8; 13];
    name[..5].copy_from_slice(b"F.BIN");
    a.extend_from_slice(&name);
    a.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    a.extend_from_slice(&[0u8; 4]); // date/time
    a.extend_from_slice(&arc_crc16(orig).to_le_bytes());
    a.extend_from_slice(&(orig.len() as u32).to_le_bytes());
    a.extend_from_slice(packed);
    a.extend_from_slice(&[0x1a, 0]);
    a
}

#[test]
fn test_arc_method5_6_7_decode() {
    // Hash-LZW vectors shared with independent decoders.
    let quadratic = [0x0a, 0x5d, 0x1f, 0x0a, 0x50];
    let quadratic2 = [
        0x93, 0x88, 0x90, 0xbf, 0x93, 0xd5, 0x89, 0x07, 0xcf, 0x07, 0x52, 0x3e, 0x23, 0xe0,
    ];
    let multiplicative = [0x84, 0x03, 0x61, 0x84, 0x00];
    for (method, orig, packed) in [
        (5u8, &b"AAAA"[..], &quadratic[..]),
        (6, b"AAAA", &quadratic),
        (6, b"banana banana", &quadratic2),
        (7, b"AAAA", &multiplicative),
    ] {
        let a = arc_packed_fixture(method, orig, packed);
        let entries = archive::archive::arc::decode::decode(&a).unwrap();
        assert_eq!(entries[0].method, method);
        assert_eq!(entries[0].data, orig, "method {method}");
    }
}

#[test]
fn test_arc_method0a_decode() {
    // Adaptive-LZW (crushed) vectors.
    let v1 = [0x82, 0x04, 0x1d];
    let v2 = [0xc4, 0x84, 0x71, 0xab, 0x30, 0x20, 0x73, 0x17, 0x00];
    for (orig, packed) in [(&b"AAAA"[..], &v1[..]), (b"banana banana", &v2)] {
        let a = arc_packed_fixture(0x0a, orig, packed);
        let entries = archive::archive::arc::decode::decode(&a).unwrap();
        assert_eq!(entries[0].method, 0x0a);
        assert_eq!(entries[0].data, orig);
    }
}

#[test]
fn test_arc_method0b_decode() {
    // Distilled member: header Huffman tree (nodes [78+6,256+6,65+6,0,
    // 66+6,2]) over {B,A,N,EOF}; "BANANA" + end. Verified byte-identical
    // against the XADMaster reference decoder.
    let packed = [
        0x06, 0x00, 0x09, 0x54, 0x0c, 0x1e, 0x01, 0x80, 0x44, 0x80, 0xd6, 0x3a,
    ];
    let a = arc_packed_fixture(0x0b, b"BANANA", &packed);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].method, 0x0b);
    assert_eq!(entries[0].data, b"BANANA");
}

#[test]
fn test_arc_packed_oracle_crosscheck() {
    use std::process::Command;

    // Independent decoders extract the same packed members we decode.
    // arc handles methods 5-7, nomarch 5-6, unar
    // 0x0a. No packaged decoder covers 0x0b.
    const QUADRATIC: &[u8] = &[0x0a, 0x5d, 0x1f, 0x0a, 0x50];
    const MULTIPLICATIVE: &[u8] = &[0x84, 0x03, 0x61, 0x84, 0x00];
    const CRUSHED: &[u8] = &[0x82, 0x04, 0x1d];
    type Case = (u8, &'static [u8], &'static [u8], &'static [&'static str]);
    let cases: &[Case] = &[
        (5, b"AAAA", QUADRATIC, &["arc", "nomarch"]),
        (6, b"AAAA", QUADRATIC, &["arc", "nomarch"]),
        (7, b"AAAA", MULTIPLICATIVE, &["arc"]),
        (0x0a, b"AAAA", CRUSHED, &["unar"]),
    ];

    let mut ran = 0;
    for &(method, orig, packed, tools) in cases {
        let a = arc_packed_fixture(method, orig, packed);
        for &tool in tools {
            if Command::new(tool).output().is_err() {
                continue;
            }
            let dir = std::env::temp_dir().join(format!(
                "archive_arc_packed_{}_{}_{}",
                std::process::id(),
                tool,
                method
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("m.arc");
            std::fs::write(&path, &a).unwrap();
            let out_dir = dir.join("out");
            std::fs::create_dir_all(&out_dir).unwrap();
            let ok = match tool {
                "nomarch" => {
                    let o = Command::new("nomarch")
                        .args(["-U", "-p"])
                        .arg(&path)
                        .output()
                        .unwrap();
                    o.status.success() && o.stdout == orig
                }
                "arc" => {
                    let st = Command::new("arc")
                        .arg("x")
                        .arg(&path)
                        .current_dir(&out_dir)
                        .output()
                        .unwrap();
                    st.status.success()
                        && std::fs::read(out_dir.join("F.BIN"))
                            .map(|d| d == orig)
                            .unwrap_or(false)
                }
                "unar" => {
                    let st = Command::new("unar")
                        .arg("-o")
                        .arg(&out_dir)
                        .arg(&path)
                        .output()
                        .unwrap();
                    st.status.success()
                        && std::fs::read(out_dir.join("m").join("F.BIN"))
                            .or_else(|_| std::fs::read(out_dir.join("F.BIN")))
                            .map(|d| d == orig)
                            .unwrap_or(false)
                }
                _ => unreachable!(),
            };
            ran += 1;
            let _ = std::fs::remove_dir_all(&dir);
            assert!(ok, "{tool} failed on method {method:#04x}");
        }
    }
    if ran == 0 {
        assert!(
            !require_external_tools(),
            "no ARC oracle installed (arc/nomarch/unar)"
        );
        eprintln!("no arc oracle installed; skipped");
    }
}

#[test]
fn test_arc_method0b_encode_roundtrip() {
    // Distilled: LZSS + header-serialised Huffman. Exercise matches
    // across the 8 KiB window, the extra-offset-bits ladder and a
    // data set with many distinct match lengths.
    let mut big = b"abcdefghij".repeat(3000).to_vec();
    big.extend((0..60000usize).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8));
    let head = big[..9000].to_vec();
    big.extend_from_slice(&head);
    let a = arc_fixture_with_method(0x0b, &big);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].method, 0x0b);
    assert_eq!(entries[0].data, big);
}
