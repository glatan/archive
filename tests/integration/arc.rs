// ============================================================
// SEA ARC container tests (methods 1/2/3; 4+ rejected)
// ============================================================

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
    // Methods 0x0c and above remain out of scope and refused.
    for m in [0x0cu8, 0x0d, 0x7e, 0xFF] {
        let mut a = Vec::new();
        a.extend_from_slice(&[0x1a, m]);
        a.extend_from_slice(&[0u8; 17]); // name + size
        a.extend_from_slice(&[0x1a, 0]);
        let err = archive::archive::arc::decode::decode(&a).unwrap_err();
        assert!(matches!(err, archive::error::Error::Unsupported(_)));
    }
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
    assert_eq!(entries[0].crc16, None);
    assert_eq!(entries[0].data, b"obsolete");
    assert_eq!(entries[1].method, 2);
    assert!(entries[1].crc16.is_some());
}

#[test]
fn test_arc_method1_header_layout() {
    // Method-1 record: marker + method=1 + name[13] + size u32le +
    // data. date/time are ignored and no CRC-16/length fields exist.
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
    assert_eq!(&a[19..22], b"xyz");
    assert_eq!(&a[22..], &[0x1a, 0]);
    assert_eq!(a.len(), 24);
}

#[test]
fn test_arc_rejects_unsupported_encode_method() {
    let mut enc = archive::archive::arc::encode::ArcEncoder::new();
    let err = enc
        .add_file_with_method("F.TXT", b"x", 0, 0, 5)
        .unwrap_err();
    assert!(matches!(err, archive::error::Error::Unsupported(_)));
}

#[test]
fn test_arc_method1_member() {
    // Obsolete unpacked member: name[13] + size + raw data, no CRC.
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, 1]);
    let mut name = [0u8; 13];
    name[..7].copy_from_slice(b"OLD.TXT");
    a.extend_from_slice(&name);
    a.extend_from_slice(&4u32.to_le_bytes());
    a.extend_from_slice(b"data");
    a.extend_from_slice(&[0x1a, 0]);
    let entries = archive::archive::arc::decode::decode(&a).unwrap();
    assert_eq!(entries[0].name, "OLD.TXT");
    assert_eq!(entries[0].data, b"data");
    assert_eq!(entries[0].crc16, None);
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
fn test_arc_method4_8_9_encode_decode_roundtrip() {
    let data = b"the quick brown fox jumps over the lazy dog. ".repeat(40);
    for method in [4u8, 8, 9] {
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

    for method in [4u8, 8, 9] {
        let archive = arc_fixture_with_method(method, &data);
        for oracle in &oracles {
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
        eprintln!("no arc oracle installed; skipped");
    }
}
