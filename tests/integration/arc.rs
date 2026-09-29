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
    // Method 4 (squeezed) and above are out of scope and refused.
    for m in [4u8, 8, 0xFF] {
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
    a.extend_from_slice(&orig_size.to_le_bytes());
    a.extend_from_slice(&0x1234u16.to_le_bytes()); // date
    a.extend_from_slice(&0x5678u16.to_le_bytes()); // time
    a.extend_from_slice(&crc.to_le_bytes());
    a.extend_from_slice(&(packed.len() as u32).to_le_bytes());
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
        .add_file_with_method("F.TXT", b"x", 0, 0, 4)
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
