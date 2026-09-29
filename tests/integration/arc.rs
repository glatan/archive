// ============================================================
// SEA ARC container tests (stored methods 1/2 only)
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
    // Method 3 (packed/RLE) is out of scope and must be refused.
    let mut a = Vec::new();
    a.extend_from_slice(&[0x1a, 3]);
    a.extend_from_slice(&[0u8; 17]); // name + size
    a.extend_from_slice(&[0x1a, 0]);
    let err = archive::archive::arc::decode::decode(&a).unwrap_err();
    assert!(matches!(err, archive::error::Error::Unsupported(_)));
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
        .add_file_with_method("F.TXT", b"x", 0, 0, 3)
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
