use super::*;

// ============================================================
// ZX5 tests
// ============================================================
//
// ZX5_* streams below were produced by the reference ZX5 compressor
// (Einar Saukas, BSD 3-Clause, ZX5 v2.0) and are used as known-answer
// decode tests.

const ZX5_FOX: &[u8] = &[
    0x55, 0xee, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
    0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
    0x20, 0xe1, 0x13, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0xa1, 0xd3, 0x23,
    0x2e, 0x0a, 0x95, 0x55, 0x60,
];

const ZX5_A300: &[u8] = &[0x81, 0x61, 0x11, 0x2e, 0x00, 0x55, 0x55, 0x80];

const ZX5_T4K: &[u8] = &[
    0x10, 0xed, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
    0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0xec, 0x55, 0x15, 0x79, 0x55, 0x56,
];

const ZX5_MIX: &[u8] = &[
    0x41, 0x0e, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
    0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
    0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
    0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x84, 0x9c, 0x45, 0x9c, 0x68, 0x65, 0x6c, 0x8e, 0x6f, 0x20,
    0x93, 0xfa, 0xa1, 0xef, 0x40, 0xe5, 0x55, 0x58,
];

const ZX5_ALT: &[u8] = &[
    0x03, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0xb4, 0xf8, 0x15, 0x80, 0x94, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x40, 0xe6, 0x20, 0x50, 0x55, 0xe5, 0x55, 0x58,
];

#[test]
fn zx5_reference_vector_text() {
    let dec = zx5::decode(ZX5_FOX).unwrap();
    assert_eq!(
        dec,
        b"the quick brown fox jumps over the lazy dog. the quick brown fox.\n"
    );
}

#[test]
fn zx5_reference_vector_rep_offset() {
    // 299 'a' + NUL: exercises copy-from-last-offset.
    let mut expected = vec![b'a'; 299];
    expected.push(0);
    let dec = zx5::decode(ZX5_A300).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx5_reference_vector_long_match() {
    // 4100 bytes: a 20-byte literal run followed by a long match chain.
    let pat = b"the quick brown fox ";
    let mut expected = Vec::new();
    for _ in 0..205 {
        expected.extend_from_slice(pat);
    }
    let dec = zx5::decode(ZX5_T4K).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx5_reference_vector_mixed() {
    // 570 bytes: 4x 0x00..=0x63 + "hello hello hello" tail.
    let mut expected = Vec::new();
    for _ in 0..4 {
        expected.extend(0u8..=99);
    }
    for _ in 0..10 {
        expected.extend_from_slice(b"hello hello hello");
    }
    let dec = zx5::decode(ZX5_MIX).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx5_reference_vector_alt_offsets() {
    // 1200 bytes: ABCDEFGH / 12345678 alternating runs. Exercises
    // 2nd-last / 3rd-last offset copies and the multi-bit offset MSB.
    let mut expected = Vec::new();
    for _ in 0..30 {
        expected.extend_from_slice(b"ABCDEFGH");
    }
    for _ in 0..30 {
        expected.extend_from_slice(b"12345678");
    }
    for _ in 0..30 {
        expected.extend_from_slice(b"ABCDEFGH");
    }
    for _ in 0..30 {
        expected.extend_from_slice(b"12345678");
    }
    for _ in 0..30 {
        expected.extend_from_slice(b"ABCDEFGH");
    }
    assert_eq!(expected.len(), 1200);
    let dec = zx5::decode(ZX5_ALT).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx5_roundtrips() {
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"x".to_vec(),
        b"ab".to_vec(),
        b"hello hello hello".to_vec(),
        vec![0u8; 3000],
    ];
    let mut text = Vec::new();
    for _ in 0..200 {
        text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
    }
    cases.push(text);
    let mut binary = Vec::new();
    for i in 0..30000u32 {
        binary.extend_from_slice(&i.to_le_bytes());
    }
    cases.push(binary);
    // mixed runs to exercise copy-from-last-offset paths
    let mut mixed = Vec::new();
    for _ in 0..80 {
        mixed.extend_from_slice(b"aaaaa");
        mixed.extend_from_slice(b"bcdefg");
    }
    cases.push(mixed);

    for data in &cases {
        assert_eq!(&zx5::decode(&zx5::encode(data)).unwrap(), data);
    }
}

#[test]
fn zx5_rejects_malformed() {
    assert!(zx5::decode(&[0x80]).is_err()); // literal len but no data
    assert!(zx5::decode(&[0x55, 0xf8]).is_err()); // truncated literals
    // trailing garbage after EOF
    let mut c = ZX5_FOX.to_vec();
    c.push(0xaa);
    assert!(zx5::decode(&c).is_err());
}
