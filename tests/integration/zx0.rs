use super::*;

// ============================================================
// ZX0 tests
// ============================================================
//
// ZX0_* streams below were produced by the reference ZX0 compressor
// (Einar Saukas, BSD 3-Clause) and are used as known-answer decode tests.

const ZX0_FOX: &[u8] = &[
    0x55, 0xf8, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
    0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72,
    0x20, 0xc2, 0x4e, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e, 0x20, 0xa6, 0x12, 0x35,
    0x2e, 0x0a, 0x55, 0x58,
];

const ZX0_A300: &[u8] = &[0x81, 0x61, 0x11, 0x2d, 0x00, 0x55, 0x56];

const ZX0_T4K: &[u8] = &[
    0x10, 0xf5, 0x74, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
    0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0xd8, 0x54, 0x55, 0xd5, 0x55, 0x60,
];

#[test]
fn zx0_reference_vector_text() {
    let dec = zx0::decode(ZX0_FOX).unwrap();
    assert_eq!(
        dec,
        b"the quick brown fox jumps over the lazy dog. the quick brown fox.\n"
    );
}

#[test]
fn zx0_reference_vector_rep_offset() {
    // 299 'a' + NUL: exercises copy-from-last-offset and inverted offset
    // MSB elias bits.
    let mut expected = vec![b'a'; 299];
    expected.push(0);
    let dec = zx0::decode(ZX0_A300).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx0_reference_vector_long_match() {
    // 4100 bytes: a 20-byte literal run followed by a long match chain.
    let pat = b"the quick brown fox ";
    let mut expected = Vec::new();
    for _ in 0..205 {
        expected.extend_from_slice(pat);
    }
    let dec = zx0::decode(ZX0_T4K).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn zx0_roundtrips() {
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
        assert_eq!(&zx0::decode(&zx0::encode(data)).unwrap(), data);
    }
}

#[test]
fn zx0_rejects_malformed() {
    assert!(zx0::decode(&[0x80]).is_err()); // literal len but no data
    assert!(zx0::decode(&[0x55, 0xf8]).is_err()); // truncated literals
    // trailing garbage after EOF
    let mut c = ZX0_FOX.to_vec();
    c.push(0xaa);
    assert!(zx0::decode(&c).is_err());
}

// ---------------------------------------------------------------
// Variant coverage: v1 classic (-c) and +N prefix streams.
// ---------------------------------------------------------------

#[test]
fn zx0_prefix_history() {
    // literal 'a' + match (distance 6, len 3) reaching into the 5-byte
    // prefix "HELLO", then EOF.
    let stream = [0xed, b'a', 0xf4, 0x55, 0x56];
    assert!(zx0::decode(&stream).is_err());
    assert_eq!(zx0::decode_with_prefix(&stream, b"HELLO").unwrap(), b"aHEL");
}

#[test]
fn zx0_classic_v1_stream() {
    // literal 'a', new-offset match at distance 130 len 3, EOF.
    // Offset MSB 2 carries a data bit so the v1 (-c, non-inverted)
    // and v2 (inverted) encodings differ; a 129-byte prefix supplies
    // the match source.
    let prefix: Vec<u8> = (0u8..129).collect();
    let v1 = [0xcb, b'a', 0xfc, 0x00, 0x00, 0x80];
    let v2 = [0xdb, b'a', 0xfc, 0x55, 0x55, 0x80];
    assert_ne!(v1, v2);
    let mut expected = b"a".to_vec();
    expected.extend_from_slice(&prefix[..3]);
    assert_eq!(
        zx0::decode_classic_with_prefix(&v1, &prefix).unwrap(),
        expected
    );
    assert_eq!(zx0::decode_with_prefix(&v2, &prefix).unwrap(), expected);
    // Each decoder rejects the other variant's stream.
    assert!(zx0::decode_with_prefix(&v1, &prefix).is_err());
    assert!(zx0::decode_classic_with_prefix(&v2, &prefix).is_err());
}
