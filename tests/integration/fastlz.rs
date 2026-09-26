use super::*;

// ============================================================
// FastLZ tests
// ============================================================
//
// The byte-level vectors below were produced by the reference FastLZ
// implementation (fastlz_compress / fastlz_compress_level) and are used
// as known-answer decode tests; encoder conformance is checked by
// round-trip.

#[test]
fn fastlz_reference_vector_l1_text() {
    // fastlz_compress("hello world hello world hello world", level 1).
    let input = [
        0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0xe0, 0x09,
        0x0b, 0x04, 0x77, 0x6f, 0x72, 0x6c, 0x64,
    ];
    let dec = fastlz::decode(&input).unwrap();
    assert_eq!(dec, b"hello world hello world hello world");
}

#[test]
fn fastlz_reference_vector_l1_run() {
    // fastlz_compress of 299 'a' bytes + NUL (level 1): two long matches
    // with a final literal run including the NUL byte.
    let input = [
        0x01, 0x61, 0x61, 0xe0, 0xfd, 0x01, 0xe0, 0x16, 0x01, 0x04, 0x61, 0x61, 0x61, 0x61, 0x00,
    ];
    let mut expected = vec![b'a'; 299];
    expected.push(0);
    let dec = fastlz::decode(&input).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn fastlz_reference_vector_l2_marker_and_chain() {
    // fastlz_compress_level(2) of 299 'a' bytes + NUL. First byte carries
    // the level-2 marker bit (0x21 = literal run 1 | 0x20).
    let input = [
        0x21, 0x61, 0x61, 0xe0, 0xff, 0x1d, 0x01, 0x04, 0x61, 0x61, 0x61, 0x61, 0x00,
    ];
    let mut expected = vec![b'a'; 299];
    expected.push(0);
    let dec = fastlz::decode(&input).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn fastlz_reference_vector_l2_far_match() {
    // fastlz_compress_level(2) of 20000 'x' bytes with "PATTERN1234" at
    // offsets 0 and 12000: contains a level-2 far match (distance >8191).
    #[rustfmt::skip]
    let input = [
        0x2b, 0x50, 0x41, 0x54, 0x54, 0x45, 0x52, 0x4e, 0x31, 0x32, 0x33, 0x34, 0x78, 0xe0,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xf9, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x51, 0xff, 0x0e, 0xe0,
        0x04, 0x78, 0x78, 0x78, 0x78, 0x78,
    ];
    let mut expected = vec![b'x'; 20000];
    expected[..11].copy_from_slice(b"PATTERN1234");
    expected[12000..12011].copy_from_slice(b"PATTERN1234");
    let dec = fastlz::decode(&input).unwrap();
    assert_eq!(dec, expected);
}

#[test]
fn fastlz_hand_built_segments() {
    // literals + short match + long match.
    let input = [
        2, b'a', b'b', b'c', // literal run 3
        0x20, 0x02, // match len 3 dist 3 -> "abcabc"
        2, b'd', b'e', b'f', // literals "def"
        0xe0, 0x00, 0x05, // long match len 9 dist 6
    ];
    let dec = fastlz::decode(&input).unwrap();
    assert_eq!(dec, b"abcabcdefabcdefabc");
}

#[test]
fn fastlz_roundtrips() {
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"x".to_vec(),
        b"hello hello hello".to_vec(),
        vec![0u8; 3000],
    ];
    let mut text = Vec::new();
    for _ in 0..300 {
        text.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
    }
    cases.push(text);
    let mut binary = Vec::new();
    for i in 0..30000u32 {
        binary.extend_from_slice(&i.to_le_bytes());
    }
    cases.push(binary); // 120 KiB -> level-2 encode path
    cases.push(vec![b'q'; 100_000]); // level-2 + long matches

    for data in &cases {
        let enc = fastlz::encode(data);
        assert_eq!(&fastlz::decode(&enc).unwrap(), data);
        assert_eq!(&fastlz::decode(&fastlz::encode_level1(data)).unwrap(), data);
        assert_eq!(&fastlz::decode(&fastlz::encode_level2(data)).unwrap(), data);
    }
}

#[test]
fn fastlz_rejects_malformed() {
    assert!(fastlz::decode(&[10, b'a']).is_err()); // truncated literal
    assert!(fastlz::decode(&[0xe0]).is_err()); // missing ext+offset
    assert!(fastlz::decode(&[0x60, 0, 0]).is_err()); // unknown level
    assert!(fastlz::decode(&[2, b'a', b'b', b'c', 0x20, 0x05]).is_err()); // offset before start
}
