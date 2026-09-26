use super::*;

// ============================================================
// LZF (liblzf) tests
// ============================================================

#[test]
fn lzf_hand_built_literal_run() {
    // Two literal runs of 32 + 5 bytes.
    let mut input = vec![31u8];
    input.extend_from_slice(b"0123456789abcdefghijklmnopqrstuv");
    input.push(4);
    input.extend_from_slice(b"wxyza");
    let dec = lzf::decode(&input).unwrap();
    assert_eq!(dec.len(), 37);
}

#[test]
fn lzf_hand_built_matches() {
    // "abc" + match(len 3, dist 3) + "def" + long match(len 9, dist 6).
    let input = [
        2, b'a', b'b', b'c', // literal run 3
        0x20, 0x02, // short match len 3 dist 3 -> "abcabc"
        2, b'd', b'e', b'f', // literal run 3 -> "abcabcdef"
        0xe0, 0x00, 0x05, // long match len 9 dist 6 -> + "abcdefabc"
    ];
    let dec = lzf::decode(&input).unwrap();
    assert_eq!(dec, b"abcabcdefabcdefabc");
}

#[test]
fn lzf_roundtrip_text_and_binary() {
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
    for i in 0..8000u32 {
        binary.extend_from_slice(&i.to_le_bytes());
    }
    cases.push(binary);

    for data in &cases {
        let enc = lzf::encode(data);
        let dec = lzf::decode(&enc).unwrap();
        assert_eq!(&dec, data);
        assert!(lzf::decode_bounded(&enc, data.len()).is_ok());
    }
}

#[test]
fn lzf_rejects_malformed() {
    assert!(lzf::decode(&[10, b'a']).is_err()); // truncated literal
    assert!(lzf::decode(&[0x60]).is_err()); // missing offset byte
    assert!(lzf::decode(&[0xe0, 0x10]).is_err()); // missing offset byte
    assert!(lzf::decode(&[0x20, 0x00]).is_err()); // offset before start
}
