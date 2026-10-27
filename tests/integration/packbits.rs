use archive::compress::packbits;

#[test]
fn test_packbits_roundtrip_bytes() {
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"aaaabbbccddddddddddxyz".to_vec(),
        (0..=255u8).collect(),
        vec![0x90; 300],
        (0..5000u32).map(|i| (i * 73 % 251) as u8).collect(),
    ];
    for data in cases {
        let encoded = packbits::encode(&data);
        assert_eq!(packbits::decode(&encoded).unwrap(), data);
    }
}

#[test]
fn test_packbits_known_vector() {
    // TN1023-style packets: literal(2)[a b] + repeat(3)[c] + NOP + literal(1)[d].
    assert_eq!(
        packbits::decode(b"\x01ab\xfec\x80\x00d").unwrap(),
        b"abcccd"
    );
}

#[test]
fn test_packbits_rejects_truncated_packets() {
    assert!(packbits::decode(b"\x05ab").is_err());
    assert!(packbits::decode(b"\xfc").is_err());
}
