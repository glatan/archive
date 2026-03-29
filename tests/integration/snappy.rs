use super::*;

// ============================================================
// Snappy tests
// ============================================================

#[test]
fn test_snappy_roundtrip() {
    let data = b"Snappy framed roundtrip data. ".repeat(200);
    let encoded = snappy::encode::encode(&data);
    let decoded = snappy::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_snappy_raw_roundtrip() {
    let data = b"abcabcabcabcabcabcabcabc";
    let encoded = snappy::encode::encode_raw(data);
    let decoded = snappy::decode::decode_raw(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_snappy_chunk_boundary_roundtrip() {
    for size in [65_536usize, 65_537] {
        let data = vec![b'X'; size];
        let encoded = snappy::encode::encode(&data);
        let decoded = snappy::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, data, "roundtrip failed at chunk size {size}");
    }
}

#[test]
fn test_snappy_decode_rejects_invalid_stream_identifier() {
    let mut encoded = snappy::encode::encode(b"snappy framed payload");
    encoded[4] ^= 0x01;

    assert!(matches!(
        snappy::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "snappy: invalid stream identifier"
        ))
    ));
}

#[test]
fn test_snappy_decode_detects_checksum_mismatch() {
    let mut encoded = snappy::encode::encode(b"snappy checksum payload");
    encoded[14] ^= 0x01;

    assert!(matches!(
        snappy::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_snappy_framed_empty_stream_roundtrip() {
    let encoded = snappy::encode::encode(b"");
    let decoded = snappy::decode::decode(&encoded).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(
        encoded.len(),
        10,
        "empty stream should contain only identifier"
    );
}

#[test]
fn test_snappy_emits_uncompressed_chunk_for_small_literal_payload() {
    let input = b"abc";
    let encoded = snappy::encode::encode(input);

    assert_eq!(
        encoded[10], 0x01,
        "small literal payload should use stored chunk"
    );

    let decoded = snappy::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_snappy_decode_accepts_skippable_chunk() {
    let payload = b"snappy skippable payload";
    let encoded = snappy::encode::encode(payload);

    let mut with_skippable = encoded[..10].to_vec();
    with_skippable.push(0x80);
    with_skippable.extend_from_slice(&3u32.to_le_bytes()[..3]);
    with_skippable.extend_from_slice(b"pad");
    with_skippable.extend_from_slice(&encoded[10..]);

    let decoded = snappy::decode::decode(&with_skippable).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_snappy_multi_chunk_roundtrip_with_trailing_chunk() {
    let mut input = vec![b'A'; 65_536];
    input.extend_from_slice(b"tail");

    let encoded = snappy::encode::encode(&input);
    let decoded = snappy::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_snappy_raw_large_roundtrip() {
    let input: Vec<u8> = (0..1_200_000u32)
        .map(|i| ((i.wrapping_mul(73).wrapping_add(19)) % 251) as u8)
        .collect();
    let encoded = snappy::encode::encode_raw(&input);
    let decoded = snappy::decode::decode_raw(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_snappy_raw_decode_rejects_trailing_bytes() {
    let mut encoded = snappy::encode::encode_raw(b"snappy raw trailing bytes");
    encoded.push(0);

    assert!(matches!(
        snappy::decode::decode_raw(&encoded),
        Err(archive::error::Error::InvalidData(
            "snappy: trailing bytes after raw block"
        ))
    ));
}
