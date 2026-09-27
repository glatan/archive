use super::*;

// ============================================================
// Stac LZS (RFC 2395 section 2.2) tests
// ============================================================
//
// Fixtures under tests/fixtures/lzs/ were produced by this crate's
// encoder and cross-validated with the compcol LZS codec (MIT,
// test oracle only — no code shared). `*.lzs` files hold a single
// compressed payload (bitstream + end marker + padding) and
// `*.expected` files hold the decoded datagram payload.

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/lzs/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn decode_fixtures() {
    for name in [
        "empty", "a", "lit", "repeat", "zeros", "rand", "text", "window", "overlap", "far",
    ] {
        let payload = fixture(&format!("{name}.lzs"));
        let expected = fixture(&format!("{name}.expected"));
        assert_eq!(lzs::decode(&payload).unwrap(), expected, "{name}");
    }
}

#[test]
fn encode_decode_roundtrip() {
    let data: Vec<u8> = (0..16384u32)
        .map(|i| (i / 13) as u8 ^ (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    for n in [0, 1, 64, 300, 1500, 4096, 8192, 16384] {
        let input = &data[..n.min(data.len())];
        let payload = lzs::encode(input).unwrap();
        assert_eq!(lzs::decode(&payload).unwrap(), input);
    }
}

#[test]
fn window_span_roundtrip() {
    // Match distances beyond the 2048-byte window must still roundtrip
    // via literals/nearer matches.
    let mut input = b"the quick brown fox".to_vec();
    input.extend(std::iter::repeat_n(0u8, 3000));
    input.extend_from_slice(b"the quick brown fox");
    let payload = lzs::encode(&input).unwrap();
    assert_eq!(lzs::decode(&payload).unwrap(), input);
}

#[test]
fn truncated_payload_rejected() {
    // Payload without the end marker must not decode.
    assert!(lzs::decode(&[0x20, 0x80]).is_err());
    assert!(lzs::decode(&[]).is_err());
}
