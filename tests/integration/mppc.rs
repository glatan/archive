use super::*;

// ============================================================
// MPPC (RFC 2118) tests
// ============================================================
//
// Fixtures under tests/fixtures/mppc/ were produced by this crate's
// encoder and cross-validated with the rdesktop MPPC decoder
// (GPL-3.0, test oracle only — no code shared). `*.pkt` files hold a
// single MPPC packet (flags|count|data); `*.pkts` files hold a
// concatenation of `[u16 LE packet_len][packet]` frames, matching how a
// link layer supplies packet boundaries.

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/mppc/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn decode_stream(pkts: &[u8]) -> Vec<u8> {
    let mut dec = mppc::Decoder::new();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < pkts.len() {
        let len = u16::from_le_bytes([pkts[pos], pkts[pos + 1]]) as usize;
        let packet = &pkts[pos + 2..pos + 2 + len];
        out.extend_from_slice(&dec.decompress(packet, 1 << 20).unwrap());
        pos += 2 + len;
    }
    out
}

#[test]
fn decode_single_packet_fixtures() {
    for name in [
        "literal",
        "matches",
        "high_literals",
        "overlap",
        "expanded",
        "max_size",
    ] {
        let packet = fixture(&format!("{name}.pkt"));
        let expected = fixture(&format!("{name}.expected"));
        assert_eq!(mppc::decode(&packet).unwrap(), expected, "{name}");
    }
}

#[test]
fn decode_multi_packet_streams() {
    for name in ["multi", "wrap_front"] {
        let pkts = fixture(&format!("{name}.pkts"));
        let expected = fixture(&format!("{name}.expected"));
        assert_eq!(decode_stream(&pkts), expected, "{name}");
    }
}

#[test]
fn encode_decode_roundtrip() {
    let data: Vec<u8> = (0..8192u32)
        .map(|i| (i / 13) as u8 ^ (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    for n in [0, 1, 64, 300, 1500, 4096, 8192] {
        let input = &data[..n.min(data.len())];
        let packet = mppc::encode(input).unwrap();
        assert_eq!(mppc::decode(&packet).unwrap(), input);
    }
}

#[test]
fn oversized_input_rejected() {
    let data = vec![0u8; mppc::HISTORY_SIZE + 1];
    assert!(mppc::encode(&data).is_err());
}
