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
//
// `*_rdp5.pkt` files instead hold a single RDP 5.0 (64 KiB dictionary)
// bulk-compression packet: `[compressedType flag byte][payload]` — RDP
// carries the flags out-of-band in the Share Data Header
// ([MS-RDPBCGR] 3.1.8.4.2). `rdp5_stream.pkts` frames
// `[u16 LE frame_len][flags][payload]` produced by this crate's
// RdpEncoder and cross-validated with rdesktop's big-dictionary
// mppc_expand (with uncompressed data inserted into the history, per
// spec — stock rdesktop skips that step).

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
        // External-encoder vector: TEST_MPPC_BELLS_RDP4 token stream from
        // FreeRDP's libfreerdp/codec/test/TestFreeRDPCodecMppc.c
        // (Apache-2.0), decompressed in FreeRDP's own test with
        // PACKET_AT_FRONT|PACKET_COMPRESSED on a fresh context. The
        // fixture prepends the equivalent RFC 2118 header
        // (FRONT|COMPRESSED, count 0 -> 0x60 0x00); the FreeRDP blob
        // itself carries no packet header.
        "external_freerdp_bells",
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

// ============================================================
// RDP bulk compression (MS-RDPBCGR 3.1.8.4) tests
// ============================================================

/// Decode framed `*_rdp5` stream fixtures: `[u16 LE frame_len][flags][payload]`.
fn decode_rdp5_stream(pkts: &[u8]) -> Vec<u8> {
    let mut dec = mppc::RdpDecoder::new(mppc::CompressionType::Rdp5);
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < pkts.len() {
        let len = u16::from_le_bytes([pkts[pos], pkts[pos + 1]]) as usize;
        let flags = pkts[pos + 2];
        let payload = &pkts[pos + 3..pos + 2 + len];
        out.extend_from_slice(&dec.decompress(flags, payload, 1 << 20).unwrap());
        pos += 2 + len;
    }
    out
}

#[test]
fn decode_rdp5_external_fixtures() {
    // External-encoder vectors from FreeRDP's
    // libfreerdp/codec/test/TestFreeRDPCodecMppc.c (Apache-2.0):
    // `external_freerdp_bells_rdp5` and `external_freerdp_island_rdp5`
    // are FreeRDP mppc_compress 64K-mode outputs; `external_freerdp_ms_rdp5`
    // is a compressed blob captured from the Microsoft implementation
    // (exercises all four RDP 5.0 offset classes). All carried flags
    // PACKET_AT_FRONT|PACKET_COMPRESSED|type64K (0x61) on a fresh context,
    // stored as the fixture's first byte.
    for name in [
        "external_freerdp_bells_rdp5",
        "external_freerdp_island_rdp5",
        "external_freerdp_ms_rdp5",
    ] {
        let packet = fixture(&format!("{name}.pkt"));
        let expected = fixture(&format!("{name}.expected"));
        assert_eq!(
            mppc::decode_rdp(packet[0], &packet[1..]).unwrap(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn decode_rdp5_stream_fixture() {
    let pkts = fixture("rdp5_stream.pkts");
    let expected = fixture("rdp5_stream.expected");
    assert_eq!(decode_rdp5_stream(&pkts), expected);
}

#[test]
fn rdp5_encode_decode_roundtrip() {
    let data: Vec<u8> = (0..65536u32)
        .map(|i| (i / 13) as u8 ^ (i.wrapping_mul(2654435761) >> 24) as u8)
        .collect();
    for n in [0, 1, 64, 300, 2368, 8192, 65536] {
        let input = &data[..n.min(data.len())];
        let (flags, payload) = mppc::encode_rdp(mppc::CompressionType::Rdp5, input).unwrap();
        assert_eq!(mppc::decode_rdp(flags, &payload).unwrap(), input);
    }
}

#[test]
fn rdp4_encode_decode_roundtrip() {
    // RDP 4.0 (8 KiB) rides the same API with CompressionType 0x00.
    let mut enc = mppc::RdpEncoder::new(mppc::CompressionType::Rdp4);
    let mut dec = mppc::RdpDecoder::new(mppc::CompressionType::Rdp4);
    let chunks: [&[u8]; 3] = [
        b"the quick brown fox jumps over the lazy dog",
        b"the quick brown fox jumps over the lazy dog",
        b"pack my box with five dozen liquor jugs",
    ];
    for (i, chunk) in chunks.iter().enumerate() {
        let (flags, payload) = enc.compress(chunk).unwrap();
        assert_eq!(
            dec.decompress(flags, &payload, 1 << 20).unwrap(),
            *chunk,
            "chunk {i}"
        );
    }
}

#[test]
fn rdp5_oversized_input_rejected() {
    let data = vec![0u8; mppc::HISTORY_SIZE_64K + 1];
    assert!(mppc::encode_rdp(mppc::CompressionType::Rdp5, &data).is_err());
}

#[test]
fn rdp6_rejected() {
    // RDP6/RDP6.1 bulk compression is a different codec.
    assert!(mppc::decode_rdp(0x22 | mppc::PACKET_COMPRESSED, b"xx").is_err());
    assert!(mppc::decode_rdp(0x23 | mppc::PACKET_COMPRESSED, b"xx").is_err());
}
