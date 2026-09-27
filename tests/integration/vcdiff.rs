use super::*;

// ============================================================
// VCDIFF (RFC 3284) tests
// ============================================================
//
// The *_xdelta3.vcd fixtures were produced by the reference xdelta3 3.2.0
// encoder (Apache-2.0, https://github.com/jmacd/xdelta) and are used as
// known-answer decode tests. `fox_xdelta3.vcd` carries an xdelta3
// application header and per-window Adler-32 checksums; `big_xdelta3.vcd`
// exercises near/same address-cache modes and large COPY sizes.

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/vcdiff/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn vcdiff_xdelta3_source_window() {
    let src = fixture("fox_src.bin");
    let tgt = fixture("fox_tgt.bin");
    let delta = fixture("fox_xdelta3.vcd");
    assert_eq!(
        vcdiff::decode_with_source(&src, &delta).unwrap(),
        tgt.as_slice()
    );
}

#[test]
fn vcdiff_xdelta3_no_source() {
    let tgt = fixture("fox_tgt.bin");
    let delta = fixture("fox_nosrc_xdelta3.vcd");
    assert_eq!(vcdiff::decode(&delta).unwrap(), tgt.as_slice());
}

#[test]
fn vcdiff_xdelta3_near_same_caches() {
    let src = fixture("big_src.bin");
    let tgt = fixture("big_tgt.bin");
    let delta = fixture("big_xdelta3.vcd");
    assert_eq!(
        vcdiff::decode_with_source(&src, &delta).unwrap(),
        tgt.as_slice()
    );
}

#[test]
fn vcdiff_roundtrips() {
    for (src, tgt) in [
        (
            &b""[..],
            &b"The quick brown fox jumps over the lazy dog"[..],
        ),
        (
            &b"aaaaaaaaaaaaaaaaaaaa"[..],
            &b"aaaa bbbb aaaa cccc aaaaaaaa"[..],
        ),
        (
            &b"The quick brown fox jumps over the lazy dog"[..],
            &b"The quick brown fox leaps over the lazy dog!!"[..],
        ),
    ] {
        let d = vcdiff::encode_with_source(src, tgt);
        assert_eq!(vcdiff::decode_with_source(src, &d).unwrap(), tgt);
        // Encoded streams must also decode standalone when no source is set.
        if src.is_empty() {
            assert_eq!(vcdiff::decode(&d).unwrap(), tgt);
        }
    }
}

#[test]
fn vcdiff_rejects_malformed() {
    let d = vcdiff::encode(b"hello vcdiff");
    // Truncations must not panic.
    for cut in 0..d.len() {
        let _ = vcdiff::decode(&d[..cut]);
    }
    // Bad magic.
    assert!(vcdiff::decode(b"not a delta").is_err());
    // Bit-flips in the window body must not panic.
    let mut buf = d.clone();
    for i in 0..buf.len() {
        for bit in [0x01u8, 0x80] {
            buf[i] ^= bit;
            let _ = vcdiff::decode(&buf);
            buf[i] ^= bit;
        }
    }
}

#[test]
fn vcdiff_rejects_bad_checksum() {
    let mut delta = fixture("fox_xdelta3.vcd");
    // Corrupt one byte inside the Adler-32 checksummed window body.
    let n = delta.len();
    delta[n - 5] ^= 0xFF;
    assert!(matches!(
        vcdiff::decode_with_source(&fixture("fox_src.bin"), &delta),
        Err(archive::error::Error::ChecksumMismatch { .. })
            | Err(archive::error::Error::InvalidData(_))
    ));
}
