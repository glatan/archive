// ============================================================
// Zstandard Seekable Format tests
// ============================================================
//
// The `.zst` fixtures were produced by the reference seekable
// compressor (zstd `contrib/seekable_format`, BSD/GPL dual license)
// and are used as known-answer decode tests. They carry per-frame
// XXH64 checksums (`Checksum_Flag` set).

use archive::compress::zstd::seekable;

const TEXT_PLAIN: &[u8] = include_bytes!("../fixtures/zstd/seekable_text.bin");
const TEXT_SEEK: &[u8] = include_bytes!("../fixtures/zstd/seekable_text.zst");
const BIN_PLAIN: &[u8] = include_bytes!("../fixtures/zstd/seekable_bin.bin");
const BIN_SEEK: &[u8] = include_bytes!("../fixtures/zstd/seekable_bin.zst");

#[test]
fn test_zstd_seekable_decode_reference_text() {
    let table = seekable::seek_table(TEXT_SEEK).unwrap();
    assert!(table.has_checksums);
    assert_eq!(table.entries.len(), 10);
    assert_eq!(seekable::decode(TEXT_SEEK).unwrap(), TEXT_PLAIN);
}

#[test]
fn test_zstd_seekable_decode_reference_binary() {
    let table = seekable::seek_table(BIN_SEEK).unwrap();
    assert!(table.has_checksums);
    assert_eq!(table.entries.len(), 3);
    assert_eq!(seekable::decode(BIN_SEEK).unwrap(), BIN_PLAIN);
}

#[test]
fn test_zstd_seekable_range_reference() {
    // Verified against the reference `seekable_decompression_mem` tool.
    assert_eq!(
        seekable::decode_range(TEXT_SEEK, 0, 3000).unwrap(),
        &TEXT_PLAIN[..3000]
    );
    assert_eq!(
        seekable::decode_range(BIN_SEEK, 5000, 19000).unwrap(),
        &BIN_PLAIN[5000..24000]
    );
}

#[test]
fn test_zstd_seekable_roundtrip() {
    let mut data = Vec::new();
    for i in 0u32..30000 {
        data.extend_from_slice(&i.to_le_bytes());
    }
    let compressed = seekable::encode(&data, 16 * 1024);
    let table = seekable::seek_table(&compressed).unwrap();
    assert_eq!(table.entries.len(), 8);
    assert!(!table.has_checksums);
    assert_eq!(seekable::decode(&compressed).unwrap(), data);
    assert_eq!(
        seekable::decode_range(&compressed, 70000, 20000).unwrap(),
        &data[70000..90000]
    );
}

#[test]
fn test_zstd_seekable_plain_zstd_decodes() {
    // A seekable stream is a valid multi-frame zstd stream: the plain
    // zstd decoder must accept it (seek table is a skippable frame).
    let via_zstd = archive::compress::zstd::decode::decode(TEXT_SEEK).unwrap();
    assert_eq!(via_zstd, TEXT_PLAIN);
}

#[test]
fn test_zstd_seekable_rejects_plain_zstd() {
    let plain = archive::compress::zstd::encode::encode(b"no table");
    assert!(seekable::decode(&plain).is_err());
    assert!(seekable::decode_range(&plain, 0, 1).is_err());
}
