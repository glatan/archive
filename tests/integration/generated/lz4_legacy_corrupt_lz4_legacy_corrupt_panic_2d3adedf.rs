#[cfg(feature = "lz4")]
#[test]
fn test_fuzz_regression_lz4_legacy_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/lz4-legacy_corrupt_lz4-legacy-corrupt-panic_2d3adedf.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking and
    // without unbounded output.
    let decoded = archive::compress::lz4::decode::decode(input);
    if let Ok(bytes) = decoded {
        assert!(
            bytes.len() <= 65536,
            "corrupt decode produced {} bytes",
            bytes.len()
        );
    }
}
