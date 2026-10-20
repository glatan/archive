#[cfg(feature = "zstd")]
#[test]
fn test_fuzz_regression_zstd_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/zstd_corrupt_zstd-corrupt-panic--unkn_d63cc79b.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking and
    // without unbounded output.
    let decoded = archive::compress::zstd::decode::decode(input);
    if let Ok(bytes) = decoded {
        assert!(
            bytes.len() <= 15674880,
            "corrupt decode produced {} bytes",
            bytes.len()
        );
    }
}
