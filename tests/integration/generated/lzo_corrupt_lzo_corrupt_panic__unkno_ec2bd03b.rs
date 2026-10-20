#[cfg(feature = "lzo")]
#[test]
fn test_fuzz_regression_lzo_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/lzo_corrupt_lzo-corrupt-panic--unkno_ec2bd03b.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking and
    // without unbounded output.
    let decoded = archive::compress::lzo::decode::decode(input);
    if let Ok(bytes) = decoded {
        assert!(
            bytes.len() <= 65536,
            "corrupt decode produced {} bytes",
            bytes.len()
        );
    }
}
