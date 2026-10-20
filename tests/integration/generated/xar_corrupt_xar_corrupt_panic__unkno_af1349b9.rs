#[cfg(feature = "xar")]
#[test]
fn test_fuzz_regression_xar_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/xar_corrupt_xar-corrupt-panic--unkno_af1349b9.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::xar::decode::decode(input);
}
