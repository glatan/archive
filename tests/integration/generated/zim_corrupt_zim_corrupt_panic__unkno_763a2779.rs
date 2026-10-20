#[cfg(feature = "zim")]
#[test]
fn test_fuzz_regression_zim_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/zim_corrupt_zim-corrupt-panic--unkno_763a2779.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::zim::decode::decode(input);
}
