#[cfg(feature = "lha")]
#[test]
fn test_fuzz_regression_lha_lh7_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/lha-lh7_corrupt_lha-lh7-corrupt-panic--u_f58a1c92.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::lha::decode::decode(input);
}
