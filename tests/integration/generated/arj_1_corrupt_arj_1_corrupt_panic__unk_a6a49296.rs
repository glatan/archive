#[cfg(feature = "arj")]
#[test]
fn test_fuzz_regression_arj_1_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/arj-1_corrupt_arj-1-corrupt-panic--unk_a6a49296.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::arj::decode::decode(input);
}
