#[cfg(feature = "mscab")]
#[test]
fn test_fuzz_regression_mscab_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/mscab_corrupt_mscab-corrupt-panic--unk_af1349b9.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::mscab::decode::decode(input);
}
