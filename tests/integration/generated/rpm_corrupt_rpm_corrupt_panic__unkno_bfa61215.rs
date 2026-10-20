#[cfg(feature = "rpm")]
#[test]
fn test_fuzz_regression_rpm_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/rpm_corrupt_rpm-corrupt-panic--unkno_bfa61215.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::rpm::decode::decode(input);
}
