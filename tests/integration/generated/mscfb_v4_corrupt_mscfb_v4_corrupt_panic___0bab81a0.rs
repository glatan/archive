#[cfg(feature = "mscfb")]
#[test]
fn test_fuzz_regression_mscfb_v4_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/mscfb-v4_corrupt_mscfb-v4-corrupt-panic--_0bab81a0.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::mscfb::decode::decode(input);
}
