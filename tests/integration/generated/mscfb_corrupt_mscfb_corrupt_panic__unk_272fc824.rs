#[cfg(feature = "mscfb")]
#[test]
fn test_fuzz_regression_mscfb_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/mscfb_corrupt_mscfb-corrupt-panic--unk_272fc824.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::mscfb::decode::decode(input);
}
