#[cfg(feature = "arc")]
#[test]
fn test_fuzz_regression_arc_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/arc_corrupt_arc-corrupt-panic--unkno_af1349b9.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::arc::decode::decode(input);
}
