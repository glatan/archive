#[cfg(feature = "cpio")]
#[test]
fn test_fuzz_regression_cpio_bin_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/cpio-bin_corrupt_cpio-bin-corrupt-panic--_c62e63e9.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::cpio::decode::decode(input);
}
