#[cfg(feature = "iso9660")]
#[test]
fn test_fuzz_regression_iso9660_rr_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/iso9660-rr_corrupt_iso9660-rr-corrupt-panic_5f84ed27.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::iso9660::decode::decode(input);
}
