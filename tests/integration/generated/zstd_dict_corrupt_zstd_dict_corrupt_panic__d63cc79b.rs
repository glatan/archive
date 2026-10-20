#[cfg(feature = "zstd")]
#[ignore = "fill in corrupt-input regression: re-encode this fixture and mutate the encoded stream"]
#[test]
fn test_fuzz_regression_zstd_dict_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/zstd-dict_corrupt_zstd-dict-corrupt-panic-_d63cc79b.mut.bin"
    );
    // Exported from fuzz failure for zstd-dict / corrupt.
    // The fixture holds the original input; the corrupt pattern derives
    // mutated encoded streams inside the fuzz harness (datagen::mutate),
    // which library tests cannot re-derive. Reproduce the failure by
    // replaying the artifact, then hand-write a decode-robustness test
    // around the offending mutated stream.
    let _ = input;
    panic!("fill in corrupt-pattern regression using this fixture");
}
