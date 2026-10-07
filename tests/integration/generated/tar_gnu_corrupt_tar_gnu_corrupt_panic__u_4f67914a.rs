#[cfg(feature = "tar")]
#[test]
fn test_fuzz_regression_tar_gnu_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/tar-gnu_corrupt_tar-gnu-corrupt-panic--u_4f67914a.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::tar::decode::decode(input);
}
