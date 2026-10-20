#[cfg(feature = "squashfs")]
#[test]
fn test_fuzz_regression_squashfs_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/squashfs_corrupt_squashfs-corrupt-panic--_c1bae26f.mut.bin"
    );
    // `input` is the mutated encoded stream that triggered this fuzz
    // failure; the decoder must return (Ok or Err) without panicking.
    let _ = archive::archive::squashfs::decode::decode(input);
}
