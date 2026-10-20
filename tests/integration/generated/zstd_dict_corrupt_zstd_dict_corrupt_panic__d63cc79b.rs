#[cfg(feature = "zstd")]
#[test]
fn test_fuzz_regression_zstd_dict_corrupt() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/zstd-dict_corrupt_zstd-dict-corrupt-panic-_d63cc79b.mut.bin"
    );
    // Reproduce the fixed dictionary used by the fuzz target.
    let samples: Vec<Vec<u8>> = (0..16u32)
        .map(|s| {
            (0..2048u32)
                .map(|i| ((i * 13 + s * 97) % 251) as u8)
                .collect()
        })
        .collect();
    let refs: Vec<&[u8]> = samples.iter().map(Vec::as_slice).collect();
    let dict = archive::compress::zstd::train::train_dictionary(
        &refs,
        &archive::compress::zstd::train::TrainOptions::default(),
    )
    .unwrap();
    let _ = archive::compress::zstd::decode::decode_with_dict(input, &dict);
}
