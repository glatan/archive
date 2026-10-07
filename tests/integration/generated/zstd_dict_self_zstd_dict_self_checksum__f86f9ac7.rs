#[cfg(feature = "zstd")]
#[test]
fn test_fuzz_regression_zstd_dict_self() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/zstd-dict_self_zstd-dict-self-checksum-_f86f9ac7.bin"
    );
    let samples: Vec<&[u8]> = vec![
        b"aaaa repeat aaaa repeat".as_slice(),
        b"bbbb repeat bbbb repeat".as_slice(),
    ];
    let dict = archive::compress::zstd::train::train_dictionary(
        &samples,
        &archive::compress::zstd::train::TrainOptions::default(),
    )
    .unwrap();
    let encoded = archive::compress::zstd::encode::encode_with_dict(input, &dict);
    let decoded = archive::compress::zstd::decode::decode_with_dict(&encoded, &dict).unwrap();
    assert_eq!(decoded, input);
}
