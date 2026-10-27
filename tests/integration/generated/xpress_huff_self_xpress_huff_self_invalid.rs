#[cfg(feature = "xca")]
#[test]
fn test_fuzz_regression_xpress_huff_self() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/xpress-huff_self_xpress-huff-self-invalid.bin"
    );
    let encoded = archive::compress::xca::huffman::encode(input);
    let decoded = archive::compress::xca::huffman::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}
