#[cfg(feature = "xz")]
#[test]
fn test_fuzz_regression_xz_riscv_self() {
    let input = include_bytes!(
        "../../fixtures/fuzz/generated/xz-riscv_self_xz-riscv-self-checksum-m_74e82f14.bin"
    );
    let encoded = archive::compress::xz::encode::encode_with_filters(
        input,
        &[archive::compress::xz::filters::Filter::RiscV { start_offset: 0 }],
    )
    .unwrap();
    let decoded = archive::compress::xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}
