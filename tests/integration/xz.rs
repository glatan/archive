use super::*;

fn xz_system_compress_with_args(args: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;

    let mut child = match std::process::Command::new("xz")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run xz: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system xz compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

fn xz_index_start(encoded: &[u8]) -> usize {
    assert!(encoded.len() >= 12, "encoded xz stream too short");
    let footer_start = encoded.len() - 12;
    let backward_size = u32::from_le_bytes([
        encoded[footer_start + 4],
        encoded[footer_start + 5],
        encoded[footer_start + 6],
        encoded[footer_start + 7],
    ]) as usize;
    let index_size = (backward_size + 1) * 4;
    footer_start - index_size
}

#[test]
fn test_xz_roundtrip_hello() {
    let data = b"Hello, World!";
    let compressed = xz::encode::encode(data);
    let decompressed = xz::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_xz_roundtrip_empty() {
    let data = b"";
    let compressed = xz::encode::encode(data);
    let decompressed = xz::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_xz_roundtrip_large() {
    let data: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
    let compressed = xz::encode::encode(&data);
    let decompressed = xz::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_xz_interop_with_system_xz() {
    let data = b"Hello from archive crate xz encoder!";
    let compressed = xz::encode::encode(data);

    let Some(decoded) = xz_system_decode(&compressed) else {
        return;
    };
    assert_eq!(decoded, data);
}

#[test]
fn test_xz_decode_system_encoded() {
    let data = b"Hello from system xz encoder!";
    let Some(compressed) = xz_system_compress_with_args(&["-c"], data) else {
        return;
    };
    assert_eq!(xz::decode::decode(&compressed).unwrap(), data);
}

#[test]
fn test_xz_decode_system_compressed_fuzz_regression() {
    let input = include_bytes!("../fixtures/fuzz/xz_original_compress_1.bin");
    // Captured `xz -c` output; the regression check does not require the
    // system tool.
    let encoded = include_bytes!("../fixtures/fuzz/xz_original_compress_1.xz");
    assert_eq!(xz::decode::decode(encoded).unwrap(), input);

    if let Some(live) = xz_system_compress_with_args(&["-c"], input) {
        assert_eq!(xz::decode::decode(&live).unwrap(), input);
    }
}

#[test]
fn test_xz_decode_system_compressed_fuzz_regression_multichunk_state() {
    let input = include_bytes!("../fixtures/fuzz/xz_original_compress_2.bin");
    // Captured `xz -c` output; the regression check does not require the
    // system tool.
    let encoded = include_bytes!("../fixtures/fuzz/xz_original_compress_2.xz");
    assert_eq!(xz::decode::decode(encoded).unwrap(), input);

    if let Some(live) = xz_system_compress_with_args(&["-c"], input) {
        assert_eq!(xz::decode::decode(&live).unwrap(), input);
    }
}

#[test]
fn test_xz_decode_system_compressed_dict_boundary_fuzz_regression() {
    // `xz -0` (dict_size=256 KiB) emits non-reset LZMA2 chunks whose
    // cumulative output exceeds dict_size; history trimming must not shift
    // the position context.
    let input = include_bytes!("../fixtures/fuzz/xz_original_compress_3.bin");
    // Captured `xz -0 -c` output; the regression check does not require the
    // system tool.
    let encoded = include_bytes!("../fixtures/fuzz/xz_original_compress_3.xz");
    assert_eq!(xz::decode::decode(encoded).unwrap(), input);

    if let Some(live) = xz_system_compress_with_args(&["-0", "-c"], input) {
        assert_eq!(xz::decode::decode(&live).unwrap(), input);
    }
}

#[test]
fn test_xz_encode_system_decode_fuzz_regression() {
    let input = include_bytes!("../fixtures/fuzz/xz_original_decompress_1.bin");
    let encoded = xz::encode::encode(input);
    // Our own decoder must always accept the encoder output.
    assert_eq!(xz::decode::decode(&encoded).unwrap(), input);

    // Additionally verify with system xz when it is installed.
    if let Some(decoded) = xz_system_decode(&encoded) {
        assert_eq!(decoded, input);
    }
}

#[test]
fn test_xz_multi_stream_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let first = xz::encode::encode(b"first xz stream ");
    let second = xz::encode::encode(b"second xz stream");
    let mut combined = first;
    combined.extend_from_slice(&second);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_xz_multi_{uniq}.xz"));
    std::fs::write(&path, &combined).unwrap();

    let output = Command::new("xz").args(["-d", "-c"]).arg(&path).output();
    let _ = std::fs::remove_file(&path);

    match output {
        Ok(result) => {
            assert!(
                result.status.success(),
                "xz -d failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, b"first xz stream second xz stream");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("Failed to run xz: {e}"),
    }
}

#[test]
fn test_xz_decode_system_encoded_x86_filter_chain() {
    let input = [
        0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x90,
    ];
    let Some(encoded) = xz_system_compress("--filters=x86 --lzma2=dict=4KiB", &input) else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_x86_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [
        0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x90,
    ];
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::X86 { start_offset: 0 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_delta_filter_chain() {
    let input: Vec<u8> = (0u8..=63).cycle().take(512).collect();
    let Some(encoded) = xz_system_compress("--filters=delta:dist=4 --lzma2=dict=4KiB", &input)
    else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_delta_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input: Vec<u8> = (0u8..=63).cycle().take(512).collect();
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::Delta { distance: 4 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_powerpc_filter_chain() {
    let input = [
        0x48, 0x12, 0x34, 0x01, 0x60, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x01,
    ];
    let Some(encoded) = xz_system_compress("--filters=powerpc --lzma2=dict=4KiB", &input) else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_powerpc_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [
        0x48, 0x12, 0x34, 0x01, 0x60, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x01,
    ];
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::PowerPc { start_offset: 0 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_ia64_filter_chain() {
    let input = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0xA0,
    ];
    let Some(encoded) = xz_system_compress("--filters=ia64:start=4096 --lzma2=dict=4KiB", &input)
    else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_ia64_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0xA0,
    ];
    let encoded = xz::encode::encode_with_filters(
        &input,
        &[Filter::Ia64 {
            start_offset: 0x1000,
        }],
    )
    .unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_sparc_filter_chain() {
    let input = [0x40, 0x00, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00];
    let Some(encoded) = xz_system_compress("--filters=sparc --lzma2=dict=4KiB", &input) else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_sparc_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [0x40, 0x00, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00];
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::Sparc { start_offset: 0 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_arm_filter_chain() {
    let input = [0x01, 0x02, 0x03, 0xEB, 0x00, 0x00, 0x00, 0x00];
    let Some(encoded) = xz_system_compress("--filters=arm --lzma2=dict=4KiB", &input) else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_arm64_filter_chain() {
    let input = [0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90];
    let Some(encoded) = xz_system_compress("--filters=arm64:start=4096 --lzma2=dict=4KiB", &input)
    else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_arm64_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00, 0x90];
    let encoded = xz::encode::encode_with_filters(
        &input,
        &[Filter::Arm64 {
            start_offset: 0x1000,
        }],
    )
    .unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_riscv_filter_chain() {
    let input = [0xEF, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
    let Some(encoded) = xz_system_compress("--filters=riscv:start=4096 --lzma2=dict=4KiB", &input)
    else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_riscv_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [0xEF, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
    let encoded = xz::encode::encode_with_filters(
        &input,
        &[Filter::RiscV {
            start_offset: 0x1000,
        }],
    )
    .unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_riscv_auipc_pair() {
    // AUIPC+inst2 pair; start offset makes the pair take the special
    // rd=x2 conversion path (regression coverage for run-1791310276).
    let input = [0x17, 0x07, 0xD1, 0x83, 0x93, 0x0D, 0x27, 0x46];
    let Some(encoded) = xz_system_compress("--filters=riscv:start=30852 --lzma2:dict=4KiB", &input)
    else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_riscv_filter_chain_system_decode_fuzz_regression() {
    use archive::compress::xz::filters::Filter;

    // Fuzz run-1791310276 input: exercises the RISC-V AUIPC
    // special-format path where the encoder produced output that
    // upstream xz could not reverse.
    let input = include_bytes!(
        "../fixtures/fuzz/generated/xz-riscv_self_xz-riscv-self-checksum-m_74e82f14.bin"
    );
    let encoded =
        xz::encode::encode_with_filters(input, &[Filter::RiscV { start_offset: 0 }]).unwrap();
    assert_eq!(xz::decode::decode(&encoded).unwrap(), input);
    if let Some(decoded) = xz_system_decode(&encoded) {
        assert_eq!(decoded, input);
    }
}

#[test]
fn test_xz_encode_arm_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [0x01, 0x02, 0x03, 0xEB, 0x00, 0x00, 0x00, 0x00];
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::Arm { start_offset: 0 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_armthumb_filter_chain() {
    let input = [0x00, 0xF0, 0x00, 0xF8, 0x11, 0x22, 0x00, 0xF0, 0x00, 0xF8];
    let Some(encoded) = xz_system_compress("--filters=armthumb --lzma2=dict=4KiB", &input) else {
        return;
    };
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_armthumb_filter_chain_system_decode() {
    use archive::compress::xz::filters::Filter;

    let input = [0x00, 0xF0, 0x00, 0xF8, 0x11, 0x22, 0x00, 0xF0, 0x00, 0xF8];
    let encoded =
        xz::encode::encode_with_filters(&input, &[Filter::ArmThumb { start_offset: 0 }]).unwrap();
    let Some(decoded) = xz_system_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_encode_reader_roundtrip() {
    use std::io::Cursor;

    let input = b"xz reader encode integration payload ".repeat(256);
    let encoded = xz::encode::encode_reader(Cursor::new(&input)).unwrap();
    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input: Vec<u8> = (0..75_000).map(|i| (i % 251) as u8).collect();
    let encoded = xz::encode::encode(&input);
    let decoded = xz::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_rejects_invalid_magic() {
    let mut encoded = xz::encode::encode(b"invalid magic");
    encoded[0] ^= 0x01;

    assert!(matches!(
        xz::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData("xz: invalid magic"))
    ));
}

#[test]
fn test_xz_decode_rejects_corrupt_stream_header_crc() {
    let mut encoded = xz::encode::encode(b"header crc");
    encoded[8] ^= 0x01;

    assert!(matches!(
        xz::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_xz_decode_rejects_truncated_stream() {
    let encoded = xz::encode::encode(b"truncate me");
    let truncated = &encoded[..encoded.len() - 1];

    assert!(xz::decode::decode(truncated).is_err());
}

#[test]
fn test_xz_decode_system_encoded_crc64_check() {
    let input = b"xz crc64 integration payload ".repeat(128);
    let Some(encoded) = xz_system_compress_with_args(&["-c", "--check=crc64"], &input) else {
        return;
    };

    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_system_encoded_sha256_check() {
    let input = b"xz sha256 integration payload ".repeat(128);
    let Some(encoded) = xz_system_compress_with_args(&["-c", "--check=sha256"], &input) else {
        return;
    };

    let decoded = xz::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_xz_decode_rejects_corrupt_block_check_crc32() {
    let mut encoded = xz::encode::encode(b"xz block check crc32");
    let index_start = xz_index_start(&encoded);
    encoded[index_start - 1] ^= 0x01;

    assert!(matches!(
        xz::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_xz_decode_rejects_corrupt_footer_crc() {
    let mut encoded = xz::encode::encode(b"xz footer crc");
    let footer_start = encoded.len() - 12;
    encoded[footer_start] ^= 0x01;

    assert!(matches!(
        xz::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}
