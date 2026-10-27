use super::*;

// ============================================================
// lzip tests
// ============================================================

#[test]
fn test_lzip_roundtrip_large() {
    let mut data = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        data.push((i % 251) as u8);
    }
    let compressed = lzip::encode::encode(&data);
    let decoded = lzip::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_lzip_roundtrip_empty() {
    let input = b"";
    let compressed = lzip::encode::encode(input);
    let decoded = lzip::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzip_roundtrip_tiny() {
    for input in [b"a".as_slice(), b"hi", b"tiny payload"] {
        let compressed = lzip::encode::encode(input);
        let decoded = lzip::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn test_lzip_roundtrip_variable_dict_sizes() {
    let input = b"dictionary-sized integration payload ".repeat(512);
    let cases = [
        (0x0C, 4_096u32),
        (0x10, 65_536u32),
        (0x11, 131_072u32),
        (0xB1, 88 * 1024u32),
    ];

    for (dict_size_byte, dict_size) in cases {
        let compressed =
            lzip::encode::encode_with_dict_size(&input, dict_size_byte, dict_size).unwrap();
        assert_eq!(compressed[5], dict_size_byte);

        let decoded = lzip::decode::decode(&compressed).unwrap();
        assert_eq!(
            decoded, input,
            "roundtrip failed for dict size byte 0x{dict_size_byte:02X}"
        );
    }
}

#[test]
fn test_lzip_roundtrip_high_entropy() {
    let input: Vec<u8> = (0..65_536u32)
        .map(|i| ((i.wrapping_mul(73) ^ 0xA5A5) & 0xFF) as u8)
        .collect();

    let compressed = lzip::encode::encode(&input);
    let decoded = lzip::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzip_decode_system_compressed() {
    use std::process::Command;

    let input = b"Hello, lzip!\n";
    let dir = unique_temp_dir("lzip_decode");
    let input_path = dir.join("input.txt");
    std::fs::write(&input_path, input).unwrap();

    let output = match Command::new("lzip")
        .args(["-9", "-c"])
        .arg(&input_path)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if require_external_tools() {
                panic!("required external tool is unavailable: lzip");
            }
            return;
        }
        Err(error) => panic!("failed to run lzip: {error}"),
    };
    assert!(
        output.status.success(),
        "system lzip failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(lzip::decode::decode(&output.stdout).unwrap(), input);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lzip_decode_system_compressed_fuzz_regression() {
    use std::process::Command;

    let input = include_bytes!("../fixtures/fuzz/lzip_original_compress_1.bin");
    // Captured `lzip -c` output; the regression check does not require the
    // system tool.
    let compressed = include_bytes!("../fixtures/fuzz/lzip_original_compress_1.lz");
    let decoded = lzip::decode::decode(compressed).unwrap();
    assert_eq!(decoded, input);

    let mut child = match Command::new("lzip")
        .args(["-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("Failed to run lzip: {e}"),
    };

    {
        use std::io::Write;
        child.stdin.as_mut().unwrap().write_all(input).unwrap();
    }

    let compressed = child.wait_with_output().unwrap();

    assert!(
        compressed.status.success(),
        "system lzip compress failed: {}",
        String::from_utf8_lossy(&compressed.stderr)
    );

    let decoded = lzip::decode::decode(&compressed.stdout).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzip_encode_decoded_by_system() {
    use std::process::Command;

    let input = b"The quick brown fox jumps over the lazy dog. Testing lzip interop!";
    let compressed = lzip::encode::encode(input);

    let dir = unique_temp_dir("lzip_encode");
    let path = dir.join("input.lz");
    std::fs::write(&path, &compressed).unwrap();
    let output = match Command::new("lzip").args(["-d", "-c"]).arg(&path).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if require_external_tools() {
                panic!("required external tool is unavailable: lzip");
            }
            assert_eq!(lzip::decode::decode(&compressed).unwrap(), input);
            return;
        }
        Err(error) => panic!("failed to run lzip: {error}"),
    };
    assert!(
        output.status.success(),
        "system lzip failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lzip_multi_member() {
    let data1 = b"first member data";
    let data2 = b"second member data";
    let mut combined = lzip::encode::encode(data1);
    combined.extend_from_slice(&lzip::encode::encode(data2));

    let decoded = lzip::decode::decode(&combined).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(data1);
    expected.extend_from_slice(data2);
    assert_eq!(decoded, expected);
}

#[test]
fn test_lzip_multi_member_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data1 = b"first member data";
    let data2 = b"second member data";
    let mut combined = lzip::encode::encode(data1);
    combined.extend_from_slice(&lzip::encode::encode(data2));

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_lzip_multi_{uniq}.lz"));
    std::fs::write(&path, &combined).unwrap();

    let output = Command::new("lzip").args(["-d", "-c"]).arg(&path).output();
    let _ = std::fs::remove_file(&path);

    match output {
        Ok(result) => {
            assert!(
                result.status.success(),
                "lzip -d failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, b"first member datasecond member data");
        }
        Err(_) => {
            let decoded = lzip::decode::decode(&combined).unwrap();
            assert_eq!(decoded, b"first member datasecond member data");
        }
    }
}
