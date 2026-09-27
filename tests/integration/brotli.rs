use super::*;

// ============================================================
// Brotli tests
// ============================================================

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_q0_uncompressed() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("hello.txt");
    let output_path = dir.join("hello.txt.br");
    std::fs::write(&input_path, b"Hello, Brotli!").unwrap();

    let result = Command::new("brotli")
        .args([
            "-f",
            "-q",
            "0",
            "-o",
            output_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let compressed = std::fs::read(&output_path).unwrap();
        let decoded = brotli::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, b"Hello, Brotli!");
    }

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_q3_compressed_run() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_q3_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("repeated.txt");
    let output_path = dir.join("repeated.txt.br");
    let input = vec![b'A'; 64];
    std::fs::write(&input_path, &input).unwrap();

    let result = Command::new("brotli")
        .args([
            "-f",
            "-q",
            "3",
            "-o",
            output_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let compressed = std::fs::read(&output_path).unwrap();
        let decoded = brotli::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_q5_repeated_pattern() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_q5_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("pattern.txt");
    let output_path = dir.join("pattern.txt.br");
    let input = b"abcde".repeat(100);
    std::fs::write(&input_path, &input).unwrap();

    let result = Command::new("brotli")
        .args([
            "-f",
            "-q",
            "5",
            "-o",
            output_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let compressed = std::fs::read(&output_path).unwrap();
        let decoded = brotli::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_roundtrip() {
    let input = b"Brotli encode baseline ".repeat(1024);
    let encoded = brotli::encode::encode(&input);
    let decoded = brotli::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_encode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("baseline.br");
    let input = b"<p>Hello Brotli!</p>".repeat(256);
    let encoded = brotli::encode::encode(&input);
    std::fs::write(&archive_path, &encoded).unwrap();

    let result = Command::new("brotli")
        .args(["-d", "-c", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli decode failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, input);
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_empty_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_empty_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("empty.br");
    let encoded = brotli::encode::encode(b"");
    std::fs::write(&archive_path, &encoded).unwrap();

    let result = Command::new("brotli")
        .args(["-d", "-c", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli decode failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty());
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_writer_roundtrip() {
    let input = b"brotli writer integration payload ".repeat(128);
    let mut encoded = Vec::new();
    let written = brotli::encode::encode_writer(&input, &mut encoded).unwrap();

    assert_eq!(written, encoded.len());

    let decoded = brotli::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_multi_metablock_roundtrip() {
    let input = vec![b'B'; 0x0100_0000];
    let encoded = brotli::encode::encode(&input);
    let decoded = brotli::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_binary_payload() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_binary_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("input.bin");
    let output_path = dir.join("input.bin.br");
    let input: Vec<u8> = (0..2048u32).map(|i| ((i * 73) % 256) as u8).collect();
    std::fs::write(&input_path, &input).unwrap();

    let result = Command::new("brotli")
        .args([
            "-f",
            "-q",
            "0",
            "-o",
            output_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let compressed = std::fs::read(&output_path).unwrap();
        let decoded = brotli::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }

    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_repeated_pattern_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_pattern_encode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("pattern.br");
    let input = b"abcd".repeat(96);
    let encoded = brotli::encode::encode(&input);
    std::fs::write(&archive_path, &encoded).unwrap();

    let result = Command::new("brotli")
        .args(["-d", "-c", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli decode failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, input);
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_encode_low_cardinality_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_brotli_low_cardinality_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join("low-cardinality.br");
    let mut state = 0x1234_5678u32;
    let alphabet = *b"ABCD";
    let input: Vec<u8> = (0..2048)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            alphabet[((state >> 16) & 0x3) as usize]
        })
        .collect();
    let encoded = brotli::encode::encode(&input);
    std::fs::write(&archive_path, &encoded).unwrap();

    let result = Command::new("brotli")
        .args(["-d", "-c", archive_path.to_str().unwrap()])
        .output();

    if let Ok(result) = result {
        assert!(
            result.status.success(),
            "brotli decode failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(result.stdout, input);
    }

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_rejects_truncated_stream() {
    let encoded = brotli::encode::encode(b"brotli truncate me");
    let truncated = &encoded[..encoded.len() - 1];

    assert!(brotli::decode::decode(truncated).is_err());
}

#[cfg(feature = "brotli")]
fn brotli_compress_with_quality(data: &[u8], quality: u32) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = match Command::new("brotli")
        .args(["-q", &quality.to_string(), "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run brotli: {e}"),
    };
    child.stdin.take().unwrap().write_all(data).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "brotli -q {quality} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_quality_levels() {
    // High-entropy data that triggers context-based compression at q5+
    let data: Vec<u8> = (0..512)
        .map(|i| ((i as u64 * 73 + 19) % 256) as u8)
        .collect();

    for quality in 0..=11 {
        let Some(compressed) = brotli_compress_with_quality(&data, quality) else {
            return;
        };
        let decoded = brotli::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, data, "quality {quality} roundtrip failed");
    }
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_signed_context_mode_regression() {
    // This data pattern triggered a context computation bug at q10+
    // where p2 was incorrectly set to p1 when output.len() == 1.
    let data: Vec<u8> = (0..256)
        .map(|i| ((i as u64 * 7 + 19) % 256) as u8)
        .collect();
    // Captured `brotli -q 10` output; the regression check does not require
    // the system tool.
    let compressed = include_bytes!("../fixtures/brotli/signed_context_mode_q10.br");
    let decoded = brotli::decode::decode(compressed).unwrap();
    assert_eq!(decoded, data);

    if let Some(live) = brotli_compress_with_quality(&data, 10) {
        let decoded = brotli::decode::decode(&live).unwrap();
        assert_eq!(decoded, data);
    }
}

#[cfg(feature = "brotli")]
#[test]
fn test_brotli_decode_system_utf8_context_table_regression() {
    // This data pattern triggered UTF-8 context table bugs at q5-6
    let data: Vec<u8> = (0..512)
        .map(|i| ((i as u64 * 73 + 19) % 256) as u8)
        .collect();
    // Captured `brotli -q 5` output; the regression check does not require
    // the system tool.
    let compressed = include_bytes!("../fixtures/brotli/utf8_context_table_q5.br");
    let decoded = brotli::decode::decode(compressed).unwrap();
    assert_eq!(decoded, data);

    if let Some(live) = brotli_compress_with_quality(&data, 5) {
        let decoded = brotli::decode::decode(&live).unwrap();
        assert_eq!(decoded, data);
    }
}
