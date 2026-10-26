use super::*;

// ============================================================
// bzip2 tests
// ============================================================

/// Decode `compressed` with the system `bzip2` binary.
///
/// Returns `None` only when `bzip2` is not installed.
fn bzip2_system_decode(compressed: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = match Command::new("bzip2")
        .args(["-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("failed to run bzip2: {error}"),
    };
    child.stdin.as_mut().unwrap().write_all(compressed).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system bzip2 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

#[test]
fn test_bzip2_roundtrip_large() {
    // 100KB data with mixed patterns
    let mut data = Vec::with_capacity(100_000);
    for i in 0..100_000u32 {
        data.push((i % 251) as u8);
    }
    let compressed = bzip2::encode::encode(&data);
    let decoded = bzip2::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_bzip2_decode_system_compressed() {
    // "Hello, bzip2 world! This is a test of interoperability.\n" compressed with system bzip2 -9
    let system_bz2: &[u8] = &[
        0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x40, 0x7b, 0xa7, 0xa7, 0x00,
        0x00, 0x06, 0xdf, 0x80, 0x00, 0x10, 0x60, 0x05, 0x10, 0x00, 0x00, 0x40, 0x04, 0x00, 0x37,
        0x65, 0xdc, 0xb0, 0x20, 0x00, 0x50, 0xa0, 0x00, 0x68, 0x19, 0x32, 0x08, 0xa7, 0x93, 0x42,
        0x7a, 0x9e, 0x9a, 0x81, 0xa7, 0x94, 0xf4, 0x3a, 0x7d, 0x56, 0x27, 0x54, 0x6c, 0xfe, 0xf8,
        0x60, 0x8d, 0xc9, 0xfb, 0xb2, 0x82, 0x79, 0xed, 0xe4, 0x5d, 0x16, 0x22, 0x84, 0x35, 0x39,
        0x3e, 0x2c, 0x22, 0x40, 0x39, 0x9b, 0x98, 0xb6, 0x34, 0x2e, 0xe4, 0x8a, 0x70, 0xa1, 0x20,
        0x80, 0xf7, 0x4f, 0x4e,
    ];
    let decoded = bzip2::decode::decode(system_bz2).unwrap();
    assert_eq!(
        decoded,
        b"Hello, bzip2 world! This is a test of interoperability.\n"
    );
}

#[test]
fn test_bzip2_encode_decoded_by_system() {
    let input = b"The quick brown fox jumps over the lazy dog. Testing bzip2 interop!";
    let compressed = bzip2::encode::encode(input);
    assert_eq!(&compressed[..3], b"BZh");

    let Some(decoded) = bzip2_system_decode(&compressed) else {
        assert_eq!(bzip2::decode::decode(&compressed).unwrap(), input);
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_bzip2_roundtrip_multi_block() {
    // Use level 1 (100KB blocks) with data exceeding one block
    let input: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let compressed = bzip2::encode::encode_with_level(&input, 1);
    let decoded = bzip2::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_bzip2_large_interop_with_system() {
    let input: Vec<u8> = (0..120_000).map(|i| (i * 37 % 256) as u8).collect();
    let compressed = bzip2::encode::encode(&input);

    let Some(decoded) = bzip2_system_decode(&compressed) else {
        assert_eq!(bzip2::decode::decode(&compressed).unwrap(), input);
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_bzip2_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    let mut encoded = Vec::new();
    let written = bzip2::encode::encode_writer(&input, &mut encoded).unwrap();

    assert_eq!(written, encoded.len());

    let decoded = bzip2::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_bzip2_decode_system_binary_payload() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let input: Vec<u8> = (0..4096u32).map(|i| ((i * 73) % 256) as u8).collect();
    let mut child = match Command::new("bzip2")
        .args(["-c", "-1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("Failed to run bzip2: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system bzip2 compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decoded = bzip2::decode::decode(&output.stdout).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_bzip2_empty_stream_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_bzip2_empty_{uniq}.bz2"));
    let compressed = bzip2::encode::encode(b"");
    std::fs::write(&path, &compressed).unwrap();

    let output = Command::new("bzip2").args(["-d", "-c"]).arg(&path).output();
    let _ = std::fs::remove_file(&path);

    match output {
        Ok(result) => {
            assert!(
                result.status.success(),
                "bzip2 -d failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(result.stdout.is_empty());
        }
        Err(_) => {
            let decoded = bzip2::decode::decode(&compressed).unwrap();
            assert!(decoded.is_empty());
        }
    }
}

#[test]
fn test_bzip2_decode_rejects_invalid_block_size() {
    let mut encoded = bzip2::encode::encode(b"invalid block size");
    encoded[3] = b'0';

    assert!(matches!(
        bzip2::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "invalid bzip2 block size"
        ))
    ));
}

#[test]
fn test_bzip2_decode_detects_stream_crc_mismatch() {
    let mut encoded = bzip2::encode::encode(b"stream crc mismatch");
    let trailer_crc_start = encoded.len() - 4;
    encoded[trailer_crc_start] ^= 0x01;

    assert!(matches!(
        bzip2::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}
