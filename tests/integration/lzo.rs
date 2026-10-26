use super::*;

const LZOP_HEADER_LEN_WITHOUT_FILENAME: usize = 38;

// ============================================================
// LZO (lzop) tests
// ============================================================

#[test]
fn test_lzo_roundtrip_hello() {
    let data = b"Hello, World!";
    let compressed = lzo::encode::encode(data);
    let decompressed = lzo::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_lzo_roundtrip_large() {
    let data = "The quick brown fox jumps over the lazy dog. ".repeat(200);
    let compressed = lzo::encode::encode(data.as_bytes());
    let decompressed = lzo::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data.as_bytes());
}

#[test]
fn test_lzo_decode_system_fixture() {
    // hello.lzo is "hello from lzop" compressed with system `lzop`
    let compressed = include_bytes!("../fixtures/lzo/hello.lzo");
    let decompressed = lzo::decode::decode(compressed).unwrap();
    assert_eq!(decompressed, b"hello from lzop");
}

#[test]
fn test_lzo_encode_decoded_by_system() {
    use std::process::Command;

    let input = b"The quick brown fox jumps over the lazy dog. Testing LZO interop!";
    let compressed = lzo::encode::encode(input);

    let dir = unique_temp_dir("lzo_interop");
    let archive_path = dir.join("test.lzo");
    let output_path = dir.join("test.out");
    std::fs::write(&archive_path, &compressed).unwrap();

    let output = Command::new("lzop")
        .args(["-d", "-f", "-o"])
        .arg(&output_path)
        .arg(&archive_path)
        .output();

    match output {
        Ok(result) => {
            assert!(
                result.status.success(),
                "system lzop failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(std::fs::read(&output_path).unwrap(), input);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            assert_eq!(lzo::decode::decode(&compressed).unwrap(), input);
        }
        Err(error) => panic!("failed to run lzop: {error}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_lzo_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input = b"lzo writer reader integration payload ".repeat(256);
    let mut encoded = Vec::new();
    let written = lzo::encode::encode_writer(&input, &mut encoded).unwrap();

    assert_eq!(written, encoded.len());

    let decoded = lzo::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzo_decode_system_binary_payload() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let input: Vec<u8> = (0..4096u32).map(|i| ((i * 73) % 256) as u8).collect();
    let mut child = match Command::new("lzop")
        .args(["-c", "-1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => panic!("Failed to run lzop: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system lzop compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decoded = lzo::decode::decode(&output.stdout).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzo_decode_rejects_corrupt_header_checksum() {
    let mut encoded = lzo::encode::encode(b"lzo header checksum");
    encoded[LZOP_HEADER_LEN_WITHOUT_FILENAME - 1] ^= 0x01;

    assert!(matches!(
        lzo::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "lzo: header checksum mismatch"
        ))
    ));
}

#[test]
fn test_lzo_decode_detects_uncompressed_adler_mismatch() {
    let mut encoded = lzo::encode::encode(b"lzo adler mismatch");
    let block_adler_offset = LZOP_HEADER_LEN_WITHOUT_FILENAME + 8;
    encoded[block_adler_offset] ^= 0x01;

    assert!(matches!(
        lzo::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}
