use super::*;

// ============================================================
// LZ4 tests
// ============================================================

#[test]
fn test_lz4_roundtrip_hello() {
    let data = b"Hello, World!";
    let compressed = lz4::encode::encode(data);
    let decompressed = lz4::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_lz4_roundtrip_large() {
    let data = "The quick brown fox jumps over the lazy dog. ".repeat(200);
    let compressed = lz4::encode::encode(data.as_bytes());
    assert!(compressed.len() < data.len(), "should compress");
    let decompressed = lz4::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data.as_bytes());
}

#[test]
fn test_lz4_decode_system_fixture() {
    // hello.lz4 is "hello from lz4" compressed with system `lz4`
    let compressed = include_bytes!("../fixtures/lz4/hello.lz4");
    let decompressed = lz4::decode::decode(compressed).unwrap();
    assert_eq!(decompressed, b"hello from lz4");
}

#[test]
fn test_lz4_encode_decoded_by_system() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let input = b"The quick brown fox jumps over the lazy dog. Testing LZ4 interop!";
    let compressed = lz4::encode::encode(input);

    let mut child = match Command::new("lz4")
        .args(["-d", "-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            assert_eq!(lz4::decode::decode(&compressed).unwrap(), input);
            return;
        }
        Err(error) => panic!("failed to run lz4: {error}"),
    };
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&compressed)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system lz4 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
}

#[test]
fn test_lz4_roundtrip_block_sizes() {
    let data = b"abcdefghij".repeat(10_000);
    for block_size in &[
        lz4::encode::BlockMaxSize::KB64,
        lz4::encode::BlockMaxSize::KB256,
        lz4::encode::BlockMaxSize::MB1,
        lz4::encode::BlockMaxSize::MB4,
    ] {
        let compressed = lz4::encode::encode_with_options(&data, *block_size, true);
        let decompressed = lz4::decode::decode(&compressed)
            .unwrap_or_else(|e| panic!("block_size={:?}: {e}", block_size));
        assert_eq!(decompressed, data, "block_size={:?}", block_size);
    }
}

#[test]
fn test_lz4_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input = b"lz4 writer reader integration payload ".repeat(256);
    let mut encoded = Vec::new();
    let written = lz4::encode::encode_writer(&input, &mut encoded).unwrap();

    assert_eq!(written, encoded.len());

    let decoded = lz4::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lz4_dictionary_roundtrip_with_id() {
    let dict = lz4::decode::Lz4Dict::with_id(b"common-prefix-", 0xAABB_CCDD);
    let payload = b"common-prefix-payload repeated common-prefix-payload";
    let encoded = lz4::encode::encode_with_dict(payload, &dict);
    let decoded = lz4::decode::decode_with_dict(&encoded, &dict).unwrap();

    assert_eq!(decoded, payload);
}

#[test]
fn test_lz4_decode_skippable_frame_before_payload() {
    let payload = b"lz4 skippable frame payload";
    let encoded = lz4::encode::encode(payload);
    let mut combined = Vec::new();
    combined.extend_from_slice(&0x184D2A50u32.to_le_bytes());
    combined.extend_from_slice(&(4u32).to_le_bytes());
    combined.extend_from_slice(b"skip");
    combined.extend_from_slice(&encoded);

    let decoded = lz4::decode::decode(&combined).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_lz4_decode_rejects_missing_and_mismatched_dictionary() {
    let dict = lz4::decode::Lz4Dict::with_id(b"prefix", 0x1122_3344);
    let wrong_dict = lz4::decode::Lz4Dict::with_id(b"prefix", 0x5566_7788);
    let encoded = lz4::encode::encode_with_dict(b"prefix-data", &dict);

    assert!(matches!(
        lz4::decode::decode(&encoded),
        Err(archive::error::Error::Unsupported(
            "lz4: dictionary required"
        ))
    ));
    assert!(matches!(
        lz4::decode::decode_with_dict(&encoded, &wrong_dict),
        Err(archive::error::Error::InvalidData(
            "lz4: dictionary ID mismatch"
        ))
    ));
}
