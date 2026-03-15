use super::*;

fn python_raw_deflate_compress(input: &[u8], level: u8) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let script = r#"import sys, zlib
level = int(sys.argv[1])
data = sys.stdin.buffer.read()
compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
sys.stdout.buffer.write(compressor.compress(data) + compressor.flush())
"#;

    let mut child = match Command::new("python3")
        .args(["-c", script, &level.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run python3: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python raw deflate compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

fn python_raw_deflate_decode(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let script = r#"import sys, zlib
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(zlib.decompress(data, -15))
"#;

    let mut child = match Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run python3: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "python raw deflate decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

// ============================================================
// DEFLATE tests
// ============================================================

#[test]
fn test_deflate_decode_hello_gz() {
    // Extract raw DEFLATE stream from hello.gz (skip gzip header, keep trailer - decoder self-terminates)
    let gz_data = include_bytes!("../fixtures/gzip/hello.gz");
    let header = gzip::header::GzipHeader::parse(gz_data).unwrap();
    let deflate_data = &gz_data[header.header_size..];
    let result = deflate::decode::decode(deflate_data).unwrap();
    assert_eq!(result, b"Hello, World!");
}

#[test]
fn test_deflate_decode_repeated_gz() {
    let gz_data = include_bytes!("../fixtures/gzip/repeated.gz");
    let header = gzip::header::GzipHeader::parse(gz_data).unwrap();
    let deflate_data = &gz_data[header.header_size..];
    let result = deflate::decode::decode(deflate_data).unwrap();
    let expected = "The quick brown fox jumps over the lazy dog. ".repeat(10);
    assert_eq!(result, expected.as_bytes());
}

#[test]
fn test_deflate_encode_roundtrip_all_levels() {
    let inputs: [&[u8]; 3] = [
        b"Hello, DEFLATE integration!",
        b"The quick brown fox jumps over the lazy dog.",
        b"abcabcabcabcabcabcabcabcabcabc",
    ];

    for input in inputs {
        for level in [
            deflate::encode::Level::NoCompression,
            deflate::encode::Level::Fast,
            deflate::encode::Level::Default,
        ] {
            let encoded = deflate::encode::encode(input, level);
            let decoded = deflate::decode::decode(&encoded).unwrap();
            assert_eq!(decoded, input, "roundtrip failed for level {level:?}");
        }
    }
}

#[test]
fn test_deflate_compression_level_size_ordering() {
    let input = b"repetitive data helps expose level ordering ".repeat(512);

    let no_compression = deflate::encode::encode(&input, deflate::encode::Level::NoCompression);
    let fast = deflate::encode::encode(&input, deflate::encode::Level::Fast);
    let default = deflate::encode::encode(&input, deflate::encode::Level::Default);

    assert!(
        no_compression.len() >= fast.len(),
        "stored blocks should not beat fast compression"
    );
    assert!(
        fast.len() >= default.len(),
        "default compression should be at least as compact as fast compression"
    );
}

#[test]
fn test_deflate_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let mut encoded = Vec::new();
    let written =
        deflate::encode::encode_writer(&input, deflate::encode::Level::Default, &mut encoded)
            .unwrap();

    assert_eq!(written, encoded.len());

    let decoded = deflate::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_deflate_decode_python_raw_deflate_stream() {
    let input = b"python raw deflate integration payload ".repeat(256);
    let Some(encoded) = python_raw_deflate_compress(&input, 6) else {
        return;
    };

    let decoded = deflate::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_deflate_encode_raw_stream_decoded_by_python() {
    let input = b"archive deflate raw stream for python decode ".repeat(256);

    for level in [
        deflate::encode::Level::NoCompression,
        deflate::encode::Level::Fast,
        deflate::encode::Level::Default,
    ] {
        let encoded = deflate::encode::encode(&input, level);
        let Some(decoded) = python_raw_deflate_decode(&encoded) else {
            return;
        };
        assert_eq!(decoded, input, "python decode failed for level {level:?}");
    }
}

#[test]
fn test_deflate_encode_empty_raw_stream_decoded_by_python() {
    let encoded = deflate::encode::encode(b"", deflate::encode::Level::NoCompression);
    let Some(decoded) = python_raw_deflate_decode(&encoded) else {
        return;
    };
    assert!(decoded.is_empty());
}

#[test]
fn test_deflate_decode_rejects_stored_block_len_mismatch() {
    let mut encoded = deflate::encode::encode(
        b"stored block mismatch",
        deflate::encode::Level::NoCompression,
    );
    encoded[3] ^= 0x01;

    assert!(matches!(
        deflate::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "stored block LEN/NLEN mismatch"
        ))
    ));
}

#[test]
fn test_deflate_decode_rejects_invalid_block_type() {
    let encoded = [0x06];

    assert!(matches!(
        deflate::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "invalid DEFLATE block type 11"
        ))
    ));
}
