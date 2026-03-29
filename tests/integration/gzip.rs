use super::*;

// ============================================================
// Gzip tests
// ============================================================

#[test]
fn test_gzip_decode_hello() {
    let gz_data = include_bytes!("../fixtures/gzip/hello.gz");
    let result = gzip::decode::decode(gz_data).unwrap();
    assert_eq!(result, b"Hello, World!");
}

#[test]
fn test_gzip_decode_repeated() {
    let gz_data = include_bytes!("../fixtures/gzip/repeated.gz");
    let result = gzip::decode::decode(gz_data).unwrap();
    let expected = "The quick brown fox jumps over the lazy dog. ".repeat(10);
    assert_eq!(result, expected.as_bytes());
}

// ============================================================
// Phase 4: Additional integration tests
// ============================================================

#[test]
fn test_gzip_roundtrip_large() {
    // 100KB of data through gzip encode → decode
    let input: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
    let encoded = gzip::encode::encode(&input, archive::compress::deflate::encode::Level::Default);
    let decoded = gzip::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
    // Verify compression actually reduced size
    assert!(encoded.len() < input.len());
}

#[test]
fn test_gzip_roundtrip_all_levels_via_reader() {
    use std::io::Cursor;

    let input = b"gzip level matrix integration payload ".repeat(256);

    for level in [
        deflate::encode::Level::NoCompression,
        deflate::encode::Level::Fast,
        deflate::encode::Level::Default,
    ] {
        let encoded = gzip::encode::encode(&input, level);
        let decoded = gzip::decode::decode_reader(Cursor::new(&encoded)).unwrap();
        assert_eq!(decoded, input, "roundtrip failed for level {level:?}");
    }

    let no_compression = gzip::encode::encode(&input, deflate::encode::Level::NoCompression);
    let default = gzip::encode::encode(&input, deflate::encode::Level::Default);
    assert!(
        default.len() < no_compression.len(),
        "default gzip should beat stored DEFLATE for repetitive payloads"
    );
}

#[test]
fn test_gzip_encode_writer_with_options_roundtrip() {
    use std::io::Cursor;

    let input = b"gzip metadata integration payload ".repeat(64);
    let extra = b"AB\x04\x00data";
    let options = gzip::encode::GzipEncodeOptions {
        filename: Some("meta.txt"),
        comment: Some("integration metadata"),
        extra: Some(extra),
        header_crc: true,
        ftext: true,
        mtime: 1_700_000_000,
        os: 3,
    };
    let mut encoded = Vec::new();
    let written = gzip::encode::encode_writer_with_options(
        &input,
        deflate::encode::Level::Fast,
        &options,
        &mut encoded,
    )
    .unwrap();

    assert_eq!(written, encoded.len());

    let header = gzip::header::GzipHeader::parse(&encoded).unwrap();
    assert_eq!(header.flags, 0x1F);
    assert_eq!(header.mtime, options.mtime);
    assert_eq!(header.os, options.os);
    assert_eq!(header.xfl, 0x04);

    let decoded = gzip::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_gzip_multi_member_stream_integration() {
    let first = gzip::encode::encode_with_options(
        b"Hello",
        deflate::encode::Level::NoCompression,
        &gzip::encode::GzipEncodeOptions {
            filename: Some("first.txt"),
            ..Default::default()
        },
    )
    .unwrap();
    let second = gzip::encode::encode_with_options(
        b" World",
        deflate::encode::Level::Default,
        &gzip::encode::GzipEncodeOptions {
            comment: Some("second member"),
            ..Default::default()
        },
    )
    .unwrap();

    let mut combined = first;
    combined.extend_from_slice(&second);

    let decoded = gzip::decode::decode(&combined).unwrap();
    assert_eq!(decoded, b"Hello World");
}

#[test]
fn test_gzip_encode_decoded_by_system_gzip() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_gzip = Command::new("gzip").arg("--version").output().is_ok();
    if !has_gzip {
        return;
    }

    let input = b"gzip system decode integration payload ".repeat(256);
    let encoded = gzip::encode::encode(&input, deflate::encode::Level::Default);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_gzip_encode_{uniq}.gz"));
    std::fs::write(&path, &encoded).unwrap();

    let output = Command::new("gzip")
        .args(["-d", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "system gzip -d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
}

#[test]
fn test_gzip_decode_system_encoded_stream() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_gzip = Command::new("gzip").arg("--version").output().is_ok();
    if !has_gzip {
        return;
    }

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let input_path = std::env::temp_dir().join(format!("archive_test_gzip_input_{uniq}.txt"));
    let input = b"system gzip encode integration payload ".repeat(192);
    std::fs::write(&input_path, &input).unwrap();

    let output = Command::new("gzip")
        .args(["-n", "-c"])
        .arg(&input_path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&input_path);

    assert!(
        output.status.success(),
        "system gzip encode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decoded = gzip::decode::decode(&output.stdout).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_gzip_multi_member_system_decode() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_gzip = Command::new("gzip").arg("--version").output().is_ok();
    if !has_gzip {
        return;
    }

    let first = gzip::encode::encode(b"first member ", deflate::encode::Level::Fast);
    let second = gzip::encode::encode(b"second member", deflate::encode::Level::Default);
    let mut combined = first;
    combined.extend_from_slice(&second);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_gzip_multi_{uniq}.gz"));
    std::fs::write(&path, &combined).unwrap();

    let output = Command::new("gzip")
        .args(["-d", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "system gzip multi-member decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"first member second member");
}

#[test]
fn test_gzip_decode_rejects_corrupt_header_crc() {
    let options = gzip::encode::GzipEncodeOptions {
        filename: Some("header-crc.txt"),
        comment: Some("header crc"),
        header_crc: true,
        ..Default::default()
    };
    let mut encoded = gzip::encode::encode_with_options(
        b"gzip header crc",
        deflate::encode::Level::Fast,
        &options,
    )
    .unwrap();
    encoded[10] ^= 0x01;

    assert!(matches!(
        gzip::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_gzip_decode_detects_trailer_crc_mismatch() {
    let mut encoded = gzip::encode::encode(b"gzip trailer crc", deflate::encode::Level::Default);
    let trailer_start = encoded.len() - 8;
    encoded[trailer_start] ^= 0x01;

    assert!(matches!(
        gzip::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}

#[test]
fn test_gzip_decode_detects_isize_mismatch() {
    let mut encoded = gzip::encode::encode(b"gzip isize mismatch", deflate::encode::Level::Default);
    let isize_start = encoded.len() - 4;
    encoded[isize_start] ^= 0x01;

    assert!(matches!(
        gzip::decode::decode(&encoded),
        Err(archive::error::Error::SizeMismatch { .. })
    ));
}

#[test]
fn test_gzip_multi_member_rejects_corrupt_second_member() {
    let first = gzip::encode::encode(b"first member ", deflate::encode::Level::Fast);
    let mut second = gzip::encode::encode(b"second member", deflate::encode::Level::Default);
    let trailer_start = second.len() - 8;
    second[trailer_start] ^= 0x01;

    let mut combined = first;
    combined.extend_from_slice(&second);

    assert!(matches!(
        gzip::decode::decode(&combined),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}
