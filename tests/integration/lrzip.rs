use super::*;

fn assert_lrzip_encode_system_decode_compat(
    compression: lrzip::encode::CompressionType,
    archive_stem: &str,
    expected: &[u8],
) {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = lrzip_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lrzip_encode_{archive_stem}_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join(format!("{archive_stem}.lrz"));
    let output_path = dir.join("decoded.bin");

    let archive = lrzip::encode::encode_with(expected, compression);
    std::fs::write(&archive_path, &archive).unwrap();

    let output = Command::new(cmd)
        .args(["-d", "-q", "-f", "-o"])
        .arg(&output_path)
        .arg(&archive_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{cmd} decompress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(&output_path).unwrap(), expected);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&output_path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_lrzip_roundtrip_hello() {
    let data = b"Hello, World!";
    let compressed = lrzip::encode::encode(data);
    let decompressed = lrzip::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_lrzip_roundtrip_large() {
    let data: Vec<u8> = (0..50_000).map(|i| (i % 251) as u8).collect();
    let compressed = lrzip::encode::encode(&data);
    let decompressed = lrzip::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_lrzip_decode_rejects_truncated_stream() {
    let compressed = lrzip::encode::encode(b"lrzip truncated integration");
    let truncated = &compressed[..compressed.len() - 1];

    assert!(matches!(
        lrzip::decode::decode(truncated),
        Err(archive::error::Error::UnexpectedEof)
    ));
}

#[test]
fn test_lrzip_decode_detects_output_size_mismatch() {
    let mut compressed = lrzip::encode::encode(b"lrzip size mismatch integration");
    compressed[6..14].copy_from_slice(&(u64::MAX).to_le_bytes());

    assert!(matches!(
        lrzip::decode::decode(&compressed),
        Err(archive::error::Error::InvalidData(
            "lrzip: output size mismatch"
        ))
    ));
}

#[test]
fn test_lrzip_decode_system_lzma_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = lrzip_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lrzip_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("hello.txt");
    let archive_path = dir.join("hello.lrz");
    std::fs::write(&input_path, b"Hello from lrzip").unwrap();

    let output = Command::new(cmd)
        .current_dir(&dir)
        .args(["--lzma", "-q", "-f", "-o"])
        .arg(&archive_path)
        .arg(&input_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{cmd} compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = std::fs::read(&archive_path).unwrap();
    let decoded = lrzip::decode::decode(&archive).unwrap();
    assert_eq!(decoded, b"Hello from lrzip");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_lrzip_decode_system_lzma_repeated_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = lrzip_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_lrzip_decode_repeated_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("repeated.txt");
    let archive_path = dir.join("repeated.lrz");
    let input = b"hello lrzip repeated ".repeat(64);
    std::fs::write(&input_path, &input).unwrap();

    let output = Command::new(cmd)
        .current_dir(&dir)
        .args(["--lzma", "-q", "-f", "-o"])
        .arg(&archive_path)
        .arg(&input_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{cmd} compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = std::fs::read(&archive_path).unwrap();
    let decoded = lrzip::decode::decode(&archive).unwrap();
    assert_eq!(decoded, input);

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[test]
fn test_lrzip_encode_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::Lzma,
        "encoded",
        b"hello lrzip",
    );
}

#[test]
fn test_lrzip_encode_bzip2_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::Bzip2,
        "encoded_bzip2",
        &b"hello lrzip bzip2 ".repeat(64),
    );
}

#[test]
fn test_lrzip_encode_gzip_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::Gzip,
        "encoded_gzip",
        &b"hello lrzip gzip ".repeat(64),
    );
}

#[test]
fn test_lrzip_encode_none_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::None,
        "encoded_none",
        &b"hello lrzip none ".repeat(64),
    );
}

#[test]
fn test_lrzip_encode_lzo_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::Lzo,
        "encoded_lzo",
        &b"hello lrzip lzo ".repeat(64),
    );
}

#[test]
fn test_lrzip_encode_zpaq_system_decode_compat() {
    assert_lrzip_encode_system_decode_compat(
        lrzip::encode::CompressionType::Zpaq,
        "encoded_zpaq",
        &b"hello lrzip zpaq ".repeat(64),
    );
}
