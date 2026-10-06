use super::*;

// ============================================================
// LZW (Unix compress) tests
// ============================================================

#[test]
fn test_lzw_roundtrip_hello() {
    let data = b"Hello, World!";
    let compressed = lzw::encode::encode(data);
    let decompressed = lzw::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_lzw_roundtrip_large() {
    let data = "The quick brown fox jumps over the lazy dog. ".repeat(200);
    let compressed = lzw::encode::encode(data.as_bytes());
    assert!(compressed.len() < data.len(), "should compress");
    let decompressed = lzw::decode::decode(&compressed).unwrap();
    assert_eq!(decompressed, data.as_bytes());
}

#[test]
fn test_lzw_roundtrip_all_max_bits() {
    let data = b"abcdefghij".repeat(100);
    for max_bits in 9..=16u8 {
        let compressed = lzw::encode::encode_with_options(&data, max_bits);
        let decompressed =
            lzw::decode::decode(&compressed).unwrap_or_else(|e| panic!("max_bits={max_bits}: {e}"));
        assert_eq!(decompressed, data, "max_bits={max_bits}");
    }
}

/// Decode a `.Z` file produced by the system `compress` utility.
#[test]
fn test_lzw_decode_system_compress_fixture() {
    // hello.Z is "Hello, World!" compressed with `compress`
    let compressed = include_bytes!("../fixtures/lzw/hello.Z");
    let decompressed = lzw::decode::decode(compressed).unwrap();
    assert_eq!(decompressed, b"Hello, World!");
}

#[test]
fn test_lzw_encode_writer_decode_reader_roundtrip() {
    use std::io::Cursor;

    let input = b"lzw writer reader integration payload ".repeat(256);
    let mut encoded = Vec::new();
    let written = lzw::encode::encode_writer(&input, &mut encoded).unwrap();

    assert_eq!(written, encoded.len());

    let decoded = lzw::decode::decode_reader(Cursor::new(&encoded)).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzw_encode_decoded_by_system_uncompress() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_uncompress = Command::new("uncompress").arg("-V").output().is_ok()
        || Command::new("gzip").arg("--version").output().is_ok();
    if !has_uncompress {
        return;
    }

    let input = b"system uncompress integration payload ".repeat(192);
    let encoded = lzw::encode::encode(&input);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("archive_test_lzw_{uniq}.Z"));
    std::fs::write(&path, &encoded).unwrap();

    let output = if Command::new("uncompress").arg("-V").output().is_ok() {
        Command::new("uncompress")
            .args(["-c"])
            .arg(&path)
            .output()
            .unwrap()
    } else {
        Command::new("gzip")
            .args(["-d", "-c", "-S", ".Z"])
            .arg(&path)
            .output()
            .unwrap()
    };
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "system .Z decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
}

/// Encode at max_bits=9 and verify system `uncompress`/`gzip -d` accepts
/// the stream: the dict-full CLEAR must be emit #256 of its run so the
/// compress42.c-family decoder never crosses its phantom width bump
/// (`free_ent > maxcode` widens with no `n_bits < maxbits` guard).
#[test]
fn test_lzw_encode_bits9_decoded_by_system_uncompress() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_uncompress = Command::new("uncompress").arg("-V").output().is_ok()
        || Command::new("gzip").arg("--version").output().is_ok();
    if !has_uncompress {
        return;
    }

    // Both inputs fill the 9-bit dictionary; incrementing-511 is the
    // input behind fuzz failure artifact run-1791251880.
    for input in [
        (0..511u32).map(|i| (i % 256) as u8).collect::<Vec<u8>>(),
        (0..4096u32).map(|i| (i % 256) as u8).collect(),
    ] {
        let encoded = lzw::encode::encode_with_options(&input, 9);

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("archive_test_lzw9_{uniq}.Z"));
        std::fs::write(&path, &encoded).unwrap();

        let output = if Command::new("uncompress").arg("-V").output().is_ok() {
            Command::new("uncompress")
                .args(["-c"])
                .arg(&path)
                .output()
                .unwrap()
        } else {
            Command::new("gzip")
                .args(["-d", "-c", "-S", ".Z"])
                .arg(&path)
                .output()
                .unwrap()
        };
        let _ = std::fs::remove_file(&path);

        assert!(
            output.status.success(),
            "system .Z decode failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, input);
    }
}

#[test]
fn test_lzw_decode_system_compressed_stream() {
    use std::process::{Command, Stdio};

    let has_compress = Command::new("compress").arg("-V").output().is_ok();
    if !has_compress {
        return;
    }

    let input = b"system compress integration payload ".repeat(192);
    let mut child = Command::new("compress")
        .args(["-c"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let decoded = lzw::decode::decode(&output.stdout).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzw_decode_rejects_reserved_header_flags() {
    let mut encoded = lzw::encode::encode(b"reserved flags");
    encoded[2] |= 0x20;

    assert!(matches!(
        lzw::decode::decode(&encoded),
        Err(archive::error::Error::InvalidData(
            "lzw: reserved header flag bits are set"
        ))
    ));
}
