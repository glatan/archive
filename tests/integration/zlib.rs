use super::*;

fn python_zlib_compress(input: &[u8], level: u8) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let script = r#"import sys, zlib
level = int(sys.argv[1])
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(zlib.compress(data, level))
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
        "python zlib compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

fn python_zlib_decode(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let script = r#"import sys, zlib
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(zlib.decompress(data))
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
        "python zlib decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

// ============================================================
// zlib tests
// ============================================================

#[test]
fn test_zlib_roundtrip_large_integration() {
    let input = b"zlib integration payload ".repeat(1024);
    let encoded = zlib::encode::encode(&input);
    let decoded = zlib::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zlib_empty_stream_roundtrip() {
    let encoded = zlib::encode::encode(b"");
    let decoded = zlib::decode::decode(&encoded).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn test_zlib_decode_python_zlib_stream() {
    let input = b"python zlib stream integration payload ".repeat(256);
    let Some(encoded) = python_zlib_compress(&input, 6) else {
        return;
    };

    let decoded = zlib::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_zlib_encode_stream_decoded_by_python() {
    let input = b"archive zlib stream for python decode ".repeat(256);
    let encoded = zlib::encode::encode(&input);
    let Some(decoded) = python_zlib_decode(&encoded) else {
        return;
    };
    assert_eq!(decoded, input);
}

#[test]
fn test_zlib_decode_rejects_preset_dictionary_flag() {
    let input = b"zlib preset dictionary flag";
    let mut encoded = zlib::encode::encode(input);
    let flg_base = (encoded[1] & 0xC0) | 0x20;
    let check = (encoded[0] as u16) * 256 + (flg_base as u16);
    let fcheck = (31 - (check % 31)) % 31;
    encoded[1] = flg_base | fcheck as u8;

    assert!(matches!(
        zlib::decode::decode(&encoded),
        Err(archive::error::Error::Unsupported(
            "zlib: preset dictionary not supported"
        ))
    ));
}

#[test]
fn test_zlib_decode_detects_adler32_mismatch() {
    let mut encoded = zlib::encode::encode(b"zlib adler mismatch");
    let trailer_start = encoded.len() - 4;
    encoded[trailer_start] ^= 0x01;

    assert!(matches!(
        zlib::decode::decode(&encoded),
        Err(archive::error::Error::ChecksumMismatch { .. })
    ));
}
