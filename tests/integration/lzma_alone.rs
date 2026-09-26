use super::*;

// ============================================================
// LZMA-Alone `.lzma` tests
// ============================================================

fn xz_lzma_system_compress(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;

    let mut child = match std::process::Command::new("xz")
        .args(["--format=lzma", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run xz: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system xz --format=lzma compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

fn xz_lzma_system_decode(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;

    let mut child = match std::process::Command::new("xz")
        .args(["--format=lzma", "-dc"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("Failed to run xz: {e}"),
    };

    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "system xz --format=lzma decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(output.stdout)
}

#[test]
fn test_lzma_alone_roundtrip_large() {
    let mut data = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        data.push((i % 251) as u8);
    }
    let compressed = lzma_alone::encode::encode(&data);
    let decoded = lzma_alone::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_lzma_alone_roundtrip_empty() {
    let input = b"";
    let compressed = lzma_alone::encode::encode(input);
    let decoded = lzma_alone::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzma_alone_roundtrip_tiny() {
    for input in [b"a".as_slice(), b"hi", b"tiny payload"] {
        let compressed = lzma_alone::encode::encode(input);
        let decoded = lzma_alone::decode::decode(&compressed).unwrap();
        assert_eq!(decoded, input);
    }
}

#[test]
fn test_lzma_alone_roundtrip_high_entropy() {
    let input: Vec<u8> = (0..65_536u32)
        .map(|i| ((i.wrapping_mul(73) ^ 0xA5A5) & 0xFF) as u8)
        .collect();

    let compressed = lzma_alone::encode::encode(&input);
    let decoded = lzma_alone::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzma_alone_decode_system_compressed() {
    // xz --format=lzma emits a .lzma file with an unknown-size header field
    // (0xFFFF_FFFF_FFFF_FFFF) and an end-of-payload marker.
    let input = b"Hello, lzma-alone interop!\n";
    let Some(compressed) = xz_lzma_system_compress(input) else {
        return;
    };

    assert!(compressed.len() > 13);
    assert_eq!(
        u64::from_le_bytes(compressed[5..13].try_into().unwrap()),
        u64::MAX
    );

    let decoded = lzma_alone::decode::decode(&compressed).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_lzma_alone_encode_decoded_by_system() {
    let input = b"The quick brown fox jumps over the lazy dog. Testing lzma-alone interop!";
    let compressed = lzma_alone::encode::encode(input);

    match xz_lzma_system_decode(&compressed) {
        Some(stdout) => assert_eq!(stdout, input),
        None => {
            let decoded = lzma_alone::decode::decode(&compressed).unwrap();
            assert_eq!(decoded, input);
        }
    }
}
