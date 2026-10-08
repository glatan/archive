use super::*;

#[cfg(feature = "rzip")]
fn assert_rzip_encode_system_decode_compat(level: u8, archive_stem: &str, expected: &[u8]) {
    let archive = rzip::encode::encode_with_level(expected, level);
    assert_rzip_archive_system_decode_compat(archive, archive_stem, expected);
}

#[cfg(feature = "rzip")]
fn assert_rzip_archive_system_decode_compat(archive: Vec<u8>, archive_stem: &str, expected: &[u8]) {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = rzip_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rzip_encode_{archive_stem}_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let archive_path = dir.join(format!("{archive_stem}.rz"));
    let output_path = dir.join("decoded.bin");

    std::fs::write(&archive_path, &archive).unwrap();

    let output = Command::new(cmd)
        .args(["-d", "-k", "-f", "-o"])
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

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_roundtrip_level_matrix() {
    let input = b"rzip level matrix payload ".repeat(8192);

    for level in [0u8, 1, 6, 9] {
        let encoded = rzip::encode::encode_with_level(&input, level);
        let decoded = rzip::decode::decode(&encoded).unwrap();
        assert_eq!(decoded, input, "rzip roundtrip failed for level {level}");
    }
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_roundtrip_binary_payload() {
    let input: Vec<u8> = (0..131_072u32).map(|i| ((i * 37) % 251) as u8).collect();

    let encoded = rzip::encode::encode(&input);
    let decoded = rzip::decode::decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_decode_system_archive() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(cmd) = rzip_binary() else {
        return;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_rzip_decode_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let input_path = dir.join("hello.txt");
    let archive_path = dir.join("hello.rz");
    std::fs::write(&input_path, b"Hello from rzip").unwrap();

    let output = Command::new(cmd)
        .args([
            "-k",
            "-f",
            "-o",
            archive_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{cmd} compress failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let archive = std::fs::read(&archive_path).unwrap();
    let decoded = rzip::decode::decode(&archive).unwrap();
    assert_eq!(decoded, b"Hello from rzip");

    let _ = std::fs::remove_file(&archive_path);
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_encode_system_decode_compat() {
    assert_rzip_encode_system_decode_compat(6, "encoded_text", b"Hello from crate rzip encoder");
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_encode_system_decode_binary_payload() {
    let input: Vec<u8> = (0..1_048_576u32).map(|i| ((i * 37) % 251) as u8).collect();
    assert_rzip_encode_system_decode_compat(6, "encoded_binary", &input);
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_encode_system_decode_multichunk_payload() {
    let input = (b"chunk-boundary-rzip-"
        .repeat((100 * 1024 * 1024 + 4096) / b"chunk-boundary-rzip-".len() + 1))
        [..100 * 1024 * 1024 + 4096]
        .to_vec();
    assert_rzip_encode_system_decode_compat(1, "encoded_multichunk", &input);
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_encode_system_decode_level_edges() {
    let input = b"rzip level edge payload ".repeat(4096);
    assert_rzip_encode_system_decode_compat(0, "encoded_l0", &input);
    assert_rzip_encode_system_decode_compat(9, "encoded_l9", &input);
}

#[cfg(feature = "rzip")]
#[test]
fn test_rzip_encode_system_decode_backend_matrix() {
    use rzip::encode::Backend;
    let input = b"rzip backend payload ".repeat(2048);
    for (stem, backend) in [
        ("b_none", Backend::None),
        ("b_gzip", Backend::Gzip),
        ("b_lzo", Backend::Lzo),
        ("b_bzip2", Backend::Bzip2),
    ] {
        let archive = rzip::encode::encode_with_backend(&input, backend);
        // Upstream rzip 2.1 only supports CTYPE_NONE(3)/CTYPE_BZIP2(4);
        // GZIP/LZO ctypes are lrzip-derived crate extensions that system
        // rzip cannot decode, so they only get a crate roundtrip check.
        match backend {
            Backend::Gzip | Backend::Lzo => {
                assert_eq!(rzip::decode::decode(&archive).unwrap(), input);
            }
            _ => assert_rzip_archive_system_decode_compat(archive, stem, &input),
        }
    }
}
