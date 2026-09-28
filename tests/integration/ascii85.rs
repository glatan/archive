use super::*;

// ============================================================
// ascii85 tests
// ============================================================

#[test]
fn test_ascii85_adobe_roundtrip() {
    let data: Vec<u8> = (0..=255u8).chain(0..50u8).collect();
    let enc = ascii85::encode(&data);
    assert_eq!(ascii85::decode(&enc).unwrap(), data);
}

#[test]
fn test_ascii85_python_a85decode_compat() {
    use std::process::Command;

    // CPython base64.a85decode must decode our Adobe output
    // (foldspaces=False default is fine; adobe=True expects <~ ~>).
    let data: Vec<u8> = (0..=255u8).chain(0..50u8).collect();
    let enc = ascii85::encode(&data);
    let path = std::env::temp_dir().join("archive_test_a85.txt");
    std::fs::write(&path, &enc).unwrap();

    let script = concat!(
        "import base64, sys\n",
        "data = open(sys.argv[1], 'rb').read()\n",
        "sys.stdout.buffer.write(base64.a85decode(data, adobe=True))\n",
    );
    let output = Command::new("python3")
        .args(["-c", script])
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let Ok(result) = output else {
        return; // python3 not available
    };
    assert!(result.status.success(), "a85decode failed");
    assert_eq!(result.stdout, data);
}

#[test]
fn test_ascii85_python_a85encode_decode() {
    use std::process::Command;

    // CPython base64.a85encode output must decode identically here.
    let script = concat!(
        "import base64, sys\n",
        "data = bytes(range(256)) + bytes(range(50))\n",
        "sys.stdout.buffer.write(base64.a85encode(data, adobe=True))\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        return; // python3 not available
    };
    assert!(result.status.success());
    let expected: Vec<u8> = (0..=255u8).chain(0..50u8).collect();
    assert_eq!(ascii85::decode(&result.stdout).unwrap(), expected);
}

#[test]
fn test_ascii85_rfc1924_python_b85_compat() {
    use std::process::Command;

    // CPython base64.b85encode uses the RFC 1924 alphabet but encodes
    // per 4-octet group (git-style). For a 16-octet input with 12
    // leading zero octets the trailing 5 RFC 1924 digits must equal
    // python's encoding of the last group — a cross-implementation
    // check of the alphabet and digit order.
    let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF];
    let ours = ascii85::encode_rfc1924(&addr).unwrap();

    let script = concat!(
        "import base64, sys
",
        "data = sys.stdin.buffer.read()
",
        "sys.stdout.buffer.write(base64.b85encode(data))
",
    );
    let spawned = Command::new("python3")
        .args(["-c", script])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn();
    let Ok(mut child) = spawned else {
        return;
    };
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&addr[12..])
        .unwrap();
    drop(child.stdin.take());
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    // ours = 15 leading '0' digits + 5 trailing digits == python group.
    assert_eq!(&ours[..15], b"000000000000000");
    assert_eq!(&ours[15..], &result.stdout[..]);
}
