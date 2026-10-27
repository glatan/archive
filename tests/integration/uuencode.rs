use super::*;

// ============================================================
// uuencode tests
// ============================================================

#[test]
fn test_uuencode_roundtrip() {
    let data: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    let doc = uuencode::encode("sample.bin", 0o644, &data);
    let e = uuencode::decode(&doc).unwrap();
    assert_eq!(e.name, "sample.bin");
    assert_eq!(e.mode, 0o644);
    assert_eq!(e.data, data);
}

#[test]
fn test_uuencode_python_b2a_uu_decode() {
    use std::process::Command;

    // Lines produced by CPython binascii.b2a_uu (space zero encoding) must
    // decode to the same octets.
    let script = concat!(
        "import binascii\n",
        "data = bytes(range(256)) + bytes(range(100))\n",
        "out = []\n",
        "out.append('begin 644 py.bin')\n",
        "for i in range(0, len(data), 45):\n",
        "    out.append(binascii.b2a_uu(data[i:i+45]).decode().rstrip('\\n'))\n",
        "out.append(' ')\n",
        "out.append('end')\n",
        "import sys\n",
        "sys.stdout.write('\\n'.join(out) + '\\n')\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        if require_external_tools() {
            panic!("required external tool is unavailable: python3");
        }
        return; // python3 not available
    };
    assert!(result.status.success());
    let e = uuencode::decode(&result.stdout).unwrap();
    assert_eq!(e.name, "py.bin");
    assert_eq!(e.mode, 0o644);
    let expected: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    assert_eq!(e.data, expected);
}

#[test]
fn test_uuencode_python_a2b_uu_decodes_ours() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Our data lines must be decodable by CPython binascii.a2b_uu.
    let data: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    let doc = uuencode::encode("ours.bin", 0o600, &data);

    // Extract data lines (between 'begin' and the zero-length marker + 'end').
    let doc_str = String::from_utf8(doc).unwrap();
    let lines: Vec<&str> = doc_str.lines().collect();
    let body = lines[1..lines.len() - 2].join("\n");

    let script = concat!(
        "import binascii, sys\n",
        "for line in sys.stdin:\n",
        "    sys.stdout.buffer.write(binascii.a2b_uu(line))\n",
    );
    let spawned = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = spawned else {
        return; // python3 not available
    };
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, data);
}

#[test]
fn test_uuencode_base64_roundtrip() {
    let data: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    let doc = uuencode::encode_base64("sample.bin", 0o644, &data);
    let e = uuencode::decode(&doc).unwrap();
    assert_eq!(e.name, "sample.bin");
    assert_eq!(e.mode, 0o644);
    assert_eq!(e.data, data);
}

#[test]
fn test_uuencode_base64_posix_doc() {
    // begin-base64 ... ==== document per POSIX.1-2017 STDOUT rules.
    let doc = b"begin-base64 644 hello.txt\nSGVsbG8sIHdvcmxkIQ==\n====\n";
    let e = uuencode::decode(doc).unwrap();
    assert_eq!(e.name, "hello.txt");
    assert_eq!(e.mode, 0o644);
    assert_eq!(e.data, b"Hello, world!");
}

#[test]
fn test_uuencode_base64_python_decode() {
    use std::process::Command;

    // Documents produced with python's base64 must decode to the same
    // octets.
    let script = concat!(
        "import base64, sys\n",
        "data = bytes(range(256)) + bytes(range(100))\n",
        "b64 = base64.b64encode(data).decode()\n",
        "sys.stdout.write('begin-base64 644 py.bin\\n')\n",
        "for i in range(0, len(b64), 76):\n",
        "    sys.stdout.write(b64[i:i+76] + '\\n')\n",
        "sys.stdout.write('====\\n')\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        if require_external_tools() {
            panic!("required external tool is unavailable: python3");
        }
        return; // python3 not available
    };
    assert!(result.status.success());
    let e = uuencode::decode(&result.stdout).unwrap();
    assert_eq!(e.name, "py.bin");
    assert_eq!(e.mode, 0o644);
    let expected: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    assert_eq!(e.data, expected);
}

#[test]
fn test_uuencode_base64_python_decodes_ours() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // python's base64.b64decode must accept our begin-base64 body.
    let data: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    let doc = uuencode::encode_base64("ours.bin", 0o600, &data);
    let doc_str = String::from_utf8(doc).unwrap();
    let lines: Vec<&str> = doc_str.lines().collect();
    let body = lines[1..lines.len() - 1].join("");

    let script = concat!(
        "import base64, sys\n",
        "sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))\n",
    );
    let spawned = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let Ok(mut child) = spawned else {
        return; // python3 not available
    };
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, data);
}
