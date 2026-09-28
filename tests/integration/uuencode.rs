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
