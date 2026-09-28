use super::*;

// ============================================================
// MacBinary tests
// ============================================================

#[test]
fn test_macbinary_roundtrip() {
    let e = macbinary::MacBinaryEntry {
        name: "doc.txt".into(),
        file_type: *b"TEXT",
        creator: *b"ttxt",
        finder_flags: 0,
        protected: false,
        data: b"hello mac".to_vec(),
        resource: b"rsrc data".to_vec(),
        creation_date: 3_000_000_000,
        modification_date: 3_000_000_001,
        macbinary2: true,
    };
    let d = macbinary::decode(&macbinary::encode(&e)).unwrap();
    assert_eq!(d, e);
}

#[test]
fn test_macbinary_python_reference_decodes_ours() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Independent spec-faithful reference decoder (MacBinary II proposal):
    // verifies zero bytes, name length, CRC-16/CCITT over 124 bytes, and
    // extracts the forks.
    let script = concat!(
        "import sys\n",
        "doc = sys.stdin.buffer.read()\n",
        "h = doc[:128]\n",
        "assert h[0] == 0 and h[74] == 0\n",
        "crc = 0\n",
        "for b in h[:124]:\n",
        "    crc ^= b << 8\n",
        "    for _ in range(8):\n",
        "        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF\n",
        "assert crc == int.from_bytes(h[124:126], 'big')\n",
        "assert h[123] <= 129\n",
        "n = h[1]\n",
        "assert 1 <= n <= 63\n",
        "name = h[2:2+n].decode('latin-1')\n",
        "dlen = int.from_bytes(h[83:87], 'big')\n",
        "rlen = int.from_bytes(h[87:91], 'big')\n",
        "sec = ((int.from_bytes(h[120:122], 'big') + 127) // 128) * 128\n",
        "pos = 128 + sec\n",
        "data = doc[pos:pos+dlen]\n",
        "pos += (dlen + 127) // 128 * 128\n",
        "rsrc = doc[pos:pos+rlen]\n",
        "sys.stdout.write(name + '|' + str(len(data)) + '|' + str(len(rsrc)) + '\\n')\n",
        "sys.stdout.flush()\n",
        "sys.stdout.buffer.write(data + b'|' + rsrc)\n",
    );
    let e = macbinary::MacBinaryEntry {
        name: "ref.bin".into(),
        file_type: *b"BINA",
        creator: *b"xxxx",
        finder_flags: 0,
        protected: false,
        data: (0..=255u8).chain(0..100u8).collect(),
        resource: b"resource-fork".to_vec(),
        creation_date: 0,
        modification_date: 0,
        macbinary2: true,
    };
    let doc = macbinary::encode(&e);
    let mut child = match Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    child.stdin.take().unwrap().write_all(&doc).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(
        out.stdout[..out.stdout.iter().position(|&b| b == b'\n').unwrap()].to_vec(),
    )
    .unwrap();
    assert_eq!(text, "ref.bin|356|13");
    let body = &out.stdout[text.len() + 1..];
    let (d, r) = body.split_at(e.data.len());
    assert_eq!(d, e.data.as_slice());
    assert_eq!(&r[1..], e.resource.as_slice());
}

#[test]
fn test_macbinary_decodes_python_reference_output() {
    use std::process::Command;

    // Reference encoder per the MB II proposal (independent impl).
    let script = concat!(
        "import sys\n",
        "name = b'pyfile.dat'\n",
        "data = bytes(range(256)) + bytes(range(50))\n",
        "rsrc = b'RSRC!'\n",
        "h = bytearray(128)\n",
        "h[1] = len(name)\n",
        "h[2:2+len(name)] = name\n",
        "h[65:69] = b'BINA'\n",
        "h[69:73] = b'pyer'\n",
        "h[83:87] = len(data).to_bytes(4, 'big')\n",
        "h[87:91] = len(rsrc).to_bytes(4, 'big')\n",
        "h[91:95] = (2900000000).to_bytes(4, 'big')\n",
        "h[95:99] = (2900000001).to_bytes(4, 'big')\n",
        "h[122] = h[123] = 129\n",
        "crc = 0\n",
        "for b in h[:124]:\n",
        "    crc ^= b << 8\n",
        "    for _ in range(8):\n",
        "        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF\n",
        "h[124:126] = crc.to_bytes(2, 'big')\n",
        "def pad(b):\n",
        "    return b + b'\\0' * ((-len(b)) % 128)\n",
        "sys.stdout.buffer.write(bytes(h) + pad(data) + pad(rsrc))\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        return;
    };
    assert!(result.status.success());
    let e = macbinary::decode(&result.stdout).unwrap();
    assert_eq!(e.name, "pyfile.dat");
    assert_eq!(&e.file_type, b"BINA");
    assert_eq!(&e.creator, b"pyer");
    assert!(e.macbinary2);
    let expected: Vec<u8> = (0..=255u8).chain(0..50u8).collect();
    assert_eq!(e.data, expected);
    assert_eq!(e.resource, b"RSRC!");
    assert_eq!(e.creation_date, 2_900_000_000);
    assert_eq!(e.modification_date, 2_900_000_001);
}
