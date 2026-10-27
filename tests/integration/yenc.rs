use super::*;

// ============================================================
// yEnc tests
// ============================================================

#[test]
fn test_yenc_roundtrip() {
    let data: Vec<u8> = (0..=255u8).chain(0..200u8).collect();
    let doc = yenc::encode("sample.bin", &data);
    let e = yenc::decode(&doc).unwrap();
    assert_eq!(e.name, "sample.bin");
    assert_eq!(e.data, data);
}

#[test]
fn test_yenc_multipart_roundtrip() {
    let whole: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    let doc = yenc::encode_part("m.bin", 1, 2, 1, &whole[..200], whole.len() as u64);
    let e = yenc::decode(&doc).unwrap();
    assert_eq!(e.name, "m.bin");
    assert_eq!(e.part, Some(1));
    assert_eq!(e.range, Some((1, 200)));
    assert_eq!(e.data, whole[..200]);
}

#[test]
fn test_yenc_python_reference_decodes_ours() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Independent spec-faithful reference decoder (per yEnc draft 1.3):
    // rotate -42 mod 256, '=' escapes decode via -64-42.
    let script = concat!(
        "import sys, zlib\n",
        "doc = sys.stdin.buffer.read()\n",
        "lines = doc.split(b'\\n')\n",
        "i = next(k for k, l in enumerate(lines)\n",
        "         if l.startswith(b'=ybegin ') and b'size=' in l and b'name=' in l)\n",
        "hdr = lines[i]\n",
        "size = int(next(t[5:] for t in hdr.split() if t.startswith(b'size=')))\n",
        "body = []\n",
        "j = i + 1\n",
        "if b'part=' in hdr:\n",
        "    j += 1  # skip =ypart\n",
        "while not lines[j].startswith(b'=yend'):\n",
        "    body.append(lines[j].rstrip(b'\\r \\t'))\n",
        "    j += 1\n",
        "out = bytearray()\n",
        "for l in body:\n",
        "    k = 0\n",
        "    while k < len(l):\n",
        "        if l[k] == 61:\n",
        "            out.append((l[k+1] - 64 - 42) % 256)\n",
        "            k += 2\n",
        "        else:\n",
        "            out.append((l[k] - 42) % 256)\n",
        "            k += 1\n",
        "assert len(out) == size, (len(out), size)\n",
        "sys.stdout.buffer.write(bytes(out))\n",
    );
    let data: Vec<u8> = (0..=255u8).chain(0..200u8).collect();
    let doc = yenc::encode("ref.bin", &data);
    let mut child = match Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            if require_external_tools() {
                panic!("required external tool is unavailable: python3");
            }
            return;
        } // python3 not available
    };
    child.stdin.take().unwrap().write_all(&doc).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, data);
}

#[test]
fn test_yenc_decodes_python_reference_output() {
    use std::process::Command;

    // Reference encoder per spec (+42 rotate, escape 0/9/10/13/61 and
    // leading/trailing space/tab, CRLF lines).
    let script = concat!(
        "import sys, zlib\n",
        "data = bytes(range(256)) + bytes(range(100))\n",
        "out = [b'=ybegin line=128 size=%d name=py.bin\\r\\n' % len(data)]\n",
        "line = bytearray()\n",
        "for b in data:\n",
        "    c = (b + 42) % 256\n",
        "    esc = c in (0, 10, 13, 61) or (len(line) == 0 and c in (9, 32)) \\\n",
        "        or (len(line) + 1 >= 128 and c in (9, 32))\n",
        "    if esc:\n",
        "        line += b'=' + bytes([(c + 64) % 256])\n",
        "    else:\n",
        "        line.append(c)\n",
        "    if len(line) >= 128:\n",
        "        out.append(bytes(line) + b'\\r\\n')\n",
        "        line = bytearray()\n",
        "if line:\n",
        "    out.append(bytes(line) + b'\\r\\n')\n",
        "out.append(b'=yend size=%d crc32=%08x\\r\\n' % (len(data), zlib.crc32(data)))\n",
        "sys.stdout.buffer.write(b''.join(out))\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        if require_external_tools() {
            panic!("required external tool is unavailable: python3");
        }
        return; // python3 not available
    };
    assert!(result.status.success());
    let e = yenc::decode(&result.stdout).unwrap();
    assert_eq!(e.name, "py.bin");
    let expected: Vec<u8> = (0..=255u8).chain(0..100u8).collect();
    assert_eq!(e.data, expected);
}
