use super::*;

// ============================================================
// BinHex tests
// ============================================================

#[test]
fn test_binhex_roundtrip() {
    let e = binhex::BinHexEntry {
        name: "doc.bin".into(),
        file_type: *b"BINA",
        creator: *b"test",
        flags: 0x8000,
        data: (0..=255u8).chain(0..100u8).collect(),
        resource: b"rsrc payload".to_vec(),
    };
    let d = binhex::decode(&binhex::encode(&e)).unwrap();
    assert_eq!(d, e);
}

#[test]
fn test_binhex_crc_matches_python_crc_hqx() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // CPython binascii.crc_hqx is the BinHex augmented CRC-16 oracle:
    // verify our stored header/data/resource CRCs equal crc_hqx over each
    // body plus two zero bytes.
    let script = concat!(
        "import sys, binascii\n",
        "doc = sys.stdin.buffer.read()\n",
        "nl = doc[0]\n",
        "hdr_len = 1 + nl + 1 + 20\n",
        "hdr = doc[:hdr_len-2]\n",
        "assert binascii.crc_hqx(hdr + b'\\0\\0', 0) == \\\n",
        "       int.from_bytes(doc[hdr_len-2:hdr_len], 'big')\n",
        "dlen = int.from_bytes(doc[nl+12:nl+16], 'big')\n",
        "rlen = int.from_bytes(doc[nl+16:nl+20], 'big')\n",
        "p = hdr_len\n",
        "data = doc[p:p+dlen]; p += dlen\n",
        "assert binascii.crc_hqx(data + b'\\0\\0', 0) == \\\n",
        "       int.from_bytes(doc[p:p+2], 'big'); p += 2\n",
        "rsrc = doc[p:p+rlen]; p += rlen\n",
        "assert binascii.crc_hqx(rsrc + b'\\0\\0', 0) == \\\n",
        "       int.from_bytes(doc[p:p+2], 'big')\n",
        "print('CRCS_OK')\n",
    );
    // Reconstruct our raw fork stream via our own encode path: encode a
    // document, decode it in Rust (already verified), and have Python
    // check the raw layer. Build the raw stream in Rust-side by reusing
    // the public encode output is not directly accessible, so feed the
    // decoded entry back through a small re-encoder below instead:
    let e = binhex::BinHexEntry {
        name: "crc.bin".into(),
        file_type: *b"BINA",
        creator: *b"ours",
        flags: 0x8000,
        data: (0..=255u8).chain(0..100u8).collect(),
        resource: b"rsrc-fork".to_vec(),
    };
    // Extract raw stream by decoding our own hqx with a tiny in-test
    // unpacker: take the ':'-delimited region, decode 6-bit + RLE.
    let doc = binhex::encode(&e);
    let colon = doc.iter().position(|&b| b == b':').unwrap();
    let end = doc.iter().rposition(|&b| b == b':').unwrap();
    let mut raw8 = Vec::new();
    {
        // local 6-bit decode of the hqx region (alphabet constant is
        // internal to the module; rebuild it here per spec).
        const ALPHA: &[u8; 64] =
            b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        let mut acc = 0u32;
        let mut nbits = 0u32;
        for &c in &doc[colon + 1..end] {
            if matches!(c, b'\r' | b'\n' | b'\t' | b' ') {
                continue;
            }
            let v = ALPHA.iter().position(|&a| a == c).unwrap() as u32;
            acc = (acc << 6) | v;
            nbits += 6;
            while nbits >= 8 {
                nbits -= 8;
                raw8.push((acc >> nbits) as u8);
            }
        }
    }
    let mut raw = Vec::new();
    {
        let mut i = 0usize;
        while i < raw8.len() {
            let b = raw8[i];
            i += 1;
            if b != 0x90 {
                raw.push(b);
            } else {
                let c = raw8[i] as usize;
                i += 1;
                if c == 0 {
                    raw.push(0x90);
                } else {
                    for _ in 0..c - 1 {
                        raw.push(*raw.last().unwrap());
                    }
                }
            }
        }
    }
    let mut child = match Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    child.stdin.take().unwrap().write_all(&raw).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(out.stdout, b"CRCS_OK\n");
}

#[test]
fn test_binhex_decodes_reference_encoder() {
    use std::process::Command;

    // Independent spec-faithful reference encoder (Peter Lewis definition
    // + RFC 1741): RLE then 6-bit packing with the canonical alphabet.
    let script = concat!(
        "import sys, binascii\n",
        "ALPHA = b'!\"#$%&\\'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr'\n",
        "name = b'pyfile.dat'\n",
        "data = bytes(range(256)) + bytes(range(50)) + bytes([0x90] * 8)\n",
        "rsrc = b'RSRC!'\n",
        "hdr = bytes([len(name)]) + name + b'\\0' + b'TEST' + b'pyer' + \\\n",
        "      (0x8000).to_bytes(2, 'big') + \\\n",
        "      len(data).to_bytes(4, 'big') + len(rsrc).to_bytes(4, 'big')\n",
        "raw = hdr + binascii.crc_hqx(hdr + b'\\0\\0', 0).to_bytes(2, 'big') + data + \\\n",
        "      binascii.crc_hqx(data + b'\\0\\0', 0).to_bytes(2, 'big') + rsrc + \\\n",
        "      binascii.crc_hqx(rsrc + b'\\0\\0', 0).to_bytes(2, 'big')\n",
        "# RLE\n",
        "rle = bytearray()\n",
        "i = 0\n",
        "while i < len(raw):\n",
        "    j = i + 1\n",
        "    while j < len(raw) and raw[j] == raw[i]:\n",
        "        j += 1\n",
        "    run = j - i\n",
        "    if raw[i] == 0x90:\n",
        "        rle += b'\\x90\\x00'\n",
        "        rem = run - 1\n",
        "        while rem > 0:\n",
        "            c = min(rem + 1, 255)\n",
        "            rle += bytes([0x90, c])\n",
        "            rem -= c - 1\n",
        "    elif run >= 4:\n",
        "        rle.append(raw[i])\n",
        "        rem = run\n",
        "        c = min(rem, 255); rle += bytes([0x90, c]); rem -= c\n",
        "        while rem > 0:\n",
        "            c = min(rem + 1, 255); rle += bytes([0x90, c]); rem -= c - 1\n",
        "    else:\n",
        "        rle += raw[i:j]\n",
        "    i = j\n",
        "# 6-bit pack\n",
        "out = []\n",
        "line = ':'\n",
        "acc = 0; nbits = 0\n",
        "for b in rle:\n",
        "    acc = (acc << 8) | b; nbits += 8\n",
        "    while nbits >= 6:\n",
        "        nbits -= 6\n",
        "        line += chr(ALPHA[(acc >> nbits) & 0x3F])\n",
        "        if len(line) == 64:\n",
        "            out.append(line + '\\n'); line = ''\n",
        "if nbits:\n",
        "    line += chr(ALPHA[(acc << (6 - nbits)) & 0x3F])\n",
        "out.append(line + ':\\n')\n",
        "sys.stdout.buffer.write(\n",
        "    b'(This file must be converted with BinHex 4.0)\\r\\n' +\n",
        "    ''.join(out).encode())\n",
    );
    let output = Command::new("python3").args(["-c", script]).output();
    let Ok(result) = output else {
        return;
    };
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let e = binhex::decode(&result.stdout).unwrap();
    assert_eq!(e.name, "pyfile.dat");
    assert_eq!(&e.file_type, b"TEST");
    assert_eq!(&e.creator, b"pyer");
    let mut expected: Vec<u8> = (0..=255u8).chain(0..50u8).collect();
    expected.extend_from_slice(&[0x90; 8]);
    assert_eq!(e.data, expected);
    assert_eq!(e.resource, b"RSRC!");
}
