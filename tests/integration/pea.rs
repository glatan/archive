use super::*;

// ============================================================
// pea integration tests (independent Python PEA-writer oracle)
// ============================================================

/// Generate a PEA 1.6 archive with an independent Python writer:
/// archive header + POD stream header (PCOMPRESS2, CRC32 stream and
/// object tags) + a dir, a compressed file, an empty file, an EOA
/// trigger, and stream/volume CRC32 tags.
fn generate_pea() -> Vec<u8> {
    let script = r#"
import struct, zlib, sys

def tag_crc32(b): return struct.pack('<I', zlib.crc32(b) & 0xFFFFFFFF)

out = bytearray()
# archive header: $EA 1 6 CRC32 0 OS=1 dt=1 enc=1 cpu=0 niter=0
out += bytes([0xEA, 1, 6, 2, 0, 1, 1, 1, 0, 0])
# stream header: 00 00 'POD' 00 | PCOMPRESS2 | 0 | CRC32 | CRC32
out += bytes([0,0]) + b'POD' + bytes([0, 2, 0, 2, 2])

def obj(name, isdir, data, mtime=0x5432):
    covered = struct.pack('<H', len(name)) + name + struct.pack('<II', mtime, 0x10 if isdir else 0)
    if isdir:
        return covered + tag_crc32(covered)
    covered += struct.pack('<Q', len(data))
    wire = struct.pack('<H', len(name)) + name + struct.pack('<II', mtime, 0) + struct.pack('<Q', len(data))
    if len(data) > 0:
        comp = zlib.compress(data, 6)
        covered += struct.pack('<I', len(comp)) + data + struct.pack('<I', len(data))
        wire += struct.pack('<I', len(comp)) + comp + struct.pack('<I', len(data))
    return wire + tag_crc32(covered)

out += obj(b'mydir', True, b'')
out += obj(b'mydir/a.txt', False, b'pea compressed payload ' * 3)
out += obj(b'empty.bin', False, b'')
out += bytes([0,0]) + b'EOA' + bytes([0])
out += tag_crc32(out)   # stream tag
out += tag_crc32(out)   # volume tag
sys.stdout.buffer.write(out)
"#;
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "python3 pea generator failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn test_pea_python_oracle() {
    if !python3_available() {
        return;
    }
    let f = generate_pea();
    let img = pea::decode::decode(&f).unwrap();
    assert_eq!(img.version, (1, 6));
    assert_eq!(img.entries.len(), 3);
    assert!(img.entries[0].is_dir);
    assert_eq!(img.entries[0].name, "mydir");
    assert_eq!(img.entries[1].name, "mydir/a.txt");
    assert_eq!(img.entries[1].data, b"pea compressed payload ".repeat(3));
    assert!(!img.entries[2].is_dir);
    assert!(img.entries[2].data.is_empty());
}

#[test]
fn test_pea_codec_trait() {
    let codec = pea::PeaCodec;
    use archive::traits::{ArchiveDecode, ArchiveEntry};
    let entries = codec.decode(&generate_pea()).unwrap();
    assert!(entries.iter().any(|e| e.name() == "mydir/a.txt"));
}

#[test]
fn test_pea_rejects_truncated() {
    if !python3_available() {
        return;
    }
    let f = generate_pea();
    // cut inside the file data area
    assert!(pea::decode::decode(&f[..f.len() - 20]).is_err());
    // cut inside a compressed block
    assert!(pea::decode::decode(&f[..30]).is_err());
}

/// Verify an archive produced by `pea::encode::PeaEncoder` with an
/// independent Python reader: parses the archive/stream headers,
/// objects, compressed blocks, and every integrity tag. Emits one
/// `name<TAB>is_dir<TAB>hexdata` line per object on stdout.
fn parse_pea_python(data: &[u8]) -> Vec<(String, bool, Vec<u8>)> {
    let script = r#"
import struct, sys, zlib

d = sys.stdin.buffer.read()
TAG_SIZE = {0:0, 1:4, 2:4, 3:8, 16:16, 17:20, 18:20, 19:32, 20:64,
            21:64, 22:32, 23:64, 24:32, 25:64}
def tag(algo, covered):
    if algo == 1: return struct.pack('<I', zlib.adler32(covered) & 0xFFFFFFFF)
    if algo == 2: return struct.pack('<I', zlib.crc32(covered) & 0xFFFFFFFF)
    return None

pos = 0
assert d[0] == 0xEA and d[1] <= 1
vol_algo = d[3]
pos = 10
entries = []
assert d[pos:pos+6] == b'\x00\x00POD\x00'
compression, ecc, stream_algo, obj_algo = d[pos+6], d[pos+7], d[pos+8], d[pos+9]
assert ecc == 0 and stream_algo in TAG_SIZE and obj_algo in TAG_SIZE
pos += 10
while True:
    (nlen,) = struct.unpack_from('<H', d, pos); pos += 2
    if nlen == 0:
        trig = d[pos:pos+4]; pos += 4
        assert trig == b'EOA\x00'
        break
    name = d[pos:pos+nlen]; pos += nlen
    mtime, attrs = struct.unpack_from('<II', d, pos); pos += 8
    covered = struct.pack('<H', nlen) + name + struct.pack('<II', mtime, attrs)
    data = b''
    if not (attrs & 0x10):
        (fsize,) = struct.unpack_from('<Q', d, pos); pos += 8
        covered += struct.pack('<Q', fsize)
        if compression == 0:
            data = d[pos:pos+fsize]; pos += fsize
            covered += data
        elif fsize > 0:
            remaining = fsize
            while remaining > 0:
                (csz,) = struct.unpack_from('<I', d, pos); pos += 4
                block = d[pos:pos+csz]; pos += csz
                want = min(remaining, 1048576)
                chunk = block if csz == want else zlib.decompress(block)
                assert len(chunk) == want
                covered += struct.pack('<I', csz) + chunk
                data += chunk
                remaining -= want
            (last,) = struct.unpack_from('<I', d, pos); pos += 4
            covered += struct.pack('<I', last)
    tsz = TAG_SIZE[obj_algo]
    t = d[pos:pos+tsz]; pos += tsz
    expected = tag(obj_algo, covered)
    assert expected is None or t == expected
    sys.stdout.write('%s\t%d\t%s\n' % (
        name.decode('utf-8'), 1 if (attrs & 0x10) else 0, data.hex()))
tsz = TAG_SIZE[stream_algo]
t = d[pos:pos+tsz]; pos += tsz
expected = tag(stream_algo, d[:pos-tsz])
assert expected is None or t == expected
tsz = TAG_SIZE[vol_algo]
t = d[pos:pos+tsz]; pos += tsz
expected = tag(vol_algo, d[:pos-tsz])
assert expected is None or t == expected
assert pos == len(d)
"#;
    let mut child = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("python3");
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), data).unwrap();
    let out = child.wait_with_output().expect("python3");
    assert!(
        out.status.success(),
        "python3 pea parser failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let mut f = line.split('\t');
            let name = f.next().unwrap().to_string();
            let is_dir = f.next().unwrap() == "1";
            let hex = f.next().unwrap();
            let data = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            (name, is_dir, data)
        })
        .collect()
}

#[test]
fn test_pea_encode_python_oracle() {
    if !python3_available() {
        return;
    }
    let mut enc = pea::encode::PeaEncoder::new();
    enc.add_dir("mydir");
    enc.add_file(
        "mydir/a.txt",
        b"pea compressed payload ".repeat(3).as_slice(),
    );
    enc.add_file("empty.bin", b"");
    let entries = parse_pea_python(&enc.finish().unwrap());
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].0, "mydir");
    assert!(entries[0].1);
    assert_eq!(entries[1].0, "mydir/a.txt");
    assert_eq!(entries[1].2, b"pea compressed payload ".repeat(3));
    assert_eq!(entries[2].0, "empty.bin");
    assert!(entries[2].2.is_empty());
}

#[test]
fn test_pea_encode_stored_python_oracle() {
    if !python3_available() {
        return;
    }
    let mut enc = pea::encode::PeaEncoder::new()
        .compression(pea::encode::PeaCompression::Store)
        .object_control(pea::decode::PeaAlgo::Adler32);
    enc.add_file("plain.txt", b"stored payload");
    let entries = parse_pea_python(&enc.finish().unwrap());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "plain.txt");
    assert_eq!(entries[0].2, b"stored payload");
}

#[test]
fn test_pea_archive_encoder_trait() {
    use archive::traits::ArchiveEncode;
    let mut enc = pea::PeaArchiveEncoder::new();
    enc.add_file("t.txt", b"trait path");
    let f = enc.finish().unwrap();
    let img = pea::decode::decode(&f).unwrap();
    assert_eq!(img.entries[0].name, "t.txt");
    assert_eq!(img.entries[0].data, b"trait path");
}
