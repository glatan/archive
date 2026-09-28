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
    let f = generate_pea();
    // cut inside the file data area
    assert!(pea::decode::decode(&f[..f.len() - 20]).is_err());
    // cut inside a compressed block
    assert!(pea::decode::decode(&f[..30]).is_err());
}
