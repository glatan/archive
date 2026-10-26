use super::*;

// ============================================================
// crx3 integration tests (independent Python protobuf oracle)
// ============================================================

/// Generate a CRX3 file with an independent Python protobuf writer:
/// Cr24 magic + version 3 + header length + CrxFileHeader protobuf
/// (one RSA proof, crx_id in signed_header_data) + a stored ZIP.
fn generate_crx3() -> Vec<u8> {
    let script = r#"
import struct, zipfile, io, sys

def varint(v):
    out = b''
    while True:
        b = v & 0x7F
        v >>= 7
        if v == 0:
            return out + bytes([b])
        out += bytes([b | 0x80])

def len_field(f, data):
    return varint(f << 3 | 2) + varint(len(data)) + data

# AsymmetricKeyProof { public_key=1, signature=2 }
proof = len_field(1, b'PUBKEY-DER-BYTES') + len_field(2, b'SIGNATURE-BYTES')
# SignedData { crx_id=1 }
signed = len_field(1, bytes(range(16)))
# CrxFileHeader: sha256_with_rsa=2, signed_header_data=10000
hdr = len_field(2, proof) + len_field(10000, signed)

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('manifest.json', b'{"manifest_version":3}')
    z.writestr('bg/worker.js', b'let x = 1;')
zdata = buf.getvalue()

out = b'Cr24' + struct.pack('<I', 3) + struct.pack('<I', len(hdr)) + hdr + zdata
sys.stdout.buffer.write(out)
"#;
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("python3");
    assert!(out.status.success(), "python3 crx3 generator failed");
    out.stdout
}

#[test]
fn test_crx3_python_oracle() {
    if !python3_available() {
        return;
    }
    let f = generate_crx3();
    let img = crx3::decode::decode(&f).unwrap();
    assert_eq!(
        img.crx_id,
        Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    );
    assert_eq!(img.proofs.len(), 1);
    assert_eq!(
        img.proofs[0].algorithm,
        crx3::decode::ProofAlgorithm::Sha256WithRsa
    );
    assert_eq!(img.proofs[0].public_key, b"PUBKEY-DER-BYTES");
    assert_eq!(img.proofs[0].signature, b"SIGNATURE-BYTES");
    assert_eq!(img.entries.len(), 2);
    assert_eq!(img.entries[0].name, "manifest.json");
    assert_eq!(img.entries[1].name, "bg/worker.js");
    assert_eq!(img.entries[1].data, b"let x = 1;");
}

#[test]
fn test_crx3_rejects_non_zip_tail() {
    if !python3_available() {
        return;
    }
    // header parses but the archive tail is not a ZIP
    let f = generate_crx3();
    let mut f2 = f.clone();
    // header len at offset 8: clobber first archive byte
    let n = u32::from_le_bytes(f2[8..12].try_into().unwrap()) as usize;
    f2[12 + n] = b'X';
    assert!(crx3::decode::decode(&f2).is_err());
}
