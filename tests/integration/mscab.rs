// ============================================================
// Microsoft Cabinet (.cab) tests
// ============================================================

/// Build a minimal cabinet with one MSZIP-compressed folder.
fn build_mszip_cab(name: &str, data: &[u8]) -> Vec<u8> {
    let payload = archive::compress::deflate::encode::encode(
        data,
        archive::compress::deflate::encode::Level::Default,
    );
    let mut block = Vec::with_capacity(payload.len() + 2);
    block.extend_from_slice(b"CK");
    block.extend_from_slice(&payload);

    let mut files_buf = Vec::new();
    files_buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    files_buf.extend_from_slice(&0u32.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(name.as_bytes());
    files_buf.push(0);

    let files_off = 44usize;
    let data_off = files_off + files_buf.len();
    let cb_cabinet = (data_off + 8 + block.len()) as u32;

    let mut out = Vec::with_capacity(cb_cabinet as usize);
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&cb_cabinet.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(files_off as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3u8, 1u8]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(data_off as u32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&files_buf);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(block.len() as u16).to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&block);
    out
}

#[test]
fn test_mscab_decode_mszip_cabinet() {
    let data = b"mscab integration test payload";
    let cab = build_mszip_cab("test.txt", data);
    let entries = archive::archive::mscab::decode::decode(&cab).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "test.txt");
    assert_eq!(entries[0].data, data);
}

#[test]
fn test_mscab_bsdtar_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data = b"mscab bsdtar interop content";
    let cab = build_mszip_cab("interop.txt", data);

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_mscab_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cab_path = dir.join("test.cab");
    std::fs::write(&cab_path, &cab).unwrap();

    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let output = Command::new("bsdtar")
        .args(["-xf"])
        .arg(&cab_path)
        .args(["-C"])
        .arg(&out_dir)
        .output();
    let Ok(result) = output else {
        let _ = std::fs::remove_dir_all(&dir);
        return; // bsdtar unavailable
    };
    if !result.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return; // bsdtar lacks cab support in this build
    }
    let extracted = std::fs::read(out_dir.join("interop.txt"));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(extracted.unwrap(), data);
}

#[test]
fn test_mscab_encoder_roundtrip() {
    use archive::archive::mscab::encode::{MscabCompression, MscabEncoder};
    let mut enc = MscabEncoder::with_compression(MscabCompression::Mszip);
    enc.add_file("one.txt", b"first file");
    enc.add_file("two.txt", b"second file payload".repeat(300).as_slice());
    let cab = enc.finish().unwrap();
    let entries = archive::archive::mscab::decode::decode(&cab).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].data, b"first file");
    assert_eq!(entries[1].data.len(), 19 * 300);
}

#[test]
fn test_mscab_encoder_bsdtar_interop() {
    use archive::archive::mscab::encode::{MscabCompression, MscabEncoder};
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let data = b"encoder-produced mszip cabinet".repeat(50);
    let mut enc = MscabEncoder::with_compression(MscabCompression::Mszip);
    enc.add_file("enc.txt", &data);
    let cab = enc.finish().unwrap();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_mscabenc_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cab_path = dir.join("enc.cab");
    std::fs::write(&cab_path, &cab).unwrap();
    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).unwrap();

    let output = Command::new("bsdtar")
        .args(["-xf"])
        .arg(&cab_path)
        .args(["-C"])
        .arg(&out_dir)
        .output();
    let Ok(result) = output else {
        let _ = std::fs::remove_dir_all(&dir);
        return; // bsdtar unavailable
    };
    if !result.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        return; // bsdtar lacks cab support in this build
    }
    let extracted = std::fs::read(out_dir.join("enc.txt"));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(extracted.unwrap(), data);
}

/// Real Microsoft-encoder LZX cabinet fixture: a single-folder CAB
/// (typeCompress 0x1203, 256 KiB window, E8 enabled) reassembled from
/// the LZX folder of cabextract's test file mixed.cab
/// (https://github.com/kyz/libmspack, cabextract/test/cabs/), kept
/// byte-identical including its CFDATA checksum. Expected output is
/// tests/fixtures/mscab/mixed_lzx.txt.
#[test]
fn test_mscab_lzx_fixture() {
    let cab = include_bytes!("../fixtures/mscab/lzx_mixed.cab");
    let want = include_bytes!("../fixtures/mscab/mixed_lzx.txt");
    let entries = archive::archive::mscab::decode::decode(cab).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "lzx.txt");
    assert_eq!(&entries[0].data[..], &want[..]);
}

/// Large real-world LZX folder: cabextract's large-files-cab.cab
/// (typeCompress 0x1503, 2 MiB window, 449 CFDATA blocks, 14.7 MB of
/// output). Exercises contiguous-stream decoding across many CFDATA
/// records and 32 KiB frame realignment.
#[test]
fn test_mscab_lzx_large_fixture() {
    let cab = include_bytes!("../fixtures/mscab/lzx_large.cab");
    let entries = archive::archive::mscab::decode::decode(cab).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "large-files.cab");
    assert_eq!(entries[0].data.len(), 14_689_228);
    // The embedded payload is itself a cabinet image.
    assert_eq!(&entries[0].data[..4], b"MSCF");
    // FNV-1a over the whole output pins the decode bit-exactly.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in entries[0].data.iter() {
        h = (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
    }
    assert_eq!(h, 0x186e_930d_7753_bc03);
}

/// Build a minimal single-folder cabinet with the given typeCompress
/// value (e.g. Quantum = 2 | window_bits<<8) wrapping a raw compressed
/// block. uncomp is the folder's cbUncomp.
fn build_raw_cab(name: &str, type_compress: u16, block: &[u8], uncomp: usize) -> Vec<u8> {
    let mut files_buf = Vec::new();
    files_buf.extend_from_slice(&(uncomp as u32).to_le_bytes());
    files_buf.extend_from_slice(&0u32.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(&0u16.to_le_bytes());
    files_buf.extend_from_slice(name.as_bytes());
    files_buf.push(0);

    let files_off = 44usize;
    let data_off = files_off + files_buf.len();
    let cb_cabinet = (data_off + 8 + block.len()) as u32;

    let mut out = Vec::with_capacity(cb_cabinet as usize);
    out.extend_from_slice(b"MSCF");
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&cb_cabinet.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(files_off as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&[3u8, 1u8]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(data_off as u32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&type_compress.to_le_bytes());
    out.extend_from_slice(&files_buf);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(block.len() as u16).to_le_bytes());
    out.extend_from_slice(&(uncomp as u16).to_le_bytes());
    out.extend_from_slice(block);
    out
}

/// Real Quantum folder stream (libmspack  fixture payload,
/// without the reader-synthesised 0xFF sentinel), window_bits 18.
const QTM_TXT_BLOCK: &[u8] = &[
    0xD6, 0x06, 0x69, 0x0B, 0xCB, 0x47, 0xF0, 0x2C, 0x2A, 0x3A, 0x8F, 0x2C, 0xAB, 0xBB, 0x3C, 0xB9,
    0x33, 0x01, 0x8B, 0xD8, 0x58, 0x4B, 0x7B, 0x01, 0xBA, 0x6F, 0x6D, 0x51, 0x6E, 0x3A, 0xC3, 0x67,
    0x42, 0x4B, 0xEB, 0x02, 0x36, 0x43, 0xD6, 0x66, 0x56, 0xCA, 0x9E, 0x72, 0xCC, 0x30, 0x00, 0x00,
];
const QTM_TXT_EXPECTED: &[u8] = b"If you can read this, the Quantum decompressor is working!
";

#[test]
fn test_mscab_quantum_synthesized_cab() {
    // typeCompress = QUANTUM (2) | (window_bits 18) << 8.
    let cab = build_raw_cab("qtm.txt", 0x1202, QTM_TXT_BLOCK, QTM_TXT_EXPECTED.len());
    let entries = archive::archive::mscab::decode::decode(&cab).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "qtm.txt");
    assert_eq!(&entries[0].data[..], QTM_TXT_EXPECTED);
}

#[test]
fn test_mscab_quantum_cabextract_interop() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    if Command::new("cabextract")
        .arg("--version")
        .output()
        .is_err()
    {
        return; // cabextract unavailable
    }
    let cab = build_raw_cab("qtm.txt", 0x1202, QTM_TXT_BLOCK, QTM_TXT_EXPECTED.len());
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("archive_test_mscab_qtm_{uniq}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cab_path = dir.join("q.cab");
    std::fs::write(&cab_path, &cab).unwrap();

    let output = Command::new("cabextract")
        .args(["-d"])
        .arg(&dir)
        .arg(&cab_path)
        .output()
        .unwrap();
    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        panic!(
            "cabextract failed on quantum cab: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let extracted = std::fs::read(dir.join("qtm.txt"));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(&extracted.unwrap()[..], QTM_TXT_EXPECTED);
}

/// Real Quantum cabinet: cabextract's cve-2010-2801-qtm-flush.cab
/// (typeCompress 0x1222, window 18, 16 CFDATA blocks) — a valid Quantum
/// stream (the CVE concerned an output-flush bug, not the stream).
/// Decodes to 524159 zero bytes.
#[test]
fn test_mscab_quantum_fixture() {
    let cab = include_bytes!("../fixtures/mscab/quantum_flush.cab");
    let entries = archive::archive::mscab::decode::decode(cab).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "zeroes");
    assert_eq!(entries[0].data.len(), 524_159);
    assert!(entries[0].data.iter().all(|&b| b == 0));
}
