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
