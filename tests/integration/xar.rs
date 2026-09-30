use archive::error::Error;
use archive::traits::ArchiveEntry;

// ============================================================
// XAR (xarformat, mackyle/xar wiki) tests
// ============================================================
//
// Fixtures under tests/fixtures/xar/ were produced by the reference
// `xar` 1.6.1 tool (mackyle/xar, BSD-style; oracle only):
//   real.xar   - sha1 TOC checksum, gzip-encoded data, nested dirs
//   md5.xar    - md5 TOC checksum + md5 file checksums
//   none.xar   - no checksums, stored (uncompressed) file data
//   bzip2.xar  - bzip2-encoded data

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/xar/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn find<'a>(
    entries: &'a [archive::archive::xar::decode::XarEntry],
    name: &str,
) -> &'a archive::archive::xar::decode::XarEntry {
    entries.iter().find(|e| e.name() == name).unwrap()
}

#[test]
fn decode_real() {
    let entries = archive::archive::xar::decode::decode(&fixture("real.xar")).unwrap();
    assert_eq!(entries.len(), 4);
    let hello = find(&entries, "hello.txt");
    assert_eq!(hello.data(), b"hello xar world\n");
    assert_eq!(hello.file_type, "file");
    assert_eq!(hello.mode.as_deref(), Some("0644"));
    let data = find(&entries, "data.bin");
    assert_eq!(data.data().len(), 2048);
    assert_eq!(data.data()[255], 255);
    assert_eq!(data.data()[256], 0);
    let sub = find(&entries, "sub");
    assert!(sub.is_dir);
    assert_eq!(sub.file_type, "directory");
    let nested = find(&entries, "sub/nested.txt");
    assert_eq!(nested.data(), b"nested file\n");
}

#[test]
fn decode_md5_checksums() {
    // cksum_alg=2: MD5 TOC checksum and MD5 extracted-checksums.
    let entries = archive::archive::xar::decode::decode(&fixture("md5.xar")).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(find(&entries, "hello.txt").data(), b"hello xar world\n");
    assert_eq!(find(&entries, "data.bin").data().len(), 2048);
}

#[test]
fn decode_stored_no_checksum() {
    // cksum_alg=0, stored file data (encoding "none").
    let entries = archive::archive::xar::decode::decode(&fixture("none.xar")).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(find(&entries, "hello.txt").data(), b"hello xar world\n");
    assert_eq!(find(&entries, "sub/nested.txt").data(), b"nested file\n");
}

#[test]
fn decode_bzip2_encoding() {
    // reference xar --compression=bzip2
    let entries = archive::archive::xar::decode::decode(&fixture("bzip2.xar")).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        find(&entries, "hello.txt").data(),
        b"hello xar world
"
    );
}

fn make_xar(heap: &[u8], toc_xml: &str) -> Vec<u8> {
    // cksum_alg=0 header: magic, size, version, toc comp/raw sizes.
    let toc_comp = archive::compress::zlib::encode::encode(toc_xml.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(b"xar!");
    out.extend_from_slice(&28u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
    out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&toc_comp);
    out.extend_from_slice(heap);
    out
}

fn xar_with_encoding(style: &str, stored: &[u8], extracted_len: usize) -> Vec<u8> {
    let toc = format!(
        concat!(
            "<?xml version='1.0'?><xar><toc>",
            "<file id='1'><name>f.bin</name><type>file</type>",
            "<data><offset>0</offset><size>{}</size><length>{}</length>",
            "<encoding style='{}'/></data></file></toc></xar>"
        ),
        extracted_len,
        stored.len(),
        style,
    );
    make_xar(stored, &toc)
}

#[test]
fn decode_xz_and_lzma_encodings() {
    use archive::compress;
    let payload: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();
    for (style, stored) in [
        ("application/x-xz", compress::xz::encode::encode(&payload)),
        (
            "application/x-lzma",
            compress::lzma_alone::encode::encode(&payload),
        ),
        (
            "application/x-bzip2",
            compress::bzip2::encode::encode(&payload),
        ),
    ] {
        let x = xar_with_encoding(style, &stored, payload.len());
        let entries = archive::archive::xar::decode::decode(&x).unwrap();
        assert_eq!(entries.len(), 1, "{style}");
        assert_eq!(entries[0].data(), &payload[..], "{style}");
    }
}

#[test]
fn reject_corrupt_encoded_data() {
    let x = xar_with_encoding("application/x-bzip2", b"not bzip2", 9);
    assert!(matches!(
        archive::archive::xar::decode::decode(&x),
        Err(Error::InvalidData(_))
    ));
}

#[test]
fn encode_roundtrip() {
    let mut enc = archive::archive::xar::encode::XarEncoder::new();
    enc.add_file("hello.txt", b"hello xar world\n");
    enc.add_file("data.bin", &[42u8; 500]);
    enc.add_file("sub/nested.txt", b"nested\n");
    enc.add_directory("emptydir");
    let bytes = enc.finish();
    let entries = archive::archive::xar::decode::decode(&bytes).unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(find(&entries, "hello.txt").data(), b"hello xar world\n");
    assert_eq!(find(&entries, "data.bin").data(), &[42u8; 500]);
    assert_eq!(find(&entries, "sub/nested.txt").data(), b"nested\n");
    assert!(find(&entries, "sub").is_dir);
    assert!(find(&entries, "emptydir").is_dir);
}

/// Corrupting stored heap bytes is caught by the per-file
/// `archived-checksum` digest (verified before decompression).
#[test]
fn archived_checksum_catches_tampered_heap() {
    let mut enc = archive::archive::xar::encode::XarEncoder::new();
    enc.add_file("payload.txt", b"archived checksum coverage\n");
    let mut bytes = enc.finish();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let err = archive::archive::xar::decode::decode(&bytes).unwrap_err();
    assert!(
        err.to_string().contains("archived-checksum"),
        "unexpected error: {err}"
    );
}

/// A valid archive with `archived-checksum` verifies cleanly.
#[test]
fn archived_checksum_verified_on_valid_archive() {
    let mut enc = archive::archive::xar::encode::XarEncoder::new();
    enc.add_file("ok.txt", b"verify me");
    let bytes = enc.finish();
    let entries = archive::archive::xar::decode::decode(&bytes).unwrap();
    assert_eq!(find(&entries, "ok.txt").data(), b"verify me");
}

#[test]
fn encode_xml_escape() {
    let mut enc = archive::archive::xar::encode::XarEncoder::new();
    enc.add_file("a&b<c>.txt", b"x");
    let bytes = enc.finish();
    let entries = archive::archive::xar::decode::decode(&bytes).unwrap();
    assert_eq!(find(&entries, "a&b<c>.txt").data(), b"x");
}

#[test]
fn bad_magic() {
    let mut f = fixture("real.xar");
    f[0] = b'z';
    assert!(matches!(
        archive::archive::xar::decode::decode(&f),
        Err(Error::InvalidData(_))
    ));
}

#[test]
fn truncated() {
    let f = fixture("real.xar");
    for n in [0, 3, 10, 27, 28, f.len() - 1] {
        assert!(
            archive::archive::xar::decode::decode(&f[..n]).is_err(),
            "len {n}"
        );
    }
}

#[test]
fn bad_toc_checksum() {
    let mut f = fixture("real.xar");
    // Heap starts at 28 + toc_length_compressed; the first 20 heap
    // bytes are the TOC checksum.
    let toc_comp = u64::from_be_bytes(f[8..16].try_into().unwrap()) as usize;
    f[28 + toc_comp] ^= 0xFF;
    assert!(archive::archive::xar::decode::decode(&f).is_err());
}

#[test]
fn bad_extracted_checksum() {
    let mut f = fixture("real.xar");
    // Corrupt one byte inside hello.txt's zlib data run (heap offset
    // 20, i.e. after the 20-byte TOC checksum). Any corruption of the
    // compressed data must surface as an error.
    let toc_comp = u64::from_be_bytes(f[8..16].try_into().unwrap()) as usize;
    let heap = 28 + toc_comp;
    f[heap + 22] ^= 0xFF;
    assert!(archive::archive::xar::decode::decode(&f).is_err());
}

#[test]
fn bad_version_rejected() {
    let mut f = fixture("real.xar");
    f[7] = 2;
    assert!(matches!(
        archive::archive::xar::decode::decode(&f),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn xar_encoded_data_unar_oracle() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let has_unar = Command::new("unar")
        .arg("--version")
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if !has_unar {
        return;
    }
    use archive::compress;
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 97) as u8).collect();
    for (style, stored) in [
        (
            "application/x-bzip2",
            compress::bzip2::encode::encode(&payload),
        ),
        ("application/x-xz", compress::xz::encode::encode(&payload)),
        (
            "application/x-lzma",
            compress::lzma_alone::encode::encode(&payload),
        ),
    ] {
        let x = xar_with_encoding(style, &stored, payload.len());
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("archive_xar_oracle_{uniq}"));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.xar");
        std::fs::write(&path, &x).unwrap();
        let outdir = dir.join("out");
        let output = Command::new("unar")
            .args(["-D", "-o", outdir.to_str().unwrap()])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "unar failed for {style}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let got = std::fs::read(outdir.join("f.bin"))
            .unwrap_or_else(|_| panic!("unar: missing f.bin for {style}"));
        assert_eq!(got, payload, "unar output mismatch for {style}");
    }
}
