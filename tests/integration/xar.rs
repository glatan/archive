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
//   bzip2.xar  - bzip2-encoded data (rejected: unsupported encoding)

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
fn reject_bzip2_encoding() {
    assert!(matches!(
        archive::archive::xar::decode::decode(&fixture("bzip2.xar")),
        Err(Error::Unsupported(_))
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
