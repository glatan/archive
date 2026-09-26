// ============================================================
// WARC (Web ARChive) tests
// ============================================================

fn warc_record(rtype: &str, uri: Option<&str>, block: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"WARC/1.1\r\n");
    r.extend_from_slice(format!("WARC-Type: {rtype}\r\n").as_bytes());
    r.extend_from_slice(b"WARC-Record-ID: <urn:uuid:it-1>\r\n");
    r.extend_from_slice(b"WARC-Date: 2024-06-01T12:00:00Z\r\n");
    if let Some(u) = uri {
        r.extend_from_slice(format!("WARC-Target-URI: {u}\r\n").as_bytes());
    }
    r.extend_from_slice(b"Content-Type: application/octet-stream\r\n");
    r.extend_from_slice(format!("Content-Length: {}\r\n", block.len()).as_bytes());
    r.extend_from_slice(b"\r\n");
    r.extend_from_slice(block);
    r.extend_from_slice(b"\r\n\r\n");
    r
}

#[test]
fn test_warc_decode_records() {
    let mut stream = warc_record("warcinfo", None, b"warc metadata");
    stream.extend_from_slice(&warc_record(
        "response",
        Some("http://example.org/a"),
        b"response payload",
    ));
    stream.extend_from_slice(&warc_record("revisit", Some("http://example.org/a"), b""));

    let entries = archive::archive::warc::decode::decode(&stream).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].name, "http://example.org/a");
    assert_eq!(entries[1].data, b"response payload");
    assert_eq!(entries[2].record_type, "revisit");
}

#[cfg(feature = "gzip")]
#[test]
fn test_warc_gzip_members() {
    //  is a concatenated gzip stream; decode with the gzip
    // decoder first, then parse the WARC records.
    let stream = warc_record("resource", Some("http://x/"), b"block data");
    let compressed = archive::compress::gzip::encode::encode(
        &stream,
        archive::compress::deflate::encode::Level::Default,
    );
    let plain = archive::compress::gzip::decode::decode(&compressed).unwrap();
    let entries = archive::archive::warc::decode::decode(&plain).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].data, b"block data");
}
