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

#[test]
fn test_warc_encode_roundtrip() {
    use archive::archive::warc::encode::{WarcRecord, encode};

    let mut info = WarcRecord::new(
        "warcinfo",
        "urn:uuid:warcinfo-1",
        "2024-06-01T00:00:00Z",
        b"software: archive-crate\r\n",
    );
    info.content_type = Some("application/warc-fields".to_string());

    let mut resp = WarcRecord::new(
        "response",
        "urn:uuid:resp-1",
        "2024-06-01T00:00:01Z",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nPAYLOAD",
    );
    resp.target_uri = Some("http://example.org/a".to_string());
    resp.content_type = Some("application/http;msgtype=response".to_string());
    resp.payload = Some(b"PAYLOAD".to_vec());

    let stream = encode(&[info, resp]).unwrap();
    assert!(stream.starts_with(b"WARC/1.1\r\n"));
    let text = core::str::from_utf8(&stream).unwrap();
    assert!(text.contains("WARC-Record-ID: <urn:uuid:warcinfo-1>\r\n"));
    assert!(text.contains("WARC-Block-Digest: sha1:"));
    assert!(text.contains("WARC-Payload-Digest: sha1:"));

    let entries = archive::archive::warc::decode::decode(&stream).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].record_type, "warcinfo");
    assert_eq!(entries[0].data, b"software: archive-crate\r\n");
    assert_eq!(entries[1].name, "http://example.org/a");
    assert_eq!(entries[1].record_id, "<urn:uuid:resp-1>");
}

#[cfg(feature = "gzip")]
#[test]
fn test_warc_gzip_write_roundtrip() {
    use archive::archive::warc::encode::{WarcRecord, encode};

    let mut rec = WarcRecord::new(
        "resource",
        "urn:uuid:gz-1",
        "2024-06-01T00:00:00Z",
        b"gzip wrapped block",
    );
    rec.target_uri = Some("http://x/".to_string());
    let stream = encode(&[rec]).unwrap();
    let compressed = archive::compress::gzip::encode::encode(
        &stream,
        archive::compress::deflate::encode::Level::Default,
    );
    let plain = archive::compress::gzip::decode::decode(&compressed).unwrap();
    assert_eq!(plain, stream);
    let entries = archive::archive::warc::decode::decode(&plain).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].data, b"gzip wrapped block");
}
