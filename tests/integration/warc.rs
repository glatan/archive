// ============================================================
// WARC (Web ARChive) tests
// ============================================================

/// Build a WARC record with a caller-chosen `Content-Type` (`None`
/// omits the field) and caller-supplied extra header lines.
fn warc_record_with(
    rtype: &str,
    uri: Option<&str>,
    content_type: Option<&str>,
    extra: &[&str],
    block: &[u8],
) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"WARC/1.1\r\n");
    r.extend_from_slice(format!("WARC-Type: {rtype}\r\n").as_bytes());
    r.extend_from_slice(b"WARC-Record-ID: <urn:uuid:it-1>\r\n");
    r.extend_from_slice(b"WARC-Date: 2024-06-01T12:00:00Z\r\n");
    if let Some(u) = uri {
        r.extend_from_slice(format!("WARC-Target-URI: {u}\r\n").as_bytes());
    }
    if let Some(ct) = content_type {
        r.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
    }
    for f in extra {
        r.extend_from_slice(f.as_bytes());
        r.extend_from_slice(b"\r\n");
    }
    r.extend_from_slice(format!("Content-Length: {}\r\n", block.len()).as_bytes());
    r.extend_from_slice(b"\r\n");
    r.extend_from_slice(block);
    r.extend_from_slice(b"\r\n\r\n");
    r
}

/// Minimal spec-valid record: `warcinfo` carries its Clause-8
/// `Content-Type: application/warc-fields` and `revisit` carries a
/// `WARC-Profile` field (mandatory per §5 named fields / §6 revisit).
fn warc_record(rtype: &str, uri: Option<&str>, block: &[u8]) -> Vec<u8> {
    const PROFILE: &str =
        "WARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest";
    match rtype {
        "warcinfo" => warc_record_with(rtype, uri, Some("application/warc-fields"), &[], block),
        "revisit" => warc_record_with(
            rtype,
            uri,
            Some("application/octet-stream"),
            &[PROFILE],
            block,
        ),
        _ => warc_record_with(rtype, uri, Some("application/octet-stream"), &[], block),
    }
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

#[test]
fn test_warc_rejects_revisit_missing_profile() {
    // WARC-Profile is mandatory on 'revisit' records (WARC 1.1 §5
    // named fields / §6 revisit).
    let data = warc_record_with("revisit", Some("http://e/"), Some("text/plain"), &[], b"");
    assert!(matches!(
        archive::archive::warc::decode::decode(&data),
        Err(archive::error::Error::InvalidData(_))
    ));
}

#[test]
fn test_warc_rejects_profile_on_non_revisit() {
    // WARC-Profile is undefined for record types other than 'revisit'.
    const PROFILE: &str =
        "WARC-Profile: http://netpreserve.org/warc/1.1/revisit/identical-payload-digest";
    for t in ["response", "resource", "request", "metadata", "conversion"] {
        let data = warc_record_with(t, Some("http://e/"), None, &[PROFILE], b"b");
        assert!(
            matches!(
                archive::archive::warc::decode::decode(&data),
                Err(archive::error::Error::InvalidData(_))
            ),
            "accepted WARC-Profile on {t}"
        );
    }
    let data = warc_record_with(
        "warcinfo",
        None,
        Some("application/warc-fields"),
        &[PROFILE],
        b"f: v",
    );
    assert!(matches!(
        archive::archive::warc::decode::decode(&data),
        Err(archive::error::Error::InvalidData(_))
    ));
    let data = warc_record_with(
        "continuation",
        Some("http://e/"),
        None,
        &[
            "WARC-Segment-Origin-ID: <urn:x:o>",
            "WARC-Segment-Number: 2",
            PROFILE,
        ],
        b"b",
    );
    assert!(matches!(
        archive::archive::warc::decode::decode(&data),
        Err(archive::error::Error::InvalidData(_))
    ));
}

#[test]
fn test_warc_accepts_revisit_with_known_profile() {
    // The two profile URIs defined by WARC 1.1 §6 'revisit'.
    for uri in [
        "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest",
        "http://netpreserve.org/warc/1.1/revisit/server-not-modified",
    ] {
        let field = format!("WARC-Profile: {uri}");
        let data = warc_record_with(
            "revisit",
            Some("http://e/"),
            Some("application/http;msgtype=response"),
            &[&field],
            b"",
        );
        let entries = archive::archive::warc::decode::decode(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].record_type, "revisit");
    }
    // An unrecognized profile URI is accepted but uninterpreted: "a
    // reader which does not recognize the profile URI shall not
    // attempt to interpret" it, and record blocks are never
    // interpreted here.
    let data = warc_record_with(
        "revisit",
        Some("http://e/"),
        None,
        &["WARC-Profile: http://example.org/custom-profile"],
        b"opaque",
    );
    let entries = archive::archive::warc::decode::decode(&data).unwrap();
    assert_eq!(entries[0].data, b"opaque");
}

#[test]
fn test_warc_identified_payload_type_needs_payload() {
    // WARC 1.1 §5: WARC-Identified-Payload-Type "shall not be used on
    // records without a well-defined payload" — 'warcinfo' and
    // 'metadata' define none.
    for (t, uri, ct) in [
        ("warcinfo", None, Some("application/warc-fields")),
        ("metadata", Some("http://e/"), None),
    ] {
        let data = warc_record_with(
            t,
            uri,
            ct,
            &["WARC-Identified-Payload-Type: image/jpeg"],
            b"b",
        );
        assert!(
            matches!(
                archive::archive::warc::decode::decode(&data),
                Err(archive::error::Error::InvalidData(_))
            ),
            "accepted WARC-Identified-Payload-Type on {t}"
        );
    }
    // Allowed where the payload is defined; Annex B.8 even shows the
    // field on a 'continuation' record.
    for t in ["response", "resource", "request", "conversion"] {
        let data = warc_record_with(
            t,
            Some("http://e/"),
            None,
            &["WARC-Identified-Payload-Type: image/jpeg"],
            b"b",
        );
        assert!(
            archive::archive::warc::decode::decode(&data).is_ok(),
            "rejected WARC-Identified-Payload-Type on {t}"
        );
    }
    let data = warc_record_with(
        "revisit",
        Some("http://e/"),
        None,
        &[
            "WARC-Profile: http://netpreserve.org/warc/1.1/revisit/server-not-modified",
            "WARC-Identified-Payload-Type: image/jpeg",
        ],
        b"b",
    );
    assert!(archive::archive::warc::decode::decode(&data).is_ok());
    let data = warc_record_with(
        "continuation",
        Some("http://e/"),
        None,
        &[
            "WARC-Segment-Origin-ID: <urn:x:o>",
            "WARC-Segment-Number: 2",
            "WARC-Identified-Payload-Type: image/jpeg",
        ],
        b"b",
    );
    assert!(archive::archive::warc::decode::decode(&data).is_ok());
}

#[test]
fn test_warc_payload_digest_needs_payload() {
    // WARC 1.1 §5: WARC-Payload-Digest carries the same "shall not be
    // used on records without a well-defined payload" constraint as
    // WARC-Identified-Payload-Type — 'warcinfo' and 'metadata'
    // define none.
    for (t, uri, ct) in [
        ("warcinfo", None, Some("application/warc-fields")),
        ("metadata", Some("http://e/"), None),
    ] {
        let data = warc_record_with(
            t,
            uri,
            ct,
            &["WARC-Payload-Digest: sha1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
            b"b",
        );
        assert!(
            matches!(
                archive::archive::warc::decode::decode(&data),
                Err(archive::error::Error::InvalidData(_))
            ),
            "accepted WARC-Payload-Digest on {t}"
        );
    }
    // Allowed where the payload is defined (a non-sha1 algorithm
    // label is accepted and left unverified).
    for t in ["response", "resource", "request", "conversion"] {
        let data = warc_record_with(
            t,
            Some("http://e/"),
            None,
            &["WARC-Payload-Digest: sha256:AAAA"],
            b"b",
        );
        assert!(
            archive::archive::warc::decode::decode(&data).is_ok(),
            "rejected WARC-Payload-Digest on {t}"
        );
    }
}

#[test]
fn test_warc_rejects_warcinfo_wrong_content_type() {
    // Clause 8: the MIME type of warcinfo records shall be
    // application/warc-fields.
    for ct in [None, Some("text/plain"), Some("application/octet-stream")] {
        let data = warc_record_with("warcinfo", None, ct, &[], b"f: v");
        assert!(
            matches!(
                archive::archive::warc::decode::decode(&data),
                Err(archive::error::Error::InvalidData(_))
            ),
            "accepted warcinfo Content-Type {ct:?}"
        );
    }
    // The required type (case/parameter variations included) passes.
    for ct in [
        "application/warc-fields",
        "Application/WARC-Fields; charset=utf-8",
    ] {
        let data = warc_record_with("warcinfo", None, Some(ct), &[], b"f: v");
        assert!(
            archive::archive::warc::decode::decode(&data).is_ok(),
            "rejected warcinfo Content-Type {ct:?}"
        );
    }
}

#[test]
fn test_warc_encoder_warcinfo_content_type() {
    use archive::archive::warc::encode::{WarcRecord, encode};

    // The encoder supplies the Clause-8 type when the caller omits it.
    let rec = WarcRecord::new("warcinfo", "urn:x:w", "2024-06-01T00:00:00Z", b"f: v");
    let stream = encode(&[rec]).unwrap();
    assert!(
        core::str::from_utf8(&stream)
            .unwrap()
            .contains("Content-Type: application/warc-fields\r\n")
    );
    assert!(archive::archive::warc::decode::decode(&stream).is_ok());
    // ... and refuses a conflicting one.
    let mut rec = WarcRecord::new("warcinfo", "urn:x:w", "2024-06-01T00:00:00Z", b"f: v");
    rec.content_type = Some("text/plain".to_string());
    assert!(matches!(
        encode(&[rec]),
        Err(archive::error::Error::InvalidData(_))
    ));
}
