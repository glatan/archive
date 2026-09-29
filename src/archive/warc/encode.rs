//! WARC record stream encoding (WARC 1.0/1.1).
//!
//! Emits `version-line CRLF *(named-field CRLF) CRLF block CRLF CRLF`
//! records. The encoder supplies the mandatory `WARC-Type`,
//! `WARC-Record-ID`, `WARC-Date`, and `Content-Length` fields and,
//! by default, a `WARC-Block-Digest: sha1:<base32>` field computed
//! over the block. `WARC-Payload-Digest` is emitted when the caller
//! provides the payload bytes (e.g. the entity-body of an
//! `application/http` block); payload identification is the caller's
//! responsibility because the block is opaque here.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

/// A WARC record to be emitted.
#[derive(Debug, Clone)]
pub struct WarcRecord {
    /// `WARC-Type` value (e.g. `warcinfo`, `response`, `resource`).
    pub record_type: String,
    /// `WARC-Record-ID` URI. Angle brackets are added when missing.
    pub record_id: String,
    /// `WARC-Date` value (W3C ISO 8601 profile string, kept raw).
    pub date: String,
    /// `WARC-Target-URI`, if any.
    pub target_uri: Option<String>,
    /// `Content-Type` of the block, if any.
    pub content_type: Option<String>,
    /// Payload bytes whose SHA-1 goes into `WARC-Payload-Digest`.
    /// `None` emits no payload-digest field (correct for records
    /// without a well-defined payload, e.g. `warcinfo`).
    pub payload: Option<Vec<u8>>,
    /// Additional named fields `(name, value)`, emitted after the
    /// defined fields and before `Content-Length`. Names must not
    /// collide with the fields the encoder manages (`WARC-Type`,
    /// `WARC-Record-ID`, `WARC-Date`, `Content-Length`,
    /// `WARC-Target-URI`, `Content-Type`).
    pub extra_fields: Vec<(String, String)>,
    /// Record block contents (`Content-Length` octets).
    pub block: Vec<u8>,
}

impl WarcRecord {
    /// Convenience constructor for a record with no optional fields.
    pub fn new(record_type: &str, record_id: &str, date: &str, block: &[u8]) -> Self {
        WarcRecord {
            record_type: record_type.to_string(),
            record_id: record_id.to_string(),
            date: date.to_string(),
            target_uri: None,
            content_type: None,
            payload: None,
            extra_fields: Vec::new(),
            block: block.to_vec(),
        }
    }
}

/// Encoder for WARC record streams.
pub struct WarcEncoder {
    out: Vec<u8>,
    version: &'static str,
    block_digest: bool,
}

impl WarcEncoder {
    /// New encoder emitting `WARC/1.1` records with SHA-1 block
    /// digests.
    pub fn new() -> Self {
        WarcEncoder {
            out: Vec::new(),
            version: "1.1",
            block_digest: true,
        }
    }

    /// Emit `WARC/1.0` records instead of `WARC/1.1`.
    pub fn warc10(mut self) -> Self {
        self.version = "1.0";
        self
    }

    /// Enable or disable the automatic `WARC-Block-Digest` field
    /// (enabled by default).
    pub fn block_digest(mut self, on: bool) -> Self {
        self.block_digest = on;
        self
    }

    /// Append one record to the stream.
    pub fn add_record(&mut self, r: &WarcRecord) -> Result<(), Error> {
        check_token(&r.record_type, "WARC-Type")?;
        check_value(&r.date, "WARC-Date")?;
        if r.date.is_empty() {
            return Err(Error::InvalidData("warc: empty WARC-Date"));
        }
        let record_id = bracket_id(&r.record_id)?;
        if let Some(u) = &r.target_uri {
            check_value(u, "WARC-Target-URI")?;
        }
        if let Some(ct) = &r.content_type {
            check_value(ct, "Content-Type")?;
        }
        const MANAGED: &[&str] = &[
            "WARC-Type",
            "WARC-Record-ID",
            "WARC-Date",
            "Content-Length",
            "WARC-Target-URI",
            "Content-Type",
        ];
        for (name, value) in &r.extra_fields {
            check_token(name, "field name")?;
            check_value(value, "field value")?;
            if MANAGED.iter().any(|m| name.eq_ignore_ascii_case(m)) {
                return Err(Error::InvalidData("warc: field managed by encoder"));
            }
        }

        let mut hdr = Vec::with_capacity(256);
        hdr.extend_from_slice(b"WARC/");
        hdr.extend_from_slice(self.version.as_bytes());
        hdr.extend_from_slice(b"\r\n");
        put_field(&mut hdr, "WARC-Type", &r.record_type);
        put_field(&mut hdr, "WARC-Record-ID", &record_id);
        put_field(&mut hdr, "WARC-Date", &r.date);
        if let Some(u) = &r.target_uri {
            put_field(&mut hdr, "WARC-Target-URI", u);
        }
        if let Some(ct) = &r.content_type {
            put_field(&mut hdr, "Content-Type", ct);
        }
        if self.block_digest && !has_field(&r.extra_fields, "WARC-Block-Digest") {
            put_field(&mut hdr, "WARC-Block-Digest", &labelled_sha1(&r.block));
        }
        if let Some(p) = &r.payload
            && !has_field(&r.extra_fields, "WARC-Payload-Digest")
        {
            put_field(&mut hdr, "WARC-Payload-Digest", &labelled_sha1(p));
        }
        for (name, value) in &r.extra_fields {
            put_field(&mut hdr, name, value);
        }
        put_field(&mut hdr, "Content-Length", &r.block.len().to_string());
        hdr.extend_from_slice(b"\r\n");
        self.out.extend_from_slice(&hdr);
        self.out.extend_from_slice(&r.block);
        self.out.extend_from_slice(b"\r\n\r\n");
        Ok(())
    }

    /// Return the encoded record stream.
    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

impl Default for WarcEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode `records` as a `WARC/1.1` stream with block digests.
pub fn encode(records: &[WarcRecord]) -> Result<Vec<u8>, Error> {
    let mut enc = WarcEncoder::new();
    for r in records {
        enc.add_record(r)?;
    }
    Ok(enc.finish())
}

/// Wrap `id` in `<...>` unless already bracketed; reject empty IDs
/// and characters that would break the header.
fn bracket_id(id: &str) -> Result<String, Error> {
    let id = id.trim();
    if id.is_empty() {
        return Err(Error::InvalidData("warc: empty WARC-Record-ID"));
    }
    check_value(id, "WARC-Record-ID")?;
    Ok(
        if id.starts_with('<') && id.ends_with('>') && id.len() > 2 {
            id.to_string()
        } else {
            alloc::format!("<{id}>")
        },
    )
}

/// Field names are tokens: printable ASCII without separators used
/// by the grammar (at minimum `:` and whitespace).
fn check_token(t: &str, _what: &str) -> Result<(), Error> {
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
        return Err(Error::InvalidData("warc: bad token"));
    }
    Ok(())
}

/// Field values must not contain CR or LF (LWS folding is input-side).
fn check_value(v: &str, _what: &str) -> Result<(), Error> {
    if v.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(Error::InvalidData("warc: CR/LF in field value"));
    }
    Ok(())
}

fn has_field(fields: &[(String, String)], name: &str) -> bool {
    fields.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn put_field(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// `sha1:<base32>` digest label per WARC 1.1 (RFC 4648 Base32, no
/// padding, uppercase).
fn labelled_sha1(data: &[u8]) -> String {
    let h = crate::util::sha1::sha1(data);
    let mut s = String::from("sha1:");
    base32_into(&h, &mut s);
    s
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 Base32 without padding.
pub(crate) fn base32_into(data: &[u8], out: &mut String) {
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::warc::decode;

    fn rec(rtype: &str, uri: Option<&str>, block: &[u8]) -> WarcRecord {
        let mut r = WarcRecord::new(rtype, "urn:uuid:enc-1", "2024-01-01T00:00:00Z", block);
        r.target_uri = uri.map(|u| u.to_string());
        r.content_type = Some("text/plain".to_string());
        r
    }

    #[test]
    fn roundtrip_single() {
        let data = encode(&[rec("resource", Some("http://e/"), b"body")]).unwrap();
        assert!(data.starts_with(b"WARC/1.1\r\n"));
        let es = decode::decode(&data).unwrap();
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].record_type, "resource");
        assert_eq!(es[0].record_id, "<urn:uuid:enc-1>");
        assert_eq!(es[0].name, "http://e/");
        assert_eq!(es[0].data, b"body");
    }

    #[test]
    fn roundtrip_multiple() {
        let recs = [
            rec("warcinfo", None, b"info"),
            rec("response", Some("http://a/"), b"HTTP/1.1 200 OK\r\n\r\nx"),
            rec("revisit", Some("http://a/"), b""),
        ];
        let es = decode::decode(&encode(&recs).unwrap()).unwrap();
        assert_eq!(es.len(), 3);
        assert_eq!(es[2].record_type, "revisit");
    }

    #[test]
    fn block_digest_is_emitted_and_correct() {
        let data = encode(&[rec("resource", None, b"body")]).unwrap();
        // sha1("body") = b8ea3715f8a0390aa7b501d1b8cf67f4cf1f74f0
        // base32 of those bytes:
        let expect = "WARC-Block-Digest: sha1:";
        let text = String::from_utf8(data.clone()).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with(expect))
            .expect("digest line");
        let got = &line[expect.len()..];
        // Recompute independently.
        let mut b = String::new();
        base32_into(&crate::util::sha1::sha1(b"body"), &mut b);
        assert_eq!(got, b);
    }

    #[test]
    fn payload_digest_only_when_given() {
        let mut r = rec(
            "response",
            Some("http://a/"),
            b"HTTP/1.1 200 OK\r\n\r\nPAYLOAD",
        );
        r.payload = Some(b"PAYLOAD".to_vec());
        let text = String::from_utf8(encode(&[r]).unwrap()).unwrap();
        let line = text
            .lines()
            .find(|l| l.starts_with("WARC-Payload-Digest: sha1:"))
            .expect("payload digest line");
        let mut want = String::new();
        base32_into(&crate::util::sha1::sha1(b"PAYLOAD"), &mut want);
        assert_eq!(&line["WARC-Payload-Digest: sha1:".len()..], want);

        let r2 = rec("warcinfo", None, b"info");
        let text2 = String::from_utf8(encode(&[r2]).unwrap()).unwrap();
        assert!(!text2.contains("WARC-Payload-Digest"));
    }

    #[test]
    fn record_id_gets_brackets() {
        let es = decode::decode(&encode(&[rec("resource", None, b"x")]).unwrap()).unwrap();
        assert_eq!(es[0].record_id, "<urn:uuid:enc-1>");
        // Already-bracketed IDs pass through unchanged.
        let mut r = rec("resource", None, b"x");
        r.record_id = "<urn:x:1>".to_string();
        let text = String::from_utf8(encode(&[r]).unwrap()).unwrap();
        assert!(text.contains("WARC-Record-ID: <urn:x:1>\r\n"));
        assert!(!text.contains("<<urn"));
    }

    #[test]
    fn warc10_version() {
        let mut enc = WarcEncoder::new().warc10();
        enc.add_record(&rec("resource", None, b"x")).unwrap();
        assert!(enc.finish().starts_with(b"WARC/1.0\r\n"));
    }

    #[test]
    fn block_digest_can_be_disabled_or_overridden() {
        let mut enc = WarcEncoder::new().block_digest(false);
        enc.add_record(&rec("resource", None, b"x")).unwrap();
        let text = String::from_utf8(enc.finish()).unwrap();
        assert!(!text.contains("WARC-Block-Digest"));

        let mut r = rec("resource", None, b"x");
        r.extra_fields
            .push(("WARC-Block-Digest".to_string(), "sha256:XYZ".to_string()));
        let text = String::from_utf8(encode(&[r]).unwrap()).unwrap();
        assert!(text.contains("WARC-Block-Digest: sha256:XYZ\r\n"));
        assert!(!text.contains("WARC-Block-Digest: sha1:"));
    }

    #[test]
    fn rejects_bad_fields() {
        let mut r = rec("resource", None, b"x");
        r.date = "2024-01-01\r\nX: y".to_string();
        assert!(matches!(encode(&[r]), Err(Error::InvalidData(_))));

        let mut r = rec("resource", None, b"x");
        r.record_type = "bad type".to_string();
        assert!(matches!(encode(&[r]), Err(Error::InvalidData(_))));

        let mut r = rec("resource", None, b"x");
        r.extra_fields
            .push(("Content-Length".to_string(), "5".to_string()));
        assert!(matches!(encode(&[r]), Err(Error::InvalidData(_))));

        let mut r = rec("resource", None, b"x");
        r.record_id.clear();
        assert!(matches!(encode(&[r]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn base32_rfc4648() {
        // RFC 4648 test vectors, padding omitted.
        for (input, want) in [
            (&b""[..], ""),
            (&b"f"[..], "MY"),
            (&b"fo"[..], "MZXQ"),
            (&b"foo"[..], "MZXW6"),
            (&b"foob"[..], "MZXW6YQ"),
            (&b"fooba"[..], "MZXW6YTB"),
            (&b"foobar"[..], "MZXW6YTBOI"),
        ] {
            let mut s = String::new();
            base32_into(input, &mut s);
            assert_eq!(s, want);
        }
    }
}
