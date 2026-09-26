//! WARC record stream decoding.
//!
//! Grammar (WARC 1.0/1.1):
//! `version-line CRLF *(named-field CRLF) CRLF block CRLF CRLF`
//!
//! where version-line is `WARC/1.0` or `WARC/1.1`, named fields are
//! `token ":" SP* value` with optional LWS folding, and block is
//! `Content-Length` octets. Unknown fields are ignored per spec.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

/// A decoded WARC record exposed as an archive entry.
#[derive(Debug, Clone)]
pub struct WarcEntry {
    /// Entry name: `WARC-Target-URI` if present, else `WARC-Record-ID`.
    pub name: String,
    /// Record block content (`Content-Length` bytes).
    pub data: Vec<u8>,
    /// `WARC-Type` value (e.g. `warcinfo`, `response`, `resource`).
    pub record_type: String,
    /// `WARC-Record-ID` value.
    pub record_id: String,
    /// `WARC-Date` value (W3C ISO 8601 profile string, kept raw).
    pub date: Option<String>,
    /// `Content-Type` of the block, if present.
    pub content_type: Option<String>,
    /// `WARC-Target-URI`, if present.
    pub target_uri: Option<String>,
}

impl crate::traits::ArchiveEntry for WarcEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

const VERSIONS: &[&[u8]] = &[b"WARC/1.0", b"WARC/1.1"];

fn parse_header_block(block: &[u8]) -> Result<BTreeMap<String, String>, Error> {
    // Header lines are UTF-8 text ending in CRLF; LWS folding joins a
    // continuation line (starting with SP/HT) onto the previous value.
    let text =
        core::str::from_utf8(block).map_err(|_| Error::InvalidData("warc: header is not UTF-8"))?;
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut last_name: Option<String> = None;
    for raw in text.split("\r\n") {
        let line = raw.trim_end_matches('\n');
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            // LWS continuation
            let Some(name) = &last_name else {
                return Err(Error::InvalidData("warc: folding without field"));
            };
            let cur = fields.get_mut(name).unwrap();
            cur.push(' ');
            cur.push_str(line.trim());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::InvalidData("warc: malformed named-field"));
        };
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii() && b > b' ' && b != b':') {
            return Err(Error::InvalidData("warc: bad field name"));
        }
        fields.insert(name.to_string(), value.trim().to_string());
        last_name = Some(name.to_string());
    }
    Ok(fields)
}

/// Decode a WARC record stream into entries.
///
/// `input` must be a raw WARC stream (decompress `.warc.gz` first).
/// Trailing whitespace between records is tolerated.
pub fn decode(input: &[u8]) -> Result<Vec<WarcEntry>, Error> {
    let mut pos = 0usize;
    let mut entries = Vec::new();

    loop {
        // Skip record separators / stray whitespace between records.
        while pos < input.len() && (input[pos] == b'\r' || input[pos] == b'\n') {
            pos += 1;
        }
        if pos >= input.len() {
            break;
        }

        // Version line
        let mut matched = false;
        for v in VERSIONS {
            if input[pos..].starts_with(v) {
                let nl = pos + v.len();
                if input.get(nl) == Some(&b'\r') && input.get(nl + 1) == Some(&b'\n') {
                    pos = nl + 2;
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            return Err(Error::InvalidData("warc: bad version line"));
        }

        // Header block up to CRLF CRLF
        let hdr_end = input[pos..]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| pos + i)
            .ok_or(Error::InvalidData("warc: unterminated header"))?;
        let fields = parse_header_block(&input[pos..hdr_end])?;
        let mut cur = hdr_end + 4;

        // Mandatory fields per spec.
        let record_type = fields
            .get("WARC-Type")
            .ok_or(Error::InvalidData("warc: missing WARC-Type"))?
            .clone();
        let record_id = fields
            .get("WARC-Record-ID")
            .ok_or(Error::InvalidData("warc: missing WARC-Record-ID"))?
            .clone();
        let date = fields.get("WARC-Date").cloned();
        if date.is_none() {
            return Err(Error::InvalidData("warc: missing WARC-Date"));
        }
        let content_length: usize = fields
            .get("Content-Length")
            .and_then(|v| v.trim().parse().ok())
            .ok_or(Error::InvalidData("warc: missing/bad Content-Length"))?;

        let block = input
            .get(cur..cur + content_length)
            .ok_or(Error::InvalidData("warc: truncated block"))?
            .to_vec();
        cur += content_length;
        // Record ends with CRLF CRLF; tolerate missing final separator on
        // the last record.
        pos = cur;

        let target_uri = fields.get("WARC-Target-URI").cloned();
        let name = target_uri.clone().unwrap_or_else(|| record_id.clone());
        let content_type = fields.get("Content-Type").cloned();

        entries.push(WarcEntry {
            name,
            data: block,
            record_type,
            record_id,
            date,
            content_type,
            target_uri,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn record(rtype: &str, uri: Option<&str>, block: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"WARC/1.1\r\n");
        r.extend_from_slice(format!("WARC-Type: {rtype}\r\n").as_bytes());
        r.extend_from_slice(b"WARC-Record-ID: <urn:uuid:test-1>\r\n");
        r.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
        if let Some(u) = uri {
            r.extend_from_slice(format!("WARC-Target-URI: {u}\r\n").as_bytes());
        }
        r.extend_from_slice(b"Content-Type: text/plain\r\n");
        r.extend_from_slice(format!("Content-Length: {}\r\n", block.len()).as_bytes());
        r.extend_from_slice(b"\r\n");
        r.extend_from_slice(block);
        r.extend_from_slice(b"\r\n\r\n");
        r
    }

    #[test]
    fn parses_single_record() {
        let data = record("resource", Some("http://example.com/"), b"body");
        let entries = decode(&data).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "http://example.com/");
        assert_eq!(entries[0].data, b"body");
        assert_eq!(entries[0].record_type, "resource");
        assert_eq!(entries[0].record_id, "<urn:uuid:test-1>");
        assert_eq!(entries[0].date.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn parses_multiple_records() {
        let mut data = record("warcinfo", None, b"info");
        data.extend_from_slice(&record("response", Some("http://a/"), b"resp"));
        let entries = decode(&data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].record_type, "warcinfo");
        assert_eq!(entries[0].name, "<urn:uuid:test-1>"); // falls back to record id
        assert_eq!(entries[1].name, "http://a/");
        assert_eq!(entries[1].data, b"resp");
    }

    #[test]
    fn tolerates_warc_1_0() {
        let mut data = record("resource", None, b"x");
        data[..8].copy_from_slice(b"WARC/1.0");
        assert!(decode(&data).is_ok());
    }

    #[test]
    fn header_folding_joins_value() {
        let mut data = Vec::new();
        data.extend_from_slice(b"WARC/1.1\r\n");
        data.extend_from_slice(b"WARC-Type: resource\r\n");
        data.extend_from_slice(b"WARC-Record-ID: <urn:x>\r\n");
        data.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
        data.extend_from_slice(b"WARC-Target-URI: http://e/\r\n");
        data.extend_from_slice(b"X-Custom: first\r\n second\r\n");
        data.extend_from_slice(b"Content-Length: 1\r\n\r\nx\r\n\r\n");
        let entries = decode(&data).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_bad_version() {
        let mut data = record("resource", None, b"x");
        data[5] = b'9';
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_missing_mandatory_field() {
        let mut data = Vec::new();
        data.extend_from_slice(b"WARC/1.1\r\n");
        data.extend_from_slice(b"WARC-Type: resource\r\n"); // no ID/Date
        data.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        assert!(decode(&data).is_err());
    }

    #[test]
    fn rejects_truncated_block() {
        let mut data = record("resource", None, b"0123456789");
        data.truncate(data.len() - 8); // cut into block
        assert!(decode(&data).is_err());
    }

    #[test]
    fn empty_stream() {
        assert_eq!(decode(b"").unwrap().len(), 0);
        assert_eq!(decode(b"\r\n\r\n").unwrap().len(), 0);
    }
}
