//! WARC record stream decoding.
//!
//! Grammar (WARC 1.0/1.1):
//! `version-line CRLF *(named-field CRLF) CRLF block CRLF CRLF`
//!
//! where version-line is `WARC/1.0` or `WARC/1.1`, named fields are
//! `token ":" SP* value` with optional LWS folding, and block is
//! `Content-Length` octets. Unknown fields are ignored per spec.
//!
//! `WARC-Block-Digest` fields (`algo:base32`) are verified against the
//! record block, and `WARC-Payload-Digest` is verified when the payload
//! is known to be the whole block (not for `application/http` blocks
//! whose payload is the entity-body, nor for `revisit`, `continuation`,
//! segmented, or truncated records whose payload may not match the
//! block). Only `sha1` digests are checked; other algorithms are
//! ignored like other unknown fields.
//!
//! Per-record, the field-usage constraints of WARC 1.1 "named fields"
//! are enforced for the eight defined record types (e.g.
//! `WARC-Filename` is `warcinfo`-only, `WARC-Target-URI` is
//! required on content records and forbidden on `warcinfo`), and
//! Clause 7 record segmentation is validated: `continuation` records
//! must carry `WARC-Segment-Origin-ID` plus a
//! `WARC-Segment-Number` continuing the series by exactly one, and a
//! series closed by `WARC-Segment-Total-Length` (which must equal the
//! summed block lengths when the whole series is observed) accepts no
//! further segments. A series first observed through a
//! `continuation` record is tracked leniently because earlier
//! segments may live in an earlier WARC file. Segment reassembly is
//! not performed.

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
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
            return Err(Error::InvalidData("warc: bad field name"));
        }
        fields.insert(name.to_string(), value.trim().to_string());
        last_name = Some(name.to_string());
    }
    Ok(fields)
}

/// RFC 4648 Base32 decode (uppercase or lowercase, `=` padding
/// optional). Returns `None` on invalid characters or an impossible
/// leftover-bit count.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a')),
            b'2'..=b'7' => Some(u32::from(b - b'2' + 26)),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s.trim_end_matches('=').as_bytes() {
        acc = (acc << 5) | val(b)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Valid Base32 encodings leave 0, 2, 4, 5, or 7 leftover bits.
    if !matches!(bits, 0 | 2 | 4 | 5 | 7) {
        return None;
    }
    Some(out)
}

/// Check one `algo:base32` digest field against `data`. Only `sha1` is
/// verified; other algorithm labels are ignored, matching the handling
/// of unknown fields. A malformed `sha1` value or a hash mismatch is
/// rejected.
fn verify_digest(value: &str, data: &[u8], mismatch: &'static str) -> Result<(), Error> {
    let Some((algo, b32)) = value.split_once(':') else {
        return Err(Error::InvalidData("warc: malformed digest field"));
    };
    if !algo.trim().eq_ignore_ascii_case("sha1") {
        return Ok(());
    }
    let want =
        base32_decode(b32.trim()).ok_or(Error::InvalidData("warc: malformed digest field"))?;
    if want[..] != crate::util::sha1::sha1(data)[..] {
        return Err(Error::InvalidData(mismatch));
    }
    Ok(())
}

/// True when the record payload is known to be the whole block, so
/// `WARC-Payload-Digest` can be checked directly. The payload is not
/// the block for `application/http` messages (payload = entity-body,
/// which is not parsed here), is absent or stored elsewhere for
/// `revisit` / truncated records, and spans records for segmented
/// ones - those digests are left unchecked.
fn payload_is_block(
    fields: &BTreeMap<String, String>,
    record_type: &str,
    content_type: Option<&str>,
) -> bool {
    for t in ["response", "request", "revisit", "continuation"] {
        if record_type.eq_ignore_ascii_case(t) {
            return false;
        }
    }
    for f in [
        "WARC-Segment-Origin-ID",
        "WARC-Segment-Number",
        "WARC-Truncated",
    ] {
        if fields.contains_key(f) {
            return false;
        }
    }
    if let Some(ct) = content_type {
        let ct = ct.trim_start().as_bytes();
        if ct.len() >= b"application/http".len()
            && ct[..b"application/http".len()].eq_ignore_ascii_case(b"application/http")
        {
            return false;
        }
    }
    true
}

/// Verify `WARC-Block-Digest` and, when the payload is identifiable,
/// `WARC-Payload-Digest` header fields against the record block.
fn verify_digests(
    fields: &BTreeMap<String, String>,
    record_type: &str,
    content_type: Option<&str>,
    block: &[u8],
) -> Result<(), Error> {
    if let Some(v) = fields.get("WARC-Block-Digest") {
        verify_digest(v, block, "warc: WARC-Block-Digest mismatch")?;
    }
    if let Some(v) = fields.get("WARC-Payload-Digest")
        && payload_is_block(fields, record_type, content_type)
    {
        verify_digest(v, block, "warc: WARC-Payload-Digest mismatch")?;
    }
    Ok(())
}

/// The eight record types defined by WARC 1.1. Records of unknown
/// type are skipped per spec ("WARC processing software shall skip
/// records of unknown type"), so the type-specific constraints below
/// only apply to these.
const KNOWN_TYPES: &[&str] = &[
    "warcinfo",
    "response",
    "resource",
    "request",
    "metadata",
    "revisit",
    "conversion",
    "continuation",
];

/// Field -> record types on which the field is forbidden, per the
/// "shall not be used" lists of WARC 1.1 "named fields". Only the
/// combinations the spec spells out are enforced.
const FORBIDDEN_FIELD_TYPES: &[(&str, &[&str])] = &[
    // WARC-Concurrent-To: "shall not be used in 'warcinfo',
    // 'conversion', and 'continuation' records".
    (
        "WARC-Concurrent-To",
        &["warcinfo", "conversion", "continuation"],
    ),
    // WARC-IP-Address: "shall not be used on 'warcinfo', 'conversion'
    // or 'continuation' records".
    (
        "WARC-IP-Address",
        &["warcinfo", "conversion", "continuation"],
    ),
    // WARC-Refers-To: "shall not be used in 'warcinfo', 'response',
    // 'resource', 'request', and 'continuation' records".
    (
        "WARC-Refers-To",
        &[
            "warcinfo",
            "response",
            "resource",
            "request",
            "continuation",
        ],
    ),
    // WARC-Refers-To-Target-URI and WARC-Refers-To-Date: "may be used
    // in 'revisit' records and shall not be used in 'warcinfo',
    // 'response', 'metadata', 'conversion', 'resource', 'request', and
    // 'continuation' records".
    (
        "WARC-Refers-To-Target-URI",
        &[
            "warcinfo",
            "response",
            "metadata",
            "conversion",
            "resource",
            "request",
            "continuation",
        ],
    ),
    (
        "WARC-Refers-To-Date",
        &[
            "warcinfo",
            "response",
            "metadata",
            "conversion",
            "resource",
            "request",
            "continuation",
        ],
    ),
    // WARC-Warcinfo-ID: "may be used in any record type except
    // 'warcinfo'".
    ("WARC-Warcinfo-ID", &["warcinfo"]),
    // WARC-Target-URI: "A 'warcinfo' record shall not have a
    // WARC-Target-URI field".
    ("WARC-Target-URI", &["warcinfo"]),
];

/// Fields restricted to a single record type ("shall not be used for
/// other record types" / "shall not be used elsewhere").
const SINGLE_TYPE_FIELDS: &[(&str, &str)] = &[
    ("WARC-Filename", "warcinfo"),
    ("WARC-Segment-Origin-ID", "continuation"),
    ("WARC-Segment-Total-Length", "continuation"),
];

/// Record types that shall carry a WARC-Target-URI field
/// (WARC-Target-URI definition); 'metadata' may and 'warcinfo' shall
/// not (handled above).
const TARGET_URI_TYPES: &[&str] = &[
    "response",
    "resource",
    "request",
    "revisit",
    "conversion",
    "continuation",
];

fn type_is(record_type: &str, list: &[&str]) -> bool {
    list.iter().any(|t| record_type.eq_ignore_ascii_case(t))
}

/// Enforce the per-record-type field constraints of WARC 1.1 "named
/// fields": forbidden field/type combinations, single-type fields, and
/// the mandatory WARC-Target-URI. Unknown record types pass unchecked,
/// matching the "skip records of unknown type" rule.
fn check_field_constraints(
    fields: &BTreeMap<String, String>,
    record_type: &str,
) -> Result<(), Error> {
    if !type_is(record_type, KNOWN_TYPES) {
        return Ok(());
    }
    for (field, banned) in FORBIDDEN_FIELD_TYPES {
        if fields.contains_key(*field) && type_is(record_type, banned) {
            return Err(Error::InvalidData(
                "warc: field not allowed on this record type",
            ));
        }
    }
    for (field, only) in SINGLE_TYPE_FIELDS {
        if fields.contains_key(*field) && !record_type.eq_ignore_ascii_case(only) {
            return Err(Error::InvalidData(
                "warc: field restricted to another record type",
            ));
        }
    }
    if type_is(record_type, TARGET_URI_TYPES) && !fields.contains_key("WARC-Target-URI") {
        return Err(Error::InvalidData("warc: missing WARC-Target-URI"));
    }
    Ok(())
}

/// Tracking state for one segmented-record series (WARC 1.1 Clause 7),
/// keyed by the WARC-Record-ID of the first segment, which
/// 'continuation' records repeat as WARC-Segment-Origin-ID.
struct SegmentSeries {
    /// Last observed WARC-Segment-Number in this stream.
    last_number: u64,
    /// Sum of the block lengths observed for this series.
    block_total: u64,
    /// WARC-Target-URI of the first observed segment; all segments of
    /// a set shall carry identical target-URI values.
    target_uri: Option<String>,
    /// Whether the origin segment (number 1) was observed. Only then
    /// can WARC-Segment-Total-Length be checked against
    /// `block_total`; a series first seen mid-way may continue a
    /// series started in another WARC file.
    from_origin: bool,
    /// WARC-Segment-Total-Length was seen: the series is closed and no
    /// further segment may follow.
    closed: bool,
}

/// Parse a `1*DIGIT` field value (WARC-Segment-Number,
/// WARC-Segment-Total-Length).
fn parse_digits(fields: &BTreeMap<String, String>, name: &str) -> Result<Option<u64>, Error> {
    match fields.get(name) {
        None => Ok(None),
        Some(v) => {
            let v = v.trim();
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::InvalidData("warc: bad numeric field"));
            }
            v.parse::<u64>()
                .map(Some)
                .map_err(|_| Error::InvalidData("warc: bad numeric field"))
        }
    }
}

/// Enforce the WARC 1.1 Clause 7 segmentation rules observable within
/// a single stream. 'continuation' records must carry
/// WARC-Segment-Origin-ID and a WARC-Segment-Number greater than 1
/// that continues its series by exactly one; a non-'continuation'
/// record carrying WARC-Segment-Number starts a series and must use
/// value "1". WARC-Segment-Total-Length closes a series and, when the
/// origin segment was observed, must equal the summed block lengths.
/// A series whose first observed record is a 'continuation' is tracked
/// leniently because earlier segments may live in another WARC file.
fn check_segmentation(
    fields: &BTreeMap<String, String>,
    record_type: &str,
    record_id: &str,
    block_len: u64,
    series: &mut BTreeMap<String, SegmentSeries>,
) -> Result<(), Error> {
    let number = parse_digits(fields, "WARC-Segment-Number")?;
    let total_len = parse_digits(fields, "WARC-Segment-Total-Length")?;

    if record_type.eq_ignore_ascii_case("continuation") {
        let origin = fields
            .get("WARC-Segment-Origin-ID")
            .ok_or(Error::InvalidData(
                "warc: continuation missing WARC-Segment-Origin-ID",
            ))?;
        let number = number.ok_or(Error::InvalidData(
            "warc: continuation missing WARC-Segment-Number",
        ))?;
        if number < 2 {
            // The first segment carries the original record type, not
            // 'continuation'.
            return Err(Error::InvalidData(
                "warc: bad continuation WARC-Segment-Number",
            ));
        }
        let target_uri = fields.get("WARC-Target-URI").cloned();
        match series.get_mut(origin) {
            Some(s) => {
                if s.closed {
                    return Err(Error::InvalidData(
                        "warc: segment after WARC-Segment-Total-Length",
                    ));
                }
                if number != s.last_number + 1 {
                    return Err(Error::InvalidData(
                        "warc: non-sequential WARC-Segment-Number",
                    ));
                }
                if s.target_uri != target_uri {
                    return Err(Error::InvalidData(
                        "warc: inconsistent segment WARC-Target-URI",
                    ));
                }
                s.last_number = number;
                s.block_total += block_len;
                if let Some(total) = total_len {
                    if s.from_origin && total != s.block_total {
                        return Err(Error::InvalidData(
                            "warc: WARC-Segment-Total-Length mismatch",
                        ));
                    }
                    s.closed = true;
                }
            }
            None => {
                // First observed record of this series is a
                // 'continuation': earlier segments live in another
                // WARC file. Track from here, but the total length
                // cannot be verified.
                series.insert(
                    origin.clone(),
                    SegmentSeries {
                        last_number: number,
                        block_total: block_len,
                        target_uri,
                        from_origin: false,
                        closed: total_len.is_some(),
                    },
                );
            }
        }
        return Ok(());
    }

    // Non-'continuation': a WARC-Segment-Number marks the first
    // segment of a series and its value there is "1".
    if let Some(n) = number {
        if n != 1 {
            return Err(Error::InvalidData(
                "warc: first WARC-Segment-Number must be 1",
            ));
        }
        if series.contains_key(record_id) {
            return Err(Error::InvalidData("warc: duplicate segment origin"));
        }
        series.insert(
            record_id.to_string(),
            SegmentSeries {
                last_number: 1,
                block_total: block_len,
                target_uri: fields.get("WARC-Target-URI").cloned(),
                from_origin: true,
                closed: false,
            },
        );
    }
    Ok(())
}

/// Decode a WARC record stream into entries.
///
/// `input` must be a raw WARC stream (decompress `.warc.gz` first).
/// Trailing whitespace between records is tolerated. `WARC-Block-Digest`
/// (and `WARC-Payload-Digest` where the payload is the whole block) is
/// verified for `sha1` digests; other digest algorithms are ignored.
/// Record-type field constraints and intra-file segmentation rules
/// (WARC 1.1 Clause 7) are enforced; records of unknown type are
/// passed through per spec.
pub fn decode(input: &[u8]) -> Result<Vec<WarcEntry>, Error> {
    let mut pos = 0usize;
    let mut entries = Vec::new();
    let mut series: BTreeMap<String, SegmentSeries> = BTreeMap::new();

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

        check_field_constraints(&fields, &record_type)?;
        check_segmentation(
            &fields,
            &record_type,
            &record_id,
            block.len() as u64,
            &mut series,
        )?;
        verify_digests(&fields, &record_type, content_type.as_deref(), &block)?;

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
    use alloc::format;
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
        let mut data = record("resource", Some("http://e/"), b"x");
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

    #[test]
    fn rejects_bad_field_name() {
        // Field names must be printable ASCII without SP/ctrl/colon.
        for bad in [
            &b"Bad Name: v"[..],
            b"Bad\x01Name: v",
            b": v",
            b"Bad\x7fName: v",
        ] {
            let mut data = Vec::new();
            data.extend_from_slice(b"WARC/1.1\r\n");
            data.extend_from_slice(b"WARC-Type: resource\r\n");
            data.extend_from_slice(b"WARC-Record-ID: <urn:x>\r\n");
            data.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
            data.extend_from_slice(bad);
            data.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
            assert!(
                matches!(decode(&data), Err(Error::InvalidData(_))),
                "accepted bad field name: {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_non_utf8_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"WARC/1.1\r\n");
        data.extend_from_slice(b"WARC-Type: resource\r\n");
        data.extend_from_slice(b"WARC-Record-ID: <urn:x>\r\n");
        data.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
        data.extend_from_slice(b"X-Bad: \xff\xfe\r\n");
        data.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    /// Build a record with caller-supplied extra header lines.
    fn record_lines(rtype: &str, lines: &[&str], block: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(b"WARC/1.1\r\n");
        r.extend_from_slice(format!("WARC-Type: {rtype}\r\n").as_bytes());
        r.extend_from_slice(b"WARC-Record-ID: <urn:uuid:test-1>\r\n");
        r.extend_from_slice(b"WARC-Date: 2024-01-01T00:00:00Z\r\n");
        for l in lines {
            r.extend_from_slice(l.as_bytes());
            r.extend_from_slice(b"\r\n");
        }
        r.extend_from_slice(format!("Content-Length: {}\r\n", block.len()).as_bytes());
        r.extend_from_slice(b"\r\n");
        r.extend_from_slice(block);
        r.extend_from_slice(b"\r\n\r\n");
        r
    }

    fn sha1_label(data: &[u8]) -> String {
        let mut s = String::from("sha1:");
        crate::archive::warc::encode::base32_into(&crate::util::sha1::sha1(data), &mut s);
        s
    }

    #[test]
    fn verifies_block_digest() {
        let d = sha1_label(b"body");
        let data = record_lines(
            "resource",
            &[
                "WARC-Target-URI: http://e/",
                format!("WARC-Block-Digest: {d}").as_str(),
            ],
            b"body",
        );
        assert_eq!(decode(&data).unwrap().len(), 1);
        // Encoder output carries a block digest and must decode.
        let mut r = crate::archive::warc::encode::WarcRecord::new(
            "resource",
            "urn:x",
            "2024-01-01T00:00:00Z",
            b"body",
        );
        r.target_uri = Some("http://e/".to_string());
        let enc = crate::archive::warc::encode::encode(&[r]).unwrap();
        assert!(
            enc.windows(b"WARC-Block-Digest".len())
                .any(|w| w == b"WARC-Block-Digest")
        );
        assert_eq!(decode(&enc).unwrap().len(), 1);
    }

    #[test]
    fn rejects_wrong_block_digest() {
        // Digest of different content.
        let d = sha1_label(b"other");
        let data = record_lines(
            "resource",
            &[
                "WARC-Target-URI: http://e/",
                format!("WARC-Block-Digest: {d}").as_str(),
            ],
            b"body",
        );
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_malformed_block_digest() {
        for line in [
            "WARC-Block-Digest: sha1",     // missing ':' and hash
            "WARC-Block-Digest: sha1:!!!", // invalid base32
            "WARC-Block-Digest: sha1:MY",  // decodes but wrong length
            "WARC-Block-Digest: sha1:M",   // impossible leftover bits
        ] {
            let data = record_lines("resource", &["WARC-Target-URI: http://e/", line], b"body");
            assert!(
                matches!(decode(&data), Err(Error::InvalidData(_))),
                "accepted {line}"
            );
        }
    }

    #[test]
    fn skips_unknown_digest_algorithm() {
        // Non-sha1 algorithms are ignored, like other unknown fields.
        let data = record_lines(
            "resource",
            &[
                "WARC-Target-URI: http://e/",
                "WARC-Block-Digest: sha256:AAAA",
                "WARC-Payload-Digest: md5:BBBB",
            ],
            b"body",
        );
        assert_eq!(decode(&data).unwrap().len(), 1);
    }

    #[test]
    fn verifies_payload_digest_for_opaque_block() {
        let d = sha1_label(b"body");
        let data = record_lines(
            "metadata",
            &[format!("WARC-Payload-Digest: {d}").as_str()],
            b"body",
        );
        assert!(decode(&data).is_ok());

        let d = sha1_label(b"other");
        let data = record_lines(
            "metadata",
            &[format!("WARC-Payload-Digest: {d}").as_str()],
            b"body",
        );
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn skips_payload_digest_when_payload_not_block() {
        let wrong = sha1_label(b"something else");
        let field = format!("WARC-Payload-Digest: {wrong}");

        // application/http block: payload is the entity-body, not the block.
        let data = record_lines(
            "response",
            &[
                "WARC-Target-URI: http://e/",
                "Content-Type: application/http; msgtype=response",
                field.as_str(),
            ],
            b"HTTP/1.1 200 OK\r\n\r\nx",
        );
        assert!(decode(&data).is_ok());

        // revisit: digest refers to a payload stored elsewhere.
        let data = record_lines(
            "revisit",
            &[
                "WARC-Target-URI: http://e/",
                "Content-Type: text/plain",
                field.as_str(),
            ],
            b"headers only",
        );
        assert!(decode(&data).is_ok());

        // segmented record: payload spans multiple records.
        let data = record_lines(
            "resource",
            &[
                "WARC-Target-URI: http://e/",
                "WARC-Segment-Number: 1",
                field.as_str(),
            ],
            b"body",
        );
        assert!(decode(&data).is_ok());
    }

    #[test]
    fn tolerates_missing_trailing_separator() {
        // The record terminator is not verified: a block without the
        // trailing CRLF CRLF still decodes, and the next record may follow
        // immediately.
        let data = record("resource", Some("http://a/"), b"body");
        let bare = &data[..data.len() - 4];
        assert_eq!(decode(bare).unwrap().len(), 1);

        let mut two = Vec::new();
        two.extend_from_slice(bare);
        two.extend_from_slice(&record("warcinfo", None, b"i")[..]);
        let entries = decode(&two).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"body");
    }

    /// Minimal otherwise-valid record for `rtype`: supplies the
    /// mandatory `WARC-Target-URI` (content record types) and, for
    /// `continuation`, the mandatory segment fields. `extra` lines are
    /// appended last so they can override defaults.
    fn valid_record(rtype: &str, extra: &[&str], block: &[u8]) -> Vec<u8> {
        let mut lines: Vec<String> = Vec::new();
        if matches!(
            rtype,
            "response" | "resource" | "request" | "revisit" | "conversion" | "continuation"
        ) {
            lines.push("WARC-Target-URI: http://e/".to_string());
        }
        if rtype == "continuation" {
            // Joins the series originated by record_lines()
            // (`WARC-Record-ID: <urn:uuid:test-1>`).
            lines.push("WARC-Segment-Origin-ID: <urn:uuid:test-1>".to_string());
            lines.push("WARC-Segment-Number: 2".to_string());
        }
        lines.extend(extra.iter().map(|s| (*s).to_string()));
        let refs: Vec<&str> = lines.iter().map(|s| s.as_str()).collect();
        record_lines(rtype, &refs, block)
    }

    #[test]
    fn rejects_field_forbidden_on_record_type() {
        // (field line, record types on which the field is banned) per
        // the "shall not" lists of WARC 1.1 named fields.
        let cases: &[(&str, &[&str])] = &[
            (
                "WARC-Concurrent-To: <urn:x:1>",
                &["warcinfo", "conversion", "continuation"],
            ),
            (
                "WARC-IP-Address: 192.0.2.1",
                &["warcinfo", "conversion", "continuation"],
            ),
            (
                "WARC-Refers-To: <urn:x:1>",
                &[
                    "warcinfo",
                    "response",
                    "resource",
                    "request",
                    "continuation",
                ],
            ),
            (
                "WARC-Refers-To-Target-URI: http://e/",
                &[
                    "warcinfo",
                    "response",
                    "metadata",
                    "conversion",
                    "resource",
                    "request",
                    "continuation",
                ],
            ),
            (
                "WARC-Refers-To-Date: 2024-01-01T00:00:00Z",
                &[
                    "warcinfo",
                    "response",
                    "metadata",
                    "conversion",
                    "resource",
                    "request",
                    "continuation",
                ],
            ),
            ("WARC-Warcinfo-ID: <urn:x:w>", &["warcinfo"]),
            ("WARC-Target-URI: http://e/", &["warcinfo"]),
            (
                "WARC-Filename: a.warc",
                &[
                    "response",
                    "resource",
                    "request",
                    "metadata",
                    "revisit",
                    "conversion",
                    "continuation",
                ],
            ),
            (
                "WARC-Segment-Origin-ID: <urn:x:o>",
                &[
                    "warcinfo",
                    "response",
                    "resource",
                    "request",
                    "metadata",
                    "revisit",
                    "conversion",
                ],
            ),
            (
                "WARC-Segment-Total-Length: 10",
                &[
                    "warcinfo",
                    "response",
                    "resource",
                    "request",
                    "metadata",
                    "revisit",
                    "conversion",
                ],
            ),
        ];
        for (field, banned) in cases {
            for t in *banned {
                let data = valid_record(t, &[*field], b"b");
                assert!(
                    matches!(decode(&data), Err(Error::InvalidData(_))),
                    "accepted {field} on {t}"
                );
            }
        }
    }

    #[test]
    fn accepts_field_on_allowed_record_type() {
        // WARC-Concurrent-To: request/response/resource/metadata/revisit.
        for t in ["request", "response", "resource", "metadata", "revisit"] {
            let data = valid_record(t, &["WARC-Concurrent-To: <urn:x:1>"], b"b");
            assert!(decode(&data).is_ok(), "rejected Concurrent-To on {t}");
        }
        // WARC-Refers-To: metadata/revisit/conversion.
        for t in ["metadata", "revisit", "conversion"] {
            let data = valid_record(t, &["WARC-Refers-To: <urn:x:1>"], b"b");
            assert!(decode(&data).is_ok(), "rejected Refers-To on {t}");
        }
        // WARC-Refers-To-Target-URI / -Date: revisit only.
        let data = valid_record(
            "revisit",
            &[
                "WARC-Refers-To-Target-URI: http://e/",
                "WARC-Refers-To-Date: 2024-01-01T00:00:00Z",
            ],
            b"b",
        );
        assert!(decode(&data).is_ok());
        // WARC-Warcinfo-ID: any type except warcinfo.
        for t in [
            "response",
            "resource",
            "request",
            "metadata",
            "revisit",
            "conversion",
            "continuation",
        ] {
            let data = valid_record(t, &["WARC-Warcinfo-ID: <urn:x:w>"], b"b");
            assert!(decode(&data).is_ok(), "rejected Warcinfo-ID on {t}");
        }
        // WARC-Filename: warcinfo only.
        let data = valid_record("warcinfo", &["WARC-Filename: a.warc"], b"b");
        assert!(decode(&data).is_ok());
        // metadata may omit WARC-Target-URI.
        assert!(decode(&valid_record("metadata", &[], b"b")).is_ok());
        // Unknown record types are skipped: no field constraints apply.
        let data = valid_record(
            "extension-type",
            &["WARC-Filename: a.warc", "WARC-Concurrent-To: <urn:x:1>"],
            b"b",
        );
        assert!(decode(&data).is_ok());
    }

    #[test]
    fn rejects_missing_target_uri() {
        for t in [
            "response",
            "resource",
            "request",
            "revisit",
            "conversion",
            "continuation",
        ] {
            let extra: &[&str] = if t == "continuation" {
                &[
                    "WARC-Segment-Origin-ID: <urn:x:o>",
                    "WARC-Segment-Number: 2",
                ]
            } else {
                &[]
            };
            let data = record_lines(t, extra, b"b");
            assert!(
                matches!(decode(&data), Err(Error::InvalidData(_))),
                "accepted {t} without WARC-Target-URI"
            );
        }
    }

    #[test]
    fn accepts_segmented_series() {
        // origin (resource, segment 1) + continuations 2,3 closed by a
        // correct WARC-Segment-Total-Length (2+2+2 = 6).
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record("continuation", &[], b"CD"));
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Segment-Number: 3", "WARC-Segment-Total-Length: 6"],
            b"EF",
        ));
        let entries = decode(&data).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].record_type, "continuation");
    }

    #[test]
    fn rejects_continuation_missing_segment_fields() {
        // Missing WARC-Segment-Origin-ID.
        let data = record_lines(
            "continuation",
            &["WARC-Target-URI: http://e/", "WARC-Segment-Number: 2"],
            b"b",
        );
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
        // Missing WARC-Segment-Number.
        let data = record_lines(
            "continuation",
            &[
                "WARC-Target-URI: http://e/",
                "WARC-Segment-Origin-ID: <urn:x:o>",
            ],
            b"b",
        );
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
        // Number 1 is reserved for the original-type first segment.
        let data = valid_record("continuation", &["WARC-Segment-Number: 1"], b"b");
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_bad_segment_number() {
        // A non-continuation record's WARC-Segment-Number must be "1".
        let data = valid_record("resource", &["WARC-Segment-Number: 3"], b"b");
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
        // Non-numeric values are rejected outright.
        let data = valid_record("resource", &["WARC-Segment-Number: x"], b"b");
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
        // A gap in the sequence (1, 2, 4) is rejected.
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record("continuation", &[], b"CD"));
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Segment-Number: 4"],
            b"EF",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
        // A repeated number (1, 2, 2) is rejected too.
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record("continuation", &[], b"CD"));
        data.extend_from_slice(&valid_record("continuation", &[], b"EF"));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_total_length_mismatch() {
        // Observed block lengths total 6, not 5.
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record("continuation", &[], b"CD"));
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Segment-Number: 3", "WARC-Segment-Total-Length: 5"],
            b"EF",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_segment_after_total_length() {
        // The series closes at segment 2; a further segment violates it.
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Segment-Total-Length: 4"],
            b"CD",
        ));
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Segment-Number: 3"],
            b"EF",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_duplicate_segment_origin() {
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record(
            "resource",
            &["WARC-Segment-Number: 1"],
            b"CD",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_segment_uri_mismatch() {
        // All segments of a set shall carry identical target-URI values.
        let mut data = valid_record("resource", &["WARC-Segment-Number: 1"], b"AB");
        data.extend_from_slice(&valid_record(
            "continuation",
            &["WARC-Target-URI: http://f/"],
            b"CD",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }

    #[test]
    fn accepts_late_joined_segment_series() {
        // Cross-file continuation: the first observed record of this
        // series is segment 3; earlier segments live in another file.
        // The stream is tracked from here (Total-Length cannot be
        // verified, so it is accepted unchecked).
        let mut data = valid_record(
            "continuation",
            &[
                "WARC-Segment-Origin-ID: <urn:x:o>",
                "WARC-Segment-Number: 3",
            ],
            b"CD",
        );
        data.extend_from_slice(&valid_record(
            "continuation",
            &[
                "WARC-Segment-Origin-ID: <urn:x:o>",
                "WARC-Segment-Number: 4",
                "WARC-Segment-Total-Length: 100",
            ],
            b"EF",
        ));
        assert_eq!(decode(&data).unwrap().len(), 2);
        // But numbering still must be sequential once observed.
        let mut data = valid_record(
            "continuation",
            &[
                "WARC-Segment-Origin-ID: <urn:x:o>",
                "WARC-Segment-Number: 3",
            ],
            b"CD",
        );
        data.extend_from_slice(&valid_record(
            "continuation",
            &[
                "WARC-Segment-Origin-ID: <urn:x:o>",
                "WARC-Segment-Number: 5",
            ],
            b"EF",
        ));
        assert!(matches!(decode(&data), Err(Error::InvalidData(_))));
    }
}
