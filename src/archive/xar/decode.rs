//! XAR archive decode.
//!
//! Parses the binary header, inflates and parses the XML table of
//! contents, verifies the TOC checksum stored at the start of the
//! heap, and extracts file data from the heap (stored or
//! compressed via `application/x-gzip`, `application/x-bzip2`,
//! `application/x-xz`, or `application/x-lzma`), verifying per-file
//! `extracted-checksum` values when present, and
//! `archived-checksum` digests over the stored bytes.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

use super::xml;

const MAGIC: [u8; 4] = *b"xar!";

fn invalid(msg: &'static str) -> Error {
    Error::InvalidData(msg)
}

/// One decoded entry from a XAR archive.
#[derive(Debug, Clone)]
pub struct XarEntry {
    /// Full path (parent directories joined with '/').
    pub name: String,
    /// Extracted file contents; empty for non-`file` types.
    pub data: Vec<u8>,
    /// The `<type>` element value (`file`, `directory`, `symlink`,
    /// `fifo`, `socket`, `character special`, `block special`,
    /// `hardlink`, or an extension value).
    pub file_type: String,
    pub is_dir: bool,
    /// Octal mode string from `<mode>` (e.g. "0755"), if present.
    pub mode: Option<String>,
    /// Owner user name (`<user>`), if present.
    pub user: Option<String>,
    /// Owner group name (`<group>`), if present.
    pub group: Option<String>,
    /// `<mtime>` timestamp string, if present.
    pub mtime: Option<String>,
    /// Link target for `symlink`/`hardlink` entries (`<link>` text).
    pub link: Option<String>,
}

impl crate::traits::ArchiveEntry for XarEntry {
    fn name(&self) -> &str {
        &self.name
    }
    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decode a complete XAR archive.
pub fn decode(input: &[u8]) -> Result<Vec<XarEntry>, Error> {
    // --- header ---
    if input.len() < 28 {
        return Err(invalid("xar: truncated header"));
    }
    if input[..4] != MAGIC {
        return Err(invalid("xar: bad magic"));
    }
    let hdr_size = u16::from_be_bytes(input[4..6].try_into().unwrap()) as usize;
    let version = u16::from_be_bytes(input[6..8].try_into().unwrap());
    let toc_comp = u64::from_be_bytes(input[8..16].try_into().unwrap()) as usize;
    let toc_raw = u64::from_be_bytes(input[16..24].try_into().unwrap()) as usize;
    let cksum_alg = u32::from_be_bytes(input[24..28].try_into().unwrap());
    if hdr_size < 28 {
        return Err(invalid("xar: header size too small"));
    }
    if version != 1 {
        // The reference library ignores the version field when
        // reading; accept it for robustness? Reject per spec SHOULD 1.
        return Err(Error::Unsupported("xar: unsupported header version"));
    }
    // Resolve the checksum algorithm: fixed ids 0/1/2, or a named
    // digest stored in an extended header for id 3.
    let cksum_kind = match cksum_alg {
        0 => None,
        1 => Some("sha1"),
        2 => Some("md5"),
        3 => {
            if hdr_size < 32 || !hdr_size.is_multiple_of(4) {
                return Err(invalid("xar: bad extended header"));
            }
            let name_bytes = &input[28..hdr_size.min(input.len())];
            let nul = name_bytes
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| invalid("xar: unterminated digest name"))?;
            if nul == 0 {
                return Err(invalid("xar: empty digest name"));
            }
            let name = core::str::from_utf8(&name_bytes[..nul])
                .map_err(|_| invalid("xar: bad digest name"))?;
            match name {
                "sha1" => Some("sha1"),
                "md5" => Some("md5"),
                "sha256" => Some("sha256"),
                _ => return Err(Error::Unsupported("xar: unsupported digest algorithm")),
            }
        }
        _ => return Err(Error::Unsupported("xar: unsupported checksum algorithm")),
    };
    if input.len() < hdr_size + toc_comp {
        return Err(invalid("xar: truncated table of contents"));
    }

    // --- table of contents ---
    let toc_packed = &input[hdr_size..hdr_size + toc_comp];
    let toc_bytes = crate::compress::zlib::decode::decode(toc_packed)
        .map_err(|_| invalid("xar: corrupt zlib table of contents"))?;
    if toc_bytes.len() != toc_raw {
        return Err(invalid("xar: TOC length mismatch"));
    }
    let toc_str = core::str::from_utf8(&toc_bytes).map_err(|_| invalid("xar: TOC is not UTF-8"))?;
    let root = xml::parse(toc_str)?;
    if root.name != "xar" {
        return Err(invalid("xar: missing <xar> root"));
    }
    let toc = root
        .child("toc")
        .ok_or_else(|| invalid("xar: missing <toc>"))?;

    // --- heap + TOC checksum ---
    let heap = &input[hdr_size + toc_comp..];
    if let Some(kind) = cksum_kind {
        let cksum = toc
            .child("checksum")
            .ok_or_else(|| invalid("xar: missing <checksum>"))?;
        if cksum.attr("style") != Some(kind) {
            return Err(invalid("xar: checksum style mismatch"));
        }
        let size = parse_u64(cksum.child_text("size"), "xar: bad checksum size")? as usize;
        let offset = parse_u64(cksum.child_text("offset"), "xar: bad checksum offset")? as usize;
        let expected = digest(kind, toc_packed)?;
        if expected.len() != size {
            return Err(invalid("xar: checksum size mismatch"));
        }
        if heap.len() < offset + size {
            return Err(invalid("xar: truncated heap checksum"));
        }
        if heap[offset..offset + size] != expected[..] {
            return Err(invalid("xar: TOC checksum mismatch"));
        }
    }

    // --- files ---
    let mut entries = Vec::new();
    for file in toc.children_named("file") {
        walk_file(file, "", heap, &mut entries)?;
    }
    Ok(entries)
}

fn parse_u64(text: Option<&str>, err: &'static str) -> Result<u64, Error> {
    text.and_then(|t| t.trim().parse::<u64>().ok())
        .ok_or_else(|| invalid(err))
}

fn digest(kind: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(match kind {
        "sha1" => crate::util::sha1::sha1(data).to_vec(),
        "md5" => crate::util::md5::md5(data).to_vec(),
        "sha256" => crate::util::sha256::sha256(data).to_vec(),
        _ => return Err(Error::Unsupported("xar: unsupported digest")),
    })
}

fn walk_file(
    node: &xml::Node,
    parent: &str,
    heap: &[u8],
    out: &mut Vec<XarEntry>,
) -> Result<(), Error> {
    let name = node
        .child_text("name")
        .ok_or_else(|| invalid("xar: file without <name>"))?;
    let file_type = node
        .child_text("type")
        .ok_or_else(|| invalid("xar: file without <type>"))?
        .to_string();
    let path = if parent.is_empty() {
        name.to_string()
    } else {
        alloc::format!("{parent}/{name}")
    };
    let is_dir = file_type == "directory";

    let mut data = Vec::new();
    if let Some(d) = node.child("data") {
        let offset = parse_u64(d.child_text("offset"), "xar: bad data offset")? as usize;
        let length = parse_u64(d.child_text("length"), "xar: bad data length")? as usize;
        let end = offset
            .checked_add(length)
            .filter(|&end| end <= heap.len())
            .ok_or_else(|| invalid("xar: data out of heap bounds"))?;
        let stored = &heap[offset..end];
        // Verify archived-checksum over the stored bytes before
        // decompression; unknown digest styles are not verified.
        if let Some(cs) = d.child("archived-checksum")
            && let Some(style) = cs.attr("style")
        {
            let expected =
                hex_bytes(cs.text.trim()).ok_or_else(|| invalid("xar: bad archived-checksum"))?;
            if let "sha1" | "md5" | "sha256" = style
                && digest(style, stored)?[..] != expected[..]
            {
                return Err(invalid("xar: archived-checksum mismatch"));
            }
        }
        let encoding = d
            .child("encoding")
            .and_then(|e| e.attr("style"))
            .unwrap_or("none");
        data = match encoding {
            "none" | "application/octet-stream" => stored.to_vec(),
            "application/x-gzip" => crate::compress::zlib::decode::decode(stored)
                .map_err(|_| invalid("xar: corrupt file data"))?,
            "application/x-bzip2" => crate::compress::bzip2::decode::decode(stored)
                .map_err(|_| invalid("xar: corrupt file data"))?,
            "application/x-xz" => crate::compress::xz::decode::decode(stored)
                .map_err(|_| invalid("xar: corrupt file data"))?,
            // libxar writes LZMA_Alone streams (5 props + u64le size).
            "application/x-lzma" => crate::compress::lzma_alone::decode::decode(stored)
                .map_err(|_| invalid("xar: corrupt file data"))?,
            _ => {
                return Err(Error::Unsupported("xar: unsupported data encoding"));
            }
        };
        // Verify declared extracted size if present.
        if let Some(size_text) = d.child_text("size")
            && let Ok(size) = size_text.trim().parse::<usize>()
            && size != data.len()
        {
            return Err(invalid("xar: extracted size mismatch"));
        }
        // Verify extracted-checksum when its style is supported.
        if let Some(cs) = d.child("extracted-checksum")
            && let Some(style) = cs.attr("style")
        {
            let expected =
                hex_bytes(cs.text.trim()).ok_or_else(|| invalid("xar: bad extracted-checksum"))?;
            // Unknown digest styles are not verified.
            if let "sha1" | "md5" | "sha256" = style
                && digest(style, &data)?[..] != expected[..]
            {
                return Err(invalid("xar: extracted-checksum mismatch"));
            }
        }
    }
    let link = node.child("link").map(|l| l.text.trim().to_string());
    out.push(XarEntry {
        name: path.clone(),
        data,
        file_type,
        is_dir,
        mode: node.child_text("mode").map(ToString::to_string),
        user: node.child_text("user").map(ToString::to_string),
        group: node.child_text("group").map(ToString::to_string),
        mtime: node.child_text("mtime").map(ToString::to_string),
        link,
    });
    for child in node.children_named("file") {
        walk_file(child, &path, heap, out)?;
    }
    Ok(())
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::sha1::sha1;
    use crate::util::sha256::sha256;

    fn hex_lower(data: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::new();
        for b in data {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    fn make_xar_cksum3(digest_name: &str, heap: &[u8], toc_xml: &str) -> Vec<u8> {
        // cksum_alg=3: extended header stores a NUL-terminated digest
        // name; hdr_size must be a multiple of 4.
        let name_len = digest_name.len() + 1; // + NUL
        let hdr_size = 28 + name_len.div_ceil(4) * 4;
        let toc_comp = crate::compress::zlib::encode::encode(toc_xml.as_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&(hdr_size as u16).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(toc_comp.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc_xml.len() as u64).to_be_bytes());
        out.extend_from_slice(&3u32.to_be_bytes());
        out.extend_from_slice(digest_name.as_bytes());
        out.push(0);
        out.resize(hdr_size, 0);
        out.extend_from_slice(&toc_comp);
        out.extend_from_slice(heap);
        out
    }

    #[test]
    fn test_cksum_alg3_named_digest() {
        // cksum_alg=3 with the digest named "sha1": the TOC checksum
        // element selects sha1 over the compressed TOC bytes.
        let toc = concat!(
            "<?xml version='1.0'?><xar><toc>",
            "<checksum style='sha1'><offset>0</offset><size>20</size></checksum>",
            "<file id='1'><name>f.txt</name><type>file</type>",
            "<data><offset>20</offset><size>5</size><length>5</length>",
            "<encoding style='none'/></data></file></toc></xar>"
        );
        let toc_comp = crate::compress::zlib::encode::encode(toc.as_bytes());
        let mut heap = sha1(&toc_comp).to_vec();
        heap.extend_from_slice(b"hello");
        let x = make_xar_cksum3("sha1", &heap, toc);
        let entries = decode(&x).unwrap();
        assert_eq!(entries[0].name, "f.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn test_cksum_alg3_sha256() {
        // cksum_alg=3 with the digest named "sha256": the TOC
        // checksum and the per-file archived/extracted checksums
        // all verify via SHA-256.
        let cksum = hex_lower(&sha256(b"hello"));
        let toc = alloc::format!(
            concat!(
                "<?xml version='1.0'?><xar><toc>",
                "<checksum style='sha256'><offset>0</offset><size>32</size></checksum>",
                "<file id='1'><name>f.txt</name><type>file</type>",
                "<data><offset>32</offset><size>5</size><length>5</length>",
                "<archived-checksum style='sha256'>{}</archived-checksum>",
                "<extracted-checksum style='sha256'>{}</extracted-checksum>",
                "<encoding style='none'/></data></file></toc></xar>"
            ),
            cksum,
            cksum,
        );
        let toc_comp = crate::compress::zlib::encode::encode(toc.as_bytes());
        let mut heap = sha256(&toc_comp).to_vec();
        heap.extend_from_slice(b"hello");
        let x = make_xar_cksum3("sha256", &heap, &toc);
        let entries = decode(&x).unwrap();
        assert_eq!(entries[0].name, "f.txt");
        assert_eq!(entries[0].data, b"hello");
    }

    #[test]
    fn test_cksum_alg3_sha256_mismatch() {
        // A corrupted sha256 TOC checksum and a tampered file byte
        // (caught by the sha256 archived-checksum) are rejected.
        let cksum = hex_lower(&sha256(b"hello"));
        let toc = alloc::format!(
            concat!(
                "<?xml version='1.0'?><xar><toc>",
                "<checksum style='sha256'><offset>0</offset><size>32</size></checksum>",
                "<file id='1'><name>f.txt</name><type>file</type>",
                "<data><offset>32</offset><size>5</size><length>5</length>",
                "<archived-checksum style='sha256'>{}</archived-checksum>",
                "<encoding style='none'/></data></file></toc></xar>"
            ),
            cksum,
        );
        let toc_comp = crate::compress::zlib::encode::encode(toc.as_bytes());

        // Corrupt the stored TOC checksum in the heap.
        let mut heap = sha256(&toc_comp).to_vec();
        heap.extend_from_slice(b"hello");
        heap[0] ^= 0xFF;
        let x = make_xar_cksum3("sha256", &heap, &toc);
        assert!(matches!(decode(&x), Err(Error::InvalidData(_))));

        // Corrupt the stored file bytes: sha256 mismatch.
        let mut heap = sha256(&toc_comp).to_vec();
        heap.extend_from_slice(b"jello");
        let x = make_xar_cksum3("sha256", &heap, &toc);
        assert!(matches!(decode(&x), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_cksum_alg3_unknown_digest_rejected() {
        // Digest names without a util implementation (sha512 etc.)
        // remain Unsupported.
        let x = make_xar_cksum3("sha512", &[], "<xar><toc/></xar>");
        assert!(matches!(decode(&x), Err(Error::Unsupported(_))));
    }
}
