//! mtree(5) manifest decoding.
//!
//! Parses the line-oriented BSD mtree format: `#`-comments (including
//! the `#mtree` signature line), `/set` and `/unset` default commands,
//! relative and full path entries, `..` directory pops, and keyword
//! definitions (`key=value`). `\ooo` octal escapes in names and values
//! are decoded.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::Error;

/// mtree entry type keyword value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtreeKind {
    /// `type=file`
    File,
    /// `type=dir`
    Dir,
    /// `type=link` (symbolic link; target in [`MtreeEntry::link`]).
    Link,
    /// `type=block`
    Block,
    /// `type=char`
    Char,
    /// `type=fifo`
    Fifo,
    /// `type=socket`
    Socket,
    /// Unrecognised `type=` value, preserved verbatim.
    Other(String),
}

/// A decoded mtree entry. File content is not part of the format, so
/// [`ArchiveEntry::data`](crate::traits::ArchiveEntry::data) is empty.
#[derive(Debug, Clone)]
pub struct MtreeEntry {
    /// Normalized relative path (no leading `./`).
    pub name: String,
    /// Entry type (`type=` keyword or `/set` default; defaults to `file`).
    pub kind: MtreeKind,
    /// `size=` in bytes.
    pub size: Option<u64>,
    /// `mode=` as parsed octal permissions.
    pub mode: Option<u32>,
    /// `uid=`.
    pub uid: Option<u32>,
    /// `gid=`.
    pub gid: Option<u32>,
    /// `uname=` owner name.
    pub uname: Option<String>,
    /// `gname=` group name.
    pub gname: Option<String>,
    /// `time=` raw `seconds.nanoseconds` string.
    pub time: Option<String>,
    /// `link=` symlink target.
    pub link: Option<String>,
    /// Digest keywords (`md5`/`sha1`/`sha256`/`sha384`/`sha512`/`rmd160`
    /// and their `*digest` synonyms), keyed by normalised algorithm name.
    pub digests: BTreeMap<String, String>,
}

impl crate::traits::ArchiveEntry for MtreeEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &[]
    }
}

/// Decode `\ooo` octal escapes and `\\` in a mtree token.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let mut j = i + 1;
            let mut val = 0u32;
            let mut digits = 0;
            while j < bytes.len() && digits < 3 && bytes[j].is_ascii_digit() && bytes[j] < b'8' {
                val = val * 8 + u32::from(bytes[j] - b'0');
                j += 1;
                digits += 1;
            }
            if digits > 0 {
                out.push(val as u8);
                i = j;
                continue;
            }
            // Non-octal escape: keep the escaped byte literally.
            out.push(bytes[i + 1]);
            i += 2;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_keywords(tokens: &[&str]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for t in tokens {
        if let Some((k, v)) = t.split_once('=') {
            map.insert(k.to_string(), unescape(v));
        } else {
            // bare keyword (e.g. `nochange`, `ignore`)
            map.insert((*t).to_string(), String::new());
        }
    }
    map
}

fn kind_of(v: &str) -> MtreeKind {
    match v {
        "file" => MtreeKind::File,
        "dir" => MtreeKind::Dir,
        "link" => MtreeKind::Link,
        "block" => MtreeKind::Block,
        "char" => MtreeKind::Char,
        "fifo" => MtreeKind::Fifo,
        "socket" => MtreeKind::Socket,
        other => MtreeKind::Other(other.to_string()),
    }
}

/// Normalise a digest keyword name to its canonical algorithm.
fn digest_name(k: &str) -> Option<&'static str> {
    Some(match k {
        "md5" | "md5digest" => "md5",
        "sha1" | "sha1digest" => "sha1",
        "sha256" | "sha256digest" => "sha256",
        "sha384" | "sha384digest" => "sha384",
        "sha512" | "sha512digest" => "sha512",
        "rmd160" | "rmd160digest" | "ripemd160digest" => "rmd160",
        _ => return None,
    })
}

fn entry_from(name: String, kw: BTreeMap<String, String>) -> MtreeEntry {
    let kind = kw
        .get("type")
        .map(|v| kind_of(v))
        .unwrap_or(MtreeKind::File);
    let digests = kw
        .iter()
        .filter_map(|(k, v)| digest_name(k).map(|n| (n.to_string(), v.clone())))
        .collect();
    MtreeEntry {
        name,
        kind,
        size: kw.get("size").and_then(|v| v.parse().ok()),
        mode: kw.get("mode").and_then(|v| u32::from_str_radix(v, 8).ok()),
        uid: kw.get("uid").and_then(|v| v.parse().ok()),
        gid: kw.get("gid").and_then(|v| v.parse().ok()),
        uname: kw.get("uname").cloned(),
        gname: kw.get("gname").cloned(),
        time: kw.get("time").cloned(),
        link: kw.get("link").cloned(),
        digests,
    }
}

/// Decode an mtree manifest into entries.
///
/// Relative entries are resolved against the directory stack; `..`
/// pops it. `/set` defaults apply until `/unset`. Comment lines and
/// blank lines are skipped. A `#mtree` signature line is not required.
pub fn decode(input: &[u8]) -> Result<Vec<MtreeEntry>, Error> {
    let text =
        core::str::from_utf8(input).map_err(|_| Error::InvalidData("mtree: not valid UTF-8"))?;

    let mut defaults: BTreeMap<String, String> = BTreeMap::new();
    let mut cwd: Vec<String> = Vec::new();
    let mut entries = Vec::new();

    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim_end_matches(['\r', '\n']);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue; // includes the "#mtree" signature comment
        }

        let mut tokens = line.split_whitespace();
        let first = tokens.next().unwrap_or("");

        if first == "/set" {
            for (k, v) in parse_keywords(&tokens.collect::<Vec<_>>()) {
                defaults.insert(k, v);
            }
            continue;
        }
        if first == "/unset" {
            for k in tokens {
                defaults.remove(k);
            }
            continue;
        }

        let name = unescape(first);
        let kw_tokens: Vec<&str> = tokens.collect();
        let mut kw = parse_keywords(&kw_tokens);
        // Apply /set defaults for absent keys.
        for (k, v) in &defaults {
            kw.entry(k.clone()).or_insert_with(|| v.clone());
        }

        if name == ".." {
            cwd.pop();
            continue;
        }

        // Full entries contain a '/' after the first character.
        let (path, is_relative) = if name.len() > 1 && name[1..].contains('/') {
            (
                name.trim_start_matches("./")
                    .trim_start_matches('/')
                    .to_string(),
                false,
            )
        } else {
            let mut p = cwd.join("/");
            if !p.is_empty() {
                p.push('/');
            }
            p.push_str(&name);
            (p, true)
        };
        if path.is_empty() {
            return Err(Error::InvalidData("mtree: empty path"));
        }
        let _ = lineno;

        let entry = entry_from(path, kw);
        if is_relative && entry.kind == MtreeKind::Dir {
            cwd.push(name);
        }
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;

    const BASIC: &str = "#mtree\n/set type=file uid=0 gid=0 mode=644 uname=root gname=root\n./hello.txt size=5 time=1700000000.000000000 sha256digest=abc123\ndir type=dir mode=755\nfile2.txt size=10\nlink.txt type=link link=hello.txt\n..\n./after.txt size=1\n";

    #[test]
    fn parses_basic_manifest() {
        let entries = decode(BASIC.as_bytes()).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].name, "hello.txt");
        assert_eq!(entries[0].kind, MtreeKind::File);
        assert_eq!(entries[0].size, Some(5));
        assert_eq!(entries[0].mode, Some(0o644));
        assert_eq!(entries[0].uid, Some(0));
        assert_eq!(entries[0].uname.as_deref(), Some("root"));
        assert_eq!(
            entries[0].digests.get("sha256").map(|s| s.as_str()),
            Some("abc123")
        );
        assert!(entries[0].data().is_empty());
    }

    #[test]
    fn relative_entries_descend_into_dirs() {
        let entries = decode(BASIC.as_bytes()).unwrap();
        assert_eq!(entries[1].name, "dir");
        assert_eq!(entries[1].kind, MtreeKind::Dir);
        // children inside dir
        assert_eq!(entries[2].name, "dir/file2.txt");
        assert_eq!(entries[3].name, "dir/link.txt");
        assert_eq!(entries[3].kind, MtreeKind::Link);
        assert_eq!(entries[3].link.as_deref(), Some("hello.txt"));
        // after
        assert_eq!(entries[4].name, "after.txt");
    }

    #[test]
    fn full_paths_are_absolute_relative_to_root() {
        let text = "#mtree\n./a/b/c.txt type=file\n./x.txt size=3\n";
        let entries = decode(text.as_bytes()).unwrap();
        assert_eq!(entries[0].name, "a/b/c.txt");
        assert_eq!(entries[1].name, "x.txt");
    }

    #[test]
    fn unset_removes_defaults() {
        let text = "#mtree\n/set mode=644 uid=0\n./a.txt\n/unset uid\n./b.txt\n";
        let entries = decode(text.as_bytes()).unwrap();
        assert_eq!(entries[0].uid, Some(0));
        assert_eq!(entries[1].uid, None);
        assert_eq!(entries[1].mode, Some(0o644));
    }

    #[test]
    fn octal_escapes_in_names() {
        let text = "#mtree\n./file\\040with\\040space.txt size=1\n";
        let entries = decode(text.as_bytes()).unwrap();
        assert_eq!(entries[0].name, "file with space.txt");
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let text = "#mtree\n# comment\n\n   \n./f.txt\n";
        let entries = decode(text.as_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn no_signature_required() {
        let entries = decode(b"./f.txt size=1\n").unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn rejects_non_utf8() {
        assert!(matches!(decode(&[0xff, 0xfe]), Err(Error::InvalidData(_))));
    }

    #[test]
    fn digest_synonyms_normalised() {
        let text = "./a sha256=x md5digest=y\n";
        let entries = decode(text.as_bytes()).unwrap();
        assert_eq!(entries[0].digests["sha256"], "x");
        assert_eq!(entries[0].digests["md5"], "y");
    }
}
