//! mtree(5) manifest encoding.
//!
//! Emits the line-oriented BSD mtree format: a `#mtree` signature,
//! `/set` and `/unset` default commands, full-path entries
//! (`./a/b/c.txt`) with `key=value` keywords, and `\ooo` octal
//! escapes for bytes that would break tokenization (the inverse of
//! the decoder's unescape). Digest keywords are written in the
//! `<alg>digest=` form used by libarchive.
//!
//! Entries are always written in full-path form (legal per mtree(5));
//! the relative/`..` navigation form is an input-side concern only.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::archive::mtree::decode::MtreeEntry;
use crate::archive::mtree::decode::MtreeKind;
use crate::error::Error;

/// Encoder for mtree manifests.
pub struct MtreeEncoder {
    out: String,
}

impl MtreeEncoder {
    /// New encoder; the output starts with the `#mtree` signature.
    pub fn new() -> Self {
        MtreeEncoder {
            out: String::from("#mtree\n"),
        }
    }

    /// Emit a comment line (`# text`). A leading `#` in `text` is
    /// not required and is stripped to keep exactly one marker.
    pub fn comment(&mut self, text: &str) -> Result<(), Error> {
        check_line(text, "comment")?;
        self.out.push_str("# ");
        self.out.push_str(text.trim_start_matches('#').trim_start());
        self.out.push('\n');
        Ok(())
    }

    /// Emit `/set key=value ...` defaults applying to subsequent
    /// entries until removed with [`MtreeEncoder::unset`].
    pub fn set(&mut self, kvs: &[(&str, &str)]) -> Result<(), Error> {
        self.out.push_str("/set");
        for (k, v) in kvs {
            check_token(k, "keyword")?;
            self.out.push(' ');
            self.out.push_str(k);
            self.out.push('=');
            self.out.push_str(&escape(v));
        }
        self.out.push('\n');
        Ok(())
    }

    /// Emit `/unset key ...` removing defaults.
    pub fn unset(&mut self, keys: &[&str]) -> Result<(), Error> {
        self.out.push_str("/unset");
        for k in keys {
            check_token(k, "keyword")?;
            self.out.push(' ');
            self.out.push_str(k);
        }
        self.out.push('\n');
        Ok(())
    }

    /// Emit one full-path entry line `./path key=value ...`.
    pub fn add_entry(&mut self, e: &MtreeEntry) -> Result<(), Error> {
        let path = e.name.trim_start_matches("./").trim_start_matches('/');
        if path.is_empty() || path == "." || path.split('/').any(|c| c == "..") {
            return Err(Error::InvalidData("mtree: bad path"));
        }
        self.out.push_str("./");
        self.out.push_str(&escape(path));

        let mut kw = |k: &str, v: &str| {
            self.out.push(' ');
            self.out.push_str(k);
            self.out.push('=');
            self.out.push_str(&escape(v));
        };
        kw("type", kind_name(&e.kind));
        if let Some(v) = &e.link {
            kw("link", v);
        }
        if let Some(v) = e.size {
            kw("size", &v.to_string());
        }
        if let Some(v) = e.mode {
            kw("mode", &alloc::format!("{v:04o}"));
        }
        if let Some(v) = e.uid {
            kw("uid", &v.to_string());
        }
        if let Some(v) = e.gid {
            kw("gid", &v.to_string());
        }
        if let Some(v) = &e.uname {
            kw("uname", v);
        }
        if let Some(v) = &e.gname {
            kw("gname", v);
        }
        if let Some(v) = &e.time {
            kw("time", v);
        }
        for (alg, value) in &e.digests {
            kw(&alloc::format!("{alg}digest"), value);
        }
        self.out.push('\n');
        Ok(())
    }

    /// Return the manifest bytes (UTF-8/ASCII).
    pub fn finish(self) -> Vec<u8> {
        self.out.into_bytes()
    }
}

impl Default for MtreeEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode `entries` as an mtree manifest with a `#mtree` signature.
pub fn encode(entries: &[MtreeEntry]) -> Result<Vec<u8>, Error> {
    let mut enc = MtreeEncoder::new();
    for e in entries {
        enc.add_entry(e)?;
    }
    Ok(enc.finish())
}

/// `type=` value for a [`MtreeKind`].
fn kind_name(k: &MtreeKind) -> &str {
    match k {
        MtreeKind::File => "file",
        MtreeKind::Dir => "dir",
        MtreeKind::Link => "link",
        MtreeKind::Block => "block",
        MtreeKind::Char => "char",
        MtreeKind::Fifo => "fifo",
        MtreeKind::Socket => "socket",
        MtreeKind::Other(s) => s.as_str(),
    }
}

/// mtree tokens must not contain whitespace or `=`.
fn check_token(t: &str, _what: &str) -> Result<(), Error> {
    if t.is_empty()
        || t.bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'=' || b == b'#')
    {
        return Err(Error::InvalidData("mtree: bad token"));
    }
    Ok(())
}

/// Lines must not contain CR or LF (the format is line-oriented).
fn check_line(t: &str, _what: &str) -> Result<(), Error> {
    if t.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(Error::InvalidData("mtree: CR/LF in field"));
    }
    Ok(())
}

/// Escape a name/keyword value for the wire: `\` and bytes that break
/// tokenization or parsing (space, `#`, control bytes, DEL, non-ASCII)
/// become `\ooo` octal escapes (inverse of the decoder's unescape).
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let b = *b;
        if b == b'\\' || b == b' ' || b == b'#' || !(0x20..0x7f).contains(&b) {
            out.push('\\');
            out.push(char::from(b'0' + ((b >> 6) & 0x07)));
            out.push(char::from(b'0' + ((b >> 3) & 0x07)));
            out.push(char::from(b'0' + (b & 0x07)));
        } else {
            out.push(b as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::mtree::decode::{MtreeEntry, decode};
    use alloc::collections::BTreeMap;

    fn entry(name: &str, kind: MtreeKind) -> MtreeEntry {
        MtreeEntry {
            name: name.to_string(),
            kind,
            size: None,
            mode: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
            time: None,
            link: None,
            digests: BTreeMap::new(),
        }
    }

    #[test]
    fn roundtrip_basic() {
        let mut e = entry("hello.txt", MtreeKind::File);
        e.size = Some(5);
        e.mode = Some(0o644);
        e.uid = Some(0);
        e.gid = Some(0);
        e.uname = Some("root".to_string());
        e.gname = Some("root".to_string());
        e.time = Some("1700000000.000000000".to_string());
        e.digests.insert("sha256".to_string(), "abc123".to_string());

        let data = encode(&[e]).unwrap();
        assert!(data.starts_with(b"#mtree\n"));
        let got = decode(&data).unwrap();
        assert_eq!(got.len(), 1);
        let g = &got[0];
        assert_eq!(g.name, "hello.txt");
        assert_eq!(g.kind, MtreeKind::File);
        assert_eq!(g.size, Some(5));
        assert_eq!(g.mode, Some(0o644));
        assert_eq!(g.uid, Some(0));
        assert_eq!(g.uname.as_deref(), Some("root"));
        assert_eq!(g.time.as_deref(), Some("1700000000.000000000"));
        assert_eq!(g.digests["sha256"], "abc123");
    }

    #[test]
    fn roundtrip_all_kinds() {
        let entries = [
            entry("f.txt", MtreeKind::File),
            entry("d", MtreeKind::Dir),
            entry("l", MtreeKind::Link),
            entry("b", MtreeKind::Block),
            entry("c", MtreeKind::Char),
            entry("p", MtreeKind::Fifo),
            entry("s", MtreeKind::Socket),
            entry("x", MtreeKind::Other("door".to_string())),
        ];
        let got = decode(&encode(&entries).unwrap()).unwrap();
        assert_eq!(got.len(), 8);
        assert_eq!(got[1].kind, MtreeKind::Dir);
        assert_eq!(got[7].kind, MtreeKind::Other("door".to_string()));
    }

    #[test]
    fn escapes_space_and_special() {
        let e = entry("dir a/file with space.txt", MtreeKind::File);
        let data = encode(std::slice::from_ref(&e)).unwrap();
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(text.contains("\\040"), "{text}");
        let got = decode(&data).unwrap();
        assert_eq!(got[0].name, e.name);
    }

    #[test]
    fn set_unset_defaults_roundtrip() {
        let mut enc = MtreeEncoder::new();
        enc.set(&[("type", "file"), ("uid", "0"), ("mode", "644")])
            .unwrap();
        enc.add_entry(&entry("a.txt", MtreeKind::File)).unwrap();
        enc.unset(&["uid"]).unwrap();
        enc.add_entry(&entry("b.txt", MtreeKind::File)).unwrap();
        let got = decode(&enc.finish()).unwrap();
        assert_eq!(got[0].uid, Some(0));
        assert_eq!(got[1].uid, None);
        assert_eq!(got[0].mode, Some(0o644));
        assert_eq!(got[1].mode, Some(0o644));
    }

    #[test]
    fn link_and_dir_paths() {
        let mut l = entry("dir/link.txt", MtreeKind::Link);
        l.link = Some("hello.txt".to_string());
        let got = decode(&encode(&[l]).unwrap()).unwrap();
        assert_eq!(got[0].kind, MtreeKind::Link);
        assert_eq!(got[0].link.as_deref(), Some("hello.txt"));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(matches!(
            encode(&[entry("", MtreeKind::File)]),
            Err(Error::InvalidData(_))
        ));
        assert!(matches!(
            encode(&[entry("../escape", MtreeKind::File)]),
            Err(Error::InvalidData(_))
        ));
        let mut enc = MtreeEncoder::new();
        assert!(matches!(
            enc.set(&[("bad key", "v")]),
            Err(Error::InvalidData(_))
        ));
        assert!(matches!(
            enc.comment("line\nbreak"),
            Err(Error::InvalidData(_))
        ));
    }
}
