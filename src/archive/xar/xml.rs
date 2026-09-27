//! Minimal non-validating XML parser for XAR table-of-contents
//! documents.
//!
//! Scope: UTF-8/ASCII well-formed documents with elements,
//! double/single-quoted attributes, character data, self-closing
//! tags, `<?...?>` processing instructions, `<!-- -->` comments,
//! `<!DOCTYPE ...>` declarations, `<![CDATA[...]]>` sections, and
//! the five predefined entities plus `&#NN;`/`&#xNN;` numeric
//! references. Namespace prefixes are treated as part of names.
//! This is intentionally not a general-purpose XML library.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;

/// A parsed XML element (small DOM node).
#[derive(Debug)]
pub(crate) struct Node {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    /// Concatenated character data (entity-decoded).
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    /// First direct child element with `name`.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Text of the first direct child element `name`, trimmed.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.trim())
    }

    /// Value of attribute `name`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, v)| v.as_str())
    }

    /// All direct children named `name`.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
}

fn invalid() -> Error {
    Error::InvalidData("xar: malformed XML table of contents")
}

/// Parse a complete XML document into a root element node.
pub(crate) fn parse(input: &str) -> Result<Node, Error> {
    let mut p = Parser { s: input, pos: 0 };
    p.misc();
    let root = p.element()?;
    p.misc();
    if p.pos != input.len() {
        return Err(invalid());
    }
    Ok(root)
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.pos..]
    }

    fn starts_with(&self, pat: &str) -> bool {
        self.rest().starts_with(pat)
    }

    fn bump(&mut self, n: usize) {
        self.pos += n;
    }

    /// Skip whitespace, comments, processing instructions, and
    /// DOCTYPE declarations (document prolog/epilog and
    /// element-level misc).
    fn misc(&mut self) {
        loop {
            let r = self.rest();
            if r.starts_with(char::is_whitespace) {
                self.bump(r.chars().next().unwrap().len_utf8());
            } else if self.starts_with("<!--") {
                match self.s[self.pos..].find("-->") {
                    Some(i) => self.bump(i + 3),
                    None => return,
                }
            } else if self.starts_with("<?") {
                match self.s[self.pos..].find("?>") {
                    Some(i) => self.bump(i + 2),
                    None => return,
                }
            } else if self.starts_with("<!DOCTYPE") {
                // Skip to '>' (internal subsets are not supported).
                match self.s[self.pos..].find('>') {
                    Some(i) => self.bump(i + 1),
                    None => return,
                }
            } else {
                return;
            }
        }
    }

    fn name(&mut self) -> Result<String, Error> {
        let start = self.pos;
        while let Some(c) = self.rest().chars().next() {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                self.bump(c.len_utf8());
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(invalid());
        }
        Ok(self.s[start..self.pos].to_owned())
    }

    fn element(&mut self) -> Result<Node, Error> {
        if !self.starts_with("<") || self.starts_with("</") {
            return Err(invalid());
        }
        self.bump(1);
        let name = self.name()?;
        let mut attrs = Vec::new();
        loop {
            self.misc();
            if self.starts_with("/>") {
                self.bump(2);
                return Ok(Node {
                    name,
                    attrs,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            if self.starts_with(">") {
                self.bump(1);
                break;
            }
            // attribute
            let k = self.name()?;
            self.misc();
            if !self.starts_with("=") {
                return Err(invalid());
            }
            self.bump(1);
            self.misc();
            let quote = self.rest().chars().next().ok_or_else(invalid)?;
            if quote != '"' && quote != '\'' {
                return Err(invalid());
            }
            self.bump(1);
            let v = self.text_until(quote)?;
            self.bump(1);
            attrs.push((k, v));
        }
        // content: text + child elements until </name>
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.starts_with("</") {
                self.bump(2);
                let close = self.name()?;
                self.misc();
                if !self.starts_with(">") || close != name {
                    return Err(invalid());
                }
                self.bump(1);
                return Ok(Node {
                    name,
                    attrs,
                    text,
                    children,
                });
            }
            if self.starts_with("<!--") {
                match self.s[self.pos..].find("-->") {
                    Some(i) => {
                        self.bump(i + 3);
                        continue;
                    }
                    None => return Err(invalid()),
                }
            }
            if self.starts_with("<![CDATA[") {
                match self.s[self.pos..].find("]]>") {
                    Some(i) => {
                        text.push_str(&self.rest()[9..i]);
                        self.bump(i + 3);
                        continue;
                    }
                    None => return Err(invalid()),
                }
            }
            if self.starts_with("<?") {
                match self.s[self.pos..].find("?>") {
                    Some(i) => {
                        self.bump(i + 2);
                        continue;
                    }
                    None => return Err(invalid()),
                }
            }
            if self.starts_with("<") {
                children.push(self.element()?);
                continue;
            }
            text.push_str(&self.text_until('<')?);
            if self.pos >= self.s.len() {
                return Err(invalid());
            }
        }
    }

    /// Consume text until `stop`, decoding entity references.
    fn text_until(&mut self, stop: char) -> Result<String, Error> {
        let mut out = String::new();
        while let Some(c) = self.rest().chars().next() {
            if c == stop {
                break;
            }
            if c == '&' {
                out.push_str(&self.entity()?);
                continue;
            }
            out.push(c);
            self.bump(c.len_utf8());
        }
        Ok(out)
    }

    fn entity(&mut self) -> Result<String, Error> {
        self.bump(1); // '&'
        let end = self
            .rest()
            .find(';')
            .filter(|&i| i <= 10)
            .ok_or_else(invalid)?;
        let name = &self.rest()[..end];
        self.bump(end + 1);
        match name {
            "lt" => Ok("<".to_owned()),
            "gt" => Ok(">".to_owned()),
            "amp" => Ok("&".to_owned()),
            "quot" => Ok("\"".to_owned()),
            "apos" => Ok("'".to_owned()),
            _ if name.starts_with("#x") || name.starts_with("#X") => {
                let cp = u32::from_str_radix(&name[2..], 16).map_err(|_| invalid())?;
                char::from_u32(cp)
                    .map(|c| c.to_string())
                    .ok_or_else(invalid)
            }
            _ if name.starts_with('#') => {
                let cp: u32 = name[1..].parse().map_err(|_| invalid())?;
                char::from_u32(cp)
                    .map(|c| c.to_string())
                    .ok_or_else(invalid)
            }
            _ => Err(invalid()),
        }
    }
}
