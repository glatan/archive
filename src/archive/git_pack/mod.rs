//! Git pack format (`pack-*.pack` / `pack-*.idx`) support.
//!
//! Implements the pack container described by gitformat-pack(5):
//! a `PACK` + version-2 header, per-object entries (undeltified or
//! ofs-delta / ref-delta), zlib-compressed payloads, and a trailing
//! pack checksum. Deltas are resolved in memory, including chained
//! and (within the same pack) ref-delta bases; thin packs are
//! rejected. The v2 index (`.idx`) can be read and written; v1 idx,
//! `.rev`, `.mtimes`, multi-pack-index, and SHA-256 repositories are
//! out of scope.
//!
//! Entries are exposed as [`GitPackEntry`] values whose name is the
//! lower-case hex object ID (SHA-1 of `"<type> <len>\0" + payload`,
//! per the git object model).

use alloc::string::String;
use alloc::vec::Vec;

pub mod decode;
pub mod encode;

/// Codec struct for trait-based git pack decode operations.
pub struct GitPackCodec;

impl crate::traits::ArchiveDecode for GitPackCodec {
    type Entry = decode::GitPackEntry;

    fn decode(&self, input: &[u8]) -> Result<Vec<Self::Entry>, crate::error::Error> {
        decode::decode(input)
    }
}

/// Git object type, as stored in the 3-bit object header field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    /// Numeric object type code (1-4).
    pub fn code(self) -> u8 {
        match self {
            Self::Commit => 1,
            Self::Tree => 2,
            Self::Blob => 3,
            Self::Tag => 4,
        }
    }

    /// Type name used in the git object header (`"<type> <len>\0"`).
    pub fn type_name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    fn from_code(code: u8) -> Result<Self, crate::error::Error> {
        match code {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            _ => Err(crate::error::Error::InvalidData(
                "git-pack: invalid object type",
            )),
        }
    }
}

/// Object ID (SHA-1 for traditional repositories).
pub type ObjectId = [u8; 20];

/// Compute the git object ID for `object_type` + `data`
/// (`SHA-1("<type> <len>\0" + data)`).
pub fn object_id(object_type: ObjectType, data: &[u8]) -> ObjectId {
    let header = alloc::format!("{} {}\0", object_type.type_name(), data.len());
    let mut h = crate::util::sha1::Sha1::new();
    h.update(header.as_bytes());
    h.update(data);
    h.finish()
}

/// Lower-case hex rendering of an object ID.
pub fn hex_id(id: &ObjectId) -> String {
    let mut s = String::with_capacity(40);
    for b in id {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xF) as u32, 16).unwrap());
    }
    s
}
