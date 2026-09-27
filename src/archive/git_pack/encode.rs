//! Git pack file (`pack-*.pack` v2) and index (`pack-*.idx` v2) encode.
//!
//! Produces a non-deltified pack: every queued object is stored as a
//! full zlib-compressed entry. [`GitPackEncoder::finish_with_index`]
//! additionally emits the matching v2 `.idx` file.

use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32::Crc32;
use crate::util::sha1::sha1;

use super::{ObjectId, ObjectType, object_id};

/// Encoder for non-deltified v2 pack files.
pub struct GitPackEncoder {
    out: Vec<u8>,
    /// Object ID, CRC32 of packed entry, and entry offset per object.
    records: Vec<(ObjectId, u32, u64)>,
}

impl GitPackEncoder {
    pub fn new() -> Self {
        let mut out = Vec::new();
        // PACK, version 2, count placeholder.
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        Self {
            out,
            records: Vec::new(),
        }
    }

    /// Add one complete (non-delta) object.
    pub fn add_object(&mut self, object_type: ObjectType, data: &[u8]) {
        let mut entry = Vec::new();
        // Object header: size in 4+7n bits, type in bits 4..6.
        let mut size = data.len() as u64;
        let mut first = ((object_type.code() & 0x7) << 4) | (size as u8 & 0xF);
        size >>= 4;
        if size != 0 {
            first |= 0x80;
        }
        entry.push(first);
        while size != 0 {
            let mut b = (size as u8) & 0x7F;
            size >>= 7;
            if size != 0 {
                b |= 0x80;
            }
            entry.push(b);
        }
        entry.extend_from_slice(&crate::compress::zlib::encode::encode(data));
        let id = object_id(object_type, data);
        let mut crc = Crc32::new();
        crc.update(&entry);
        let offset = self.out.len() as u64;
        self.records.push((id, crc.finish(), offset));
        self.out.extend_from_slice(&entry);
    }

    /// Finish the pack: patch the object count and append the
    /// SHA-1 pack checksum trailer.
    pub fn finish(mut self) -> Vec<u8> {
        let count = self.records.len() as u32;
        self.out[8..12].copy_from_slice(&count.to_be_bytes());
        let trailer = sha1(&self.out);
        self.out.extend_from_slice(&trailer);
        self.out
    }

    /// Finish and also produce the matching v2 `.idx` file.
    pub fn finish_with_index(self) -> (Vec<u8>, Vec<u8>) {
        let records = self.records.clone();
        let pack = self.finish();
        let idx = encode_idx(&records, &pack);
        (pack, idx)
    }
}

impl Default for GitPackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for GitPackEncoder {
    /// Add the file contents as a blob object. Git objects are
    /// content-addressed, so the filename is not stored.
    fn add_file(&mut self, _name: &str, data: &[u8]) {
        self.add_object(super::ObjectType::Blob, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        Ok(self.finish())
    }
}

/// Build a v2 `.idx` file for `records` (ID, entry CRC32, entry
/// offset) over the completed `pack` bytes.
fn encode_idx(records: &[(ObjectId, u32, u64)], pack: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<&(ObjectId, u32, u64)> = records.iter().collect();
    sorted.sort_by_key(|r| r.0);

    let mut idx = Vec::new();
    idx.extend_from_slice(&[0xFF, 0x74, 0x4F, 0x63]);
    idx.extend_from_slice(&2u32.to_be_bytes());
    // Fanout: cumulative counts of IDs grouped by first byte.
    let mut fanout = [0u32; 256];
    for r in &sorted {
        fanout[r.0[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for f in fanout.iter_mut() {
        acc += *f;
        idx.extend_from_slice(&acc.to_be_bytes());
    }
    for r in &sorted {
        idx.extend_from_slice(&r.0);
    }
    for r in &sorted {
        idx.extend_from_slice(&r.1.to_be_bytes());
    }
    let mut large: Vec<u64> = Vec::new();
    for r in &sorted {
        if r.2 >= 0x8000_0000 {
            idx.extend_from_slice(&((0x8000_0000u32) | large.len() as u32).to_be_bytes());
            large.push(r.2);
        } else {
            idx.extend_from_slice(&(r.2 as u32).to_be_bytes());
        }
    }
    for off in large {
        idx.extend_from_slice(&off.to_be_bytes());
    }
    idx.extend_from_slice(&pack[pack.len() - 20..]);
    let idx_sum = sha1(&idx);
    idx.extend_from_slice(&idx_sum);
    idx
}
