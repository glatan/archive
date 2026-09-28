//! MS-CAB single-cabinet encode (stored and MSZIP folders).
//!
//! [`MscabEncoder`] produces a single cabinet with one folder holding
//! every queued file. Stored cabinets emit raw `CFDATA` blocks;
//! MSZIP cabinets emit `CK`-prefixed raw-DEFLATE blocks with the
//! 32 KiB history window carried across `CFDATA` boundaries
//! (MS-CAB §3.1 `tcompTYPE_MSZIP`). Reserved areas, cabinet sets,
//! and per-file date/attribute metadata are not emitted.

use alloc::string::String;
use alloc::vec::Vec;

use super::decode::checksum;
use crate::compress::deflate;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"MSCF";
const COMPRESS_NONE: u16 = 0;
const COMPRESS_MSZIP: u16 = 1;
/// Maximum uncompressed bytes per CFDATA block (MS-CAB §2.2: 32 KiB).
const CFDATA_MAX: usize = 32 * 1024;
/// MSZIP sliding-window depth carried across CFDATA blocks (§3.1).
const MSZIP_WINDOW: usize = 32 * 1024;

/// Folder compression applied to every file in the cabinet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscabCompression {
    /// Store (`tcompTYPE_NONE`).
    None,
    /// MSZIP (`tcompTYPE_MSZIP`): raw DEFLATE per CFDATA block with
    /// the "CK" signature and a carried 32 KiB dictionary.
    Mszip,
}

/// Encoder for single-file MS-CAB archives.
///
/// All queued files share one folder; the folder stream is chunked
/// into `CFDATA` blocks of at most 32 KiB uncompressed.
pub struct MscabEncoder {
    compression: MscabCompression,
    /// (name, data) pairs in queue order; `uoffFileStart` is the
    /// concatenated folder offset, computed at finish time.
    files: Vec<(String, Vec<u8>)>,
}

impl MscabEncoder {
    /// New encoder storing files uncompressed.
    pub fn new() -> Self {
        Self::with_compression(MscabCompression::None)
    }

    /// New encoder with the given folder compression.
    pub fn with_compression(compression: MscabCompression) -> Self {
        Self {
            compression,
            files: Vec::new(),
        }
    }

    /// Queue one file. Names are emitted as ASCIIZ; they must be
    /// non-empty and contain no NUL bytes (enforced at finish).
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.files.push((String::from(name), data.to_vec()));
    }

    /// Serialize the cabinet. Returns [`Error::InvalidData`] if a
    /// queued name is empty, contains a NUL byte, or the cabinet
    /// would exceed u32/u16 field limits.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.files.len() > u16::MAX as usize {
            return Err(Error::InvalidData("mscab: too many files"));
        }

        // Concatenated folder stream + per-file offsets.
        let mut stream = Vec::new();
        let mut uoffs = Vec::with_capacity(self.files.len());
        for (name, data) in &self.files {
            if name.is_empty() || name.as_bytes().contains(&0) {
                return Err(Error::InvalidData("mscab: invalid file name"));
            }
            uoffs.push(stream.len() as u32);
            stream.extend_from_slice(data);
        }

        // Split into CFDATA blocks, compressing each with the
        // folder history as preset dictionary.
        let type_compress = match self.compression {
            MscabCompression::None => COMPRESS_NONE,
            MscabCompression::Mszip => COMPRESS_MSZIP,
        };
        let mut blocks: Vec<Vec<u8>> = Vec::new(); // wire payloads (incl. "CK")
        let mut uncomp_sizes: Vec<u16> = Vec::new();
        let mut history = Vec::new();
        for chunk in stream.chunks(CFDATA_MAX) {
            let block = match self.compression {
                MscabCompression::None => chunk.to_vec(),
                MscabCompression::Mszip => {
                    let dict_start = history.len().saturating_sub(MSZIP_WINDOW);
                    let mut b = Vec::with_capacity(chunk.len() + 2);
                    b.extend_from_slice(b"CK");
                    b.extend_from_slice(&deflate::encode::encode_with_dict(
                        chunk,
                        &history[dict_start..],
                    ));
                    b
                }
            };
            uncomp_sizes.push(chunk.len() as u16);
            blocks.push(block);
            history.extend_from_slice(chunk);
        }
        if blocks.len() > u16::MAX as usize {
            return Err(Error::InvalidData("mscab: too many CFDATA blocks"));
        }

        // Layout: CFHEADER(36) | CFFOLDER(8) | CFFILE array | CFDATA*.
        let folders_off = 36usize;
        let mut files_buf = Vec::new();
        for ((name, data), uoff) in self.files.iter().zip(uoffs.iter()) {
            files_buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            files_buf.extend_from_slice(&uoff.to_le_bytes());
            files_buf.extend_from_slice(&0u16.to_le_bytes()); // iFolder
            files_buf.extend_from_slice(&0u16.to_le_bytes()); // date
            files_buf.extend_from_slice(&0u16.to_le_bytes()); // time
            files_buf.extend_from_slice(&0u16.to_le_bytes()); // attribs
            files_buf.extend_from_slice(name.as_bytes());
            files_buf.push(0);
        }
        let data_off = folders_off + 8 + files_buf.len();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        out.extend_from_slice(&[0; 4]); // cbCabinet, patched below
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        // Single 8-byte CFFOLDER: CFFILEs follow immediately.
        out.extend_from_slice(&((folders_off + 8) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
        out.push(3); // versionMinor
        out.push(1); // versionMajor
        out.extend_from_slice(&1u16.to_le_bytes()); // cFolders
        out.extend_from_slice(&(self.files.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // setID
        out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet

        // The single CFFOLDER record.
        out.extend_from_slice(&(data_off as u32).to_le_bytes()); // coffCabStart
        out.extend_from_slice(&(blocks.len() as u16).to_le_bytes()); // cCFDATA
        out.extend_from_slice(&type_compress.to_le_bytes());
        out.extend_from_slice(&files_buf);

        for (block, &uncomp) in blocks.iter().zip(&uncomp_sizes) {
            if block.len() > u16::MAX as usize {
                return Err(Error::InvalidData("mscab: CFDATA block too large"));
            }
            let cb_data = block.len() as u16;
            // csum covers cbData|cbUncomp (as seed) + payload.
            let seed = (uncomp as u32) << 16 | cb_data as u32;
            let csum = checksum(block, seed);
            out.extend_from_slice(&csum.to_le_bytes());
            out.extend_from_slice(&cb_data.to_le_bytes());
            out.extend_from_slice(&uncomp.to_le_bytes());
            out.extend_from_slice(block);
        }

        let cb_cabinet = out.len();
        if cb_cabinet > u32::MAX as usize {
            return Err(Error::InvalidData("mscab: cabinet too large"));
        }
        out[8..12].copy_from_slice(&(cb_cabinet as u32).to_le_bytes());
        Ok(out)
    }
}

impl Default for MscabEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::traits::ArchiveEncode for MscabEncoder {
    fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file(name, data);
    }

    fn finish(self) -> Result<Vec<u8>, Error> {
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::mscab::decode::decode;
    use crate::traits::ArchiveEntry;

    #[test]
    fn stored_roundtrip() {
        let mut enc = MscabEncoder::new();
        enc.add_file("a.txt", b"alpha");
        enc.add_file("dir/b.txt", b"bravo payload");
        let cab = enc.finish().unwrap();
        let entries = decode(&cab).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "a.txt");
        assert_eq!(entries[0].data(), b"alpha");
        assert_eq!(entries[1].name(), "dir/b.txt");
        assert_eq!(entries[1].data(), b"bravo payload");
    }

    #[test]
    fn mszip_roundtrip() {
        let mut enc = MscabEncoder::with_compression(MscabCompression::Mszip);
        let payload = b"repeated content repeated content repeated ".repeat(64);
        enc.add_file("big.bin", &payload);
        let cab = enc.finish().unwrap();
        let entries = decode(&cab).unwrap();
        assert_eq!(entries[0].data(), payload.as_slice());
    }

    #[test]
    fn mszip_cross_block_history() {
        // >32 KiB forces multiple CFDATA blocks; the second block's
        // deflate stream may reference the previous 32 KiB window.
        let mut enc = MscabEncoder::with_compression(MscabCompression::Mszip);
        let mut payload = Vec::new();
        for i in 0..4500u32 {
            payload.extend_from_slice(format!("chunk-{i:03}-").as_bytes());
        }
        let repeat: Vec<u8> = payload[..20000].to_vec();
        payload.extend_from_slice(&repeat);
        enc.add_file("big.bin", &payload);
        let cab = enc.finish().unwrap();
        let entries = decode(&cab).unwrap();
        assert_eq!(entries[0].data(), payload.as_slice());
    }

    #[test]
    fn file_spanning_blocks() {
        let mut enc = MscabEncoder::new();
        enc.add_file("a", &vec![0xAA; 40000]);
        enc.add_file("b", b"tail");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries[0].data().len(), 40000);
        assert_eq!(entries[1].data(), b"tail");
    }

    #[test]
    fn rejects_bad_names() {
        let mut enc = MscabEncoder::new();
        enc.add_file("", b"x");
        assert!(enc.finish().is_err());
        let mut enc = MscabEncoder::new();
        enc.add_file("a\0b", b"x");
        assert!(enc.finish().is_err());
    }
}
