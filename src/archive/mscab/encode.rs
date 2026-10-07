//! MS-CAB single-cabinet encode (stored and MSZIP folders).
//!
//! [`MscabEncoder`] produces a single cabinet with one folder holding
//! every queued file. Stored cabinets emit raw `CFDATA` blocks;
//! MSZIP cabinets emit `CK`-prefixed raw-DEFLATE blocks with the
//! 32 KiB history window carried across `CFDATA` boundaries
//! (MS-CAB §3.1 `tcompTYPE_MSZIP`). [`MscabEncoder::reserve`] emits
//! `FLAG_RESERVE_PRESENT` zero-filled reserved areas;
//! [`MscabEncoder::add_file_with_meta`] emits per-file CFFILE
//! date/time/attribs metadata (defaulting to zero via
//! [`MscabEncoder::add_file`]); cabinet sets are not emitted.

use alloc::string::String;
use alloc::vec::Vec;

use super::decode::checksum;
use crate::compress::deflate;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"MSCF";
const COMPRESS_NONE: u16 = 0;
const COMPRESS_MSZIP: u16 = 1;
const FLAG_RESERVE_PRESENT: u16 = 0x0004;
/// Maximum uncompressed bytes per CFDATA block (MS-CAB §2.2: 32 KiB).
const CFDATA_MAX: usize = 32 * 1024;
/// MSZIP sliding-window depth carried across CFDATA blocks (§3.1).
const MSZIP_WINDOW: usize = 32 * 1024;

/// Per-file metadata emitted into the CFFILE record (MS-CAB §2.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct MscabFileMeta {
    /// MS-DOS format date (CFFILE `date` field).
    pub date: u16,
    /// MS-DOS format time (CFFILE `time` field).
    pub time: u16,
    /// File attributes (CFFILE `attribs` field).
    pub attribs: u16,
}

/// Folder compression applied to every file in the cabinet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MscabCompression {
    /// Store (`tcompTYPE_NONE`).
    None,
    /// MSZIP (`tcompTYPE_MSZIP`): raw DEFLATE per CFDATA block with
    /// the "CK" signature and a carried 32 KiB dictionary.
    Mszip,
}

/// Queued file: name, contents, and CFFILE metadata.
struct FileRec {
    name: String,
    data: Vec<u8>,
    meta: MscabFileMeta,
}

/// Encoder for single-file MS-CAB archives.
///
/// All queued files share one folder; the folder stream is chunked
/// into `CFDATA` blocks of at most 32 KiB uncompressed.
pub struct MscabEncoder {
    compression: MscabCompression,
    /// (cbCFHeader, cbCFFolder, cbCFData) reserved-area sizes emitted
    /// when `FLAG_RESERVE_PRESENT` is set; areas are zero-filled.
    reserve: Option<(u16, u8, u8)>,
    /// Files in queue order; `uoffFileStart` is the concatenated
    /// folder offset, computed at finish time.
    files: Vec<FileRec>,
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
            reserve: None,
        }
    }

    /// Emit `FLAG_RESERVE_PRESENT` with per-structure reserved areas:
    /// `cb_header` bytes after the CFHEADER reserve fields,
    /// `cb_folder` bytes after each CFFOLDER record, and `cb_data`
    /// bytes between each CFDATA header and its payload ([MS-CAB]
    /// CFHEADER/CFFOLDER/CFDATA `abReserve`). Areas are zero-filled;
    /// the CFDATA checksum covers its reserve area. `cb_header`
    /// beyond the [MS-CAB] §2.1 limit of 60,000 is rejected at
    /// `finish`.
    pub fn reserve(mut self, cb_header: u16, cb_folder: u8, cb_data: u8) -> Self {
        self.reserve = Some((cb_header, cb_folder, cb_data));
        self
    }

    /// Queue one file. Names are emitted as ASCIIZ; they must be
    /// non-empty and contain no NUL bytes (enforced at finish).
    /// CFFILE date/time/attribs are emitted as zero.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.add_file_with_meta(name, data, MscabFileMeta::default());
    }

    /// Queue a file with explicit CFFILE date/time/attribs metadata.
    pub fn add_file_with_meta(&mut self, name: &str, data: &[u8], meta: MscabFileMeta) {
        self.files.push(FileRec {
            name: String::from(name),
            data: data.to_vec(),
            meta,
        });
    }

    /// Serialize the cabinet. Returns [`Error::InvalidData`] if a
    /// queued name is empty, contains a NUL byte, or the cabinet
    /// would exceed u32/u16 field limits.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        if self.reserve.is_some_and(|(h, _, _)| h > 60_000) {
            return Err(Error::InvalidData("mscab: cbCFHeader exceeds 60,000"));
        }
        if self.files.len() > u16::MAX as usize {
            return Err(Error::InvalidData("mscab: too many files"));
        }

        // Concatenated folder stream + per-file offsets.
        let mut stream = Vec::new();
        let mut uoffs = Vec::with_capacity(self.files.len());
        for file in &self.files {
            if file.name.is_empty() || file.name.as_bytes().contains(&0) {
                return Err(Error::InvalidData("mscab: invalid file name"));
            }
            uoffs.push(stream.len() as u32);
            stream.extend_from_slice(&file.data);
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

        // Layout: CFHEADER(36) | [reserve fields + abReserve] |
        // CFFOLDER(8 + cbCFFolder) | CFFILE array | CFDATA*.
        let (cb_cfheader, cb_cffolder, cb_cfdata) = self.reserve.unwrap_or((0, 0, 0));
        let folders_off = if self.reserve.is_some() {
            36 + 4 + cb_cfheader as usize
        } else {
            36
        };
        let mut files_buf = Vec::new();
        for (file, uoff) in self.files.iter().zip(uoffs.iter()) {
            files_buf.extend_from_slice(&(file.data.len() as u32).to_le_bytes());
            files_buf.extend_from_slice(&uoff.to_le_bytes());
            files_buf.extend_from_slice(&0u16.to_le_bytes()); // iFolder
            files_buf.extend_from_slice(&file.meta.date.to_le_bytes());
            files_buf.extend_from_slice(&file.meta.time.to_le_bytes());
            files_buf.extend_from_slice(&file.meta.attribs.to_le_bytes());
            files_buf.extend_from_slice(file.name.as_bytes());
            files_buf.push(0);
        }
        let data_off = folders_off + 8 + cb_cffolder as usize + files_buf.len();

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
        out.extend_from_slice(&[0; 4]); // cbCabinet, patched below
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
        // Single CFFOLDER: CFFILEs follow the record + its reserve.
        out.extend_from_slice(&((folders_off + 8 + cb_cffolder as usize) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
        out.push(3); // versionMinor
        out.push(1); // versionMajor
        out.extend_from_slice(&1u16.to_le_bytes()); // cFolders
        out.extend_from_slice(&(self.files.len() as u16).to_le_bytes());
        out.extend_from_slice(
            &if self.reserve.is_some() {
                FLAG_RESERVE_PRESENT
            } else {
                0
            }
            .to_le_bytes(),
        ); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // setID
        out.extend_from_slice(&0u16.to_le_bytes()); // iCabinet

        // FLAG_RESERVE_PRESENT: reserve sizes + cbCFHeader reserve area.
        if self.reserve.is_some() {
            out.extend_from_slice(&cb_cfheader.to_le_bytes());
            out.push(cb_cffolder);
            out.push(cb_cfdata);
            out.resize(out.len() + cb_cfheader as usize, 0);
        }

        // The single CFFOLDER record.
        out.extend_from_slice(&(data_off as u32).to_le_bytes()); // coffCabStart
        out.extend_from_slice(&(blocks.len() as u16).to_le_bytes()); // cCFDATA
        out.extend_from_slice(&type_compress.to_le_bytes());
        out.resize(out.len() + cb_cffolder as usize, 0); // CFFOLDER abReserve
        out.extend_from_slice(&files_buf);

        for (block, &uncomp) in blocks.iter().zip(&uncomp_sizes) {
            if block.len() > u16::MAX as usize {
                return Err(Error::InvalidData("mscab: CFDATA block too large"));
            }
            let cb_data = block.len() as u16;
            // csum covers cbData|cbUncomp (as seed) + abReserve + payload.
            let seed = (uncomp as u32) << 16 | cb_data as u32;
            let mut covered = Vec::with_capacity(cb_cfdata as usize + block.len());
            covered.resize(covered.len() + cb_cfdata as usize, 0);
            covered.extend_from_slice(block);
            let csum = checksum(&covered, seed);
            out.extend_from_slice(&csum.to_le_bytes());
            out.extend_from_slice(&cb_data.to_le_bytes());
            out.extend_from_slice(&uncomp.to_le_bytes());
            out.extend_from_slice(&covered);
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
    use alloc::format;
    use alloc::vec;

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
    fn reserve_roundtrip_stored() {
        let mut enc = MscabEncoder::new().reserve(6, 3, 5);
        enc.add_file("a.bin", b"reserved stored");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data(), b"reserved stored");
    }

    #[test]
    fn reserve_roundtrip_mszip() {
        let mut enc = MscabEncoder::with_compression(MscabCompression::Mszip).reserve(4, 2, 3);
        enc.add_file("a.bin", b"reserved mszip");
        enc.add_file("b.bin", &vec![0x5A; 70000]);
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data(), b"reserved mszip");
        assert_eq!(entries[1].data().len(), 70000);
    }

    #[test]
    fn reserve_wire_layout() {
        let mut enc = MscabEncoder::new().reserve(6, 3, 5);
        enc.add_file("a.bin", b"x");
        let cab = enc.finish().unwrap();
        // FLAG_RESERVE_PRESENT
        assert_eq!(u16::from_le_bytes([cab[30], cab[31]]), 0x0004);
        // cbCFHeader=6, cbCFFolder=3, cbCFData=5 at offset 36
        assert_eq!(u16::from_le_bytes([cab[36], cab[37]]), 6);
        assert_eq!(cab[38], 3);
        assert_eq!(cab[39], 5);
        // 6-byte zeroed header reserve follows.
        assert!(cab[40..46].iter().all(|&b| b == 0));
        // CFFOLDER at 46; its 3-byte reserve trails the 8-byte record.
        let coff_files = u32::from_le_bytes([cab[16], cab[17], cab[18], cab[19]]);
        assert_eq!(coff_files as usize, 46 + 8 + 3);
        assert!(cab[54..57].iter().all(|&b| b == 0));
        // The decoder's checksum verification covers the 5-byte CFDATA
        // reserve, so a clean round-trip proves it was included.
        decode(&cab).unwrap();
    }

    #[test]
    fn reserve_rejects_oversize_header() {
        assert!(MscabEncoder::new().reserve(60_000, 0, 0).finish().is_ok());
        let mut enc = MscabEncoder::new().reserve(60_001, 0, 0);
        enc.add_file("a", b"x");
        assert!(enc.finish().is_err());
    }

    #[test]
    fn encoder_emits_date_time_attribs() {
        let mut enc = MscabEncoder::new();
        enc.add_file_with_meta(
            "meta.bin",
            b"payload",
            MscabFileMeta {
                date: 0x5021,
                time: 0x7C00,
                attribs: 0x20,
            },
        );
        enc.add_file("plain.bin", b"no meta");
        let entries = decode(&enc.finish().unwrap()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "meta.bin");
        assert_eq!(entries[0].date, 0x5021);
        assert_eq!(entries[0].time, 0x7C00);
        assert_eq!(entries[0].attribs, 0x20);
        // add_file keeps emitting zeroed metadata.
        assert_eq!(entries[1].date, 0);
        assert_eq!(entries[1].time, 0);
        assert_eq!(entries[1].attribs, 0);
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
