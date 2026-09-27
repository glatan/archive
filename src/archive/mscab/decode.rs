//! Microsoft Cabinet (MSCAB) decoding.
//!
//! Parses `CFHEADER` / `CFFOLDER` / `CFFILE` / `CFDATA` structures from
//! [MS-CAB] and extracts files for folders using `tcompTYPE_NONE` (stored)
//! or `tcompTYPE_MSZIP` compression.

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"MSCF";

const FLAG_PREV_CABINET: u16 = 0x0001;
const FLAG_NEXT_CABINET: u16 = 0x0002;
const FLAG_RESERVE_PRESENT: u16 = 0x0004;

const COMPRESS_NONE: u16 = 0;
const COMPRESS_MSZIP: u16 = 1;

/// MSZIP data blocks carry at most a 32KiB history window.
const MSZIP_WINDOW: usize = 32 * 1024;

/// A decoded cabinet file entry.
#[derive(Debug, Clone)]
pub struct MscabEntry {
    /// Entry file name.
    pub name: String,
    /// Uncompressed file contents.
    pub data: Vec<u8>,
}

impl crate::traits::ArchiveEntry for MscabEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

struct Folder {
    coff_cab_start: usize,
    c_cfdata: usize,
    type_compress: u16,
}

struct FileRec {
    cb_file: usize,
    uoff_folder_start: usize,
    i_folder: usize,
    name: String,
}

fn le_u16(data: &[u8], off: usize) -> Result<u16, Error> {
    let bytes = data
        .get(off..off + 2)
        .ok_or(Error::InvalidData("mscab: truncated header"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn le_u32(data: &[u8], off: usize) -> Result<u32, Error> {
    let bytes = data
        .get(off..off + 4)
        .ok_or(Error::InvalidData("mscab: truncated header"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_asciiz(data: &[u8], off: usize) -> Result<(String, usize), Error> {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    if end >= data.len() {
        return Err(Error::InvalidData("mscab: unterminated string"));
    }
    Ok((
        String::from_utf8_lossy(&data[off..end]).into_owned(),
        end + 1,
    ))
}

/// Per-MS-CAB checksum: XOR of little-endian u32 words, tail zero-padded.
/// For CFDATA the checksum is seeded with the cbData and cbUncomp
/// fields packed as a little-endian u32 and covers abReserve + ab.
fn checksum(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let (chunks, rem) = data.as_chunks::<4>();
    for c in chunks {
        sum ^= u32::from_le_bytes(*c);
    }
    if !rem.is_empty() {
        let mut word = [0u8; 4];
        word[..rem.len()].copy_from_slice(rem);
        sum ^= u32::from_le_bytes(word);
    }
    sum
}

fn decompress_folder(
    input: &[u8],
    folder: &Folder,
    cb_cfdata_reserve: usize,
) -> Result<Vec<u8>, Error> {
    let comp_type = folder.type_compress & 0x00ff;
    if comp_type != COMPRESS_NONE && comp_type != COMPRESS_MSZIP {
        return Err(Error::Unsupported(
            "mscab: unsupported folder compression type",
        ));
    }

    let mut off = folder.coff_cab_start;
    let mut out = Vec::new();
    for _ in 0..folder.c_cfdata {
        let csum = le_u32(input, off)?;
        let cb_data = le_u16(input, off + 4)? as usize;
        let cb_uncomp = le_u16(input, off + 6)? as usize;
        let data_start = off + 8 + cb_cfdata_reserve;
        let block = input
            .get(data_start..data_start + cb_data)
            .ok_or(Error::InvalidData("mscab: truncated CFDATA"))?;
        if csum != 0 {
            // The checksum covers cbData, cbUncomp, the abReserve area, and
            // the data itself; the two u16 fields pack into the seed.
            let seed = (cb_uncomp as u32) << 16 | cb_data as u32;
            let covered = &input[off + 8..data_start + cb_data];
            if checksum(covered, seed) != csum {
                return Err(Error::InvalidData("mscab: CFDATA checksum mismatch"));
            }
        }

        match comp_type {
            COMPRESS_NONE => {
                if cb_data != cb_uncomp {
                    return Err(Error::InvalidData("mscab: stored block size mismatch"));
                }
                out.extend_from_slice(block);
            }
            COMPRESS_MSZIP => {
                if block.len() < 2 || &block[..2] != b"CK" {
                    return Err(Error::InvalidData("mscab: bad MSZIP block signature"));
                }
                let dict_start = out.len().saturating_sub(MSZIP_WINDOW);
                let decoded = deflate::decode::decode_with_dict(&block[2..], &out[dict_start..])?;
                if decoded.len() != cb_uncomp {
                    return Err(Error::InvalidData("mscab: MSZIP block size mismatch"));
                }
                out.extend_from_slice(&decoded);
            }
            _ => unreachable!(),
        }
        off = data_start + cb_data;
    }
    Ok(out)
}

/// Decode an MSCAB archive into a list of entries.
pub fn decode(input: &[u8]) -> Result<Vec<MscabEntry>, Error> {
    if input.len() < 36 {
        return Err(Error::InvalidData("mscab: input too short"));
    }
    if &input[..4] != MAGIC {
        return Err(Error::InvalidData("mscab: bad magic"));
    }

    let cb_cabinet = le_u32(input, 8)? as usize;
    let coff_files = le_u32(input, 16)? as usize;
    let version_minor = input[24];
    let version_major = input[25];
    let c_folders = le_u16(input, 26)? as usize;
    let c_files = le_u16(input, 28)? as usize;
    let flags = le_u16(input, 30)?;

    if version_major != 1 || version_minor > 3 {
        return Err(Error::InvalidData("mscab: unsupported version"));
    }
    if cb_cabinet == 0 || cb_cabinet > input.len() {
        return Err(Error::InvalidData("mscab: bad cabinet size"));
    }

    let mut off = 36usize;
    let mut cb_cffolder_reserve = 0usize;
    let mut cb_cfdata_reserve = 0usize;
    if flags & FLAG_RESERVE_PRESENT != 0 {
        let cb_cfheader = le_u16(input, off)? as usize;
        cb_cffolder_reserve = *input
            .get(off + 2)
            .ok_or(Error::InvalidData("mscab: truncated header"))?
            as usize;
        cb_cfdata_reserve = *input
            .get(off + 3)
            .ok_or(Error::InvalidData("mscab: truncated header"))?
            as usize;
        off += 4 + cb_cfheader;
    }
    if flags & FLAG_PREV_CABINET != 0 {
        let (_, n) = read_asciiz(input, off)?;
        off = n;
        let (_, n) = read_asciiz(input, off)?;
        off = n;
    }
    if flags & FLAG_NEXT_CABINET != 0 {
        let (_, n) = read_asciiz(input, off)?;
        off = n;
        let (_, n) = read_asciiz(input, off)?;
        off = n;
    }

    let folder_stride = 8 + cb_cffolder_reserve;
    let mut folders = Vec::with_capacity(c_folders);
    for i in 0..c_folders {
        let base = off + i * folder_stride;
        folders.push(Folder {
            coff_cab_start: le_u32(input, base)? as usize,
            c_cfdata: le_u16(input, base + 4)? as usize,
            type_compress: le_u16(input, base + 6)?,
        });
    }

    let mut files = Vec::with_capacity(c_files);
    let mut foff = coff_files;
    for _ in 0..c_files {
        let cb_file = le_u32(input, foff)? as usize;
        let uoff_folder_start = le_u32(input, foff + 4)? as usize;
        let i_folder = le_u16(input, foff + 8)? as usize;
        let _attribs = le_u16(input, foff + 14)?;
        let (name, next) = read_asciiz(input, foff + 16)?;
        if i_folder >= 0xfffd {
            return Err(Error::Unsupported(
                "mscab: multi-cabinet file spanning is not supported",
            ));
        }
        if i_folder >= c_folders && cb_file > 0 {
            return Err(Error::InvalidData("mscab: folder index out of range"));
        }
        files.push(FileRec {
            cb_file,
            uoff_folder_start,
            i_folder,
            name,
        });
        foff = next;
    }

    let mut folder_data = Vec::with_capacity(c_folders);
    for f in &folders {
        folder_data.push(decompress_folder(input, f, cb_cfdata_reserve)?);
    }

    let mut entries = Vec::with_capacity(files.len());
    for f in &files {
        let mut data = Vec::with_capacity(f.cb_file);
        let mut pos = f.uoff_folder_start;
        let mut fi = f.i_folder;
        while data.len() < f.cb_file {
            let folder = folder_data
                .get(fi)
                .ok_or(Error::InvalidData("mscab: file data overruns folders"))?;
            if pos > folder.len() {
                return Err(Error::InvalidData("mscab: file offset out of range"));
            }
            let avail = &folder[pos..];
            let need = f.cb_file - data.len();
            let take = avail.len().min(need);
            data.extend_from_slice(&avail[..take]);
            if take < need {
                fi += 1;
                pos = 0;
            }
        }
        entries.push(MscabEntry {
            name: f.name.clone(),
            data,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::ArchiveEntry;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Minimal cabinet builder for tests: stored or MSZIP single folder.
    struct CabBuilder {
        set_id: u16,
        i_cabinet: u16,
        folders: Vec<(u16, Vec<Vec<u8>>)>, // (type_compress, [cfdatas])
        files: Vec<(usize, usize, usize, String)>, // (cb_file, uoff, i_folder, name)
        flags: u16,
        /// Reserve sizes (cbCFHeader, cbCFFolder, cbCFData) emitted when
        /// `FLAG_RESERVE_PRESENT` is set. The reserved areas are filled
        /// with non-zero dummy bytes so the decoder must actually skip them.
        reserve: (u16, u8, u8),
    }

    /// Filler byte for reserved areas (non-zero, never a valid structure).
    const RESERVE_FILL: u8 = 0xA5;

    impl CabBuilder {
        fn new() -> Self {
            Self {
                set_id: 0,
                i_cabinet: 0,
                folders: Vec::new(),
                files: Vec::new(),
                flags: 0,
                reserve: (0, 0, 0),
            }
        }

        fn mszip_block(payload: &[u8]) -> Vec<u8> {
            let mut b = Vec::with_capacity(payload.len() + 2);
            b.extend_from_slice(b"CK");
            b.extend_from_slice(payload);
            b
        }

        fn build(&self) -> Vec<u8> {
            let c_folders = self.folders.len() as u16;
            let c_files = self.files.len() as u16;

            let (cb_cfheader, cb_cffolder, cb_cfdata) = if self.flags & FLAG_RESERVE_PRESENT != 0 {
                self.reserve
            } else {
                (0, 0, 0)
            };
            let mut header_ext = Vec::new();
            if self.flags & FLAG_RESERVE_PRESENT != 0 {
                header_ext.extend_from_slice(&cb_cfheader.to_le_bytes()); // cbCFHeader
                header_ext.push(cb_cffolder); // cbCFFolder
                header_ext.push(cb_cfdata); // cbCFData
                header_ext.resize(header_ext.len() + cb_cfheader as usize, RESERVE_FILL);
            }
            if self.flags & FLAG_PREV_CABINET != 0 {
                header_ext.extend_from_slice(b"prev.cab\0prev-disk\0");
            }
            if self.flags & FLAG_NEXT_CABINET != 0 {
                header_ext.extend_from_slice(b"next.cab\0next-disk\0");
            }
            let folders_off = 36 + header_ext.len();
            let files_off = folders_off + self.folders.len() * (8 + cb_cffolder as usize);

            let mut files_buf = Vec::new();
            for (cb, uoff, ifo, name) in &self.files {
                files_buf.extend_from_slice(&(*cb as u32).to_le_bytes());
                files_buf.extend_from_slice(&(*uoff as u32).to_le_bytes());
                files_buf.extend_from_slice(&(*ifo as u16).to_le_bytes());
                files_buf.extend_from_slice(&0u16.to_le_bytes()); // date
                files_buf.extend_from_slice(&0u16.to_le_bytes()); // time
                files_buf.extend_from_slice(&0u16.to_le_bytes()); // attribs
                files_buf.extend_from_slice(name.as_bytes());
                files_buf.push(0);
            }

            let data_off = files_off + files_buf.len();

            // Wrap MSZIP payloads with the "CK" block signature.
            let mut cfdatas: Vec<Vec<Vec<u8>>> = Vec::new();
            for (ty, blocks) in &self.folders {
                let mut v = Vec::new();
                for b in blocks {
                    if *ty == COMPRESS_MSZIP {
                        v.push(Self::mszip_block(b));
                    } else {
                        v.push(b.clone());
                    }
                }
                cfdatas.push(v);
            }

            let mut folders_buf = Vec::new();
            let mut data_buf = Vec::new();
            for (i, (ty, _blocks)) in self.folders.iter().enumerate() {
                folders_buf.extend_from_slice(&((data_off + data_buf.len()) as u32).to_le_bytes());
                folders_buf.extend_from_slice(&(cfdatas[i].len() as u16).to_le_bytes());
                folders_buf.extend_from_slice(&ty.to_le_bytes());
                folders_buf.resize(folders_buf.len() + cb_cffolder as usize, RESERVE_FILL);
                // MSZIP history carried across CFDATA blocks in the folder, so
                // blocks with cross-block back-references size correctly.
                let mut history: Vec<u8> = Vec::new();
                for b in &cfdatas[i] {
                    let uncomp = if *ty == COMPRESS_MSZIP {
                        let dict_start = history.len().saturating_sub(MSZIP_WINDOW);
                        let decoded =
                            deflate::decode::decode_with_dict(&b[2..], &history[dict_start..])
                                .unwrap();
                        history.extend_from_slice(&decoded);
                        decoded.len()
                    } else {
                        b.len()
                    };
                    data_buf.extend_from_slice(&0u32.to_le_bytes()); // csum
                    data_buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
                    data_buf.extend_from_slice(&(uncomp as u16).to_le_bytes());
                    data_buf.resize(data_buf.len() + cb_cfdata as usize, RESERVE_FILL);
                    data_buf.extend_from_slice(b);
                }
            }

            let cb_cabinet = (data_off + data_buf.len()) as u32;
            let mut out = Vec::with_capacity(cb_cabinet as usize);
            out.extend_from_slice(MAGIC);
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
            out.extend_from_slice(&cb_cabinet.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
            out.extend_from_slice(&(files_off as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // reserved3
            out.push(3); // versionMinor
            out.push(1); // versionMajor
            out.extend_from_slice(&c_folders.to_le_bytes());
            out.extend_from_slice(&c_files.to_le_bytes());
            out.extend_from_slice(&self.flags.to_le_bytes());
            out.extend_from_slice(&self.set_id.to_le_bytes());
            out.extend_from_slice(&self.i_cabinet.to_le_bytes());
            out.extend_from_slice(&header_ext);
            out.extend_from_slice(&folders_buf);
            out.extend_from_slice(&files_buf);
            out.extend_from_slice(&data_buf);
            out
        }
    }

    fn stored_cab() -> Vec<u8> {
        let mut b = CabBuilder::new();
        b.folders
            .push((COMPRESS_NONE, vec![b"hello cabinet".to_vec()]));
        b.files.push((13, 0, 0, "hello.txt".into()));
        b.build()
    }

    #[test]
    fn parses_stored_cabinet() {
        let cab = stored_cab();
        let entries = decode(&cab).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "hello.txt");
        assert_eq!(entries[0].data(), b"hello cabinet");
    }

    #[test]
    fn parses_mszip_cabinet() {
        let payload = deflate::encode::encode(b"hello mszip data", deflate::encode::Level::Default);
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_MSZIP, vec![payload]));
        b.files.push((16, 0, 0, "data.txt".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "data.txt");
        assert_eq!(entries[0].data(), b"hello mszip data");
    }

    #[test]
    fn mszip_history_spans_cfdata_blocks() {
        // Two deflate streams; the second references bytes from the first
        // via the MSZIP cross-block history window.
        let first = b"abcdefghijabcdefghij";
        let second_src = b"abcdefghij"; // will be emitted as a match at dist 10? Not guaranteed.
        let _ = second_src;
        // Build: block1 = deflate("abcdefghij"), block2 raw literals "XYZ"
        // referencing nothing; but decode_with_dict must accept dict.
        let b1 = deflate::encode::encode(first, deflate::encode::Level::Default);
        let b2 = deflate::encode::encode(b"XYZ", deflate::encode::Level::Default);
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_MSZIP, vec![b1, b2]));
        b.files.push((23, 0, 0, "f.txt".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(
            entries[0].data(),
            {
                let mut v = first.to_vec();
                v.extend_from_slice(b"XYZ");
                v
            }
            .as_slice()
        );
    }

    #[test]
    fn file_spans_two_folders() {
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_NONE, vec![b"AAA".to_vec()]));
        b.folders.push((COMPRESS_NONE, vec![b"BBB".to_vec()]));
        // file starts at offset 1 of folder 0, len 4 → "AA" + "BB"
        b.files.push((4, 1, 0, "span.bin".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data(), b"AABB");
    }

    #[test]
    fn rejects_bad_magic() {
        let mut cab = stored_cab();
        cab[0] = b'X';
        assert!(matches!(decode(&cab), Err(Error::InvalidData(_))));
    }

    #[test]
    fn rejects_quantum_folder() {
        let mut b = CabBuilder::new();
        b.folders.push((2, vec![b"x".to_vec()])); // tcompTYPE_QUANTUM
        b.files.push((1, 0, 0, "f".into()));
        let e = decode(&b.build()).unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)));
    }

    #[test]
    fn rejects_spanned_file() {
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_NONE, vec![b"ab".to_vec()]));
        b.files.push((1, 0, 0xfffe, "f".into()));
        assert!(matches!(decode(&b.build()), Err(Error::Unsupported(_))));
    }

    #[test]
    fn rejects_truncated() {
        let cab = stored_cab();
        assert!(decode(&cab[..cab.len() - 1]).is_err());
    }

    #[test]
    fn rejects_mszip_bad_signature() {
        let payload = deflate::encode::encode(b"xy", deflate::encode::Level::Default);
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_MSZIP, vec![payload]));
        b.files.push((2, 0, 0, "f".into()));
        let mut cab = b.build();
        // corrupt the "CK" block signature in the data area
        let idx = cab.windows(2).position(|w| w == b"CK").unwrap();
        cab[idx] = b'Z';
        assert!(matches!(decode(&cab), Err(Error::InvalidData(_))));
    }

    /// Offset of the first CFDATA of folder `i` (no reserve, no prev/next).
    fn first_cfdata_off(cab: &[u8], i: usize) -> usize {
        le_u32(cab, 36 + i * 8).unwrap() as usize
    }

    fn assert_invalid(res: Result<Vec<MscabEntry>, Error>, expected: &str) {
        match res {
            Err(Error::InvalidData(msg)) => assert_eq!(msg, expected),
            Err(e) => panic!("expected InvalidData({expected:?}), got {e:?}"),
            Ok(_) => panic!("expected InvalidData({expected:?}), got Ok"),
        }
    }

    /// Minimal fixed-Huffman DEFLATE writer for hand-built streams.
    enum Op {
        Lit(u8),
        Match(u16, u16), // (length 3..=258, distance 1..=32768)
    }

    struct BitWriter {
        out: Vec<u8>,
        acc: u32,
        n: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                out: Vec::new(),
                acc: 0,
                n: 0,
            }
        }

        /// Write `len` bits LSB-first (header fields and extra bits).
        fn bits(&mut self, value: u32, len: u32) {
            for i in 0..len {
                self.acc |= ((value >> i) & 1) << self.n;
                self.n += 1;
                if self.n == 8 {
                    self.out.push(self.acc as u8);
                    self.acc = 0;
                    self.n = 0;
                }
            }
        }

        /// Write a Huffman code MSB-first.
        fn code(&mut self, code: u32, len: u32) {
            for i in (0..len).rev() {
                self.bits((code >> i) & 1, 1);
            }
        }

        fn litlen(&mut self, sym: u32) {
            match sym {
                0..=143 => self.code(0x30 + sym, 8),
                144..=255 => self.code(0x190 + sym - 144, 9),
                256..=279 => self.code(sym - 256, 7),
                _ => self.code(0xC0 + sym - 280, 8),
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.n > 0 {
                self.out.push(self.acc as u8);
            }
            self.out
        }
    }

    fn fixed_huffman_stream(ops: &[Op]) -> Vec<u8> {
        const LEN_BASE: [u16; 29] = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
            115, 131, 163, 195, 227, 258,
        ];
        const LEN_EXTRA: [u32; 29] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
        ];
        const DIST_BASE: [u16; 30] = [
            1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025,
            1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
        ];
        const DIST_EXTRA: [u32; 30] = [
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12,
            12, 13, 13,
        ];
        let mut w = BitWriter::new();
        w.bits(1, 1); // BFINAL
        w.bits(1, 2); // BTYPE = 01 (fixed Huffman)
        for op in ops {
            match *op {
                Op::Lit(b) => w.litlen(b as u32),
                Op::Match(len, dist) => {
                    let li = LEN_BASE.iter().rposition(|&b| b <= len).unwrap();
                    w.litlen(257 + li as u32);
                    w.bits((len - LEN_BASE[li]) as u32, LEN_EXTRA[li]);
                    let di = DIST_BASE.iter().rposition(|&b| b <= dist).unwrap();
                    w.code(di as u32, 5);
                    w.bits((dist - DIST_BASE[di]) as u32, DIST_EXTRA[di]);
                }
            }
        }
        w.litlen(256); // end of block
        w.finish()
    }

    #[test]
    fn rejects_bad_major_version() {
        let mut cab = stored_cab();
        assert_eq!(cab[25], 1);
        cab[25] = 2;
        assert_invalid(decode(&cab), "mscab: unsupported version");
        cab[25] = 0;
        assert_invalid(decode(&cab), "mscab: unsupported version");
    }

    #[test]
    fn rejects_bad_minor_version() {
        let mut cab = stored_cab();
        assert_eq!(cab[24], 3);
        cab[24] = 4;
        assert_invalid(decode(&cab), "mscab: unsupported version");
        // minor 0..=3 are all accepted for major 1.
        for minor in 0..=3 {
            cab[24] = minor;
            assert!(decode(&cab).is_ok(), "minor={minor} should be accepted");
        }
    }

    #[test]
    fn parses_cabinet_with_prev_next_names() {
        let mut b = CabBuilder::new();
        b.flags = FLAG_PREV_CABINET | FLAG_NEXT_CABINET;
        b.folders
            .push((COMPRESS_NONE, vec![b"first-folder".to_vec()]));
        b.folders.push((COMPRESS_NONE, vec![b"second".to_vec()]));
        b.files.push((5, 0, 0, "a.txt".into()));
        b.files.push((6, 6, 0, "b.txt".into()));
        b.files.push((6, 0, 1, "c.txt".into()));
        let cab = b.build();
        // The header_ext strings really are present after the fixed header.
        assert_eq!(&cab[36..36 + 19], b"prev.cab\0prev-disk\0");
        assert_eq!(&cab[55..55 + 19], b"next.cab\0next-disk\0");

        let entries = decode(&cab).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name(), "a.txt");
        assert_eq!(entries[0].data(), b"first");
        assert_eq!(entries[1].name(), "b.txt");
        assert_eq!(entries[1].data(), b"folder");
        assert_eq!(entries[2].name(), "c.txt");
        assert_eq!(entries[2].data(), b"second");
    }

    #[test]
    fn parses_cabinet_with_nonzero_reserve() {
        let payload = deflate::encode::encode(b"reserved mszip", deflate::encode::Level::Default);
        let mut b = CabBuilder::new();
        b.flags = FLAG_RESERVE_PRESENT | FLAG_PREV_CABINET;
        b.reserve = (7, 3, 5);
        b.folders
            .push((COMPRESS_NONE, vec![b"stored".to_vec(), b"-two".to_vec()]));
        b.folders.push((COMPRESS_MSZIP, vec![payload]));
        b.files.push((10, 0, 0, "s.txt".into()));
        b.files.push((14, 0, 1, "m.txt".into()));
        let cab = b.build();
        // Reserve header fields and a filled cbCFHeader area are present.
        assert_eq!(le_u16(&cab, 36).unwrap(), 7);
        assert_eq!(cab[38], 3);
        assert_eq!(cab[39], 5);
        assert!(cab[40..47].iter().all(|&x| x == RESERVE_FILL));

        let entries = decode(&cab).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "s.txt");
        assert_eq!(entries[0].data(), b"stored-two");
        assert_eq!(entries[1].name(), "m.txt");
        assert_eq!(entries[1].data(), b"reserved mszip");
    }

    #[test]
    fn rejects_checksum_mismatch() {
        let mut cab = stored_cab();
        let off = first_cfdata_off(&cab, 0);
        assert_eq!(le_u32(&cab, off).unwrap(), 0, "builder writes csum=0");
        let cb_data = le_u16(&cab, off + 4).unwrap() as usize;
        let cb_uncomp = le_u16(&cab, off + 6).unwrap() as usize;
        let seed = (cb_uncomp as u32) << 16 | cb_data as u32;
        let good = checksum(&cab[off + 8..off + 8 + cb_data], seed);
        // A correctly-computed nonzero csum is accepted.
        cab[off..off + 4].copy_from_slice(&good.to_le_bytes());
        assert!(decode(&cab).is_ok(), "valid csum must be accepted");
        assert_ne!(good, 0, "seed makes the csum nonzero for this block");
        let bad = good ^ 0x5A5A_5A5A;
        assert_ne!(bad, 0);
        cab[off..off + 4].copy_from_slice(&bad.to_le_bytes());
        assert_invalid(decode(&cab), "mscab: CFDATA checksum mismatch");
    }

    #[test]
    fn checksum_covers_cfdata_reserve() {
        // The csum covers cbData, cbUncomp, abReserve, and ab. A cabinet
        // whose csum was computed over the whole covered range must pass.
        let mut b = CabBuilder::new();
        b.flags = FLAG_RESERVE_PRESENT;
        b.reserve = (0, 0, 5);
        b.folders.push((COMPRESS_NONE, vec![b"data".to_vec()]));
        b.files.push((4, 0, 0, "r.txt".into()));
        let mut cab = b.build();
        // header_ext = 4-byte reserve fields (cbCFHeader=0 -> no fill).
        let off = le_u32(&cab, 36 + 4).unwrap() as usize;
        let cb_data = le_u16(&cab, off + 4).unwrap() as usize;
        let cb_uncomp = le_u16(&cab, off + 6).unwrap() as usize;
        let seed = (cb_uncomp as u32) << 16 | cb_data as u32;
        // Covered range = 5-byte abReserve (RESERVE_FILL) + cb_data bytes.
        let good = checksum(&cab[off + 8..off + 8 + 5 + cb_data], seed);
        cab[off..off + 4].copy_from_slice(&good.to_le_bytes());
        let entries = decode(&cab).unwrap();
        assert_eq!(entries[0].data(), b"data");
        // And a csum computed without the reserve area must fail.
        let mut cab2 = b.build();
        let narrow = checksum(&cab2[off + 8 + 5..off + 8 + 5 + cb_data], seed);
        cab2[off..off + 4].copy_from_slice(&narrow.to_le_bytes());
        if narrow != 0 && narrow != good {
            assert_invalid(decode(&cab2), "mscab: CFDATA checksum mismatch");
        }
    }

    #[test]
    fn mszip_cross_block_backreference_resolves() {
        // Block 1: ordinary deflate stream of a distinctive payload.
        let first: Vec<u8> = (0..300u32)
            .map(|i| b"0123456789ABCDEFGHIJ"[(i * 7 % 20) as usize] ^ (i as u8 / 20))
            .collect();
        let b1 = deflate::encode::encode(&first, deflate::encode::Level::Default);

        // Block 2: hand-built fixed-Huffman stream whose matches reach back
        // into block 1's output (distances larger than block 2's own output).
        let ops = [
            Op::Match(20, 300), // first[0..20]
            Op::Lit(b'|'),
            Op::Match(50, 321 - 100), // first[100..150]
            Op::Match(3, 1),          // repeat last byte (intra-block)
        ];
        let b2 = fixed_huffman_stream(&ops);
        // Standalone, block 2 is undecodable: its references need history.
        assert!(deflate::decode::decode(&b2).is_err());

        let mut expected = first.clone();
        expected.extend_from_slice(&first[0..20]);
        expected.push(b'|');
        expected.extend_from_slice(&first[100..150]);
        let last = *expected.last().unwrap();
        expected.extend_from_slice(&[last; 3]);

        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_MSZIP, vec![b1, b2]));
        b.files.push((expected.len(), 0, 0, "x.bin".into()));
        let cab = b.build();
        let off = first_cfdata_off(&cab, 0);
        let cb1 = le_u16(&cab, off + 4).unwrap() as usize;
        assert_eq!(le_u16(&cab, off + 6).unwrap() as usize, first.len());
        assert_eq!(le_u16(&cab, off + 8 + cb1 + 6).unwrap() as usize, 74);

        let entries = decode(&cab).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data(), expected.as_slice());
    }

    #[test]
    fn rejects_uncompressed_size_mismatch() {
        let payload = deflate::encode::encode(b"hello mszip data", deflate::encode::Level::Default);
        let mut b = CabBuilder::new();
        b.folders.push((COMPRESS_MSZIP, vec![payload]));
        b.files.push((16, 0, 0, "data.txt".into()));
        let mut cab = b.build();
        let off = first_cfdata_off(&cab, 0);
        assert_eq!(le_u16(&cab, off + 6).unwrap(), 16);
        cab[off + 6..off + 8].copy_from_slice(&17u16.to_le_bytes());
        assert_invalid(decode(&cab), "mscab: MSZIP block size mismatch");
        cab[off + 6..off + 8].copy_from_slice(&15u16.to_le_bytes());
        assert_invalid(decode(&cab), "mscab: MSZIP block size mismatch");
    }
}
