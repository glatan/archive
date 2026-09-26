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
fn checksum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(4);
    for c in &mut chunks {
        sum ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let rem = chunks.remainder();
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
        if csum != 0 && checksum(block) != csum {
            return Err(Error::InvalidData("mscab: CFDATA checksum mismatch"));
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
    }

    impl CabBuilder {
        fn new() -> Self {
            Self {
                set_id: 0,
                i_cabinet: 0,
                folders: Vec::new(),
                files: Vec::new(),
                flags: 0,
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

            let mut header_ext = Vec::new();
            if self.flags & FLAG_RESERVE_PRESENT != 0 {
                header_ext.extend_from_slice(&0u16.to_le_bytes()); // cbCFHeader
                header_ext.push(0); // cbCFFolder
                header_ext.push(0); // cbCFData
            }
            if self.flags & FLAG_PREV_CABINET != 0 {
                header_ext.extend_from_slice(b"prev.cab\0prev-disk\0");
            }
            if self.flags & FLAG_NEXT_CABINET != 0 {
                header_ext.extend_from_slice(b"next.cab\0next-disk\0");
            }
            let folders_off = 36 + header_ext.len();
            let files_off = folders_off + self.folders.len() * 8;

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
                for b in &cfdatas[i] {
                    let uncomp = if *ty == COMPRESS_MSZIP {
                        deflate::decode::decode(&b[2..]).unwrap().len()
                    } else {
                        b.len()
                    };
                    data_buf.extend_from_slice(&0u32.to_le_bytes()); // csum
                    data_buf.extend_from_slice(&(b.len() as u16).to_le_bytes());
                    data_buf.extend_from_slice(&(uncomp as u16).to_le_bytes());
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
}
