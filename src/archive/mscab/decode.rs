//! Microsoft Cabinet (MSCAB) decoding.
//!
//! Parses `CFHEADER` / `CFFOLDER` / `CFFILE` / `CFDATA` structures from
//! [MS-CAB] and extracts files for folders using `tcompTYPE_NONE` (stored),
//! `tcompTYPE_MSZIP` or `tcompTYPE_LZX` compression.

use alloc::string::String;
use alloc::vec::Vec;

use crate::compress::deflate;
use crate::compress::lzx;
use crate::error::Error;

const MAGIC: &[u8; 4] = b"MSCF";

const FLAG_PREV_CABINET: u16 = 0x0001;
const FLAG_NEXT_CABINET: u16 = 0x0002;
const FLAG_RESERVE_PRESENT: u16 = 0x0004;

const COMPRESS_NONE: u16 = 0;
const COMPRESS_MSZIP: u16 = 1;
const COMPRESS_QUANTUM: u16 = 2;
const COMPRESS_LZX: u16 = 3;

/// Cabinet LZX window sizes are log2-encoded in `typeCompress` bits
/// 8..12 (`(typeCompress >> 8) & 0x1f`, 15..=21 for 32 KiB..2 MiB).
const LZX_WINDOW_BITS_MIN: u16 = 15;
const LZX_WINDOW_BITS_MAX: u16 = 21;

/// Cabinet Quantum window sizes share the same `typeCompress` bits
/// 8..12 field, valid range 10..=21 (1 KiB..2 MiB).
const QUANTUM_WINDOW_BITS_MIN: u16 = 10;
const QUANTUM_WINDOW_BITS_MAX: u16 = 21;

/// `iFolder` values reserved for files spanning cabinets (MS-CAB §2.3).
const IFOLD_CONTINUED_FROM_PREV: usize = 0xfffd;
const IFOLD_CONTINUED_TO_NEXT: usize = 0xfffe;
const IFOLD_CONTINUED_PREV_AND_NEXT: usize = 0xffff;

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

/// Per-MS-CAB checksum: XOR of little-endian u32 words. A trailing
/// 1-3 byte remainder is packed into a u32 with the first tail byte in
/// the most significant used byte (libmspack's case-3/2/1 fallthrough
/// into bits 16/8/0), not little-endian zero-padded; real cabinets
/// such as cabextract's large-files-cab.cab depend on this.
/// For CFDATA the checksum is seeded with the cbData and cbUncomp
/// fields packed as a little-endian u32 and covers abReserve + ab.
pub(crate) fn checksum(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let (chunks, rem) = data.as_chunks::<4>();
    for c in chunks {
        sum ^= u32::from_le_bytes(*c);
    }
    if !rem.is_empty() {
        let mut word = 0u32;
        for &b in rem {
            word = (word << 8) | b as u32;
        }
        sum ^= word;
    }
    sum
}

/// Accumulated input/expected-output counters for an LZX or Quantum
/// logical folder that may span cabinet members (those bitstreams are
/// contiguous across folder fragments, so they can only be decoded
/// once the last fragment is in).
#[derive(Default)]
struct StreamAccum {
    /// Concatenated compressed CFDATA payloads.
    data: Vec<u8>,
    /// Sum of `cbUncomp` over the fragments seen so far.
    expected: usize,
}

/// Decompress one CFFOLDER fragment into `stream`.
///
/// `logical_start` is the offset in `stream` where the containing
/// logical folder began (used as the MSZIP dictionary boundary, so a
/// fragment continued from a previous cabinet shares history).
///
/// `pending` carries the compressed prefix of a CFDATA block split
/// across cabinets: per MS-CAB §2.4 a trailing CFDATA with
/// `cbUncomp == 0` continues in the first CFDATA of the next
/// cabinet's folder fragment, which reports the total size.
///
/// For LZX and Quantum folders, `stream_acc` accumulates the
/// contiguous bitstream across the fragment's blocks (and across
/// cabinet members while the folder continues, i.e. while `pending`
/// is non-empty); decoding runs once the logical folder is complete.
fn decompress_folder(
    input: &[u8],
    folder: &Folder,
    cb_cfdata_reserve: usize,
    logical_start: usize,
    stream: &mut Vec<u8>,
    pending: &mut Vec<u8>,
    stream_acc: &mut StreamAccum,
) -> Result<(), Error> {
    // typeCompress bits 0-3 select the codec; bits 8-12 carry the
    // window size for LZX/Quantum (MS-CAB §3.2 CFFOLDER).
    let comp_type = folder.type_compress & 0x000f;
    if !matches!(
        comp_type,
        COMPRESS_NONE | COMPRESS_MSZIP | COMPRESS_QUANTUM | COMPRESS_LZX
    ) {
        return Err(Error::Unsupported(
            "mscab: unsupported folder compression type",
        ));
    }
    let mut lzx_window = 0usize;
    let mut quantum_window_bits = 0u32;
    let window_bits = (folder.type_compress >> 8) & 0x1f;
    if comp_type == COMPRESS_LZX {
        if !(LZX_WINDOW_BITS_MIN..=LZX_WINDOW_BITS_MAX).contains(&window_bits) {
            return Err(Error::InvalidData("mscab: LZX window size out of range"));
        }
        lzx_window = 1usize << window_bits;
    } else if comp_type == COMPRESS_QUANTUM
        && !(QUANTUM_WINDOW_BITS_MIN..=QUANTUM_WINDOW_BITS_MAX).contains(&window_bits)
    {
        return Err(Error::InvalidData(
            "mscab: Quantum window size out of range",
        ));
    } else if comp_type == COMPRESS_QUANTUM {
        quantum_window_bits = u32::from(window_bits);
    }

    let mut off = folder.coff_cab_start;
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

        let data = if cb_uncomp == 0 {
            // Split block: buffer the compressed prefix; the matching
            // tail arrives in the next cabinet's fragment.
            pending.extend_from_slice(block);
            off = data_start + cb_data;
            continue;
        } else if pending.is_empty() {
            alloc::borrow::Cow::Borrowed(block)
        } else {
            let mut full = Vec::with_capacity(pending.len() + block.len());
            full.extend_from_slice(pending);
            full.extend_from_slice(block);
            pending.clear();
            alloc::borrow::Cow::Owned(full)
        };

        match comp_type {
            COMPRESS_NONE => {
                if data.len() != cb_uncomp {
                    return Err(Error::InvalidData("mscab: stored block size mismatch"));
                }
                stream.extend_from_slice(&data[..]);
            }
            COMPRESS_MSZIP => {
                if data.len() < 2 || &data[..2] != b"CK" {
                    return Err(Error::InvalidData("mscab: bad MSZIP block signature"));
                }
                let dict_start = stream.len().saturating_sub(MSZIP_WINDOW).max(logical_start);
                let decoded = deflate::decode::decode_with_dict(&data[2..], &stream[dict_start..])?;
                if decoded.len() != cb_uncomp {
                    return Err(Error::InvalidData("mscab: MSZIP block size mismatch"));
                }
                stream.extend_from_slice(&decoded);
            }
            COMPRESS_LZX | COMPRESS_QUANTUM => {
                // CFDATA records are byte containers only: LZX/Quantum
                // decoder state is contiguous across them, so the
                // payloads accumulate. Quantum additionally realigns at
                // every block boundary, so a synthesised 0xFF sentinel
                // byte is fed after each block (as cabd.c does).
                stream_acc.data.extend_from_slice(&data);
                if comp_type == COMPRESS_QUANTUM {
                    stream_acc.data.push(0xFF);
                }
                stream_acc.expected += cb_uncomp;
            }
            _ => unreachable!(),
        }
        off = data_start + cb_data;
    }
    if comp_type == COMPRESS_LZX && pending.is_empty() {
        // Logical folder complete: decode the contiguous LZX stream.
        let decoded = lzx::decode_cabinet(&stream_acc.data, lzx_window, stream_acc.expected)?;
        stream.extend_from_slice(&decoded);
        *stream_acc = StreamAccum::default();
    } else if comp_type == COMPRESS_QUANTUM && pending.is_empty() {
        let decoded =
            super::quantum::decode(&stream_acc.data, quantum_window_bits, stream_acc.expected)?;
        stream.extend_from_slice(&decoded);
        *stream_acc = StreamAccum::default();
    }
    Ok(())
}

/// A cabinet member with its structures parsed; folder data is
/// decompressed later so continuation fragments can chain across
/// the members of a cabinet set.
struct ParsedCab<'a> {
    input: &'a [u8],
    set_id: u16,
    i_cabinet: u16,
    cb_cfdata_reserve: usize,
    folders: Vec<Folder>,
    files: Vec<FileRec>,
}

/// Decode an MSCAB archive into a list of entries.
pub fn decode(input: &[u8]) -> Result<Vec<MscabEntry>, Error> {
    let cab = parse_cabinet(input)?;
    extract_cabs(&[&cab])
}

/// Decode a multi-cabinet set (`disk1.cab`, `disk2.cab`, ...) into a
/// list of entries (MS-CAB §2.1 cabinet set).
///
/// Each supplied slice is one complete cabinet file in set order;
/// `CFHEADER.iCabinet` must match the slice index and `setID` must be
/// identical across members. Files whose `iFolder` is one of the
/// continuation sentinels (§2.3 `0xFFFD`-`0xFFFF`) are resolved
/// across member boundaries: folder fragments chain into one
/// uncompressed stream, and a CFDATA block split mid-record
/// (`cbUncomp == 0` tail) is reassembled from the next member.
/// A file that begins before the first supplied member is rejected.
pub fn decode_parts(parts: &[&[u8]]) -> Result<Vec<MscabEntry>, Error> {
    if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
        return Err(Error::InvalidData("mscab: empty cabinet part"));
    }
    let mut cabs: Vec<ParsedCab<'_>> = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate() {
        let cab = parse_cabinet(p)?;
        if cab.i_cabinet != i as u16 {
            return Err(Error::InvalidData("mscab: cabinet index mismatch"));
        }
        if let Some(first) = cabs.first()
            && cab.set_id != first.set_id
        {
            return Err(Error::InvalidData("mscab: set id mismatch"));
        }
        cabs.push(cab);
    }
    extract_cabs(&cabs.iter().collect::<Vec<_>>())
}

fn parse_cabinet(input: &[u8]) -> Result<ParsedCab<'_>, Error> {
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
    let set_id = le_u16(input, 32)?;
    let i_cabinet = le_u16(input, 34)?;

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
        if i_folder < 0xfffd && i_folder >= c_folders && cb_file > 0 {
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

    Ok(ParsedCab {
        input,
        set_id,
        i_cabinet,
        cb_cfdata_reserve,
        folders,
        files,
    })
}

/// Extract all files of a cabinet set (single member for
/// [`decode`]). Folder fragments chain into one uncompressed stream;
/// file `uoffFolderStart` values are offsets into their logical
/// folder, so spanning files are sliced directly out of the stream.
fn extract_cabs(cabs: &[&ParsedCab<'_>]) -> Result<Vec<MscabEntry>, Error> {
    let multi = cabs.len() > 1;

    // Per §2.3, entries for files continued from the previous cabinet
    // come first and bind folder index 0 as a continuation fragment
    // of the previous cabinet's last folder.
    let mut continues = alloc::vec![false; cabs.len()];
    if multi {
        for (k, cab) in cabs.iter().enumerate().skip(1) {
            continues[k] = cab.files.iter().any(|f| {
                f.i_folder == IFOLD_CONTINUED_FROM_PREV
                    || f.i_folder == IFOLD_CONTINUED_PREV_AND_NEXT
            });
        }
    }

    let mut stream = Vec::new();
    let mut folder_base: Vec<Vec<usize>> = Vec::with_capacity(cabs.len());
    let mut pending: Vec<u8> = Vec::new();
    let mut stream_acc = StreamAccum::default();
    let mut cur_logical = 0usize;
    let mut prev_type = u16::MAX;
    for (k, cab) in cabs.iter().enumerate() {
        let mut bases = Vec::with_capacity(cab.folders.len());
        for (i, folder) in cab.folders.iter().enumerate() {
            let cont = i == 0 && continues[k];
            if !cont {
                if !pending.is_empty() {
                    return Err(Error::InvalidData(
                        "mscab: split CFDATA without continuation",
                    ));
                }
                cur_logical = stream.len();
            } else if folder.type_compress != prev_type {
                // MS-CAB §2.2: typeCompress may vary between folders
                // but not between fragments of one continued folder.
                return Err(Error::InvalidData(
                    "mscab: continuation folder compression type mismatch",
                ));
            }
            prev_type = folder.type_compress;
            bases.push(cur_logical);
            decompress_folder(
                cab.input,
                folder,
                cab.cb_cfdata_reserve,
                cur_logical,
                &mut stream,
                &mut pending,
                &mut stream_acc,
            )?;
        }
        folder_base.push(bases);
    }
    if !pending.is_empty() {
        return Err(Error::InvalidData("mscab: truncated split CFDATA"));
    }

    // Files continued from a previous cabinet are already emitted by
    // the earlier member's split entry; skip their duplicate records.
    let mut seen: Vec<(String, usize)> = Vec::new();
    let mut entries = Vec::new();
    for (k, cab) in cabs.iter().enumerate() {
        for f in &cab.files {
            match f.i_folder {
                IFOLD_CONTINUED_FROM_PREV | IFOLD_CONTINUED_PREV_AND_NEXT => {
                    if seen.iter().any(|(n, c)| n == &f.name && *c == f.cb_file) {
                        continue;
                    }
                    return Err(Error::Unsupported(
                        "mscab: file begins in a missing earlier cabinet",
                    ));
                }
                ifolder => {
                    if !multi && ifolder >= 0xfffd {
                        return Err(Error::Unsupported(
                            "mscab: multi-cabinet file spanning is not supported",
                        ));
                    }
                    let frag = if ifolder == IFOLD_CONTINUED_TO_NEXT {
                        // §2.3: index is actually cFolders - 1.
                        if cab.folders.is_empty() {
                            return Err(Error::InvalidData("mscab: split file without folder"));
                        }
                        cab.folders.len() - 1
                    } else {
                        ifolder
                    };
                    if f.cb_file == 0 {
                        entries.push(MscabEntry {
                            name: f.name.clone(),
                            data: Vec::new(),
                        });
                        seen.push((f.name.clone(), 0));
                        continue;
                    }
                    let base = folder_base[k]
                        .get(frag)
                        .ok_or(Error::InvalidData("mscab: folder index out of range"))?;
                    let pos = base + f.uoff_folder_start;
                    let end = pos + f.cb_file;
                    if end > stream.len() {
                        return Err(Error::InvalidData("mscab: file data overruns folders"));
                    }
                    entries.push(MscabEntry {
                        name: f.name.clone(),
                        data: stream[pos..end].to_vec(),
                    });
                    seen.push((f.name.clone(), f.cb_file));
                }
            }
        }
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
        /// Per-block cbUncomp overrides for LZX folders, keyed by folder
        /// index (compressed and uncompressed sizes differ there).
        uncomp_overrides: Vec<(usize, Vec<u16>)>,
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
                uncomp_overrides: Vec::new(),
            }
        }

        /// Push an LZX/Quantum folder; `uncomps` carries each CFDATA
        /// block's cbUncomp (compressed payloads say nothing about it).
        fn push_lzx(&mut self, type_compress: u16, blocks: Vec<Vec<u8>>, uncomps: Vec<u16>) {
            self.uncomp_overrides.push((self.folders.len(), uncomps));
            self.folders.push((type_compress, blocks));
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
                for (j, b) in cfdatas[i].iter().enumerate() {
                    let uncomp = if *ty == COMPRESS_MSZIP {
                        let dict_start = history.len().saturating_sub(MSZIP_WINDOW);
                        let decoded =
                            deflate::decode::decode_with_dict(&b[2..], &history[dict_start..])
                                .unwrap();
                        history.extend_from_slice(&decoded);
                        decoded.len()
                    } else if let Some(v) = self
                        .uncomp_overrides
                        .iter()
                        .find(|(idx, _)| *idx == i)
                        .and_then(|(_, v)| v.get(j))
                    {
                        *v as usize
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
    fn decodes_quantum_folder() {
        // Real Quantum stream (libmspack qtm.txt fixture), window 18.
        let qtm: &[u8] = &[
            0xD6, 0x06, 0x69, 0x0B, 0xCB, 0x47, 0xF0, 0x2C, 0x2A, 0x3A, 0x8F, 0x2C, 0xAB, 0xBB,
            0x3C, 0xB9, 0x33, 0x01, 0x8B, 0xD8, 0x58, 0x4B, 0x7B, 0x01, 0xBA, 0x6F, 0x6D, 0x51,
            0x6E, 0x3A, 0xC3, 0x67, 0x42, 0x4B, 0xEB, 0x02, 0x36, 0x43, 0xD6, 0x66, 0x56, 0xCA,
            0x9E, 0x72, 0xCC, 0x30, 0x00, 0x00,
        ];
        const EXPECTED: &[u8] = b"If you can read this, the Quantum decompressor is working!\n";
        let mut b = CabBuilder::new();
        // typeCompress = QUANTUM | (window_bits << 8) = 2 | 18<<8.
        b.push_lzx(0x1202, vec![qtm.to_vec()], vec![EXPECTED.len() as u16]);
        b.files.push((EXPECTED.len(), 0, 0, "qtm.txt".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].name(), "qtm.txt");
        assert_eq!(entries[0].data(), EXPECTED);
    }

    #[test]
    fn rejects_unknown_folder_compression() {
        let mut b = CabBuilder::new();
        b.folders.push((7, vec![b"x".to_vec()])); // invalid typeCompress
        b.files.push((1, 0, 0, "f".into()));
        let e = decode(&b.build()).unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)));
    }

    #[test]
    fn rejects_bad_quantum_window_bits() {
        let mut b = CabBuilder::new();
        // window_bits 22 is outside Quantum's 10..=21 range.
        b.push_lzx(2 | (22 << 8), vec![b"xx".to_vec()], vec![1]);
        b.files.push((1, 0, 0, "f".into()));
        let e = decode(&b.build()).unwrap_err();
        assert!(matches!(e, Error::InvalidData(_)));
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

    /// Build a two-cabinet set: `first` carries folder data + file
    /// records for `a` and `b` (b split to next), `second` carries the
    /// continuation fragment + the continued record for `b`.
    fn split_cab_set() -> (Vec<u8>, Vec<u8>) {
        let mut first = CabBuilder::new();
        first.set_id = 7;
        first.i_cabinet = 0;
        first.flags = FLAG_NEXT_CABINET;
        first
            .folders
            .push((COMPRESS_NONE, vec![b"AAAABBBB".to_vec()]));
        first.files.push((4, 0, 0, "a.txt".into()));
        first.files.push((8, 4, 0xfffe, "b.txt".into()));
        let cab0 = first.build();

        let mut second = CabBuilder::new();
        second.set_id = 7;
        second.i_cabinet = 1;
        second.flags = FLAG_PREV_CABINET;
        second.folders.push((COMPRESS_NONE, vec![b"CCCC".to_vec()]));
        second.files.push((8, 4, 0xfffd, "b.txt".into()));
        let cab1 = second.build();
        (cab0, cab1)
    }

    #[test]
    fn decode_parts_split_file() {
        let (cab0, cab1) = split_cab_set();
        let entries = decode_parts(&[&cab0, &cab1]).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "a.txt");
        assert_eq!(entries[0].data(), b"AAAA");
        assert_eq!(entries[1].name(), "b.txt");
        assert_eq!(entries[1].data(), b"BBBBCCCC");
        // The first member alone still reports spanning as unsupported.
        assert!(matches!(decode(&cab0), Err(Error::Unsupported(_))));
    }

    #[test]
    fn decode_parts_set_id_mismatch() {
        let (cab0, mut cab1) = split_cab_set();
        // setID field sits at header offset 32.
        cab1[32..34].copy_from_slice(&9u16.to_le_bytes());
        assert!(matches!(
            decode_parts(&[&cab0, &cab1]),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn decode_parts_index_mismatch() {
        let (cab0, mut cab1) = split_cab_set();
        // iCabinet field sits at header offset 34.
        cab1[34..36].copy_from_slice(&5u16.to_le_bytes());
        assert!(matches!(
            decode_parts(&[&cab0, &cab1]),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn decode_parts_missing_earlier_member() {
        // A cabinet whose first file is a continuation but which is
        // supplied as member 0: the file's beginning is unavailable.
        let mut b = CabBuilder::new();
        b.flags = FLAG_PREV_CABINET;
        b.folders.push((COMPRESS_NONE, vec![b"tail".to_vec()]));
        b.files.push((9, 0, 0xfffd, "big.bin".into()));
        let cab = b.build();
        assert!(matches!(decode_parts(&[&cab]), Err(Error::Unsupported(_))));
    }

    /// Patch the `cbUncomp` field of folder `folder_idx`'s first
    /// CFDATA record in a built cabinet.
    fn patch_cbuncomp(cab: &mut [u8], folder_idx: usize, value: u16) {
        let flags = u16::from_le_bytes(cab[30..32].try_into().unwrap());
        let mut off = 36usize;
        if flags & FLAG_RESERVE_PRESENT != 0 {
            off += 4 + u16::from_le_bytes(cab[36..38].try_into().unwrap()) as usize;
        }
        for flag in [FLAG_PREV_CABINET, FLAG_NEXT_CABINET] {
            if flags & flag != 0 {
                for _ in 0..2 {
                    while cab[off] != 0 {
                        off += 1;
                    }
                    off += 1;
                }
            }
        }
        let coff = u32::from_le_bytes(
            cab[off + folder_idx * 8..off + folder_idx * 8 + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        cab[coff + 6..coff + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn decode_parts_cfdata_block_split() {
        // A CFDATA record itself split across the boundary: the first
        // member's block reports cbUncomp == 0 and the next member's
        // first CFDATA reports the total (MS-CAB §2.4).
        let mut first = CabBuilder::new();
        first.i_cabinet = 0;
        first.flags = FLAG_NEXT_CABINET;
        first
            .folders
            .push((COMPRESS_NONE, vec![b"AAAA012345".to_vec()]));
        first.files.push((4, 0, 0, "a.txt".into()));
        first.files.push((10, 4, 0xfffe, "b.txt".into()));
        let mut cab0 = first.build();

        let mut second = CabBuilder::new();
        second.i_cabinet = 1;
        second.flags = FLAG_PREV_CABINET;
        second.folders.push((COMPRESS_NONE, vec![b"6789".to_vec()]));
        second.files.push((10, 4, 0xfffd, "b.txt".into()));
        let mut cab1 = second.build();

        patch_cbuncomp(&mut cab0, 0, 0);
        patch_cbuncomp(&mut cab1, 0, 14);

        let entries = decode_parts(&[&cab0, &cab1]).unwrap();
        assert_eq!(entries[0].data(), b"AAAA");
        assert_eq!(entries[1].data(), b"0123456789");
    }

    #[test]
    fn decode_parts_rejects_empty() {
        assert!(matches!(decode_parts(&[]), Err(Error::InvalidData(_))));
        assert!(matches!(
            decode_parts(&[&[0x4d; 4], &[]]),
            Err(Error::InvalidData(_))
        ));
        // A lone member parses exactly like decode().
        let (cab0, _) = split_cab_set();
        let via_decode = decode(&cab0);
        let via_parts = decode_parts(&[&cab0]);
        assert_eq!(via_decode.is_err(), via_parts.is_err());
    }

    #[test]
    fn decode_parts_three_member_chain() {
        // Middle member is a pure continuation fragment: cFolders=1
        // and only CONTINUED records, chained prev+next (0xFFFF).
        let mut first = CabBuilder::new();
        first.set_id = 3;
        first.i_cabinet = 0;
        first.flags = FLAG_NEXT_CABINET;
        first.folders.push((COMPRESS_NONE, vec![b"head".to_vec()]));
        first.files.push((12, 0, 0xfffe, "big.bin".into()));

        let mut middle = CabBuilder::new();
        middle.set_id = 3;
        middle.i_cabinet = 1;
        middle.flags = FLAG_PREV_CABINET | FLAG_NEXT_CABINET;
        middle.folders.push((COMPRESS_NONE, vec![b"body".to_vec()]));
        middle.files.push((12, 0, 0xffff, "big.bin".into()));

        let mut last = CabBuilder::new();
        last.set_id = 3;
        last.i_cabinet = 2;
        last.flags = FLAG_PREV_CABINET;
        last.folders.push((COMPRESS_NONE, vec![b"tail".to_vec()]));
        last.files.push((12, 0, 0xfffd, "big.bin".into()));

        let (c0, c1, c2) = (first.build(), middle.build(), last.build());
        let entries = decode_parts(&[&c0, &c1, &c2]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data(), b"headbodytail");
    }

    #[test]
    fn decode_parts_continued_type_mismatch() {
        // A continuation fragment must keep the original folder's
        // compression type (MS-CAB §2.2).
        let mut first = CabBuilder::new();
        first.i_cabinet = 0;
        first.flags = FLAG_NEXT_CABINET;
        first.folders.push((COMPRESS_NONE, vec![b"head".to_vec()]));
        first.files.push((8, 0, 0xfffe, "x.bin".into()));

        let mut second = CabBuilder::new();
        second.i_cabinet = 1;
        second.flags = FLAG_PREV_CABINET;
        // Continuation fragment wrongly claims MSZIP (the payload
        // itself is a valid block so the type check is what fails).
        let tail = deflate::encode::encode(b"tail", deflate::encode::Level::Default);
        second.folders.push((COMPRESS_MSZIP, vec![tail]));
        second.files.push((8, 0, 0xfffd, "x.bin".into()));

        let (c0, c1) = (first.build(), second.build());
        assert!(matches!(
            decode_parts(&[&c0, &c1]),
            Err(Error::InvalidData(_))
        ));
    }
    /// Build a small cabinet LZX (typeCompress 0x0f03, 32 KiB window)
    /// verbatim-block stream for the given data.
    fn lzx_stream(data: &[u8]) -> Vec<u8> {
        lzx_stream_window(data, 1 << 15)
    }

    /// LZX stream for data at the given window size (the main tree's
    /// element count depends on the position-slot count, which grows
    /// with the window, so the encoding must match the decode window).
    fn lzx_stream_window(data: &[u8], window: usize) -> Vec<u8> {
        use crate::compress::lzx::cabtest::{Elem, Enc, nslots, trees_for};
        let mut lits: Vec<usize> = data.iter().map(|&b| b as usize).collect();
        lits.sort();
        lits.dedup();
        let trees = trees_for(&lits, &[], &[], &[], nslots(window));
        let mut e = Enc::new(window, None);
        let elems: Vec<Elem> = data.iter().map(|&b| Elem::Lit(b)).collect();
        e.compressed(false, data.len() as u32, &trees, &elems);
        e.finish()
    }

    const LZX_TC_32K: u16 = (15 << 8) | COMPRESS_LZX;

    #[test]
    fn parses_lzx_cabinet() {
        let data = b"hello lzx cabinet";
        let mut b = CabBuilder::new();
        b.push_lzx(LZX_TC_32K, vec![lzx_stream(data)], vec![data.len() as u16]);
        b.files.push((data.len(), 0, 0, "lzx.txt".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "lzx.txt");
        assert_eq!(entries[0].data(), data.as_slice());
    }

    #[test]
    fn lzx_stream_spans_cfdata_blocks() {
        // The LZX bitstream is contiguous across CFDATA records: split
        // the compressed bytes at arbitrary positions; only the sum of
        // cbUncomp matters.
        let stream = lzx_stream(b"bitstream crosses record boundaries");
        let total = 35u16;
        let mid1 = stream.len() / 3;
        let mid2 = 2 * stream.len() / 3;
        let blocks = vec![
            stream[..mid1].to_vec(),
            stream[mid1..mid2].to_vec(),
            stream[mid2..].to_vec(),
        ];
        let mut b = CabBuilder::new();
        b.push_lzx(LZX_TC_32K, blocks, vec![10, 10, total - 20]);
        b.files.push((total as usize, 0, 0, "x.bin".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data(), b"bitstream crosses record boundaries");
    }

    #[test]
    fn lzx_uncompressed_block_cabinet() {
        let data = b"stored through an LZX uncompressed block!";
        let mut e = crate::compress::lzx::cabtest::Enc::new(1 << 15, None);
        e.uncompressed(data, [1, 1, 1]);
        let stream = e.finish();
        let mut b = CabBuilder::new();
        b.push_lzx(LZX_TC_32K, vec![stream], vec![data.len() as u16]);
        b.files.push((data.len(), 0, 0, "raw.bin".into()));
        let entries = decode(&b.build()).unwrap();
        assert_eq!(entries[0].data(), data.as_slice());
    }

    #[test]
    fn lzx_window_size_bits() {
        let data = b"window bits check";
        for bits in [15u16, 18, 21] {
            let stream = lzx_stream_window(data, 1usize << bits);
            let mut b = CabBuilder::new();
            b.push_lzx((bits << 8) | COMPRESS_LZX, vec![stream.clone()], vec![17]);
            b.files.push((17, 0, 0, "w.bin".into()));
            let entries = decode(&b.build()).unwrap();
            assert_eq!(entries[0].data(), data.as_slice());
        }
    }

    #[test]
    fn rejects_lzx_bad_window_bits() {
        let stream = lzx_stream(b"xx");
        for bits in [0u16, 14, 22, 31] {
            let mut b = CabBuilder::new();
            b.push_lzx((bits << 8) | COMPRESS_LZX, vec![stream.clone()], vec![2]);
            b.files.push((2, 0, 0, "w.bin".into()));
            assert!(matches!(decode(&b.build()), Err(Error::InvalidData(_))));
        }
    }

    #[test]
    fn decode_parts_lzx_folder_continues() {
        // An LZX logical folder whose CFDATA block is split across two
        // cabinet members: the compressed stream is contiguous.
        let data = b"lzx folder split across cabinet members";
        let stream = lzx_stream(data);
        let cut = stream.len() / 2;

        let mut first = CabBuilder::new();
        first.i_cabinet = 0;
        first.flags = FLAG_NEXT_CABINET;
        first.push_lzx(LZX_TC_32K, vec![stream[..cut].to_vec()], vec![0]);
        first.files.push((data.len(), 0, 0xfffe, "big.bin".into()));

        let mut second = CabBuilder::new();
        second.i_cabinet = 1;
        second.flags = FLAG_PREV_CABINET;
        second.push_lzx(
            LZX_TC_32K,
            vec![stream[cut..].to_vec()],
            vec![data.len() as u16],
        );
        second.files.push((data.len(), 0, 0xfffd, "big.bin".into()));

        let (c0, c1) = (first.build(), second.build());
        let entries = decode_parts(&[&c0, &c1]).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].data(), data.as_slice());
    }
}
