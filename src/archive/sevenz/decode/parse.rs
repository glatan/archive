//! Internal 7z header parsing: structures, cursor, and all `parse_*` functions.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;

use super::{
    NID_ANTI, NID_ATIME, NID_COMMENT, NID_CRC, NID_CTIME, NID_DUMMY, NID_EMPTY_FILE,
    NID_EMPTY_STREAM, NID_END, NID_MTIME, NID_NAME, NID_NUM_UNPACK_STREAM, NID_SIZE, NID_START_POS,
    NID_WIN_ATTRIBUTES,
};

use super::graph::folder_total_final_unpack_size;

#[derive(Debug, Clone)]
pub(super) struct ArchiveMetadata {
    pub(super) files: Vec<FileEntry>,
    pub(super) main_streams: Option<StreamsInfo>,
}

#[derive(Debug, Clone)]
pub(super) struct FileEntry {
    pub(super) name: String,
    pub(super) attributes: Option<u32>,
    pub(super) ctime: Option<u64>,
    pub(super) atime: Option<u64>,
    pub(super) mtime: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct StreamsInfo {
    pub(super) pack_pos: u64,
    pub(super) pack_sizes: Vec<u64>,
    pub(super) pack_crcs: Vec<Option<u32>>,
    pub(super) folders: Vec<Folder>,
    pub(super) substreams: Vec<Vec<Substream>>,
}

#[derive(Debug, Clone)]
pub(super) struct Substream {
    pub(super) unpack_size: u64,
    pub(super) crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct Folder {
    pub(super) coders: Vec<Coder>,
    pub(super) bind_pairs: Vec<BindPair>,
    pub(super) packed_streams: Vec<u64>,
    pub(super) unpack_sizes: Vec<u64>,
    pub(super) crc32: Option<u32>,
}

#[derive(Debug, Clone)]
pub(super) struct Coder {
    pub(super) method_id: Vec<u8>,
    pub(super) properties: Vec<u8>,
    pub(super) num_in_streams: u64,
    pub(super) num_out_streams: u64,
    pub(super) input_index: u64,
    pub(super) output_index: u64,
}

#[derive(Debug, Clone)]
pub(super) struct BindPair {
    pub(super) in_index: u64,
    pub(super) out_index: u64,
}

#[derive(Clone, Copy)]
pub(super) struct Cursor<'a> {
    pub(super) data: &'a [u8],
    pub(super) pos: usize,
}

impl<'a> Cursor<'a> {
    pub(super) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(super) fn read_byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let byte = self.data[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    pub(super) fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(Error::UnexpectedEof);
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    pub(super) fn read_u32_le(&mut self) -> Result<u32, Error> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a 7z UINT64. The number of leading 1-bits in the first byte counts
    /// the extension bytes; the remaining low bits of the first byte hold the
    /// most-significant part of the value, and the extension bytes store the
    /// rest in little-endian order (least-significant byte first).
    pub(super) fn read_uint64(&mut self) -> Result<u64, Error> {
        let first = self.read_byte()?;
        let mut mask = 0x80u8;
        let mut value = 0u64;
        for extra in 0..8u32 {
            if first & mask == 0 {
                value |= u64::from(first & (mask - 1)) << (8 * extra);
                return Ok(value);
            }
            value |= u64::from(self.read_byte()?) << (8 * extra);
            mask >>= 1;
        }
        Ok(value)
    }

    pub(super) const fn is_eof(&self) -> bool {
        self.pos == self.data.len()
    }

    pub(super) const fn consume_remaining(&mut self) {
        self.pos = self.data.len();
    }
}

pub(super) fn parse_header(cursor: &mut Cursor<'_>) -> Result<ArchiveMetadata, Error> {
    let mut main_streams = None;
    let mut files = Vec::new();

    loop {
        let nid = cursor.read_byte()?;
        match nid {
            NID_END => break,
            super::NID_ARCHIVE_PROPERTIES => skip_archive_properties(cursor)?,
            super::NID_ADDITIONAL_STREAMS_INFO => {
                let _ = parse_streams_info(cursor)?;
            }
            super::NID_MAIN_STREAMS_INFO => {
                main_streams = Some(parse_streams_info(cursor)?);
            }
            super::NID_FILES_INFO => {
                files = parse_files_info(cursor)?;
            }
            _ => return Err(Error::Unsupported("7z: unsupported header property")),
        }
    }

    Ok(ArchiveMetadata {
        files,
        main_streams,
    })
}

fn skip_archive_properties(cursor: &mut Cursor<'_>) -> Result<(), Error> {
    loop {
        let property = cursor.read_byte()?;
        if property == NID_END {
            return Ok(());
        }
        let size = cursor.read_uint64()? as usize;
        cursor.read_bytes(size)?;
    }
}

pub(super) fn parse_streams_info(cursor: &mut Cursor<'_>) -> Result<StreamsInfo, Error> {
    let mut streams = StreamsInfo::default();
    let mut saw_unpack = false;
    let mut saw_substreams = false;

    loop {
        let nid = cursor.read_byte()?;
        match nid {
            NID_END => break,
            super::NID_PACK_INFO => parse_pack_info(cursor, &mut streams)?,
            super::NID_UNPACK_INFO => {
                parse_unpack_info(cursor, &mut streams)?;
                saw_unpack = true;
            }
            super::NID_SUBSTREAMS_INFO => {
                parse_substreams_info(cursor, &mut streams)?;
                saw_substreams = true;
            }
            _ => return Err(Error::Unsupported("7z: unsupported streams info property")),
        }
    }

    if !saw_unpack {
        if !streams.pack_sizes.is_empty() {
            return Err(Error::InvalidData("7z: pack info without unpack info"));
        }
        return Ok(streams);
    }

    if !saw_substreams {
        streams.substreams = streams
            .folders
            .iter()
            .map(|folder| {
                let unpack_size = folder_total_final_unpack_size(folder)?;
                Ok(vec![Substream {
                    unpack_size,
                    crc32: folder.crc32,
                }])
            })
            .collect::<Result<Vec<_>, Error>>()?;
    }

    Ok(streams)
}

fn parse_pack_info(cursor: &mut Cursor<'_>, streams: &mut StreamsInfo) -> Result<(), Error> {
    streams.pack_pos = cursor.read_uint64()?;
    let num_pack_streams = cursor.read_uint64()? as usize;

    let mut pack_sizes = None;
    let mut pack_crcs = None;

    loop {
        let nid = cursor.read_byte()?;
        match nid {
            NID_END => break,
            NID_SIZE => {
                let mut sizes = Vec::with_capacity(num_pack_streams);
                for _ in 0..num_pack_streams {
                    sizes.push(cursor.read_uint64()?);
                }
                pack_sizes = Some(sizes);
            }
            NID_CRC => {
                pack_crcs = Some(parse_digests(cursor, num_pack_streams)?);
            }
            _ => return Err(Error::Unsupported("7z: unsupported pack info property")),
        }
    }

    streams.pack_sizes = pack_sizes.ok_or(Error::InvalidData("7z: missing pack sizes"))?;
    streams.pack_crcs = pack_crcs.unwrap_or_else(|| vec![None; num_pack_streams]);
    Ok(())
}

pub(super) fn parse_unpack_info(
    cursor: &mut Cursor<'_>,
    streams: &mut StreamsInfo,
) -> Result<(), Error> {
    if cursor.read_byte()? != super::NID_FOLDER {
        return Err(Error::InvalidData("7z: expected folder list"));
    }
    let num_folders = cursor.read_uint64()? as usize;
    if cursor.read_byte()? != 0 {
        return Err(Error::Unsupported(
            "7z: external folder lists are not supported",
        ));
    }

    let mut folders = Vec::with_capacity(num_folders);
    for _ in 0..num_folders {
        folders.push(parse_folder(cursor)?);
    }

    if cursor.read_byte()? != super::NID_CODERS_UNPACK_SIZE {
        return Err(Error::InvalidData("7z: missing folder unpack sizes"));
    }
    for folder in &mut folders {
        let outputs = folder.total_out_streams()? as usize;
        folder.unpack_sizes = Vec::with_capacity(outputs);
        for _ in 0..outputs {
            folder.unpack_sizes.push(cursor.read_uint64()?);
        }
    }

    let next = cursor.read_byte()?;
    match next {
        NID_CRC => {
            let digests = parse_digests(cursor, num_folders)?;
            for (folder, digest) in folders.iter_mut().zip(digests) {
                folder.crc32 = digest;
            }
            if cursor.read_byte()? != NID_END {
                return Err(Error::InvalidData("7z: expected end after folder digests"));
            }
        }
        NID_END => {}
        _ => return Err(Error::Unsupported("7z: unsupported unpack info property")),
    }

    streams.folders = folders;
    Ok(())
}

fn parse_folder(cursor: &mut Cursor<'_>) -> Result<Folder, Error> {
    let num_coders = cursor.read_uint64()? as usize;
    let mut coders = Vec::with_capacity(num_coders);
    let mut total_in = 0u64;
    let mut total_out = 0u64;

    for _ in 0..num_coders {
        let flags = cursor.read_byte()?;
        if flags & 0x80 != 0 || flags & 0x40 != 0 {
            return Err(Error::Unsupported(
                "7z: alternative or reserved coder flags are not supported",
            ));
        }
        let method_len = (flags & 0x0F) as usize;
        if method_len == 0 {
            return Err(Error::InvalidData("7z: coder id length must be non-zero"));
        }
        let method_id = cursor.read_bytes(method_len)?.to_vec();
        let is_complex = flags & 0x10 != 0;
        let has_properties = flags & 0x20 != 0;
        let num_in_streams = if is_complex { cursor.read_uint64()? } else { 1 };
        let num_out_streams = if is_complex { cursor.read_uint64()? } else { 1 };
        let properties = if has_properties {
            let len = cursor.read_uint64()? as usize;
            cursor.read_bytes(len)?.to_vec()
        } else {
            Vec::new()
        };
        coders.push(Coder {
            method_id,
            properties,
            num_in_streams,
            num_out_streams,
            input_index: total_in,
            output_index: total_out,
        });
        total_in += num_in_streams;
        total_out += num_out_streams;
    }

    if total_out == 0 {
        return Err(Error::InvalidData("7z: folder has no output streams"));
    }
    let num_bind_pairs = total_out
        .checked_sub(1)
        .ok_or(Error::InvalidData("7z: invalid bind pair count"))?
        as usize;
    let mut bind_pairs = Vec::with_capacity(num_bind_pairs);
    for _ in 0..num_bind_pairs {
        bind_pairs.push(BindPair {
            in_index: cursor.read_uint64()?,
            out_index: cursor.read_uint64()?,
        });
    }

    let num_packed_streams = total_in
        .checked_sub(num_bind_pairs as u64)
        .ok_or(Error::InvalidData("7z: invalid packed stream count"))?
        as usize;
    let packed_streams = if num_packed_streams == 1 {
        let mut bound_inputs = vec![false; total_in as usize];
        for bind_pair in &bind_pairs {
            let index = bind_pair.in_index as usize;
            if index >= bound_inputs.len() {
                return Err(Error::InvalidData("7z: bind pair input out of range"));
            }
            bound_inputs[index] = true;
        }
        let packed = bound_inputs
            .iter()
            .position(|bound| !bound)
            .ok_or(Error::InvalidData("7z: missing packed stream"))?;
        vec![packed as u64]
    } else {
        let mut packed = Vec::with_capacity(num_packed_streams);
        for _ in 0..num_packed_streams {
            packed.push(cursor.read_uint64()?);
        }
        packed
    };

    Ok(Folder {
        coders,
        bind_pairs,
        packed_streams,
        unpack_sizes: Vec::new(),
        crc32: None,
    })
}

fn parse_substreams_info(cursor: &mut Cursor<'_>, streams: &mut StreamsInfo) -> Result<(), Error> {
    let num_folders = streams.folders.len();
    let mut counts = vec![1usize; num_folders];
    let mut explicit_sizes = Vec::new();
    let mut explicit_crcs = None;

    loop {
        let nid = cursor.read_byte()?;
        match nid {
            NID_END => break,
            NID_NUM_UNPACK_STREAM => {
                for count in &mut counts {
                    *count = cursor.read_uint64()? as usize;
                }
            }
            NID_SIZE => {
                for (folder, &count) in streams.folders.iter().zip(&counts) {
                    if count == 0 {
                        return Err(Error::InvalidData("7z: folder has zero substreams"));
                    }
                    for _ in 0..count.saturating_sub(1) {
                        explicit_sizes.push(cursor.read_uint64()?);
                    }
                    if count == 1 && folder.unpack_sizes.is_empty() {
                        return Err(Error::InvalidData("7z: folder missing unpack size"));
                    }
                }
            }
            NID_CRC => {
                let unknown_crc_count = streams
                    .folders
                    .iter()
                    .zip(&counts)
                    .map(|(folder, &count)| {
                        if count == 1 && folder.crc32.is_some() {
                            0
                        } else {
                            count
                        }
                    })
                    .sum();
                explicit_crcs = Some(parse_digests(cursor, unknown_crc_count)?);
            }
            _ => return Err(Error::Unsupported("7z: unsupported substreams property")),
        }
    }

    let mut size_index = 0usize;
    let mut crc_index = 0usize;
    let mut folders = Vec::with_capacity(num_folders);
    let crcs = explicit_crcs.unwrap_or_default();

    for (folder, &count) in streams.folders.iter().zip(&counts) {
        let total_size = folder_total_final_unpack_size(folder)?;
        let mut folder_substreams = Vec::with_capacity(count);
        let mut assigned = 0u64;
        for _ in 0..count.saturating_sub(1) {
            let size = *explicit_sizes
                .get(size_index)
                .ok_or(Error::InvalidData("7z: substream size count mismatch"))?;
            size_index += 1;
            assigned = assigned
                .checked_add(size)
                .ok_or(Error::InvalidData("7z: substream size overflow"))?;
            folder_substreams.push(Substream {
                unpack_size: size,
                crc32: None,
            });
        }
        if assigned > total_size {
            return Err(Error::InvalidData("7z: substream sizes exceed folder size"));
        }
        folder_substreams.push(Substream {
            unpack_size: total_size - assigned,
            crc32: None,
        });

        if count == 1 && folder.crc32.is_some() {
            folder_substreams[0].crc32 = folder.crc32;
        } else {
            for substream in &mut folder_substreams {
                substream.crc32 = crcs.get(crc_index).copied().flatten();
                crc_index += 1;
            }
        }
        folders.push(folder_substreams);
    }

    if size_index != explicit_sizes.len() {
        return Err(Error::InvalidData("7z: unused substream sizes"));
    }
    if crc_index != crcs.len() {
        return Err(Error::InvalidData("7z: unused substream CRCs"));
    }

    streams.substreams = folders;
    Ok(())
}

pub(super) fn parse_digests(
    cursor: &mut Cursor<'_>,
    count: usize,
) -> Result<Vec<Option<u32>>, Error> {
    let all_defined = cursor.read_byte()?;
    let defined = if all_defined == 0 {
        read_bitset(cursor, count)?
    } else {
        vec![true; count]
    };

    let mut digests = Vec::with_capacity(count);
    for is_defined in defined {
        if is_defined {
            digests.push(Some(cursor.read_u32_le()?));
        } else {
            digests.push(None);
        }
    }
    Ok(digests)
}

pub(super) fn parse_files_info(cursor: &mut Cursor<'_>) -> Result<Vec<FileEntry>, Error> {
    let num_files = cursor.read_uint64()? as usize;
    let mut names = vec![String::new(); num_files];
    let mut attributes = vec![None; num_files];
    let mut ctimes = vec![None; num_files];
    let mut atimes = vec![None; num_files];
    let mut mtimes = vec![None; num_files];
    let mut empty_streams = vec![false; num_files];
    let mut empty_files_count = 0usize;

    loop {
        let property = cursor.read_byte()?;
        if property == NID_END {
            break;
        }
        let size = cursor.read_uint64()? as usize;
        let data = cursor.read_bytes(size)?;
        let mut prop_cursor = Cursor::new(data);
        match property {
            NID_EMPTY_STREAM => {
                empty_streams = read_bitset(&mut prop_cursor, num_files)?;
                empty_files_count = empty_streams.iter().filter(|empty| **empty).count();
            }
            NID_EMPTY_FILE => {
                let flags = read_bitset(&mut prop_cursor, empty_files_count)?;
                if flags.iter().any(|is_file| !*is_file) {
                    return Err(Error::Unsupported(
                        "7z: directory entries are not supported",
                    ));
                }
            }
            NID_ANTI => {
                let flags = read_bitset(&mut prop_cursor, empty_files_count)?;
                if flags.iter().any(|flag| *flag) {
                    return Err(Error::Unsupported("7z: anti-items are not supported"));
                }
            }
            NID_NAME => parse_names_property(&mut prop_cursor, &mut names)?,
            NID_CTIME => parse_filetime_property(&mut prop_cursor, &mut ctimes)?,
            NID_ATIME => parse_filetime_property(&mut prop_cursor, &mut atimes)?,
            NID_MTIME => parse_filetime_property(&mut prop_cursor, &mut mtimes)?,
            NID_COMMENT | NID_START_POS | NID_DUMMY => prop_cursor.consume_remaining(),
            NID_WIN_ATTRIBUTES => parse_attributes_property(&mut prop_cursor, &mut attributes)?,
            _ => {}
        }
        if !prop_cursor.is_eof() {
            return Err(Error::InvalidData("7z: file property size mismatch"));
        }
    }

    if empty_streams.iter().any(|empty| *empty) {
        return Err(Error::Unsupported(
            "7z: empty-stream entries are not supported",
        ));
    }

    Ok(names
        .into_iter()
        .zip(attributes)
        .zip(ctimes)
        .zip(atimes)
        .zip(mtimes)
        .map(|((((name, attributes), ctime), atime), mtime)| FileEntry {
            name,
            attributes,
            ctime,
            atime,
            mtime,
        })
        .collect())
}

pub(super) fn parse_names_property(
    cursor: &mut Cursor<'_>,
    names: &mut [String],
) -> Result<(), Error> {
    if cursor.read_byte()? != 0 {
        return Err(Error::Unsupported(
            "7z: external name streams are not supported",
        ));
    }
    let mut units = Vec::new();
    for name in names {
        units.clear();
        loop {
            let bytes = cursor.read_bytes(2)?;
            let unit = u16::from_le_bytes([bytes[0], bytes[1]]);
            if unit == 0 {
                *name = String::from_utf16(&units)
                    .map_err(|_| Error::InvalidData("7z: invalid UTF-16 filename"))?;
                break;
            }
            units.push(unit);
        }
    }
    Ok(())
}

pub(super) fn parse_attributes_property(
    cursor: &mut Cursor<'_>,
    attributes: &mut [Option<u32>],
) -> Result<(), Error> {
    let all_defined = cursor.read_byte()?;
    let defined = if all_defined == 0 {
        read_bitset(cursor, attributes.len())?
    } else {
        vec![true; attributes.len()]
    };
    if cursor.read_byte()? != 0 {
        return Err(Error::Unsupported(
            "7z: external attributes are not supported",
        ));
    }
    for (slot, is_defined) in attributes.iter_mut().zip(defined) {
        if is_defined {
            *slot = Some(cursor.read_u32_le()?);
        }
    }
    Ok(())
}

fn parse_filetime_property(
    cursor: &mut Cursor<'_>,
    timestamps: &mut [Option<u64>],
) -> Result<(), Error> {
    let all_defined = cursor.read_byte()?;
    let defined = if all_defined == 0 {
        read_bitset(cursor, timestamps.len())?
    } else {
        vec![true; timestamps.len()]
    };
    if cursor.read_byte()? != 0 {
        return Err(Error::Unsupported(
            "7z: external timestamps are not supported",
        ));
    }
    for (slot, is_defined) in timestamps.iter_mut().zip(defined) {
        if is_defined {
            let bytes = cursor.read_bytes(8)?;
            *slot = Some(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]));
        }
    }
    Ok(())
}

pub(super) fn read_bitset(cursor: &mut Cursor<'_>, count: usize) -> Result<Vec<bool>, Error> {
    let bytes = count.div_ceil(8);
    let data = cursor.read_bytes(bytes)?;
    let mut result = Vec::with_capacity(count);
    for index in 0..count {
        let byte = data[index / 8];
        result.push(((byte >> (7 - (index % 8))) & 1) != 0);
    }
    Ok(result)
}

impl Folder {
    pub(super) fn total_in_streams(&self) -> Result<u64, Error> {
        self.coders.iter().try_fold(0u64, |acc, coder| {
            acc.checked_add(coder.num_in_streams)
                .ok_or(Error::InvalidData("7z: input stream count overflow"))
        })
    }

    pub(super) fn total_out_streams(&self) -> Result<u64, Error> {
        self.coders.iter().try_fold(0u64, |acc, coder| {
            acc.checked_add(coder.num_out_streams)
                .ok_or(Error::InvalidData("7z: output stream count overflow"))
        })
    }
}

pub(super) fn read_u32_le(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() != 4 {
        return Err(Error::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn read_u64_le(bytes: &[u8]) -> Result<u64, Error> {
    if bytes.len() != 8 {
        return Err(Error::UnexpectedEof);
    }
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
