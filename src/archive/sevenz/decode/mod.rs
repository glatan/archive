//! 7z archive decoding.

mod codecs;
mod graph;
mod parse;

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::crc32;

// Re-export pub(crate) items that the encoder module depends on.
pub(crate) use codecs::{derive_7z_aes_key, encode_password_utf16le, parse_7z_aes_properties};

use codecs::decode_folder;
use graph::folder_uses_encryption;
use parse::{
    ArchiveMetadata, Cursor, StreamsInfo, parse_header, parse_streams_info, read_u32_le,
    read_u64_le,
};

const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
const SIGNATURE_HEADER_SIZE: usize = 32;

const NID_END: u8 = 0x00;
const NID_HEADER: u8 = 0x01;
const NID_ARCHIVE_PROPERTIES: u8 = 0x02;
const NID_ADDITIONAL_STREAMS_INFO: u8 = 0x03;
const NID_MAIN_STREAMS_INFO: u8 = 0x04;
const NID_FILES_INFO: u8 = 0x05;
const NID_PACK_INFO: u8 = 0x06;
const NID_UNPACK_INFO: u8 = 0x07;
const NID_SUBSTREAMS_INFO: u8 = 0x08;
const NID_SIZE: u8 = 0x09;
const NID_CRC: u8 = 0x0A;
const NID_FOLDER: u8 = 0x0B;
const NID_CODERS_UNPACK_SIZE: u8 = 0x0C;
const NID_NUM_UNPACK_STREAM: u8 = 0x0D;
const NID_EMPTY_STREAM: u8 = 0x0E;
const NID_EMPTY_FILE: u8 = 0x0F;
const NID_ANTI: u8 = 0x10;
const NID_NAME: u8 = 0x11;
const NID_CTIME: u8 = 0x12;
const NID_ATIME: u8 = 0x13;
const NID_MTIME: u8 = 0x14;
const NID_WIN_ATTRIBUTES: u8 = 0x15;
const NID_COMMENT: u8 = 0x16;
const NID_ENCODED_HEADER: u8 = 0x17;
const NID_START_POS: u8 = 0x18;
const NID_DUMMY: u8 = 0x19;

const METHOD_COPY: &[u8] = &[0x00];
const METHOD_DELTA: &[u8] = &[0x03];
const METHOD_BCJ_X86: &[u8] = &[0x03, 0x03, 0x01, 0x03];
const METHOD_BCJ_POWERPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
const METHOD_BCJ_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
const METHOD_BCJ_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
const METHOD_BCJ_ARMTHUMB: &[u8] = &[0x03, 0x03, 0x07, 0x01];
const METHOD_BCJ_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
const METHOD_BCJ_ARM64: &[u8] = &[0x0A];
const METHOD_BCJ_RISCV: &[u8] = &[0x0B];
const METHOD_BCJ2_X86: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
const METHOD_7Z_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
const METHOD_LZMA2: &[u8] = &[0x21];
const METHOD_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const METHOD_BROTLI: &[u8] = &[0x04, 0xF7, 0x11, 0x01];

/// A single decoded 7z entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenZEntry {
    /// UTF-8 file name from the archive header.
    pub name: String,
    /// Decompressed file contents.
    pub data: Vec<u8>,
    /// Per-file CRC-32 when present.
    pub crc32: Option<u32>,
    /// Windows file attributes when present.
    pub attributes: Option<u32>,
    /// Creation time as Windows FILETIME (100-ns intervals since 1601-01-01).
    pub ctime: Option<u64>,
    /// Last access time as Windows FILETIME (100-ns intervals since 1601-01-01).
    pub atime: Option<u64>,
    /// Last modification time as Windows FILETIME (100-ns intervals since 1601-01-01).
    pub mtime: Option<u64>,
}

impl crate::traits::ArchiveEntry for SevenZEntry {
    fn name(&self) -> &str {
        &self.name
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Decode a 7z archive into memory.
pub fn decode(input: &[u8]) -> Result<Vec<SevenZEntry>, Error> {
    decode_impl(input, None)
}

/// Decode a 7z archive using a UTF-16LE password for encrypted folders.
pub fn decode_with_password(input: &[u8], password: &str) -> Result<Vec<SevenZEntry>, Error> {
    let password = encode_password_utf16le(password);
    decode_impl(input, Some(&password))
}

/// Decode a 7z archive using raw password bytes for encrypted folders.
pub fn decode_with_password_bytes(
    input: &[u8],
    password: &[u8],
) -> Result<Vec<SevenZEntry>, Error> {
    decode_impl(input, Some(password))
}

fn decode_impl(input: &[u8], password: Option<&[u8]>) -> Result<Vec<SevenZEntry>, Error> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.len() < SIGNATURE_HEADER_SIZE {
        return Err(Error::UnexpectedEof);
    }
    if input[..6] != SIGNATURE {
        return Err(Error::InvalidData("7z: invalid signature"));
    }
    if input[6] != 0 || input[7] != 4 {
        return Err(Error::Unsupported("7z: unsupported archive version"));
    }

    let start_header_crc = read_u32_le(&input[8..12])?;
    let start_header = &input[12..32];
    let actual_start_header_crc = crc32::crc32(start_header);
    if start_header_crc != actual_start_header_crc {
        return Err(Error::ChecksumMismatch {
            expected: start_header_crc,
            actual: actual_start_header_crc,
        });
    }

    let next_header_offset = read_u64_le(&input[12..20])? as usize;
    let next_header_size = read_u64_le(&input[20..28])? as usize;
    let next_header_crc = read_u32_le(&input[28..32])?;

    let next_header_start = SIGNATURE_HEADER_SIZE
        .checked_add(next_header_offset)
        .ok_or(Error::InvalidData("7z: next header offset overflow"))?;
    let next_header_end = next_header_start
        .checked_add(next_header_size)
        .ok_or(Error::InvalidData("7z: next header size overflow"))?;
    if next_header_end > input.len() {
        return Err(Error::UnexpectedEof);
    }

    let next_header = &input[next_header_start..next_header_end];
    let actual_next_header_crc = crc32::crc32(next_header);
    if next_header_crc != actual_next_header_crc {
        return Err(Error::ChecksumMismatch {
            expected: next_header_crc,
            actual: actual_next_header_crc,
        });
    }

    let metadata = parse_next_header(input, next_header, password)?;
    decode_entries(input, metadata, password)
}

fn parse_next_header(
    input: &[u8],
    next_header: &[u8],
    password: Option<&[u8]>,
) -> Result<ArchiveMetadata, Error> {
    let mut cursor = Cursor::new(next_header);
    match cursor.read_byte()? {
        NID_HEADER => parse_header(&mut cursor),
        NID_ENCODED_HEADER => {
            let header_streams = parse_streams_info(&mut cursor)?;
            if !cursor.is_eof() {
                return Err(Error::InvalidData("7z: trailing data after encoded header"));
            }
            let decoded = decode_streams_blob(input, &header_streams, password)?;
            let mut inner = Cursor::new(&decoded);
            if inner.read_byte()? != NID_HEADER {
                return Err(Error::InvalidData(
                    "7z: decoded header missing header marker",
                ));
            }
            parse_header(&mut inner)
        }
        _ => Err(Error::Unsupported("7z: unsupported next header type")),
    }
}

fn decode_entries(
    input: &[u8],
    metadata: ArchiveMetadata,
    password: Option<&[u8]>,
) -> Result<Vec<SevenZEntry>, Error> {
    if metadata.files.is_empty() {
        return Ok(Vec::new());
    }
    let streams = metadata
        .main_streams
        .ok_or(Error::InvalidData("7z: files present without stream info"))?;
    let total_substreams: usize = streams.substreams.iter().map(Vec::len).sum();
    if total_substreams != metadata.files.len() {
        return Err(Error::InvalidData("7z: file/substream count mismatch"));
    }

    let mut entries = Vec::with_capacity(metadata.files.len());
    let mut files = metadata.files.into_iter();

    for (folder_index, folder) in streams.folders.iter().enumerate() {
        if folder_uses_encryption(folder) && password.is_none() {
            return Err(Error::Unsupported(
                "7z: encrypted archive requires a password",
            ));
        }
        let packed = pack_stream_slices(input, &streams, folder_index)?;
        let unpacked = decode_folder(folder, &packed, password)?;
        if let Some(expected_crc) = folder.crc32 {
            let actual_crc = crc32::crc32(&unpacked);
            if actual_crc != expected_crc {
                return Err(Error::ChecksumMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                });
            }
        }

        let substreams = streams
            .substreams
            .get(folder_index)
            .ok_or(Error::InvalidData("7z: missing substream metadata"))?;
        let mut pos = 0usize;
        for substream in substreams {
            let file = files
                .next()
                .ok_or(Error::InvalidData("7z: file/substream count mismatch"))?;
            let end = pos
                .checked_add(substream.unpack_size as usize)
                .ok_or(Error::InvalidData("7z: substream size overflow"))?;
            if end > unpacked.len() {
                return Err(Error::UnexpectedEof);
            }
            let data = unpacked[pos..end].to_vec();
            pos = end;
            if let Some(expected_crc) = substream.crc32 {
                let actual_crc = crc32::crc32(&data);
                if actual_crc != expected_crc {
                    return Err(Error::ChecksumMismatch {
                        expected: expected_crc,
                        actual: actual_crc,
                    });
                }
            }
            entries.push(SevenZEntry {
                name: file.name,
                data,
                crc32: substream.crc32,
                attributes: file.attributes,
                ctime: file.ctime,
                atime: file.atime,
                mtime: file.mtime,
            });
        }
        if pos != unpacked.len() {
            return Err(Error::InvalidData("7z: unused unpacked bytes remain"));
        }
    }

    if files.next().is_some() {
        return Err(Error::InvalidData("7z: file/substream count mismatch"));
    }
    Ok(entries)
}

fn decode_streams_blob(
    input: &[u8],
    streams: &StreamsInfo,
    password: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    for folder_index in 0..streams.folders.len() {
        let folder = &streams.folders[folder_index];
        if folder_uses_encryption(folder) && password.is_none() {
            return Err(Error::Unsupported(
                "7z: encrypted archive requires a password",
            ));
        }
        let packed = pack_stream_slices(input, streams, folder_index)?;
        let folder_decoded = decode_folder(folder, &packed, password)?;
        if let Some(expected_crc) = folder.crc32 {
            let actual_crc = crc32::crc32(&folder_decoded);
            if actual_crc != expected_crc {
                return Err(Error::ChecksumMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                });
            }
        }
        decoded.extend_from_slice(&folder_decoded);
    }
    Ok(decoded)
}

fn pack_stream_slices<'a>(
    input: &'a [u8],
    streams: &StreamsInfo,
    folder_index: usize,
) -> Result<Vec<&'a [u8]>, Error> {
    let folder = streams
        .folders
        .get(folder_index)
        .ok_or(Error::InvalidData("7z: folder index out of range"))?;
    let first_pack_stream_index =
        streams
            .folders
            .iter()
            .take(folder_index)
            .try_fold(0usize, |acc, folder| {
                acc.checked_add(folder.packed_streams.len())
                    .ok_or(Error::InvalidData("7z: pack stream index overflow"))
            })?;
    let mut slices = Vec::with_capacity(folder.packed_streams.len());
    for local_index in 0..folder.packed_streams.len() {
        let pack_stream_index = first_pack_stream_index + local_index;
        let pack_offset =
            streams
                .pack_sizes
                .iter()
                .take(pack_stream_index)
                .try_fold(0usize, |acc, &size| {
                    acc.checked_add(size as usize)
                        .ok_or(Error::InvalidData("7z: pack offset overflow"))
                })?;
        let pack_start = SIGNATURE_HEADER_SIZE
            .checked_add(streams.pack_pos as usize)
            .and_then(|base| base.checked_add(pack_offset))
            .ok_or(Error::InvalidData("7z: pack position overflow"))?;
        let pack_size = *streams
            .pack_sizes
            .get(pack_stream_index)
            .ok_or(Error::InvalidData("7z: missing pack size"))? as usize;
        let pack_end = pack_start
            .checked_add(pack_size)
            .ok_or(Error::InvalidData("7z: pack size overflow"))?;
        if pack_end > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let packed = &input[pack_start..pack_end];
        if let Some(expected_crc) = streams.pack_crcs.get(pack_stream_index).copied().flatten() {
            let actual_crc = crc32::crc32(packed);
            if actual_crc != expected_crc {
                return Err(Error::ChecksumMismatch {
                    expected: expected_crc,
                    actual: actual_crc,
                });
            }
        }
        slices.push(packed);
    }
    Ok(slices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::sevenz::encode::{SevenZEncoder, SevenZFilter};
    use crate::compress::lzma::{self, LzmaProperties};
    use crate::util::aes256::Aes256;

    use super::codecs::decode_7z_aes;
    use super::graph::{InputSource, normalize_folder_graph};
    use super::parse::{
        BindPair, Coder, Cursor, Folder, StreamsInfo, parse_attributes_property, parse_files_info,
        parse_names_property, parse_unpack_info,
    };

    fn copy_coder(input_index: u64, output_index: u64) -> Coder {
        Coder {
            method_id: METHOD_COPY.to_vec(),
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
            input_index,
            output_index,
        }
    }

    fn encode_uint64_local(output: &mut Vec<u8>, value: u64) {
        for extra in 0..8u8 {
            let total_bits = 7 * (u32::from(extra) + 1);
            if extra < 8 && value < (1u64 << total_bits) {
                let prefix = if extra == 0 {
                    0
                } else {
                    (((1u16 << extra) - 1) << (8 - extra)) as u8
                };
                let mask = if extra == 0 {
                    0x7F
                } else if extra == 7 {
                    0
                } else {
                    ((1u16 << (7 - extra)) - 1) as u8
                };
                let high_bits = (value >> (u32::from(extra) * 8)) as u8 & mask;
                output.push(prefix | high_bits);
                for shift in (0..usize::from(extra)).rev() {
                    output.push((value >> (shift * 8)) as u8);
                }
                return;
            }
        }
        output.push(0xFF);
        for shift in (0..8).rev() {
            output.push((value >> (shift * 8)) as u8);
        }
    }

    #[test]
    fn test_uint64_roundtrip() {
        let values = [
            0,
            1,
            0x7F,
            0x80,
            0x1234,
            0x1F_FFFF,
            0x01_02_03_04_05_06_07_08,
        ];
        for value in values {
            let mut encoded = Vec::new();
            encode_uint64_local(&mut encoded, value);
            let mut cursor = Cursor::new(&encoded);
            assert_eq!(cursor.read_uint64().unwrap(), value, "value {value:#x}");
            assert!(cursor.is_eof());
        }
    }

    #[test]
    fn test_parse_unpack_info_rejects_external_folder_lists() {
        let mut bytes = Vec::new();
        bytes.push(NID_FOLDER);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(1);

        let mut streams = StreamsInfo {
            pack_pos: 0,
            pack_sizes: Vec::new(),
            pack_crcs: Vec::new(),
            folders: Vec::new(),
            substreams: Vec::new(),
        };
        let mut cursor = Cursor::new(&bytes);
        assert_eq!(
            parse_unpack_info(&mut cursor, &mut streams),
            Err(Error::Unsupported(
                "7z: external folder lists are not supported"
            ))
        );
    }

    #[test]
    fn test_parse_files_info_rejects_empty_stream_entries() {
        let mut bytes = Vec::new();
        encode_uint64_local(&mut bytes, 1);
        bytes.push(NID_EMPTY_STREAM);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(0x80);
        bytes.push(NID_END);

        let mut cursor = Cursor::new(&bytes);
        assert!(matches!(
            parse_files_info(&mut cursor),
            Err(Error::Unsupported(
                "7z: empty-stream entries are not supported"
            ))
        ));
    }

    #[test]
    fn test_parse_files_info_rejects_directory_entries() {
        let mut bytes = Vec::new();
        encode_uint64_local(&mut bytes, 1);
        bytes.push(NID_EMPTY_STREAM);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(0x80);
        bytes.push(NID_EMPTY_FILE);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(0x00);
        bytes.push(NID_END);

        let mut cursor = Cursor::new(&bytes);
        assert!(matches!(
            parse_files_info(&mut cursor),
            Err(Error::Unsupported(
                "7z: directory entries are not supported"
            ))
        ));
    }

    #[test]
    fn test_parse_files_info_rejects_anti_items() {
        let mut bytes = Vec::new();
        encode_uint64_local(&mut bytes, 1);
        bytes.push(NID_EMPTY_STREAM);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(0x80);
        bytes.push(NID_ANTI);
        encode_uint64_local(&mut bytes, 1);
        bytes.push(0x80);
        bytes.push(NID_END);

        let mut cursor = Cursor::new(&bytes);
        assert!(matches!(
            parse_files_info(&mut cursor),
            Err(Error::Unsupported("7z: anti-items are not supported"))
        ));
    }

    #[test]
    fn test_parse_names_property_rejects_external_streams() {
        let mut names = vec![String::new()];
        let mut cursor = Cursor::new(&[1]);
        assert_eq!(
            parse_names_property(&mut cursor, &mut names),
            Err(Error::Unsupported(
                "7z: external name streams are not supported"
            ))
        );
    }

    #[test]
    fn test_parse_attributes_property_rejects_external_streams() {
        let mut attributes = vec![None];
        let mut cursor = Cursor::new(&[1, 1]);
        assert_eq!(
            parse_attributes_property(&mut cursor, &mut attributes),
            Err(Error::Unsupported(
                "7z: external attributes are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_roundtrip_multiple_entries() {
        let mut encoder = SevenZEncoder::new();
        encoder.add_file("alpha.txt", b"alpha");
        encoder.add_file("beta.txt", b"beta-beta");
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha.txt");
        assert_eq!(entries[0].data, b"alpha");
        assert_eq!(entries[1].name, "beta.txt");
        assert_eq!(entries[1].data, b"beta-beta");
    }

    #[test]
    fn test_decode_roundtrip_with_bcj_filter() {
        let mut payload = Vec::new();
        for offset in (0..128).step_by(5) {
            payload.extend_from_slice(&[0xE8, offset as u8, 0x00, 0x00, 0x00]);
        }
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.add_file("code.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_decode_roundtrip_with_delta_filter() {
        let payload: Vec<u8> = (0..200).map(|i| (i as u8).wrapping_mul(3)).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 1 }]);
        encoder.add_file("delta.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_decode_encoded_header_archive() {
        let plain_header = vec![NID_HEADER, NID_FILES_INFO, 0x00, NID_END, NID_END];
        let packed_header = crate::compress::lzma2::lzma2_encode(&plain_header, 1 << 20);
        let mut header_info = Vec::new();
        header_info.push(NID_ENCODED_HEADER);
        header_info.push(NID_PACK_INFO);
        encode_uint64_local(&mut header_info, 0);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(NID_SIZE);
        encode_uint64_local(&mut header_info, packed_header.len() as u64);
        header_info.push(NID_END);
        header_info.push(NID_UNPACK_INFO);
        header_info.push(NID_FOLDER);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(0);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(0x21);
        header_info.push(0x21);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(16);
        header_info.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header_info, plain_header.len() as u64);
        header_info.push(NID_CRC);
        header_info.push(1);
        header_info.extend_from_slice(&crc32::crc32(&plain_header).to_le_bytes());
        header_info.push(NID_END);
        header_info.push(NID_END);

        let next_header_crc = crc32::crc32(&header_info);
        let next_header_offset = packed_header.len() as u64;
        let next_header_size = header_info.len() as u64;

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed_header);
        archive.extend_from_slice(&header_info);

        let entries = decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_decode_multi_folder_copy_archive() {
        let archive = build_multi_folder_copy_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha.txt");
        assert_eq!(entries[0].data, b"alpha");
        assert_eq!(entries[1].name, "beta.txt");
        assert_eq!(entries[1].data, b"beta-beta");
    }

    #[test]
    fn test_decode_multi_folder_lzma2_and_copy_archive() {
        let archive = build_multi_folder_lzma2_copy_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "alpha-lzma2.txt");
        assert_eq!(entries[0].data, b"alpha payload through lzma2".as_slice());
        assert_eq!(entries[1].name, "beta-copy.txt");
        assert_eq!(entries[1].data, b"copy folder payload");
    }

    #[test]
    fn test_decode_multi_folder_bcj2_and_copy_archive() {
        let archive = build_multi_folder_bcj2_copy_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "bcj2.bin");
        assert_eq!(entries[0].data, b"plain bcj2 payload");
        assert_eq!(entries[1].name, "copy.txt");
        assert_eq!(entries[1].data, b"copy folder payload");
    }

    #[test]
    fn test_normalize_folder_graph_simple_copy() {
        let folder = Folder {
            coders: vec![copy_coder(0, 0)],
            bind_pairs: Vec::new(),
            packed_streams: vec![0],
            unpack_sizes: vec![5],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.total_outputs, 1);
        assert_eq!(graph.input_sources, vec![InputSource::Packed(0)]);
        assert_eq!(graph.output_owners, vec![0]);
        assert_eq!(graph.output_consumers, vec![Vec::<u64>::new()]);
        assert_eq!(graph.final_outputs, vec![0]);
    }

    #[test]
    fn test_normalize_folder_graph_tracks_multi_output_coder_ownership() {
        let folder = Folder {
            coders: vec![Coder {
                num_out_streams: 2,
                ..copy_coder(0, 0)
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0],
            unpack_sizes: vec![5, 5],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.execution_order, vec![0]);
        assert_eq!(graph.output_owners, vec![0, 0]);
        assert_eq!(
            graph.output_consumers,
            vec![Vec::<u64>::new(), Vec::<u64>::new()]
        );
        assert_eq!(graph.final_outputs, vec![0, 1]);
    }

    #[test]
    fn test_normalize_folder_graph_computes_execution_order_for_linear_chain() {
        let folder = Folder {
            coders: vec![copy_coder(0, 0), copy_coder(1, 1)],
            bind_pairs: vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            packed_streams: vec![0],
            unpack_sizes: vec![5, 5],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.execution_order, vec![0, 1]);
        assert_eq!(graph.output_owners, vec![0, 1]);
        assert_eq!(graph.output_consumers, vec![vec![1], Vec::<u64>::new()]);
        assert_eq!(graph.final_outputs, vec![1]);
    }

    #[test]
    fn test_normalize_folder_graph_tracks_bcj2_input_sources() {
        let folder = Folder {
            coders: vec![
                copy_coder(0, 0),
                Coder {
                    method_id: METHOD_BCJ2_X86.to_vec(),
                    properties: Vec::new(),
                    num_in_streams: 4,
                    num_out_streams: 1,
                    input_index: 1,
                    output_index: 1,
                },
            ],
            bind_pairs: vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            packed_streams: vec![0, 2, 3, 4],
            unpack_sizes: vec![16, 16],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(
            graph.input_sources,
            vec![
                InputSource::Packed(0),
                InputSource::Output(0),
                InputSource::Packed(1),
                InputSource::Packed(2),
                InputSource::Packed(3),
            ]
        );
        assert_eq!(graph.output_owners, vec![0, 1]);
        assert_eq!(graph.output_consumers, vec![vec![1], Vec::<u64>::new()]);
        assert_eq!(graph.final_outputs, vec![1]);
    }

    #[test]
    fn test_normalize_folder_graph_computes_execution_order_for_bcj2_chain() {
        let folder = Folder {
            coders: vec![
                copy_coder(0, 0),
                Coder {
                    method_id: METHOD_BCJ2_X86.to_vec(),
                    properties: Vec::new(),
                    num_in_streams: 4,
                    num_out_streams: 1,
                    input_index: 1,
                    output_index: 1,
                },
            ],
            bind_pairs: vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            packed_streams: vec![0, 2, 3, 4],
            unpack_sizes: vec![16, 16],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.execution_order, vec![0, 1]);
    }

    #[test]
    fn test_normalize_folder_graph_tracks_multiple_final_outputs() {
        let folder = Folder {
            coders: vec![copy_coder(0, 0), copy_coder(1, 1)],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1],
            unpack_sizes: vec![5, 5],
            crc32: None,
        };
        let graph = normalize_folder_graph(&folder).unwrap();
        assert_eq!(graph.execution_order, vec![0, 1]);
        assert_eq!(graph.output_owners, vec![0, 1]);
        assert_eq!(
            graph.output_consumers,
            vec![Vec::<u64>::new(), Vec::<u64>::new()]
        );
        assert_eq!(graph.final_outputs, vec![0, 1]);
    }

    #[test]
    fn test_decode_folder_concatenates_multiple_final_outputs() {
        let folder = Folder {
            coders: vec![copy_coder(0, 0), copy_coder(1, 1)],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1],
            unpack_sizes: vec![5, 4],
            crc32: None,
        };
        let packed = [b"alpha".as_slice(), b"beta".as_slice()];
        let decoded = decode_folder(&folder, &packed, None).unwrap();
        assert_eq!(decoded, b"alphabeta");
    }

    #[test]
    fn test_decode_bcj2_type0_copy_archive() {
        let archive = build_bcj2_type0_copy_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj2.bin");
        assert_eq!(entries[0].data, b"plain bcj2 payload");
    }

    #[test]
    fn test_decode_bcj2_with_lzma_main_chain_archive() {
        let archive = build_bcj2_lzma_main_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj2-lzma.bin");
        assert_eq!(entries[0].data, b"plain bcj2 payload through lzma");
    }

    #[test]
    fn test_decode_bcj2_with_aes_main_and_downstream_copy_archive() {
        let archive = build_bcj2_aes_main_copy_archive();
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj2-aes.bin");
        assert_eq!(entries[0].data, b"plain bcj2 payload through aes");
    }

    #[test]
    fn test_decode_bcj2_with_multiple_upstream_coders_and_downstream_copy_archive() {
        let archive = build_bcj2_aes_main_and_copy_call_stream_archive();
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj2-aes-copy.bin");
        assert_eq!(entries[0].data, b"plain bcj2 payload through aes");
    }

    #[test]
    fn test_decode_copy_fanout_multi_final_output_archive() {
        let archive = build_copy_fanout_multi_final_output_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "copy-fanout.bin");
        assert_eq!(entries[0].data, b"alphaalpha");
    }

    #[test]
    fn test_decode_rejects_multi_output_multi_input_copy_graph_archive() {
        let archive = build_multi_output_multi_input_copy_archive();
        assert_eq!(
            decode(&archive),
            Err(Error::Unsupported(
                "7z: multi-output coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_rejects_delta_multi_input_archive() {
        let archive = build_delta_multi_input_archive();
        assert_eq!(
            decode(&archive),
            Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_folder_rejects_multi_input_lzma2_coder() {
        let folder = Folder {
            coders: vec![Coder {
                method_id: METHOD_LZMA2.to_vec(),
                properties: Vec::new(),
                num_in_streams: 2,
                num_out_streams: 1,
                input_index: 0,
                output_index: 0,
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1],
            unpack_sizes: vec![5],
            crc32: None,
        };
        let packed = [b"alpha".as_slice(), b"beta".as_slice()];
        assert_eq!(
            decode_folder(&folder, &packed, None),
            Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_folder_rejects_multi_input_ppmd_coder() {
        let folder = Folder {
            coders: vec![Coder {
                method_id: METHOD_PPMD.to_vec(),
                properties: Vec::new(),
                num_in_streams: 2,
                num_out_streams: 1,
                input_index: 0,
                output_index: 0,
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1],
            unpack_sizes: vec![5],
            crc32: None,
        };
        let packed = [b"alpha".as_slice(), b"beta".as_slice()];
        assert_eq!(
            decode_folder(&folder, &packed, None),
            Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_folder_rejects_multi_input_delta_coder() {
        let folder = Folder {
            coders: vec![Coder {
                method_id: METHOD_DELTA.to_vec(),
                properties: Vec::new(),
                num_in_streams: 2,
                num_out_streams: 1,
                input_index: 0,
                output_index: 0,
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1],
            unpack_sizes: vec![5],
            crc32: None,
        };
        let packed = [b"alpha".as_slice(), b"beta".as_slice()];
        assert_eq!(
            decode_folder(&folder, &packed, None),
            Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_folder_rejects_bcj2_with_nonstandard_input_arity() {
        let folder = Folder {
            coders: vec![Coder {
                method_id: METHOD_BCJ2_X86.to_vec(),
                properties: Vec::new(),
                num_in_streams: 3,
                num_out_streams: 1,
                input_index: 0,
                output_index: 0,
            }],
            bind_pairs: Vec::new(),
            packed_streams: vec![0, 1, 2],
            unpack_sizes: vec![5],
            crc32: None,
        };
        let packed = [b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()];
        assert_eq!(
            decode_folder(&folder, &packed, None),
            Err(Error::Unsupported(
                "7z: non-BCJ2 multi-input coder methods are not supported"
            ))
        );
    }

    #[test]
    fn test_decode_rejects_encrypted_folder() {
        let archive = build_encrypted_file_archive();
        let result = decode(&archive);
        assert_eq!(
            result,
            Err(Error::Unsupported(
                "7z: encrypted archive requires a password"
            ))
        );
    }

    #[test]
    fn test_decode_rejects_encrypted_encoded_header() {
        let archive = build_encrypted_encoded_header_archive();
        let result = decode(&archive);
        assert_eq!(
            result,
            Err(Error::Unsupported(
                "7z: encrypted archive requires a password"
            ))
        );
    }

    #[test]
    fn test_decode_with_password_encrypted_file_archive() {
        let archive = build_encrypted_file_archive();
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.bin");
        assert_eq!(entries[0].data, b"encrypted sevenz payload");
    }

    #[test]
    fn test_decode_with_password_wrong_password_fails() {
        let archive = build_encrypted_file_archive();
        assert!(decode_with_password(&archive, "wrong").is_err());
    }

    #[test]
    fn test_decode_with_password_encrypted_encoded_header_archive() {
        let archive = build_encrypted_encoded_header_archive();
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_decode_7z_aes_coder_roundtrip() {
        let password = encode_password_utf16le("secret");
        let plaintext = crate::compress::lzma2::lzma2_encode(b"encrypted sevenz payload", 1 << 20);
        let encrypted = encrypt_test_stream(&plaintext, &password);
        let decrypted =
            decode_7z_aes(&encrypted, &[0x3F], plaintext.len(), Some(&password)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decode_ppmd_coder_fixture() {
        use super::codecs::decode_coder;
        let coder = Coder {
            method_id: METHOD_PPMD.to_vec(),
            properties: vec![6, 0x00, 0x00, 0x20, 0x00],
            num_in_streams: 1,
            num_out_streams: 1,
            input_index: 0,
            output_index: 0,
        };
        let payload = b"PPMd coder fixture";
        let props =
            crate::compress::ppmd::Ppmd7Properties::from_sevenz_properties(&coder.properties)
                .unwrap();
        let packed = crate::compress::ppmd::encode(payload, props, false).unwrap();
        assert_eq!(
            decode_coder(&coder, &[packed], &[payload.len()], None).unwrap(),
            vec![payload.to_vec()]
        );
    }

    #[test]
    fn test_decode_raw_lzma_archive() {
        let archive = build_raw_lzma_archive();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "raw-lzma.txt");
        assert_eq!(
            entries[0].data,
            b"raw LZMA in 7z uses the folder unpack size".as_slice()
        );
    }

    #[test]
    fn test_decode_roundtrip_with_ppmd_method() {
        let payload = b"PPMd 7z roundtrip fixture";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(crate::archive::sevenz::encode::SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.add_file("ppmd.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ppmd.txt");
        assert_eq!(entries[0].data, payload);
    }

    fn build_multi_folder_copy_archive() -> Vec<u8> {
        let files = [
            ("alpha.txt", b"alpha".as_slice()),
            ("beta.txt", b"beta-beta".as_slice()),
        ];
        let packed: Vec<u8> = files
            .iter()
            .flat_map(|(_, data)| data.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, files.len() as u64);
        header.push(NID_SIZE);
        for (_, data) in &files {
            encode_uint64_local(&mut header, data.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for (_, data) in &files {
            header.extend_from_slice(&crc32::crc32(data).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, files.len() as u64);
        header.push(0);
        for _ in &files {
            encode_uint64_local(&mut header, 1);
            header.push(0x01);
            header.push(0x00);
        }
        header.push(NID_CODERS_UNPACK_SIZE);
        for (_, data) in &files {
            encode_uint64_local(&mut header, data.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for (_, data) in &files {
            header.extend_from_slice(&crc32::crc32(data).to_le_bytes());
        }
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, files.len() as u64);

        let mut names = Vec::new();
        names.push(0);
        for (name, _) in &files {
            for unit in name.encode_utf16() {
                names.extend_from_slice(&unit.to_le_bytes());
            }
            names.extend_from_slice(&0u16.to_le_bytes());
        }
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        for _ in &files {
            attrs.extend_from_slice(&0x20u32.to_le_bytes());
        }
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn append_pack_info(header: &mut Vec<u8>, pack_streams: &[&[u8]]) {
        header.push(NID_PACK_INFO);
        encode_uint64_local(header, 0);
        encode_uint64_local(header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in pack_streams {
            encode_uint64_local(header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);
    }

    fn append_file_info(header: &mut Vec<u8>, files: &[(&str, &[u8])]) {
        header.push(NID_FILES_INFO);
        encode_uint64_local(header, files.len() as u64);

        let mut names = Vec::new();
        names.push(0);
        for (name, _) in files {
            for unit in name.encode_utf16() {
                names.extend_from_slice(&unit.to_le_bytes());
            }
            names.extend_from_slice(&0u16.to_le_bytes());
        }
        header.push(NID_NAME);
        encode_uint64_local(header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        for _ in files {
            attrs.extend_from_slice(&0x20u32.to_le_bytes());
        }
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
    }

    fn finalize_archive(packed: &[u8], header: &[u8]) -> Vec<u8> {
        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(packed);
        archive.extend_from_slice(header);
        archive
    }

    fn build_multi_folder_lzma2_copy_archive() -> Vec<u8> {
        let payload_lzma2 = b"alpha payload through lzma2";
        let payload_copy = b"copy folder payload";
        let packed_lzma2 = crate::compress::lzma2::lzma2_encode(payload_lzma2, 1 << 20);
        let pack_streams = [packed_lzma2.as_slice(), payload_copy.as_slice()];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);
        append_pack_info(&mut header, &pack_streams);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 2);
        header.push(0);

        encode_uint64_local(&mut header, 1);
        header.push(0x21);
        header.extend_from_slice(METHOD_LZMA2);
        encode_uint64_local(&mut header, 1);
        header.push(16);

        encode_uint64_local(&mut header, 1);
        header.push(0x01);
        header.push(0x00);

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload_lzma2.len() as u64);
        encode_uint64_local(&mut header, payload_copy.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload_lzma2).to_le_bytes());
        header.extend_from_slice(&crc32::crc32(payload_copy).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        append_file_info(
            &mut header,
            &[
                ("alpha-lzma2.txt", payload_lzma2.as_slice()),
                ("beta-copy.txt", payload_copy.as_slice()),
            ],
        );
        header.push(NID_END);

        finalize_archive(&packed, &header)
    }

    fn build_multi_folder_bcj2_copy_archive() -> Vec<u8> {
        let payload_bcj2 = b"plain bcj2 payload";
        let payload_copy = b"copy folder payload";
        let bcj2_pack_streams = [
            payload_bcj2.as_slice(),
            &[][..],
            &[][..],
            &[0, 0, 0, 0, 0][..],
        ];
        let pack_streams = [
            bcj2_pack_streams[0],
            bcj2_pack_streams[1],
            bcj2_pack_streams[2],
            bcj2_pack_streams[3],
            payload_copy.as_slice(),
        ];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);
        append_pack_info(&mut header, &pack_streams);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 2);
        header.push(0);

        encode_uint64_local(&mut header, 2);
        header.push(0x01);
        header.push(0x00);
        header.push(0x14);
        header.extend_from_slice(METHOD_BCJ2_X86);
        encode_uint64_local(&mut header, 4);
        encode_uint64_local(&mut header, 1);
        header.push(1);
        header.push(0);
        for &packed_index in &[0u64, 2, 3, 4] {
            encode_uint64_local(&mut header, packed_index);
        }

        encode_uint64_local(&mut header, 1);
        header.push(0x01);
        header.push(0x00);

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload_bcj2.len() as u64);
        encode_uint64_local(&mut header, payload_bcj2.len() as u64);
        encode_uint64_local(&mut header, payload_copy.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload_bcj2).to_le_bytes());
        header.extend_from_slice(&crc32::crc32(payload_copy).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        append_file_info(
            &mut header,
            &[
                ("bcj2.bin", payload_bcj2.as_slice()),
                ("copy.txt", payload_copy.as_slice()),
            ],
        );
        header.push(NID_END);

        finalize_archive(&packed, &header)
    }

    fn build_raw_lzma_archive() -> Vec<u8> {
        let payload = b"raw LZMA in 7z uses the folder unpack size";
        let dict_size = 1 << 20;
        let props = LzmaProperties::LZIP;
        let packed = lzma::lzma_encode_with_props_no_eos(payload, dict_size, props);

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 1);
        header.push(NID_SIZE);
        encode_uint64_local(&mut header, packed.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(&packed).to_le_bytes());
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 1);
        header.push(0x23);
        header.extend_from_slice(METHOD_LZMA);
        encode_uint64_local(&mut header, 5);
        header.push(props.to_props_byte());
        header.extend_from_slice(&dict_size.to_le_bytes());
        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);
        let mut names = Vec::new();
        names.push(0);
        for unit in "raw-lzma.txt".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_bcj2_type0_copy_archive() -> Vec<u8> {
        let payload = b"plain bcj2 payload";
        let pack_streams = [payload.as_slice(), &[][..], &[][..], &[0, 0, 0, 0, 0][..]];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in &pack_streams {
            encode_uint64_local(&mut header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in &pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 2);

        header.push(0x01);
        header.push(0x00);

        header.push(0x14);
        header.extend_from_slice(METHOD_BCJ2_X86);
        encode_uint64_local(&mut header, 4);
        encode_uint64_local(&mut header, 1);

        header.push(1);
        header.push(0);

        for &packed_index in &[0u64, 2, 3, 4] {
            encode_uint64_local(&mut header, packed_index);
        }

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "bcj2.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_bcj2_lzma_main_archive() -> Vec<u8> {
        let payload = b"plain bcj2 payload through lzma";
        let dict_size = 1 << 20;
        let props = LzmaProperties::LZIP;
        let main = lzma::lzma_encode_with_props_no_eos(payload, dict_size, props);
        let pack_streams = [main.as_slice(), &[][..], &[][..], &[0, 0, 0, 0, 0][..]];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in &pack_streams {
            encode_uint64_local(&mut header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in &pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 2);

        header.push(0x23);
        header.extend_from_slice(METHOD_LZMA);
        encode_uint64_local(&mut header, 5);
        header.push(props.to_props_byte());
        header.extend_from_slice(&dict_size.to_le_bytes());

        header.push(0x14);
        header.extend_from_slice(METHOD_BCJ2_X86);
        encode_uint64_local(&mut header, 4);
        encode_uint64_local(&mut header, 1);

        header.push(1);
        header.push(0);

        for &packed_index in &[0u64, 2, 3, 4] {
            encode_uint64_local(&mut header, packed_index);
        }

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "bcj2-lzma.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_bcj2_aes_main_copy_archive() -> Vec<u8> {
        let payload = b"plain bcj2 payload through aes";
        let password = encode_password_utf16le("secret");
        let encrypted_main = encrypt_test_stream(payload, &password);
        let pack_streams = [
            encrypted_main.as_slice(),
            &[][..],
            &[][..],
            &[0, 0, 0, 0, 0][..],
        ];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in &pack_streams {
            encode_uint64_local(&mut header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in &pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 3);

        header.push(0x24);
        header.extend_from_slice(METHOD_7Z_AES);
        encode_uint64_local(&mut header, 1);
        header.push(0x3F);

        header.push(0x14);
        header.extend_from_slice(METHOD_BCJ2_X86);
        encode_uint64_local(&mut header, 4);
        encode_uint64_local(&mut header, 1);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 5);
        encode_uint64_local(&mut header, 1);

        for &packed_index in &[0u64, 2, 3, 4] {
            encode_uint64_local(&mut header, packed_index);
        }

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "bcj2-aes.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_bcj2_aes_main_and_copy_call_stream_archive() -> Vec<u8> {
        let payload = b"plain bcj2 payload through aes";
        let password = encode_password_utf16le("secret");
        let encrypted_main = encrypt_test_stream(payload, &password);
        let empty_call = [];
        let pack_streams = [
            encrypted_main.as_slice(),
            empty_call.as_slice(),
            &[][..],
            &[0, 0, 0, 0, 0][..],
        ];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in &pack_streams {
            encode_uint64_local(&mut header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in &pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 4);

        header.push(0x24);
        header.extend_from_slice(METHOD_7Z_AES);
        encode_uint64_local(&mut header, 1);
        header.push(0x3F);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        header.push(0x14);
        header.extend_from_slice(METHOD_BCJ2_X86);
        encode_uint64_local(&mut header, 4);
        encode_uint64_local(&mut header, 1);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        encode_uint64_local(&mut header, 2);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 3);
        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 6);
        encode_uint64_local(&mut header, 2);

        for &packed_index in &[0u64, 1, 4, 5] {
            encode_uint64_local(&mut header, packed_index);
        }

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, payload.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "bcj2-aes-copy.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_multi_output_multi_input_copy_archive() -> Vec<u8> {
        let packed = b"alpha".to_vec();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 1);
        header.push(NID_SIZE);
        encode_uint64_local(&mut header, packed.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(&packed).to_le_bytes());
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 2);

        header.push(0x11);
        header.extend_from_slice(METHOD_COPY);
        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 2);

        header.push(0x11);
        header.extend_from_slice(METHOD_COPY);
        encode_uint64_local(&mut header, 2);
        encode_uint64_local(&mut header, 1);

        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 2);
        encode_uint64_local(&mut header, 1);

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, packed.len() as u64);
        encode_uint64_local(&mut header, packed.len() as u64);
        encode_uint64_local(&mut header, packed.len() as u64);
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "unsupported-graph.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_copy_fanout_multi_final_output_archive() -> Vec<u8> {
        let packed = b"alpha".to_vec();
        let unpacked = b"alphaalpha";

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 1);
        header.push(NID_SIZE);
        encode_uint64_local(&mut header, packed.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(&packed).to_le_bytes());
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 3);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        header.push(0x01);
        header.extend_from_slice(METHOD_COPY);

        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 2);
        encode_uint64_local(&mut header, 0);

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, packed.len() as u64);
        encode_uint64_local(&mut header, packed.len() as u64);
        encode_uint64_local(&mut header, packed.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(unpacked).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "copy-fanout.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_delta_multi_input_archive() -> Vec<u8> {
        let pack_streams = [b"ace".as_slice(), b"bdf".as_slice()];
        let packed: Vec<u8> = pack_streams
            .iter()
            .flat_map(|stream| stream.iter().copied())
            .collect();

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, pack_streams.len() as u64);
        header.push(NID_SIZE);
        for stream in &pack_streams {
            encode_uint64_local(&mut header, stream.len() as u64);
        }
        header.push(NID_CRC);
        header.push(1);
        for stream in &pack_streams {
            header.extend_from_slice(&crc32::crc32(stream).to_le_bytes());
        }
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 1);
        header.push(0x31);
        header.extend_from_slice(METHOD_DELTA);
        encode_uint64_local(&mut header, 2);
        encode_uint64_local(&mut header, 1);
        encode_uint64_local(&mut header, 1);
        header.push(1);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 1);

        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, 6);
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);

        let mut names = Vec::new();
        names.push(0);
        for unit in "delta-multi-input.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);

        let mut attrs = vec![1, 0];
        attrs.extend_from_slice(&0x20u32.to_le_bytes());
        header.push(NID_WIN_ATTRIBUTES);
        encode_uint64_local(&mut header, attrs.len() as u64);
        header.extend_from_slice(&attrs);

        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_encrypted_file_archive() -> Vec<u8> {
        let password = encode_password_utf16le("secret");
        let payload = b"encrypted sevenz payload";
        let compressed = crate::compress::lzma2::lzma2_encode(payload, 1 << 20);
        let encrypted = encrypt_test_stream(&compressed, &password);

        let mut header = Vec::new();
        header.push(NID_HEADER);
        header.push(NID_MAIN_STREAMS_INFO);

        header.push(NID_PACK_INFO);
        encode_uint64_local(&mut header, 0);
        encode_uint64_local(&mut header, 1);
        header.push(NID_SIZE);
        encode_uint64_local(&mut header, encrypted.len() as u64);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(&encrypted).to_le_bytes());
        header.push(NID_END);

        header.push(NID_UNPACK_INFO);
        header.push(NID_FOLDER);
        encode_uint64_local(&mut header, 1);
        header.push(0);
        encode_uint64_local(&mut header, 2);
        header.push(0x24);
        header.extend_from_slice(METHOD_7Z_AES);
        encode_uint64_local(&mut header, 1);
        header.push(0x3F);
        header.push(0x21);
        header.push(0x21);
        encode_uint64_local(&mut header, 1);
        header.push(16);
        header.push(1);
        header.push(0);
        header.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header, compressed.len() as u64);
        encode_uint64_local(&mut header, payload.len() as u64);
        header.push(NID_END);

        header.push(NID_SUBSTREAMS_INFO);
        header.push(NID_CRC);
        header.push(1);
        header.extend_from_slice(&crc32::crc32(payload).to_le_bytes());
        header.push(NID_END);
        header.push(NID_END);

        header.push(NID_FILES_INFO);
        encode_uint64_local(&mut header, 1);
        let mut names = Vec::new();
        names.push(0);
        for unit in "secret.bin".encode_utf16() {
            names.extend_from_slice(&unit.to_le_bytes());
        }
        names.extend_from_slice(&0u16.to_le_bytes());
        header.push(NID_NAME);
        encode_uint64_local(&mut header, names.len() as u64);
        header.extend_from_slice(&names);
        header.push(NID_END);
        header.push(NID_END);

        let next_header_offset = encrypted.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&encrypted);
        archive.extend_from_slice(&header);
        archive
    }

    fn build_encrypted_encoded_header_archive() -> Vec<u8> {
        let password = encode_password_utf16le("secret");
        let payload = vec![NID_HEADER, NID_FILES_INFO, 0x00, NID_END, NID_END];
        let compressed = crate::compress::lzma2::lzma2_encode(&payload, 1 << 20);
        let encrypted = encrypt_test_stream(&compressed, &password);

        let mut header_info = Vec::new();
        header_info.push(NID_ENCODED_HEADER);
        header_info.push(NID_PACK_INFO);
        encode_uint64_local(&mut header_info, 0);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(NID_SIZE);
        encode_uint64_local(&mut header_info, encrypted.len() as u64);
        header_info.push(NID_CRC);
        header_info.push(1);
        header_info.extend_from_slice(&crc32::crc32(&encrypted).to_le_bytes());
        header_info.push(NID_END);

        header_info.push(NID_UNPACK_INFO);
        header_info.push(NID_FOLDER);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(0);
        encode_uint64_local(&mut header_info, 2);
        header_info.push(0x24);
        header_info.extend_from_slice(METHOD_7Z_AES);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(0x3F);
        header_info.push(0x21);
        header_info.push(0x21);
        encode_uint64_local(&mut header_info, 1);
        header_info.push(16);
        header_info.push(1);
        header_info.push(0);
        header_info.push(NID_CODERS_UNPACK_SIZE);
        encode_uint64_local(&mut header_info, compressed.len() as u64);
        encode_uint64_local(&mut header_info, payload.len() as u64);
        header_info.push(NID_END);
        header_info.push(NID_END);

        let next_header_offset = encrypted.len() as u64;
        let next_header_size = header_info.len() as u64;
        let next_header_crc = crc32::crc32(&header_info);

        let mut archive = Vec::new();
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        archive.extend_from_slice(&crc32::crc32(&start_header).to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&encrypted);
        archive.extend_from_slice(&header_info);
        archive
    }

    fn encrypt_test_stream(plaintext: &[u8], password: &[u8]) -> Vec<u8> {
        let props = parse_7z_aes_properties(&[0x3F]).unwrap();
        let key = derive_7z_aes_key(password, &props).unwrap();
        let cipher = Aes256::new(&key);
        cipher.encrypt_cbc_zero_padded(plaintext, &props.iv)
    }

    #[test]
    fn test_decode_timestamps_preserved() {
        let mut encoder = SevenZEncoder::new();
        let entry = SevenZEntry {
            name: "ts.txt".to_string(),
            data: b"timestamp test".to_vec(),
            crc32: Some(crc32::crc32(b"timestamp test")),
            attributes: Some(0x20),
            ctime: Some(132_456_789_000_000_000),
            atime: Some(132_456_789_100_000_000),
            mtime: Some(132_456_789_200_000_000),
        };
        encoder.add_entry(entry);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ts.txt");
        assert_eq!(entries[0].data, b"timestamp test");
        assert_eq!(entries[0].ctime, Some(132_456_789_000_000_000));
        assert_eq!(entries[0].atime, Some(132_456_789_100_000_000));
        assert_eq!(entries[0].mtime, Some(132_456_789_200_000_000));
    }
}
