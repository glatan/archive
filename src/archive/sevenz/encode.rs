//! 7z archive encoding.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use crate::archive::sevenz::decode::{
    SevenZEntry, derive_7z_aes_key, encode_password_utf16le, parse_7z_aes_properties,
};
use crate::compress::bcj;
use crate::compress::delta;
use crate::compress::lzma;
use crate::compress::lzma2;
use crate::compress::ppmd;
use crate::error::Error;
use crate::util::aes256::Aes256;
use crate::util::crc32;

use super::bcj2;

const SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

const NID_END: u8 = 0x00;
const NID_HEADER: u8 = 0x01;
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
const NID_NAME: u8 = 0x11;
const NID_CTIME: u8 = 0x12;
const NID_ATIME: u8 = 0x13;
const NID_MTIME: u8 = 0x14;
const NID_ENCODED_HEADER: u8 = 0x17;
const NID_WIN_ATTRIBUTES: u8 = 0x15;
const METHOD_7Z_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
const AES_PROPERTIES: [u8; 1] = [0x3F];

/// Baseline 7z compression methods exposed by the archive writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZMethod {
    /// Store bytes without compression.
    Copy,
    /// Use a single LZMA coder with the provided dictionary size.
    Lzma { dict_size: u32 },
    /// Use a single LZMA2 coder with the provided dictionary size.
    Lzma2 { dict_size: u32 },
    /// Use a single PPMdH / PPMd7 coder.
    Ppmd { order: u8, mem_size: u32 },
    /// Use DEFLATE compression (7z method `04 01 08`).
    Deflate {
        /// DEFLATE compression level.
        level: crate::compress::deflate::encode::Level,
    },
    /// Use Deflate64 compression (7z method `04 01 09`, no
    /// properties). Output stays in the DEFLATE-compatible subset
    /// (matches <=257, 32 KB window).
    Deflate64,
    /// Use BZip2 compression (7z method `04 02 02`).
    Bzip2 {
        /// BZip2 block size level (1-9).
        level: u8,
    },
    /// Use Brotli compression (requires `brotli` feature).
    #[cfg(feature = "brotli")]
    Brotli,
}

/// Optional filters applied before compression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SevenZFilter {
    /// x86 BCJ transform.
    X86Bcj,
    /// x86 BCJ2 transform (4-stream split).
    X86Bcj2,
    /// IA-64 (Itanium) BCJ transform.
    Ia64Bcj,
    /// PowerPC BCJ transform.
    PowerPcBcj,
    /// ARM BCJ transform.
    ArmBcj,
    /// ARM Thumb BCJ transform.
    ArmThumbBcj,
    /// SPARC BCJ transform.
    SparcBcj,
    /// AArch64 BCJ transform.
    Arm64Bcj,
    /// RISC-V BCJ transform.
    RiscVBcj,
    /// Delta filter with a 1..=256 byte distance.
    Delta { distance: u16 },
}

/// Builder for baseline 7z archives.
#[derive(Debug)]
pub struct SevenZEncoder {
    method: SevenZMethod,
    filters: Vec<SevenZFilter>,
    password: Option<Vec<u8>>,
    encoded_header: bool,
    two_folder_split: Option<usize>,
    folder_splits: Option<Vec<usize>>,
    entries: Vec<SevenZEntry>,
}

impl SevenZEncoder {
    /// Create a baseline LZMA2 encoder.
    pub const fn new() -> Self {
        Self {
            method: SevenZMethod::Lzma2 { dict_size: 1 << 23 },
            filters: Vec::new(),
            password: None,
            encoded_header: false,
            two_folder_split: None,
            folder_splits: None,
            entries: Vec::new(),
        }
    }

    /// Override the solid-folder compression method.
    pub const fn set_method(&mut self, method: SevenZMethod) {
        self.method = method;
    }

    /// Configure optional pre-compression filters.
    pub fn set_filters(&mut self, filters: Vec<SevenZFilter>) {
        self.filters = filters;
    }

    /// Store the next header as an encoded-header stream.
    ///
    /// When a password is configured, the encoded header is encrypted with the
    /// same linear 7zAES folder pipeline used for file content.
    pub const fn set_encoded_header(&mut self, enabled: bool) {
        self.encoded_header = enabled;
    }

    /// Split file-content streams into two solid folders at the given entry index.
    ///
    /// Entries before `split_at` go into the first folder and the rest into the
    /// second folder. The current writer keeps the same method/filter/password
    /// configuration for both folders.
    pub const fn set_two_folder_split(&mut self, split_at: usize) {
        self.two_folder_split = Some(split_at);
    }

    /// Split file-content streams into `splits.len() + 1` solid folders at
    /// the given entry indices.
    ///
    /// `splits` must be strictly increasing and each point must divide the
    /// entry list into non-empty groups (validated at finish). Overrides
    /// [`set_two_folder_split`](Self::set_two_folder_split). All folders
    /// share the same method/filter/password configuration.
    pub fn set_folder_splits(&mut self, splits: &[usize]) {
        self.folder_splits = Some(splits.to_vec());
        self.two_folder_split = None;
    }

    /// Enable linear 7zAES file-content encryption using a UTF-16LE password.
    pub fn set_password(&mut self, password: &str) {
        self.password = Some(encode_password_utf16le(password));
    }

    /// Enable linear 7zAES file-content encryption using raw password bytes.
    pub fn set_password_bytes(&mut self, password: &[u8]) {
        self.password = Some(password.to_vec());
    }

    /// Add a regular file entry.
    pub fn add_file(&mut self, name: &str, data: &[u8]) {
        self.entries.push(SevenZEntry {
            name: name.to_string(),
            data: data.to_vec(),
            crc32: Some(crc32::crc32(data)),
            attributes: Some(0x20),
            ctime: None,
            atime: None,
            mtime: None,
        });
    }

    /// Add a pre-built entry.
    pub fn add_entry(&mut self, mut entry: SevenZEntry) {
        if entry.crc32.is_none() {
            entry.crc32 = Some(crc32::crc32(&entry.data));
        }
        self.entries.push(entry);
    }

    /// Finish the archive and return the encoded bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        let ArchiveBody { packed, header } = build_archive_body(
            &self.entries,
            self.method,
            &self.filters,
            self.password.as_deref(),
            self.encoded_header,
            self.folder_splits
                .or(self.two_folder_split.map(|s| alloc::vec![s])),
        )?;

        let next_header_offset = packed.len() as u64;
        let next_header_size = header.len() as u64;
        let next_header_crc = crc32::crc32(&header);

        let mut start_header = Vec::with_capacity(20);
        start_header.extend_from_slice(&next_header_offset.to_le_bytes());
        start_header.extend_from_slice(&next_header_size.to_le_bytes());
        start_header.extend_from_slice(&next_header_crc.to_le_bytes());
        let start_header_crc = crc32::crc32(&start_header);

        let mut archive = Vec::with_capacity(32 + packed.len() + header.len());
        archive.extend_from_slice(&SIGNATURE);
        archive.extend_from_slice(&[0, 4]);
        archive.extend_from_slice(&start_header_crc.to_le_bytes());
        archive.extend_from_slice(&start_header);
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&header);
        Ok(archive)
    }
}

impl Default for SevenZEncoder {
    fn default() -> Self {
        Self::new()
    }
}

struct ArchiveBody {
    packed: Vec<u8>,
    header: Vec<u8>,
}

fn build_archive_body(
    entries: &[SevenZEntry],
    method: SevenZMethod,
    filters: &[SevenZFilter],
    password: Option<&[u8]>,
    encoded_header: bool,
    folder_splits: Option<Vec<usize>>,
) -> Result<ArchiveBody, Error> {
    let mut packed = Vec::new();
    let main_streams = if entries.is_empty() {
        None
    } else if let Some(splits) = folder_splits {
        // Validate strictly-increasing interior split points.
        let mut prev = 0usize;
        for &s in &splits {
            if s <= prev || s >= entries.len() {
                return Err(Error::InvalidData(
                    "7z: folder splits must be strictly increasing and divide entries into non-empty folders",
                ));
            }
            prev = s;
        }
        let mut bounds = Vec::with_capacity(splits.len() + 2);
        bounds.push(0);
        bounds.extend_from_slice(&splits);
        bounds.push(entries.len());
        let mut streams = Vec::with_capacity(splits.len() + 1);
        let mut pack_pos = 0u64;
        for w in bounds.windows(2) {
            let folder_entries = &entries[w[0]..w[1]];
            let solid_data = concatenate_entries(folder_entries)?;
            let stream = encode_payload_as_stream(
                &solid_data,
                method,
                filters,
                password,
                pack_pos,
                folder_entries
                    .iter()
                    .map(|entry| entry.data.len() as u64)
                    .collect(),
                folder_entries.iter().map(|entry| entry.crc32).collect(),
            )?;
            pack_pos = pack_pos
                .checked_add(stream.metadata.total_pack_size())
                .ok_or(Error::InvalidData("7z: pack size overflow"))?;
            packed.extend_from_slice(&stream.packed);
            streams.push(stream.metadata);
        }
        Some(streams)
    } else {
        let solid_data = concatenate_entries(entries)?;
        let stream = encode_payload_as_stream(
            &solid_data,
            method,
            filters,
            password,
            0,
            entries
                .iter()
                .map(|entry| entry.data.len() as u64)
                .collect(),
            entries.iter().map(|entry| entry.crc32).collect(),
        )?;
        packed.extend_from_slice(&stream.packed);
        Some(vec![stream.metadata])
    };

    let plain_header = encode_header(entries, main_streams.as_deref())?;
    if !encoded_header {
        return Ok(ArchiveBody {
            packed,
            header: plain_header,
        });
    }

    let header_stream = encode_payload_as_stream(
        &plain_header,
        method,
        filters,
        password,
        packed.len() as u64,
        vec![plain_header.len() as u64],
        vec![Some(crc32::crc32(&plain_header))],
    )?;
    packed.extend_from_slice(&header_stream.packed);
    Ok(ArchiveBody {
        packed,
        header: encode_encoded_header(&header_stream.metadata)?,
    })
}

fn concatenate_entries(entries: &[SevenZEntry]) -> Result<Vec<u8>, Error> {
    let total = entries.iter().try_fold(0usize, |acc, entry| {
        acc.checked_add(entry.data.len())
            .ok_or(Error::InvalidData("7z: solid payload size overflow"))
    })?;
    let mut output = Vec::with_capacity(total);
    for entry in entries {
        output.extend_from_slice(&entry.data);
    }
    Ok(output)
}

fn apply_filters_encode(input: &[u8], filters: &[SevenZFilter]) -> Result<Vec<u8>, Error> {
    let mut data = input.to_vec();
    for filter in filters {
        data = match *filter {
            SevenZFilter::X86Bcj => bcj::x86_encode(&data, 0),
            SevenZFilter::X86Bcj2 => {
                // BCJ2 is handled specially in encode_payload_as_stream
                return Err(Error::InvalidData(
                    "7z: BCJ2 must be the only filter and is handled at the stream level",
                ));
            }
            SevenZFilter::Ia64Bcj => bcj::ia64_encode(&data, 0),
            SevenZFilter::PowerPcBcj => bcj::powerpc_encode(&data, 0),
            SevenZFilter::ArmBcj => bcj::arm_encode(&data, 0),
            SevenZFilter::ArmThumbBcj => bcj::armthumb_encode(&data, 0),
            SevenZFilter::SparcBcj => bcj::sparc_encode(&data, 0),
            SevenZFilter::Arm64Bcj => bcj::arm64_encode(&data, 0),
            SevenZFilter::RiscVBcj => bcj::riscv_encode(&data, 0),
            SevenZFilter::Delta { distance } => delta::encode(&data, usize::from(distance))?,
        };
    }
    Ok(data)
}

fn encode_method(input: &[u8], method: SevenZMethod) -> Result<Vec<u8>, Error> {
    Ok(match method {
        SevenZMethod::Copy => input.to_vec(),
        SevenZMethod::Lzma { dict_size } => {
            let props = lzma::LzmaProperties::LZIP;
            lzma::lzma_encode_with_props_no_eos(input, dict_size, props)
        }
        SevenZMethod::Lzma2 { dict_size } => {
            let canonical = canonical_lzma2_dict_size(dict_size)?;
            lzma2::lzma2_encode(input, canonical)
        }
        SevenZMethod::Ppmd { order, mem_size } => {
            let props = ppmd::Ppmd7Properties::new(order, mem_size)?;
            ppmd::encode(input, props, false)?
        }
        SevenZMethod::Deflate { level } => crate::compress::deflate::encode::encode(input, level),
        SevenZMethod::Deflate64 => crate::compress::deflate64::encode::encode(input),
        SevenZMethod::Bzip2 { level } => {
            crate::compress::bzip2::encode::encode_with_level(input, level)
        }
        #[cfg(feature = "brotli")]
        SevenZMethod::Brotli => crate::compress::brotli::encode::encode(input),
    })
}

fn encode_delta_property(distance: u16) -> Result<u8, Error> {
    if !(1..=256).contains(&distance) {
        return Err(Error::InvalidData("7z: delta distance out of range"));
    }
    Ok((distance - 1) as u8)
}

fn encrypt_packed_data(input: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
    let props = parse_7z_aes_properties(&AES_PROPERTIES)?;
    let key = derive_7z_aes_key(password, &props)?;
    let cipher = Aes256::new(&key);
    Ok(cipher.encrypt_cbc_zero_padded(input, &props.iv))
}

#[derive(Debug)]
struct StreamMetadata {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
    pack_crcs: Vec<u32>,
    folder_crc: u32,
    file_sizes: Vec<u64>,
    file_crcs: Vec<Option<u32>>,
    folder: FolderDescription,
}

impl StreamMetadata {
    fn total_pack_size(&self) -> u64 {
        self.pack_sizes.iter().sum()
    }
}

#[derive(Debug)]
struct FolderDescription {
    coders: Vec<CoderDescription>,
    unpack_sizes: Vec<u64>,
    bind_pairs: Vec<(u64, u64)>,
    packed_streams: Vec<u64>,
}

#[derive(Debug)]
struct CoderDescription {
    method_id: Vec<u8>,
    properties: Vec<u8>,
    num_in_streams: u64,
    num_out_streams: u64,
}

struct EncodedStream {
    packed: Vec<u8>,
    metadata: StreamMetadata,
}

fn encode_payload_as_stream(
    input: &[u8],
    method: SevenZMethod,
    filters: &[SevenZFilter],
    password: Option<&[u8]>,
    pack_pos: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<Option<u32>>,
) -> Result<EncodedStream, Error> {
    // Special path for BCJ2 filter
    if filters.len() == 1 && filters[0] == SevenZFilter::X86Bcj2 {
        return encode_bcj2_stream(input, method, password, pack_pos, file_sizes, file_crcs);
    }

    let filtered = apply_filters_encode(input, filters)?;
    let packed_plain = encode_method(&filtered, method)?;
    let packed_plain_size = packed_plain.len() as u64;
    let packed = if let Some(password) = password {
        encrypt_packed_data(&packed_plain, password)?
    } else {
        packed_plain
    };
    let folder = build_folder(
        method,
        filters,
        password.is_some(),
        packed_plain_size,
        filtered.len() as u64,
        input.len() as u64,
    )?;
    Ok(EncodedStream {
        metadata: StreamMetadata {
            pack_pos,
            pack_sizes: vec![packed.len() as u64],
            pack_crcs: vec![crc32::crc32(&packed)],
            folder_crc: crc32::crc32(input),
            file_sizes,
            file_crcs,
            folder,
        },
        packed,
    })
}

fn encode_bcj2_stream(
    input: &[u8],
    method: SevenZMethod,
    password: Option<&[u8]>,
    pack_pos: u64,
    file_sizes: Vec<u64>,
    file_crcs: Vec<Option<u32>>,
) -> Result<EncodedStream, Error> {
    let encoded = bcj2::encode(input);
    let main_compressed = encode_method(&encoded.main, method)?;
    let main_compressed_size = main_compressed.len() as u64;

    let main_packed = if let Some(password) = password {
        encrypt_packed_data(&main_compressed, password)?
    } else {
        main_compressed
    };

    let mut packed = Vec::new();
    let mut pack_sizes = Vec::new();
    let mut pack_crcs = Vec::new();

    // Pack stream 0: main (possibly encrypted + compressed)
    pack_sizes.push(main_packed.len() as u64);
    pack_crcs.push(crc32::crc32(&main_packed));
    packed.extend_from_slice(&main_packed);

    // Pack stream 1: call stream
    pack_sizes.push(encoded.call.len() as u64);
    pack_crcs.push(crc32::crc32(&encoded.call));
    packed.extend_from_slice(&encoded.call);

    // Pack stream 2: jump stream
    pack_sizes.push(encoded.jump.len() as u64);
    pack_crcs.push(crc32::crc32(&encoded.jump));
    packed.extend_from_slice(&encoded.jump);

    // Pack stream 3: range coder stream
    pack_sizes.push(encoded.rc.len() as u64);
    pack_crcs.push(crc32::crc32(&encoded.rc));
    packed.extend_from_slice(&encoded.rc);

    // Build a folder graph:
    // Coder 0: compression method (input_index=0, output_index=0) - reads from pack[0]
    // Coder 1: BCJ2 (input_index=1..4, output_index=1) - reads from output[0], pack[1..3]
    // Bind pair: BCJ2 input 1 -> compression output 0
    // Coder 2 (optional filter like Copy at final output): final_output_index=2
    // For now: simple 2-coder folder

    let mut coders = Vec::new();
    let mut unpack_sizes = Vec::new();

    // Track cumulative input stream index for bind pair construction
    let mut next_in = 0u64;

    if password.is_some() {
        coders.push(CoderDescription {
            method_id: METHOD_7Z_AES.to_vec(),
            properties: AES_PROPERTIES.to_vec(),
            num_in_streams: 1,
            num_out_streams: 1,
        });
        unpack_sizes.push(main_compressed_size);
        next_in += 1;
    }

    // Compression coder
    let compression_coder = match method {
        SevenZMethod::Copy => CoderDescription {
            method_id: vec![0x00],
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        },
        SevenZMethod::Lzma { dict_size } => {
            let props = lzma::LzmaProperties::LZIP;
            let mut prop_bytes = vec![props.to_props_byte()];
            prop_bytes.extend_from_slice(&dict_size.to_le_bytes());
            CoderDescription {
                method_id: vec![0x03, 0x01, 0x01],
                properties: prop_bytes,
                num_in_streams: 1,
                num_out_streams: 1,
            }
        }
        SevenZMethod::Lzma2 { dict_size } => {
            let canonical = canonical_lzma2_dict_size(dict_size)?;
            CoderDescription {
                method_id: vec![0x21],
                properties: vec![encode_lzma2_property(canonical)?],
                num_in_streams: 1,
                num_out_streams: 1,
            }
        }
        SevenZMethod::Ppmd { order, mem_size } => {
            let props = ppmd::Ppmd7Properties::new(order, mem_size)?;
            CoderDescription {
                method_id: vec![0x03, 0x04, 0x01],
                properties: props.to_sevenz_properties().to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
            }
        }
        SevenZMethod::Deflate { .. } => CoderDescription {
            method_id: vec![0x04, 0x01, 0x08],
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        },
        SevenZMethod::Deflate64 => CoderDescription {
            method_id: vec![0x04, 0x01, 0x09],
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        },
        SevenZMethod::Bzip2 { .. } => CoderDescription {
            method_id: vec![0x04, 0x02, 0x02],
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        },
        #[cfg(feature = "brotli")]
        SevenZMethod::Brotli => CoderDescription {
            method_id: vec![0x04, 0xF7, 0x11, 0x01],
            properties: Vec::new(),
            num_in_streams: 1,
            num_out_streams: 1,
        },
    };
    coders.push(compression_coder);
    unpack_sizes.push(encoded.main.len() as u64);
    next_in += 1;

    // BCJ2 coder (4 inputs, 1 output)
    let bcj2_in_start = next_in;
    coders.push(CoderDescription {
        method_id: vec![0x03, 0x03, 0x01, 0x1B],
        properties: Vec::new(),
        num_in_streams: 4,
        num_out_streams: 1,
    });
    unpack_sizes.push(input.len() as u64);

    // Bind pairs:
    // The compression output feeds into BCJ2's first input
    let mut bind_pairs = Vec::new();
    if password.is_some() {
        // AES output 0 -> compression input 1
        bind_pairs.push((1u64, 0u64));
        // compression output 1 -> BCJ2 first input
        bind_pairs.push((bcj2_in_start, 1u64));
    } else {
        // compression output 0 -> BCJ2 first input
        bind_pairs.push((bcj2_in_start, 0u64));
    }

    // Packed streams: pack[0] -> first coder input, pack[1..3] -> BCJ2 inputs [1..3]
    let packed_streams = vec![
        0u64,              // pack[0] -> first coder
        bcj2_in_start + 1, // pack[1] -> BCJ2 call
        bcj2_in_start + 2, // pack[2] -> BCJ2 jump
        bcj2_in_start + 3, // pack[3] -> BCJ2 rc
    ];

    let folder = FolderDescription {
        coders,
        unpack_sizes,
        bind_pairs,
        packed_streams,
    };

    Ok(EncodedStream {
        metadata: StreamMetadata {
            pack_pos,
            pack_sizes,
            pack_crcs,
            folder_crc: crc32::crc32(input),
            file_sizes,
            file_crcs,
            folder,
        },
        packed,
    })
}

fn build_folder(
    method: SevenZMethod,
    filters: &[SevenZFilter],
    encrypted: bool,
    packed_plain_size: u64,
    filtered_size: u64,
    final_size: u64,
) -> Result<FolderDescription, Error> {
    let mut coders = Vec::new();
    let mut unpack_sizes = Vec::new();

    if encrypted {
        coders.push(CoderDescription {
            method_id: METHOD_7Z_AES.to_vec(),
            properties: AES_PROPERTIES.to_vec(),
            num_in_streams: 1,
            num_out_streams: 1,
        });
        unpack_sizes.push(packed_plain_size);
    }

    match method {
        SevenZMethod::Copy => {
            coders.push(CoderDescription {
                method_id: vec![0x00],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Lzma { dict_size } => {
            let props = lzma::LzmaProperties::LZIP;
            let mut prop_bytes = vec![props.to_props_byte()];
            prop_bytes.extend_from_slice(&dict_size.to_le_bytes());
            coders.push(CoderDescription {
                method_id: vec![0x03, 0x01, 0x01],
                properties: prop_bytes,
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Lzma2 { dict_size } => {
            let canonical = canonical_lzma2_dict_size(dict_size)?;
            coders.push(CoderDescription {
                method_id: vec![0x21],
                properties: vec![encode_lzma2_property(canonical)?],
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Ppmd { order, mem_size } => {
            let props = ppmd::Ppmd7Properties::new(order, mem_size)?;
            coders.push(CoderDescription {
                method_id: vec![0x03, 0x04, 0x01],
                properties: props.to_sevenz_properties().to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Deflate { .. } => {
            coders.push(CoderDescription {
                method_id: vec![0x04, 0x01, 0x08],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Deflate64 => {
            coders.push(CoderDescription {
                method_id: vec![0x04, 0x01, 0x09],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        SevenZMethod::Bzip2 { .. } => {
            coders.push(CoderDescription {
                method_id: vec![0x04, 0x02, 0x02],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
        #[cfg(feature = "brotli")]
        SevenZMethod::Brotli => {
            coders.push(CoderDescription {
                method_id: vec![0x04, 0xF7, 0x11, 0x01],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            });
            unpack_sizes.push(filtered_size);
        }
    }

    for filter in filters.iter().rev() {
        coders.push(match *filter {
            SevenZFilter::X86Bcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x01, 0x03],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::X86Bcj2 => {
                // BCJ2 is handled at the stream level, not as a linear filter
                return Err(Error::InvalidData(
                    "7z: BCJ2 must be the only filter and is handled at the stream level",
                ));
            }
            SevenZFilter::Ia64Bcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x04, 0x01],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::PowerPcBcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x02, 0x05],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::ArmBcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x05, 0x01],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::ArmThumbBcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x07, 0x01],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::SparcBcj => CoderDescription {
                method_id: vec![0x03, 0x03, 0x08, 0x05],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::Arm64Bcj => CoderDescription {
                method_id: vec![0x0A],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::RiscVBcj => CoderDescription {
                method_id: vec![0x0B],
                properties: Vec::new(),
                num_in_streams: 1,
                num_out_streams: 1,
            },
            SevenZFilter::Delta { distance } => CoderDescription {
                method_id: vec![0x03],
                properties: vec![encode_delta_property(distance)?],
                num_in_streams: 1,
                num_out_streams: 1,
            },
        });
        unpack_sizes.push(final_size);
    }

    if unpack_sizes.is_empty() {
        unpack_sizes.push(final_size);
    }

    // For linear folders, build simple bind pairs and packed_streams
    let num_coders = coders.len();
    let mut bind_pairs = Vec::new();
    for index in 0..num_coders.saturating_sub(1) {
        bind_pairs.push(((index + 1) as u64, index as u64));
    }
    let packed_streams = vec![0u64];

    Ok(FolderDescription {
        coders,
        unpack_sizes,
        bind_pairs,
        packed_streams,
    })
}

fn encode_header(
    entries: &[SevenZEntry],
    streams: Option<&[StreamMetadata]>,
) -> Result<Vec<u8>, Error> {
    let mut header = Vec::new();
    header.push(NID_HEADER);

    if let Some(streams) = streams {
        header.push(NID_MAIN_STREAMS_INFO);
        encode_streams_info(&mut header, streams)?;
    }

    header.push(NID_FILES_INFO);
    encode_uint64(&mut header, entries.len() as u64);
    encode_names_property(&mut header, entries);
    encode_attributes_property(&mut header, entries);
    encode_filetime_property(&mut header, entries, NID_CTIME, |e| e.ctime);
    encode_filetime_property(&mut header, entries, NID_ATIME, |e| e.atime);
    encode_filetime_property(&mut header, entries, NID_MTIME, |e| e.mtime);
    header.push(NID_END);
    header.push(NID_END);
    Ok(header)
}

fn encode_encoded_header(streams: &StreamMetadata) -> Result<Vec<u8>, Error> {
    let mut header = Vec::new();
    header.push(NID_ENCODED_HEADER);
    encode_streams_info(&mut header, core::slice::from_ref(streams))?;
    Ok(header)
}

fn encode_streams_info(output: &mut Vec<u8>, streams: &[StreamMetadata]) -> Result<(), Error> {
    let first_pack_pos = streams.first().map(|stream| stream.pack_pos).unwrap_or(0);
    let total_pack_streams: usize = streams.iter().map(|s| s.pack_sizes.len()).sum();
    output.push(NID_PACK_INFO);
    encode_uint64(output, first_pack_pos);
    encode_uint64(output, total_pack_streams as u64);
    output.push(NID_SIZE);
    for stream in streams {
        for &size in &stream.pack_sizes {
            encode_uint64(output, size);
        }
    }
    output.push(NID_CRC);
    output.push(1);
    for stream in streams {
        for &crc in &stream.pack_crcs {
            output.extend_from_slice(&crc.to_le_bytes());
        }
    }
    output.push(NID_END);

    output.push(NID_UNPACK_INFO);
    output.push(NID_FOLDER);
    encode_uint64(output, streams.len() as u64);
    output.push(0);
    for stream in streams {
        encode_folder(output, &stream.folder)?;
    }
    output.push(NID_CODERS_UNPACK_SIZE);
    for stream in streams {
        for &size in &stream.folder.unpack_sizes {
            encode_uint64(output, size);
        }
    }
    output.push(NID_CRC);
    output.push(1);
    for stream in streams {
        output.extend_from_slice(&stream.folder_crc.to_le_bytes());
    }
    output.push(NID_END);

    let needs_substreams = streams.iter().any(|stream| stream.file_sizes.len() > 1);
    if needs_substreams {
        output.push(NID_SUBSTREAMS_INFO);
        if streams.iter().any(|stream| stream.file_sizes.len() != 1) {
            output.push(NID_NUM_UNPACK_STREAM);
            for stream in streams {
                encode_uint64(output, stream.file_sizes.len() as u64);
            }
        }

        let explicit_sizes_count: usize = streams
            .iter()
            .map(|stream| stream.file_sizes.len().saturating_sub(1))
            .sum();
        if explicit_sizes_count > 0 {
            output.push(NID_SIZE);
            for stream in streams {
                for &size in stream
                    .file_sizes
                    .iter()
                    .take(stream.file_sizes.len().saturating_sub(1))
                {
                    encode_uint64(output, size);
                }
            }
        }

        let explicit_crc_count: usize = streams
            .iter()
            .map(|stream| {
                if stream.file_sizes.len() == 1 {
                    0
                } else {
                    stream.file_crcs.len()
                }
            })
            .sum();
        if explicit_crc_count > 0 {
            output.push(NID_CRC);
            output.push(1);
            for stream in streams {
                if stream.file_sizes.len() > 1 {
                    for crc in &stream.file_crcs {
                        output.extend_from_slice(&crc.unwrap_or(0).to_le_bytes());
                    }
                }
            }
            output.push(NID_END);
        }
    }

    output.push(NID_END);
    Ok(())
}

fn encode_folder(output: &mut Vec<u8>, folder: &FolderDescription) -> Result<(), Error> {
    encode_uint64(output, folder.coders.len() as u64);
    for coder in &folder.coders {
        let method_len = coder.method_id.len();
        if method_len == 0 || method_len > 0x0F {
            return Err(Error::InvalidData("7z: invalid coder method id length"));
        }
        let is_complex = coder.num_in_streams != 1 || coder.num_out_streams != 1;
        let mut flags = method_len as u8;
        if is_complex {
            flags |= 0x10;
        }
        if !coder.properties.is_empty() {
            flags |= 0x20;
        }
        output.push(flags);
        output.extend_from_slice(&coder.method_id);
        if is_complex {
            encode_uint64(output, coder.num_in_streams);
            encode_uint64(output, coder.num_out_streams);
        }
        if !coder.properties.is_empty() {
            encode_uint64(output, coder.properties.len() as u64);
            output.extend_from_slice(&coder.properties);
        }
    }

    // Bind pairs
    for &(in_index, out_index) in &folder.bind_pairs {
        encode_uint64(output, in_index);
        encode_uint64(output, out_index);
    }

    // Packed stream indices (only if more than 1)
    if folder.packed_streams.len() > 1 {
        for &index in &folder.packed_streams {
            encode_uint64(output, index);
        }
    }

    Ok(())
}

fn encode_names_property(output: &mut Vec<u8>, entries: &[SevenZEntry]) {
    let mut data = Vec::new();
    data.push(0);
    for entry in entries {
        for unit in entry.name.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes());
    }
    output.push(NID_NAME);
    encode_uint64(output, data.len() as u64);
    output.extend_from_slice(&data);
}

fn encode_attributes_property(output: &mut Vec<u8>, entries: &[SevenZEntry]) {
    let mut data = Vec::with_capacity(2 + entries.len() * 4);
    data.push(1);
    data.push(0);
    for entry in entries {
        data.extend_from_slice(&entry.attributes.unwrap_or(0x20).to_le_bytes());
    }
    output.push(NID_WIN_ATTRIBUTES);
    encode_uint64(output, data.len() as u64);
    output.extend_from_slice(&data);
}

fn encode_filetime_property(
    output: &mut Vec<u8>,
    entries: &[SevenZEntry],
    nid: u8,
    accessor: fn(&SevenZEntry) -> Option<u64>,
) {
    if !entries.iter().any(|e| accessor(e).is_some()) {
        return;
    }
    let mut data = Vec::with_capacity(2 + entries.len() * 8);
    // all_defined = 1 (all entries have a value, use 0 for absent)
    data.push(1);
    // external = 0
    data.push(0);
    for entry in entries {
        let ts = accessor(entry).unwrap_or(0);
        data.extend_from_slice(&ts.to_le_bytes());
    }
    output.push(nid);
    encode_uint64(output, data.len() as u64);
    output.extend_from_slice(&data);
}

fn encode_uint64(output: &mut Vec<u8>, value: u64) {
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

fn canonical_lzma2_dict_size(dict_size: u32) -> Result<u32, Error> {
    if dict_size == u32::MAX {
        return Ok(u32::MAX);
    }
    for prop in 0..=39 {
        let candidate = decode_lzma2_property(prop)?;
        if candidate >= dict_size.max(4096) {
            return Ok(candidate);
        }
    }
    Err(Error::Unsupported(
        "7z: requested LZMA2 dictionary size is too large",
    ))
}

fn encode_lzma2_property(dict_size: u32) -> Result<u8, Error> {
    if dict_size == u32::MAX {
        return Ok(40);
    }
    for prop in 0..=39u8 {
        if decode_lzma2_property(prop)? == dict_size {
            return Ok(prop);
        }
    }
    Err(Error::InvalidData(
        "7z: LZMA2 dictionary size is not representable",
    ))
}

fn decode_lzma2_property(prop: u8) -> Result<u32, Error> {
    if prop > 40 {
        return Err(Error::InvalidData("7z: invalid LZMA2 property"));
    }
    if prop == 40 {
        return Ok(u32::MAX);
    }
    let base = 2u32 | u32::from(prop & 1);
    let shift = u32::from(prop / 2) + 11;
    Ok(base << shift)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::sevenz::decode::{decode, decode_with_password};
    use crate::compress::lzma::LzmaProperties;

    #[test]
    fn test_encode_empty_archive() {
        let archive = SevenZEncoder::new().finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_encode_copy_method_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Copy);
        encoder.add_file("plain.txt", b"plain text");
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, b"plain text");
    }

    #[test]
    fn test_encode_ppmd_method_roundtrip() {
        let payload = b"PPMd encoder fixture";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.add_file("ppmd.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_delta_and_bcj_roundtrip() {
        let payload = b"The quick brown fox jumps over the lazy dog.".repeat(8);
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![
            SevenZFilter::Delta { distance: 1 },
            SevenZFilter::X86Bcj,
        ]);
        encoder.add_file("combo.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_delta_distance_256_roundtrip() {
        let payload = vec![0x5A; 1024];
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 256 }]);
        encoder.add_file("delta256.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_encrypted_roundtrip() {
        let payload = b"encrypted sevenz payload";
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.add_file("secret.bin", payload);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries[0].name, "secret.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_encrypted_with_wrong_password_fails() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.add_file("secret.bin", b"encrypted sevenz payload");
        let archive = encoder.finish().unwrap();

        assert!(decode_with_password(&archive, "wrong").is_err());
    }

    #[test]
    fn test_encode_encoded_header_roundtrip() {
        let payload = b"encoded header payload";
        let mut encoder = SevenZEncoder::new();
        encoder.set_encoded_header(true);
        encoder.add_file("header.txt", payload);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "header.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_ppmd_encoded_header_roundtrip() {
        let payload = b"ppmd encoded header payload ppmd encoded header payload";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.set_encoded_header(true);
        encoder.add_file("ppmd-header.txt", payload);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ppmd-header.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_ppmd_encrypted_encoded_header_roundtrip() {
        let payload = b"ppmd encrypted encoded header payload";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.add_file("ppmd-secret.txt", payload);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ppmd-secret.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_x86_bcj_encoded_header_roundtrip() {
        let payload = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0x90,
        ];
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.set_encoded_header(true);
        encoder.add_file("bcj-header.bin", &payload);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj-header.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_delta_encoded_header_roundtrip() {
        let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.set_encoded_header(true);
        encoder.add_file("delta-header.bin", &payload);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "delta-header.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_x86_bcj_encrypted_encoded_header_roundtrip() {
        let payload = [
            0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF, 0x90,
        ];
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.set_encoded_header(true);
        encoder.add_file("bcj-secret.bin", &payload);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj-secret.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_delta_encrypted_encoded_header_roundtrip() {
        let payload: Vec<u8> = (0..4096u32).map(|i| ((i * 17) % 251) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.set_encoded_header(true);
        encoder.add_file("delta-secret.bin", &payload);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "delta-secret.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_encrypted_encoded_header_roundtrip() {
        let payload = b"encrypted encoded header payload";
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.add_file("secret.txt", payload);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "secret.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_two_folder_copy_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Copy);
        encoder.set_two_folder_split(1);
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
    fn test_encode_two_folder_with_multiple_files_in_first_folder() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Copy);
        encoder.set_two_folder_split(2);
        encoder.add_file("alpha.txt", b"alpha");
        encoder.add_file("beta.txt", b"beta");
        encoder.add_file("gamma.txt", b"gamma");
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].data, b"alpha");
        assert_eq!(entries[1].data, b"beta");
        assert_eq!(entries[2].data, b"gamma");
    }

    #[test]
    fn test_encode_two_folder_encrypted_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_password("secret");
        encoder.set_two_folder_split(1);
        encoder.add_file("left.bin", b"left payload");
        encoder.add_file("right.bin", b"right payload");
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"left payload");
        assert_eq!(entries[1].data, b"right payload");
    }

    #[test]
    fn test_encode_two_folder_encoded_header_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_encoded_header(true);
        encoder.add_file("alpha.txt", b"alpha payload");
        encoder.add_file("beta.txt", b"beta payload");
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"alpha payload");
        assert_eq!(entries[1].data, b"beta payload");
    }

    #[test]
    fn test_encode_two_folder_encrypted_encoded_header_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.add_file("alpha.txt", b"alpha payload");
        encoder.add_file("beta.txt", b"beta payload");
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"alpha payload");
        assert_eq!(entries[1].data, b"beta payload");
    }

    #[test]
    fn test_encode_two_folder_x86_bcj_roundtrip() {
        let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
        let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_delta_roundtrip() {
        let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
        let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_x86_bcj_encoded_header_roundtrip() {
        let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
        let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_encoded_header(true);
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_delta_encoded_header_roundtrip() {
        let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
        let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_encoded_header(true);
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_ppmd_encrypted_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.add_file("alpha.txt", b"first encrypted ppmd payload");
        encoder.add_file("beta.txt", b"second encrypted ppmd payload");
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"first encrypted ppmd payload");
        assert_eq!(entries[1].data, b"second encrypted ppmd payload");
    }

    #[test]
    fn test_encode_two_folder_ppmd_encoded_header_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.set_two_folder_split(1);
        encoder.set_encoded_header(true);
        encoder.add_file("alpha.txt", b"first ppmd encoded-header payload");
        encoder.add_file("beta.txt", b"second ppmd encoded-header payload");
        let archive = encoder.finish().unwrap();

        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, b"first ppmd encoded-header payload");
        assert_eq!(entries[1].data, b"second ppmd encoded-header payload");
    }

    #[test]
    fn test_encode_two_folder_ppmd_encrypted_encoded_header_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Ppmd {
            order: 6,
            mem_size: 1 << 20,
        });
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.add_file("alpha.txt", b"first encrypted ppmd encoded-header payload");
        encoder.add_file("beta.txt", b"second encrypted ppmd encoded-header payload");
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].data,
            b"first encrypted ppmd encoded-header payload"
        );
        assert_eq!(
            entries[1].data,
            b"second encrypted ppmd encoded-header payload"
        );
    }

    #[test]
    fn test_encode_two_folder_x86_bcj_encrypted_roundtrip() {
        let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
        let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_x86_bcj_encrypted_encoded_header_roundtrip() {
        let payload0 = [0x90, 0xE8, 0x78, 0x56, 0x34, 0x12, 0x90, 0xE9, 0xF0, 0xFF];
        let payload1 = [0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90, 0xE9, 0x10, 0x00];
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.set_filters(vec![SevenZFilter::X86Bcj]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_delta_encrypted_roundtrip() {
        let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
        let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_encode_two_folder_delta_encrypted_encoded_header_roundtrip() {
        let payload0: Vec<u8> = (0..2048u32).map(|i| ((i * 17) % 251) as u8).collect();
        let payload1: Vec<u8> = (0..2048u32).map(|i| ((i * 29) % 253) as u8).collect();
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(1);
        encoder.set_password("secret");
        encoder.set_encoded_header(true);
        encoder.set_filters(vec![SevenZFilter::Delta { distance: 4 }]);
        encoder.add_file("alpha.bin", &payload0);
        encoder.add_file("beta.bin", &payload1);
        let archive = encoder.finish().unwrap();

        assert!(decode(&archive).is_err());
        let entries = decode_with_password(&archive, "secret").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, payload0);
        assert_eq!(entries[1].data, payload1);
    }

    #[test]
    fn test_two_folder_split_requires_two_non_empty_folders() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_two_folder_split(0);
        encoder.add_file("alpha.txt", b"alpha");
        assert!(matches!(encoder.finish(), Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_encode_multi_folder_roundtrip() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Copy);
        for i in 0..7 {
            encoder.add_file(&alloc::format!("f{i}.txt"), &[b'0' + i as u8; 64]);
        }
        // Three solid folders: [0..2), [2..5), [5..7).
        encoder.set_folder_splits(&[2, 5]);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 7);
        for (i, e) in entries.iter().enumerate() {
            assert_eq!(e.data, vec![b'0' + i as u8; 64]);
        }
    }

    #[test]
    fn test_folder_splits_validation() {
        let mut encoder = SevenZEncoder::new();
        encoder.set_folder_splits(&[3, 1]); // not increasing
        for i in 0..4 {
            encoder.add_file(&alloc::format!("f{i}"), b"x");
        }
        assert!(encoder.finish().is_err());

        let mut encoder = SevenZEncoder::new();
        encoder.set_folder_splits(&[4]); // empty tail folder
        for i in 0..4 {
            encoder.add_file(&alloc::format!("f{i}"), b"x");
        }
        assert!(encoder.finish().is_err());

        let mut encoder = SevenZEncoder::new();
        encoder.set_folder_splits(&[0, 2]); // empty head folder
        for i in 0..4 {
            encoder.add_file(&alloc::format!("f{i}"), b"x");
        }
        assert!(encoder.finish().is_err());
    }

    #[test]
    fn test_canonical_lzma2_dict_size_rounds_up() {
        let size = canonical_lzma2_dict_size((1 << 20) + 1).unwrap();
        assert!(size > (1 << 20));
        assert_eq!(encode_lzma2_property(size).unwrap(), 17);
    }

    #[test]
    fn test_lzma_property_byte_matches_lzip_default() {
        assert_eq!(LzmaProperties::LZIP.to_props_byte(), 0x5D);
    }

    #[test]
    fn test_encode_lzma_method_roundtrip() {
        let payload = b"LZMA method roundtrip test data for sevenz archive";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Lzma { dict_size: 1 << 20 });
        encoder.add_file("lzma.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "lzma.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn test_encode_brotli_method_roundtrip() {
        let payload = b"Brotli method roundtrip test data for sevenz archive";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Brotli);
        encoder.add_file("brotli.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "brotli.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_deflate_method_roundtrip() {
        let payload = b"Deflate method roundtrip test data for sevenz archive";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Deflate {
            level: crate::compress::deflate::encode::Level::Default,
        });
        encoder.add_file("deflate.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "deflate.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_deflate64_method_roundtrip() {
        let payload = b"Deflate64 method roundtrip payload ".repeat(200);
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Deflate64);
        encoder.add_file("deflate64.txt", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "deflate64.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_bzip2_method_roundtrip() {
        let payload = b"BZip2 method roundtrip test data for sevenz archive";
        let mut encoder = SevenZEncoder::new();
        encoder.set_method(SevenZMethod::Bzip2 { level: 9 });
        encoder.add_file("bzip2.txt", payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bzip2.txt");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_bcj2_roundtrip() {
        // Simple x86-like data with CALL and JMP instructions
        let mut payload = Vec::new();
        payload.push(0x90); // NOP
        payload.push(0xE8); // CALL
        payload.extend_from_slice(&0x00001234u32.to_le_bytes());
        payload.push(0x90); // NOP
        payload.push(0xE9); // JMP
        payload.extend_from_slice(&0xFFFFFF00u32.to_le_bytes());
        payload.push(0x90); // NOP
        // Add some plain padding
        payload.extend_from_slice(&[0x90; 64]);

        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::X86Bcj2]);
        encoder.add_file("bcj2.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "bcj2.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_powerpc_bcj_roundtrip() {
        // PowerPC instructions are 4-byte aligned.
        // Create a simple payload that exercises the filter.
        let mut payload = vec![0u8; 256];
        // PowerPC branch instruction: opcode 18 (bits 0-5 = 0b010010)
        // 0x48000010 = branch +16
        for i in (0..payload.len()).step_by(4) {
            payload[i] = 0x48;
            payload[i + 1] = 0x00;
            payload[i + 2] = 0x00;
            payload[i + 3] = 0x10;
        }

        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::PowerPcBcj]);
        encoder.add_file("ppc.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ppc.bin");
        assert_eq!(entries[0].data, payload);
    }

    #[test]
    fn test_encode_ia64_bcj_roundtrip() {
        // IA-64 (Itanium) instructions are organized in 128-bit (16-byte) bundles.
        // Create a payload that exercises the filter.
        let mut payload = vec![0u8; 256];
        // Fill with a pattern that looks like IA-64 bundles.
        // Each 16-byte bundle starts with a template byte followed by 3 instruction slots.
        for i in (0..payload.len()).step_by(16) {
            // Template byte 0x05 = MII template (slot types that include branch-like ops)
            payload[i] = 0x05;
            // Fill remaining 15 bytes with a non-trivial pattern
            for j in 1..16 {
                payload[i + j] = (i + j) as u8;
            }
        }

        let mut encoder = SevenZEncoder::new();
        encoder.set_filters(vec![SevenZFilter::Ia64Bcj]);
        encoder.add_file("ia64.bin", &payload);
        let archive = encoder.finish().unwrap();
        let entries = decode(&archive).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ia64.bin");
        assert_eq!(entries[0].data, payload);
    }
}
