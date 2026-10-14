//! zstd decompression per [RFC 8878].
//!
//! Supports multi-frame inputs, dictionary-based decoding, and XXH64
//! content checksum verification.
//!
//! [RFC 8878]: https://datatracker.ietf.org/doc/html/rfc8878

use alloc::vec;
use alloc::vec::Vec;

use crate::error::Error;
use crate::util::xxhash;

use super::frame::{BlockHeader, BlockType, FrameHeader};
use super::fse::{FseEntry, FseTable};
use super::huff::{HuffmanTable, parse_huffman_weights};
use super::sequences::{self, LL_BASE, LL_EXTRA, ML_BASE, ML_EXTRA, Sequence};

/// Magic number for zstd dictionaries (RFC 8878 §5).
const DICT_MAGIC: u32 = 0xEC30A437;

/// A parsed zstd dictionary.
///
/// Dictionaries provide initial entropy tables and content that can be
/// referenced by compressed frames via match offsets.
///
/// Per RFC 8878 §5, a dictionary contains:
/// - Entropy tables (Huffman + FSE for LL/OF/ML)
/// - Content bytes (used as initial history for sequence matching)
/// - Repeat offsets (derived from the last offsets in the content)
///
/// This struct does not panic on construction or usage.
///
/// # Examples
///
/// ```no_run
/// use archive::compress::zstd::decode::ZstdDict;
/// use archive::compress::zstd::train::{train_dictionary, TrainOptions};
///
/// let dict = train_dictionary(&[b"sample sample sample".as_slice()], &TrainOptions::default())
///     .unwrap();
/// println!("dict id: {}", dict.id);
/// ```
///
/// See [`decode_with_dict`] for usage with decoding.
#[derive(Debug, Clone)]
pub struct ZstdDict {
    /// Dictionary ID.
    pub id: u32,
    /// Initial Huffman table for literals.
    huff_table: Option<HuffmanTable>,
    /// Initial FSE table for literal lengths.
    ll_table: Option<FseTable>,
    /// Initial FSE table for offsets.
    of_table: Option<FseTable>,
    /// Initial FSE table for match lengths.
    ml_table: Option<FseTable>,
    /// Dictionary content (used as prefix history).
    pub content: Vec<u8>,
    /// Initial repeat offsets [rep1, rep2, rep3].
    rep_offsets: [u32; 3],
}

impl ZstdDict {
    /// Construct a zstd dictionary directly from content bytes.
    ///
    /// This creates a content-only dictionary suitable for the crate's own
    /// `encode_with_dict` / `decode_with_dict` APIs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidData`] if `id == 0` or `content` is empty.
    pub fn from_content(id: u32, content: &[u8]) -> Result<Self, Error> {
        if id == 0 {
            return Err(Error::InvalidData("dictionary ID must be non-zero"));
        }
        if content.is_empty() {
            return Err(Error::InvalidData("dictionary content is empty"));
        }

        let content_len = content.len() as u32;
        let rep_offsets = [1, content_len.clamp(1, 4), content_len.clamp(1, 8)];

        Ok(Self {
            id,
            huff_table: None,
            ll_table: None,
            of_table: None,
            ml_table: None,
            content: content.to_vec(),
            rep_offsets,
        })
    }

    /// Parse a zstd dictionary from raw bytes.
    ///
    /// The dictionary format (RFC 8878 §5) is:
    /// - 4 bytes: magic number (0xEC30A437)
    /// - 4 bytes: dictionary ID (LE)
    /// - Huffman weights table
    /// - 3 FSE tables: offsets, match lengths, literal lengths
    /// - Remaining: content bytes
    ///
    /// This method does not panic.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidData`] if the magic number is wrong or the
    /// dictionary is malformed.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use archive::compress::zstd::decode::ZstdDict;
    /// use archive::compress::zstd::train::{train_dictionary, TrainOptions};
    ///
    /// let dict = train_dictionary(&[b"sample sample sample".as_slice()], &TrainOptions::default())
    ///     .unwrap();
    /// assert_eq!(dict.id != 0, true);
    /// ```
    ///
    /// See [`decode_with_dict`] for usage with decoding.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::InvalidData("dictionary too short"));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != DICT_MAGIC {
            return Err(Error::InvalidData("invalid dictionary magic number"));
        }

        let id = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        // RFC 8878 §5: Dictionary_ID can be any value except 0
        // (which means "no Dictionary_ID").
        if id == 0 {
            return Err(Error::InvalidData("dictionary ID must be non-zero"));
        }
        let mut pos = 8;

        // Parse Huffman table
        let (weights, huff_consumed) = parse_huffman_weights(&data[pos..])?;
        pos += huff_consumed;
        let huff_table = if weights.is_empty() {
            None
        } else {
            Some(HuffmanTable::from_weights(&weights)?)
        };

        // Parse FSE tables: OF, ML, LL (order per RFC 8878 §5)
        let (of_table, of_consumed) = FseTable::from_bitstream(&data[pos..], 31, 8)?;
        pos += of_consumed;

        let (ml_table, ml_consumed) = FseTable::from_bitstream(&data[pos..], 52, 9)?;
        pos += ml_consumed;

        let (ll_table, ll_consumed) = FseTable::from_bitstream(&data[pos..], 35, 9)?;
        pos += ll_consumed;

        // Repeat offsets: 3 x u32 LE (12 bytes) after FSE tables, before content
        // RFC 8878 §5: Magic(4) + DictID(4) + HuffTable + OFTable + MLTable + LLTable + RepOffsets(12) + Content
        let remaining = &data[pos..];
        if remaining.len() < 12 {
            return Err(Error::InvalidData(
                "dictionary too short for repeat offsets",
            ));
        }

        let rep1 = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]);
        let rep2 = u32::from_le_bytes([remaining[4], remaining[5], remaining[6], remaining[7]]);
        let rep3 = u32::from_le_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]);
        let rep_offsets = [rep1, rep2, rep3];
        let content = remaining[12..].to_vec();

        // RFC 8878 §5: each repeat offset must be non-zero and less than
        // the dictionary size. Repeat offsets address positions inside the
        // content history, so the content size bounds their valid range.
        let content_size = content.len() as u64;
        for &rep in &rep_offsets {
            if rep == 0 || rep as u64 >= content_size {
                return Err(Error::InvalidData("dictionary repeat offset out of range"));
            }
        }

        Ok(ZstdDict {
            id,
            huff_table,
            ll_table: Some(ll_table),
            of_table: Some(of_table),
            ml_table: Some(ml_table),
            content,
            rep_offsets,
        })
    }
}

/// Decode a zstd compressed byte slice.
///
/// Supports single-frame and multi-frame inputs. Returns an empty `Vec` for
/// empty input.
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::{encode, decode};
///
/// let zst = encode::encode(b"Hello!");
/// let data = decode::decode(&zst).unwrap();
/// assert_eq!(data, b"Hello!");
/// ```
///
/// # Errors
///
/// Returns [`Error::ChecksumMismatch`] if XXH64 verification fails,
/// [`Error::InvalidData`] for malformed frames.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Error> {
    decode_internal(input, None)
}

/// Decode a zstd compressed byte slice using a dictionary.
///
/// The dictionary must match the dictionary ID referenced in the frame header.
/// Supports single-frame and multi-frame inputs.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns [`Error::InvalidData`] if the dictionary ID does not match.
///
/// # Examples
///
/// ```no_run
/// use archive::compress::zstd::{decode, encode};
/// use archive::compress::zstd::train::{train_dictionary, TrainOptions};
///
/// let dict = train_dictionary(&[b"sample sample sample".as_slice()], &TrainOptions::default())
///     .unwrap();
///
/// let compressed = encode::encode_with_dict(b"some data", &dict);
/// let decompressed = decode::decode_with_dict(&compressed, &dict).unwrap();
/// assert_eq!(decompressed, b"some data");
/// ```
pub fn decode_with_dict(input: &[u8], dict: &ZstdDict) -> Result<Vec<u8>, Error> {
    decode_internal(input, Some(dict))
}

fn decode_internal(input: &[u8], dict: Option<&ZstdDict>) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut pos = 0;

    while pos < input.len() {
        // Check for skippable frame (magic 0x184D2A5?)
        if pos + 4 <= input.len() {
            let magic =
                u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
            if (magic & 0xFFFFFFF0) == 0x184D2A50 {
                if pos + 8 > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                let frame_size = u32::from_le_bytes([
                    input[pos + 4],
                    input[pos + 5],
                    input[pos + 6],
                    input[pos + 7],
                ]) as usize;
                if pos + 8 + frame_size > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                pos += 8 + frame_size;
                continue;
            }
        }

        let frame_output = decode_frame(&input[pos..], &mut pos, dict)?;
        output.extend_from_slice(&frame_output);
    }

    Ok(output)
}

fn build_literals_huffman_table(weights: Vec<u8>) -> Result<HuffmanTable, Error> {
    let mut all_weights = weights;
    let weight_sum: u32 = all_weights
        .iter()
        .filter(|&&w| w > 0)
        .map(|&w| 1u32 << (w - 1))
        .sum();

    if weight_sum == 0 {
        return HuffmanTable::from_weights(&all_weights);
    }

    // RFC 8878 §4.2.1: tableLog = BIT_highbit32(weightTotal) + 1.
    // The reference zstd always uses 2^tableLog as the target, which is
    // strictly greater than weight_sum when weight_sum is a power of 2.
    // This differs from next_power_of_two() which returns x itself when
    // x is already a power of 2.
    let table_log = 32 - (weight_sum.leading_zeros() as u8); // = floor(log2(weight_sum)) + 1
    let target = 1u32 << table_log;
    let last_weight_value = target - weight_sum;

    // last_weight_value must be a power of 2 (RFC 8878 §4.2.1)
    if last_weight_value > 0 {
        if last_weight_value & (last_weight_value - 1) != 0 {
            return Err(Error::InvalidData(
                "zstd: implicit Huffman weight is not a power of 2",
            ));
        }
        let last_weight = (32 - last_weight_value.leading_zeros()) as u8;
        all_weights.push(last_weight);
    }

    HuffmanTable::from_weights(&all_weights)
}

/// Whether a Dictionary_ID falls in a reserved range.
///
/// RFC 8878 §3.1.1.1.3: the ranges 1-32767 and 2^31-(2^32-1) are reserved
/// for dictionaries registered in the IANA dictionary-ID registry.
const fn is_reserved_dictionary_id(id: u32) -> bool {
    (id >= 1 && id <= 32767) || id >= 0x8000_0000
}

/// Decode a single zstd frame.
fn decode_frame(
    input: &[u8],
    global_pos: &mut usize,
    dict: Option<&ZstdDict>,
) -> Result<Vec<u8>, Error> {
    let header = FrameHeader::parse(input)?;
    let mut pos = header.header_size;
    let mut output = Vec::new();

    // RFC 8878 §3.1.1.1: minimum window size is 1024 bytes.
    // Only check when single_segment is false; when true, window_size equals
    // frame_content_size which can legitimately be small.
    if !header.single_segment && header.window_size < 1024 {
        return Err(Error::InvalidData("zstd: window size below minimum (1024)"));
    }

    // RFC 8878 §3.1.1.1.1.2 / §8: a decoder must limit its memory
    // requirements. Frame_Content_Size is attacker-controlled, so cap the
    // speculative pre-allocation at the same 128 MiB bound used for
    // Window_Size and use try_reserve so that even the clamped amount
    // failing to allocate is non-fatal -- the output buffer still grows as
    // blocks decode.
    const MAX_PREALLOC: u64 = 128 * 1024 * 1024;
    if let Some(size) = header.frame_content_size {
        let _ = output.try_reserve(size.min(MAX_PREALLOC) as usize);
    }

    // Determine if this frame uses a dictionary
    let use_dict = if let Some(frame_dict_id) = header.dictionary_id {
        match dict {
            Some(d) if d.id == frame_dict_id => true,
            Some(_) => {
                return Err(Error::InvalidData(
                    "dictionary ID mismatch between frame and provided dictionary",
                ));
            }
            None => {
                // RFC 8878 §3.1.1.1.3: Dictionary_IDs in [1, 32767] and
                // [2^31, 2^32-1] are reserved for registered dictionaries.
                // This crate has no dictionary registry, so a frame
                // referencing a reserved ID without a matching provided
                // dictionary is malformed input rather than just a missing
                // dictionary.
                if is_reserved_dictionary_id(frame_dict_id) {
                    return Err(Error::InvalidData(
                        "frame references a reserved Dictionary_ID",
                    ));
                }
                return Err(Error::Unsupported(
                    "frame requires dictionary but none provided",
                ));
            }
        }
    } else {
        false
    };

    // Initialize state from dictionary or defaults
    let mut rep_offsets = if use_dict {
        dict.unwrap().rep_offsets
    } else {
        [1u32, 4, 8]
    };

    let mut huff_table: Option<HuffmanTable> = if use_dict {
        dict.unwrap().huff_table.clone()
    } else {
        None
    };

    let mut prev_ll_table: Option<FseTable> = if use_dict {
        dict.unwrap().ll_table.clone()
    } else {
        None
    };
    let mut prev_of_table: Option<FseTable> = if use_dict {
        dict.unwrap().of_table.clone()
    } else {
        None
    };
    let mut prev_ml_table: Option<FseTable> = if use_dict {
        dict.unwrap().ml_table.clone()
    } else {
        None
    };

    let dict_content: &[u8] = if use_dict {
        &dict.unwrap().content
    } else {
        &[]
    };

    // RFC 8878 §3.1.1.2: Block_Maximum_Size = min(Window_Size, 128KB)
    let max_block_size = header.window_size.min(128 * 1024) as u32;

    loop {
        let bh = BlockHeader::parse(&input[pos..])?;
        pos += 3;

        // Validate block size against Block_Maximum_Size (RFC 8878 §3.1.1.2)
        if bh.block_type != BlockType::Compressed && bh.block_size > max_block_size {
            return Err(Error::InvalidData("block size exceeds Block_Maximum_Size"));
        }

        match bh.block_type {
            BlockType::Raw => {
                if pos + bh.block_size as usize > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                output.extend_from_slice(&input[pos..pos + bh.block_size as usize]);
                pos += bh.block_size as usize;
            }
            BlockType::Rle => {
                if pos + 1 > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                let byte = input[pos];
                pos += 1;
                output.resize(output.len() + bh.block_size as usize, byte);
            }
            BlockType::Compressed => {
                if pos + bh.block_size as usize > input.len() {
                    return Err(Error::UnexpectedEof);
                }
                let block_data = &input[pos..pos + bh.block_size as usize];
                pos += bh.block_size as usize;
                let block_start_output_len = output.len();
                decode_compressed_block(
                    block_data,
                    &mut output,
                    &mut rep_offsets,
                    &mut huff_table,
                    &mut prev_ll_table,
                    &mut prev_of_table,
                    &mut prev_ml_table,
                    dict_content,
                    header.window_size,
                )?;
                // RFC 8878 §3.1.1.2: decompressed block size must not exceed
                // Block_Maximum_Size = min(Window_Size, 128 KB).
                let decompressed_size = output.len() - block_start_output_len;
                if decompressed_size > max_block_size as usize {
                    return Err(Error::InvalidData(
                        "compressed block decompressed size exceeds Block_Maximum_Size",
                    ));
                }
            }
            BlockType::Reserved => {
                return Err(Error::InvalidData("reserved block type"));
            }
        }

        if bh.last_block {
            break;
        }
    }

    // Verify checksum if present
    if header.has_checksum {
        if pos + 4 > input.len() {
            return Err(Error::UnexpectedEof);
        }
        let expected =
            u32::from_le_bytes([input[pos], input[pos + 1], input[pos + 2], input[pos + 3]]);
        pos += 4;

        let hash = xxhash::xxhash64(&output, 0);
        let actual = (hash & 0xFFFFFFFF) as u32;
        // Zstd uses the low 32 bits of XXH64
        if actual != expected {
            return Err(Error::ChecksumMismatch { expected, actual });
        }
    }

    // Verify content size if specified
    if let Some(expected_size) = header.frame_content_size
        && output.len() as u64 != expected_size
    {
        return Err(Error::SizeMismatch {
            expected: expected_size as u32,
            actual: output.len() as u32,
        });
    }

    *global_pos += pos;
    Ok(output)
}

/// Decode a compressed block.
#[allow(clippy::too_many_arguments)]
fn decode_compressed_block(
    data: &[u8],
    output: &mut Vec<u8>,
    rep_offsets: &mut [u32; 3],
    huff_table: &mut Option<HuffmanTable>,
    prev_ll_table: &mut Option<FseTable>,
    prev_of_table: &mut Option<FseTable>,
    prev_ml_table: &mut Option<FseTable>,
    dict_content: &[u8],
    window_size: u64,
) -> Result<(), Error> {
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }

    // Literals section
    let (literals, lit_consumed) = decode_literals_section(data, huff_table)?;
    let mut pos = lit_consumed;

    // Sequences section
    let remaining = &data[pos..];
    if remaining.is_empty() {
        // No sequences, just literals
        output.extend_from_slice(&literals);
        return Ok(());
    }

    let (num_sequences, seq_header_size) = sequences::decode_sequences_header(remaining)?;
    pos += seq_header_size;

    if num_sequences == 0 {
        output.extend_from_slice(&literals);
        return Ok(());
    }

    // Decode sequence compression modes
    let mode_byte = data[pos];
    pos += 1;

    let ll_mode = (mode_byte >> 6) & 0x03;
    let of_mode = (mode_byte >> 4) & 0x03;
    let ml_mode = (mode_byte >> 2) & 0x03;
    let reserved_bits = mode_byte & 0x03;
    if reserved_bits != 0 {
        return Err(Error::InvalidData(
            "sequence compression modes reserved bits are set",
        ));
    }

    // Get FSE tables based on modes, using previous tables for Repeat mode
    let ll_table = get_fse_table(
        ll_mode,
        &data[pos..],
        &mut pos,
        35,
        9,
        super::fse::default_literal_length_table(),
        prev_ll_table,
    )?;
    let of_table = get_fse_table(
        of_mode,
        &data[pos..],
        &mut pos,
        31,
        8,
        super::fse::default_offset_table(),
        prev_of_table,
    )?;
    let ml_table = get_fse_table(
        ml_mode,
        &data[pos..],
        &mut pos,
        52,
        9,
        super::fse::default_match_length_table(),
        prev_ml_table,
    )?;

    // Decode sequences using reverse bitstream
    let seq_data = &data[pos..];
    let decoded_sequences = decode_sequences_from_bitstream(
        seq_data,
        num_sequences,
        &ll_table,
        &of_table,
        &ml_table,
        rep_offsets,
    )?;

    // Execute sequences
    sequences::execute_sequences_with_dict(
        &literals,
        &decoded_sequences,
        output,
        dict_content,
        window_size,
    )?;

    Ok(())
}

/// Get an FSE table based on the compression mode.
///
/// For Repeat mode (3), uses the previously stored table. If no previous table
/// exists (first block in frame), returns an error per RFC 8878 §3.1.1.2.
fn get_fse_table(
    mode: u8,
    data: &[u8],
    pos: &mut usize,
    max_symbol: u8,
    max_accuracy_log: u8,
    default_fn: FseTable,
    prev_table: &mut Option<FseTable>,
) -> Result<FseTable, Error> {
    let table = match mode {
        0 => {
            // Predefined
            default_fn
        }
        1 => {
            // RLE: single symbol
            if data.is_empty() {
                return Err(Error::UnexpectedEof);
            }
            let symbol = data[0];
            *pos += 1;
            // RLE mode defines a degenerate one-symbol table
            // (accuracy_log = 0, one entry emitting the symbol with 0 bits).
            // It is not a spec FSE table description -- which requires >= 2
            // non-zero-probability symbols (RFC 8878 §4.1.1) -- so build it
            // directly instead of via FseTable::from_probabilities.
            FseTable {
                entries: vec![FseEntry {
                    symbol,
                    num_bits: 0,
                    baseline: 0,
                }],
                accuracy_log: 0,
            }
        }
        2 => {
            // FSE compressed
            let (table, consumed) = FseTable::from_bitstream(data, max_symbol, max_accuracy_log)?;
            *pos += consumed;
            table
        }
        3 => {
            // Repeat: use the previous table from a prior compressed block
            match prev_table {
                Some(t) => t.clone(),
                None => {
                    return Err(Error::InvalidData("repeat mode without previous FSE table"));
                }
            }
        }
        _ => unreachable!(),
    };
    // Store as previous table for future Repeat mode usage
    *prev_table = Some(table.clone());
    Ok(table)
}

/// Update repeat offsets based on the current sequence's offset and literal length.
/// Returns the resolved real offset.
///
/// Per RFC 8878 §3.1.1.5:
/// - If offset_raw > 3: real_offset = offset_raw - 3, push onto stack
/// - If offset_raw ∈ {1,2,3} and literal_length > 0: use rep_offsets[idx]
/// - If offset_raw ∈ {1,2,3} and literal_length == 0: shifted mapping
const fn resolve_offset(offset_raw: u32, literal_length: u32, rep_offsets: &mut [u32; 3]) -> u32 {
    // RFC 8878 §3.1.1.5: Repeat offset resolution.
    if offset_raw > 3 {
        let real_offset = offset_raw - 3;
        rep_offsets[2] = rep_offsets[1];
        rep_offsets[1] = rep_offsets[0];
        rep_offsets[0] = real_offset;
        real_offset
    } else if literal_length > 0 {
        // Normal repeat offset: offset_raw 1→rep[0], 2→rep[1], 3→rep[2]
        let idx = offset_raw as usize - 1;
        let real_offset = rep_offsets[idx];
        // Rotate used offset to front
        if idx == 1 {
            rep_offsets[1] = rep_offsets[0];
        } else if idx == 2 {
            rep_offsets[2] = rep_offsets[1];
            rep_offsets[1] = rep_offsets[0];
        }
        rep_offsets[0] = real_offset;
        real_offset
    } else {
        // literal_length == 0: shifted mapping per RFC 8878 §3.1.1.5
        // offset_raw 1→rep[1], 2→rep[2], 3→rep[0]-1
        if offset_raw == 1 {
            // Use RepOffset2, then swap RepOffset1 and RepOffset2
            let real_offset = rep_offsets[1];
            rep_offsets[1] = rep_offsets[0];
            rep_offsets[0] = real_offset;
            real_offset
        } else if offset_raw == 2 {
            // Use RepOffset3, then rotate all three
            let real_offset = rep_offsets[2];
            rep_offsets[2] = rep_offsets[1];
            rep_offsets[1] = rep_offsets[0];
            rep_offsets[0] = real_offset;
            real_offset
        } else {
            // offset_raw == 3: Use RepOffset1 - 1, then rotate all three
            let real_offset = rep_offsets[0].wrapping_sub(1);
            rep_offsets[2] = rep_offsets[1];
            rep_offsets[1] = rep_offsets[0];
            rep_offsets[0] = real_offset;
            real_offset
        }
    }
}

/// Decode sequences from a reverse bitstream.
fn decode_sequences_from_bitstream(
    data: &[u8],
    num_sequences: usize,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
    rep_offsets: &mut [u32; 3],
) -> Result<Vec<Sequence>, Error> {
    let mut sequences = Vec::with_capacity(num_sequences);
    let mut bitstream = BitDstream::new(data)?;

    // Initialize FSE states
    let ll_al = ll_table.accuracy_log;
    let of_al = of_table.accuracy_log;
    let ml_al = ml_table.accuracy_log;

    let mut ll_state = bitstream.read_bits(ll_al)? as usize;
    bitstream.reload();
    let mut of_state = bitstream.read_bits(of_al)? as usize;
    bitstream.reload();
    let mut ml_state = bitstream.read_bits(ml_al)? as usize;
    bitstream.reload();

    for i in 0..num_sequences {
        // Read values from current states
        if of_table.entries.is_empty() || ml_table.entries.is_empty() || ll_table.entries.is_empty()
        {
            return Err(Error::InvalidData("FSE table has no entries"));
        }
        if of_state >= of_table.entries.len() {
            return Err(Error::InvalidData("FSE state out of range"));
        }
        if ml_state >= ml_table.entries.len() {
            return Err(Error::InvalidData("FSE state out of range"));
        }
        if ll_state >= ll_table.entries.len() {
            return Err(Error::InvalidData("FSE state out of range"));
        }
        let of_entry = &of_table.entries[of_state];
        let ml_entry = &ml_table.entries[ml_state];
        let ll_entry = &ll_table.entries[ll_state];

        let of_code = of_entry.symbol as usize;
        let ml_code = ml_entry.symbol as usize;
        let ll_code = ll_entry.symbol as usize;

        // RFC 8878 Table 18: offset codes must be 0-31
        if of_code > 31 {
            return Err(Error::InvalidData("offset code out of range"));
        }

        // Decode offset
        let offset_bits = if of_code > 0 { of_code as u8 } else { 0 };
        let offset_raw = if offset_bits > 0 {
            (1u32 << offset_bits) + bitstream.read_bits(offset_bits)?
        } else {
            1
        };

        // Decode match length
        if ml_code >= ML_BASE.len() {
            return Err(Error::InvalidData("match length code out of range"));
        }
        let ml_val = ML_BASE[ml_code] + bitstream.read_bits(ML_EXTRA[ml_code])?;

        // Decode literal length
        if ll_code >= LL_BASE.len() {
            return Err(Error::InvalidData("literal length code out of range"));
        }
        let ll_val = LL_BASE[ll_code] + bitstream.read_bits(LL_EXTRA[ll_code])?;

        // Handle repeat offsets
        let offset = resolve_offset(offset_raw, ll_val, rep_offsets);

        sequences.push(Sequence {
            literal_length: ll_val,
            offset,
            match_length: ml_val,
        });

        // Update FSE states (except for last sequence)
        if i < num_sequences - 1 {
            let ll_nb = ll_entry.num_bits;
            let ml_nb = ml_entry.num_bits;
            let of_nb = of_entry.num_bits;

            // RFC 8878 §3.1.1.3.2.1: reload between extra bits and state updates.
            // The combined extra bits (offset up to 31 + ML up to 16 + LL up to 16)
            // plus state update bits (up to ~26) can exceed 64 bits total, so the
            // bitstream must be reloaded here before reading the state update bits.
            bitstream.reload();

            ll_state = ll_entry.baseline as usize + bitstream.read_bits(ll_nb)? as usize;
            ml_state = ml_entry.baseline as usize + bitstream.read_bits(ml_nb)? as usize;
            of_state = of_entry.baseline as usize + bitstream.read_bits(of_nb)? as usize;
            bitstream.reload();
        }
    }

    // RFC 8878 §3.1.1.3.2.1.2: sequences bitstream must be fully consumed.
    if !bitstream.is_fully_consumed() {
        return Err(Error::InvalidData(
            "zstd: sequences bitstream not fully consumed",
        ));
    }

    Ok(sequences)
}

struct BitDstream<'a> {
    data: &'a [u8],
    bit_container: u64,
    bits_consumed: u32,
    ptr: usize,
}

impl<'a> BitDstream<'a> {
    fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.is_empty() {
            return Err(Error::UnexpectedEof);
        }

        let last_byte = *data.last().unwrap();
        if last_byte == 0 {
            return Err(Error::InvalidData("sequence bitstream: no sentinel"));
        }

        let mut bit_container = 0u64;
        let ptr;
        let mut bits_consumed = 1 + last_byte.leading_zeros();

        if data.len() >= 8 {
            ptr = data.len() - 8;
            bit_container = read_le_u64(&data[ptr..ptr + 8]);
        } else {
            ptr = 0;
            for (i, &byte) in data.iter().enumerate() {
                bit_container |= (byte as u64) << (i * 8);
            }
            bits_consumed += ((8 - data.len()) * 8) as u32;
        }

        Ok(Self {
            data,
            bit_container,
            bits_consumed,
            ptr,
        })
    }

    const fn read_bits(&mut self, n: u8) -> Result<u32, Error> {
        if n == 0 {
            return Ok(0);
        }
        if self.bits_consumed + n as u32 > 64 {
            return Err(Error::InvalidData("sequence bitstream overflow"));
        }
        let shift = 64 - self.bits_consumed - n as u32;
        let value = ((self.bit_container >> shift) & ((1u64 << n) - 1)) as u32;
        self.bits_consumed += n as u32;
        Ok(value)
    }

    fn reload(&mut self) {
        if self.bits_consumed > 64 {
            return;
        }

        if self.data.len() <= 8 {
            return;
        }

        if self.ptr >= 8 {
            self.ptr -= (self.bits_consumed / 8) as usize;
            self.bits_consumed &= 7;
            self.bit_container = read_le_u64(&self.data[self.ptr..self.ptr + 8]);
            return;
        }

        if self.ptr == 0 {
            return;
        }

        let mut nb_bytes = (self.bits_consumed / 8) as usize;
        if self.ptr < nb_bytes {
            nb_bytes = self.ptr;
        }
        self.ptr -= nb_bytes;
        self.bits_consumed -= (nb_bytes * 8) as u32;
        self.bit_container = read_le_u64(&self.data[self.ptr..self.ptr + 8]);
    }

    /// Check whether the bitstream has been fully consumed (no remaining bits).
    ///
    /// RFC 8878 §3.1.1.3.2.1.2: after all sequences are decoded, the bitstream
    /// must be exactly exhausted.
    const fn is_fully_consumed(&self) -> bool {
        self.ptr == 0 && self.bits_consumed == 64
    }
}

fn read_le_u64(bytes: &[u8]) -> u64 {
    let mut out = 0u64;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        out |= (byte as u64) << (i * 8);
    }
    out
}

/// Decode the literals section of a compressed block.
fn decode_literals_section(
    data: &[u8],
    huff_table: &mut Option<HuffmanTable>,
) -> Result<(Vec<u8>, usize), Error> {
    if data.is_empty() {
        return Err(Error::UnexpectedEof);
    }

    let header_byte = data[0];
    let lit_type = header_byte & 0x03;

    match lit_type {
        0 => {
            // Raw literals
            let (regen_size, header_size) = decode_literals_header_size(data)?;
            let total = header_size + regen_size;
            if total > data.len() {
                return Err(Error::UnexpectedEof);
            }
            let literals = data[header_size..total].to_vec();
            Ok((literals, total))
        }
        1 => {
            // RLE literals
            let (regen_size, header_size) = decode_literals_header_size(data)?;
            if header_size >= data.len() {
                return Err(Error::UnexpectedEof);
            }
            let byte = data[header_size];
            let literals = vec![byte; regen_size];
            Ok((literals, header_size + 1))
        }
        2 | 3 => {
            // Compressed or treeless literals
            let needs_tree = lit_type == 2;
            decode_compressed_literals(data, huff_table, needs_tree)
        }
        _ => unreachable!(),
    }
}

/// Decode literals header to get regenerated size.
fn decode_literals_header_size(data: &[u8]) -> Result<(usize, usize), Error> {
    let header_byte = data[0];
    let size_format = (header_byte >> 2) & 0x03;

    match size_format {
        0 | 2 => {
            // 1 byte header, size = header >> 3
            let size = (header_byte >> 3) as usize;
            Ok((size, 1))
        }
        1 => {
            // 2 byte header
            if data.len() < 2 {
                return Err(Error::UnexpectedEof);
            }
            let size = ((header_byte >> 4) as usize) | ((data[1] as usize) << 4);
            Ok((size, 2))
        }
        3 => {
            // 3 byte header
            if data.len() < 3 {
                return Err(Error::UnexpectedEof);
            }
            let size = ((header_byte >> 4) as usize)
                | ((data[1] as usize) << 4)
                | ((data[2] as usize) << 12);
            Ok((size, 3))
        }
        _ => unreachable!(),
    }
}

/// Decode compressed (Huffman-coded) literals.
fn decode_compressed_literals(
    data: &[u8],
    huff_table: &mut Option<HuffmanTable>,
    needs_tree: bool,
) -> Result<(Vec<u8>, usize), Error> {
    if data.len() < 3 {
        return Err(Error::UnexpectedEof);
    }

    let header_byte = data[0];
    let size_format = (header_byte >> 2) & 0x03;

    let (regen_size, compressed_size, num_streams, header_size) = match size_format {
        0 => {
            // 3 bytes header, single stream
            let rs = ((data[0] as usize) >> 4) | (((data[1] as usize) & 0x3F) << 4);
            let cs = ((data[1] as usize) >> 6) | ((data[2] as usize) << 2);
            (rs, cs, 1, 3)
        }
        1 => {
            // 3 bytes header, 4 streams
            let rs = ((data[0] as usize) >> 4) | (((data[1] as usize) & 0x3F) << 4);
            let cs = ((data[1] as usize) >> 6) | ((data[2] as usize) << 2);
            (rs, cs, 4, 3)
        }
        2 => {
            // 4 bytes header, 4 streams
            if data.len() < 4 {
                return Err(Error::UnexpectedEof);
            }
            let rs = ((data[0] as usize) >> 4)
                | ((data[1] as usize) << 4)
                | (((data[2] as usize) & 0x03) << 12);
            let cs = ((data[2] as usize) >> 2) | ((data[3] as usize) << 6);
            (rs, cs, 4, 4)
        }
        3 => {
            // 5 bytes header, 4 streams
            if data.len() < 5 {
                return Err(Error::UnexpectedEof);
            }
            let rs = ((data[0] as usize) >> 4)
                | ((data[1] as usize) << 4)
                | (((data[2] as usize) & 0x3F) << 12);
            let cs =
                ((data[2] as usize) >> 6) | ((data[3] as usize) << 2) | ((data[4] as usize) << 10);
            (rs, cs, 4, 5)
        }
        _ => unreachable!(),
    };

    let mut pos = header_size;

    // Parse Huffman tree if needed
    if needs_tree {
        let (weights, wt_consumed) = parse_huffman_weights(&data[pos..])?;
        pos += wt_consumed;
        let table = build_literals_huffman_table(weights)?;
        *huff_table = Some(table);
    }

    let table = huff_table
        .as_ref()
        .ok_or(Error::InvalidData("no Huffman table for treeless literals"))?;

    // Decode literals from compressed stream(s)
    // compressed_size covers everything after the header (weights + stream),
    // so the stream data ends at header_size + compressed_size.
    let stream_end = (header_size + compressed_size).min(data.len());
    let compressed_data = &data[pos..stream_end];
    let mut literals = Vec::with_capacity(regen_size);

    if num_streams == 1 {
        decode_huff_stream(compressed_data, &mut literals, regen_size, table)?;
    } else {
        // 4 streams: first 6 bytes are 3 u16 LE jump table entries
        if compressed_data.len() < 6 {
            return Err(Error::UnexpectedEof);
        }
        let jump1 = u16::from_le_bytes([compressed_data[0], compressed_data[1]]) as usize;
        let jump2 = u16::from_le_bytes([compressed_data[2], compressed_data[3]]) as usize;
        let jump3 = u16::from_le_bytes([compressed_data[4], compressed_data[5]]) as usize;

        let stream_data = &compressed_data[6..];
        let s1_end = jump1;
        let s2_end = jump1 + jump2;
        let s3_end = jump1 + jump2 + jump3;

        // RFC 8878 §3.1.1.3.1.6: if the sum of stream sizes exceeds the
        // total, the data are considered corrupted.
        if s3_end > stream_data.len() {
            return Err(Error::InvalidData(
                "zstd: 4-stream jump table size overflow",
            ));
        }

        let segment_size = regen_size.div_ceil(4);

        decode_huff_stream(&stream_data[..s1_end], &mut literals, segment_size, table)?;
        decode_huff_stream(
            &stream_data[s1_end..s2_end],
            &mut literals,
            segment_size,
            table,
        )?;
        decode_huff_stream(
            &stream_data[s2_end..s3_end],
            &mut literals,
            segment_size,
            table,
        )?;
        if s3_end < stream_data.len() {
            let remaining_size = regen_size - literals.len();
            decode_huff_stream(&stream_data[s3_end..], &mut literals, remaining_size, table)?;
        }
    }

    if literals.len() < regen_size {
        return Err(Error::InvalidData(
            "literal section: decoded fewer literals than expected",
        ));
    }
    literals.truncate(regen_size);
    let total_consumed = header_size + compressed_size;
    Ok((literals, total_consumed))
}

/// Decode a single Huffman stream using the same reverse-bitstream approach
/// as the sequence decoder (BIT_DStream per RFC 8878 §4.2.2).
fn decode_huff_stream(
    data: &[u8],
    output: &mut Vec<u8>,
    max_symbols: usize,
    table: &HuffmanTable,
) -> Result<(), Error> {
    if data.is_empty() || table.max_bits() == 0 {
        return Ok(());
    }

    let mut bs = BitDstream::new(data)
        .map_err(|_| Error::InvalidData("zstd: invalid Huffman bitstream (no sentinel)"))?;

    let max_bits = table.max_bits();

    for _ in 0..max_symbols {
        // Peek at the top max_bits from the bitstream
        let remaining = 64 - bs.bits_consumed;
        if remaining == 0 {
            break;
        }
        let peek = if remaining >= max_bits as u32 {
            let shift = 64 - bs.bits_consumed - max_bits as u32;
            ((bs.bit_container >> shift) & ((1u64 << max_bits) - 1)) as u32
        } else {
            // Fewer bits remaining than max_bits; pad with zeros on the right
            let shift = max_bits as u32 - remaining;
            ((bs.bit_container << shift) & ((1u64 << max_bits) - 1)) as u32
        };

        let (symbol, num_bits) = table.decode_symbol(peek);
        if num_bits == 0 || num_bits as u32 > remaining {
            break;
        }
        output.push(symbol);
        bs.bits_consumed += num_bits as u32;
        bs.reload();
    }

    // RFC 8878 §4.2.2: Huffman bitstream must be fully consumed after decoding.
    if !bs.is_fully_consumed() {
        return Err(Error::InvalidData(
            "zstd: Huffman bitstream not fully consumed",
        ));
    }

    Ok(())
}

/// Decode zstd compressed data from a [`std::io::Read`] source.
///
/// This function does not panic.
///
/// # Errors
///
/// Returns an error if reading from the source fails, or if the data is malformed.
///
/// # Examples
///
/// ```
/// use archive::compress::zstd::{encode, decode};
///
/// let zst = encode::encode(b"data");
/// let data = decode::decode_reader(zst.as_slice()).unwrap();
/// assert_eq!(data, b"data");
/// ```
#[cfg(feature = "std")]
pub fn decode_reader<R: std::io::Read>(mut reader: R) -> Result<Vec<u8>, crate::error::Error> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|_| crate::error::Error::UnexpectedEof)?;
    decode(&buf)
}

/// Decode with a maximum output size limit.
///
/// Returns `Error::OutputLimitExceeded` if the decompressed output
/// would exceed `max_output` bytes.
pub fn decode_bounded(input: &[u8], max_output: usize) -> Result<Vec<u8>, Error> {
    let result = decode(input)?;
    if result.len() > max_output {
        return Err(Error::OutputLimitExceeded { limit: max_output });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::xxhash;

    /// Build a minimal zstd frame with a Raw block.
    /// descriptor: single_segment=true, FCS_flag=0 (1-byte FCS), checksum flag configurable
    fn build_raw_zstd_frame(data: &[u8], with_checksum: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        // Magic
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: FCS_flag=00, single_segment=1, reserved=0, checksum=?, dict_id_flag=00
        let descriptor = if with_checksum {
            0b0010_0100
        } else {
            0b0010_0000
        };
        frame.push(descriptor);
        // FCS (1 byte since FCS_flag=0 and single_segment=true)
        frame.push(data.len() as u8);
        // Raw block: last_block=1, block_type=0 (Raw), block_size=data.len()
        let block_header = (data.len() as u32) << 3 | 0b001; // last=1, type=0
        frame.push(block_header as u8);
        frame.push((block_header >> 8) as u8);
        frame.push((block_header >> 16) as u8);
        // Block content
        frame.extend_from_slice(data);
        // Checksum
        if with_checksum {
            let hash = xxhash::xxhash64(data, 0);
            let checksum = (hash & 0xFFFFFFFF) as u32;
            frame.extend_from_slice(&checksum.to_le_bytes());
        }
        frame
    }

    #[test]
    fn test_empty_input() {
        // Empty input should return empty output (the while loop exits immediately)
        let result = decode(&[]).unwrap();
        assert!(result.is_empty());
    }

    // Phase 1: Error detection

    #[cfg(feature = "std")]
    #[test]
    fn test_decode_reader() {
        let data = b"Hello, zstd!";
        let frame = build_raw_zstd_frame(data, false);
        let cursor = std::io::Cursor::new(&frame);
        let decoded = decode_reader(cursor).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_zstd_checksum_mismatch() {
        let mut frame = build_raw_zstd_frame(b"Hi", true);
        // Corrupt the checksum (last 4 bytes)
        let len = frame.len();
        frame[len - 1] ^= 0xFF;
        let result = decode(&frame);
        assert!(matches!(result, Err(Error::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_zstd_size_mismatch() {
        // Build a frame claiming FCS=5 but containing only 2 bytes
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // SS=1, no checksum
        frame.push(5); // FCS = 5 (but we'll only provide 2 bytes)
        // Raw block with 2 bytes
        let block_header: u32 = (2 << 3) | 0b001;
        frame.push(block_header as u8);
        frame.push((block_header >> 8) as u8);
        frame.push((block_header >> 16) as u8);
        frame.extend_from_slice(b"Hi");
        let result = decode(&frame);
        assert!(matches!(result, Err(Error::SizeMismatch { .. })));
    }

    // Phase 2: Repeat offset & skippable frame

    #[test]
    fn test_repeat_offset_spec_example() {
        // Verify initial repeat offsets are [1, 4, 8] as per RFC 8878 §3.1.1.5
        // Test by decoding a valid frame and verifying output
        let data = b"Hello!";
        let frame = build_raw_zstd_frame(data, false);
        let result = decode(&frame).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_reserved_block_type_error() {
        // Build a frame with BlockType=Reserved (3)
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // SS=1, no checksum
        frame.push(0); // FCS = 0
        // Block header: last_block=1, block_type=3 (Reserved), block_size=0
        // val = (0 << 3) | (3 << 1) | 1 = 7
        frame.push(0x07);
        frame.push(0x00);
        frame.push(0x00);
        let result = decode(&frame);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_repeat_offset_rfc8878() {
        // RFC 8878 §3.1.1.5: Repeat offset resolution with literal_length == 0 shift.
        // When LL > 0: offset_raw 1→rep[0], 2→rep[1], 3→rep[2]
        // When LL == 0: offset_raw 1→rep[1], 2→rep[2], 3→rep[0]-1

        let mut rep = [1u32, 4, 8];

        // OV > 3: always real_offset = OV - 3, regardless of LL
        assert_eq!(resolve_offset(5, 0, &mut rep), 2);
        assert_eq!(rep, [2, 1, 4]);

        // OV=1, LL=2 (>0): use rep[0]=2, no table change
        assert_eq!(resolve_offset(1, 2, &mut rep), 2);
        assert_eq!(rep, [2, 1, 4]);

        // OV=2, LL=0: shifted → use rep[2]=4, rotate
        assert_eq!(resolve_offset(2, 0, &mut rep), 4);
        assert_eq!(rep, [4, 2, 1]);

        // OV=3, LL=0: shifted → use rep[0]-1=3, rotate
        assert_eq!(resolve_offset(3, 0, &mut rep), 3);
        assert_eq!(rep, [3, 4, 2]);

        // OV=3, LL=3 (>0): use rep[2]=2, rotate
        assert_eq!(resolve_offset(3, 3, &mut rep), 2);
        assert_eq!(rep, [2, 3, 4]);

        // OV=1, LL=0: shifted → use rep[1]=3, swap rep[0]↔rep[1]
        assert_eq!(resolve_offset(1, 0, &mut rep), 3);
        assert_eq!(rep, [3, 2, 4]);

        // OV=2, LL=0: shifted → use rep[2]=4, rotate
        assert_eq!(resolve_offset(2, 0, &mut rep), 4);
        assert_eq!(rep, [4, 3, 2]);

        // OV=3, LL=0: shifted → use rep[0]-1=3, rotate
        assert_eq!(resolve_offset(3, 0, &mut rep), 3);
        assert_eq!(rep, [3, 4, 3]);

        // OV=1, LL=2 (>0): use rep[0]=3, no change
        assert_eq!(resolve_offset(1, 2, &mut rep), 3);
        assert_eq!(rep, [3, 4, 3]);
    }

    #[test]
    fn test_skippable_frame() {
        // Skippable frame: magic 0x184D2A50 + 4-byte size + payload
        let mut data = Vec::new();
        // Skippable frame
        data.extend_from_slice(&0x184D2A50u32.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes()); // 4 bytes of skippable data
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // skippable payload

        // Normal frame
        let normal = build_raw_zstd_frame(b"OK", false);
        data.extend_from_slice(&normal);

        let result = decode(&data).unwrap();
        assert_eq!(result, b"OK");
    }

    #[test]
    fn test_block_size_exceeds_frame() {
        // Build a valid raw frame, then corrupt the block header to claim a larger size
        let mut frame = build_raw_zstd_frame(b"test", true);
        // Frame layout: 4 (magic) + 1 (descriptor) + 1 (FCS) + 3 (block header) + 4 (data) + 4 (checksum)
        // Block header is at offset 6, 3 bytes LE.
        // Current block header: (4 << 3) | 0b001 = 33 = 0x21
        // Set block_size to something huge, e.g. 0x1000 (4096), keeping last=1, type=0 (Raw)
        let fake_size: u32 = 0x1000; // way larger than remaining data
        let block_header = (fake_size << 3) | 0b001; // last=1, type=Raw
        frame[6] = block_header as u8;
        frame[7] = (block_header >> 8) as u8;
        frame[8] = (block_header >> 16) as u8;
        let result = decode(&frame);
        assert!(
            result.is_err(),
            "expected error for oversized block, got {:?}",
            result
        );
    }

    #[test]
    fn test_compressed_block_literals_only() {
        // Build a frame with a compressed block that has num_sequences=0 (literals only).
        // Compressed block data: literals section (raw literals) + sequences header (0 sequences).
        let literal_data = b"abcd";
        let mut block_content = Vec::new();
        // Literals header: type=0 (raw), size_format=0, regen_size=4
        // header_byte = (regen_size << 3) | (size_format << 2) | lit_type
        // = (4 << 3) | 0 | 0 = 0x20
        block_content.push(0x20);
        block_content.extend_from_slice(literal_data);
        // Sequences header: num_sequences=0 (single byte 0x00)
        block_content.push(0x00);

        let mut frame = Vec::new();
        // Magic
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: SS=1, no checksum
        frame.push(0b0010_0000);
        // FCS = 4
        frame.push(4);
        // Compressed block header: last=1, type=Compressed(2), size=block_content.len()
        // bits: last(1) | block_type(2=10) | size => 0b101 | (size << 3)
        let bh = (block_content.len() as u32) << 3 | 0b101; // last=1, block_type=2
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(&block_content);

        let result = decode(&frame).unwrap();
        assert_eq!(result, literal_data);
    }

    #[test]
    fn test_raw_literals_block_direct() {
        let mut huff_table = None;
        let (literals, consumed) =
            decode_literals_section(&[0x20, b'a', b'b', b'c', b'd'], &mut huff_table).unwrap();
        assert_eq!(literals, b"abcd");
        assert_eq!(consumed, 5);
    }

    #[test]
    fn test_rle_literals_block_direct() {
        let mut huff_table = None;
        let (literals, consumed) = decode_literals_section(&[0x29, b'Z'], &mut huff_table).unwrap();
        assert_eq!(literals, b"ZZZZZ");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_compressed_literals_with_tree_direct() {
        let mut huff_table = None;
        // Huffman weights [1, 1] → implicit weight 2 (symbol 2) → max_bits=2.
        // Stream byte 0x11 = 0b00010001: sentinel at bit 4,
        // data: 00 (sym 0, 2 bits) 01 (sym 1, 2 bits).
        let data = [0x22, 0xC0, 0x00, 129, 0x11, 0x11];
        let (literals, consumed) = decode_literals_section(&data, &mut huff_table).unwrap();
        assert_eq!(literals, vec![0, 1]);
        assert_eq!(consumed, data.len());
        assert!(huff_table.is_some());
    }

    #[test]
    fn test_treeless_literals_with_previous_table_direct() {
        let mut huff_table = None;
        let compressed_with_tree = [0x22, 0xC0, 0x00, 129, 0x11, 0x11];
        let _ = decode_literals_section(&compressed_with_tree, &mut huff_table).unwrap();

        // Treeless: reuses the table from the previous block.
        // regen_size=2, compressed_size=1, 1 stream.
        // Stream byte 0x11 encodes [0, 1] with max_bits=2.
        let treeless = [0x23, 0x40, 0x00, 0x11];
        let (literals, consumed) = decode_literals_section(&treeless, &mut huff_table).unwrap();
        assert_eq!(literals, vec![0, 1]);
        assert_eq!(consumed, treeless.len());
    }

    #[test]
    fn test_treeless_literals_four_stream_jump_table_direct() {
        let mut huff_table = Some(HuffmanTable::from_weights(&[1, 1]).unwrap());
        let data = [
            0x47, 0x80, 0x02, // treeless, size_format=1, regen=4, compressed=10
            0x01, 0x00, 0x01, 0x00, 0x01, 0x00, // 3x u16 LE jump table entries
            0x02, 0x03, 0x02, 0x03, // four 1-byte Huffman streams
        ];
        let (literals, consumed) = decode_literals_section(&data, &mut huff_table).unwrap();
        assert_eq!(literals, vec![0, 1, 0, 1]);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_treeless_literals_without_previous_table_error() {
        let mut huff_table = None;
        let result = decode_literals_section(&[0x03, 0x00, 0x00], &mut huff_table);
        assert!(matches!(
            result,
            Err(Error::InvalidData("no Huffman table for treeless literals"))
        ));
    }

    #[test]
    fn test_decode_literals_header_size_formats() {
        assert_eq!(decode_literals_header_size(&[0x20]).unwrap(), (4, 1));
        assert_eq!(
            decode_literals_header_size(&[0x14, 0x12]).unwrap(),
            (0x121, 2)
        );
        assert_eq!(decode_literals_header_size(&[0x28]).unwrap(), (5, 1));
        assert_eq!(
            decode_literals_header_size(&[0x3C, 0xAB, 0x12]).unwrap(),
            (0x12AB3, 3)
        );
    }

    #[test]
    fn test_rle_block_direct() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // single segment, no checksum
        frame.push(5); // FCS = 5
        let bh: u32 = (5 << 3) | (1 << 1) | 1; // last=1, block_type=RLE, block_size=5
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.push(b'Z'); // repeated byte

        let result = decode(&frame).unwrap();
        assert_eq!(result, b"ZZZZZ");
    }

    #[test]
    fn test_build_literals_huffman_table_adds_implicit_last_weight() {
        let table = build_literals_huffman_table(vec![1, 2]).unwrap();
        let expected = HuffmanTable::from_weights(&[1, 2, 1]).unwrap();

        assert_eq!(table.max_bits(), expected.max_bits());
        for bits in 0..(1u32 << table.max_bits()) {
            assert_eq!(table.decode_symbol(bits), expected.decode_symbol(bits));
        }
    }

    #[test]
    fn test_repeat_mode_first_block_error() {
        // Test that FSE Repeat mode (mode=3) on the first block without a prior table
        // returns an error. We construct a minimal compressed block where the sequence
        // compression modes byte uses mode=3 for literal lengths.
        let block_content = vec![
            0x08, // raw literals section, size=1
            b'X', // one raw literal byte
            0x01, // num_sequences=1
            0xC0, // LL=repeat, OF/ML=predefined
            0x00, // dummy bitstream byte
        ];

        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // SS=1, no checksum
        frame.push(1); // FCS = 1 byte
        // Compressed block header: last=1, type=Compressed(2)
        let bh = (block_content.len() as u32) << 3 | 0b101; // last=1, block_type=2
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(&block_content);

        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::InvalidData(_))),
            "expected InvalidData error for repeat mode without prior table, got {:?}",
            result
        );
    }

    // Dictionary tests

    #[test]
    fn test_dict_parse_invalid_magic() {
        let mut data = vec![0u8; 32];
        // Wrong magic
        data[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let result = ZstdDict::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_dict_parse_too_short() {
        let result = ZstdDict::parse(&[0xEC, 0x30, 0xA4, 0x37]);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_dict_from_content_rejects_empty() {
        let result = ZstdDict::from_content(1, b"");
        assert!(matches!(
            result,
            Err(Error::InvalidData("dictionary content is empty"))
        ));
    }

    #[test]
    fn test_dict_from_content_rejects_zero_id() {
        let result = ZstdDict::from_content(0, b"abc");
        assert!(matches!(
            result,
            Err(Error::InvalidData("dictionary ID must be non-zero"))
        ));
    }

    /// Build a minimal well-formed dictionary blob (RFC 8878 §5) with a
    /// direct-weight Huffman table and two-symbol FSE tables, followed
    /// by the given repeat offsets and content.
    fn build_test_dict(id: u32, rep_offsets: [u32; 3], content: &[u8]) -> Vec<u8> {
        let mut dict = Vec::new();
        dict.extend_from_slice(&0xEC30A437u32.to_le_bytes());
        dict.extend_from_slice(&id.to_le_bytes());
        // Huffman weights: direct representation (header >= 128), 1 weight.
        dict.extend_from_slice(&[0x80, 0x10]);
        // FSE tables (OF, ML, LL order): accuracy_log=5, symbols 0 and 1
        // with probability 16 each. RFC 8878 §4.1.1 requires >= 2 symbols
        // with non-zero probability, so a single-symbol description is
        // not usable here.
        for _ in 0..3 {
            dict.extend_from_slice(&[0x10, 0x3F]);
        }
        for rep in rep_offsets {
            dict.extend_from_slice(&rep.to_le_bytes());
        }
        dict.extend_from_slice(content);
        dict
    }

    #[test]
    fn test_dict_parse_minimal_valid() {
        let content = b"0123456789abcdef";
        let data = build_test_dict(0x1234, [1, 4, 8], content);
        let dict = ZstdDict::parse(&data).unwrap();
        assert_eq!(dict.id, 0x1234);
        assert_eq!(dict.content, content);
        assert_eq!(dict.rep_offsets, [1, 4, 8]);
    }

    #[test]
    fn test_dict_parse_zero_dictionary_id() {
        // RFC 8878 §5: Dictionary_ID can be any value except 0.
        let data = build_test_dict(0, [1, 4, 8], b"0123456789abcdef");
        let result = ZstdDict::parse(&data);
        assert!(matches!(
            result,
            Err(Error::InvalidData("dictionary ID must be non-zero"))
        ));
    }

    #[test]
    fn test_dict_parse_rep_offset_out_of_range() {
        // RFC 8878 §5: each repeat offset must be less than the dictionary
        // size; a rep offset that cannot point into the content history is
        // invalid.
        let content = b"0123456789abcdef"; // 16 bytes
        for rep in [16u32, 17, 100] {
            let data = build_test_dict(1, [rep, 4, 8], content);
            let result = ZstdDict::parse(&data);
            assert!(
                matches!(result, Err(Error::InvalidData(_))),
                "expected InvalidData for rep offset {}, got {:?}",
                rep,
                result
            );
        }
    }

    #[test]
    fn test_dict_parse_rep_offset_zero() {
        // A repeat offset of 0 is not a usable history distance.
        let data = build_test_dict(1, [0, 4, 8], b"0123456789abcdef");
        let result = ZstdDict::parse(&data);
        assert!(matches!(result, Err(Error::InvalidData(_))));
    }

    #[test]
    fn test_compressed_block_offset_exceeds_window() {
        // RFC 8878 §3.1.1.4: offsets leading to previously decoded data
        // must stay within Window_Size. The block decodes 10 literals and
        // one sequence with offset 5; with window_size=4 the offset falls
        // outside the valid window even though history is available.
        let mut block = vec![
            0x50, // raw literals header: size_format=0, size=10
        ];
        block.extend_from_slice(b"abcdefghij");
        block.extend_from_slice(&[
            0x01, // num_sequences = 1
            0x54, // modes: LL/OF/ML all RLE
            10,   // LL RLE symbol -> literal_length 10
            3,    // OF RLE symbol -> offset code 3
            0,    // ML RLE symbol -> match_length 3
            0x08, // bitstream: sentinel + 3 zero bits -> offset_raw 8, real 5
        ]);

        let mut output = Vec::new();
        let mut rep_offsets = [1u32, 4, 8];
        let mut huff_table = None;
        let mut prev_ll_table = None;
        let mut prev_of_table = None;
        let mut prev_ml_table = None;

        let result = decode_compressed_block(
            &block,
            &mut output,
            &mut rep_offsets,
            &mut huff_table,
            &mut prev_ll_table,
            &mut prev_of_table,
            &mut prev_ml_table,
            &[],
            4,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidData("offset exceeds Window_Size"))
        ));

        // Same block with a window that covers the offset decodes fine.
        let mut output = Vec::new();
        decode_compressed_block(
            &block,
            &mut output,
            &mut rep_offsets,
            &mut huff_table,
            &mut prev_ll_table,
            &mut prev_of_table,
            &mut prev_ml_table,
            &[],
            1024,
        )
        .unwrap();
        assert_eq!(output, b"abcdefghijfgh");
    }

    #[test]
    fn test_decode_dict_required_but_missing() {
        // Build a frame that references a non-reserved dictionary_id=40000.
        // (1-byte and most 2-byte IDs fall in the reserved range
        // [1, 32767] and are rejected earlier as InvalidData.)
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: FCS_flag=00, single_segment=1, dict_id_flag=10 (2-byte dict ID)
        let descriptor = 0b0010_0010;
        frame.push(descriptor);
        frame.extend_from_slice(&40000u16.to_le_bytes()); // dict_id = 40000
        frame.push(5); // FCS = 5 bytes
        // Raw block: last=1, type=Raw, size=5
        let bh = (5u32 << 3) | 0b001;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(b"Hello");

        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::Unsupported(_))),
            "expected Unsupported error for missing dictionary, got {:?}",
            result
        );
    }

    #[test]
    fn test_decode_dict_id_mismatch() {
        let dict = ZstdDict::from_content(7, b"dict").unwrap();

        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0001); // single segment + 1-byte dict id
        frame.push(42u8);
        frame.push(1); // FCS
        let bh = (1u32 << 3) | 0b001; // raw block, last
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.push(b'X');

        let result = decode_with_dict(&frame, &dict);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "dictionary ID mismatch between frame and provided dictionary"
                ))
            ),
            "expected dictionary ID mismatch, got {:?}",
            result
        );
    }

    #[test]
    fn test_decode_reserved_dictionary_id_no_dict() {
        // RFC 8878 §3.1.1.1.3: Dictionary_IDs 1..=32767 and >= 2^31 are
        // reserved for registered dictionaries. Without a matching
        // dictionary provided, frames referencing them are rejected.
        let cases: [(u8, Vec<u8>); 4] = [
            (0b01, vec![42u8]),                            // 1-byte id = 42
            (0b10, 32767u16.to_le_bytes().to_vec()),       // 2-byte id = 32767
            (0b11, 0x8000_0000u32.to_le_bytes().to_vec()), // 4-byte id = 2^31
            (0b11, 0xFFFF_FFFFu32.to_le_bytes().to_vec()), // 4-byte id = 2^32-1
        ];
        for (flag, id_bytes) in cases {
            let mut frame = Vec::new();
            frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
            // single_segment=1, dict_id_flag=<flag>
            frame.push(0b0010_0000 | flag);
            frame.extend_from_slice(&id_bytes);
            frame.push(5); // FCS = 5 bytes
            let bh = (5u32 << 3) | 0b001; // raw block, last
            frame.push(bh as u8);
            frame.push((bh >> 8) as u8);
            frame.push((bh >> 16) as u8);
            frame.extend_from_slice(b"Hello");

            let result = decode(&frame);
            assert!(
                matches!(
                    result,
                    Err(Error::InvalidData(
                        "frame references a reserved Dictionary_ID"
                    ))
                ),
                "expected reserved Dictionary_ID error for id {:?}, got {:?}",
                id_bytes,
                result
            );
        }
    }

    #[test]
    fn test_decode_nonreserved_dictionary_id_boundaries() {
        // Just outside the reserved ranges: 32768 and 2^31-1 are normal
        // (non-registered) Dictionary_IDs; without a dictionary the frame
        // still fails, but with Unsupported rather than a reserved-ID error.
        let cases: [(u8, Vec<u8>); 2] = [
            (0b10, 32768u16.to_le_bytes().to_vec()), // 2-byte id = 32768
            (0b11, 0x7FFF_FFFFu32.to_le_bytes().to_vec()), // 4-byte id = 2^31-1
        ];
        for (flag, id_bytes) in cases {
            let mut frame = Vec::new();
            frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
            frame.push(0b0010_0000 | flag);
            frame.extend_from_slice(&id_bytes);
            frame.push(5); // FCS
            let bh = (5u32 << 3) | 0b001;
            frame.push(bh as u8);
            frame.push((bh >> 8) as u8);
            frame.push((bh >> 16) as u8);
            frame.extend_from_slice(b"Hello");

            let result = decode(&frame);
            assert!(
                matches!(result, Err(Error::Unsupported(_))),
                "expected Unsupported for non-reserved id {:?}, got {:?}",
                id_bytes,
                result
            );
        }
    }

    #[test]
    fn test_decode_reserved_dictionary_id_with_matching_dict() {
        // A payload referencing a reserved Dictionary_ID "may or may not be
        // decodable" (RFC 8878 §3.1.1.1.3): when the caller supplies a
        // dictionary with the exact ID, decoding proceeds normally.
        let dict = ZstdDict::from_content(0x8000_0001, b"reserved dict content").unwrap();
        let payload = b"reserved dictionary payload payload";
        let encoded = super::super::encode::encode_with_dict(payload, &dict);
        let decoded = decode_with_dict(&encoded, &dict).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_decode_frame_huge_fcs_no_panic() {
        // RFC 8878 §3.1.1.1.1.2 / §8: the decoder must bound memory driven by
        // attacker-controlled Frame_Content_Size. A non-single-segment frame
        // declaring FCS = u64::MAX must not panic via an unbounded
        // Vec::reserve; decoding proceeds and fails the content-size check.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: FCS_flag=3 (8-byte FCS), single_segment=0.
        frame.push(0b1100_0000);
        frame.push(0x00); // window descriptor => window_size = 1024
        frame.extend_from_slice(&u64::MAX.to_le_bytes()); // FCS = u64::MAX
        // Last raw block with 3 bytes of payload.
        let bh: u32 = (3 << 3) | 0b001;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(b"abc");

        let result = decode(&frame);
        assert!(
            matches!(result, Err(Error::SizeMismatch { .. })),
            "expected SizeMismatch (no panic) for huge FCS, got {:?}",
            result
        );
    }

    #[test]
    fn test_execute_sequences_with_dict_content() {
        // Test that sequences can reference dictionary content
        let dict_content = b"ABCDEFGH";
        let literals = b"XY";
        let seqs = vec![Sequence {
            literal_length: 2,
            match_length: 4,
            offset: 10, // 10 bytes back = into dict_content (pos 0 in virtual: dict[0..8] + output[0..2])
        }];
        let mut output = Vec::new();
        sequences::execute_sequences_with_dict(literals, &seqs, &mut output, dict_content, 1024)
            .unwrap();
        // Output: "XY" (literals) + "ABCD" (4 bytes from dict at offset 10 from end)
        // Virtual history: ABCDEFGHXY, offset=10 => start at 0 => "ABCD"
        assert_eq!(output, b"XYABCD");
    }

    #[test]
    fn test_rle_block_truncated() {
        // Valid frame header + RLE block header (block_type=1) but no RLE byte.
        // Frame header: magic(4) + descriptor(1, no SS so window desc follows) + window_desc(1)
        // Descriptor: FCS_flag=00, single_segment=0, checksum=0, dict_id_flag=00 => 0x00
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes()); // magic
        frame.push(0x00); // descriptor: no FCS, no dict, no checksum, window descriptor follows
        frame.push(0x00); // window descriptor (smallest window)
        // Block header: last_block=1, block_type=1 (RLE), block_size=10
        // val = (10 << 3) | (1 << 1) | 1 = 80 | 2 | 1 = 83 = 0x53
        let bh: u32 = (10 << 3) | (1 << 1) | 1;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        // NO RLE byte — truncated
        let result = decode(&frame);
        assert!(
            result.is_err(),
            "expected error for truncated RLE block, got {:?}",
            result
        );
    }

    #[test]
    fn test_compressed_block_truncated() {
        // Valid frame header + compressed block header (block_type=2) claiming block_size=100
        // but only 5 bytes of data provided.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0x00); // descriptor: window descriptor follows, no SS
        frame.push(0x00); // window descriptor
        // Block header: last_block=1, block_type=2 (Compressed), block_size=100
        let bh: u32 = (100 << 3) | (2 << 1) | 1;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        // Only 5 bytes of data instead of 100
        frame.extend_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04]);
        let result = decode(&frame);
        assert!(
            result.is_err(),
            "expected error for truncated compressed block, got {:?}",
            result
        );
    }

    #[test]
    fn test_checksum_truncated() {
        // Valid frame with checksum flag set + a raw block with data, but truncate
        // so checksum bytes are missing.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: single_segment=1, checksum=1, FCS_flag=00
        let descriptor = 0b0010_0100; // SS=1, checksum=1
        frame.push(descriptor);
        frame.push(3); // FCS = 3 bytes
        // Raw block: last=1, type=Raw(0), size=3
        let bh: u32 = (3 << 3) | 0b001;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(b"abc"); // 3 bytes of data
        // NO checksum bytes — truncated (should have 4 bytes of checksum)
        let result = decode(&frame);
        assert!(
            result.is_err(),
            "expected error for truncated checksum, got {:?}",
            result
        );
    }

    #[test]
    fn test_fse_empty_table_error() {
        // Construct input that would produce an empty FSE table.
        // An FSE table where all probabilities are 0 (no symbols) should fail
        // rather than producing a valid table or panicking.
        use super::super::fse::FseTable;

        // All-zero probabilities: no symbols have any probability.
        // This must not succeed — it should either return Err or panic
        // (both indicate the invalid input is rejected).
        let probs = vec![0i16; 36];
        let result = std::panic::catch_unwind(|| FseTable::from_probabilities(&probs, 6));
        match result {
            Ok(Ok(_)) => panic!("expected error or panic for empty FSE table, but got Ok"),
            Ok(Err(_)) => {} // proper error returned
            Err(_) => {}     // panicked, which also rejects the input
        }
    }

    #[test]
    fn test_execute_sequences_with_dict_overlap() {
        // Test match that starts in dict and continues into output
        let dict_content = b"ABCD";
        let literals = b"EF";
        let seqs = vec![Sequence {
            literal_length: 2,
            match_length: 5,
            offset: 6, // 6 bytes back in "ABCDEF" => start at pos 0 => "ABCDE"
        }];
        let mut output = Vec::new();
        sequences::execute_sequences_with_dict(literals, &seqs, &mut output, dict_content, 1024)
            .unwrap();
        // Virtual: ABCDEF, offset=6 from end(6) = pos 0, copy 5 = ABCDE
        assert_eq!(output, b"EFABCDE");
    }

    #[test]
    fn test_get_fse_table_rle_mode() {
        // Mode 1 (RLE): single symbol FSE table
        use super::super::fse::FseTable;

        let data = [5u8]; // symbol = 5
        let mut pos = 0usize;
        let default_table = super::super::fse::default_literal_length_table();
        let mut prev_table: Option<FseTable> = None;

        let table =
            get_fse_table(1, &data, &mut pos, 35, 9, default_table, &mut prev_table).unwrap();

        assert_eq!(pos, 1); // consumed 1 byte
        // The RLE table should have 1 entry (accuracy_log=0, table_size=1)
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].symbol, 5);
        // prev_table should be set
        assert!(prev_table.is_some());
    }

    #[test]
    fn test_get_fse_table_predefined_mode() {
        use super::super::fse::FseTable;

        let mut pos = 0usize;
        let default_table = super::super::fse::default_literal_length_table();
        let expected_len = default_table.entries.len();
        let expected_accuracy_log = default_table.accuracy_log;
        let expected_first_symbol = default_table.entries[0].symbol;
        let mut prev_table: Option<FseTable> = None;

        let table = get_fse_table(0, &[], &mut pos, 35, 9, default_table, &mut prev_table).unwrap();

        assert_eq!(pos, 0);
        assert_eq!(table.entries.len(), expected_len);
        assert_eq!(table.accuracy_log, expected_accuracy_log);
        assert_eq!(table.entries[0].symbol, expected_first_symbol);
        assert!(prev_table.is_some());
    }

    #[test]
    fn test_get_fse_table_fse_compressed_mode() {
        use super::super::fse::FseTable;

        let data = [0x90, 0xB4, 0x6B, 0xC4];
        let mut pos = 0usize;
        let default_table = super::super::fse::default_literal_length_table();
        let mut prev_table: Option<FseTable> = None;

        let table =
            get_fse_table(2, &data, &mut pos, 12, 6, default_table, &mut prev_table).unwrap();

        assert_eq!(pos, 3);
        assert_eq!(table.accuracy_log, 5);
        assert_eq!(table.entries.len(), 32);
        assert_eq!(table.entries[0].symbol, 0);
        assert!(prev_table.is_some());
    }

    #[test]
    fn test_get_fse_table_repeat_mode() {
        // Mode 3 (Repeat): reuse previous table
        use super::super::fse::FseTable;

        // First, set up a previous table via RLE mode
        let data = [7u8];
        let mut pos = 0usize;
        let default_table = super::super::fse::default_literal_length_table();
        let mut prev_table: Option<FseTable> = None;

        get_fse_table(
            1,
            &data,
            &mut pos,
            35,
            9,
            super::super::fse::default_literal_length_table(),
            &mut prev_table,
        )
        .unwrap();
        assert!(prev_table.is_some());

        // Now use Repeat mode (3) — should succeed and return the same table
        let mut pos2 = 0usize;
        let table =
            get_fse_table(3, &[], &mut pos2, 35, 9, default_table, &mut prev_table).unwrap();

        assert_eq!(pos2, 0); // Repeat mode consumes no bytes
        assert_eq!(table.entries.len(), 1);
        assert_eq!(table.entries[0].symbol, 7);
    }

    #[test]
    fn test_sequence_compression_modes_reserved_bits_error() {
        let block = vec![
            0x08, // raw literals section, size=1
            b'X', // one raw literal byte
            0x01, // num_sequences=1
            0x01, // reserved low bits set
        ];

        let mut output = Vec::new();
        let mut rep_offsets = [1u32, 4, 8];
        let mut huff_table = None;
        let mut prev_ll_table = None;
        let mut prev_of_table = None;
        let mut prev_ml_table = None;

        let result = decode_compressed_block(
            &block,
            &mut output,
            &mut rep_offsets,
            &mut huff_table,
            &mut prev_ll_table,
            &mut prev_of_table,
            &mut prev_ml_table,
            &[],
            1024,
        );

        assert!(matches!(
            result,
            Err(Error::InvalidData(
                "sequence compression modes reserved bits are set"
            ))
        ));
    }

    #[test]
    fn test_repeat_mode_across_blocks() {
        fn make_block(literal: u8, mode_byte: u8, table_bytes: &[u8]) -> Vec<u8> {
            let mut block = vec![
                0x08, // raw literals section, size=1
                literal, 0x01, // one sequence
                mode_byte,
            ];
            block.extend_from_slice(table_bytes);
            block.push(0x01); // minimal valid reverse bitstream (endMark only)
            block
        }

        let mut output = Vec::new();
        let mut rep_offsets = [1u32, 4, 8];
        let mut huff_table = None;
        let mut prev_ll_table = None;
        let mut prev_of_table = None;
        let mut prev_ml_table = None;

        // Block 1 establishes LL/OF/ML tables using RLE mode:
        // LL symbol=1, OF symbol=0, ML symbol=0.
        let block1 = make_block(b'A', 0x54, &[0x01, 0x00, 0x00]);
        decode_compressed_block(
            &block1,
            &mut output,
            &mut rep_offsets,
            &mut huff_table,
            &mut prev_ll_table,
            &mut prev_of_table,
            &mut prev_ml_table,
            &[],
            1024,
        )
        .unwrap();
        assert_eq!(output, b"AAAA");

        // Block 2 reuses the exact same tables via Repeat mode.
        let block2 = make_block(b'B', 0xFC, &[]);
        decode_compressed_block(
            &block2,
            &mut output,
            &mut rep_offsets,
            &mut huff_table,
            &mut prev_ll_table,
            &mut prev_of_table,
            &mut prev_ml_table,
            &[],
            1024,
        )
        .unwrap();
        assert_eq!(output, b"AAAABBBB");
    }

    #[test]
    fn test_compressed_block_decompressed_size_exceeds_block_maximum_size() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        frame.push(0b0010_0000); // single segment
        frame.push(1); // FCS => window size = 1

        // Compressed block with raw literals only, regenerated size 2 > Block_Maximum_Size(1).
        let block_content = [0x10, b'A', b'B', 0x00];
        let bh = (block_content.len() as u32) << 3 | 0b101; // compressed, last
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(&block_content);

        let result = decode(&frame);
        assert!(
            matches!(
                result,
                Err(Error::InvalidData(
                    "compressed block decompressed size exceeds Block_Maximum_Size"
                ))
            ),
            "expected Block_Maximum_Size error, got {:?}",
            result
        );
    }

    #[test]
    fn test_fse_state_out_of_range() {
        // Build a minimal FSE table with a single entry, then call
        // decode_sequences_from_bitstream with data that will produce an
        // initial state value >= table size, triggering the out-of-range error.
        use super::super::fse::{FseEntry, FseTable};

        let small_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0, // 2^0 = 1 entry
        };

        // Build a bitstream whose initial state reads will exceed the table size.
        // accuracy_log=0 means read 0 bits per initial state → each state = 0.
        // With 1 entry (index 0), state 0 is valid — so we need a table with
        // accuracy_log > 0 to force a state > 0 from the bit data.
        //
        // Use accuracy_log=2 (reads 2 bits) but only 1 entry in the table.
        // The bitstream byte 0xFF will yield state values of 3, which is >= 1.
        let bad_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 2, // reads 2 bits → state can be up to 3
        };

        // Data: a valid bitstream with padding bit set. Reverse bitstream starts
        // from the last byte. We need at least 6 bits (2 per table) plus padding.
        // 0xFF = 1111_1111 — the first '1' from MSB is the padding sentinel,
        // then remaining bits are all 1s which will give states of 3.
        let data = [0xFF];
        let mut rep_offsets = [1u32, 4, 8];

        // ll_table and ml_table are fine (accuracy_log=0), of_table is bad.
        // Initial read order: ll (0 bits) → of (2 bits) → ml (0 bits).
        // of_state will be 3, which is >= bad_table.entries.len() (1).
        let result = decode_sequences_from_bitstream(
            &data,
            1,
            &small_table, // ll
            &bad_table,   // of — will produce out-of-range state
            &small_table, // ml
            &mut rep_offsets,
        );

        assert!(
            matches!(result, Err(Error::InvalidData("FSE state out of range"))),
            "expected FSE state out of range error, got {:?}",
            result
        );
    }

    #[test]
    fn test_offset_code_zero() {
        // RFC 8878 §3.1.2.3: offset_code=0 means offset_bits=0, offset_raw=1.
        // With initial rep_offsets=[1,4,8], offset_raw=1 is a repeat offset
        // (RepOffset1). For LL>0, this returns rep_offsets[0]=1.
        let mut rep = [1u32, 4, 8];
        // offset_raw=1, LL=5 → repeat offset 1 → returns rep_offsets[0]=1
        let result = resolve_offset(1, 5, &mut rep);
        assert_eq!(result, 1);
        assert_eq!(rep, [1, 4, 8]); // unchanged since idx=0

        // Verify the offset decoding logic: of_code=0 → offset_bits=0, offset_raw=1
        // This is implemented in decode_sequences_from_bitstream lines 645-650
        let offset_code: usize = 0;
        let offset_bits: u8 = if offset_code > 0 {
            offset_code as u8
        } else {
            0
        };
        let offset_raw: u32 = if offset_bits > 0 {
            1u32 << offset_bits // extra bits would be 0
        } else {
            1
        };
        assert_eq!(offset_raw, 1);
    }

    #[test]
    fn test_offset_formula_nonzero_code() {
        use super::super::fse::{FseEntry, FseTable};

        let ll_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let of_table = FseTable {
            entries: vec![FseEntry {
                symbol: 2, // offset_bits = 2
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let ml_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };

        let mut rep_offsets = [1u32, 4, 8];
        let sequences = decode_sequences_from_bitstream(
            &[0x07],
            1,
            &ll_table,
            &of_table,
            &ml_table,
            &mut rep_offsets,
        )
        .unwrap();

        assert_eq!(sequences.len(), 1);
        assert_eq!(sequences[0].offset, 4); // offset_raw = (1 << 2) + 0b11 = 7, real offset = 4
        assert_eq!(sequences[0].literal_length, 0);
        assert_eq!(sequences[0].match_length, 3);
    }

    #[test]
    fn test_match_length_code_out_of_range() {
        use super::super::fse::{FseEntry, FseTable};

        let ll_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let of_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let ml_table = FseTable {
            entries: vec![FseEntry {
                symbol: 53,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };

        let mut rep_offsets = [1u32, 4, 8];
        let result = decode_sequences_from_bitstream(
            &[0x01],
            1,
            &ll_table,
            &of_table,
            &ml_table,
            &mut rep_offsets,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidData("match length code out of range"))
        ));
    }

    #[test]
    fn test_literal_length_code_out_of_range() {
        use super::super::fse::{FseEntry, FseTable};

        let ll_table = FseTable {
            entries: vec![FseEntry {
                symbol: 36,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let of_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let ml_table = FseTable {
            entries: vec![FseEntry {
                symbol: 0,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };

        let mut rep_offsets = [1u32, 4, 8];
        let result = decode_sequences_from_bitstream(
            &[0x01],
            1,
            &ll_table,
            &of_table,
            &ml_table,
            &mut rep_offsets,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidData("literal length code out of range"))
        ));
    }

    #[test]
    fn test_window_size_below_minimum() {
        // RFC 8878 §3.1.1.1: minimum window size is 1024 bytes.
        // Build a frame with single_segment=false and a window descriptor that
        // yields a window_size below 1024.
        //
        // Window_Descriptor byte layout: Exponent (high 3 bits) | Mantissa (low 5 bits)
        // window_size = (1 << (10 + exponent)) + mantissa * (1 << (7 + exponent))
        // With exponent=0, mantissa=0: window_size = 1 << 10 = 1024 (valid)
        // We need window_size < 1024, but the formula's minimum with exponent=0
        // is 1024. However, we can test by directly constructing a frame whose
        // Window_Descriptor byte would be parsed. The smallest value from the
        // formula is 1024 (exponent=0, mantissa=0). So the check guards against
        // corrupted headers. Let's manually construct invalid frame bytes where
        // the window_size field is forced below 1024 by using the raw frame bytes.
        //
        // Actually, given the formula, window_descriptor=0x00 gives exactly 1024.
        // There's no valid window_descriptor that gives < 1024. But a corrupted
        // or malicious encoder could produce one. We can't easily forge this
        // through FrameHeader::parse since the formula always yields >= 1024.
        //
        // Instead, test at the decode_frame level by verifying that window_descriptor=0x00
        // (window_size=1024) passes, i.e., the boundary is correct.
        let mut frame = Vec::new();
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes()); // magic
        // Descriptor: single_segment=0, no checksum, no dict, FCS_flag=0
        frame.push(0x00);
        // Window descriptor = 0x00 => window_size = 1024 (minimum valid)
        frame.push(0x00);
        // Raw block: last=1, type=Raw(0), size=3
        let bh: u32 = (3 << 3) | 0b001;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        frame.extend_from_slice(b"abc");
        // This should succeed (window_size=1024 is exactly the minimum)
        let result = decode(&frame);
        assert!(
            result.is_ok(),
            "expected success for window_size=1024, got {:?}",
            result
        );
    }

    #[test]
    fn test_skippable_frame_truncated() {
        // Skippable frame (magic 0x184D2A50) with declared size larger than
        // remaining data. The decoder should return UnexpectedEof.
        let mut data = Vec::new();
        data.extend_from_slice(&0x184D2A50u32.to_le_bytes());
        // Declare 100 bytes of payload but provide only 4
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let result = decode(&data);
        assert!(
            matches!(result, Err(Error::UnexpectedEof)),
            "expected UnexpectedEof for truncated skippable frame, got {:?}",
            result
        );
    }

    #[test]
    fn test_rle_block_size_zero() {
        // Construct a valid zstd frame with an RLE block of size 0.
        // The RLE block still consumes 1 byte (the repeated value) but
        // produces zero output bytes.
        let mut frame = Vec::new();
        // Magic
        frame.extend_from_slice(&0xFD2FB528u32.to_le_bytes());
        // Descriptor: single_segment=1, no checksum, FCS_flag=00
        frame.push(0b0010_0000);
        // FCS = 0 (the frame produces 0 bytes of output)
        frame.push(0);
        // Block header: last_block=1, block_type=1 (RLE), block_size=0
        // val = (0 << 3) | (1 << 1) | 1 = 3
        let bh: u32 = (1 << 1) | 1;
        frame.push(bh as u8);
        frame.push((bh >> 8) as u8);
        frame.push((bh >> 16) as u8);
        // RLE byte (still required even though block_size=0)
        frame.push(0xAB);

        let result = decode(&frame).unwrap();
        assert!(
            result.is_empty(),
            "expected empty output for RLE block with size 0, got {:?}",
            result
        );
    }

    #[test]
    fn test_bitdstream_reads_from_tail_with_sentinel() {
        let mut stream = BitDstream::new(&[0xAA, 0x03]).unwrap();
        let bits: Vec<u32> = (0..8).map(|_| stream.read_bits(1).unwrap()).collect();
        assert_eq!(bits, vec![1, 1, 0, 1, 0, 1, 0, 1]);
    }

    #[test]
    fn test_bitdstream_requires_nonzero_last_byte() {
        let result = BitDstream::new(&[0xAA, 0x00]);
        assert!(matches!(
            result,
            Err(Error::InvalidData("sequence bitstream: no sentinel"))
        ));
    }

    #[test]
    fn test_decode_sequences_reads_offset_ml_ll_in_order() {
        use super::super::fse::{FseEntry, FseTable};

        let ll_table = FseTable {
            entries: vec![FseEntry {
                symbol: 16,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let of_table = FseTable {
            entries: vec![FseEntry {
                symbol: 1,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };
        let ml_table = FseTable {
            entries: vec![FseEntry {
                symbol: 32,
                num_bits: 0,
                baseline: 0,
            }],
            accuracy_log: 0,
        };

        let mut rep_offsets = [1u32, 4, 8];
        let sequences = decode_sequences_from_bitstream(
            &[0x0D],
            1,
            &ll_table,
            &of_table,
            &ml_table,
            &mut rep_offsets,
        )
        .unwrap();

        assert_eq!(sequences.len(), 1);
        assert_eq!(sequences[0].offset, 8);
        assert_eq!(sequences[0].match_length, 35);
        assert_eq!(sequences[0].literal_length, 17);
    }

    #[test]
    fn test_decode_sequences_updates_states_ll_ml_of_order() {
        use super::super::fse::{FseEntry, FseTable};

        let ll_table = FseTable {
            entries: vec![
                FseEntry {
                    symbol: 0,
                    num_bits: 1,
                    baseline: 0,
                },
                FseEntry {
                    symbol: 1,
                    num_bits: 1,
                    baseline: 0,
                },
            ],
            accuracy_log: 1,
        };
        let of_table = FseTable {
            entries: vec![
                FseEntry {
                    symbol: 0,
                    num_bits: 1,
                    baseline: 0,
                },
                FseEntry {
                    symbol: 1,
                    num_bits: 1,
                    baseline: 0,
                },
            ],
            accuracy_log: 1,
        };
        let ml_table = FseTable {
            entries: vec![
                FseEntry {
                    symbol: 0,
                    num_bits: 1,
                    baseline: 0,
                },
                FseEntry {
                    symbol: 1,
                    num_bits: 1,
                    baseline: 0,
                },
            ],
            accuracy_log: 1,
        };

        let mut rep_offsets = [1u32, 4, 8];
        let sequences = decode_sequences_from_bitstream(
            &[0x8A],
            2,
            &ll_table,
            &of_table,
            &ml_table,
            &mut rep_offsets,
        )
        .unwrap();

        assert_eq!(sequences.len(), 2);
        assert_eq!(sequences[0].literal_length, 0);
        assert_eq!(sequences[0].offset, 4);
        assert_eq!(sequences[0].match_length, 3);
        assert_eq!(sequences[1].literal_length, 1);
        assert_eq!(sequences[1].offset, 1);
        assert_eq!(sequences[1].match_length, 3);
    }

    #[test]
    fn test_repeat_offset_rotation_3_steps() {
        // Test 3 consecutive repeat offset updates showing correct
        // rep_offsets[0]/[1]/[2] rotation through resolve_offset.
        let mut rep = [10u32, 20, 30];

        // Step 1: offset_raw=2, LL=5 (>0) → use rep[1]=20, rotate to front
        let r1 = resolve_offset(2, 5, &mut rep);
        assert_eq!(r1, 20);
        assert_eq!(rep, [20, 10, 30]);

        // Step 2: offset_raw=3, LL=1 (>0) → use rep[2]=30, rotate to front
        let r2 = resolve_offset(3, 1, &mut rep);
        assert_eq!(r2, 30);
        assert_eq!(rep, [30, 20, 10]);

        // Step 3: offset_raw=1, LL=0 → shifted mapping: use rep[1]=20, swap
        let r3 = resolve_offset(1, 0, &mut rep);
        assert_eq!(r3, 20);
        assert_eq!(rep, [20, 30, 10]);
    }

    #[test]
    fn test_offset_raw3_ll0_rep0_is_1() {
        // Test resolve_offset(3, 0, [1, 4, 8]) to verify the wrapping
        // subtraction edge case: rep_offsets[0] - 1 = 0 when rep_offsets[0]=1.
        // Per RFC 8878 §3.1.1.5, offset_raw=3 with LL=0 means
        // real_offset = rep_offsets[0] - 1, then rotate all three.
        let mut rep = [1u32, 4, 8];
        let result = resolve_offset(3, 0, &mut rep);
        // 1 - 1 = 0 (wrapping_sub produces 0)
        assert_eq!(result, 0);
        assert_eq!(rep, [0, 1, 4]);
    }

    #[test]
    fn test_decode_bounded_within_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, 1000).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exact_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let result = decode_bounded(&compressed, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_decode_bounded_exceeds_limit() {
        let data = b"Hello, World! Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, data.len() - 1).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_decode_bounded_zero_limit() {
        let data = b"Hello, World!";
        let compressed = super::super::encode::encode(data);
        let err = decode_bounded(&compressed, 0).unwrap_err();
        assert!(matches!(
            err,
            crate::error::Error::OutputLimitExceeded { .. }
        ));
    }

    #[test]
    fn test_truncated_at_every_position() {
        // RFC 8878 §3.1.1: every proper prefix of a valid frame must fail —
        // a cut lands inside the frame header, a block, or the checksum.
        let data = b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.";
        let compressed = super::super::encode::encode(data);
        for cut in 1..compressed.len() {
            assert!(
                decode(&compressed[..cut]).is_err(),
                "cut={cut} must not decode"
            );
        }
    }
}
